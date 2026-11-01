//! The scheduling inbox of a principal: what other organizers' invitations, cancellations and answers left there.
//!
//! The inbox belongs to its principal alone: only they read and delete in it (`Operation::ReadInbox`,
//! `Operation::DeleteInboxItem`), and an inbox that somebody else asks for does not exist for them. Quarantined
//! messages (inbound iTIP that was not applied) are kept for inspection by operators and are never shown here.

use std::collections::HashMap;

use davhaven_domain::{
    Access, CalendarKind, InboxItem, ObjectUri, Operation, Precondition, PrincipalName, RequestContext, ResourceKind,
    ResourcePath, Tenant, TenantSlug, privileges,
};
use davhaven_ical::{ErrorContext, IcalError};
use davhaven_ports::{InboxScope, TxMode};

use super::SchedulingServiceImpl;
use crate::authz::{blocking, enforce, home_facts, home_of, require_scope, resolve_home, retrying};
use crate::error::{AppError, AppResult};
use crate::services::{CalendarDataSpec, InboxEntry, InboxItemView};

/// The view of an inbox item; `data` is the iTIP message, as stored or cut down to what a request selected, and
/// `None` where the read asked for no message. The size is that of the stored message either way, and the owner of
/// the home is the only one who sees the item at all.
fn view(tenant: &Tenant, principal: &PrincipalName, item: &InboxItem, data: Option<String>) -> InboxItemView {
    InboxItemView {
        path: ResourcePath::InboxItem {
            tenant: tenant.slug.clone(),
            principal: principal.clone(),
            uri: item.uri.clone(),
        },
        id: item.id,
        etag: item.etag.clone(),
        size: u64::try_from(item.data.len()).unwrap_or(u64::MAX),
        data,
        privileges: privileges(Access::Owner, CalendarKind::Personal, ResourceKind::InboxItem),
        created_at: item.created_at,
    }
}

/// The name of the item a path names in the inbox of `principal` in `tenant`.
fn name_in(path: &ResourcePath, tenant: &TenantSlug, principal: &PrincipalName) -> Option<ObjectUri> {
    match path {
        ResourcePath::InboxItem {
            tenant: of_tenant,
            principal: of_principal,
            uri,
        } if of_tenant == tenant && of_principal == principal => Some(uri.clone()),
        _ => None,
    }
}

/// The principal and the name of an inbox item path.
fn item_of(path: &ResourcePath) -> AppResult<(&TenantSlug, &PrincipalName, &ObjectUri)> {
    match path {
        ResourcePath::InboxItem { tenant, principal, uri } => Ok((tenant, principal, uri)),
        _ => Err(AppError::not_found()),
    }
}

impl SchedulingServiceImpl {
    /// Lists the delivered items of the inbox of `principal`.
    pub(super) async fn list_inbox(
        &self,
        ctx: &RequestContext,
        principal: &PrincipalName,
    ) -> AppResult<Vec<InboxItemView>> {
        require_scope(ctx, Operation::ReadInbox)?;
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let home = home_of(tx.as_mut(), ctx, principal).await?;
        let inbox = ResourcePath::Inbox {
            tenant: home.tenant.slug.clone(),
            principal: home.principal.name.clone(),
        };
        enforce(
            ctx,
            &home_facts(&home.tenant, &home.principal),
            Operation::ReadInbox,
            || inbox.href(),
        )?;
        let items = tx.inbox().list(home.principal.id, InboxScope::Delivered).await?;
        tx.commit().await?;
        Ok(items
            .into_iter()
            .map(|item| view(&home.tenant, &home.principal.name, &item, None))
            .collect())
    }

    /// Reads one item of an inbox.
    pub(super) async fn read_inbox_item(&self, ctx: &RequestContext, path: &ResourcePath) -> AppResult<InboxItemView> {
        require_scope(ctx, Operation::ReadInbox)?;
        let (tenant, principal, uri) = item_of(path)?;
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let home = resolve_home(tx.as_mut(), ctx, tenant, principal).await?;
        enforce(
            ctx,
            &home_facts(&home.tenant, &home.principal),
            Operation::ReadInbox,
            || path.href(),
        )?;
        let item = tx.inbox().get_by_uri(home.principal.id, uri).await?;
        if item.quarantined {
            return Err(AppError::not_found());
        }
        tx.commit().await?;
        Ok(view(&home.tenant, &home.principal.name, &item, Some(item.data.clone())))
    }

    /// Reads several items of one inbox in one transaction: the bulk read behind `calendar-multiget`, listings that
    /// carry the messages and `sync-collection` (`SchedulingService::inbox_get_many`). The inbox is resolved once,
    /// with the tenant of its path, and the items come from one query; a path that is no item of this inbox, an item
    /// that does not exist and a quarantined message are `Missing`. The messages are cut down to the selection of the
    /// request on a blocking thread.
    pub(super) async fn read_inbox_items(
        &self,
        ctx: &RequestContext,
        inbox: &ResourcePath,
        paths: Vec<ResourcePath>,
        spec: &CalendarDataSpec,
    ) -> AppResult<Vec<InboxEntry>> {
        require_scope(ctx, Operation::ReadInbox)?;
        let ResourcePath::Inbox { tenant, principal } = inbox else {
            return Err(AppError::not_found());
        };
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let home = resolve_home(tx.as_mut(), ctx, tenant, principal).await?;
        enforce(
            ctx,
            &home_facts(&home.tenant, &home.principal),
            Operation::ReadInbox,
            || inbox.href(),
        )?;
        // Visibility comes first: a caller who cannot see the inbox is not told how many items it may name.
        let most = usize::try_from(self.core.deps().limits.dav.max_multiget_hrefs).unwrap_or(usize::MAX);
        if paths.len() > most {
            return Err(AppError::forbidden().with_precondition(Precondition::NumberOfMatchesWithinLimits));
        }
        let names: Vec<ObjectUri> = paths
            .iter()
            .filter_map(|path| name_in(path, tenant, principal))
            .collect();
        let stored = tx.inbox().get_many_by_uri(home.principal.id, &names).await?;
        tx.commit().await?;
        let delivered: HashMap<ObjectUri, InboxItem> = stored
            .into_iter()
            .filter(|item| !item.quarantined)
            .map(|item| (item.uri.clone(), item))
            .collect();
        let project = spec.include_data && !spec.projection.is_identity();
        let projected = if project {
            let messages: Vec<(ObjectUri, String)> = delivered
                .values()
                .map(|item| (item.uri.clone(), item.data.clone()))
                .collect();
            let projection = spec.projection.clone();
            blocking(&self.core, ErrorContext::Query, move |limits| {
                messages
                    .into_iter()
                    .map(|(uri, data)| {
                        let calendar = davhaven_ical::parse::parse(data.as_bytes(), limits)?;
                        let text = davhaven_ical::projection::project(&calendar, &projection, limits)?;
                        Ok::<_, IcalError>((uri, text))
                    })
                    .collect::<Result<HashMap<_, _>, IcalError>>()
            })
            .await?
        } else {
            HashMap::new()
        };
        Ok(paths
            .into_iter()
            .map(|path| {
                let found = name_in(&path, tenant, principal).and_then(|name| delivered.get(&name));
                match found {
                    Some(item) => {
                        let data = if !spec.include_data {
                            None
                        } else if project {
                            projected.get(&item.uri).cloned()
                        } else {
                            Some(item.data.clone())
                        };
                        InboxEntry::Found(view(&home.tenant, &home.principal.name, item, data))
                    }
                    None => InboxEntry::Missing(path),
                }
            })
            .collect())
    }

    /// Deletes one item of an inbox.
    pub(super) async fn delete_inbox_item(&self, ctx: &RequestContext, path: &ResourcePath) -> AppResult<()> {
        require_scope(ctx, Operation::DeleteInboxItem)?;
        let (tenant, principal, uri) = item_of(path)?;
        retrying(false, || async {
            let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadWrite).await?;
            let home = resolve_home(tx.as_mut(), ctx, tenant, principal).await?;
            enforce(
                ctx,
                &home_facts(&home.tenant, &home.principal),
                Operation::DeleteInboxItem,
                || path.href(),
            )?;
            let item = tx.inbox().get_by_uri(home.principal.id, uri).await?;
            if item.quarantined {
                return Err(AppError::not_found());
            }
            tx.inbox().delete(item.id).await?;
            tx.commit().await?;
            Ok(())
        })
        .await
    }
}
