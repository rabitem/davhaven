//! Calendar sharing: CalendarServer invitations, replies, grants and notifications.
//!
//! Sharing follows PLAN 2.9:
//!
//! 1. the owner (or an administrator of the calendar) posts `CS:share` to the calendar collection: every sharee
//!    becomes a **pending grant** and receives a `CS:invite-notification` in their notification collection;
//! 2. the sharee answers with `CS:invite-reply` in their home: accepting binds the calendar into their home and tells
//!    the owner through an `invite-reply` notification, declining marks the grant declined;
//! 3. with `tenant.settings.sharing.auto_accept` step 2 happens at once and no notification is sent;
//! 4. the management API creates grants that are **accepted at once**; one grant exists per (calendar, grantee) and
//!    the last write wins between the API and DAV, the `source` records who wrote last.
//!
//! Sharees must be active users or groups of the same tenant (an external address is refused per item, the request
//! as a whole succeeds); managed and mirror calendars cannot be shared through DAV; clients cannot change or remove
//! grants the API made on group and managed calendars. The management API also grants to **service principals** (the
//! machine identities of assistants and integrations), which client sharing does not offer: they are no valid sharee,
//! `CS:invite` does not list them, and a client cannot remove their API grants on any kind of calendar. A grant to a
//! group gives every current member access through the group (PLAN 2.6), so it is accepted at once and needs no
//! binding of its own.
//!
//! Every change writes its audit record and its domain event in the transaction, and moves the `CTag` of the
//! calendar (`CalendarRepo::touch`), because `CS:invite` is a property of the collection.

mod grants;
mod xml;

pub(crate) use grants::{drop_invitation, restore_for_new_members};

use async_trait::async_trait;
use davhaven_domain::audit::GrantAudit;
use davhaven_domain::events::GrantPayload;
use davhaven_domain::{
    Access, AuditEvent, Binding, BindingId, Calendar, CalendarKind, CalendarUserAddress, Decision, ETag, EventPayload,
    EventType, Grant, GrantSource, GrantStatus, Notification, NotificationId, NotificationKind, ObjectUri, Operation,
    Precondition, PrincipalKind, PrincipalName, PrincipalStatus, RequestContext, ResourceKind, ResourcePath, Uid,
    decide, privileges,
};
use davhaven_ports::{StoreError, Tx, TxMode, UniqueKey};
use davhaven_wire::{GrantView, Page};

use crate::audit::Journal;
use crate::authz::{Home, enforce, facts_for, home_facts, home_of, resolve_home, retrying};
use crate::calendars::Views;
use crate::error::{AppError, AppResult};
use crate::principals::find_by_address;
use crate::services::{
    CalendarRef, Conditions, GrantSpec, IfMatch, InviteReply, InviteReplyOutcome, NotificationView, PageRequest,
    ShareItemResult, ShareRequest, ShareeSet, SharingService, Upserted, WritePrecondition,
};
use crate::wiring::AppCore;

/// The longest summary of an invitation or of its answer, in characters.
const MAX_SUMMARY_CHARS: usize = 200;

/// The [`SharingService`] of the application.
#[derive(Debug, Clone)]
pub struct SharingServiceImpl {
    core: AppCore,
}

impl SharingServiceImpl {
    /// Creates the service on the shared application core.
    pub fn new(core: AppCore) -> Self {
        Self { core }
    }

    /// The shared application core: ports, configuration and limits.
    pub fn core(&self) -> &AppCore {
        &self.core
    }
}

/// The audit record and the event payload of a grant change.
pub(crate) fn grant_audit(grant: &Grant, with_access: bool) -> GrantAudit {
    GrantAudit {
        calendar: grant.calendar_id,
        grant: Some(grant.id),
        grantee: grant.grantee_id,
        access: with_access.then_some(grant.access),
        required: grant.required,
    }
}

pub(crate) fn grant_payload(grant: &Grant) -> EventPayload {
    EventPayload::Grant(GrantPayload {
        calendar: grant.calendar_id,
        grant: grant.id,
        grantee: grant.grantee_id,
        access: grant.access,
        status: grant.status,
        required: grant.required,
    })
}

/// The principal's address as sharing shows it: the primary mail address, or `urn:uuid` without one.
fn sharing_address(principal: &davhaven_domain::Principal) -> CalendarUserAddress {
    principal.email.as_ref().map_or_else(
        || CalendarUserAddress::urn_uuid(principal.id),
        CalendarUserAddress::mailto,
    )
}

/// A notification of `principal` named after `stem`.
fn new_notification(
    core: &AppCore,
    principal: &davhaven_domain::Principal,
    stem: &str,
    uid: &Uid,
    kind: NotificationKind,
    body: String,
) -> AppResult<Notification> {
    let deps = core.deps();
    let now = deps.clock.now();
    let uri = ObjectUri::parse(&format!("{stem}.xml")).map_err(AppError::internal)?;
    Ok(Notification {
        id: NotificationId::from_uuid(deps.ids.new_id()),
        tenant_id: principal.tenant_id,
        principal_id: principal.id,
        uri,
        uid: uid.clone(),
        etag: ETag::from_bytes(body.as_bytes()),
        kind,
        body_xml: body,
        created_at: now,
        updated_at: now,
        version: 1,
    })
}

/// Tells the owner of a calendar how a sharee answered an invitation.
async fn notify_owner(
    core: &AppCore,
    tx: &mut dyn Tx,
    home: &Home,
    calendar: &Calendar,
    grant: &Grant,
    accepted: bool,
    host_href: &str,
) -> AppResult<()> {
    let owner = tx.principals().get(calendar.owner_id).await?;
    let uid = grant
        .invite_uid
        .clone()
        .unwrap_or_else(|| Uid::from_uuid(core.deps().ids.new_id()));
    let sharee_address = sharing_address(&home.principal);
    let body = xml::reply(&xml::Reply {
        at: core.deps().clock.now(),
        accepted,
        sharee: &sharee_address,
        sharee_name: &home.principal.display_name,
        host_href,
        in_reply_to: uid.as_str(),
        summary: grant.summary.as_deref(),
    });
    let stem = format!("{}-reply-{}", uid, core.deps().ids.new_id().simple());
    let notification = new_notification(core, &owner, &stem, &uid, NotificationKind::InviteReply, body)?;
    tx.notifications().create(notification).await?;
    Ok(())
}

/// A sharee leaves a share: the binding goes, the grant is declined and the owner is told (PLAN 2.9: DELETE of a
/// bound collection by a sharee).
///
/// # Errors
///
/// Store failures.
pub(crate) async fn leave_share(
    core: &AppCore,
    journal: &Journal<'_>,
    tx: &mut dyn Tx,
    home: &Home,
    calendar: &Calendar,
    grant: &Grant,
    binding: &Binding,
) -> AppResult<()> {
    tx.bindings().delete(binding.id).await?;
    let declined = Grant {
        status: GrantStatus::Declined,
        ..grant.clone()
    };
    let stored = tx.grants().update(declined, grant.version).await?;
    let owner_slug = Views::new(core, &home.tenant).owner_slug(tx, calendar).await?;
    let owner = tx.principals().get(calendar.owner_id).await?;
    let host = ResourcePath::Collection {
        tenant: home.tenant.slug.clone(),
        principal: owner.name,
        binding: owner_slug,
    }
    .format();
    notify_owner(core, tx, home, calendar, &stored, false, &host).await?;
    journal
        .audit(tx, AuditEvent::ShareRemoved(grant_audit(&stored, false)))
        .await?;
    journal
        .publish(tx, EventType::ShareDeclined, grant_payload(&stored))
        .await
}

/// A slug for the binding of a sharee: the calendar's slug unless the home uses it already.
async fn binding_for_sharee(core: &AppCore, tx: &mut dyn Tx, home: &Home, calendar: &Calendar) -> AppResult<Binding> {
    let deps = core.deps();
    if let Some(existing) = tx.bindings().find_for_calendar(home.principal.id, calendar.id).await? {
        return Ok(existing);
    }
    let taken: std::collections::HashSet<String> = tx
        .bindings()
        .list_for(home.principal.id)
        .await?
        .into_iter()
        .map(|bound| bound.binding.slug.as_str().to_owned())
        .collect();
    let slug = crate::calendars::free_binding_slug(&calendar.slug, &taken)?;
    let now = deps.clock.now();
    let binding = Binding {
        id: BindingId::from_uuid(deps.ids.new_id()),
        tenant_id: home.principal.tenant_id,
        principal_id: home.principal.id,
        calendar_id: calendar.id,
        slug,
        display_name: None,
        color: None,
        sort_order: None,
        schedule_transp: None,
        hidden: false,
        created_at: now,
        updated_at: now,
        version: 1,
    };
    match tx.bindings().create(binding).await {
        Ok(created) => Ok(created),
        // Lost a race against another binding of the same home: the transaction starts over.
        Err(StoreError::UniqueViolation(UniqueKey::BindingSlug | UniqueKey::BindingCalendar)) => {
            Err(AppError::from(StoreError::SerializationFailure))
        }
        Err(error) => Err(error.into()),
    }
}

impl SharingServiceImpl {
    /// One attempt of a `CS:share` request.
    async fn share_once(
        &self,
        ctx: &RequestContext,
        collection: &ResourcePath,
        request: &ShareRequest,
    ) -> AppResult<Vec<ShareItemResult>> {
        let ResourcePath::Collection {
            tenant,
            principal,
            binding,
        } = collection
        else {
            return Err(AppError::not_found());
        };
        let deps = self.core.deps();
        let journal = Journal::new(&self.core, ctx);
        let mut tx = deps.database.begin(ctx.tenant, TxMode::ReadWrite).await?;
        let home = resolve_home(tx.as_mut(), ctx, tenant, principal).await?;
        let binding = tx.bindings().get_by_slug(home.principal.id, binding).await?;
        let calendar = tx
            .calendars()
            .lock(&[binding.calendar_id])
            .await?
            .into_iter()
            .next()
            .ok_or_else(AppError::not_found)?;
        let facts = facts_for(tx.as_mut(), ctx, calendar.id).await?;
        let decision = decide(&ctx.subject(), ctx.channel, &facts, Operation::ShareCalendar);
        if decision == Decision::Hidden {
            return Err(AppError::not_found());
        }
        // Sharing that the server has switched off is refused to those who see the calendar, and to them only: the
        // answer for a calendar that is not there stays 404 (PLAN 2.6).
        if !self.core.deps().config.sharing.enabled {
            return Err(AppError::forbidden().with_precondition(Precondition::SharingNotAllowed));
        }
        match decision {
            Decision::Allow => {}
            Decision::Hidden => return Err(AppError::not_found()),
            Decision::Forbidden(privilege) => {
                let shareable = !matches!(
                    calendar.kind,
                    davhaven_domain::CalendarKind::Managed | davhaven_domain::CalendarKind::Mirror
                ) && facts.tenant_settings.sharing.enabled;
                return Err(if shareable {
                    AppError::need_privilege(collection.href(), privilege)
                } else {
                    AppError::forbidden().with_precondition(Precondition::SharingNotAllowed)
                });
            }
        }
        let shared = Shared {
            service: self,
            journal: &journal,
            home: &home,
            calendar: &calendar,
            collection,
        };
        let mut results = Vec::with_capacity(request.set.len() + request.remove.len());
        let mut changed = false;
        for sharee in &request.set {
            let (error, did) = shared.set(tx.as_mut(), sharee).await?;
            changed |= did;
            results.push(ShareItemResult {
                address: sharee.address.clone(),
                error,
            });
        }
        for address in &request.remove {
            let (error, did) = shared.remove(tx.as_mut(), address).await?;
            changed |= did;
            results.push(ShareItemResult {
                address: address.clone(),
                error,
            });
        }
        if changed {
            tx.calendars().touch(calendar.id).await?;
        }
        tx.commit().await?;
        Ok(results)
    }

    /// The path of the owner's collection of a calendar, which invitations name as the host.
    async fn host_href(&self, tx: &mut dyn Tx, home: &Home, calendar: &Calendar) -> AppResult<String> {
        let slug = Views::new(&self.core, &home.tenant).owner_slug(tx, calendar).await?;
        let owner = tx.principals().get(calendar.owner_id).await?;
        Ok(ResourcePath::Collection {
            tenant: home.tenant.slug.clone(),
            principal: owner.name,
            binding: slug,
        }
        .format())
    }
}

/// The context of one `CS:share` request, shared by its items.
struct Shared<'a> {
    service: &'a SharingServiceImpl,
    journal: &'a Journal<'a>,
    home: &'a Home,
    calendar: &'a Calendar,
    collection: &'a ResourcePath,
}

impl Shared<'_> {
    fn refused(&self) -> AppError {
        AppError::forbidden().with_precondition(Precondition::InvalidSharee(self.collection.href()))
    }

    /// Whether `grant`, which is for a principal of kind `grantee`, is one that clients must not change or remove: the
    /// API's grants on group and managed calendars, and the API's grants to service principals on every kind of
    /// calendar (PLAN 2.9). A service principal is no sharee of client sharing (it does not appear in `CS:invite`), so
    /// the grant that an integration holds is not the client's to take back. A grant that is marked `required` is the
    /// operator's on every kind of calendar: a client that changed or removed it would take the calendar out of the
    /// home of the people who must have it.
    fn protects(&self, grant: &Grant, grantee: PrincipalKind) -> bool {
        grant.required
            || (grant.source == GrantSource::Api
                && (grantee == PrincipalKind::Service
                    || matches!(
                        self.calendar.kind,
                        davhaven_domain::CalendarKind::Group | davhaven_domain::CalendarKind::Managed
                    )))
    }

    /// The error of an item that touches a grant the API made on a group or managed calendar.
    fn not_theirs(&self) -> AppError {
        AppError::need_privilege(self.collection.href(), davhaven_domain::Privilege::Share)
    }

    /// Invites a sharee or changes their access. Returns the item's error and whether anything changed.
    async fn set(&self, tx: &mut dyn Tx, item: &ShareeSet) -> AppResult<(Option<AppError>, bool)> {
        let core = &self.service.core;
        let urls = &core.deps().urls;
        let Some(sharee) = find_by_address(tx, &self.home.tenant, urls, &item.address).await? else {
            return Ok((Some(self.refused()), false));
        };
        let usable = matches!(sharee.kind, PrincipalKind::User | PrincipalKind::Group)
            && sharee.status == PrincipalStatus::Active
            && sharee.id != self.calendar.owner_id;
        if !usable {
            return Ok((Some(self.refused()), false));
        }
        // A grant the API made on a group or managed calendar is not the clients' to change either: a set would
        // rewrite its `source` to `share` and the removal that follows would undo what the integration provisioned.
        if let Some(grant) = tx.grants().find(self.calendar.id, sharee.id).await?
            && self.protects(&grant, sharee.kind)
        {
            return Ok((Some(self.not_theirs()), false));
        }
        let tenant = &self.home.tenant;
        // A group answers no invitation: its members get the access through the group.
        let auto = tenant.settings.sharing.auto_accept || sharee.kind == PrincipalKind::Group;
        let Some(grant) = self.write_grant(tx, &sharee, item, auto).await? else {
            return Ok((None, false));
        };
        match grant.status {
            GrantStatus::Pending => self.invite(tx, &sharee, &grant).await?,
            GrantStatus::Accepted if sharee.kind == PrincipalKind::User => {
                // Accepted at once (auto-accept): the calendar appears in the home right away.
                let home = Home {
                    tenant: tenant.clone(),
                    principal: sharee.clone(),
                };
                binding_for_sharee(core, tx, &home, self.calendar).await?;
            }
            GrantStatus::Accepted | GrantStatus::Declined => {}
        }
        Ok((None, true))
    }

    /// Creates the grant of a sharee or changes it, with its audit record and events. `None` when the grant is as
    /// the request wants it already.
    async fn write_grant(
        &self,
        tx: &mut dyn Tx,
        sharee: &davhaven_domain::Principal,
        item: &ShareeSet,
        auto: bool,
    ) -> AppResult<Option<Grant>> {
        let deps = self.service.core.deps();
        let summary = item
            .summary
            .as_deref()
            .map(|text| text.chars().take(MAX_SUMMARY_CHARS).collect::<String>());
        let common_name = item
            .common_name
            .as_deref()
            .map(|text| text.chars().take(MAX_SUMMARY_CHARS).collect::<String>());
        let now = deps.clock.now();
        let grant = match tx.grants().find(self.calendar.id, sharee.id).await? {
            None => {
                let grant = Grant {
                    id: davhaven_domain::GrantId::from_uuid(deps.ids.new_id()),
                    tenant_id: self.home.tenant.id,
                    calendar_id: self.calendar.id,
                    grantee_id: sharee.id,
                    access: item.access,
                    status: if auto {
                        GrantStatus::Accepted
                    } else {
                        GrantStatus::Pending
                    },
                    source: GrantSource::Share,
                    // Client sharing never requires a calendar: only the operator's API grants do.
                    required: false,
                    invite_uid: Some(Uid::from_uuid(deps.ids.new_id())),
                    summary,
                    common_name,
                    created_at: now,
                    updated_at: now,
                    version: 1,
                };
                let stored = tx.grants().create(grant).await?;
                self.journal
                    .audit(tx, AuditEvent::ShareInvited(grant_audit(&stored, true)))
                    .await?;
                self.journal
                    .publish(tx, EventType::ShareInvited, grant_payload(&stored))
                    .await?;
                stored
            }
            Some(current) => {
                let status = match (current.status, auto) {
                    (GrantStatus::Accepted, _) | (_, true) => GrantStatus::Accepted,
                    (GrantStatus::Pending | GrantStatus::Declined, false) => GrantStatus::Pending,
                };
                let updated = Grant {
                    access: item.access,
                    status,
                    source: GrantSource::Share,
                    summary: summary.or_else(|| current.summary.clone()),
                    common_name: common_name.or_else(|| current.common_name.clone()),
                    invite_uid: current
                        .invite_uid
                        .clone()
                        .or_else(|| Some(Uid::from_uuid(deps.ids.new_id()))),
                    ..current.clone()
                };
                if updated == current {
                    return Ok(None);
                }
                let stored = tx.grants().update(updated, current.version).await?;
                self.journal
                    .audit(tx, AuditEvent::GrantUpdated(grant_audit(&stored, true)))
                    .await?;
                self.journal
                    .publish(tx, EventType::GrantUpdated, grant_payload(&stored))
                    .await?;
                if current.status != GrantStatus::Accepted && stored.status == GrantStatus::Accepted {
                    self.journal
                        .publish(tx, EventType::ShareAccepted, grant_payload(&stored))
                        .await?;
                }
                stored
            }
        };
        Ok(Some(grant))
    }

    /// Writes (or refreshes) the invitation in the sharee's notification collection.
    async fn invite(&self, tx: &mut dyn Tx, sharee: &davhaven_domain::Principal, grant: &Grant) -> AppResult<()> {
        let core = &self.service.core;
        let uid = grant
            .invite_uid
            .clone()
            .ok_or_else(|| AppError::internal(StoreError::internal("a grant without an invitation")))?;
        let owner = tx.principals().get(self.calendar.owner_id).await?;
        let host = self.service.host_href(tx, self.home, self.calendar).await?;
        let sharee_address = sharing_address(sharee);
        let organizer = sharing_address(&owner);
        let body = xml::invite(&xml::Invitation {
            at: core.deps().clock.now(),
            invite_uid: uid.as_str(),
            sharee: &sharee_address,
            access: grant.access,
            host_href: &host,
            organizer: &organizer,
            organizer_name: &owner.display_name,
            summary: grant.summary.as_deref(),
            components: &self.calendar.components,
        });
        if let Some(existing) = tx.notifications().find_by_uid(sharee.id, &uid).await? {
            let updated = Notification {
                etag: ETag::from_bytes(body.as_bytes()),
                body_xml: body,
                ..existing.clone()
            };
            tx.notifications().update(updated, existing.version).await?;
        } else {
            let notification = new_notification(core, sharee, uid.as_str(), &uid, NotificationKind::Invite, body)?;
            tx.notifications().create(notification).await?;
        }
        Ok(())
    }

    /// Removes a sharee. Returns the item's error and whether anything changed.
    async fn remove(&self, tx: &mut dyn Tx, address: &CalendarUserAddress) -> AppResult<(Option<AppError>, bool)> {
        let urls = &self.service.core.deps().urls;
        let Some(sharee) = find_by_address(tx, &self.home.tenant, urls, address).await? else {
            return Ok((None, false));
        };
        let Some(grant) = tx.grants().find(self.calendar.id, sharee.id).await? else {
            return Ok((None, false));
        };
        if self.protects(&grant, sharee.kind) {
            return Ok((Some(self.not_theirs()), false));
        }
        if let Some(binding) = tx.bindings().find_for_calendar(sharee.id, self.calendar.id).await? {
            tx.bindings().delete(binding.id).await?;
        }
        if let Some(uid) = &grant.invite_uid
            && let Some(notification) = tx.notifications().find_by_uid(sharee.id, uid).await?
        {
            tx.notifications().delete(notification.id).await?;
        }
        tx.grants().delete(grant.id).await?;
        self.journal
            .audit(tx, AuditEvent::ShareRemoved(grant_audit(&grant, false)))
            .await?;
        self.journal
            .publish(tx, EventType::GrantDeleted, grant_payload(&grant))
            .await?;
        Ok((None, true))
    }
}

impl SharingServiceImpl {
    /// One attempt of an invitation reply.
    async fn reply_once(
        &self,
        ctx: &RequestContext,
        path: &ResourcePath,
        reply: &InviteReply,
    ) -> AppResult<InviteReplyOutcome> {
        let ResourcePath::Home { tenant, principal } = path else {
            return Err(AppError::not_found());
        };
        let deps = self.core.deps();
        let journal = Journal::new(&self.core, ctx);
        let mut tx = deps.database.begin(ctx.tenant, TxMode::ReadWrite).await?;
        let home = resolve_home(tx.as_mut(), ctx, tenant, principal).await?;
        let grant = tx
            .grants()
            .find_by_invite_uid(&reply.in_reply_to)
            .await?
            .filter(|grant| grant.grantee_id == home.principal.id)
            .ok_or_else(AppError::not_found)?;
        let calendar = tx
            .calendars()
            .lock(&[grant.calendar_id])
            .await?
            .into_iter()
            .next()
            .ok_or_else(AppError::not_found)?;
        // Answering twice with the same answer repeats the first answer.
        match (grant.status, reply.accepted) {
            (GrantStatus::Accepted, true) => {
                // The repeated answer is a write like any other: it needs the access the grant gave, which a
                // hidden binding or a changed calendar may have taken away.
                let facts = facts_for(tx.as_mut(), ctx, calendar.id).await?;
                enforce(ctx, &facts, Operation::ReadCollection, || path.href())?;
                let binding = binding_for_sharee(&self.core, tx.as_mut(), &home, &calendar).await?;
                tx.commit().await?;
                return Ok(InviteReplyOutcome::Accepted {
                    shared_as: collection_path(&home, &binding),
                });
            }
            (GrantStatus::Declined, false) => {
                tx.commit().await?;
                return Ok(InviteReplyOutcome::Declined);
            }
            _ => {}
        }
        let facts = facts_for(tx.as_mut(), ctx, calendar.id).await?;
        enforce(ctx, &facts, Operation::ReplyInvite, || path.href())?;
        let status = if reply.accepted {
            GrantStatus::Accepted
        } else {
            GrantStatus::Declined
        };
        // The sharee's remark is shown to the owner and kept in `CS:invite` like the owner's own: the same limit.
        let summary = reply
            .summary
            .as_deref()
            .map(|text| text.chars().take(MAX_SUMMARY_CHARS).collect::<String>());
        let updated = Grant {
            status,
            summary: summary.or_else(|| grant.summary.clone()),
            ..grant.clone()
        };
        let stored = tx.grants().update(updated, grant.version).await?;
        let host = self.host_href(tx.as_mut(), &home, &calendar).await?;
        notify_owner(
            &self.core,
            tx.as_mut(),
            &home,
            &calendar,
            &stored,
            reply.accepted,
            &host,
        )
        .await?;
        let (audit, event) = if reply.accepted {
            (
                AuditEvent::ShareAccepted(grant_audit(&stored, true)),
                EventType::ShareAccepted,
            )
        } else {
            (
                AuditEvent::ShareDeclined(grant_audit(&stored, false)),
                EventType::ShareDeclined,
            )
        };
        journal.audit(tx.as_mut(), audit).await?;
        journal.publish(tx.as_mut(), event, grant_payload(&stored)).await?;
        let outcome = if reply.accepted {
            let binding = binding_for_sharee(&self.core, tx.as_mut(), &home, &calendar).await?;
            InviteReplyOutcome::Accepted {
                shared_as: collection_path(&home, &binding),
            }
        } else {
            // Declining ends the share: the collection leaves the home like it does when the sharee leaves it.
            if let Some(binding) = tx.bindings().find_for_calendar(home.principal.id, calendar.id).await? {
                tx.bindings().delete(binding.id).await?;
            }
            InviteReplyOutcome::Declined
        };
        tx.calendars().touch(calendar.id).await?;
        tx.commit().await?;
        Ok(outcome)
    }
}

/// The collection a binding is in the home.
fn collection_path(home: &Home, binding: &Binding) -> ResourcePath {
    ResourcePath::Collection {
        tenant: home.tenant.slug.clone(),
        principal: home.principal.name.clone(),
        binding: binding.slug.clone(),
    }
}

/// The notification as DAV shows it.
fn notification_view(home: &Home, notification: &Notification) -> NotificationView {
    NotificationView {
        path: ResourcePath::Notification {
            tenant: home.tenant.slug.clone(),
            principal: home.principal.name.clone(),
            uri: notification.uri.clone(),
        },
        id: notification.id,
        uid: notification.uid.clone(),
        etag: notification.etag.clone(),
        kind: notification.kind,
        body_xml: notification.body_xml.clone(),
        size: u64::try_from(notification.body_xml.len()).unwrap_or(u64::MAX),
        // Only the owner of a home reads its notifications (the services answer 404 to everybody else).
        privileges: privileges(Access::Owner, CalendarKind::Personal, ResourceKind::Notification),
        created_at: notification.created_at,
        updated_at: notification.updated_at,
    }
}

/// Evaluates the conditional headers of a `DELETE` against the entity tag of the notification: `PreconditionFailed`
/// when one does not hold. A notification has no schedule tag, so a condition on one never holds.
fn check_preconditions(preconditions: &WritePrecondition, etag: &ETag) -> AppResult<()> {
    let holds = match &preconditions.if_match {
        None | Some(IfMatch::Any) => true,
        Some(IfMatch::Tags(tags)) => tags.contains(etag),
    };
    if holds && !preconditions.if_none_match_any && preconditions.if_schedule_tag_match.is_none() {
        Ok(())
    } else {
        Err(AppError::precondition_failed())
    }
}

#[async_trait]
impl SharingService for SharingServiceImpl {
    async fn share(
        &self,
        ctx: &RequestContext,
        collection: &ResourcePath,
        request: ShareRequest,
    ) -> AppResult<Vec<ShareItemResult>> {
        retrying(false, || self.share_once(ctx, collection, &request)).await
    }

    async fn reply_invite(
        &self,
        ctx: &RequestContext,
        home: &ResourcePath,
        reply: InviteReply,
    ) -> AppResult<InviteReplyOutcome> {
        retrying(false, || self.reply_once(ctx, home, &reply)).await
    }

    async fn list_grants(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        page: PageRequest,
    ) -> AppResult<Page<GrantView>> {
        self.grants_of(ctx, calendar, page).await
    }

    async fn put_grant(
        &self,
        ctx: &RequestContext,
        spec: GrantSpec,
        conditions: Conditions,
    ) -> AppResult<Upserted<GrantView>> {
        self.upsert_grant(ctx, spec, conditions).await
    }

    async fn delete_grant(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        grantee: &PrincipalName,
        conditions: Conditions,
    ) -> AppResult<()> {
        self.remove_grant(ctx, calendar, grantee, conditions).await
    }

    async fn list_notifications(
        &self,
        ctx: &RequestContext,
        principal: &PrincipalName,
    ) -> AppResult<Vec<NotificationView>> {
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let home = home_of(tx.as_mut(), ctx, principal).await?;
        let facts = home_facts(&home.tenant, &home.principal);
        enforce(ctx, &facts, Operation::ReadNotifications, || {
            ResourcePath::Notifications {
                tenant: home.tenant.slug.clone(),
                principal: home.principal.name.clone(),
            }
            .href()
        })?;
        let notifications = tx.notifications().list(home.principal.id).await?;
        tx.commit().await?;
        Ok(notifications
            .iter()
            .map(|notification| notification_view(&home, notification))
            .collect())
    }

    async fn get_notification(&self, ctx: &RequestContext, path: &ResourcePath) -> AppResult<NotificationView> {
        let ResourcePath::Notification { tenant, principal, uri } = path else {
            return Err(AppError::not_found());
        };
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let home = resolve_home(tx.as_mut(), ctx, tenant, principal).await?;
        let facts = home_facts(&home.tenant, &home.principal);
        enforce(ctx, &facts, Operation::ReadNotifications, || path.href())?;
        let notification = tx.notifications().get_by_uri(home.principal.id, uri).await?;
        tx.commit().await?;
        Ok(notification_view(&home, &notification))
    }

    async fn get_notifications_many(
        &self,
        ctx: &RequestContext,
        collection: &ResourcePath,
        paths: Vec<ResourcePath>,
    ) -> AppResult<Vec<NotificationView>> {
        let ResourcePath::Notifications { tenant, principal } = collection else {
            return Err(AppError::not_found());
        };
        let most = usize::try_from(self.core.deps().limits.dav.max_multiget_hrefs).unwrap_or(usize::MAX);
        if paths.len() > most {
            return Err(AppError::forbidden().with_precondition(Precondition::NumberOfMatchesWithinLimits));
        }
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let home = resolve_home(tx.as_mut(), ctx, tenant, principal).await?;
        let facts = home_facts(&home.tenant, &home.principal);
        enforce(ctx, &facts, Operation::ReadNotifications, || collection.href())?;
        let uris: Vec<ObjectUri> = paths
            .iter()
            .filter_map(|path| match path {
                ResourcePath::Notification {
                    tenant: of_tenant,
                    principal: of_principal,
                    uri,
                } if of_tenant == tenant && of_principal == principal => Some(uri.clone()),
                _ => None,
            })
            .collect();
        let found = tx.notifications().get_many_by_uri(home.principal.id, &uris).await?;
        tx.commit().await?;
        Ok(found
            .iter()
            .map(|notification| notification_view(&home, notification))
            .collect())
    }

    async fn delete_notification(&self, ctx: &RequestContext, path: &ResourcePath) -> AppResult<()> {
        self.delete_notification_if(ctx, path, WritePrecondition::none()).await
    }

    async fn delete_notification_if(
        &self,
        ctx: &RequestContext,
        path: &ResourcePath,
        preconditions: WritePrecondition,
    ) -> AppResult<()> {
        let ResourcePath::Notification { tenant, principal, uri } = path else {
            return Err(AppError::not_found());
        };
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadWrite).await?;
        let home = resolve_home(tx.as_mut(), ctx, tenant, principal).await?;
        let facts = home_facts(&home.tenant, &home.principal);
        enforce(ctx, &facts, Operation::DeleteNotification, || path.href())?;
        let notification = tx.notifications().get_by_uri(home.principal.id, uri).await?;
        // The conditions are judged on the row this transaction deletes: an invitation that was rewritten after the
        // client read it has another entity tag by now.
        check_preconditions(&preconditions, &notification.etag)?;
        tx.notifications().delete(notification.id).await?;
        tx.commit().await?;
        Ok(())
    }
}
