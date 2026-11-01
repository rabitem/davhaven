//! Audit event recording and listing.
//!
//! Security-relevant changes write their audit record **in the transaction of the change** (`Journal::audit`), so a
//! change that is rolled back leaves no record and a change that commits always has one. The same goes for the
//! domain events of PLAN 2.11: `Journal::publish` writes the `OutboxMessage::DomainEvent` into the outbox of the
//! transaction, and the dispatcher fans it out after the commit.
//!
//! The two tenant events of the system scope (a tenant is created and changed in a system transaction) are appended in
//! that transaction too (`Journal::audit_system`).
//!
//! Audit records carry ids, kinds and counters only (PLAN 2.18); the client address is stored as a keyed hash that is
//! bound to the tenant, and the label of the credential the request used (a token's label, the device name of an app
//! password) tells operators which integration acted. Domain events carry neither: their consumers are third parties
//! (webhook endpoints), and a stable hash of a client address must not reach them.
//! [`AuditServiceImpl`] lists the records of the tenant for `GET …/audit-events`.

use std::fmt::Write as _;

use async_trait::async_trait;
use davhaven_domain::RequestContext;
use davhaven_domain::{
    AdminOperation, AuditActor, AuditEvent, CredentialId, CredentialKind, Envelope, EventId, EventPayload, EventType,
    OutboxId, TenantId, TokenId,
};
use davhaven_ports::{AuditFilter as StoreAuditFilter, SystemTx, Tx};
use davhaven_ports::{KeyPurpose, NewAudit, NewOutbox, NewTenantAudit, OutboxMessage, PageReq, TenantAudit, TxMode};
use davhaven_wire::{AuditEventView, Page};

use crate::authz::{admin, field_error};
use crate::error::{AppError, AppResult};
use crate::paging;
use crate::services::{AuditFilter, AuditService, PageRequest};
use crate::wiring::AppCore;

/// The listing name that binds cursors to the audit log.
const LISTING: &str = "audit";

/// The longest `action` or `target` filter.
const MAX_FILTER_CHARS: usize = 200;

/// Writes audit records and domain events into the transaction of a change.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Journal<'a> {
    core: &'a AppCore,
    ctx: &'a RequestContext,
}

impl<'a> Journal<'a> {
    /// A journal for the request `ctx`.
    pub(crate) const fn new(core: &'a AppCore, ctx: &'a RequestContext) -> Self {
        Self { core, ctx }
    }

    /// The actor of the request as audit records show it: kinds and ids, the label of the credential when the caller
    /// knows it, plus a keyed hash of the client address (bound to the tenant), never the address itself.
    pub(crate) fn actor(&self, label: Option<String>) -> AuditActor {
        self.actor_in(self.ctx.tenant, label)
    }

    /// [`actor`](Self::actor) for a record of the log of `tenant`, which the hash of the client address is bound to.
    /// It is not the tenant of the request when a request of the system scope writes into the log of another tenant
    /// (the system context has no tenant of its own), and the same address must not have the same hash in every log.
    fn actor_in(&self, tenant: TenantId, label: Option<String>) -> AuditActor {
        let ip_hash = self.ctx.client_ip.map(|ip| {
            let mac = self
                .core
                .deps()
                .keyring
                .sign(
                    KeyPurpose::CacheKey,
                    format!("davhaven/audit-ip/v2/{tenant}/{ip}").as_bytes(),
                )
                .mac;
            let mut hex = String::with_capacity(16);
            for byte in mac.iter().take(8) {
                // Writing into a `String` cannot fail.
                let _ = write!(hex, "{byte:02x}");
            }
            hex
        });
        AuditActor::from_context(self.ctx, label, ip_hash)
    }

    /// The label of the credential the request authenticated with, read in the transaction: the name of an app
    /// password or the label of an API token. Feed and RSVP credentials have none. A label that cannot be read is
    /// left out; it is information for operators, not a reason to fail the change.
    async fn label(&self, tx: &mut dyn Tx) -> Option<String> {
        let credential = self.ctx.credential?;
        match credential.kind {
            CredentialKind::AppPassword => tx
                .credentials()
                .get_app_password(CredentialId::from_uuid(credential.id))
                .await
                .ok()
                .map(|password| password.label),
            CredentialKind::ApiToken => tx
                .credentials()
                .get_api_token(TokenId::from_uuid(credential.id))
                .await
                .ok()
                .map(|token| token.label),
            CredentialKind::FeedToken | CredentialKind::RsvpToken => None,
        }
    }

    /// Appends an audit record to the transaction.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub(crate) async fn audit(&self, tx: &mut dyn Tx, event: AuditEvent) -> AppResult<()> {
        let label = self.label(tx).await;
        tx.audit()
            .append(NewAudit {
                id: self.core.deps().ids.new_id(),
                actor: self.actor(label),
                event,
            })
            .await?;
        Ok(())
    }

    /// Appends an audit record about `tenant` to a **system** transaction (`SystemTenantRepo::append_audit`), for the
    /// changes that are made across tenants and so have no transaction of the tenant: its creation and the change of
    /// its settings. The record commits with the change. The actor carries no credential label (the credential of such
    /// a request is a system token, which no tenant owns) and the hash of the client address is bound to `tenant`, the
    /// owner of the log the record goes to, as for every other record of it.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub(crate) async fn audit_system(
        &self,
        tx: &mut dyn SystemTx,
        tenant: TenantId,
        event: TenantAudit,
    ) -> AppResult<()> {
        tx.tenants()
            .append_audit(
                tenant,
                NewTenantAudit {
                    id: self.core.deps().ids.new_id(),
                    actor: self.actor_in(tenant, None),
                    event,
                },
            )
            .await?;
        Ok(())
    }

    /// Writes a domain event into the outbox of the transaction. After the commit the dispatcher delivers it to
    /// the event sinks and the webhook subscriptions.
    ///
    /// # Errors
    ///
    /// Store failures; `Internal` when the payload does not fit the event type (a bug).
    pub(crate) async fn publish(&self, tx: &mut dyn Tx, event_type: EventType, payload: EventPayload) -> AppResult<()> {
        let deps = self.core.deps();
        let envelope = Envelope::new(
            EventId::from_uuid(deps.ids.new_id()),
            event_type,
            self.ctx.tenant,
            deps.clock.now(),
            // No label and no address hash: the consumers of events are third parties.
            AuditActor::from_context(self.ctx, None, None),
            payload,
        )
        .map_err(AppError::internal)?;
        tx.outbox()
            .enqueue(NewOutbox::now(
                OutboxId::from_uuid(deps.ids.new_id()),
                OutboxMessage::DomainEvent(envelope),
            ))
            .await?;
        Ok(())
    }
}

/// The [`AuditService`] of the application.
#[derive(Debug, Clone)]
pub struct AuditServiceImpl {
    core: AppCore,
}

impl AuditServiceImpl {
    /// Creates the service on the shared application core.
    pub fn new(core: AppCore) -> Self {
        Self { core }
    }

    /// The shared application core: ports, configuration and limits.
    pub fn core(&self) -> &AppCore {
        &self.core
    }
}

/// Whether a filter text is unusable: too long or with control characters.
fn unusable(text: &str) -> bool {
    text.chars().count() > MAX_FILTER_CHARS || text.chars().any(char::is_control)
}

/// Checks the filter and turns it into the filter of the store.
fn store_filter(filter: &AuditFilter) -> AppResult<StoreAuditFilter> {
    let message = "The filter is too long or contains control characters.";
    if filter.action.as_deref().is_some_and(unusable) {
        return Err(field_error("/action", "invalid", message));
    }
    if filter.target.as_deref().is_some_and(unusable) {
        return Err(field_error("/target", "invalid", message));
    }
    if let (Some(since), Some(until)) = (filter.since, filter.until)
        && until < since
    {
        return Err(field_error(
            "/until",
            "before-since",
            "`until` must not be before `since`.",
        ));
    }
    Ok(StoreAuditFilter {
        action: filter.action.clone(),
        since: filter.since,
        until: filter.until,
        principal: None,
        target: filter.target.clone(),
    })
}

#[async_trait]
impl AuditService for AuditServiceImpl {
    async fn list(
        &self,
        ctx: &RequestContext,
        filter: AuditFilter,
        page: PageRequest,
    ) -> AppResult<Page<AuditEventView>> {
        admin(ctx, AdminOperation::ListAuditEvents)?;
        let store_filter = store_filter(&filter)?;
        let request: PageReq = paging::page_request(&self.core, ctx, LISTING, &page)?;
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let rows = tx.audit().list(&store_filter, request).await?;
        tx.commit().await?;
        let next = paging::next_cursor(&self.core, ctx, LISTING, rows.next)?;
        let items = rows
            .items
            .into_iter()
            .map(|row| AuditEventView {
                id: row.id,
                at: row.at,
                actor: row.actor,
                action: row.action,
                target: row.target,
                details: row.details,
            })
            .collect();
        Ok(Page::new(items, next))
    }
}
