//! The in-memory tables.
//!
//! The whole database is one [`State`]: a map of tenants, each with its own [`TenantData`] holding that tenant's
//! tables, plus the few things that live outside any tenant (system tokens and the audit log, which outlives the
//! tenant it describes, as in the PostgreSQL schema). A tenant transaction is only ever given the data of its own
//! tenant, so a repository method *cannot* reach another tenant's rows (`ENGINEERING_RULES` R4); the system
//! transaction iterates over all tenants for the cross-tenant operations.
//!
//! Rows are keyed by their typed id in `BTreeMap`s, so iteration is in id order, which is the order the port
//! promises for lists and pages. `State` is cloned when a read-write transaction begins (the snapshot a rollback
//! restores), so everything in it is plain `Clone` data.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use davhaven_domain::{
    ApiToken, AppPassword, Binding, BindingId, Calendar, CalendarId, CollectionKind, CredentialId, ExternalAccount,
    ExternalAccountId, FeedToken, Grant, GrantId, InboxItem, InboxItemId, Notification, NotificationId, ObjectId,
    ObjectUri, Principal, PrincipalId, RsvpToken, StoredObject, Tenant, TenantId, TokenId, WebhookId,
    WebhookSubscription,
};
use davhaven_ports::{
    AuditRow, ChangeKind, CollectionProperty, DeliveryRecord, IdempotencyRecord, OAuthState, ObjectAttendee,
    OutboxRecord, PrincipalAddress, SyncPosition,
};
use uuid::Uuid;

/// A value that is shared between a transaction's snapshot and the live state until someone writes to it.
///
/// A read-write transaction keeps a copy of the whole state to restore on rollback. Copying every row of every
/// tenant at every `begin` would make each transaction cost as much as the data is big; with [`Shared`] the copy
/// shares every table with the live state, and a table is duplicated only when a transaction first changes it
/// (`Arc::make_mut` through [`DerefMut`]). Reading never duplicates anything.
#[derive(Debug)]
pub(crate) struct Shared<T>(Arc<T>);

impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T: Default> Default for Shared<T> {
    fn default() -> Self {
        Self(Arc::new(T::default()))
    }
}

impl<T> Deref for Shared<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: Clone> DerefMut for Shared<T> {
    fn deref_mut(&mut self) -> &mut T {
        Arc::make_mut(&mut self.0)
    }
}

/// One entry of a collection's change log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChangeEntry {
    /// The sequence number of the change.
    pub(crate) seq: u64,
    /// The name of the member that changed.
    pub(crate) uri: ObjectUri,
    /// What happened to it.
    pub(crate) kind: ChangeKind,
    /// When it happened.
    pub(crate) at: DateTime<Utc>,
}

/// The sync state of the collections that belong to a principal (`principals_sync`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PrincipalSync {
    /// The calendar home.
    pub(crate) home: SyncPosition,
    /// The scheduling inbox.
    pub(crate) inbox: SyncPosition,
    /// The notification collection.
    pub(crate) notifications: SyncPosition,
}

impl PrincipalSync {
    /// The position of one of the three collections; `None` for a calendar, whose state is on the calendar.
    pub(crate) fn position(&self, kind: CollectionKind) -> Option<&SyncPosition> {
        match kind {
            CollectionKind::Home => Some(&self.home),
            CollectionKind::Inbox => Some(&self.inbox),
            CollectionKind::Notifications => Some(&self.notifications),
            CollectionKind::Calendar => None,
        }
    }

    /// Mutable access to the position of one of the three collections.
    pub(crate) fn position_mut(&mut self, kind: CollectionKind) -> Option<&mut SyncPosition> {
        match kind {
            CollectionKind::Home => Some(&mut self.home),
            CollectionKind::Inbox => Some(&mut self.inbox),
            CollectionKind::Notifications => Some(&mut self.notifications),
            CollectionKind::Calendar => None,
        }
    }
}

/// An idempotency key with the end of its in-flight lease (`None` once the key is done).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct IdempotencyEntry {
    /// The record as the port shows it.
    pub(crate) record: IdempotencyRecord,
    /// When the claimant's lease runs out; a claim may take the key over from then on.
    pub(crate) lease_until: Option<DateTime<Utc>>,
}

/// The change logs of a tenant by collection; each log is shared on its own, so appending to one does not copy the
/// others.
pub(crate) type ChangeLogs = BTreeMap<(CollectionKind, Uuid), Shared<Vec<ChangeEntry>>>;

/// The key of a collection property: calendar, binding (`None` = shared), namespace and name.
pub(crate) type PropertyKey = (CalendarId, Option<BindingId>, String, String);

/// The tables of one tenant.
#[derive(Debug, Clone, Default)]
pub(crate) struct TenantData {
    /// `principals`.
    pub(crate) principals: Shared<BTreeMap<PrincipalId, Principal>>,
    /// `principal_addresses`, per principal.
    pub(crate) addresses: Shared<BTreeMap<PrincipalId, Vec<PrincipalAddress>>>,
    /// `memberships` as `(group, member)`.
    pub(crate) memberships: Shared<BTreeSet<(PrincipalId, PrincipalId)>>,
    /// `principals_sync`.
    pub(crate) sync: Shared<BTreeMap<PrincipalId, PrincipalSync>>,
    /// `calendars` (soft-deleted ones included; they have `deleted_at` set).
    pub(crate) calendars: Shared<BTreeMap<CalendarId, Calendar>>,
    /// `calendar_bindings`.
    pub(crate) bindings: Shared<BTreeMap<BindingId, Binding>>,
    /// `collection_properties`.
    pub(crate) properties: Shared<BTreeMap<PropertyKey, CollectionProperty>>,
    /// `calendar_grants`.
    pub(crate) grants: Shared<BTreeMap<GrantId, Grant>>,
    /// `calendar_objects`.
    pub(crate) objects: Shared<BTreeMap<ObjectId, Arc<StoredObject>>>,
    /// `object_attendees`, per object.
    pub(crate) attendees: Shared<BTreeMap<ObjectId, Vec<ObjectAttendee>>>,
    /// `collection_changes`, per collection, in sequence order.
    pub(crate) changes: Shared<ChangeLogs>,
    /// `notifications`.
    pub(crate) notifications: Shared<BTreeMap<NotificationId, Notification>>,
    /// `scheduling_inbox`.
    pub(crate) inbox: Shared<BTreeMap<InboxItemId, InboxItem>>,
    /// `app_passwords`.
    pub(crate) app_passwords: Shared<BTreeMap<CredentialId, AppPassword>>,
    /// `api_tokens` of the tenant (system tokens live in [`State::system_tokens`]).
    pub(crate) api_tokens: Shared<BTreeMap<TokenId, ApiToken>>,
    /// `feed_tokens`.
    pub(crate) feed_tokens: Shared<BTreeMap<TokenId, FeedToken>>,
    /// `rsvp_tokens`.
    pub(crate) rsvp_tokens: Shared<BTreeMap<TokenId, RsvpToken>>,
    /// `outbox`.
    pub(crate) outbox: Shared<BTreeMap<davhaven_domain::OutboxId, OutboxRecord>>,
    /// `webhook_subscriptions`.
    pub(crate) webhooks: Shared<BTreeMap<WebhookId, WebhookSubscription>>,
    /// `webhook_deliveries`.
    pub(crate) deliveries: Shared<BTreeMap<davhaven_domain::DeliveryId, DeliveryRecord>>,
    /// `external_accounts`.
    pub(crate) external_accounts: Shared<BTreeMap<ExternalAccountId, ExternalAccount>>,
    /// `oauth_states`, by row id.
    pub(crate) oauth_states: Shared<BTreeMap<Uuid, OAuthState>>,
    /// `idempotency_keys`, by token and key.
    pub(crate) idempotency: Shared<BTreeMap<(TokenId, String), IdempotencyEntry>>,
}

/// A tenant with its tables.
#[derive(Debug, Clone)]
pub(crate) struct TenantEntry {
    /// The tenant row.
    pub(crate) tenant: Tenant,
    /// Everything that belongs to the tenant.
    pub(crate) data: TenantData,
}

/// The whole database.
#[derive(Debug, Clone, Default)]
pub(crate) struct State {
    /// The tenants.
    pub(crate) tenants: BTreeMap<TenantId, TenantEntry>,
    /// System tokens: tokens without a tenant.
    pub(crate) system_tokens: Shared<BTreeMap<TokenId, ApiToken>>,
    /// The audit log by tenant and row id. It has no foreign key to the tenant, so a deleted tenant's records
    /// stay until retention removes them.
    pub(crate) audit: Shared<BTreeMap<(TenantId, Uuid), AuditRow>>,
}

impl TenantData {
    /// Appends a change-log row and advances nothing: callers advance the sequence first and pass the result.
    pub(crate) fn log(&mut self, kind: CollectionKind, collection: Uuid, entry: ChangeEntry) {
        self.changes.entry((kind, collection)).or_default().push(entry);
    }

    /// Whether the live (not soft-deleted) calendar exists.
    pub(crate) fn calendar_is_live(&self, id: CalendarId) -> bool {
        self.calendars
            .get(&id)
            .is_some_and(|calendar| calendar.deleted_at.is_none())
    }

    /// Whether the object exists in a live calendar.
    pub(crate) fn object_is_live(&self, object: &StoredObject) -> bool {
        self.calendar_is_live(object.calendar_id)
    }

    /// The groups the principal currently belongs to, in id order.
    pub(crate) fn groups_of(&self, member: PrincipalId) -> Vec<PrincipalId> {
        self.memberships
            .iter()
            .filter(|(_, candidate)| *candidate == member)
            .map(|(group, _)| *group)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Removes a calendar and everything that hangs off it: objects (with attendees and RSVP tokens), bindings
    /// (with their properties), grants, shared properties, the change log and the mirror references of provider
    /// accounts.
    pub(crate) fn remove_calendar(&mut self, id: CalendarId) {
        self.calendars.remove(&id);
        let objects: Vec<ObjectId> = self
            .objects
            .values()
            .filter(|object| object.calendar_id == id)
            .map(|object| object.id)
            .collect();
        for object in objects {
            self.remove_object(object);
        }
        self.bindings.retain(|_, binding| binding.calendar_id != id);
        self.grants.retain(|_, grant| grant.calendar_id != id);
        self.properties.retain(|(calendar, _, _, _), _| *calendar != id);
        self.changes.remove(&(CollectionKind::Calendar, id.as_uuid()));
        for account in self.external_accounts.values_mut() {
            if account.mirror_calendar_id == Some(id) {
                account.mirror_calendar_id = None;
            }
        }
    }

    /// Removes one object with its attendees and RSVP tokens.
    pub(crate) fn remove_object(&mut self, id: ObjectId) {
        self.objects.remove(&id);
        self.attendees.remove(&id);
        self.rsvp_tokens.retain(|_, token| token.object_id != id);
    }

    /// Removes a binding and the properties private to it.
    pub(crate) fn remove_binding(&mut self, id: BindingId) {
        self.bindings.remove(&id);
        self.properties.retain(|(_, binding, _, _), _| *binding != Some(id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_copy_shares_a_table_until_somebody_writes_to_it() {
        let mut live: Shared<BTreeMap<u32, u32>> = Shared::default();
        live.insert(1, 10);
        let snapshot = live.clone();
        assert!(Arc::ptr_eq(&live.0, &snapshot.0), "a copy shares the table");
        assert_eq!(live.get(&1), Some(&10));
        assert!(Arc::ptr_eq(&live.0, &snapshot.0), "reading does not copy it");

        live.insert(2, 20);
        assert!(!Arc::ptr_eq(&live.0, &snapshot.0), "the first write copies the table");
        assert_eq!(
            (live.len(), snapshot.len()),
            (2, 1),
            "and the snapshot keeps what it had"
        );
        let before = Arc::as_ptr(&live.0);
        live.insert(3, 30);
        assert_eq!(
            Arc::as_ptr(&live.0),
            before,
            "later writes find the table unshared and copy nothing"
        );
    }

    #[test]
    fn a_state_copy_shares_the_tables_of_its_tenants_and_the_system_tables() {
        // The snapshot of a read-write transaction is a copy of the whole state: it must share the tables of every
        // tenant in it, not only those of an empty state.
        let tenant = TenantId::from_uuid(Uuid::nil());
        let mut state = State::default();
        state.audit.insert((tenant, Uuid::nil()), audit_row());
        let mut data = TenantData::default();
        data.log(
            CollectionKind::Home,
            Uuid::nil(),
            ChangeEntry {
                seq: 1,
                uri: ObjectUri::parse("a.ics").unwrap(),
                kind: ChangeKind::Upsert,
                at: DateTime::UNIX_EPOCH,
            },
        );
        state.tenants.insert(
            tenant,
            TenantEntry {
                tenant: tenant_row(tenant),
                data,
            },
        );
        let copy = state.clone();
        assert!(Arc::ptr_eq(&state.audit.0, &copy.audit.0));
        assert!(Arc::ptr_eq(&state.system_tokens.0, &copy.system_tokens.0));
        let (live, copied) = (&state.tenants[&tenant].data, &copy.tenants[&tenant].data);
        assert!(Arc::ptr_eq(&live.changes.0, &copied.changes.0));
        let log = &(CollectionKind::Home, Uuid::nil());
        assert!(
            Arc::ptr_eq(&live.changes[log].0, &copied.changes[log].0),
            "a log is shared on its own"
        );
        assert!(Arc::ptr_eq(&live.objects.0, &copied.objects.0));
        assert!(Arc::ptr_eq(&live.principals.0, &copied.principals.0));
        assert!(Arc::ptr_eq(&live.outbox.0, &copied.outbox.0));
    }

    fn tenant_row(id: TenantId) -> Tenant {
        Tenant {
            id,
            slug: davhaven_domain::TenantSlug::parse("acme").unwrap(),
            display_name: "Acme".to_owned(),
            login_domain: None,
            status: davhaven_domain::TenantStatus::Active,
            settings: davhaven_domain::TenantSettings::default(),
            created_at: DateTime::UNIX_EPOCH,
            updated_at: DateTime::UNIX_EPOCH,
            version: 1,
        }
    }

    fn audit_row() -> AuditRow {
        AuditRow {
            id: Uuid::nil(),
            tenant_id: TenantId::from_uuid(Uuid::nil()),
            at: DateTime::UNIX_EPOCH,
            actor: davhaven_domain::AuditActor::system(),
            action: "tenant.created".to_owned(),
            target: None,
            details: serde_json::Value::Null,
        }
    }
}
