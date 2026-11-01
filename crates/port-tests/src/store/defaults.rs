//! A store that forwards only the methods the port requires, so that the default bodies of its additive methods run.
//!
//! The batch reads of the repositories (`find_for_calendars`, `list_many`, `for_calendars`, `get_many_by_name`,
//! `addresses_many`, `members_of_many`, `groups_of_many`, the `get_many_by_uri` of notifications and of the inbox, and
//! the defaults of `find_by_addresses` and `get_many`) were added to the port with a default body that asks the single
//! read once per item. Both adapters of this repository override every one of them with a read of their own, so the default bodies are what **any other adapter** gets
//! (`ENGINEERING_RULES` R2) and nothing else runs them. They encode the contract points that are easy to get wrong: a
//! repeated key counts once, the order of the answer, a missing parent is skipped.
//!
//! [`required_methods_only`] wraps a database so that every repository answers the required methods through the
//! wrapped store and leaves the additive batch reads to their defaults. The batch cases of the suite, which compare each
//! batch read with the single reads, then run through it on an adapter and check the defaults against the same
//! expectations as the override.

use std::sync::Arc;

use async_trait::async_trait;
use davhaven_domain::{
    Binding, BindingId, CalendarId, CalendarSlug, CalendarUserAddress, Grant, GrantId, InboxItem, InboxItemId,
    Notification, NotificationId, ObjectUri, Principal, PrincipalId, PrincipalName, TenantId, Uid,
};
use davhaven_ports::{
    AuditRepo, BindingRepo, BoundCalendar, CalendarRepo, ChangeRepo, CollectionProperty, CredentialRepo, Database,
    ExternalAccountRepo, GrantRepo, Health, IdempotencyRepo, InboxRepo, InboxScope, MembershipDiff, MembershipRepo,
    NotificationRepo, OAuthStateRepo, ObjectRepo, OutboxRepo, PageReq, PrincipalAddress, PrincipalFilter,
    PrincipalMatch, PrincipalQuery, PrincipalRepo, PropertyRepo, PropertyScope, RsvpRepo, StoreError, StorePage,
    SystemTx, TenantRepo, Tx, TxMode, WebhookRepo,
};

/// Wraps `inner` so that the additive methods of the repositories are answered by their default bodies.
pub fn required_methods_only(inner: Arc<dyn Database>) -> Arc<dyn Database> {
    Arc::new(RequiredOnly { inner })
}

/// The wrapped database.
struct RequiredOnly {
    inner: Arc<dyn Database>,
}

#[async_trait]
impl Database for RequiredOnly {
    async fn begin(&self, tenant: TenantId, mode: TxMode) -> Result<Box<dyn Tx>, StoreError> {
        let inner = self.inner.begin(tenant, mode).await?;
        Ok(Box::new(RequiredOnlyTx { inner }))
    }

    async fn begin_system(&self) -> Result<Box<dyn SystemTx>, StoreError> {
        self.inner.begin_system().await
    }

    async fn health(&self) -> Health {
        self.inner.health().await
    }
}

/// A transaction of the wrapped database: the repositories with additive methods are this value itself, which
/// implements their required methods only.
struct RequiredOnlyTx {
    inner: Box<dyn Tx>,
}

#[async_trait]
impl Tx for RequiredOnlyTx {
    fn tenant_id(&self) -> TenantId {
        self.inner.tenant_id()
    }

    fn tenant(&mut self) -> &mut dyn TenantRepo {
        self.inner.tenant()
    }

    fn principals(&mut self) -> &mut dyn PrincipalRepo {
        self
    }

    fn memberships(&mut self) -> &mut dyn MembershipRepo {
        self
    }

    fn calendars(&mut self) -> &mut dyn CalendarRepo {
        self.inner.calendars()
    }

    fn bindings(&mut self) -> &mut dyn BindingRepo {
        self
    }

    fn properties(&mut self) -> &mut dyn PropertyRepo {
        self
    }

    fn grants(&mut self) -> &mut dyn GrantRepo {
        self
    }

    fn objects(&mut self) -> &mut dyn ObjectRepo {
        self.inner.objects()
    }

    fn changes(&mut self) -> &mut dyn ChangeRepo {
        self.inner.changes()
    }

    fn notifications(&mut self) -> &mut dyn NotificationRepo {
        self
    }

    fn inbox(&mut self) -> &mut dyn InboxRepo {
        self
    }

    fn credentials(&mut self) -> &mut dyn CredentialRepo {
        self.inner.credentials()
    }

    fn rsvp(&mut self) -> &mut dyn RsvpRepo {
        self.inner.rsvp()
    }

    fn outbox(&mut self) -> &mut dyn OutboxRepo {
        self.inner.outbox()
    }

    fn webhooks(&mut self) -> &mut dyn WebhookRepo {
        self.inner.webhooks()
    }

    fn external_accounts(&mut self) -> &mut dyn ExternalAccountRepo {
        self.inner.external_accounts()
    }

    fn oauth_states(&mut self) -> &mut dyn OAuthStateRepo {
        self.inner.oauth_states()
    }

    fn idempotency(&mut self) -> &mut dyn IdempotencyRepo {
        self.inner.idempotency()
    }

    fn audit(&mut self) -> &mut dyn AuditRepo {
        self.inner.audit()
    }

    async fn commit(self: Box<Self>) -> Result<(), StoreError> {
        self.inner.commit().await
    }
}

#[async_trait]
impl PrincipalRepo for RequiredOnlyTx {
    async fn get(&mut self, id: PrincipalId) -> Result<Principal, StoreError> {
        self.inner.principals().get(id).await
    }

    async fn get_by_name(&mut self, name: &PrincipalName) -> Result<Principal, StoreError> {
        self.inner.principals().get_by_name(name).await
    }

    async fn find_by_external_ref(&mut self, external_ref: &str) -> Result<Option<Principal>, StoreError> {
        self.inner.principals().find_by_external_ref(external_ref).await
    }

    async fn find_by_address(&mut self, address: &CalendarUserAddress) -> Result<Option<Principal>, StoreError> {
        self.inner.principals().find_by_address(address).await
    }

    async fn list(&mut self, filter: &PrincipalFilter, page: PageReq) -> Result<StorePage<Principal>, StoreError> {
        self.inner.principals().list(filter, page).await
    }

    async fn search(&mut self, query: &PrincipalQuery) -> Result<Vec<PrincipalMatch>, StoreError> {
        self.inner.principals().search(query).await
    }

    async fn create(&mut self, principal: Principal) -> Result<Principal, StoreError> {
        self.inner.principals().create(principal).await
    }

    async fn update(&mut self, principal: Principal, expected_version: i64) -> Result<Principal, StoreError> {
        self.inner.principals().update(principal, expected_version).await
    }

    async fn bump_credential_generation(&mut self, id: PrincipalId) -> Result<i32, StoreError> {
        self.inner.principals().bump_credential_generation(id).await
    }

    async fn addresses(&mut self, id: PrincipalId) -> Result<Vec<PrincipalAddress>, StoreError> {
        self.inner.principals().addresses(id).await
    }

    async fn set_addresses(&mut self, id: PrincipalId, addresses: Vec<PrincipalAddress>) -> Result<(), StoreError> {
        self.inner.principals().set_addresses(id, addresses).await
    }

    async fn purge(&mut self, id: PrincipalId) -> Result<(), StoreError> {
        self.inner.principals().purge(id).await
    }
}

#[async_trait]
impl MembershipRepo for RequiredOnlyTx {
    async fn members(&mut self, group: PrincipalId) -> Result<Vec<PrincipalId>, StoreError> {
        self.inner.memberships().members(group).await
    }

    async fn groups_of(&mut self, member: PrincipalId) -> Result<Vec<PrincipalId>, StoreError> {
        self.inner.memberships().groups_of(member).await
    }

    async fn set_members(&mut self, group: PrincipalId, members: &[PrincipalId]) -> Result<MembershipDiff, StoreError> {
        self.inner.memberships().set_members(group, members).await
    }

    async fn add_member(&mut self, group: PrincipalId, member: PrincipalId) -> Result<bool, StoreError> {
        self.inner.memberships().add_member(group, member).await
    }

    async fn remove_member(&mut self, group: PrincipalId, member: PrincipalId) -> Result<bool, StoreError> {
        self.inner.memberships().remove_member(group, member).await
    }
}

#[async_trait]
impl BindingRepo for RequiredOnlyTx {
    async fn get(&mut self, id: BindingId) -> Result<Binding, StoreError> {
        self.inner.bindings().get(id).await
    }

    async fn get_by_slug(&mut self, principal: PrincipalId, slug: &CalendarSlug) -> Result<Binding, StoreError> {
        self.inner.bindings().get_by_slug(principal, slug).await
    }

    async fn find_for_calendar(
        &mut self,
        principal: PrincipalId,
        calendar: CalendarId,
    ) -> Result<Option<Binding>, StoreError> {
        self.inner.bindings().find_for_calendar(principal, calendar).await
    }

    async fn list_for(&mut self, principal: PrincipalId) -> Result<Vec<BoundCalendar>, StoreError> {
        self.inner.bindings().list_for(principal).await
    }

    async fn list_for_calendar(&mut self, calendar: CalendarId) -> Result<Vec<Binding>, StoreError> {
        self.inner.bindings().list_for_calendar(calendar).await
    }

    async fn create(&mut self, binding: Binding) -> Result<Binding, StoreError> {
        self.inner.bindings().create(binding).await
    }

    async fn update(&mut self, binding: Binding, expected_version: i64) -> Result<Binding, StoreError> {
        self.inner.bindings().update(binding, expected_version).await
    }

    async fn delete(&mut self, id: BindingId) -> Result<(), StoreError> {
        self.inner.bindings().delete(id).await
    }
}

#[async_trait]
impl PropertyRepo for RequiredOnlyTx {
    async fn list(
        &mut self,
        calendar: CalendarId,
        scope: PropertyScope,
    ) -> Result<Vec<CollectionProperty>, StoreError> {
        self.inner.properties().list(calendar, scope).await
    }

    async fn get(
        &mut self,
        calendar: CalendarId,
        scope: PropertyScope,
        ns: &str,
        name: &str,
    ) -> Result<Option<CollectionProperty>, StoreError> {
        self.inner.properties().get(calendar, scope, ns, name).await
    }

    async fn set(&mut self, property: CollectionProperty) -> Result<(), StoreError> {
        self.inner.properties().set(property).await
    }

    async fn remove(
        &mut self,
        calendar: CalendarId,
        scope: PropertyScope,
        ns: &str,
        name: &str,
    ) -> Result<bool, StoreError> {
        self.inner.properties().remove(calendar, scope, ns, name).await
    }

    async fn count(&mut self, calendar: CalendarId, scope: PropertyScope) -> Result<u64, StoreError> {
        self.inner.properties().count(calendar, scope).await
    }
}

#[async_trait]
impl GrantRepo for RequiredOnlyTx {
    async fn get(&mut self, id: GrantId) -> Result<Grant, StoreError> {
        self.inner.grants().get(id).await
    }

    async fn find(&mut self, calendar: CalendarId, grantee: PrincipalId) -> Result<Option<Grant>, StoreError> {
        self.inner.grants().find(calendar, grantee).await
    }

    async fn find_by_invite_uid(&mut self, uid: &Uid) -> Result<Option<Grant>, StoreError> {
        self.inner.grants().find_by_invite_uid(uid).await
    }

    async fn for_calendar(&mut self, calendar: CalendarId) -> Result<Vec<Grant>, StoreError> {
        self.inner.grants().for_calendar(calendar).await
    }

    async fn for_grantee(&mut self, grantee: PrincipalId) -> Result<Vec<Grant>, StoreError> {
        self.inner.grants().for_grantee(grantee).await
    }

    async fn create(&mut self, grant: Grant) -> Result<Grant, StoreError> {
        self.inner.grants().create(grant).await
    }

    async fn update(&mut self, grant: Grant, expected_version: i64) -> Result<Grant, StoreError> {
        self.inner.grants().update(grant, expected_version).await
    }

    async fn delete(&mut self, id: GrantId) -> Result<(), StoreError> {
        self.inner.grants().delete(id).await
    }
}

#[async_trait]
impl NotificationRepo for RequiredOnlyTx {
    async fn get(&mut self, id: NotificationId) -> Result<Notification, StoreError> {
        self.inner.notifications().get(id).await
    }

    async fn get_by_uri(&mut self, principal: PrincipalId, uri: &ObjectUri) -> Result<Notification, StoreError> {
        self.inner.notifications().get_by_uri(principal, uri).await
    }

    async fn find_by_uid(&mut self, principal: PrincipalId, uid: &Uid) -> Result<Option<Notification>, StoreError> {
        self.inner.notifications().find_by_uid(principal, uid).await
    }

    async fn list(&mut self, principal: PrincipalId) -> Result<Vec<Notification>, StoreError> {
        self.inner.notifications().list(principal).await
    }

    async fn create(&mut self, notification: Notification) -> Result<Notification, StoreError> {
        self.inner.notifications().create(notification).await
    }

    async fn update(&mut self, notification: Notification, expected_version: i64) -> Result<Notification, StoreError> {
        self.inner.notifications().update(notification, expected_version).await
    }

    async fn delete(&mut self, id: NotificationId) -> Result<(), StoreError> {
        self.inner.notifications().delete(id).await
    }
}

#[async_trait]
impl InboxRepo for RequiredOnlyTx {
    async fn get(&mut self, id: InboxItemId) -> Result<InboxItem, StoreError> {
        self.inner.inbox().get(id).await
    }

    async fn get_by_uri(&mut self, principal: PrincipalId, uri: &ObjectUri) -> Result<InboxItem, StoreError> {
        self.inner.inbox().get_by_uri(principal, uri).await
    }

    async fn list(&mut self, principal: PrincipalId, scope: InboxScope) -> Result<Vec<InboxItem>, StoreError> {
        self.inner.inbox().list(principal, scope).await
    }

    async fn create(&mut self, item: InboxItem) -> Result<InboxItem, StoreError> {
        self.inner.inbox().create(item).await
    }

    async fn delete(&mut self, id: InboxItemId) -> Result<(), StoreError> {
        self.inner.inbox().delete(id).await
    }
}
