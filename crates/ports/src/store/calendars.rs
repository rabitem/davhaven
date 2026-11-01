//! Repositories for calendars, bindings, collection properties and grants.

use std::collections::BTreeSet;

use async_trait::async_trait;
use davhaven_domain::{
    AccessFacts, Binding, BindingId, Calendar, CalendarId, CalendarKind, CalendarSlug, Grant, GrantId, PrincipalId, Uid,
};

use super::{PageReq, StorePage};
use crate::error::StoreError;

/// Filter of [`CalendarRepo::list`] (tenant-wide calendar search). Every set field must match.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CalendarFilter {
    /// Only calendars of this owner.
    pub owner: Option<PrincipalId>,
    /// Only calendars of this kind.
    pub kind: Option<CalendarKind>,
    /// Only calendars with this slug.
    pub slug: Option<CalendarSlug>,
    /// Only calendars whose display name contains the text, case-insensitively.
    pub text: Option<String>,
}

/// Calendars of the transaction's tenant.
///
/// Every write that changes what clients see of the calendar itself (create, update, soft delete) advances the
/// calendar's `sync_seq`; object writes do so through [`ObjectRepo`](super::ObjectRepo).
#[async_trait]
pub trait CalendarRepo: Send {
    /// The live calendar with `id`.
    ///
    /// # Errors
    ///
    /// `NotFound`, also for soft-deleted calendars.
    async fn get(&mut self, id: CalendarId) -> Result<Calendar, StoreError>;

    /// The live calendars with the given ids, in id order; unknown, foreign and deleted ids are skipped. One query
    /// instead of one per id.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn get_many(&mut self, ids: &[CalendarId]) -> Result<Vec<Calendar>, StoreError>;

    /// The live calendar of `owner` with `slug`.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn get_by_slug(&mut self, owner: PrincipalId, slug: &CalendarSlug) -> Result<Calendar, StoreError>;

    /// All live calendars owned by `owner`, in id order.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn list_owned(&mut self, owner: PrincipalId) -> Result<Vec<Calendar>, StoreError>;

    /// Searches the live calendars of the tenant in id order.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn list(&mut self, filter: &CalendarFilter, page: PageReq) -> Result<StorePage<Calendar>, StoreError>;

    /// Calendars the principal can see but has no binding for yet: calendars of groups the principal belongs to and
    /// calendars with an accepted grant to the principal or to one of the principal's groups, excluding calendars the
    /// principal owns and calendars with an existing binding (hidden ones included). The application creates the
    /// bindings lazily on the first home listing.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn visible_without_binding(&mut self, principal: PrincipalId) -> Result<Vec<Calendar>, StoreError>;

    /// Loads everything [`decide`](davhaven_domain::decide) needs about one calendar in one query: kind, owner and
    /// owner kind, the caller's group memberships, the calendar's grants, the caller's binding and the tenant
    /// settings. `principal` is the principal the request acts as; actors without a principal (tenant tokens) get no
    /// memberships and no binding.
    ///
    /// # Errors
    ///
    /// `NotFound` when the calendar does not exist in the tenant.
    async fn access_facts(
        &mut self,
        calendar: CalendarId,
        principal: Option<PrincipalId>,
    ) -> Result<AccessFacts, StoreError>;

    /// [`CalendarRepo::access_facts`] for several calendars at once (home listings), in the order of `calendars`.
    /// Calendars that do not exist are skipped.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn access_facts_many(
        &mut self,
        calendars: &[CalendarId],
        principal: Option<PrincipalId>,
    ) -> Result<Vec<(CalendarId, AccessFacts)>, StoreError>;

    /// Creates a calendar with `sync_seq` 0, `sync_min_seq` 0 and the `sync_epoch` of the entity.
    ///
    /// # Errors
    ///
    /// `NotFound` when the owner does not exist and `UniqueViolation` of `CalendarSlug`.
    async fn create(&mut self, calendar: Calendar) -> Result<Calendar, StoreError>;

    /// Replaces the mutable columns (display name, description, color, sort order, components, time zone) if the
    /// stored version equals `expected_version`; slug, kind, owner and the sync columns never change. Advances
    /// `sync_seq`.
    ///
    /// # Errors
    ///
    /// `NotFound` and `PreconditionFailed`.
    async fn update(&mut self, calendar: Calendar, expected_version: i64) -> Result<Calendar, StoreError>;

    /// Soft-deletes the calendar (sets `deleted_at`) if the stored version equals `expected_version`, as one unit
    /// that the store enforces (no caller can forget a part of it):
    ///
    /// * the calendar's objects stop being visible, the calendar's `sync_seq` advances;
    /// * **every binding of the calendar is deleted** (the owner's and every sharee's, with the properties private
    ///   to them) and each affected principal's home change log gets a `delete` entry named after the binding's
    ///   slug, with the home sequence advanced, exactly as [`BindingRepo::delete`] does. The slug of the owner's
    ///   binding is therefore free for reuse together with the calendar's own, and clients that sync a home see
    ///   the collection disappear;
    /// * grants stay until the purge (they have no client-visible state of their own).
    ///
    /// The application needs no [`BindingRepo::list_for_calendar`] pass before deleting (it would answer `NotFound`
    /// afterwards anyway).
    ///
    /// The update of the calendar's object rows (`live = false`) is as large as the calendar. The PostgreSQL
    /// adapter runs it under its maintenance timeout (`database.maintenance_timeout`), not the request's statement
    /// timeout, and holds the calendar's row lock for that long: writers of the calendar queue (and answer
    /// `Timeout` after the lock wait), which is acceptable for a calendar that is being deleted.
    ///
    /// # Errors
    ///
    /// `NotFound` and `PreconditionFailed`.
    async fn soft_delete(&mut self, id: CalendarId, expected_version: i64) -> Result<(), StoreError>;

    /// Locks the calendars for the rest of the transaction (a row lock that conflicts with other writers of the
    /// calendar and with this method, but not with readers, nor with inserts that merely reference the calendar,
    /// such as a new binding or grant; `SELECT ... FOR NO KEY UPDATE` in ascending id order, so concurrent callers
    /// cannot deadlock) and returns them with their current sync state. Callers that touch more than one calendar
    /// lock them all first. Needs a read-write transaction.
    ///
    /// # Errors
    ///
    /// `NotFound` when any calendar does not exist; `Internal` in a read-only transaction.
    async fn lock(&mut self, ids: &[CalendarId]) -> Result<Vec<Calendar>, StoreError>;

    /// Advances the calendar's `sync_seq` by one without changing any object, so its `CTag` changes. The application
    /// calls it for collection property, sharing and binding changes. Returns the new sequence number.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn touch(&mut self, id: CalendarId) -> Result<u64, StoreError>;

    /// Removes a soft-deleted calendar and its objects, changes, bindings, grants and properties for good
    /// (retention purge).
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn purge(&mut self, id: CalendarId) -> Result<(), StoreError>;
}

/// A binding together with the calendar it points to.
#[derive(Debug, Clone, PartialEq)]
pub struct BoundCalendar {
    /// The binding.
    pub binding: Binding,
    /// The live calendar.
    pub calendar: Calendar,
}

/// Bindings: the calendars listed in a principal's home.
///
/// `create`, `update` and `delete` advance the home collection's sequence of the binding's principal (the home
/// change log), so clients that sync the home notice them.
#[async_trait]
pub trait BindingRepo: Send {
    /// The binding with `id`.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn get(&mut self, id: BindingId) -> Result<Binding, StoreError>;

    /// The binding of `principal` with the collection `slug`.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn get_by_slug(&mut self, principal: PrincipalId, slug: &CalendarSlug) -> Result<Binding, StoreError>;

    /// The binding of `principal` for `calendar`, if there is one (hidden bindings included).
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn find_for_calendar(
        &mut self,
        principal: PrincipalId,
        calendar: CalendarId,
    ) -> Result<Option<Binding>, StoreError>;

    /// All bindings of `principal` with their live calendars, hidden ones included, in binding id order. Bindings
    /// of soft-deleted calendars are skipped.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn list_for(&mut self, principal: PrincipalId) -> Result<Vec<BoundCalendar>, StoreError>;

    /// All bindings of one calendar, in id order.
    ///
    /// # Errors
    ///
    /// `NotFound` when the calendar does not exist.
    async fn list_for_calendar(&mut self, calendar: CalendarId) -> Result<Vec<Binding>, StoreError>;

    /// [`find_for_calendar`](Self::find_for_calendar) for several `(principal, calendar)` pairs at once: the bindings
    /// that exist (hidden ones included), in ascending order of calendar id and then principal id. Pairs without a
    /// binding are skipped and a pair that is repeated counts once. A home listing uses it to find the collection under
    /// which the owner of each calendar lists it (where a sharee's `shared-url` points). Additive method: the default
    /// asks [`find_for_calendar`](Self::find_for_calendar) once per pair; an adapter that can read them in one query
    /// overrides it (`ENGINEERING_RULES` R14).
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn find_for_calendars(&mut self, pairs: &[(PrincipalId, CalendarId)]) -> Result<Vec<Binding>, StoreError> {
        // Each distinct pair once, in the order of the answer: by calendar id and then principal id.
        let wanted: BTreeSet<(CalendarId, PrincipalId)> = pairs
            .iter()
            .map(|(principal, calendar)| (*calendar, *principal))
            .collect();
        let mut found: Vec<Binding> = Vec::with_capacity(wanted.len());
        for (calendar, principal) in wanted {
            if let Some(binding) = self.find_for_calendar(principal, calendar).await? {
                found.push(binding);
            }
        }
        Ok(found)
    }

    /// Creates a binding.
    ///
    /// **Take [`CalendarRepo::lock`] first** when the calendar may be deleted at the same time. The existence check
    /// of this method is an unlocked read, and the lock of the soft delete (`FOR NO KEY UPDATE`) does not conflict
    /// with the `KEY SHARE` lock the new row's foreign key takes, so without the calendar lock a concurrent
    /// [`CalendarRepo::soft_delete`] can commit between the check and this write and leave the new row pointing at
    /// a deleted calendar (a binding would then keep its slug occupied and its home would never log the change).
    /// With the lock held, the soft delete waits and then removes the row as part of "every binding of the
    /// calendar". The application takes the lock anyway to `touch` the calendar after such a change.
    ///
    /// # Errors
    ///
    /// `NotFound` when the principal or the calendar does not exist and `UniqueViolation` of `BindingSlug` or
    /// `BindingCalendar`.
    async fn create(&mut self, binding: Binding) -> Result<Binding, StoreError>;

    /// Replaces the overrides (display name, color, sort order, transparency, hidden) if the stored version equals
    /// `expected_version`.
    ///
    /// # Errors
    ///
    /// `NotFound` and `PreconditionFailed`.
    async fn update(&mut self, binding: Binding, expected_version: i64) -> Result<Binding, StoreError>;

    /// Deletes the binding and its per-binding properties.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn delete(&mut self, id: BindingId) -> Result<(), StoreError>;
}

/// Where a collection property lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PropertyScope {
    /// Shared by everyone who sees the calendar (`binding_id` NULL).
    Shared,
    /// Private to one principal's binding.
    Binding(BindingId),
}

/// A dead property of a calendar collection (`collection_properties`): an XML element stored verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionProperty {
    /// The calendar.
    pub calendar_id: CalendarId,
    /// Shared or per binding.
    pub scope: PropertyScope,
    /// The XML namespace of the property.
    pub ns: String,
    /// The local name of the property.
    pub name: String,
    /// The serialized XML element.
    pub value_xml: String,
}

/// Collection properties. Setting a property does not advance the calendar's sync sequence by itself; the
/// application calls `CalendarRepo::touch`.
#[async_trait]
pub trait PropertyRepo: Send {
    /// The properties of one scope of a calendar, ordered by namespace and name.
    ///
    /// # Errors
    ///
    /// `NotFound` when the calendar (or the binding of a binding scope) does not exist.
    async fn list(&mut self, calendar: CalendarId, scope: PropertyScope)
    -> Result<Vec<CollectionProperty>, StoreError>;

    /// The properties of several bindings at once, as a home listing shows them: for every `(calendar, binding)` pair
    /// the properties shared by everyone who sees the calendar ([`PropertyScope::Shared`]) and the ones private to the
    /// binding ([`PropertyScope::Binding`]), grouped by calendar in ascending id order, the shared ones first, then
    /// by namespace and name (the order of [`list`](Self::list)), then those of each binding by binding id. A pair
    /// whose binding does not belong to the calendar, or whose calendar does not exist, contributes nothing; a pair
    /// that is repeated counts once, and a calendar named by several pairs yields its shared properties once.
    /// Additive method: the default asks [`list`](Self::list) once for each distinct binding and once for each
    /// calendar; an adapter that can read them in one query overrides it (`ENGINEERING_RULES` R14).
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn list_many(&mut self, bindings: &[(CalendarId, BindingId)]) -> Result<Vec<CollectionProperty>, StoreError> {
        // Each distinct pair once, by calendar id and then binding id: the answer is built in that order, a calendar's
        // shared properties before the properties of its first valid binding.
        let wanted: BTreeSet<(CalendarId, BindingId)> = bindings.iter().copied().collect();
        let mut shared_of: Option<CalendarId> = None;
        let mut found: Vec<CollectionProperty> = Vec::new();
        for (calendar, binding) in wanted {
            let own = match self.list(calendar, PropertyScope::Binding(binding)).await {
                Ok(own) => own,
                Err(StoreError::NotFound) => continue,
                Err(error) => return Err(error),
            };
            if shared_of != Some(calendar) {
                shared_of = Some(calendar);
                found.extend(self.list(calendar, PropertyScope::Shared).await?);
            }
            found.extend(own);
        }
        Ok(found)
    }

    /// One property.
    ///
    /// # Errors
    ///
    /// `NotFound` when the calendar (or binding) does not exist; a missing property is `None`.
    async fn get(
        &mut self,
        calendar: CalendarId,
        scope: PropertyScope,
        ns: &str,
        name: &str,
    ) -> Result<Option<CollectionProperty>, StoreError>;

    /// Creates or replaces a property.
    ///
    /// **Take [`CalendarRepo::lock`] first** when the calendar may be deleted at the same time. The existence check
    /// of this method is an unlocked read, and the lock of the soft delete (`FOR NO KEY UPDATE`) does not conflict
    /// with the `KEY SHARE` lock the new row's foreign key takes, so without the calendar lock a concurrent
    /// [`CalendarRepo::soft_delete`] can commit between the check and this write and leave the new row pointing at
    /// a deleted calendar (a binding would then keep its slug occupied and its home would never log the change).
    /// With the lock held, the soft delete waits and then removes the row as part of "every binding of the
    /// calendar". The application takes the lock anyway to `touch` the calendar after such a change.
    ///
    /// # Errors
    ///
    /// `NotFound` when the calendar (or binding) does not exist.
    async fn set(&mut self, property: CollectionProperty) -> Result<(), StoreError>;

    /// Removes a property; `false` when it did not exist.
    ///
    /// # Errors
    ///
    /// `NotFound` when the calendar (or binding) does not exist.
    async fn remove(
        &mut self,
        calendar: CalendarId,
        scope: PropertyScope,
        ns: &str,
        name: &str,
    ) -> Result<bool, StoreError>;

    /// The number of properties in one scope (the limit of 50 dead properties per binding).
    ///
    /// # Errors
    ///
    /// `NotFound` when the calendar (or binding) does not exist.
    async fn count(&mut self, calendar: CalendarId, scope: PropertyScope) -> Result<u64, StoreError>;
}

/// Calendar grants. There is one grant per calendar and grantee; the last write wins between the API and
/// CalendarServer sharing.
#[async_trait]
pub trait GrantRepo: Send {
    /// The grant with `id`.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn get(&mut self, id: GrantId) -> Result<Grant, StoreError>;

    /// The grant of `grantee` on `calendar`, if any.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn find(&mut self, calendar: CalendarId, grantee: PrincipalId) -> Result<Option<Grant>, StoreError>;

    /// The grant of a CalendarServer invitation, by its invite UID.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn find_by_invite_uid(&mut self, uid: &Uid) -> Result<Option<Grant>, StoreError>;

    /// All grants of a calendar (pending and declined included), in id order.
    ///
    /// # Errors
    ///
    /// `NotFound` when the calendar does not exist.
    async fn for_calendar(&mut self, calendar: CalendarId) -> Result<Vec<Grant>, StoreError>;

    /// The grants of several calendars at once (pending and declined included), grouped by calendar in ascending id
    /// order and in id order within a calendar. Calendars that do not exist or are soft-deleted are skipped and a
    /// calendar that is repeated counts once. Additive method: the default asks
    /// [`for_calendar`](Self::for_calendar) once per calendar; an adapter that can read them in one query overrides
    /// it (`ENGINEERING_RULES` R14).
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn for_calendars(&mut self, calendars: &[CalendarId]) -> Result<Vec<Grant>, StoreError> {
        let mut wanted: Vec<CalendarId> = calendars.to_vec();
        wanted.sort_unstable();
        wanted.dedup();
        let mut found = Vec::new();
        for calendar in wanted {
            match self.for_calendar(calendar).await {
                Ok(grants) => found.extend(grants),
                Err(StoreError::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(found)
    }

    /// The grants given directly to `grantee` (not those given to its groups), in id order.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn for_grantee(&mut self, grantee: PrincipalId) -> Result<Vec<Grant>, StoreError>;

    /// Creates a grant.
    ///
    /// **Take [`CalendarRepo::lock`] first** when the calendar may be deleted at the same time. The existence check
    /// of this method is an unlocked read, and the lock of the soft delete (`FOR NO KEY UPDATE`) does not conflict
    /// with the `KEY SHARE` lock the new row's foreign key takes, so without the calendar lock a concurrent
    /// [`CalendarRepo::soft_delete`] can commit between the check and this write and leave the new row pointing at
    /// a deleted calendar (a binding would then keep its slug occupied and its home would never log the change).
    /// With the lock held, the soft delete waits and then removes the row as part of "every binding of the
    /// calendar". The application takes the lock anyway to `touch` the calendar after such a change.
    ///
    /// # Errors
    ///
    /// `NotFound` when the calendar or grantee does not exist and `UniqueViolation` of `Grant`.
    async fn create(&mut self, grant: Grant) -> Result<Grant, StoreError>;

    /// Replaces access, status, source and display fields if the stored version equals `expected_version`.
    ///
    /// # Errors
    ///
    /// `NotFound` and `PreconditionFailed`.
    async fn update(&mut self, grant: Grant, expected_version: i64) -> Result<Grant, StoreError>;

    /// Deletes the grant.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn delete(&mut self, id: GrantId) -> Result<(), StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calendar_filters_default_to_everything() {
        let filter = CalendarFilter::default();
        assert!(filter.owner.is_none() && filter.kind.is_none() && filter.slug.is_none() && filter.text.is_none());
    }
}
