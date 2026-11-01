//! Principal use cases: lifecycle, memberships, search and DAV principal properties.
//!
//! Principals (users, groups, resources and services) are provisioned through the management API
//! (`principals:read` / `principals:write`) and looked up by DAV clients (search, principal properties, address
//! classification), which only need an authenticated caller of the same tenant.
//!
//! * **Addresses.** A principal has one primary e-mail address (`mailto:`), further addresses and two derived
//!   ones: the principal URL and `urn:uuid:{id}` (PLAN 2.6). The stored rows (`principal_addresses`) are unique per
//!   tenant, case-insensitively, and the addresses of deleted principals stay reserved until the purge.
//! * **Replace semantics.** `PUT` replaces every writable field: what the body leaves out is cleared. `PATCH`
//!   computes the new body from the stored one and a JSON Merge Patch. The same body twice changes nothing: no
//!   new version, no audit record, no event.
//! * **Deletion** (PLAN 2.10) hides the principal at once and revokes everything it could be used for: credentials
//!   and RSVP links, the shares of its calendars and the shares made to it, and its group memberships. The purge
//!   removes the rest after `retention.principal_purge_days` (or at once with `purge`). Organizer events in group
//!   calendars stay; telling their attendees (`notify_attendees`) is scheduling and happens only where a scheduler
//!   is installed (see `objects::ObjectScheduler`).
//! * **Personal calendar.** A new user gets a personal calendar `personal` when the tenant enables
//!   `auto_create_personal_calendar`.

use std::collections::{BTreeSet, HashMap, HashSet};

use async_trait::async_trait;
use davhaven_domain::audit::PrincipalAudit;
use davhaven_domain::events::{CalendarPayload, MembershipPayload, PrincipalPayload};
use davhaven_domain::{
    Actor, AddressKind, AdminOperation, AuditEvent, CalendarId, CalendarKind, CalendarSlug, CalendarUserAddress,
    Channel, EventPayload, EventType, Grant, Principal, PrincipalId, PrincipalKind, PrincipalName, PrincipalStatus,
    PublicUrls, RequestContext, ResourcePath, Tenant,
};
use davhaven_ports::{
    PageReq, PrincipalAddress, PrincipalFilter as StoreFilter, PrincipalQuery, StoreError, Tx, TxMode,
};
use davhaven_wire::{MembershipSet, Page, PrincipalView, PrincipalWrite};
use url::Url;

use crate::audit::Journal;
use crate::authz::{admin, clean_name, field_error, found, invalid, principal_named, retrying};
use crate::calendars::{NewCalendar, provision};
use crate::error::{AppError, AppResult};
use crate::paging;
use crate::services::{
    AddressClass, Conditions, DeleteOptions, MAX_SEARCH_HITS, MergePatch, PageRequest, PrincipalFilter, PrincipalHit,
    PrincipalProps, PrincipalSearch, PrincipalSearchResult, PrincipalService, PrincipalSpec, SearchPlan, Upserted,
};
use crate::sharing::{drop_invitation, grant_audit, grant_payload, restore_for_new_members};
use crate::texts;
use crate::wiring::AppCore;

/// The listing name that binds cursors to the principal list.
const LISTING: &str = "principals";

/// The longest display name or external reference.
const MAX_TEXT: usize = 200;

/// The most additional addresses of one principal.
const MAX_ADDRESSES: usize = 20;

/// The [`PrincipalService`] of the application.
#[derive(Debug, Clone)]
pub struct PrincipalServiceImpl {
    core: AppCore,
}

impl PrincipalServiceImpl {
    /// Creates the service on the shared application core.
    pub fn new(core: AppCore) -> Self {
        Self { core }
    }

    /// The shared application core: ports, configuration and limits.
    pub fn core(&self) -> &AppCore {
        &self.core
    }
}

/// The path of the principal resource.
pub(crate) fn principal_path(tenant: &Tenant, principal: &Principal) -> ResourcePath {
    ResourcePath::Principal {
        tenant: tenant.slug.clone(),
        principal: principal.name.clone(),
    }
}

/// Every calendar user address of a principal (PLAN 2.6): the primary address, the further stored ones, the
/// principal URL, `urn:uuid:{id}` and, when the tenant says so, the login address.
pub(crate) fn address_set(
    tenant: &Tenant,
    principal: &Principal,
    stored: &[PrincipalAddress],
) -> Vec<CalendarUserAddress> {
    let mut addresses: Vec<CalendarUserAddress> = Vec::new();
    let mut push = |address: CalendarUserAddress| {
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    };
    if let Some(email) = &principal.email {
        push(CalendarUserAddress::mailto(email));
    }
    for row in stored.iter().filter(|row| row.primary) {
        push(row.address.clone());
    }
    for row in stored.iter().filter(|row| !row.primary) {
        push(row.address.clone());
    }
    if let Ok(url) = CalendarUserAddress::parse(&principal_path(tenant, principal).format()) {
        push(url);
    }
    push(CalendarUserAddress::urn_uuid(principal.id));
    if tenant.settings.login_address_is_cua
        && let Some(domain) = &tenant.login_domain
        && let Ok(address) = CalendarUserAddress::parse(&format!("mailto:{}@{domain}", principal.name))
    {
        push(address);
    }
    addresses
}

/// The view of a principal for the management API.
async fn view_of(core: &AppCore, tx: &mut dyn Tx, tenant: &Tenant, principal: &Principal) -> AppResult<PrincipalView> {
    let rows = tx.principals().addresses(principal.id).await?;
    Ok(PrincipalView {
        id: principal.id,
        kind: principal.kind,
        name: principal.name.clone(),
        display_name: principal.display_name.clone(),
        email: principal.email.clone(),
        addresses: rows
            .iter()
            .filter(|row| !row.primary)
            .map(|row| row.address.clone())
            .collect(),
        locale: principal.locale.clone(),
        timezone: principal.timezone,
        external_ref: principal.external_ref.clone(),
        status: principal.status,
        dav_url: core
            .deps()
            .urls
            .for_tenant(&tenant.settings)
            .dav_url(&principal_path(tenant, principal)),
        created_at: principal.created_at,
        updated_at: principal.updated_at,
        version: principal.version,
    })
}

/// The writable form of a principal, for merge patches.
fn writable(principal: &Principal, rows: &[PrincipalAddress]) -> PrincipalWrite {
    PrincipalWrite {
        kind: principal.kind,
        display_name: principal.display_name.clone(),
        email: principal.email.clone(),
        addresses: rows
            .iter()
            .filter(|row| !row.primary)
            .map(|row| row.address.clone())
            .collect(),
        locale: principal.locale.clone(),
        timezone: principal.timezone,
        external_ref: principal.external_ref.clone(),
        status: Some(principal.status),
    }
}

/// The body of a write after validation.
struct Checked {
    body: PrincipalWrite,
    display_name: String,
    /// The status the body asks for; `None` leaves the stored one (a new principal is active).
    status: Option<PrincipalStatus>,
    addresses: Vec<CalendarUserAddress>,
}

impl Checked {
    fn of(body: PrincipalWrite) -> AppResult<Self> {
        let display_name = clean_name("/display_name", &body.display_name, MAX_TEXT)?;
        if let Some(reference) = &body.external_ref {
            clean_name("/external_ref", reference, MAX_TEXT)?;
        }
        let status = body.status;
        if status == Some(PrincipalStatus::Deleted) {
            return Err(field_error(
                "/status",
                "not-allowed",
                "A principal is deleted with DELETE, not by setting its status.",
            ));
        }
        let primary = body.email.as_ref().map(CalendarUserAddress::mailto);
        let mut addresses: Vec<CalendarUserAddress> = Vec::new();
        for address in &body.addresses {
            if address.kind() == AddressKind::UrnUuid {
                return Err(field_error(
                    "/addresses",
                    "not-allowed",
                    "The urn:uuid address of a principal is derived and cannot be set.",
                ));
            }
            if Some(address) != primary.as_ref() && !addresses.contains(address) {
                addresses.push(address.clone());
            }
        }
        if addresses.len() > MAX_ADDRESSES {
            return Err(field_error(
                "/addresses",
                "too-many",
                "A principal can have at most 20 further addresses.",
            ));
        }
        Ok(Self {
            body,
            display_name,
            status,
            addresses,
        })
    }

    /// Every address the body asks for: the primary address first, the others in order.
    fn wanted_addresses(&self) -> Vec<CalendarUserAddress> {
        let mut wanted = Vec::with_capacity(self.addresses.len() + 1);
        wanted.extend(self.body.email.as_ref().map(CalendarUserAddress::mailto));
        wanted.extend(self.addresses.iter().cloned());
        wanted
    }

    /// The rows of `principal_addresses` the body asks for: the primary address first, the others in order.
    fn rows(&self, id: PrincipalId) -> Vec<PrincipalAddress> {
        let mut rows = Vec::with_capacity(self.addresses.len() + 1);
        if let Some(email) = &self.body.email {
            rows.push(PrincipalAddress {
                principal_id: id,
                address: CalendarUserAddress::mailto(email),
                primary: true,
            });
        }
        rows.extend(self.addresses.iter().map(|address| PrincipalAddress {
            principal_id: id,
            address: address.clone(),
            primary: false,
        }));
        rows
    }
}

/// Refuses the values of a write that belong to a **deleted principal that has not been purged yet**.
///
/// A deleted principal is hidden, but its name, its external reference and its addresses stay reserved until the
/// purge (PLAN 2.6, 2.10). A client that provisions principals has to tell that apart from a conflict with a live
/// principal, because it can act on it (purge the hidden principal, or wait for the retention period):
/// `name-reserved`, `external-ref-reserved` and `address-reserved` (409). A **live** holder is left to the unique
/// constraints, which answer the generic 409 `conflict`. The name is answered by the write itself (`If-None-Match: *`
/// answers 412 for it, like for every name that exists, and an unconditional write answers `name-reserved`).
///
/// Only values that are **new** to the principal are passed: a create passes all of its values, a replace only the
/// external reference and the addresses that it did not hold before, so the principal itself never holds a value that
/// is checked, and a write that changes only a display name asks the store nothing. The cost is one query for the
/// external reference and one for all the new addresses (`PrincipalRepo::find_by_addresses`).
///
/// # Errors
///
/// `Conflict` refined by `ExternalRefReserved` or `AddressReserved`; store failures.
async fn check_reserved(
    tx: &mut dyn Tx,
    external_ref: Option<&str>,
    addresses: &[CalendarUserAddress],
) -> AppResult<()> {
    if let Some(reference) = external_ref
        && let Some(holder) = tx.principals().find_by_external_ref(reference).await?
        && holder.status == PrincipalStatus::Deleted
    {
        return Err(AppError::external_ref_reserved());
    }
    if !addresses.is_empty() {
        let holders = tx.principals().find_by_addresses(addresses).await?;
        if holders
            .iter()
            .any(|(_, holder)| holder.status == PrincipalStatus::Deleted)
        {
            return Err(AppError::address_reserved());
        }
    }
    Ok(())
}

/// Orders stored rows so that two sets can be compared.
fn sorted(mut rows: Vec<PrincipalAddress>) -> Vec<PrincipalAddress> {
    rows.sort_by(|a, b| (b.primary, a.address.as_str()).cmp(&(a.primary, b.address.as_str())));
    rows
}

impl PrincipalServiceImpl {
    /// One attempt of a create-or-replace.
    async fn upsert_once(
        &self,
        ctx: &RequestContext,
        name: &PrincipalName,
        checked: &Checked,
        conditions: Conditions,
        must_exist: bool,
    ) -> AppResult<Upserted<PrincipalView>> {
        let journal = Journal::new(&self.core, ctx);
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadWrite).await?;
        let tenant = tx.tenant().get().await?;
        let existing = found(tx.principals().get_by_name(name).await)?;
        if must_exist && existing.is_none() {
            return Err(AppError::not_found());
        }
        conditions.check(existing.as_ref().map(|principal| principal.version))?;
        let (stored, created) = match existing {
            // The name of a deleted principal stays reserved until the purge: `If-None-Match: *` was answered 412
            // above, like for every name that exists; a write without it learns why it conflicts.
            Some(current) if current.status == PrincipalStatus::Deleted => {
                return Err(AppError::name_reserved());
            }
            Some(current) => {
                let replaced = self.replace_principal(&journal, tx.as_mut(), &current, checked).await?;
                let Some(stored) = replaced else {
                    // The same body again: nothing changes, nothing is recorded.
                    let view = view_of(&self.core, tx.as_mut(), &tenant, &current).await?;
                    tx.commit().await?;
                    return Ok(Upserted::replaced(view));
                };
                (stored, false)
            }
            None => (
                self.create_principal(&journal, tx.as_mut(), &tenant, name, checked)
                    .await?,
                true,
            ),
        };
        let view = view_of(&self.core, tx.as_mut(), &tenant, &stored).await?;
        tx.commit().await?;
        Ok(if created {
            Upserted::created(view)
        } else {
            Upserted::replaced(view)
        })
    }

    /// Replaces the writable fields and the addresses of an existing principal. `None` when the body changes
    /// nothing.
    async fn replace_principal(
        &self,
        journal: &Journal<'_>,
        tx: &mut dyn Tx,
        current: &Principal,
        checked: &Checked,
    ) -> AppResult<Option<Principal>> {
        let body = &checked.body;
        if current.kind != body.kind {
            return Err(field_error(
                "/kind",
                "immutable",
                "The kind of a principal cannot change.",
            ));
        }
        let before = sorted(tx.principals().addresses(current.id).await?);
        let after = sorted(checked.rows(current.id));
        let updated = Principal {
            display_name: checked.display_name.clone(),
            email: body.email.clone(),
            locale: body.locale.clone(),
            timezone: body.timezone,
            external_ref: body.external_ref.clone(),
            status: checked.status.unwrap_or(current.status),
            ..current.clone()
        };
        if updated == *current && before == after {
            return Ok(None);
        }
        // Only what is new to the principal can belong to someone else.
        let new_reference = if body.external_ref == current.external_ref {
            None
        } else {
            body.external_ref.as_deref()
        };
        let new_addresses: Vec<CalendarUserAddress> = after
            .iter()
            .filter(|row| !before.iter().any(|held| held.address == row.address))
            .map(|row| row.address.clone())
            .collect();
        check_reserved(tx, new_reference, &new_addresses).await?;
        let stored = tx.principals().update(updated, current.version).await?;
        if before != after {
            tx.principals().set_addresses(stored.id, after).await?;
        }
        if (current.status == PrincipalStatus::Active) != (stored.status == PrincipalStatus::Active) {
            // Cached verifications of the principal's credentials must not outlive the suspension.
            tx.principals().bump_credential_generation(stored.id).await?;
        }
        journal
            .audit(
                tx,
                AuditEvent::PrincipalUpdated(PrincipalAudit { principal: stored.id }),
            )
            .await?;
        journal
            .publish(
                tx,
                EventType::PrincipalUpdated,
                EventPayload::Principal(PrincipalPayload { principal: stored.id }),
            )
            .await?;
        Ok(Some(stored))
    }

    /// Creates a principal with its addresses, its audit record and event and, for users of tenants that want one,
    /// its personal calendar.
    async fn create_principal(
        &self,
        journal: &Journal<'_>,
        tx: &mut dyn Tx,
        tenant: &Tenant,
        name: &PrincipalName,
        checked: &Checked,
    ) -> AppResult<Principal> {
        let deps = self.core.deps();
        let body = &checked.body;
        let now = deps.clock.now();
        let principal = Principal {
            id: PrincipalId::from_uuid(deps.ids.new_id()),
            tenant_id: tenant.id,
            kind: body.kind,
            name: name.clone(),
            display_name: checked.display_name.clone(),
            email: body.email.clone(),
            locale: body.locale.clone(),
            timezone: body.timezone,
            external_ref: body.external_ref.clone(),
            status: checked.status.unwrap_or(PrincipalStatus::Active),
            deleted_at: None,
            credential_generation: 0,
            created_at: now,
            updated_at: now,
            version: 1,
        };
        check_reserved(tx, body.external_ref.as_deref(), &checked.wanted_addresses()).await?;
        let stored = tx.principals().create(principal).await?;
        tx.principals()
            .set_addresses(stored.id, checked.rows(stored.id))
            .await?;
        journal
            .audit(
                tx,
                AuditEvent::PrincipalCreated(PrincipalAudit { principal: stored.id }),
            )
            .await?;
        journal
            .publish(
                tx,
                EventType::PrincipalCreated,
                EventPayload::Principal(PrincipalPayload { principal: stored.id }),
            )
            .await?;
        if stored.kind == PrincipalKind::User && tenant.settings.auto_create_personal_calendar {
            self.create_personal_calendar(journal, tx, tenant, &stored).await?;
        }
        Ok(stored)
    }

    /// Creates the personal calendar of a new user and its binding.
    async fn create_personal_calendar(
        &self,
        journal: &Journal<'_>,
        tx: &mut dyn Tx,
        tenant: &Tenant,
        owner: &Principal,
    ) -> AppResult<()> {
        let slug = CalendarSlug::parse(texts::PERSONAL_CALENDAR_SLUG).map_err(AppError::internal)?;
        let locale = owner.locale.as_ref().unwrap_or(&tenant.settings.locale);
        let (calendar, _binding) = provision(
            &self.core,
            tx,
            owner,
            NewCalendar {
                slug,
                kind: CalendarKind::Personal,
                display_name: texts::personal_calendar_name(locale).to_owned(),
                description: None,
                color: None,
                sort_order: 0,
                components: tenant.settings.allowed_components.clone(),
                timezone_ics: None,
                schedule_transp: None,
            },
        )
        .await?;
        journal
            .publish(
                tx,
                EventType::CalendarCreated,
                EventPayload::Calendar(CalendarPayload {
                    calendar: calendar.id,
                    owner: owner.id,
                    kind: calendar.kind,
                }),
            )
            .await
    }

    async fn upsert(
        &self,
        ctx: &RequestContext,
        name: &PrincipalName,
        body: PrincipalWrite,
        conditions: Conditions,
    ) -> AppResult<Upserted<PrincipalView>> {
        let checked = Checked::of(body)?;
        retrying(conditions == Conditions::none(), || {
            self.upsert_once(ctx, name, &checked, conditions, false)
        })
        .await
    }

    /// Reads the principals of `names` for a membership change: they must exist, must not be deleted and must not be
    /// groups (groups are not nested).
    async fn members_named(&self, tx: &mut dyn Tx, names: &[PrincipalName]) -> AppResult<Vec<PrincipalId>> {
        let mut ids = Vec::with_capacity(names.len());
        for name in names {
            let member = match principal_named(tx, name).await {
                Ok(member) => member,
                Err(error) if error.kind() == davhaven_domain::ErrorKind::NotFound => {
                    return Err(field_error("/members", "unknown-member", "A member does not exist."));
                }
                Err(error) => return Err(error),
            };
            if member.kind == PrincipalKind::Group {
                return Err(field_error(
                    "/members",
                    "group-member",
                    "Groups cannot be members of groups.",
                ));
            }
            if !ids.contains(&member.id) {
                ids.push(member.id);
            }
        }
        Ok(ids)
    }

    /// The group named `name`.
    async fn group(&self, tx: &mut dyn Tx, name: &PrincipalName) -> AppResult<Principal> {
        let group = principal_named(tx, name).await?;
        if group.kind == PrincipalKind::Group {
            Ok(group)
        } else {
            Err(invalid("The principal is not a group."))
        }
    }

    /// The names of the members of a group, sorted.
    async fn member_names(&self, tx: &mut dyn Tx, group: PrincipalId) -> AppResult<MembershipSet> {
        let ids = tx.memberships().members(group).await?;
        let mut members: Vec<PrincipalName> = tx
            .principals()
            .get_many(&ids)
            .await?
            .into_iter()
            .filter(|member| member.status != PrincipalStatus::Deleted)
            .map(|member| member.name)
            .collect();
        members.sort();
        Ok(MembershipSet { members })
    }

    async fn publish_membership(
        &self,
        journal: &Journal<'_>,
        tx: &mut dyn Tx,
        group: PrincipalId,
        added: Vec<PrincipalId>,
        removed: Vec<PrincipalId>,
    ) -> AppResult<()> {
        if added.is_empty() && removed.is_empty() {
            return Ok(());
        }
        journal
            .publish(
                tx,
                EventType::MembershipChanged,
                EventPayload::Membership(MembershipPayload { group, added, removed }),
            )
            .await
    }
}

/// The DAV properties of a principal from what was read about it: its stored addresses and the principal resources of
/// its members (groups) and of the groups it belongs to.
fn props_from(
    tenant: &Tenant,
    principal: &Principal,
    stored: &[PrincipalAddress],
    group_members: Vec<ResourcePath>,
    group_membership: Vec<ResourcePath>,
) -> PrincipalProps {
    let home = |make: fn(davhaven_domain::TenantSlug, PrincipalName) -> ResourcePath| {
        make(tenant.slug.clone(), principal.name.clone())
    };
    PrincipalProps {
        path: principal_path(tenant, principal),
        id: principal.id,
        name: principal.name.clone(),
        display_name: principal.display_name.clone(),
        kind: principal.kind,
        addresses: address_set(tenant, principal, stored),
        home: home(|tenant, principal| ResourcePath::Home { tenant, principal }),
        inbox: home(|tenant, principal| ResourcePath::Inbox { tenant, principal }),
        outbox: home(|tenant, principal| ResourcePath::Outbox { tenant, principal }),
        notifications: home(|tenant, principal| ResourcePath::Notifications { tenant, principal }),
        group_members,
        group_membership,
    }
}

/// Whether the caller may use the DAV-facing lookups: any authenticated actor that acts in a tenant.
fn require_lookup(ctx: &RequestContext) -> AppResult<()> {
    if ctx.channel == Channel::Internal {
        return Ok(());
    }
    match ctx.actor {
        Actor::Principal(_) | Actor::PrincipalToken { .. } | Actor::TenantToken(_) => Ok(()),
        Actor::Anonymous => Err(AppError::unauthenticated()),
        Actor::SystemToken(_) | Actor::FeedReader { .. } | Actor::RsvpAttendee { .. } => Err(AppError::forbidden()),
    }
}

/// The principal that owns `address` in the tenant of the transaction, if it is an active member of the tenant.
///
/// Mail addresses match the stored addresses and, when the tenant counts the login address as a calendar user
/// address, `name@login_domain`; `urn:uuid` addresses name the principal by id; principal URLs name it by path, and
/// only a path-absolute URL or one on the DAV origin of this deployment counts (another deployment's principal URL
/// names a principal there, not here).
///
/// # Errors
///
/// Store failures.
pub(crate) async fn find_by_address(
    tx: &mut dyn Tx,
    tenant: &Tenant,
    urls: &PublicUrls,
    address: &CalendarUserAddress,
) -> AppResult<Option<Principal>> {
    Ok(find_by_addresses(tx, tenant, urls, std::slice::from_ref(address))
        .await?
        .into_iter()
        .next()
        .map(|(_, principal)| principal))
}

/// Whether the principal URL `address` is this deployment's: a path-absolute reference, or an absolute URL whose
/// origin is the DAV origin of the tenant.
fn is_local_url(urls: &PublicUrls, tenant: &Tenant, address: &CalendarUserAddress) -> bool {
    let text = address.as_str();
    if text.starts_with('/') {
        return true;
    }
    let Ok(url) = Url::parse(text) else {
        return false;
    };
    url.origin() == urls.for_tenant(&tenant.settings).dav_base().origin()
}

/// How one address of [`find_by_addresses`] is resolved: by what the stored addresses answered, or by the id or the
/// login name that it names.
enum Resolution {
    /// A mail address that a stored address of a principal matches.
    Stored(Principal),
    /// A `urn:uuid` address, which names the principal by id.
    Id(PrincipalId),
    /// A principal URL of this deployment or the login address of a mail address in the login domain, which name the
    /// principal by its login name.
    Name(PrincipalName),
    /// An address that names no principal of this tenant.
    Nobody,
}

/// [`find_by_address`] for several addresses with a fixed number of store calls (a write with 200 attendees per
/// instance must not cost 200 queries, `ENGINEERING_RULES` R14): the stored mail addresses, the principals named by
/// `urn:uuid` and the principals named by a login name (a principal URL, or a login address) are one read each, whatever
/// the number and the kinds of the addresses. The result lists the addresses that name an active principal of the
/// tenant, once each, in the order they were given.
///
/// # Errors
///
/// Store failures.
pub(crate) async fn find_by_addresses(
    tx: &mut dyn Tx,
    tenant: &Tenant,
    urls: &PublicUrls,
    addresses: &[CalendarUserAddress],
) -> AppResult<Vec<(CalendarUserAddress, Principal)>> {
    let mut seen: HashSet<&CalendarUserAddress> = HashSet::with_capacity(addresses.len());
    let wanted: Vec<&CalendarUserAddress> = addresses.iter().filter(|address| seen.insert(*address)).collect();
    // Pass one: the stored mail addresses, with one call for all of them.
    let mailtos: Vec<CalendarUserAddress> = wanted
        .iter()
        .filter(|address| address.kind() == AddressKind::Mailto)
        .map(|address| (*address).clone())
        .collect();
    let mut stored: HashMap<CalendarUserAddress, Principal> = if mailtos.is_empty() {
        HashMap::new()
    } else {
        tx.principals().find_by_addresses(&mailtos).await?.into_iter().collect()
    };
    // Pass two: what each address names, and the ids and login names to read.
    let mut ids: Vec<PrincipalId> = Vec::new();
    let mut names: Vec<PrincipalName> = Vec::new();
    let mut plan: Vec<(&CalendarUserAddress, Resolution)> = Vec::with_capacity(wanted.len());
    for address in wanted {
        let resolution = match address.kind() {
            AddressKind::Mailto => match (stored.remove(address), address.email(), &tenant.login_domain) {
                (Some(principal), _, _) => Resolution::Stored(principal),
                (None, Some(email), Some(domain))
                    if tenant.settings.login_address_is_cua && email.domain() == domain.as_str() =>
                {
                    PrincipalName::from_login(email.local()).map_or(Resolution::Nobody, Resolution::Name)
                }
                _ => Resolution::Nobody,
            },
            AddressKind::UrnUuid => address.principal_id().map_or(Resolution::Nobody, Resolution::Id),
            AddressKind::Url if is_local_url(urls, tenant, address) => {
                match ResourcePath::from_href(address.as_str()) {
                    Ok(
                        ResourcePath::Principal {
                            tenant: slug,
                            principal,
                        }
                        | ResourcePath::Home {
                            tenant: slug,
                            principal,
                        },
                    ) if slug == tenant.slug => Resolution::Name(principal),
                    _ => Resolution::Nobody,
                }
            }
            AddressKind::Url => Resolution::Nobody,
        };
        match &resolution {
            Resolution::Id(id) => ids.push(*id),
            Resolution::Name(name) => names.push(name.clone()),
            Resolution::Stored(_) | Resolution::Nobody => {}
        }
        plan.push((address, resolution));
    }
    // Pass three: the principals those name, with one call for the ids and one for the login names.
    let mut by_id: HashMap<PrincipalId, Principal> = HashMap::new();
    if !ids.is_empty() {
        by_id.extend(
            tx.principals()
                .get_many(&ids)
                .await?
                .into_iter()
                .map(|principal| (principal.id, principal)),
        );
    }
    let mut by_name: HashMap<PrincipalName, Principal> = HashMap::new();
    if !names.is_empty() {
        by_name.extend(
            tx.principals()
                .get_many_by_name(&names)
                .await?
                .into_iter()
                .map(|principal| (principal.name.clone(), principal)),
        );
    }
    Ok(plan
        .into_iter()
        .filter_map(|(address, resolution)| {
            let principal = match resolution {
                Resolution::Stored(principal) => Some(principal),
                Resolution::Id(id) => by_id.get(&id).cloned(),
                Resolution::Name(name) => by_name.get(&name).cloned(),
                Resolution::Nobody => None,
            };
            principal
                .filter(|principal| principal.status != PrincipalStatus::Deleted)
                .map(|principal| (address.clone(), principal))
        })
        .collect())
}

#[async_trait]
impl PrincipalService for PrincipalServiceImpl {
    async fn list(
        &self,
        ctx: &RequestContext,
        filter: PrincipalFilter,
        page: PageRequest,
    ) -> AppResult<Page<PrincipalView>> {
        admin(ctx, AdminOperation::ListPrincipals)?;
        let request: PageReq = paging::page_request(&self.core, ctx, LISTING, &page)?;
        let store_filter = StoreFilter {
            kind: filter.kind,
            external_ref: filter.external_ref,
            status: None,
            include_deleted: false,
        };
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let tenant = tx.tenant().get().await?;
        let rows = tx.principals().list(&store_filter, request).await?;
        let next = paging::next_cursor(&self.core, ctx, LISTING, rows.next)?;
        let mut items = Vec::with_capacity(rows.items.len());
        for principal in &rows.items {
            items.push(view_of(&self.core, tx.as_mut(), &tenant, principal).await?);
        }
        tx.commit().await?;
        Ok(Page::new(items, next))
    }

    async fn get(&self, ctx: &RequestContext, name: &PrincipalName) -> AppResult<PrincipalView> {
        admin(ctx, AdminOperation::GetPrincipal)?;
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let tenant = tx.tenant().get().await?;
        let principal = principal_named(tx.as_mut(), name).await?;
        let view = view_of(&self.core, tx.as_mut(), &tenant, &principal).await?;
        tx.commit().await?;
        Ok(view)
    }

    async fn upsert(
        &self,
        ctx: &RequestContext,
        spec: PrincipalSpec,
        conditions: Conditions,
    ) -> AppResult<Upserted<PrincipalView>> {
        admin(ctx, AdminOperation::PutPrincipal)?;
        self.upsert(ctx, &spec.name, spec.body, conditions).await
    }

    async fn patch(
        &self,
        ctx: &RequestContext,
        name: &PrincipalName,
        patch: MergePatch,
        conditions: Conditions,
    ) -> AppResult<PrincipalView> {
        admin(ctx, AdminOperation::PatchPrincipal)?;
        let value = retrying(conditions == Conditions::none(), || async {
            let (current, rows) = {
                let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
                let current = principal_named(tx.as_mut(), name).await?;
                let rows = tx.principals().addresses(current.id).await?;
                tx.commit().await?;
                (current, rows)
            };
            conditions.check(Some(current.version))?;
            let mut document = serde_json::to_value(writable(&current, &rows)).map_err(AppError::internal)?;
            patch.apply(&mut document);
            let body: PrincipalWrite =
                serde_json::from_value(document).map_err(|_| invalid("The patched principal is not valid."))?;
            let checked = Checked::of(body)?;
            // A concurrent change makes the write fail its version check; the patch is then computed again.
            self.upsert_once(ctx, name, &checked, Conditions::if_match(current.version), true)
                .await
                .map_err(|error| {
                    if error.kind() == davhaven_domain::ErrorKind::PreconditionFailed {
                        AppError::from(davhaven_ports::StoreError::PreconditionFailed)
                    } else {
                        error
                    }
                })
        })
        .await?;
        Ok(value.value)
    }

    async fn delete(&self, ctx: &RequestContext, name: &PrincipalName, options: DeleteOptions) -> AppResult<()> {
        admin(ctx, AdminOperation::DeletePrincipal)?;
        let expected = options.conditions.require_if_match()?;
        retrying(false, || self.delete_once(ctx, name, &options, expected)).await
    }

    async fn members(&self, ctx: &RequestContext, group: &PrincipalName) -> AppResult<MembershipSet> {
        admin(ctx, AdminOperation::GetMembers)?;
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let group = self.group(tx.as_mut(), group).await?;
        let names = self.member_names(tx.as_mut(), group.id).await?;
        tx.commit().await?;
        Ok(names)
    }

    async fn set_members(
        &self,
        ctx: &RequestContext,
        group: &PrincipalName,
        members: Vec<PrincipalName>,
    ) -> AppResult<MembershipSet> {
        admin(ctx, AdminOperation::SetMembers)?;
        let journal = Journal::new(&self.core, ctx);
        retrying(false, || async {
            let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadWrite).await?;
            let group = self.group(tx.as_mut(), group).await?;
            let ids = self.members_named(tx.as_mut(), &members).await?;
            let diff = tx.memberships().set_members(group.id, &ids).await?;
            restore_for_new_members(tx.as_mut(), &journal, group.id, &diff.added).await?;
            self.publish_membership(&journal, tx.as_mut(), group.id, diff.added, diff.removed)
                .await?;
            let result = self.member_names(tx.as_mut(), group.id).await?;
            tx.commit().await?;
            Ok(result)
        })
        .await
    }

    async fn add_member(&self, ctx: &RequestContext, group: &PrincipalName, member: &PrincipalName) -> AppResult<()> {
        admin(ctx, AdminOperation::AddMember)?;
        let journal = Journal::new(&self.core, ctx);
        retrying(false, || async {
            let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadWrite).await?;
            let group = self.group(tx.as_mut(), group).await?;
            let ids = self.members_named(tx.as_mut(), std::slice::from_ref(member)).await?;
            let Some(member_id) = ids.first().copied() else {
                return Err(AppError::not_found());
            };
            if tx.memberships().add_member(group.id, member_id).await? {
                restore_for_new_members(tx.as_mut(), &journal, group.id, &[member_id]).await?;
                self.publish_membership(&journal, tx.as_mut(), group.id, vec![member_id], Vec::new())
                    .await?;
            }
            tx.commit().await?;
            Ok(())
        })
        .await
    }

    async fn remove_member(
        &self,
        ctx: &RequestContext,
        group: &PrincipalName,
        member: &PrincipalName,
    ) -> AppResult<()> {
        admin(ctx, AdminOperation::RemoveMember)?;
        let journal = Journal::new(&self.core, ctx);
        retrying(false, || async {
            let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadWrite).await?;
            let group = self.group(tx.as_mut(), group).await?;
            // The member may be deleted already; its membership is removed all the same.
            let member = tx.principals().get_by_name(member).await?;
            if tx.memberships().remove_member(group.id, member.id).await? {
                self.publish_membership(&journal, tx.as_mut(), group.id, Vec::new(), vec![member.id])
                    .await?;
            }
            tx.commit().await?;
            Ok(())
        })
        .await
    }

    async fn search(&self, ctx: &RequestContext, search: PrincipalSearch) -> AppResult<Vec<PrincipalHit>> {
        Ok(self.find_principals(ctx, search).await?.hits)
    }

    async fn find_principals(&self, ctx: &RequestContext, search: PrincipalSearch) -> AppResult<PrincipalSearchResult> {
        require_lookup(ctx)?;
        let (text, criteria) = match search.plan() {
            SearchPlan::Nothing => return Ok(PrincipalSearchResult::default()),
            SearchPlan::TooShort => {
                return Err(field_error(
                    "/query",
                    "too-short",
                    "The search text needs at least two characters.",
                ));
            }
            SearchPlan::Ask { text, criteria } => (text, criteria),
        };
        let limit = search.limit.unwrap_or(MAX_SEARCH_HITS).clamp(1, MAX_SEARCH_HITS);
        // People, groups and resources are the principals a search finds; a list of kinds narrows that set.
        let kinds: Vec<PrincipalKind> = search
            .kinds
            .iter()
            .copied()
            .filter(|kind| *kind != PrincipalKind::Service)
            .collect();
        if kinds.is_empty() && !search.kinds.is_empty() {
            return Ok(PrincipalSearchResult::default());
        }
        // One more than the limit: the extra hit tells that the answer was cut.
        let query = PrincipalQuery {
            text,
            kinds,
            limit: limit.saturating_add(1),
            criteria,
            any_of: search.any_of,
        };
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let tenant = tx.tenant().get().await?;
        let matches = tx.principals().search(&query).await?;
        tx.commit().await?;
        let wanted = usize::try_from(limit).unwrap_or(usize::MAX);
        let truncated = matches.len() > wanted;
        Ok(PrincipalSearchResult {
            hits: matches
                .into_iter()
                .take(wanted)
                .map(|hit| PrincipalHit {
                    path: principal_path(&tenant, &hit.principal),
                    id: hit.principal.id,
                    name: hit.principal.name.clone(),
                    display_name: hit.principal.display_name.clone(),
                    kind: hit.principal.kind,
                    addresses: address_set(&tenant, &hit.principal, &hit.addresses),
                })
                .collect(),
            truncated,
        })
    }

    async fn dav_properties(&self, ctx: &RequestContext, path: &ResourcePath) -> AppResult<PrincipalProps> {
        require_lookup(ctx)?;
        let ResourcePath::Principal {
            tenant: slug,
            principal: name,
        } = path
        else {
            return Err(AppError::not_found());
        };
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let tenant = crate::authz::tenant_for_path(tx.as_mut(), slug).await?;
        let principal = principal_named(tx.as_mut(), name).await?;
        let props = self.props_of(tx.as_mut(), &tenant, &principal).await?;
        tx.commit().await?;
        Ok(props)
    }

    async fn dav_properties_many(
        &self,
        ctx: &RequestContext,
        paths: &[ResourcePath],
    ) -> AppResult<Vec<PrincipalProps>> {
        require_lookup(ctx)?;
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let tenant = tx.tenant().get().await?;
        // The principal resources of this tenant; anything else is not there for the caller (other tenants' resources
        // are invisible, R4).
        let names: Vec<PrincipalName> = paths
            .iter()
            .filter_map(|path| match path {
                ResourcePath::Principal {
                    tenant: slug,
                    principal,
                } if *slug == tenant.slug => Some(principal.clone()),
                _ => None,
            })
            .collect();
        if names.is_empty() {
            tx.commit().await?;
            return Ok(Vec::new());
        }
        let principals: Vec<Principal> = tx
            .principals()
            .get_many_by_name(&names)
            .await?
            .into_iter()
            .filter(|principal| principal.status != PrincipalStatus::Deleted)
            .collect();
        let found: HashMap<PrincipalName, PrincipalProps> = self
            .props_of_many(tx.as_mut(), &tenant, &principals)
            .await?
            .into_iter()
            .map(|props| (props.name.clone(), props))
            .collect();
        tx.commit().await?;
        // In the order of the request, as the answers of one path at a time would come.
        Ok(names.iter().filter_map(|name| found.get(name).cloned()).collect())
    }

    async fn current(&self, ctx: &RequestContext) -> AppResult<PrincipalProps> {
        // Only a person authenticates as a principal: a tenant or system token, a feed or RSVP link and an anonymous
        // request act as nobody.
        let (Actor::Principal(id) | Actor::PrincipalToken { principal: id, .. }) = ctx.actor else {
            return Err(AppError::unauthenticated());
        };
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let tenant = tx.tenant().get().await?;
        let principal = found(tx.principals().get(id).await)?
            .filter(|principal| principal.status != PrincipalStatus::Deleted)
            .ok_or_else(AppError::not_found)?;
        let props = self.props_of(tx.as_mut(), &tenant, &principal).await?;
        tx.commit().await?;
        Ok(props)
    }

    async fn resolve_address(&self, ctx: &RequestContext, address: &CalendarUserAddress) -> AppResult<AddressClass> {
        require_lookup(ctx)?;
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let tenant = tx.tenant().get().await?;
        let urls = &self.core.deps().urls;
        let class = match find_by_address(tx.as_mut(), &tenant, urls, address).await? {
            Some(principal) => AddressClass::Internal {
                principal: principal.id,
                name: principal.name,
                kind: principal.kind,
            },
            // The addresses of deleted principals stay reserved until the purge (PLAN 2.6): mail to them must not
            // leave the server as if nobody owned them.
            None if address.kind() == AddressKind::Mailto
                && tx.principals().find_by_address(address).await?.is_none() =>
            {
                AddressClass::External
            }
            None => AddressClass::Unresolvable,
        };
        tx.commit().await?;
        Ok(class)
    }
}

impl PrincipalServiceImpl {
    /// The DAV properties of a principal that was read inside `tx`.
    async fn props_of(&self, tx: &mut dyn Tx, tenant: &Tenant, principal: &Principal) -> AppResult<PrincipalProps> {
        self.props_of_many(tx, tenant, std::slice::from_ref(principal))
            .await?
            .pop()
            .ok_or_else(|| {
                AppError::internal(StoreError::internal(
                    "the properties of a principal are missing from the answer for it",
                ))
            })
    }

    /// The DAV properties of several principals that were read inside `tx`, in the order of `principals`, with a fixed
    /// number of queries whatever their number (`ENGINEERING_RULES` R14): the addresses of all of them, the members of
    /// all groups, the groups of all of them and the principals those name, one query each.
    async fn props_of_many(
        &self,
        tx: &mut dyn Tx,
        tenant: &Tenant,
        principals: &[Principal],
    ) -> AppResult<Vec<PrincipalProps>> {
        let ids: Vec<PrincipalId> = principals.iter().map(|principal| principal.id).collect();
        let group_ids: Vec<PrincipalId> = principals
            .iter()
            .filter(|principal| principal.kind == PrincipalKind::Group)
            .map(|principal| principal.id)
            .collect();
        let mut rows: HashMap<PrincipalId, Vec<PrincipalAddress>> = HashMap::new();
        for row in tx.principals().addresses_many(&ids).await? {
            rows.entry(row.principal_id).or_default().push(row);
        }
        let mut members: HashMap<PrincipalId, Vec<PrincipalId>> = HashMap::new();
        for (group, member) in tx.memberships().members_of_many(&group_ids).await? {
            members.entry(group).or_default().push(member);
        }
        let mut groups: HashMap<PrincipalId, Vec<PrincipalId>> = HashMap::new();
        for (member, group) in tx.memberships().groups_of_many(&ids).await? {
            groups.entry(member).or_default().push(group);
        }
        // The principals the memberships name, read once; deleted ones are not part of an answer.
        let mut linked: Vec<PrincipalId> = members.values().chain(groups.values()).flatten().copied().collect();
        linked.sort_unstable();
        linked.dedup();
        let linked: HashMap<PrincipalId, Principal> = tx
            .principals()
            .get_many(&linked)
            .await?
            .into_iter()
            .filter(|other| other.status != PrincipalStatus::Deleted)
            .map(|other| (other.id, other))
            .collect();
        let paths = |ids: Option<&Vec<PrincipalId>>| -> Vec<ResourcePath> {
            let mut paths: Vec<ResourcePath> = ids
                .into_iter()
                .flatten()
                .filter_map(|id| linked.get(id))
                .map(|other| principal_path(tenant, other))
                .collect();
            paths.sort_by_key(ResourcePath::format);
            paths
        };
        Ok(principals
            .iter()
            .map(|principal| {
                let stored = rows.get(&principal.id).map_or(&[][..], Vec::as_slice);
                props_from(
                    tenant,
                    principal,
                    stored,
                    paths(members.get(&principal.id)),
                    paths(groups.get(&principal.id)),
                )
            })
            .collect())
    }

    /// One attempt of a principal deletion.
    async fn delete_once(
        &self,
        ctx: &RequestContext,
        name: &PrincipalName,
        options: &DeleteOptions,
        expected: i64,
    ) -> AppResult<()> {
        let deps = self.core.deps();
        let journal = Journal::new(&self.core, ctx);
        let mut tx = deps.database.begin(ctx.tenant, TxMode::ReadWrite).await?;
        let principal = principal_named(tx.as_mut(), name).await?;
        if principal.version != expected {
            return Err(AppError::precondition_failed());
        }
        let rows = tx.principals().addresses(principal.id).await?;
        let tenant = tx.tenant().get().await?;
        self.revoke_everything(&journal, tx.as_mut(), &tenant, &principal, &rows)
            .await?;
        if options.purge {
            tx.principals().purge(principal.id).await?;
        } else {
            let now = deps.clock.now();
            let hidden = Principal {
                status: PrincipalStatus::Deleted,
                deleted_at: Some(now),
                ..principal.clone()
            };
            tx.principals().update(hidden, principal.version).await?;
        }
        let audit = PrincipalAudit {
            principal: principal.id,
        };
        journal
            .audit(tx.as_mut(), AuditEvent::PrincipalDeleted(audit.clone()))
            .await?;
        if options.purge {
            journal.audit(tx.as_mut(), AuditEvent::PrincipalPurged(audit)).await?;
        }
        journal
            .publish(
                tx.as_mut(),
                EventType::PrincipalDeleted,
                EventPayload::Principal(PrincipalPayload {
                    principal: principal.id,
                }),
            )
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Removes a grant with its audit record and its event.
    async fn drop_grant(&self, journal: &Journal<'_>, tx: &mut dyn Tx, grant: &Grant) -> AppResult<()> {
        tx.grants().delete(grant.id).await?;
        journal
            .audit(tx, AuditEvent::GrantDeleted(grant_audit(grant, false)))
            .await?;
        journal.publish(tx, EventType::GrantDeleted, grant_payload(grant)).await
    }

    /// Revokes what a deleted principal could be used for: credentials, RSVP links, shares in both directions, group
    /// memberships and, for a group, the access its members had through it.
    ///
    /// Every removal writes what the API's own removal writes: the audit record and the domain event of each grant,
    /// `membership.changed` of each group, the removal of the invitations that wait, and one move of the `CTag` of
    /// every calendar whose sharing changed, so webhook consumers and syncing clients see the same changes either
    /// way.
    async fn revoke_everything(
        &self,
        journal: &Journal<'_>,
        tx: &mut dyn Tx,
        tenant: &Tenant,
        principal: &Principal,
        rows: &[PrincipalAddress],
    ) -> AppResult<()> {
        tx.principals().bump_credential_generation(principal.id).await?;
        tx.credentials().revoke_all_for_principal(principal.id).await?;
        for address in address_set(tenant, principal, rows) {
            tx.rsvp().revoke_for_address(&address).await?;
        }
        let mut touched: BTreeSet<CalendarId> = BTreeSet::new();
        // Shares made to the principal.
        for grant in tx.grants().for_grantee(principal.id).await? {
            self.drop_grant(journal, tx, &grant).await?;
            touched.insert(grant.calendar_id);
        }
        let owned = tx.calendars().list_owned(principal.id).await?;
        // Shares of the principal's calendars: the sharees lose them at once, with the invitations that wait.
        for calendar in &owned {
            for grant in tx.grants().for_calendar(calendar.id).await? {
                if let Some(binding) = tx.bindings().find_for_calendar(grant.grantee_id, calendar.id).await? {
                    tx.bindings().delete(binding.id).await?;
                }
                drop_invitation(tx, &grant).await?;
                self.drop_grant(journal, tx, &grant).await?;
                touched.insert(calendar.id);
            }
        }
        for group in tx.memberships().groups_of(principal.id).await? {
            tx.memberships().remove_member(group, principal.id).await?;
            self.publish_membership(journal, tx, group, Vec::new(), vec![principal.id])
                .await?;
        }
        if principal.kind == PrincipalKind::Group {
            // The members of a deleted group keep nothing the group gave them: the default access of the group's
            // calendars and, with it, their bindings of those calendars.
            let members = tx.memberships().members(principal.id).await?;
            for calendar in &owned {
                for member in &members {
                    if let Some(binding) = tx.bindings().find_for_calendar(*member, calendar.id).await? {
                        tx.bindings().delete(binding.id).await?;
                    }
                }
                touched.insert(calendar.id);
            }
            let diff = tx.memberships().set_members(principal.id, &[]).await?;
            self.publish_membership(journal, tx, principal.id, diff.added, diff.removed)
                .await?;
        }
        let ids: Vec<CalendarId> = touched.into_iter().collect();
        if !ids.is_empty() {
            // Calendars that were deleted meanwhile need no new CTag.
            let live: Vec<CalendarId> = tx
                .calendars()
                .get_many(&ids)
                .await?
                .into_iter()
                .map(|calendar| calendar.id)
                .collect();
            if !live.is_empty() {
                tx.calendars().lock(&live).await?;
                for id in live {
                    tx.calendars().touch(id).await?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::DateTime;
    use davhaven_domain::{Email, Locale, TenantId, TenantSettings, TenantSlug, TenantStatus};
    use uuid::Uuid;

    use super::*;

    fn tenant(login_address_is_cua: bool) -> Tenant {
        Tenant {
            id: TenantId::from_uuid(Uuid::from_u128(1)),
            slug: TenantSlug::parse("acme").unwrap(),
            display_name: "Acme".to_owned(),
            login_domain: Some("acme.example".parse().unwrap()),
            status: TenantStatus::Active,
            settings: TenantSettings::default()
                .modified(|settings| settings.login_address_is_cua = login_address_is_cua),
            created_at: DateTime::UNIX_EPOCH,
            updated_at: DateTime::UNIX_EPOCH,
            version: 1,
        }
    }

    fn principal() -> Principal {
        Principal {
            id: PrincipalId::from_uuid(Uuid::from_u128(7)),
            tenant_id: TenantId::from_uuid(Uuid::from_u128(1)),
            kind: PrincipalKind::User,
            name: PrincipalName::parse("anna").unwrap(),
            display_name: "Anna".to_owned(),
            email: Some(Email::parse("Anna@Acme.example").unwrap()),
            locale: Some(Locale::de()),
            timezone: None,
            external_ref: None,
            status: PrincipalStatus::Active,
            deleted_at: None,
            credential_generation: 0,
            created_at: DateTime::UNIX_EPOCH,
            updated_at: DateTime::UNIX_EPOCH,
            version: 1,
        }
    }

    fn address(text: &str) -> CalendarUserAddress {
        CalendarUserAddress::parse(text).unwrap()
    }

    #[test]
    fn the_address_set_lists_primary_further_derived_and_login_addresses_once() {
        let principal = principal();
        let rows = vec![
            PrincipalAddress {
                principal_id: principal.id,
                address: address("mailto:anna@acme.example"),
                primary: true,
            },
            PrincipalAddress {
                principal_id: principal.id,
                address: address("mailto:a.schmidt@elsewhere.example"),
                primary: false,
            },
        ];
        let without_login = address_set(&tenant(false), &principal, &rows);
        let shown: Vec<&str> = without_login.iter().map(CalendarUserAddress::as_str).collect();
        assert_eq!(
            shown,
            vec![
                "mailto:anna@acme.example",
                "mailto:a.schmidt@elsewhere.example",
                "/dav/principals/acme/anna/",
                "urn:uuid:00000000-0000-0000-0000-000000000007",
            ]
        );
        let with_login = address_set(&tenant(true), &principal, &rows);
        assert_eq!(
            with_login
                .iter()
                .filter(|a| a.as_str() == "mailto:anna@acme.example")
                .count(),
            1,
            "the login address equals the primary one here and appears once"
        );
        let other_login = Principal {
            name: PrincipalName::parse("a.schmidt").unwrap(),
            ..principal
        };
        let set = address_set(&tenant(true), &other_login, &rows);
        assert!(set.iter().any(|a| a.as_str() == "mailto:a.schmidt@acme.example"));
    }

    #[test]
    fn writes_are_validated_before_anything_is_stored() {
        let body = |status: Option<PrincipalStatus>, addresses: Vec<CalendarUserAddress>| PrincipalWrite {
            kind: PrincipalKind::User,
            display_name: "  Anna  ".to_owned(),
            email: Some(Email::parse("anna@acme.example").unwrap()),
            addresses,
            locale: None,
            timezone: None,
            external_ref: None,
            status,
        };
        let checked = Checked::of(body(
            None,
            vec![
                address("mailto:anna@acme.example"),
                address("mailto:b@x.example"),
                address("mailto:b@x.example"),
            ],
        ))
        .unwrap();
        assert_eq!(checked.display_name, "Anna");
        assert_eq!(
            checked.status, None,
            "an absent status leaves the stored one (active for a new principal)"
        );
        assert_eq!(
            checked.addresses,
            vec![address("mailto:b@x.example")],
            "the primary and duplicates are dropped"
        );
        let rows = checked.rows(PrincipalId::from_uuid(Uuid::from_u128(3)));
        assert_eq!(rows.len(), 2);
        assert!(rows.first().is_some_and(|row| row.primary));
        assert!(Checked::of(body(Some(PrincipalStatus::Deleted), Vec::new())).is_err());
        let urn = address("urn:uuid:00000000-0000-0000-0000-000000000001");
        assert!(Checked::of(body(None, vec![urn])).is_err());
        let many: Vec<CalendarUserAddress> = (0..=MAX_ADDRESSES)
            .map(|n| address(&format!("mailto:p{n}@x.example")))
            .collect();
        assert!(Checked::of(body(None, many)).is_err());
        let mut blank = body(None, Vec::new());
        blank.display_name = "   ".to_owned();
        assert!(Checked::of(blank).is_err());
    }
}
