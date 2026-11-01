//! Builders and the seeded world of the store suite.
//!
//! Every case starts from an empty database (the factory builds a fresh one) and seeds what it needs. The ids are
//! constants derived from small numbers, ascending, so id order equals creation order. Entities carry placeholder
//! values for the columns the store owns (`tenant_id`, `version`, `created_at`, `updated_at`): the suite checks
//! that the store ignores them.

use core::fmt::{Debug, Display};
use std::sync::Arc;

use chrono::{DateTime, TimeZone, Utc};
use davhaven_domain::{
    ApiToken, AppPassword, AttendeeRef, Binding, Calendar, CalendarId, CalendarKind, CalendarSlug, CalendarUserAddress,
    Classification, ComponentKind, ContentHash, DomainName, ETag, Email, ExternalKey, FeedMode, FeedToken, Grant,
    GrantAccess, GrantId, GrantSource, GrantStatus, InboxItem, InboxItemId, Notification, NotificationId,
    NotificationKind, ObjectId, ObjectIndex, ObjectUri, Principal, PrincipalId, PrincipalKind, PrincipalName,
    PrincipalStatus, RsvpToken, ScopeSet, Tenant, TenantId, TenantSettings, TenantSlug, TenantStatus, TokenId,
    TokenKind, Transparency, Uid,
};
use davhaven_ports::{Database, NewVersion, PrincipalAddress, StoreError, SystemTx, Tx, TxMode};
use uuid::Uuid;

use crate::suite::Checks;
use davhaven_ports::UniqueKey;

/// The database a case works on.
pub(super) type Db = Arc<dyn Database>;

/// The part of every id that makes it look like a UUIDv7.
const ID_BASE: u128 = 0x0190_0000_0001_7000_8000_0000_0000_0000;

/// The id with the number `n`: ascending in `n`.
pub(super) fn uuid(n: u128) -> Uuid {
    Uuid::from_u128(ID_BASE | n)
}

/// A typed id with the number `n`.
pub(super) fn id<T: From<Uuid>>(n: u128) -> T {
    T::from(uuid(n))
}

/// Wraps the error of a validating constructor: a fixture of the suite that is invalid is a bug of the suite.
pub(super) fn key<T, E: Display>(result: Result<T, E>) -> Result<T, StoreError> {
    result.map_err(|error| StoreError::internal(format!("the suite's fixture is invalid: {error}")))
}

/// A tenant id for entities whose tenant the store fills in.
pub(super) fn nobody() -> TenantId {
    TenantId::from_uuid(Uuid::nil())
}

/// A placeholder for the timestamps the store owns.
pub(super) fn epoch() -> DateTime<Utc> {
    DateTime::UNIX_EPOCH
}

/// An instant long before any clock a test uses (2000-01-01).
pub(super) fn long_ago() -> DateTime<Utc> {
    DateTime::from_timestamp(946_684_800, 0).unwrap_or(DateTime::UNIX_EPOCH)
}

/// An instant long after any clock a test uses (2200-01-01).
pub(super) fn far_future() -> DateTime<Utc> {
    DateTime::from_timestamp(7_258_118_400, 0).unwrap_or(DateTime::UNIX_EPOCH)
}

/// An hour on 2027-03-01, for the intervals of events.
pub(super) fn at(hour: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2027, 3, 1, hour, 0, 0)
        .single()
        .unwrap_or(DateTime::UNIX_EPOCH)
}

/// Opens a read-write transaction of a tenant.
pub(super) async fn begin(db: &Db, tenant: TenantId) -> Result<Box<dyn Tx>, StoreError> {
    db.begin(tenant, TxMode::ReadWrite).await
}

/// Opens a read-only transaction of a tenant.
pub(super) async fn read(db: &Db, tenant: TenantId) -> Result<Box<dyn Tx>, StoreError> {
    db.begin(tenant, TxMode::ReadOnly).await
}

/// Opens a system transaction.
pub(super) async fn system(db: &Db) -> Result<Box<dyn SystemTx>, StoreError> {
    db.begin_system().await
}

/// A tenant.
pub(super) fn tenant(n: u128, slug: &str, domain: Option<&str>) -> Result<Tenant, StoreError> {
    Ok(Tenant {
        id: id(n),
        slug: key(TenantSlug::parse(slug))?,
        display_name: format!("Tenant {slug}"),
        login_domain: domain.map(|domain| key(DomainName::parse(domain))).transpose()?,
        status: TenantStatus::Active,
        settings: TenantSettings::default(),
        created_at: epoch(),
        updated_at: epoch(),
        version: 99,
    })
}

/// A principal whose e-mail address is `{name}@example.org`.
pub(super) fn principal(n: u128, name: &str, kind: PrincipalKind) -> Result<Principal, StoreError> {
    Ok(Principal {
        id: id(n),
        tenant_id: nobody(),
        kind,
        name: key(PrincipalName::parse(name))?,
        display_name: format!("Display {name}"),
        email: Some(key(Email::parse(&format!("{name}@example.org")))?),
        locale: None,
        timezone: None,
        external_ref: None,
        status: PrincipalStatus::Active,
        deleted_at: None,
        credential_generation: 0,
        created_at: epoch(),
        updated_at: epoch(),
        version: 99,
    })
}

/// An address of a principal.
pub(super) fn address(principal: PrincipalId, text: &str, primary: bool) -> Result<PrincipalAddress, StoreError> {
    Ok(PrincipalAddress {
        principal_id: principal,
        address: key(CalendarUserAddress::parse(text))?,
        primary,
    })
}

/// A calendar with the component set VEVENT and VTODO and its own sync epoch.
pub(super) fn calendar(n: u128, owner: PrincipalId, slug: &str, kind: CalendarKind) -> Result<Calendar, StoreError> {
    Ok(Calendar {
        id: id(n),
        tenant_id: nobody(),
        owner_id: owner,
        slug: key(CalendarSlug::parse(slug))?,
        kind,
        display_name: format!("Calendar {slug}"),
        description: None,
        color: None,
        sort_order: 0,
        components: vec![ComponentKind::Event, ComponentKind::Todo],
        timezone_ics: None,
        sync_seq: 41,
        sync_min_seq: 7,
        sync_epoch: uuid(0xE000 + n),
        deleted_at: None,
        created_at: epoch(),
        updated_at: epoch(),
        version: 99,
    })
}

/// A binding.
pub(super) fn binding(
    n: u128,
    principal: PrincipalId,
    calendar: CalendarId,
    slug: &str,
) -> Result<Binding, StoreError> {
    Ok(Binding {
        id: id(n),
        tenant_id: nobody(),
        principal_id: principal,
        calendar_id: calendar,
        slug: key(CalendarSlug::parse(slug))?,
        display_name: None,
        color: None,
        sort_order: None,
        schedule_transp: None,
        hidden: false,
        created_at: epoch(),
        updated_at: epoch(),
        version: 99,
    })
}

/// A grant.
pub(super) fn grant(n: u128, calendar: CalendarId, grantee: PrincipalId, status: GrantStatus) -> Grant {
    Grant {
        id: id::<GrantId>(n),
        tenant_id: nobody(),
        calendar_id: calendar,
        grantee_id: grantee,
        access: GrantAccess::ReadWrite,
        status,
        source: GrantSource::Share,
        required: false,
        invite_uid: None,
        summary: None,
        common_name: None,
        created_at: epoch(),
        updated_at: epoch(),
        version: 99,
    }
}

/// The iCalendar text of an event.
pub(super) fn ics(uid: &str) -> String {
    format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:{uid}\r\nSUMMARY:{uid}\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
    )
}

/// A new version of an object: a one-hour event on 2027-03-01 without organizer and attendees.
///
/// # Errors
///
/// [`StoreError::Internal`] when `uri` or `uid` is not a valid key.
pub fn version(n: u128, uri: &str, uid: &str) -> Result<NewVersion, StoreError> {
    let data = ics(uid);
    let digest = [u8::try_from(n % 251).unwrap_or(0); 32];
    Ok(NewVersion {
        id: id::<ObjectId>(n),
        uri: key(ObjectUri::parse(uri))?,
        etag: ETag::from_bytes(data.as_bytes()),
        data,
        schedule_tag: None,
        content_hash: ContentHash::from_digest(digest),
        index: ObjectIndex {
            uid: key(Uid::parse(uid))?,
            component: ComponentKind::Event,
            first_start: Some(at(10)),
            last_end: Some(at(11)),
            is_recurring: false,
            is_scheduling: false,
            organizer: None,
            attendees: Vec::new(),
            sequence: 0,
            class: Classification::Public,
            transp: Transparency::Opaque,
        },
        attendee_principals: Vec::new(),
        external_key: None,
        origin: None,
    })
}

/// Makes a version a scheduling object organized by `organizer` with the given attendees.
pub(super) fn scheduling(
    mut version: NewVersion,
    organizer: &str,
    attendees: &[(&str, Option<PrincipalId>)],
) -> Result<NewVersion, StoreError> {
    version.index.is_scheduling = true;
    version.index.organizer = Some(key(CalendarUserAddress::parse(organizer))?);
    for (text, principal) in attendees {
        let address = key(CalendarUserAddress::parse(text))?;
        version.index.attendees.push(AttendeeRef::new(address.clone()));
        if let Some(principal) = principal {
            version.attendee_principals.push((address, *principal));
        }
    }
    Ok(version)
}

/// Gives a version an external key.
pub(super) fn keyed(mut version: NewVersion, external_key: &str) -> Result<NewVersion, StoreError> {
    version.external_key = Some(key(ExternalKey::parse(external_key))?);
    Ok(version)
}

/// An app password.
pub(super) fn app_password(n: u128, principal: PrincipalId, prefix: &str) -> AppPassword {
    AppPassword {
        id: id(n),
        tenant_id: nobody(),
        principal_id: principal,
        label: "iPhone".to_owned(),
        prefix: prefix.to_owned(),
        hash: vec![1, 2, 3],
        pepper_kid: "k1".to_owned(),
        last_used_at: None,
        revoked_at: None,
        created_at: epoch(),
        updated_at: epoch(),
        version: 99,
    }
}

/// An API token of the given kind.
pub(super) fn api_token(n: u128, kind: TokenKind, principal: Option<PrincipalId>, prefix: &str) -> ApiToken {
    ApiToken {
        id: id::<TokenId>(n),
        tenant_id: None,
        kind,
        principal_id: principal,
        label: "ci".to_owned(),
        scopes: ScopeSet::empty(),
        prefix: prefix.to_owned(),
        hash: vec![4, 5, 6],
        pepper_kid: "k1".to_owned(),
        expires_at: None,
        created_by: None,
        allowed_origins: vec!["https://example.org".to_owned()],
        last_used_at: None,
        revoked_at: None,
        created_at: epoch(),
        updated_at: epoch(),
        version: 99,
    }
}

/// A feed token for the calendars.
pub(super) fn feed_token(n: u128, principal: PrincipalId, calendars: Vec<CalendarId>, prefix: &str) -> FeedToken {
    FeedToken {
        id: id(n),
        tenant_id: nobody(),
        principal_id: principal,
        mode: FeedMode::Busy,
        calendar_ids: calendars,
        prefix: prefix.to_owned(),
        hash: vec![7, 8, 9],
        pepper_kid: "k1".to_owned(),
        revoked_at: None,
        created_at: epoch(),
        updated_at: epoch(),
        version: 99,
    }
}

/// An RSVP token for an attendee of an object.
pub(super) fn rsvp_token(n: u128, object: ObjectId, attendee: &str, prefix: &str) -> Result<RsvpToken, StoreError> {
    Ok(RsvpToken {
        id: id(n),
        tenant_id: nobody(),
        object_id: object,
        attendee_address: key(CalendarUserAddress::parse(attendee))?,
        prefix: prefix.to_owned(),
        hash: vec![1, 1, 1],
        pepper_kid: "k1".to_owned(),
        expires_at: far_future(),
        revoked_at: None,
        last_used_at: None,
        last_response: None,
        created_at: epoch(),
        updated_at: epoch(),
        version: 99,
    })
}

/// What a case seeds: two tenants with a few principals and calendars.
#[derive(Debug, Clone, Copy)]
pub struct World {
    /// The first tenant, `acme`.
    pub a: TenantId,
    /// The second tenant, `globex`.
    pub b: TenantId,
    /// A user of `acme` who owns `personal` and `shared`.
    pub olivia: PrincipalId,
    /// A user of `acme`, member of `team`.
    pub mia: PrincipalId,
    /// A group of `acme` that owns `team_calendar`.
    pub team: PrincipalId,
    /// A user of `globex`.
    pub gina: PrincipalId,
    /// The personal calendar of Olivia.
    pub personal: CalendarId,
    /// A calendar of Olivia.
    pub shared: CalendarId,
    /// The calendar of the group.
    pub team_calendar: CalendarId,
}

/// Seeds the two tenants, their principals, the membership and the calendars, and commits.
///
/// # Errors
///
/// Whatever the store answers; a store that fails here cannot run any case.
pub async fn seed(db: &Db) -> Result<World, StoreError> {
    let world = World {
        a: id(0xA),
        b: id(0xB),
        olivia: id(0x101),
        mia: id(0x102),
        team: id(0x103),
        gina: id(0x201),
        personal: id(0x301),
        shared: id(0x302),
        team_calendar: id(0x303),
    };
    let mut tx = system(db).await?;
    tx.tenants().create(tenant(0xA, "acme", Some("acme.example"))?).await?;
    tx.tenants()
        .create(tenant(0xB, "globex", Some("globex.example"))?)
        .await?;
    tx.commit().await?;

    let mut tx = begin(db, world.a).await?;
    tx.principals()
        .create(principal(0x101, "olivia", PrincipalKind::User)?)
        .await?;
    tx.principals()
        .create(principal(0x102, "mia", PrincipalKind::User)?)
        .await?;
    tx.principals()
        .create(principal(0x103, "team", PrincipalKind::Group)?)
        .await?;
    tx.memberships().add_member(world.team, world.mia).await?;
    tx.calendars()
        .create(calendar(0x301, world.olivia, "personal", CalendarKind::Personal)?)
        .await?;
    tx.calendars()
        .create(calendar(0x302, world.olivia, "projects", CalendarKind::User)?)
        .await?;
    tx.calendars()
        .create(calendar(0x303, world.team, "team-calendar", CalendarKind::Group)?)
        .await?;
    tx.commit().await?;

    let mut tx = begin(db, world.b).await?;
    tx.principals()
        .create(principal(0x201, "gina", PrincipalKind::User)?)
        .await?;
    tx.commit().await?;
    Ok(world)
}

/// Assertions about store errors.
pub(super) trait StoreChecks {
    /// The result must be `NotFound`.
    fn not_found<T: Debug>(&mut self, result: Result<T, StoreError>, what: &str);
    /// The result must be a unique violation of `key`.
    fn unique<T: Debug>(&mut self, result: Result<T, StoreError>, key: UniqueKey, what: &str);
    /// The result must be `PreconditionFailed`.
    fn precondition_failed<T: Debug>(&mut self, result: Result<T, StoreError>, what: &str);
    /// The result must be `InvalidSyncToken`.
    fn invalid_sync_token<T: Debug>(&mut self, result: Result<T, StoreError>, what: &str);
    /// The result must be `LeaseLost`.
    fn lease_lost<T: Debug>(&mut self, result: Result<T, StoreError>, what: &str);
    /// The result must be `InvalidData`.
    fn invalid_data<T: Debug>(&mut self, result: Result<T, StoreError>, what: &str);
    /// The result must be `Internal` (a misuse the store refuses, or a write in a read-only transaction).
    fn internal<T: Debug>(&mut self, result: Result<T, StoreError>, what: &str);
}

impl StoreChecks for Checks {
    fn not_found<T: Debug>(&mut self, result: Result<T, StoreError>, what: &str) {
        if let Some(error) = self.err(result, what) {
            self.equal(&error, &StoreError::NotFound, what);
        }
    }

    fn unique<T: Debug>(&mut self, result: Result<T, StoreError>, key: UniqueKey, what: &str) {
        if let Some(error) = self.err(result, what) {
            self.equal(&error, &StoreError::UniqueViolation(key), what);
        }
    }

    fn precondition_failed<T: Debug>(&mut self, result: Result<T, StoreError>, what: &str) {
        if let Some(error) = self.err(result, what) {
            self.equal(&error, &StoreError::PreconditionFailed, what);
        }
    }

    fn invalid_sync_token<T: Debug>(&mut self, result: Result<T, StoreError>, what: &str) {
        if let Some(error) = self.err(result, what) {
            self.equal(&error, &StoreError::InvalidSyncToken, what);
        }
    }

    fn lease_lost<T: Debug>(&mut self, result: Result<T, StoreError>, what: &str) {
        if let Some(error) = self.err(result, what) {
            self.equal(&error, &StoreError::LeaseLost, what);
        }
    }

    fn invalid_data<T: Debug>(&mut self, result: Result<T, StoreError>, what: &str) {
        if let Some(error) = self.err(result, what) {
            self.that(
                matches!(error, StoreError::InvalidData(_)),
                &format!("{what}: expected InvalidData, got {error:?}"),
            );
        }
    }

    fn internal<T: Debug>(&mut self, result: Result<T, StoreError>, what: &str) {
        if let Some(error) = self.err(result, what) {
            self.that(
                matches!(error, StoreError::Internal(_)),
                &format!("{what}: expected an internal error, got {error:?}"),
            );
        }
    }
}

/// A share invitation for a principal.
pub(super) fn notification(n: u128, principal: PrincipalId, uri: &str, uid: &str) -> Result<Notification, StoreError> {
    Ok(Notification {
        id: id::<NotificationId>(n),
        tenant_id: nobody(),
        principal_id: principal,
        uri: key(ObjectUri::parse(uri))?,
        uid: key(Uid::parse(uid))?,
        etag: ETag::from_bytes(uri.as_bytes()),
        kind: NotificationKind::Invite,
        body_xml: format!("<notification>{uid}</notification>"),
        created_at: epoch(),
        updated_at: epoch(),
        version: 99,
    })
}

/// An item of a principal's scheduling inbox.
pub(super) fn inbox_item(
    n: u128,
    principal: PrincipalId,
    uri: &str,
    quarantined: bool,
) -> Result<InboxItem, StoreError> {
    let data = ics(uri);
    Ok(InboxItem {
        id: id::<InboxItemId>(n),
        tenant_id: nobody(),
        principal_id: principal,
        uri: key(ObjectUri::parse(uri))?,
        etag: ETag::from_bytes(data.as_bytes()),
        data,
        quarantined,
        created_at: epoch(),
        updated_at: epoch(),
        version: 99,
    })
}
