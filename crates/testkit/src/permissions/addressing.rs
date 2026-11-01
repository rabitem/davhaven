//! Where a case sends its request: the paths of the calendars, objects and homes of the fixture world, as every actor
//! addresses them.
//!
//! On DAV an actor reaches a calendar through the binding in the own home when there is one (the owner, accepted
//! sharees, members of the owning group, grantees of a managed calendar), and otherwise probes the home of the
//! calendar's owner, where the calendar must stay invisible. The management API and MCP address the calendar by its
//! natural key below its owner. Actors that are only a credential (tenant and system tokens, anonymous) have no home
//! and always probe the owner's.

use davhaven_domain::{CalendarKind, ResourcePath};
use davhaven_fixtures::{ActorRole, CalendarRole, FixtureCalendar, FixtureEvent, FixtureWorld};

/// The addresses of a world.
#[derive(Debug, Clone, Copy)]
pub struct Addressing<'a> {
    world: &'a FixtureWorld,
}

impl<'a> Addressing<'a> {
    /// The addresses of `world`.
    pub const fn new(world: &'a FixtureWorld) -> Self {
        Self { world }
    }

    /// The world.
    pub const fn world(&self) -> &'a FixtureWorld {
        self.world
    }

    /// The calendar of a role.
    ///
    /// # Panics
    ///
    /// Never for a world built by [`FixtureWorld::standard`] or [`FixtureWorld::with_names`], which hold every calendar
    /// role; a world without one is a bug of the test.
    #[expect(
        clippy::expect_used,
        reason = "a world without a calendar role is a bug of the test that builds it"
    )]
    pub fn calendar(&self, role: CalendarRole) -> &'a FixtureCalendar {
        self.world.calendar(role).expect("the world has every calendar role")
    }

    /// The event of the calendar of a role.
    ///
    /// # Panics
    ///
    /// See [`Addressing::calendar`].
    #[expect(
        clippy::expect_used,
        reason = "a world without an event is a bug of the test that builds it"
    )]
    pub fn event(&self, role: CalendarRole) -> &'a FixtureEvent {
        self.world
            .event(role)
            .expect("the world has an event in every calendar")
    }

    /// The slug of the tenant of the calendar.
    pub fn tenant(&self, role: CalendarRole) -> String {
        self.calendar(role).key.tenant.to_string()
    }

    /// The name of the principal that owns the calendar.
    pub fn owner(&self, role: CalendarRole) -> String {
        self.calendar(role).key.owner.to_string()
    }

    /// The slug of the calendar.
    pub fn slug(&self, role: CalendarRole) -> String {
        self.calendar(role).key.slug.to_string()
    }

    /// The kind of principal that owns the calendar.
    pub fn owner_is_group(&self, role: CalendarRole) -> bool {
        self.calendar(role).kind == CalendarKind::Group
    }

    /// The collection of the calendar as the actor addresses it on DAV.
    pub fn dav_collection(&self, actor: ActorRole, role: CalendarRole) -> ResourcePath {
        self.world.collection_path(actor, role).unwrap_or_else(|_| {
            let calendar = self.calendar(role);
            ResourcePath::Collection {
                tenant: calendar.key.tenant.clone(),
                principal: calendar.key.owner.clone(),
                binding: calendar.key.slug.clone(),
            }
        })
    }

    /// The path of the collection as text.
    pub fn dav_collection_path(&self, actor: ActorRole, role: CalendarRole) -> String {
        self.dav_collection(actor, role).format()
    }

    /// The fixture event of the calendar as the actor addresses it on DAV.
    pub fn dav_object_path(&self, actor: ActorRole, role: CalendarRole) -> String {
        format!(
            "{}{}",
            self.dav_collection_path(actor, role),
            object_segment(self.event(role).uri.as_str())
        )
    }

    /// A new resource in the collection as the actor addresses it on DAV.
    pub fn dav_new_object_path(&self, actor: ActorRole, role: CalendarRole, name: &str) -> String {
        format!("{}{}", self.dav_collection_path(actor, role), object_segment(name))
    }

    /// The home of the owner of the calendar (where the inbox, outbox and notifications of the calendar's owner live).
    pub fn dav_owner_home(&self, role: CalendarRole) -> String {
        format!("/dav/calendars/{}/{}/", self.tenant(role), self.owner(role))
    }

    /// The own home of an actor that is a principal; `None` for tokens and anonymous.
    pub fn dav_own_home(&self, actor: ActorRole) -> Option<String> {
        let principal = self.world.principal(actor).ok()?;
        Some(format!("/dav/calendars/{}/{}/", principal.tenant, principal.name))
    }

    /// The personal calendar of an actor that is a principal.
    pub fn dav_own_personal(&self, actor: ActorRole) -> Option<String> {
        Some(format!("{}personal/", self.dav_own_home(actor)?))
    }

    /// Whether the actor reaches the calendar through a binding in the own home.
    pub fn is_bound(&self, actor: ActorRole, role: CalendarRole) -> bool {
        let Ok(principal) = self.world.principal(actor) else {
            return false;
        };
        self.dav_collection(actor, role)
            .format()
            .starts_with(&format!("/dav/calendars/{}/{}/", principal.tenant, principal.name))
    }

    /// The calendar user address of the owner of the calendar, if the owner has one.
    pub fn owner_address(&self, role: CalendarRole) -> Option<String> {
        let calendar = self.calendar(role);
        self.world
            .principal_named(calendar.key.tenant.as_str(), calendar.key.owner.as_str())
            .ok()?
            .address()
            .map(|address| address.as_str().to_owned())
    }

    /// The calendar user address of an actor that is a principal with an address.
    pub fn actor_address(&self, actor: ActorRole) -> Option<String> {
        self.world
            .principal(actor)
            .ok()?
            .address()
            .map(|address| address.as_str().to_owned())
    }

    /// The root of the management API paths of the calendar's tenant.
    pub fn api_base(&self, role: CalendarRole) -> String {
        format!("/api/v1/tenants/{}", self.tenant(role))
    }

    /// The management API path of the calendar.
    pub fn api_calendar(&self, role: CalendarRole) -> String {
        format!(
            "{}/principals/{}/calendars/{}",
            self.api_base(role),
            self.owner(role),
            self.slug(role)
        )
    }

    /// The management API path of the owner of the calendar.
    pub fn api_owner(&self, role: CalendarRole) -> String {
        format!("{}/principals/{}", self.api_base(role), self.owner(role))
    }
}

/// An object name as a path segment: the characters `A-Za-z0-9._@:~+=-` of the names of the world are legal as they
/// are, anything else is percent-encoded.
pub fn object_segment(name: &str) -> String {
    name.bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"._@:~+=-".contains(&byte) {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actors_reach_calendars_through_their_bindings_or_probe_the_owners_home() {
        let world = FixtureWorld::standard();
        let at = Addressing::new(&world);
        assert_eq!(
            at.dav_collection_path(ActorRole::ShareeRead, CalendarRole::Shared),
            "/dav/calendars/acme/rita/projects/"
        );
        assert_eq!(
            at.dav_collection_path(ActorRole::TenantToken, CalendarRole::Shared),
            "/dav/calendars/acme/olivia/projects/",
            "a token has no home"
        );
        assert_eq!(
            at.dav_object_path(ActorRole::Owner, CalendarRole::Personal),
            "/dav/calendars/acme/olivia/personal/personal-event@acme.example.ics"
        );
        assert_eq!(
            at.dav_new_object_path(ActorRole::Owner, CalendarRole::Personal, "a b.ics"),
            "/dav/calendars/acme/olivia/personal/a%20b.ics"
        );
        assert_eq!(at.dav_owner_home(CalendarRole::Group), "/dav/calendars/acme/team/");
        assert_eq!(
            at.dav_own_personal(ActorRole::OtherUser).as_deref(),
            Some("/dav/calendars/acme/otto/personal/")
        );
        assert_eq!(at.dav_own_home(ActorRole::SystemToken), None);
        assert!(at.is_bound(ActorRole::ShareeRead, CalendarRole::Shared));
        assert!(!at.is_bound(ActorRole::OtherUser, CalendarRole::Shared));
        assert!(at.is_bound(ActorRole::Owner, CalendarRole::Personal));
        assert!(!at.is_bound(ActorRole::Anonymous, CalendarRole::Personal));
    }

    #[test]
    fn the_api_addresses_calendars_by_owner_and_slug() {
        let world = FixtureWorld::standard();
        let at = Addressing::new(&world);
        assert_eq!(
            at.api_calendar(CalendarRole::Group),
            "/api/v1/tenants/acme/principals/team/calendars/team-calendar"
        );
        assert_eq!(
            at.api_owner(CalendarRole::Managed),
            "/api/v1/tenants/acme/principals/robot"
        );
        assert_eq!(
            at.owner_address(CalendarRole::Personal).as_deref(),
            Some("mailto:olivia@acme.example")
        );
        assert_eq!(
            at.owner_address(CalendarRole::Managed),
            None,
            "a service principal has no address"
        );
        assert_eq!(
            at.actor_address(ActorRole::OtherUser).as_deref(),
            Some("mailto:otto@acme.example")
        );
        assert!(at.owner_is_group(CalendarRole::Group) && !at.owner_is_group(CalendarRole::Personal));
    }

    #[test]
    fn names_are_encoded_as_path_segments() {
        assert_eq!(
            object_segment("personal-event@acme.example.ics"),
            "personal-event@acme.example.ics"
        );
        assert_eq!(object_segment("a b/c.ics"), "a%20b%2Fc.ics");
    }
}
