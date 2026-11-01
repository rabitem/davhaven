//! The standard world of the fake: two tenants, a handful of principals, calendars and credentials with constant
//! names, so protocol tests can log in and address resources without any setup.
//!
//! ```text
//! tenant acme (login domain acme.example)
//!   anna   user      password ANNA_PASSWORD   calendars personal, work (event standup.ics)
//!   ben    user      password BEN_PASSWORD    calendar  personal
//!   cara   user      password CARA_PASSWORD   suspended: cannot log in
//!   team   group     members anna and ben     group calendar team-calendar
//!   room1  resource
//!   robot  service
//!   tokens: ADMIN_TOKEN (tenant token, every tenant scope), ANNA_TOKEN (principal token with mcp scopes)
//! tenant globex (login domain globex.example)
//!   gina   user      password GINA_PASSWORD
//! system token: SYSTEM_TOKEN
//! ```

#![expect(
    clippy::expect_used,
    reason = "the seed parses string literals that are valid by construction; the smoke test builds the world"
)]

use davhaven_domain::{
    CalendarKind, CalendarSlug, DomainName, Email, ObjectUri, PrincipalKind, PrincipalName, PrincipalStatus, Scope,
    ScopeSet, TenantSlug, TokenKind,
};

use crate::state::FakeWorld;

/// The slug of the main tenant.
pub const TENANT: &str = "acme";
/// The login domain of the main tenant: users log in as `anna@acme.example`.
pub const LOGIN_DOMAIN: &str = "acme.example";
/// The slug of the second tenant, for isolation tests.
pub const OTHER_TENANT: &str = "globex";
/// The login domain of the second tenant.
pub const OTHER_LOGIN_DOMAIN: &str = "globex.example";

/// The app password of `anna`.
pub const ANNA_PASSWORD: &str = "anna-secret-pass";
/// The app password of `ben`.
pub const BEN_PASSWORD: &str = "ben-secret-pass";
/// The app password of the suspended `cara`.
pub const CARA_PASSWORD: &str = "cara-secret-pass";
/// The app password of `gina` of the other tenant.
pub const GINA_PASSWORD: &str = "gina-secret-pass";

/// The tenant token with every tenant scope.
pub const ADMIN_TOKEN: &str = "dvh_pat_fakeadmin_secret";
/// The principal token of `anna` with the calendar, event and MCP scopes.
pub const ANNA_TOKEN: &str = "dvh_pat_fakeanna00_secret";
/// The system token (`system:tenants`).
pub const SYSTEM_TOKEN: &str = "dvh_pat_fakesystem_secret";

/// The event of `anna`'s `work` calendar.
pub const STANDUP_ICS: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Davhaven//app-fake//EN\r\n\
BEGIN:VEVENT\r\nUID:standup-1@acme.example\r\nDTSTAMP:20270101T000000Z\r\nSUMMARY:Standup\r\n\
DTSTART;TZID=Europe/Berlin:20270301T100000\r\nDTEND;TZID=Europe/Berlin:20270301T101500\r\nEND:VEVENT\r\n\
END:VCALENDAR\r\n";

fn slug(text: &str) -> TenantSlug {
    TenantSlug::parse(text).expect("a valid tenant slug")
}

fn name(text: &str) -> PrincipalName {
    PrincipalName::parse(text).expect("a valid principal name")
}

fn calendar_slug(text: &str) -> CalendarSlug {
    CalendarSlug::parse(text).expect("a valid calendar slug")
}

fn email(text: &str) -> Email {
    Email::parse(text).expect("a valid e-mail address")
}

fn domain(text: &str) -> DomainName {
    DomainName::parse(text).expect("a valid domain name")
}

/// The scopes of the tenant token: everything a tenant token may carry.
fn tenant_scopes() -> ScopeSet {
    Scope::ALL
        .iter()
        .copied()
        .filter(|scope| scope.allowed_for(TokenKind::Tenant))
        .collect()
}

/// Builds the standard world described in the module documentation.
///
/// # Panics
///
/// Never in practice: the function only parses string literals that are valid by construction.
pub fn standard_world() -> FakeWorld {
    let mut world = FakeWorld::new();
    let acme = world.add_tenant(slug(TENANT), "Acme", Some(domain(LOGIN_DOMAIN)));
    let globex = world.add_tenant(slug(OTHER_TENANT), "Globex", Some(domain(OTHER_LOGIN_DOMAIN)));

    let anna = world.add_principal(
        acme,
        PrincipalKind::User,
        name("anna"),
        "Anna Acme",
        Some(email("anna@acme.example")),
    );
    let ben = world.add_principal(
        acme,
        PrincipalKind::User,
        name("ben"),
        "Ben Baker",
        Some(email("ben@acme.example")),
    );
    let cara = world.add_principal(
        acme,
        PrincipalKind::User,
        name("cara"),
        "Cara Clark",
        Some(email("cara@acme.example")),
    );
    let team = world.add_principal(acme, PrincipalKind::Group, name("team"), "The Team", None);
    world.add_principal(
        acme,
        PrincipalKind::Resource,
        name("room1"),
        "Meeting room 1",
        Some(email("room1@acme.example")),
    );
    world.add_principal(acme, PrincipalKind::Service, name("robot"), "Robot", None);
    let gina = world.add_principal(
        globex,
        PrincipalKind::User,
        name("gina"),
        "Gina Globex",
        Some(email("gina@globex.example")),
    );

    if let Some(principal) = world.principals.get_mut(&cara) {
        principal.status = PrincipalStatus::Suspended;
    }
    world.add_member(team, anna);
    world.add_member(team, ben);

    let work = world.add_calendar(anna, calendar_slug("work"), CalendarKind::User, "Work");
    world.add_object(
        work,
        ObjectUri::parse("standup.ics").expect("a valid object name"),
        STANDUP_ICS,
    );
    world.add_calendar(
        team,
        calendar_slug("team-calendar"),
        CalendarKind::Group,
        "Team calendar",
    );

    world.add_app_password(anna, ANNA_PASSWORD);
    world.add_app_password(ben, BEN_PASSWORD);
    world.add_app_password(cara, CARA_PASSWORD);
    world.add_app_password(gina, GINA_PASSWORD);

    world.add_api_token(Some(acme), TokenKind::Tenant, None, tenant_scopes(), ADMIN_TOKEN);
    world.add_api_token(
        Some(acme),
        TokenKind::Principal,
        Some(anna),
        ScopeSet::of(&[
            Scope::CalendarsRead,
            Scope::CalendarsWrite,
            Scope::EventsRead,
            Scope::EventsWrite,
            Scope::McpRead,
            Scope::McpWrite,
        ]),
        ANNA_TOKEN,
    );
    world.add_api_token(
        None,
        TokenKind::System,
        None,
        ScopeSet::of(&[Scope::SystemTenants]),
        SYSTEM_TOKEN,
    );
    world
}
