//! Contract suites of the `Authenticator` port.
//!
//! Two suites, because two different things are promised.
//!
//! [`run`] is what **every** authenticator promises, `noop` included, without any store: a value that is not a
//! credential of its kind is passed on (`NotApplicable`) or refused, never accepted; a well-formed credential that no
//! store knows is never accepted; and no input, however odd or large, makes it fail or accept.
//!
//! [`run_store_backed`] is what an authenticator promises that verifies the credentials of the Davhaven store (the
//! local authenticator; a token introspection authenticator would not run it). It is run against a real store (the
//! memory adapter, and PostgreSQL where a rig for it exists) so that the rules hold for what the application actually
//! writes:
//!
//! * every kind of credential authenticates on its own surface as the actor its kind names, with the scopes of the
//!   row (app passwords on `dav`, API tokens on `api` and `mcp`, feed tokens and RSVP tokens on their pages);
//! * every credential is refused on every other surface;
//! * values that are not of the authenticator's kind pass on (`NotApplicable`) and malformed marked ones are
//!   refused, without reaching the store;
//! * wrong secrets and unknown prefixes are refused, never accepted, and a cached success never makes a wrong
//!   secret pass;
//! * revoked and expired credentials, suspended and deleted principals and suspended tenants are refused, and the
//!   revocation of **one** credential applies at once even to a credential that was accepted a moment before,
//!   without anyone bumping the principal's `credential_generation`;
//! * logins must be the owner's; a valid credential is authenticated whatever tenant the request path names (the
//!   application answers 404 for the path, R4), except that a bare login name means "this name in the tenant of the
//!   path";
//! * a use is recorded in `last_used_at` once the authenticator's worker has flushed it.
//!
//! # The convention of the stored hash
//!
//! The suite mints credentials the way the application does: the row stores `CredentialHasher::hash(kind, secret)`
//! where `secret` is the whole app password in its canonical form, or, for tokens, the 43 characters after the prefix;
//! the prefix of an app password is its first two groups and the prefix of a token the 12 characters after the
//! marker. The suite does not repeat these rules: it splits credentials with
//! `davhaven_domain::credential_format`, the one definition that the application and the authenticators share.
//!
//! The factory builds a **rig**: the authenticator under test, the database it reads and the hasher it verifies
//! with, and the one `ManualClock` that the authenticator and the database share. The suite seeds the database
//! through the port, so a rig can be built over any store. Nothing in the suite sleeps.

use core::fmt::Debug;
use std::future::Future;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use davhaven_domain::{
    Actor, ApiToken, AppPassword, AppPasswordText, CalendarUserAddress, CredentialKind, CredentialRef, FeedMode,
    FeedToken, ObjectId, PrincipalId, PrincipalStatus, RequestId, RsvpToken, Scope, ScopeSet, TenantId, TenantStatus,
    TokenId, TokenKind, TokenText,
};
use davhaven_fixtures::world::{api_token_secret, app_password_secret, feed_token_secret, rsvp_token_secret};
use davhaven_ports::testing::ManualClock;
use davhaven_ports::{
    AuthHint, AuthOutcome, Authenticated, Authenticator, Clock as _, CredentialHasher, Database, Expected,
    PresentedCredential, RejectReason, StoreError, TxMode, Worker,
};
use secrecy::SecretString;
use uuid::Uuid;

use crate::store::fixtures::{World, seed, version};
use crate::suite::{Checks, ContractReport, Suite};

/// What a factory builds: the authenticator and everything the suite needs to seed and drive it.
pub struct AuthRig {
    /// The authenticator under test.
    pub authenticator: Arc<dyn Authenticator>,
    /// The database the authenticator reads; the suite seeds it through the port.
    pub database: Arc<dyn Database>,
    /// The hasher the authenticator verifies with; the suite hashes the secrets of its rows with it.
    pub hasher: Arc<dyn CredentialHasher>,
    /// The clock of both the database and the authenticator.
    pub clock: ManualClock,
    /// The worker that flushes `last_used_at`, if the authenticator has one.
    pub flush: Option<Arc<dyn Worker>>,
}

/// A credential the suite put into the store.
#[derive(Debug, Clone)]
struct Minted {
    id: Uuid,
    presented: String,
}

/// The rows the cases work on.
struct Seeded {
    world: World,
    object: ObjectId,
    password: Minted,
    gina_password: Minted,
    tenant_token: Minted,
    principal_token: Minted,
    system_token: Minted,
    feed_token: Minted,
    rsvp_token: Minted,
}

const SCOPES: [Scope; 2] = [Scope::PrincipalsRead, Scope::CalendarsWrite];
const ACME_LOGIN: &str = "mia@acme.example";

fn epoch() -> DateTime<Utc> {
    DateTime::UNIX_EPOCH
}

fn nobody() -> TenantId {
    TenantId::from_uuid(Uuid::nil())
}

fn id(n: u128) -> Uuid {
    Uuid::from_u128(0x0190_0000_0001_7000_8000_0000_0000_0000 | (0x8000 + n))
}

fn secret(text: &str) -> SecretString {
    SecretString::from(text)
}

/// The prefix of an app password and of a token, and the secret that is hashed, as the one definition of the formats
/// (`davhaven_domain::credential_format`) splits them. A value that is no credential of its kind has no prefix: the
/// row built from it finds nothing, which fails the case that expected it to authenticate.
fn split(kind: CredentialKind, presented: &str) -> (String, String) {
    if kind == CredentialKind::AppPassword {
        return AppPasswordText::parse(presented).map_or_else(
            || (String::new(), presented.to_owned()),
            |password| (password.prefix().to_owned(), password.expose().to_owned()),
        );
    }
    TokenText::parse(kind, presented).map_or_else(
        || (String::new(), presented.to_owned()),
        |token| (token.prefix().to_owned(), token.secret().to_owned()),
    )
}

struct Kit {
    rig: AuthRig,
    seeded: Seeded,
}

/// The prefix, hash and pepper key id a row stores for a presented credential.
fn hashed(rig: &AuthRig, kind: CredentialKind, presented: &str) -> (String, Vec<u8>, String) {
    let (prefix, secret_text) = split(kind, presented);
    let stored = rig.hasher.hash(kind, &secret(&secret_text));
    (prefix, stored.hash, stored.pepper_kid)
}

/// An app password row.
fn app_password_row(rig: &AuthRig, n: u128, principal: PrincipalId, presented: &str) -> AppPassword {
    let (prefix, hash, pepper_kid) = hashed(rig, CredentialKind::AppPassword, presented);
    AppPassword {
        id: id(n).into(),
        tenant_id: nobody(),
        principal_id: principal,
        label: "iPhone".to_owned(),
        prefix,
        hash,
        pepper_kid,
        last_used_at: None,
        revoked_at: None,
        created_at: epoch(),
        updated_at: epoch(),
        version: 99,
    }
}

/// An API token row without expiry.
fn token_row(
    rig: &AuthRig,
    n: u128,
    kind: TokenKind,
    principal: Option<PrincipalId>,
    scopes: &[Scope],
    presented: &str,
) -> ApiToken {
    let (prefix, hash, pepper_kid) = hashed(rig, CredentialKind::ApiToken, presented);
    ApiToken {
        id: TokenId::from_uuid(id(n)),
        tenant_id: None,
        kind,
        principal_id: principal,
        label: "ci".to_owned(),
        scopes: ScopeSet::of(scopes),
        prefix,
        hash,
        pepper_kid,
        expires_at: None,
        created_by: None,
        allowed_origins: Vec::new(),
        last_used_at: None,
        revoked_at: None,
        created_at: epoch(),
        updated_at: epoch(),
        version: 99,
    }
}

/// A feed token row.
fn feed_row(rig: &AuthRig, n: u128, principal: PrincipalId, presented: &str) -> FeedToken {
    let (prefix, hash, pepper_kid) = hashed(rig, CredentialKind::FeedToken, presented);
    FeedToken {
        id: TokenId::from_uuid(id(n)),
        tenant_id: nobody(),
        principal_id: principal,
        mode: FeedMode::Busy,
        calendar_ids: Vec::new(),
        prefix,
        hash,
        pepper_kid,
        revoked_at: None,
        created_at: epoch(),
        updated_at: epoch(),
        version: 99,
    }
}

/// An RSVP token row.
fn rsvp_row(
    rig: &AuthRig,
    n: u128,
    object: ObjectId,
    expires_at: DateTime<Utc>,
    presented: &str,
) -> Result<RsvpToken, StoreError> {
    let (prefix, hash, pepper_kid) = hashed(rig, CredentialKind::RsvpToken, presented);
    Ok(RsvpToken {
        id: TokenId::from_uuid(id(n)),
        tenant_id: nobody(),
        object_id: object,
        attendee_address: guest().map_err(StoreError::internal)?,
        prefix,
        hash,
        pepper_kid,
        expires_at,
        revoked_at: None,
        last_used_at: None,
        last_response: None,
        created_at: epoch(),
        updated_at: epoch(),
        version: 99,
    })
}

/// Seeds the tenants and principals of the store suite, an object, and one credential of every kind.
async fn seeded(rig: &AuthRig) -> Result<Seeded, StoreError> {
    let world = seed(&rig.database).await?;
    let now = rig.clock.now();
    let minted = |n: u128, presented: String| Minted { id: id(n), presented };
    let password = minted(1, app_password_secret("mia-iphone"));
    let tenant_token = minted(2, api_token_secret("acme-admin"));
    let principal_token = minted(3, api_token_secret("mia-mcp"));
    let feed_token = minted(4, feed_token_secret("mia-feed"));
    let rsvp_token = minted(5, rsvp_token_secret("guest"));
    let gina_password = minted(6, app_password_secret("gina-laptop"));
    let system_token = minted(7, api_token_secret("root"));

    let mut tx = rig.database.begin(world.a, TxMode::ReadWrite).await?;
    let written = tx
        .objects()
        .put(world.personal, version(0x4C1, "m.ics", "meeting")?, Expected::Absent)
        .await?;
    tx.credentials()
        .create_app_password(app_password_row(rig, 1, world.mia, &password.presented))
        .await?;
    tx.credentials()
        .create_api_token(token_row(
            rig,
            2,
            TokenKind::Tenant,
            None,
            &SCOPES,
            &tenant_token.presented,
        ))
        .await?;
    let mut mcp = token_row(
        rig,
        3,
        TokenKind::Principal,
        Some(world.mia),
        &[Scope::EventsRead, Scope::McpRead],
        &principal_token.presented,
    );
    mcp.expires_at = Some(now + Duration::days(30));
    tx.credentials().create_api_token(mcp).await?;
    tx.credentials()
        .create_feed_token(feed_row(rig, 4, world.mia, &feed_token.presented))
        .await?;
    tx.rsvp()
        .create(rsvp_row(
            rig,
            5,
            written.object_id,
            now + Duration::days(7),
            &rsvp_token.presented,
        )?)
        .await?;
    tx.commit().await?;

    let mut tx = rig.database.begin(world.b, TxMode::ReadWrite).await?;
    tx.credentials()
        .create_app_password(app_password_row(rig, 6, world.gina, &gina_password.presented))
        .await?;
    tx.commit().await?;

    let mut system = rig.database.begin_system().await?;
    let root = token_row(
        rig,
        7,
        TokenKind::System,
        None,
        &[Scope::SystemTenants],
        &system_token.presented,
    );
    system.credential_lookup().create_system_token(root).await?;
    system.commit().await?;

    Ok(Seeded {
        world,
        object: written.object_id,
        password,
        gina_password,
        tenant_token,
        principal_token,
        system_token,
        feed_token,
        rsvp_token,
    })
}

impl Kit {
    fn hint(channel: davhaven_domain::Channel, tenant: Option<&str>) -> AuthHint {
        AuthHint {
            channel,
            tenant_hint: tenant.and_then(|slug| davhaven_domain::TenantSlug::parse(slug).ok()),
            client_ip: None,
            request_id: RequestId::from_uuid(Uuid::nil()),
        }
    }

    async fn ask(
        &self,
        credential: &PresentedCredential,
        channel: davhaven_domain::Channel,
        tenant: Option<&str>,
    ) -> Result<AuthOutcome, davhaven_ports::PortError> {
        self.rig
            .authenticator
            .authenticate(credential, &Self::hint(channel, tenant))
            .await
    }

    /// The outcome, or a recorded failure when the authenticator itself failed.
    async fn outcome(
        &self,
        checks: &mut Checks,
        credential: &PresentedCredential,
        channel: davhaven_domain::Channel,
        tenant: Option<&str>,
        what: &str,
    ) -> Option<AuthOutcome> {
        checks.ok(self.ask(credential, channel, tenant).await, what)
    }

    async fn expect_rejected(
        &self,
        checks: &mut Checks,
        credential: &PresentedCredential,
        channel: davhaven_domain::Channel,
        tenant: Option<&str>,
        reason: RejectReason,
        what: &str,
    ) {
        if let Some(outcome) = self.outcome(checks, credential, channel, tenant, what).await {
            checks.equal(&outcome, &AuthOutcome::Rejected(reason), what);
        }
    }

    async fn expect_accepted(
        &self,
        checks: &mut Checks,
        credential: &PresentedCredential,
        channel: davhaven_domain::Channel,
        tenant: Option<&str>,
        what: &str,
    ) -> Option<Authenticated> {
        match self.outcome(checks, credential, channel, tenant, what).await? {
            AuthOutcome::Accepted(authenticated) => Some(authenticated),
            other => {
                checks.fail(format!("{what}: expected the credential to be accepted, got {other:?}"));
                None
            }
        }
    }
}

/// The attendee the RSVP token of the suite was issued to.
fn guest() -> Result<CalendarUserAddress, String> {
    CalendarUserAddress::parse("mailto:guest@example.org")
        .map_err(|error| format!("the suite's fixture is invalid: {error}"))
}

fn basic(login: &str, password: &Minted) -> PresentedCredential {
    PresentedCredential::Basic {
        username: login.to_owned(),
        password: secret(&password.presented),
    }
}

fn bearer(token: &Minted) -> PresentedCredential {
    PresentedCredential::Bearer(secret(&token.presented))
}

fn feed(token: &Minted) -> PresentedCredential {
    PresentedCredential::Feed(secret(&token.presented))
}

fn rsvp(token: &Minted) -> PresentedCredential {
    PresentedCredential::Rsvp(secret(&token.presented))
}

/// Changes the last character of a presented secret, so that the prefix stays and the secret is wrong.
fn tampered(presented: &str) -> String {
    let mut text = presented.to_owned();
    let last = text.pop().unwrap_or('a');
    text.push(if last == 'a' { 'b' } else { 'a' });
    text
}

type Channel = davhaven_domain::Channel;

/// What an accepted credential must turn into.
struct Identity {
    what: &'static str,
    credential: PresentedCredential,
    channel: Channel,
    tenant: Option<TenantId>,
    actor: Actor,
    reference: CredentialRef,
    scopes: ScopeSet,
}

/// The identity every credential of the seeded world must authenticate as.
fn identities(kit: &Kit) -> Result<Vec<Identity>, String> {
    let Seeded {
        world,
        object,
        password,
        tenant_token,
        principal_token,
        system_token,
        feed_token,
        rsvp_token,
        ..
    } = &kit.seeded;
    let token_id = |minted: &Minted| TokenId::from_uuid(minted.id);
    let mut expected = vec![
        Identity {
            what: "an app password",
            credential: basic(ACME_LOGIN, password),
            channel: Channel::Dav,
            tenant: Some(world.a),
            actor: Actor::Principal(world.mia),
            reference: CredentialRef::app_password(password.id.into()),
            scopes: ScopeSet::empty(),
        },
        Identity {
            what: "a tenant token",
            credential: bearer(tenant_token),
            channel: Channel::Api,
            tenant: Some(world.a),
            actor: Actor::TenantToken(token_id(tenant_token)),
            reference: CredentialRef::api_token(token_id(tenant_token)),
            scopes: ScopeSet::of(&SCOPES),
        },
        Identity {
            what: "a system token",
            credential: bearer(system_token),
            channel: Channel::Api,
            tenant: None,
            actor: Actor::SystemToken(token_id(system_token)),
            reference: CredentialRef::api_token(token_id(system_token)),
            scopes: ScopeSet::of(&[Scope::SystemTenants]),
        },
        Identity {
            what: "a feed token",
            credential: feed(feed_token),
            channel: Channel::Feed,
            tenant: Some(world.a),
            actor: Actor::FeedReader {
                principal: world.mia,
                token: token_id(feed_token),
            },
            reference: CredentialRef::feed_token(token_id(feed_token)),
            scopes: ScopeSet::empty(),
        },
        Identity {
            what: "an RSVP token",
            credential: rsvp(rsvp_token),
            channel: Channel::Rsvp,
            tenant: Some(world.a),
            actor: Actor::RsvpAttendee {
                object: *object,
                address: guest()?,
            },
            reference: CredentialRef::rsvp_token(token_id(rsvp_token)),
            scopes: ScopeSet::empty(),
        },
    ];
    for (what, channel) in [
        ("a principal token on the API", Channel::Api),
        ("a principal token on MCP", Channel::Mcp),
    ] {
        expected.push(Identity {
            what,
            credential: bearer(principal_token),
            channel,
            tenant: Some(world.a),
            actor: Actor::PrincipalToken {
                principal: world.mia,
                token: token_id(principal_token),
            },
            reference: CredentialRef::api_token(token_id(principal_token)),
            scopes: ScopeSet::of(&[Scope::EventsRead, Scope::McpRead]),
        });
    }
    Ok(expected)
}

async fn every_kind_authenticates_on_its_surface(kit: &Kit, checks: &mut Checks) {
    let expected = match identities(kit) {
        Ok(expected) => expected,
        Err(error) => return checks.fail(error),
    };
    for case in expected {
        let Some(auth) = kit
            .expect_accepted(checks, &case.credential, case.channel, None, case.what)
            .await
        else {
            continue;
        };
        checks.equal(&auth.tenant, &case.tenant, &format!("the tenant of {}", case.what));
        checks.equal(&auth.actor, &case.actor, &format!("the actor of {}", case.what));
        checks.equal(
            &auth.credential,
            &case.reference,
            &format!("the credential of {}", case.what),
        );
        checks.equal(&auth.scopes, &case.scopes, &format!("the scopes of {}", case.what));
    }
}

async fn credentials_are_bound_to_their_surface(kit: &Kit, checks: &mut Checks) {
    let seeded = &kit.seeded;
    let others = |own: &[Channel]| -> Vec<Channel> {
        Channel::ALL
            .iter()
            .copied()
            .filter(|channel| !own.contains(channel))
            .collect()
    };
    for channel in others(&[Channel::Dav]) {
        kit.expect_rejected(
            checks,
            &basic(ACME_LOGIN, &seeded.password),
            channel,
            None,
            RejectReason::WrongSurface,
            &format!("an app password on {channel}"),
        )
        .await;
    }
    for (name, token) in [
        ("a tenant token", &seeded.tenant_token),
        ("a principal token", &seeded.principal_token),
        ("a system token", &seeded.system_token),
    ] {
        for channel in others(&[Channel::Api, Channel::Mcp]) {
            kit.expect_rejected(
                checks,
                &bearer(token),
                channel,
                None,
                RejectReason::WrongSurface,
                &format!("{name} on {channel}"),
            )
            .await;
        }
    }
    for channel in others(&[Channel::Feed]) {
        kit.expect_rejected(
            checks,
            &feed(&seeded.feed_token),
            channel,
            None,
            RejectReason::WrongSurface,
            &format!("a feed token on {channel}"),
        )
        .await;
    }
    for channel in others(&[Channel::Rsvp]) {
        kit.expect_rejected(
            checks,
            &rsvp(&seeded.rsvp_token),
            channel,
            None,
            RejectReason::WrongSurface,
            &format!("an RSVP token on {channel}"),
        )
        .await;
    }
    // A token of one kind presented as another kind of credential.
    kit.expect_rejected(
        checks,
        &bearer(&seeded.feed_token),
        Channel::Api,
        None,
        RejectReason::WrongSurface,
        "a feed token as a bearer token",
    )
    .await;
    kit.expect_rejected(
        checks,
        &feed(&seeded.rsvp_token),
        Channel::Feed,
        None,
        RejectReason::WrongSurface,
        "an RSVP token in a feed URL",
    )
    .await;
}

async fn foreign_and_malformed_values(kit: &Kit, checks: &mut Checks) {
    for (what, credential, channel) in [
        (
            "a JWT as a bearer token",
            PresentedCredential::Bearer(secret("eyJhbGciOiJIUzI1NiJ9.e30.sig")),
            Channel::Api,
        ),
        (
            "an empty bearer token",
            PresentedCredential::Bearer(secret("")),
            Channel::Api,
        ),
        (
            "an ordinary password",
            PresentedCredential::Basic {
                username: ACME_LOGIN.to_owned(),
                password: secret("correct horse battery staple"),
            },
            Channel::Dav,
        ),
        (
            "a random feed token",
            PresentedCredential::Feed(secret("not-a-token")),
            Channel::Feed,
        ),
    ] {
        if let Some(outcome) = kit.outcome(checks, &credential, channel, None, what).await {
            checks.equal(&outcome, &AuthOutcome::NotApplicable, what);
        }
    }
    for (what, credential, channel) in [
        (
            "a truncated API token",
            PresentedCredential::Bearer(secret("dvh_pat_short")),
            Channel::Api,
        ),
        (
            "a truncated feed token",
            PresentedCredential::Feed(secret("dvh_feed_abc_def")),
            Channel::Feed,
        ),
    ] {
        kit.expect_rejected(checks, &credential, channel, None, RejectReason::Malformed, what)
            .await;
    }
}

/// A credential that is in no store, for the refusals of unknown ones.
fn unminted(presented: String) -> Minted {
    Minted { id: id(0), presented }
}

async fn wrong_and_unknown_secrets(kit: &Kit, checks: &mut Checks) {
    let seeded = &kit.seeded;
    let right_password = basic(ACME_LOGIN, &seeded.password);
    let right_token = bearer(&seeded.tenant_token);
    // Warm whatever the authenticator caches, then present wrong secrets under the same prefixes.
    kit.expect_accepted(checks, &right_password, Channel::Dav, None, "the right password")
        .await;
    kit.expect_accepted(checks, &right_token, Channel::Api, None, "the right token")
        .await;

    let wrong_password = basic(ACME_LOGIN, &unminted(tampered(&seeded.password.presented)));
    kit.expect_rejected(
        checks,
        &wrong_password,
        Channel::Dav,
        None,
        RejectReason::BadSecret,
        "a wrong app password",
    )
    .await;
    let wrong_token = bearer(&unminted(tampered(&seeded.tenant_token.presented)));
    for _ in 0..2 {
        kit.expect_rejected(
            checks,
            &wrong_token,
            Channel::Api,
            None,
            RejectReason::BadSecret,
            "a wrong token, asked twice (failures are never cached)",
        )
        .await;
    }
    let unknown = [
        (
            "an unknown app password",
            basic(ACME_LOGIN, &unminted(app_password_secret("nobody"))),
            Channel::Dav,
        ),
        (
            "an unknown token",
            bearer(&unminted(api_token_secret("nobody"))),
            Channel::Api,
        ),
        (
            "an unknown feed token",
            feed(&unminted(feed_token_secret("nobody"))),
            Channel::Feed,
        ),
        (
            "an unknown RSVP token",
            rsvp(&unminted(rsvp_token_secret("nobody"))),
            Channel::Rsvp,
        ),
    ];
    for (what, credential, channel) in &unknown {
        kit.expect_rejected(
            checks,
            credential,
            *channel,
            None,
            RejectReason::UnknownCredential,
            what,
        )
        .await;
    }
    // The right secrets still work afterwards.
    kit.expect_accepted(checks, &right_password, Channel::Dav, None, "the right password again")
        .await;
}

/// Revokes every credential of Mia and bumps her credential generation, as the credential service does.
async fn revoke_everything(kit: &Kit) -> Result<(), StoreError> {
    let seeded = &kit.seeded;
    let mut tx = kit.rig.database.begin(seeded.world.a, TxMode::ReadWrite).await?;
    tx.credentials().revoke_app_password(seeded.password.id.into()).await?;
    tx.credentials()
        .revoke_api_token(TokenId::from_uuid(seeded.tenant_token.id))
        .await?;
    tx.credentials()
        .revoke_api_token(TokenId::from_uuid(seeded.principal_token.id))
        .await?;
    tx.credentials()
        .revoke_feed_token(TokenId::from_uuid(seeded.feed_token.id))
        .await?;
    tx.rsvp().revoke(TokenId::from_uuid(seeded.rsvp_token.id)).await?;
    tx.principals().bump_credential_generation(seeded.world.mia).await?;
    tx.commit().await
}

async fn revocation_applies_at_once(kit: &Kit, checks: &mut Checks) {
    let seeded = &kit.seeded;
    // Accepted a moment ago (and therefore possibly cached) ...
    for (what, credential, channel) in credentials_of_mia(seeded) {
        kit.expect_accepted(checks, &credential, channel, None, what).await;
    }
    checks.ok(revoke_everything(kit).await, "revoking the credentials");
    // ... and refused now, whatever the authenticator remembers.
    for (what, credential, channel) in credentials_of_mia(seeded) {
        kit.expect_rejected(
            checks,
            &credential,
            channel,
            None,
            RejectReason::Revoked,
            &format!("{what} after revocation"),
        )
        .await;
    }
    kit.expect_accepted(
        checks,
        &bearer(&seeded.system_token),
        Channel::Api,
        None,
        "a system token is unaffected by revocations of others",
    )
    .await;
}

async fn a_revocation_alone_applies_at_once(kit: &Kit, checks: &mut Checks) {
    let seeded = &kit.seeded;
    // Warm whatever the authenticator remembers, with several uses.
    for _ in 0..3 {
        kit.expect_accepted(
            checks,
            &basic(ACME_LOGIN, &seeded.password),
            Channel::Dav,
            None,
            "the password",
        )
        .await;
        kit.expect_accepted(
            checks,
            &bearer(&seeded.principal_token),
            Channel::Mcp,
            None,
            "the principal token",
        )
        .await;
    }
    // Revoke one credential of each kind and nothing else: no bump of the credential generation, no status change.
    let revoked = async {
        let mut tx = kit.rig.database.begin(seeded.world.a, TxMode::ReadWrite).await?;
        tx.credentials().revoke_app_password(seeded.password.id.into()).await?;
        tx.commit().await
    }
    .await;
    if checks.ok(revoked, "revoking the app password").is_none() {
        return;
    }
    kit.expect_rejected(
        checks,
        &basic(ACME_LOGIN, &seeded.password),
        Channel::Dav,
        None,
        RejectReason::Revoked,
        "the app password right after its revocation, whatever is cached",
    )
    .await;
    kit.expect_accepted(
        checks,
        &bearer(&seeded.principal_token),
        Channel::Mcp,
        None,
        "the other credential of the same principal is not affected",
    )
    .await;
    let revoked = async {
        let mut tx = kit.rig.database.begin(seeded.world.a, TxMode::ReadWrite).await?;
        tx.credentials()
            .revoke_api_token(TokenId::from_uuid(seeded.principal_token.id))
            .await?;
        tx.commit().await
    }
    .await;
    if checks.ok(revoked, "revoking the principal token").is_none() {
        return;
    }
    kit.expect_rejected(
        checks,
        &bearer(&seeded.principal_token),
        Channel::Mcp,
        None,
        RejectReason::Revoked,
        "the principal token right after its revocation, whatever is cached",
    )
    .await;
}

fn credentials_of_mia(seeded: &Seeded) -> Vec<(&'static str, PresentedCredential, Channel)> {
    vec![
        ("an app password", basic(ACME_LOGIN, &seeded.password), Channel::Dav),
        ("a tenant token", bearer(&seeded.tenant_token), Channel::Api),
        ("a principal token", bearer(&seeded.principal_token), Channel::Mcp),
        ("a feed token", feed(&seeded.feed_token), Channel::Feed),
        ("an RSVP token", rsvp(&seeded.rsvp_token), Channel::Rsvp),
    ]
}

async fn expiry_follows_the_clock(kit: &Kit, checks: &mut Checks) {
    let seeded = &kit.seeded;
    let now = kit.rig.clock.now();
    // An API token that expires in an hour.
    let presented = api_token_secret("expiring");
    let created = async {
        let mut row = token_row(&kit.rig, 20, TokenKind::Tenant, None, &SCOPES, &presented);
        row.expires_at = Some(now + Duration::hours(1));
        let mut tx = kit.rig.database.begin(seeded.world.a, TxMode::ReadWrite).await?;
        tx.credentials().create_api_token(row).await?;
        tx.commit().await
    }
    .await;
    if checks.ok(created, "creating an expiring token").is_none() {
        return;
    }
    let expiring = Minted { id: id(20), presented };
    kit.expect_accepted(checks, &bearer(&expiring), Channel::Api, None, "before the expiry")
        .await;
    kit.rig.clock.advance(Duration::minutes(59));
    kit.expect_accepted(
        checks,
        &bearer(&expiring),
        Channel::Api,
        None,
        "a minute before the expiry",
    )
    .await;
    kit.rig.clock.advance(Duration::minutes(1));
    kit.expect_rejected(
        checks,
        &bearer(&expiring),
        Channel::Api,
        None,
        RejectReason::Expired,
        "at the expiry",
    )
    .await;
    // The RSVP link expires seven days after it was minted; a token without expiry (the tenant token) does not.
    kit.expect_accepted(
        checks,
        &rsvp(&seeded.rsvp_token),
        Channel::Rsvp,
        None,
        "an RSVP link in its week",
    )
    .await;
    kit.rig.clock.advance(Duration::days(7));
    kit.expect_rejected(
        checks,
        &rsvp(&seeded.rsvp_token),
        Channel::Rsvp,
        None,
        RejectReason::Expired,
        "an RSVP link after its week",
    )
    .await;
    kit.expect_accepted(
        checks,
        &bearer(&seeded.tenant_token),
        Channel::Api,
        None,
        "a token without expiry",
    )
    .await;
}

async fn suspension_and_deletion(kit: &Kit, checks: &mut Checks) {
    let seeded = &kit.seeded;
    let mia_credentials = [
        ("an app password", basic(ACME_LOGIN, &seeded.password), Channel::Dav),
        ("a principal token", bearer(&seeded.principal_token), Channel::Api),
        ("a feed token", feed(&seeded.feed_token), Channel::Feed),
    ];
    for (what, credential, channel) in &mia_credentials {
        kit.expect_accepted(checks, credential, *channel, None, what).await;
    }
    for status in [PrincipalStatus::Suspended, PrincipalStatus::Deleted] {
        let changed = async {
            let mut tx = kit.rig.database.begin(seeded.world.a, TxMode::ReadWrite).await?;
            let mut mia = tx.principals().get(seeded.world.mia).await?;
            let stored_version = mia.version;
            mia.status = status;
            mia.deleted_at = (status == PrincipalStatus::Deleted).then(|| kit.rig.clock.now());
            tx.principals().update(mia, stored_version).await?;
            tx.principals().bump_credential_generation(seeded.world.mia).await?;
            tx.commit().await
        }
        .await;
        if checks.ok(changed, "changing the status of the principal").is_none() {
            return;
        }
        for (what, credential, channel) in &mia_credentials {
            kit.expect_rejected(
                checks,
                credential,
                *channel,
                None,
                RejectReason::Suspended,
                &format!("{what} of a {status} principal"),
            )
            .await;
        }
        kit.expect_accepted(
            checks,
            &bearer(&seeded.tenant_token),
            Channel::Api,
            None,
            "a tenant token does not depend on a principal",
        )
        .await;
    }
    // A suspended tenant refuses every credential of the tenant, but not a system token.
    let suspended = async {
        let mut tx = kit.rig.database.begin_system().await?;
        let tenant = tx.tenants().get(seeded.world.a).await?;
        let stored_version = tenant.version;
        let mut tenant = tenant;
        tenant.status = TenantStatus::Suspended;
        tx.tenants().update(tenant, stored_version).await?;
        tx.commit().await
    }
    .await;
    if checks.ok(suspended, "suspending the tenant").is_none() {
        return;
    }
    kit.expect_rejected(
        checks,
        &bearer(&seeded.tenant_token),
        Channel::Api,
        None,
        RejectReason::Suspended,
        "a tenant token of a suspended tenant",
    )
    .await;
    kit.expect_rejected(
        checks,
        &rsvp(&seeded.rsvp_token),
        Channel::Rsvp,
        None,
        RejectReason::Suspended,
        "an RSVP link of a suspended tenant",
    )
    .await;
    kit.expect_accepted(
        checks,
        &bearer(&seeded.system_token),
        Channel::Api,
        None,
        "a system token ignores the status of tenants",
    )
    .await;
    kit.expect_accepted(
        checks,
        &basic("gina@globex.example", &seeded.gina_password),
        Channel::Dav,
        None,
        "another tenant is unaffected",
    )
    .await;
}

async fn names_are_checked(kit: &Kit, checks: &mut Checks) {
    logins_are_checked(kit, checks).await;
    tokens_ignore_the_tenant_of_the_path(kit, checks).await;
}

async fn logins_are_checked(kit: &Kit, checks: &mut Checks) {
    let seeded = &kit.seeded;
    for login in ["MIA@ACME.EXAMPLE", " mia@acme.example "] {
        kit.expect_accepted(checks, &basic(login, &seeded.password), Channel::Dav, None, login)
            .await;
    }
    kit.expect_accepted(
        checks,
        &basic("mia", &seeded.password),
        Channel::Dav,
        Some("acme"),
        "a bare name with the tenant of the path",
    )
    .await;
    for (login, tenant) in [
        ("mia", None),
        ("olivia@acme.example", None),
        ("mia@globex.example", None),
        ("mia", Some("globex")),
        ("", None),
    ] {
        kit.expect_rejected(
            checks,
            &basic(login, &seeded.password),
            Channel::Dav,
            tenant,
            RejectReason::UnknownCredential,
            &format!("the login {login:?} on the path of {tenant:?}"),
        )
        .await;
    }
    // A login that names its tenant needs no path, and a valid credential is authenticated whatever tenant the path
    // names: the resources of another tenant are invisible (404), they are not a reason to doubt the credential.
    // The application answers the 404; the authenticator must not report a failed authentication, which would
    // count toward the failure backoff of a client that did nothing wrong.
    for tenant in [Some("acme"), Some("globex"), Some("nonexistent")] {
        if let Some(auth) = kit
            .expect_accepted(
                checks,
                &basic(ACME_LOGIN, &seeded.password),
                Channel::Dav,
                tenant,
                &format!("a login that names its tenant, on the path of {tenant:?}"),
            )
            .await
        {
            checks.equal(
                &auth.tenant,
                &Some(seeded.world.a),
                "the tenant of the credential, not the one of the path",
            );
        }
    }
    if let Some(auth) = kit
        .expect_accepted(
            checks,
            &basic("gina@globex.example", &seeded.gina_password),
            Channel::Dav,
            Some("acme"),
            "a login of another tenant on this tenant's path",
        )
        .await
    {
        checks.equal(&auth.tenant, &Some(seeded.world.b), "authenticated for its own tenant");
    }
    kit.expect_accepted(
        checks,
        &basic("gina", &seeded.gina_password),
        Channel::Dav,
        Some("globex"),
        "the other tenant, by bare name",
    )
    .await;
    kit.expect_rejected(
        checks,
        &basic("gina", &seeded.gina_password),
        Channel::Dav,
        Some("acme"),
        RejectReason::UnknownCredential,
        "a bare name of another tenant on this tenant's path: gina of acme is nobody",
    )
    .await;
}

async fn tokens_ignore_the_tenant_of_the_path(kit: &Kit, checks: &mut Checks) {
    let seeded = &kit.seeded;
    // Tokens carry their tenant: the path does not matter to the authenticator. System tokens belong to none.
    for tenant in [None, Some("acme"), Some("globex"), Some("nonexistent")] {
        for (what, token, expected) in [
            ("a tenant token", &seeded.tenant_token, Some(seeded.world.a)),
            ("a principal token", &seeded.principal_token, Some(seeded.world.a)),
            ("a system token", &seeded.system_token, None),
        ] {
            let channel = if token.id == seeded.principal_token.id {
                Channel::Mcp
            } else {
                Channel::Api
            };
            if let Some(auth) = kit
                .expect_accepted(
                    checks,
                    &bearer(token),
                    channel,
                    tenant,
                    &format!("{what} on the path of {tenant:?}"),
                )
                .await
            {
                checks.equal(&auth.tenant, &expected, &format!("the tenant of {what} on {tenant:?}"));
            }
        }
    }
}

async fn uses_are_recorded(kit: &Kit, checks: &mut Checks) {
    let Some(flush) = &kit.rig.flush else {
        return;
    };
    let seeded = &kit.seeded;
    let first = kit.rig.clock.now();
    for _ in 0..3 {
        kit.expect_accepted(
            checks,
            &basic(ACME_LOGIN, &seeded.password),
            Channel::Dav,
            None,
            "using the password",
        )
        .await;
        kit.rig.clock.advance(Duration::seconds(5));
    }
    let used = |kit: &Kit| {
        let database = Arc::clone(&kit.rig.database);
        let tenant = kit.seeded.world.a;
        let password = kit.seeded.password.id;
        async move {
            let mut tx = database.begin(tenant, TxMode::ReadOnly).await?;
            Ok::<_, StoreError>(tx.credentials().get_app_password(password.into()).await?.last_used_at)
        }
    };
    let before = checks.ok(used(kit).await, "reading the password").flatten();
    checks.equal(&before, &None, "nothing is written before the flush");
    flush.tick().await;
    let after = checks.ok(used(kit).await, "reading the password").flatten();
    checks.equal(&after, &Some(first), "the first use of the interval is recorded");
    // Within the interval a further use does not change it.
    kit.expect_accepted(
        checks,
        &basic(ACME_LOGIN, &seeded.password),
        Channel::Dav,
        None,
        "using the password again",
    )
    .await;
    flush.tick().await;
    let later = checks.ok(used(kit).await, "reading the password").flatten();
    checks.equal(
        &later,
        &Some(first),
        "a use within the flush interval is not written again",
    );
}

/// Builds a rig, seeds it and runs one case on it.
macro_rules! case {
    ($suite:expr, $factory:expr, $name:literal, $function:ident) => {{
        let mut checks = Checks::new($name);
        let rig = $factory().await;
        match seeded(&rig).await {
            Ok(seeded) => {
                let kit = Kit { rig, seeded };
                $function(&kit, &mut checks).await;
            }
            Err(error) => checks.fail(format!("seeding the database failed: {error:?}")),
        }
        $suite.record(checks);
    }};
}

/// The values that are no credential of the authenticator's kind, and the surface to present them on.
fn foreign_values() -> Vec<(&'static str, PresentedCredential, Channel)> {
    vec![
        (
            "a JWT as a bearer token",
            PresentedCredential::Bearer(secret("eyJhbGciOiJIUzI1NiJ9.e30.sig")),
            Channel::Api,
        ),
        (
            "an empty bearer token",
            PresentedCredential::Bearer(secret("")),
            Channel::Api,
        ),
        (
            "an ordinary password",
            PresentedCredential::Basic {
                username: ACME_LOGIN.to_owned(),
                password: secret("correct horse battery staple"),
            },
            Channel::Dav,
        ),
        (
            "a random feed token",
            PresentedCredential::Feed(secret("not-a-token")),
            Channel::Feed,
        ),
        (
            "a random RSVP token",
            PresentedCredential::Rsvp(secret("not-a-token")),
            Channel::Rsvp,
        ),
    ]
}

/// What an authenticator that does not know a credential may answer: pass it on or refuse it.
fn never_accepted(outcome: &AuthOutcome) -> bool {
    !matches!(outcome, AuthOutcome::Accepted(_))
}

async fn generic_foreign_values_pass_on(auth: &dyn Authenticator, checks: &mut Checks) {
    for (what, credential, channel) in foreign_values() {
        match auth.authenticate(&credential, &Kit::hint(channel, None)).await {
            Ok(outcome) => checks.equal(&outcome, &AuthOutcome::NotApplicable, what),
            Err(error) => checks.fail(format!("{what}: the authenticator failed: {error}")),
        }
    }
    // Marked values of our formats that are malformed: passed on or refused, never accepted.
    for (what, credential, channel) in [
        (
            "a truncated API token",
            PresentedCredential::Bearer(secret("dvh_pat_short")),
            Channel::Api,
        ),
        (
            "a truncated feed token",
            PresentedCredential::Feed(secret("dvh_feed_abc_def")),
            Channel::Feed,
        ),
        (
            "a bare marker",
            PresentedCredential::Rsvp(secret("dvh_rsvp_")),
            Channel::Rsvp,
        ),
    ] {
        match auth.authenticate(&credential, &Kit::hint(channel, None)).await {
            Ok(outcome) => checks.that(never_accepted(&outcome), &format!("{what} is not accepted")),
            Err(error) => checks.fail(format!("{what}: the authenticator failed: {error}")),
        }
    }
}

async fn generic_unknown_credentials_are_never_accepted(auth: &dyn Authenticator, checks: &mut Checks) {
    for (what, credential, channel) in [
        (
            "an app password in no store",
            basic(ACME_LOGIN, &unminted(app_password_secret("nobody"))),
            Channel::Dav,
        ),
        (
            "an API token in no store",
            bearer(&unminted(api_token_secret("nobody"))),
            Channel::Api,
        ),
        (
            "a feed token in no store",
            feed(&unminted(feed_token_secret("nobody"))),
            Channel::Feed,
        ),
        (
            "an RSVP token in no store",
            rsvp(&unminted(rsvp_token_secret("nobody"))),
            Channel::Rsvp,
        ),
    ] {
        match auth.authenticate(&credential, &Kit::hint(channel, Some("acme"))).await {
            Ok(outcome) => checks.that(never_accepted(&outcome), &format!("{what} is not accepted")),
            Err(error) => checks.fail(format!("{what}: the authenticator failed: {error}")),
        }
    }
}

async fn generic_no_input_breaks_the_authenticator(auth: &dyn Authenticator, checks: &mut Checks) {
    let huge = "x".repeat(1 << 20);
    let long_marked = format!("dvh_pat_{}", "a".repeat(1 << 16));
    let values = [
        "\0",
        "\n\r\t",
        "\u{feff}\u{202e}ünïcödé 🔑",
        "dvh_pat_\0",
        "dvh_rsvp_abcdefghijkl_\n",
        huge.as_str(),
        long_marked.as_str(),
    ];
    for value in values {
        for (credential, channel) in [
            (PresentedCredential::Bearer(secret(value)), Channel::Api),
            (PresentedCredential::Feed(secret(value)), Channel::Feed),
            (PresentedCredential::Rsvp(secret(value)), Channel::Rsvp),
            (
                PresentedCredential::Basic {
                    username: value.to_owned(),
                    password: secret(value),
                },
                Channel::Dav,
            ),
        ] {
            let label = format!("{channel} with a value of {} bytes", value.len());
            match auth.authenticate(&credential, &Kit::hint(channel, Some("acme"))).await {
                Ok(outcome) => checks.that(never_accepted(&outcome), &format!("{label} is not accepted")),
                Err(error) => checks.fail(format!("{label}: the authenticator failed: {error}")),
            }
        }
    }
}

/// Runs the suite every authenticator must pass, `noop` included, and returns the report.
///
/// It needs no store and no seeded rows; only the authenticator of the rig is used.
pub async fn run<F, Fut>(factory: F) -> ContractReport
where
    F: Fn() -> Fut,
    Fut: Future<Output = AuthRig>,
{
    let mut suite = Suite::new("auth");
    let rig = factory().await;
    let auth = rig.authenticator.as_ref();

    let mut checks = Checks::new("values that are no credential pass on, malformed marked ones are never accepted");
    generic_foreign_values_pass_on(auth, &mut checks).await;
    suite.record(checks);

    let mut checks = Checks::new("a well-formed credential that no store knows is never accepted");
    generic_unknown_credentials_are_never_accepted(auth, &mut checks).await;
    suite.record(checks);

    let mut checks = Checks::new("no input, however odd or large, makes the authenticator fail or accept");
    generic_no_input_breaks_the_authenticator(auth, &mut checks).await;
    suite.record(checks);

    suite.finish()
}

/// Runs [`run`] and fails the running test when any case fails.
///
/// # Panics
///
/// When a case fails.
pub async fn run_all<F, Fut>(factory: F)
where
    F: Fn() -> Fut,
    Fut: Future<Output = AuthRig>,
{
    run(factory).await.assert_ok();
}

/// Runs the suite of the authenticators that verify the credentials of the store against rigs built by `factory`
/// and returns the report.
///
/// Every case gets a fresh rig, so the cases never depend on each other.
pub async fn run_store_backed<F, Fut>(factory: F) -> ContractReport
where
    F: Fn() -> Fut,
    Fut: Future<Output = AuthRig>,
{
    let mut suite = Suite::new("auth (store backed)");
    case!(
        suite,
        factory,
        "every kind of credential authenticates on its surface",
        every_kind_authenticates_on_its_surface
    );
    case!(
        suite,
        factory,
        "credentials are bound to their surface",
        credentials_are_bound_to_their_surface
    );
    case!(
        suite,
        factory,
        "values that are not credentials of this kind pass on and malformed ones are refused",
        foreign_and_malformed_values
    );
    case!(
        suite,
        factory,
        "wrong and unknown secrets are refused and never cached",
        wrong_and_unknown_secrets
    );
    case!(suite, factory, "revocation applies at once", revocation_applies_at_once);
    case!(
        suite,
        factory,
        "the revocation of one credential applies at once without a bump of the generation",
        a_revocation_alone_applies_at_once
    );
    case!(suite, factory, "expiry follows the clock", expiry_follows_the_clock);
    case!(
        suite,
        factory,
        "suspended and deleted principals and suspended tenants are refused",
        suspension_and_deletion
    );
    case!(
        suite,
        factory,
        "logins are checked and the tenant of the path is not a reason to refuse a credential",
        names_are_checked
    );
    case!(suite, factory, "uses are recorded in batches", uses_are_recorded);
    suite.finish()
}

/// Runs [`run_store_backed`] and fails the running test when any case fails.
///
/// # Panics
///
/// When a case fails.
pub async fn run_store_backed_all<F, Fut>(factory: F)
where
    F: Fn() -> Fut,
    Fut: Future<Output = AuthRig>,
{
    run_store_backed(factory).await.assert_ok();
}

impl Debug for AuthRig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthRig").finish_non_exhaustive()
    }
}
