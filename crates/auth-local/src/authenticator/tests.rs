//! Tests of the authenticator over an in-memory credential source: the verification rules, the cache, the
//! equal-cost refusal of unknown credentials and the batched recording of uses. The contract suite of the port runs
//! against the real store in `crates/it/tests/auth_local.rs`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use chrono::{Duration as Chrono, TimeZone as _};
use davhaven_domain::{
    AppPassword, CalendarUserAddress, DomainName, FeedMode, FeedToken, ObjectId, PrincipalName, RequestId, RsvpToken,
    Scope, TenantSlug,
};
use davhaven_ports::testing::{FixedHasher, FixedKeyRing, ManualClock, SeqIds};

use super::*;
use crate::testing::{Generated, app_password, token};

fn id<T: From<Uuid>>(n: u128) -> T {
    T::from(Uuid::from_u128(n))
}

fn secret(text: &str) -> SecretString {
    SecretString::from(text)
}

/// A hasher that counts its verifications, to prove that refusals cost the same and that a cached secret is not
/// verified again.
struct CountingHasher {
    inner: FixedHasher,
    verifies: AtomicUsize,
}

impl CredentialHasher for CountingHasher {
    fn hash(&self, kind: CredentialKind, secret: &SecretString) -> StoredHash {
        self.inner.hash(kind, secret)
    }

    fn verify(&self, stored: &StoredHash, secret: &SecretString) -> bool {
        self.verifies.fetch_add(1, Ordering::SeqCst);
        self.inner.verify(stored, secret)
    }
}

/// An in-memory [`CredentialSource`].
#[derive(Default)]
struct Fake {
    credentials: Mutex<HashMap<(CredentialKind, String), LookedUpCredential>>,
    touched: Mutex<Vec<(TenantId, Vec<CredentialUse>)>>,
    /// The re-hashes that changed a row, with the tenant they were made for.
    rehashed: Mutex<Vec<(TenantId, Rehash)>>,
    finds: AtomicUsize,
    fail_touch: AtomicBool,
    fail_rehash: AtomicBool,
}

/// Replaces the hash of a stored credential.
fn set_hash(record: &mut CredentialRecord, hash: &[u8], pepper_kid: &str) {
    let (stored_hash, stored_kid) = match record {
        CredentialRecord::AppPassword(row) => (&mut row.hash, &mut row.pepper_kid),
        CredentialRecord::ApiToken(row) => (&mut row.hash, &mut row.pepper_kid),
        CredentialRecord::FeedToken(row) => (&mut row.hash, &mut row.pepper_kid),
        CredentialRecord::RsvpToken(row) => (&mut row.hash, &mut row.pepper_kid),
    };
    hash.clone_into(stored_hash);
    pepper_kid.clone_into(stored_kid);
}

#[async_trait]
impl CredentialSource for Fake {
    async fn find(&self, kind: CredentialKind, prefix: &str) -> Result<Option<LookedUpCredential>, PortError> {
        self.finds.fetch_add(1, Ordering::SeqCst);
        Ok(self.credentials.lock().await.get(&(kind, prefix.to_owned())).cloned())
    }

    async fn touch(&self, tenant: TenantId, uses: &[CredentialUse]) -> Result<(), PortError> {
        if self.fail_touch.load(Ordering::SeqCst) {
            return Err(PortError::unavailable("the store is down"));
        }
        self.touched.lock().await.push((tenant, uses.to_vec()));
        Ok(())
    }

    async fn rehash(&self, tenant: TenantId, rehash: &Rehash) -> Result<bool, PortError> {
        if self.fail_rehash.load(Ordering::SeqCst) {
            return Err(PortError::unavailable("the store is down"));
        }
        let mut credentials = self.credentials.lock().await;
        let Some(found) = credentials
            .values_mut()
            .find(|found| found.record.kind() == rehash.credential.kind && found.record.id() == rehash.credential.id)
        else {
            return Ok(false);
        };
        let current = stored_hash_of(&found.record);
        if current.pepper_kid != rehash.from_kid || found.record.tenant_id() != Some(tenant) {
            return Ok(false);
        }
        set_hash(&mut found.record, &rehash.to.hash, &rehash.to.pepper_kid);
        self.rehashed.lock().await.push((tenant, rehash.clone()));
        Ok(true)
    }
}

const ACME: u128 = 1;
const ANNA: u128 = 10;

struct World {
    source: Arc<Fake>,
    hasher: Arc<CountingHasher>,
    clock: ManualClock,
    ids: Arc<SeqIds>,
    auth: LocalAuthenticator,
    config: AuthConfig,
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap()
}

fn deps(
    source: Arc<dyn CredentialSource>,
    hasher: Arc<CountingHasher>,
    clock: &ManualClock,
    ids: Arc<SeqIds>,
) -> LocalDeps {
    LocalDeps {
        source,
        hasher,
        keyring: Arc::new(FixedKeyRing::default()),
        clock: Arc::new(clock.clone()),
        ids,
    }
}

fn world_with(config: AuthConfig, max_recent: usize) -> World {
    let source = Arc::new(Fake::default());
    let hasher = Arc::new(CountingHasher {
        inner: FixedHasher::default(),
        verifies: AtomicUsize::new(0),
    });
    let clock = ManualClock::new(now());
    let ids = Arc::new(SeqIds::starting_at(1000));
    let auth = LocalAuthenticator::with_recent_limit(
        deps(
            Arc::<Fake>::clone(&source),
            Arc::clone(&hasher),
            &clock,
            Arc::<SeqIds>::clone(&ids),
        ),
        &config,
        max_recent,
    );
    let world = World {
        source,
        hasher,
        clock,
        ids,
        auth,
        config,
    };
    // The verifications of the dummy hashes of the constructor are not part of any test.
    world.hasher.verifies.store(0, Ordering::SeqCst);
    world
}

fn world() -> World {
    world_with(AuthConfig::default(), MAX_RECENT)
}

/// The names of the tenant `acme` and of its principal Anna.
fn acme_owner(principal: Option<&str>) -> CredentialOwner {
    CredentialOwner {
        tenant_slug: TenantSlug::parse("acme").unwrap(),
        login_domain: Some(DomainName::parse("acme.example").unwrap()),
        principal_name: principal.map(|name| PrincipalName::parse(name).unwrap()),
    }
}

impl World {
    async fn put(&self, kind: CredentialKind, prefix: &str, found: LookedUpCredential) {
        self.source
            .credentials
            .lock()
            .await
            .insert((kind, prefix.to_owned()), found);
    }

    fn hash(&self, kind: CredentialKind, secret_text: &SecretString) -> (Vec<u8>, String) {
        let stored = self.hasher.hash(kind, secret_text);
        (stored.hash, stored.pepper_kid)
    }

    /// An app password of Anna; returns what she types.
    async fn app_password(&self, n: u128) -> Generated {
        let generated = app_password(self.ids.as_ref());
        let (hash, pepper_kid) = self.hash(CredentialKind::AppPassword, &generated.secret);
        let row = AppPassword {
            id: id(n),
            tenant_id: id(ACME),
            principal_id: id(ANNA),
            label: "iPhone".to_owned(),
            prefix: generated.prefix.clone(),
            hash,
            pepper_kid,
            last_used_at: None,
            revoked_at: None,
            created_at: now(),
            updated_at: now(),
            version: 1,
        };
        self.put(
            CredentialKind::AppPassword,
            &generated.prefix,
            LookedUpCredential {
                record: CredentialRecord::AppPassword(Box::new(row)),
                tenant_status: Some(TenantStatus::Active),
                principal_status: Some(PrincipalStatus::Active),
                credential_generation: Some(3),
                owner: Some(acme_owner(Some("anna"))),
            },
        )
        .await;
        generated
    }

    /// An API token of the given kind in `ACME` (system tokens belong to no tenant).
    async fn api_token(
        &self,
        n: u128,
        kind: TokenKind,
        scopes: &[Scope],
        expires_at: Option<DateTime<Utc>>,
    ) -> Generated {
        let generated = token(CredentialKind::ApiToken, self.ids.as_ref());
        let (hash, pepper_kid) = self.hash(CredentialKind::ApiToken, &generated.secret);
        let row = ApiToken {
            id: id(n),
            tenant_id: (kind != TokenKind::System).then(|| id(ACME)),
            kind,
            principal_id: (kind == TokenKind::Principal).then(|| id(ANNA)),
            label: "ci".to_owned(),
            scopes: ScopeSet::of(scopes),
            prefix: generated.prefix.clone(),
            hash,
            pepper_kid,
            expires_at,
            created_by: None,
            allowed_origins: Vec::new(),
            last_used_at: None,
            revoked_at: None,
            created_at: now(),
            updated_at: now(),
            version: 1,
        };
        let found = LookedUpCredential {
            record: CredentialRecord::ApiToken(Box::new(row)),
            tenant_status: (kind != TokenKind::System).then_some(TenantStatus::Active),
            principal_status: (kind == TokenKind::Principal).then_some(PrincipalStatus::Active),
            credential_generation: (kind == TokenKind::Principal).then_some(3),
            owner: (kind != TokenKind::System).then(|| acme_owner((kind == TokenKind::Principal).then_some("anna"))),
        };
        self.put(CredentialKind::ApiToken, &generated.prefix, found).await;
        generated
    }

    async fn feed_token(&self, n: u128) -> Generated {
        let generated = token(CredentialKind::FeedToken, self.ids.as_ref());
        let (hash, pepper_kid) = self.hash(CredentialKind::FeedToken, &generated.secret);
        let row = FeedToken {
            id: id(n),
            tenant_id: id(ACME),
            principal_id: id(ANNA),
            mode: FeedMode::Busy,
            calendar_ids: Vec::new(),
            prefix: generated.prefix.clone(),
            hash,
            pepper_kid,
            revoked_at: None,
            created_at: now(),
            updated_at: now(),
            version: 1,
        };
        self.put(
            CredentialKind::FeedToken,
            &generated.prefix,
            LookedUpCredential {
                record: CredentialRecord::FeedToken(Box::new(row)),
                tenant_status: Some(TenantStatus::Active),
                principal_status: Some(PrincipalStatus::Active),
                credential_generation: Some(3),
                owner: Some(acme_owner(Some("anna"))),
            },
        )
        .await;
        generated
    }

    async fn rsvp_token(&self, n: u128, expires_at: DateTime<Utc>) -> Generated {
        let generated = token(CredentialKind::RsvpToken, self.ids.as_ref());
        let (hash, pepper_kid) = self.hash(CredentialKind::RsvpToken, &generated.secret);
        let row = RsvpToken {
            id: id(n),
            tenant_id: id(ACME),
            object_id: ObjectId::from_uuid(Uuid::from_u128(77)),
            attendee_address: CalendarUserAddress::parse("mailto:guest@example.org").unwrap(),
            prefix: generated.prefix.clone(),
            hash,
            pepper_kid,
            expires_at,
            revoked_at: None,
            last_used_at: None,
            last_response: None,
            created_at: now(),
            updated_at: now(),
            version: 1,
        };
        self.put(
            CredentialKind::RsvpToken,
            &generated.prefix,
            LookedUpCredential {
                record: CredentialRecord::RsvpToken(Box::new(row)),
                tenant_status: Some(TenantStatus::Active),
                principal_status: None,
                credential_generation: None,
                owner: Some(acme_owner(None)),
            },
        )
        .await;
        generated
    }

    /// Edits the stored row of a credential.
    async fn edit(&self, kind: CredentialKind, prefix: &str, change: impl FnOnce(&mut LookedUpCredential)) {
        let mut credentials = self.source.credentials.lock().await;
        change(credentials.get_mut(&(kind, prefix.to_owned())).unwrap());
    }

    async fn authenticate(
        &self,
        credential: &PresentedCredential,
        channel: Channel,
        tenant: Option<&str>,
    ) -> AuthOutcome {
        let hint = AuthHint {
            channel,
            tenant_hint: tenant.map(|slug| TenantSlug::parse(slug).unwrap()),
            client_ip: None,
            request_id: RequestId::from_uuid(Uuid::nil()),
        };
        self.auth.authenticate(credential, &hint).await.unwrap()
    }

    async fn dav(&self, login: &str, password: &Generated, tenant: Option<&str>) -> AuthOutcome {
        let credential = PresentedCredential::Basic {
            username: login.to_owned(),
            password: password.presented.clone(),
        };
        self.authenticate(&credential, Channel::Dav, tenant).await
    }

    async fn bearer(&self, token: &Generated, channel: Channel, tenant: Option<&str>) -> AuthOutcome {
        self.authenticate(&PresentedCredential::Bearer(token.presented.clone()), channel, tenant)
            .await
    }

    fn finds(&self) -> usize {
        self.source.finds.load(Ordering::SeqCst)
    }

    fn verifies(&self) -> usize {
        self.hasher.verifies.load(Ordering::SeqCst)
    }
}

fn rejected(reason: RejectReason) -> AuthOutcome {
    AuthOutcome::Rejected(reason)
}

fn accepted(outcome: AuthOutcome) -> Authenticated {
    match outcome {
        AuthOutcome::Accepted(authenticated) => authenticated,
        other => panic!("expected an accepted credential, got {other:?}"),
    }
}

#[tokio::test]
async fn app_passwords_authenticate_their_owner_on_dav() {
    let world = world();
    let password = world.app_password(500).await;
    let authenticated = accepted(world.dav("anna@acme.example", &password, None).await);
    assert_eq!(authenticated.tenant, Some(id(ACME)));
    assert_eq!(authenticated.actor, Actor::Principal(id(ANNA)));
    assert_eq!(authenticated.credential, CredentialRef::app_password(id(500)));
    assert!(authenticated.scopes.is_empty());
    assert_eq!(authenticated.label.as_deref(), Some("iPhone"));
}

#[tokio::test]
async fn the_login_must_be_the_owners_and_may_be_typed_loosely() {
    let world = world();
    let password = world.app_password(500).await;
    for login in ["ANNA@ACME.EXAMPLE", " anna@acme.example ", "Anna@Acme.Example"] {
        assert!(
            matches!(world.dav(login, &password, None).await, AuthOutcome::Accepted(_)),
            "{login}"
        );
    }
    // A bare name is a login only where the path names the tenant.
    assert!(matches!(
        world.dav("anna", &password, Some("acme")).await,
        AuthOutcome::Accepted(_)
    ));
    assert_eq!(
        world.dav("anna", &password, None).await,
        rejected(RejectReason::UnknownCredential)
    );
    for (login, tenant) in [
        ("bert@acme.example", None),
        ("anna@other.example", None),
        ("anna@", None),
        ("@acme.example", None),
        ("", None),
        ("anna@globex.example", None),
        // A bare name means "this name in the tenant of the path": anna of globex is not this credential's owner.
        ("anna", Some("globex")),
    ] {
        assert_eq!(
            world.dav(login, &password, tenant).await,
            rejected(RejectReason::UnknownCredential),
            "{login:?} {tenant:?}"
        );
    }
    // The right login with the tenant of the path.
    assert!(matches!(
        world.dav("anna@acme.example", &password, Some("acme")).await,
        AuthOutcome::Accepted(_)
    ));
}

#[tokio::test]
async fn credentials_are_bound_to_their_surface() {
    let world = world();
    let password = world.app_password(500).await;
    let token = world
        .api_token(501, TokenKind::Tenant, &[Scope::PrincipalsRead], None)
        .await;
    let feed = world.feed_token(502).await;
    let rsvp = world.rsvp_token(503, now() + Chrono::days(1)).await;

    for channel in [
        Channel::Api,
        Channel::Mcp,
        Channel::Feed,
        Channel::Rsvp,
        Channel::Internal,
    ] {
        let credential = PresentedCredential::Basic {
            username: "anna@acme.example".to_owned(),
            password: password.presented.clone(),
        };
        assert_eq!(
            world.authenticate(&credential, channel, None).await,
            rejected(RejectReason::WrongSurface),
            "an app password on {channel}"
        );
    }
    for channel in [Channel::Dav, Channel::Feed, Channel::Rsvp, Channel::Internal] {
        assert_eq!(
            world.bearer(&token, channel, None).await,
            rejected(RejectReason::WrongSurface),
            "an API token on {channel}"
        );
    }
    for channel in [Channel::Api, Channel::Mcp] {
        assert!(matches!(
            world.bearer(&token, channel, None).await,
            AuthOutcome::Accepted(_)
        ));
    }
    // Feed and RSVP tokens work on their own page only, and not as bearer tokens.
    let as_feed = PresentedCredential::Feed(feed.presented.clone());
    let as_rsvp = PresentedCredential::Rsvp(rsvp.presented.clone());
    assert!(matches!(
        world.authenticate(&as_feed, Channel::Feed, None).await,
        AuthOutcome::Accepted(_)
    ));
    assert!(matches!(
        world.authenticate(&as_rsvp, Channel::Rsvp, None).await,
        AuthOutcome::Accepted(_)
    ));
    assert_eq!(
        world.authenticate(&as_feed, Channel::Rsvp, None).await,
        rejected(RejectReason::WrongSurface)
    );
    assert_eq!(
        world.authenticate(&as_rsvp, Channel::Feed, None).await,
        rejected(RejectReason::WrongSurface)
    );
    assert_eq!(
        world.bearer(&feed, Channel::Api, None).await,
        rejected(RejectReason::WrongSurface)
    );
    assert_eq!(
        world.bearer(&rsvp, Channel::Api, None).await,
        rejected(RejectReason::WrongSurface)
    );
    let rsvp_on_feed_page = PresentedCredential::Feed(rsvp.presented.clone());
    assert_eq!(
        world.authenticate(&rsvp_on_feed_page, Channel::Feed, None).await,
        rejected(RejectReason::WrongSurface),
        "an RSVP token in a feed URL"
    );
}

#[tokio::test]
async fn values_that_are_not_ours_pass_to_the_next_authenticator_and_marked_ones_are_refused() {
    let world = world();
    for (credential, channel) in [
        (
            PresentedCredential::Bearer(secret("eyJhbGciOiJIUzI1NiJ9.e30.sig")),
            Channel::Api,
        ),
        (PresentedCredential::Bearer(secret("")), Channel::Api),
        (PresentedCredential::Feed(secret("random-token")), Channel::Feed),
        (PresentedCredential::Rsvp(secret("random-token")), Channel::Rsvp),
        (
            PresentedCredential::Basic {
                username: "anna".to_owned(),
                password: secret("a normal password"),
            },
            Channel::Dav,
        ),
    ] {
        assert_eq!(
            world.authenticate(&credential, channel, None).await,
            AuthOutcome::NotApplicable
        );
    }
    for (credential, channel) in [
        (PresentedCredential::Bearer(secret("dvh_pat_short")), Channel::Api),
        (PresentedCredential::Feed(secret("dvh_feed_abc_def")), Channel::Feed),
        (PresentedCredential::Rsvp(secret("dvh_rsvp_")), Channel::Rsvp),
    ] {
        assert_eq!(
            world.authenticate(&credential, channel, None).await,
            rejected(RejectReason::Malformed)
        );
    }
    assert_eq!(
        world.finds(),
        0,
        "a value that cannot be a credential never reaches the store"
    );
}

#[tokio::test]
async fn unknown_and_wrong_credentials_cost_one_verification_each() {
    let world = world();
    let known = world
        .api_token(501, TokenKind::Tenant, &[Scope::PrincipalsRead], None)
        .await;
    let before = world.verifies();

    // A wrong secret under a known prefix.
    let mut wrong = known.presented.expose_secret().to_owned();
    wrong.pop();
    wrong.push(if known.presented.expose_secret().ends_with('A') {
        'B'
    } else {
        'A'
    });
    let credential = PresentedCredential::Bearer(secret(&wrong));
    assert_eq!(
        world.authenticate(&credential, Channel::Api, None).await,
        rejected(RejectReason::BadSecret)
    );
    assert_eq!(world.verifies(), before + 1);

    // An unknown prefix.
    let unknown = token(CredentialKind::ApiToken, world.ids.as_ref());
    assert_eq!(
        world.bearer(&unknown, Channel::Api, None).await,
        rejected(RejectReason::UnknownCredential)
    );
    assert_eq!(
        world.verifies(),
        before + 2,
        "the dummy verification costs what a real one costs"
    );
    assert_eq!(world.finds(), 2, "and both look the prefix up");
}

#[tokio::test]
async fn revoked_expired_and_suspended_credentials_are_refused() {
    let world = world();
    let password = world.app_password(500).await;
    let token = world
        .api_token(
            501,
            TokenKind::Tenant,
            &[Scope::PrincipalsRead],
            Some(now() + Chrono::hours(1)),
        )
        .await;
    let rsvp = world.rsvp_token(503, now() + Chrono::hours(2)).await;
    let feed = world.feed_token(502).await;

    // Expiry follows the clock.
    assert!(matches!(
        world.bearer(&token, Channel::Api, None).await,
        AuthOutcome::Accepted(_)
    ));
    world.clock.advance(Chrono::hours(1));
    assert_eq!(
        world.bearer(&token, Channel::Api, None).await,
        rejected(RejectReason::Expired)
    );
    let as_rsvp = PresentedCredential::Rsvp(rsvp.presented.clone());
    assert!(matches!(
        world.authenticate(&as_rsvp, Channel::Rsvp, None).await,
        AuthOutcome::Accepted(_)
    ));
    world.clock.advance(Chrono::hours(1));
    assert_eq!(
        world.authenticate(&as_rsvp, Channel::Rsvp, None).await,
        rejected(RejectReason::Expired)
    );

    // Revocation, per kind.
    for (kind, prefix) in [
        (CredentialKind::AppPassword, password.prefix.clone()),
        (CredentialKind::FeedToken, feed.prefix.clone()),
    ] {
        world
            .edit(kind, &prefix, |found| match &mut found.record {
                CredentialRecord::AppPassword(row) => row.revoked_at = Some(now()),
                CredentialRecord::FeedToken(row) => row.revoked_at = Some(now()),
                _ => {}
            })
            .await;
    }
    assert_eq!(
        world.dav("anna@acme.example", &password, None).await,
        rejected(RejectReason::Revoked)
    );
    let as_feed = PresentedCredential::Feed(feed.presented.clone());
    assert_eq!(
        world.authenticate(&as_feed, Channel::Feed, None).await,
        rejected(RejectReason::Revoked)
    );

    // A wrong secret is reported as such even for a revoked credential: the secret is checked first.
    let mut wrong = password.presented.expose_secret().to_owned();
    let last = wrong.pop().unwrap();
    wrong.push(if last == 'a' { 'b' } else { 'a' });
    let credential = PresentedCredential::Basic {
        username: "anna@acme.example".to_owned(),
        password: secret(&wrong),
    };
    assert_eq!(
        world.authenticate(&credential, Channel::Dav, None).await,
        rejected(RejectReason::BadSecret)
    );
}

#[tokio::test]
async fn suspended_tenants_and_principals_and_deleted_principals_are_refused() {
    let world = world();
    let password = world.app_password(500).await;
    let token = world
        .api_token(501, TokenKind::Tenant, &[Scope::PrincipalsRead], None)
        .await;
    let principal_token = world
        .api_token(504, TokenKind::Principal, &[Scope::EventsRead], None)
        .await;
    let system = world
        .api_token(505, TokenKind::System, &[Scope::SystemTenants], None)
        .await;

    for status in [PrincipalStatus::Suspended, PrincipalStatus::Deleted] {
        world
            .edit(CredentialKind::AppPassword, &password.prefix, |found| {
                found.principal_status = Some(status);
            })
            .await;
        world
            .edit(CredentialKind::ApiToken, &principal_token.prefix, |found| {
                found.principal_status = Some(status);
            })
            .await;
        assert_eq!(
            world.dav("anna@acme.example", &password, None).await,
            rejected(RejectReason::Suspended),
            "{status}"
        );
        assert_eq!(
            world.bearer(&principal_token, Channel::Api, None).await,
            rejected(RejectReason::Suspended),
            "{status}"
        );
    }
    world
        .edit(CredentialKind::ApiToken, &token.prefix, |found| {
            found.tenant_status = Some(TenantStatus::Suspended);
        })
        .await;
    assert_eq!(
        world.bearer(&token, Channel::Api, None).await,
        rejected(RejectReason::Suspended)
    );
    // A system token belongs to no tenant: tenant status does not touch it.
    assert!(matches!(
        world.bearer(&system, Channel::Api, None).await,
        AuthOutcome::Accepted(_)
    ));
}

#[tokio::test]
async fn a_credential_whose_tenant_or_principal_cannot_be_found_is_refused_not_assumed_active() {
    let world = world();
    let password = world.app_password(500).await;
    let tenant_token = world
        .api_token(501, TokenKind::Tenant, &[Scope::PrincipalsRead], None)
        .await;
    let principal_token = world
        .api_token(502, TokenKind::Principal, &[Scope::EventsRead], None)
        .await;
    let feed = world.feed_token(503).await;
    let rsvp = world.rsvp_token(504, now() + Chrono::days(1)).await;
    let system = world
        .api_token(505, TokenKind::System, &[Scope::SystemTenants], None)
        .await;

    // The join of the lookup came back without the status of the tenant or the principal.
    for (kind, prefix) in [
        (CredentialKind::AppPassword, &password.prefix),
        (CredentialKind::ApiToken, &principal_token.prefix),
        (CredentialKind::FeedToken, &feed.prefix),
    ] {
        world.edit(kind, prefix, |found| found.principal_status = None).await;
    }
    for (kind, prefix) in [
        (CredentialKind::ApiToken, &tenant_token.prefix),
        (CredentialKind::RsvpToken, &rsvp.prefix),
    ] {
        world.edit(kind, prefix, |found| found.tenant_status = None).await;
    }
    let as_feed = PresentedCredential::Feed(feed.presented.clone());
    let as_rsvp = PresentedCredential::Rsvp(rsvp.presented.clone());
    let refusals = [
        world.dav("anna@acme.example", &password, None).await,
        world.bearer(&principal_token, Channel::Api, None).await,
        world.bearer(&tenant_token, Channel::Api, None).await,
        world.authenticate(&as_feed, Channel::Feed, None).await,
        world.authenticate(&as_rsvp, Channel::Rsvp, None).await,
    ];
    for refusal in refusals {
        assert_eq!(refusal, rejected(RejectReason::UnknownCredential));
    }
    // A system token names no tenant and no principal, so there is nothing to find.
    assert!(matches!(
        world.bearer(&system, Channel::Api, None).await,
        AuthOutcome::Accepted(_)
    ));
    // An app password without the names of its owner cannot be compared with the login.
    let other = world.app_password(510).await;
    world
        .edit(CredentialKind::AppPassword, &other.prefix, |found| found.owner = None)
        .await;
    assert_eq!(
        world.dav("anna@acme.example", &other, None).await,
        rejected(RejectReason::UnknownCredential)
    );
}

#[tokio::test]
async fn api_tokens_become_the_actor_their_kind_names() {
    let world = world();
    let tenant = world
        .api_token(
            501,
            TokenKind::Tenant,
            &[Scope::PrincipalsRead, Scope::CalendarsWrite],
            None,
        )
        .await;
    let principal = world
        .api_token(
            502,
            TokenKind::Principal,
            &[Scope::EventsRead, Scope::McpRead],
            Some(now() + Chrono::days(30)),
        )
        .await;
    let system = world
        .api_token(503, TokenKind::System, &[Scope::SystemTenants], None)
        .await;

    let tenant = accepted(world.bearer(&tenant, Channel::Api, Some("acme")).await);
    assert_eq!(tenant.actor, Actor::TenantToken(id(501)));
    assert_eq!(tenant.tenant, Some(id(ACME)));
    assert_eq!(
        tenant.scopes,
        ScopeSet::of(&[Scope::PrincipalsRead, Scope::CalendarsWrite])
    );

    let principal = accepted(world.bearer(&principal, Channel::Mcp, None).await);
    assert_eq!(
        principal.actor,
        Actor::PrincipalToken {
            principal: id(ANNA),
            token: id(502)
        }
    );
    assert_eq!(principal.credential, CredentialRef::api_token(id(502)));

    // System tokens are not bound to a tenant and ignore the tenant of the path.
    for hint in [None, Some("acme"), Some("globex"), Some("nonexistent")] {
        let system = accepted(world.bearer(&system, Channel::Api, hint).await);
        assert_eq!(system.tenant, None);
        assert_eq!(system.actor, Actor::SystemToken(id(503)));
    }
}

#[tokio::test]
async fn a_valid_credential_is_authenticated_whatever_tenant_the_path_names() {
    // R4: the resources of another tenant are invisible (404), they are not a reason to doubt the credential. The
    // application answers 404 for the path; the authenticator reports the credential's own tenant and refuses
    // nothing, so a request like this never counts as a failed authentication.
    let world = world();
    let token = world
        .api_token(501, TokenKind::Tenant, &[Scope::PrincipalsRead], None)
        .await;
    let principal = world
        .api_token(502, TokenKind::Principal, &[Scope::EventsRead], None)
        .await;
    let password = world.app_password(500).await;
    for hint in [None, Some("acme"), Some("globex"), Some("nonexistent")] {
        let authenticated = accepted(world.bearer(&token, Channel::Api, hint).await);
        assert_eq!(authenticated.tenant, Some(id(ACME)), "{hint:?}");
        let authenticated = accepted(world.bearer(&principal, Channel::Mcp, hint).await);
        assert_eq!(authenticated.tenant, Some(id(ACME)), "{hint:?}");
        // The cache does not change it.
        assert!(matches!(
            world.bearer(&principal, Channel::Mcp, hint).await,
            AuthOutcome::Accepted(_)
        ));
        let authenticated = accepted(world.dav("anna@acme.example", &password, hint).await);
        assert_eq!(
            authenticated.tenant,
            Some(id(ACME)),
            "a login that names its tenant, {hint:?}"
        );
    }
    // Only a bare name depends on the path: it is anna of the tenant the path names.
    assert!(matches!(
        world.dav("anna", &password, Some("acme")).await,
        AuthOutcome::Accepted(_)
    ));
    assert_eq!(
        world.dav("anna", &password, Some("globex")).await,
        rejected(RejectReason::UnknownCredential)
    );
}

#[tokio::test]
async fn token_rows_that_contradict_the_token_model_are_refused() {
    let world = world();
    // `mcp:*` without an expiry, a tenant token with an MCP scope, a system token with a tenant scope.
    let no_expiry = world
        .api_token(501, TokenKind::Principal, &[Scope::McpRead], None)
        .await;
    let wrong_kind = world
        .api_token(502, TokenKind::Tenant, &[Scope::McpRead], Some(now() + Chrono::days(1)))
        .await;
    let system_scope = world
        .api_token(503, TokenKind::System, &[Scope::PrincipalsRead], None)
        .await;
    for token in [&no_expiry, &wrong_kind, &system_scope] {
        assert_eq!(
            world.bearer(token, Channel::Api, None).await,
            rejected(RejectReason::Malformed)
        );
    }
}

#[tokio::test]
async fn a_row_of_another_kind_than_the_marker_names_is_refused_even_when_its_hash_matches() {
    // A source that answers a lookup of API tokens with a feed token (a broken query, a shared prefix index) must not
    // turn a feed link into a bearer token of the API: the marker decides the kind, the row has to agree.
    let world = world();
    let feed = world.feed_token(520).await;
    let found = world
        .source
        .credentials
        .lock()
        .await
        .get(&(CredentialKind::FeedToken, feed.prefix.clone()))
        .cloned()
        .unwrap();
    world.put(CredentialKind::ApiToken, &feed.prefix, found).await;
    let as_api = feed.presented.expose_secret().replacen("dvh_feed_", "dvh_pat_", 1);
    let outcome = world
        .authenticate(&PresentedCredential::Bearer(secret(&as_api)), Channel::Api, None)
        .await;
    assert_eq!(outcome, rejected(RejectReason::UnknownCredential));
    // The same row under its own kind still works: the refusal is the kind check, not a broken fixture.
    assert!(matches!(
        world
            .authenticate(&PresentedCredential::Feed(feed.presented.clone()), Channel::Feed, None)
            .await,
        AuthOutcome::Accepted(_)
    ));
}

#[tokio::test]
async fn a_request_costs_one_lookup_whether_or_not_the_credential_is_cached() {
    let world = world();
    let password = world.app_password(500).await;
    let token = world
        .api_token(501, TokenKind::Principal, &[Scope::EventsRead], None)
        .await;
    for n in 1..=4_usize {
        assert!(matches!(
            world.dav("anna@acme.example", &password, None).await,
            AuthOutcome::Accepted(_)
        ));
        assert_eq!(
            world.finds(),
            n,
            "DAV: the first request (a miss) and every later one (a hit) read once"
        );
    }
    let before = world.finds();
    for n in 1..=4_usize {
        assert!(matches!(
            world.bearer(&token, Channel::Mcp, None).await,
            AuthOutcome::Accepted(_)
        ));
        assert_eq!(
            world.finds(),
            before + n,
            "MCP: no second read for the facts of the tenant"
        );
    }
}

#[tokio::test]
async fn successful_verifications_are_cached_and_failures_never_are() {
    let world = world();
    let password = world.app_password(500).await;
    for _ in 0..5 {
        assert!(matches!(
            world.dav("anna@acme.example", &password, None).await,
            AuthOutcome::Accepted(_)
        ));
    }
    assert_eq!(world.finds(), 5, "the row is read on every request, it decides");
    assert_eq!(world.verifies(), 1, "but the secret is verified once");

    // A wrong secret is never accepted because the right one is cached: the cache is keyed by the secret.
    let other = app_password(world.ids.as_ref());
    let head: String = password.presented.expose_secret().chars().take(20).collect();
    let tail: String = other.presented.expose_secret().chars().skip(20).collect();
    let same_prefix = PresentedCredential::Basic {
        username: "anna@acme.example".to_owned(),
        password: secret(&format!("{head}{tail}")),
    };
    assert_eq!(
        world.authenticate(&same_prefix, Channel::Dav, None).await,
        rejected(RejectReason::BadSecret)
    );
    assert_eq!(
        world.authenticate(&same_prefix, Channel::Dav, None).await,
        rejected(RejectReason::BadSecret)
    );
    assert_eq!(world.finds(), 7, "failures are decided afresh every time");
    assert_eq!(world.verifies(), 3, "and every one of them is verified");
}

#[tokio::test]
async fn cached_entries_expire_with_the_ttl() {
    let world = world();
    let token = world
        .api_token(501, TokenKind::Principal, &[Scope::EventsRead], None)
        .await;
    for _ in 0..3 {
        assert!(matches!(
            world.bearer(&token, Channel::Api, None).await,
            AuthOutcome::Accepted(_)
        ));
    }
    assert_eq!(world.verifies(), 1);
    world
        .clock
        .advance(Chrono::from_std(world.config.cache_ttl).unwrap() - Chrono::seconds(1));
    assert!(matches!(
        world.bearer(&token, Channel::Api, None).await,
        AuthOutcome::Accepted(_)
    ));
    assert_eq!(world.verifies(), 1, "still remembered just before the TTL");
    world.clock.advance(Chrono::seconds(1));
    assert!(matches!(
        world.bearer(&token, Channel::Api, None).await,
        AuthOutcome::Accepted(_)
    ));
    assert_eq!(world.verifies(), 2, "verified again after the TTL");
}

#[tokio::test]
async fn revoking_one_credential_applies_at_once_with_a_warm_cache_and_no_generation_bump() {
    // Nothing bumps the credential generation of the principal here: the revocation alone must be enough.
    let world = world();
    let password = world.app_password(500).await;
    let token = world
        .api_token(501, TokenKind::Principal, &[Scope::EventsRead], None)
        .await;
    for _ in 0..3 {
        assert!(matches!(
            world.dav("anna@acme.example", &password, None).await,
            AuthOutcome::Accepted(_)
        ));
        assert!(matches!(
            world.bearer(&token, Channel::Mcp, None).await,
            AuthOutcome::Accepted(_)
        ));
    }
    world
        .edit(CredentialKind::AppPassword, &password.prefix, |found| {
            if let CredentialRecord::AppPassword(row) = &mut found.record {
                row.revoked_at = Some(now());
            }
            assert_eq!(found.credential_generation, Some(3), "no bump");
        })
        .await;
    assert_eq!(
        world.dav("anna@acme.example", &password, None).await,
        rejected(RejectReason::Revoked)
    );
    // The other credential of the same principal is not affected.
    assert!(matches!(
        world.bearer(&token, Channel::Mcp, None).await,
        AuthOutcome::Accepted(_)
    ));
    world
        .edit(CredentialKind::ApiToken, &token.prefix, |found| {
            if let CredentialRecord::ApiToken(row) = &mut found.record {
                row.revoked_at = Some(now());
            }
        })
        .await;
    assert_eq!(
        world.bearer(&token, Channel::Mcp, None).await,
        rejected(RejectReason::Revoked)
    );
}

#[tokio::test]
async fn a_bumped_credential_generation_makes_the_cache_verify_again() {
    let world = world();
    let password = world.app_password(500).await;
    assert!(matches!(
        world.dav("anna@acme.example", &password, None).await,
        AuthOutcome::Accepted(_)
    ));
    assert!(matches!(
        world.dav("anna@acme.example", &password, None).await,
        AuthOutcome::Accepted(_)
    ));
    assert_eq!(world.verifies(), 1);
    world
        .edit(CredentialKind::AppPassword, &password.prefix, |found| {
            found.credential_generation = Some(4);
        })
        .await;
    assert!(
        matches!(
            world.dav("anna@acme.example", &password, None).await,
            AuthOutcome::Accepted(_)
        ),
        "a bump alone does not refuse a credential that is in order"
    );
    assert_eq!(world.verifies(), 2, "it makes the secret be verified again");
    assert!(matches!(
        world.dav("anna@acme.example", &password, None).await,
        AuthOutcome::Accepted(_)
    ));
    assert_eq!(world.verifies(), 2, "and the new generation is remembered");
}

#[tokio::test]
async fn a_cached_verification_covers_the_row_it_was_made_for_and_no_other() {
    let world = world();
    let password = world.app_password(500).await;
    assert!(matches!(
        world.dav("anna@acme.example", &password, None).await,
        AuthOutcome::Accepted(_)
    ));
    assert_eq!(world.verifies(), 1);

    // The credential was replaced under the same prefix: another id and another hash.
    let replacement = world.hash(CredentialKind::AppPassword, &secret("another secret"));
    world
        .edit(CredentialKind::AppPassword, &password.prefix, |found| {
            if let CredentialRecord::AppPassword(row) = &mut found.record {
                row.id = id(501);
                row.hash = replacement.0.clone();
                row.pepper_kid = replacement.1.clone();
            }
        })
        .await;
    assert_eq!(
        world.dav("anna@acme.example", &password, None).await,
        rejected(RejectReason::BadSecret),
        "the old secret does not open the new credential, although the cache remembered it"
    );
    assert_eq!(world.verifies(), 2, "the replaced row was verified again");
}

#[tokio::test]
async fn a_cached_secret_does_not_open_another_prefix() {
    let world = world();
    let token = world
        .api_token(501, TokenKind::Principal, &[Scope::EventsRead], None)
        .await;
    assert!(matches!(
        world.bearer(&token, Channel::Api, None).await,
        AuthOutcome::Accepted(_)
    ));
    // The same secret under a prefix nobody has: the prefix is part of what the cache remembers.
    let secret_part = token.secret.expose_secret();
    let other_prefix = "zzzzzzzzzzzz";
    assert_ne!(token.prefix, other_prefix);
    let forged = Generated {
        presented: secret(&format!("dvh_pat_{other_prefix}_{secret_part}")),
        prefix: other_prefix.to_owned(),
        secret: secret(secret_part),
    };
    let before = world.verifies();
    assert_eq!(
        world.bearer(&forged, Channel::Api, None).await,
        rejected(RejectReason::UnknownCredential)
    );
    assert_eq!(
        world.verifies(),
        before + 1,
        "refused through the dummy verification, not from the cache"
    );
}

#[tokio::test]
async fn suspending_a_principal_or_a_tenant_ends_cached_verifications_at_once() {
    let world = world();
    let password = world.app_password(500).await;
    let token = world
        .api_token(501, TokenKind::Principal, &[Scope::EventsRead], None)
        .await;
    assert!(matches!(
        world.dav("anna@acme.example", &password, None).await,
        AuthOutcome::Accepted(_)
    ));
    assert!(matches!(
        world.bearer(&token, Channel::Api, None).await,
        AuthOutcome::Accepted(_)
    ));

    world
        .edit(CredentialKind::AppPassword, &password.prefix, |found| {
            found.principal_status = Some(PrincipalStatus::Suspended);
        })
        .await;
    assert_eq!(
        world.dav("anna@acme.example", &password, None).await,
        rejected(RejectReason::Suspended)
    );

    world
        .edit(CredentialKind::ApiToken, &token.prefix, |found| {
            found.tenant_status = Some(TenantStatus::Suspended);
        })
        .await;
    assert_eq!(
        world.bearer(&token, Channel::Api, None).await,
        rejected(RejectReason::Suspended)
    );
}

#[tokio::test]
async fn an_entry_never_outlives_the_expiry_of_its_token() {
    let world = world();
    let token = world
        .api_token(
            501,
            TokenKind::Principal,
            &[Scope::EventsRead],
            Some(now() + Chrono::minutes(2)),
        )
        .await;
    assert!(matches!(
        world.bearer(&token, Channel::Api, None).await,
        AuthOutcome::Accepted(_)
    ));
    world.clock.advance(Chrono::minutes(2));
    assert_eq!(
        world.bearer(&token, Channel::Api, None).await,
        rejected(RejectReason::Expired)
    );
}

#[tokio::test]
async fn tenant_and_system_tokens_are_never_cached_so_their_secret_is_verified_every_time() {
    let world = world();
    let tenant = world
        .api_token(501, TokenKind::Tenant, &[Scope::PrincipalsRead], None)
        .await;
    let system = world
        .api_token(502, TokenKind::System, &[Scope::SystemTenants], None)
        .await;
    for token in [&tenant, &system] {
        for _ in 0..3 {
            assert!(matches!(
                world.bearer(token, Channel::Api, None).await,
                AuthOutcome::Accepted(_)
            ));
        }
    }
    assert_eq!(world.finds(), 6, "every request looks the token up");
    assert_eq!(world.verifies(), 6, "and verifies its secret");
    for token in [&tenant, &system] {
        world
            .edit(CredentialKind::ApiToken, &token.prefix, |found| {
                if let CredentialRecord::ApiToken(row) = &mut found.record {
                    row.revoked_at = Some(now());
                }
            })
            .await;
        assert_eq!(
            world.bearer(token, Channel::Api, None).await,
            rejected(RejectReason::Revoked)
        );
    }
}

#[tokio::test]
async fn feed_and_rsvp_tokens_are_never_cached() {
    let world = world();
    let feed = world.feed_token(502).await;
    let rsvp = world.rsvp_token(503, now() + Chrono::days(1)).await;
    let as_feed = PresentedCredential::Feed(feed.presented.clone());
    let as_rsvp = PresentedCredential::Rsvp(rsvp.presented.clone());
    for _ in 0..3 {
        let authenticated = accepted(world.authenticate(&as_feed, Channel::Feed, None).await);
        assert_eq!(
            authenticated.actor,
            Actor::FeedReader {
                principal: id(ANNA),
                token: id(502)
            }
        );
        let authenticated = accepted(world.authenticate(&as_rsvp, Channel::Rsvp, None).await);
        assert_eq!(
            authenticated.actor,
            Actor::RsvpAttendee {
                object: ObjectId::from_uuid(Uuid::from_u128(77)),
                address: CalendarUserAddress::parse("mailto:guest@example.org").unwrap(),
            }
        );
        assert_eq!(authenticated.tenant, Some(id(ACME)));
    }
    assert_eq!(world.finds(), 6);
    assert_eq!(world.verifies(), 6, "links are verified every time");
}

#[tokio::test]
async fn uses_are_recorded_in_batches_and_at_most_once_per_interval() {
    let world = world();
    let password = world.app_password(500).await;
    let token = world
        .api_token(501, TokenKind::Tenant, &[Scope::PrincipalsRead], None)
        .await;
    let system = world
        .api_token(502, TokenKind::System, &[Scope::SystemTenants], None)
        .await;
    let flusher = world.auth.flusher();
    assert_eq!(flusher.name(), "auth_last_used");
    assert_eq!(flusher.interval(), world.config.last_used_flush);

    for _ in 0..4 {
        world.dav("anna@acme.example", &password, None).await;
        world.bearer(&token, Channel::Api, None).await;
        world.bearer(&system, Channel::Api, None).await;
        world.clock.advance(Chrono::seconds(10));
    }
    let report = flusher.tick().await;
    assert_eq!(
        (report.processed, report.failed),
        (2, 0),
        "two credentials, once each; system tokens have no tenant"
    );
    {
        let touched = world.source.touched.lock().await;
        assert_eq!(touched.len(), 1, "one write for the tenant");
        let (tenant, uses) = &touched[0];
        assert_eq!(*tenant, id(ACME));
        assert_eq!(uses.len(), 2);
        assert!(
            uses.iter().all(|usage| usage.at == now()),
            "the time of the first use in the interval"
        );
    }
    assert!(flusher.tick().await.is_idle(), "nothing new to write");

    // Within the interval nothing is noted again; after it, the next use is.
    world.dav("anna@acme.example", &password, None).await;
    assert!(flusher.tick().await.is_idle());
    world
        .clock
        .advance(Chrono::from_std(world.config.last_used_flush).unwrap());
    world.dav("anna@acme.example", &password, None).await;
    let report = flusher.tick().await;
    assert_eq!(report.processed, 1);
}

#[tokio::test]
async fn the_last_use_debounce_stays_bounded_however_many_credentials_are_used() {
    let world = world_with(AuthConfig::default(), 20);
    let flusher = world.auth.flusher();
    let mut passwords = Vec::new();
    for n in 0..60_u128 {
        passwords.push(world.app_password(1000 + n).await);
    }
    for password in &passwords {
        world.clock.advance(Chrono::seconds(1));
        assert!(matches!(
            world.dav("anna@acme.example", password, None).await,
            AuthOutcome::Accepted(_)
        ));
        assert!(
            world.auth.last_used.remembered().await <= 20,
            "the table of recent uses is a real bound"
        );
    }
    // Nothing is lost: every credential that was used is written, the forgetting only costs a second write at most.
    let report = flusher.tick().await;
    assert_eq!(report.processed, 60);
    assert_eq!(report.failed, 0);
}

#[tokio::test]
async fn a_failed_flush_is_retried_and_loses_nothing() {
    let world = world();
    let password = world.app_password(500).await;
    let flusher = world.auth.flusher();
    world.dav("anna@acme.example", &password, None).await;
    world.source.fail_touch.store(true, Ordering::SeqCst);
    let report = flusher.tick().await;
    assert_eq!((report.processed, report.failed), (0, 1));
    world.source.fail_touch.store(false, Ordering::SeqCst);
    let report = flusher.tick().await;
    assert_eq!((report.processed, report.failed), (1, 0));
    assert_eq!(world.source.touched.lock().await.len(), 1);
}

#[tokio::test]
async fn a_failing_store_is_an_error_not_a_refusal() {
    struct Broken;

    #[async_trait]
    impl CredentialSource for Broken {
        async fn find(&self, _: CredentialKind, _: &str) -> Result<Option<LookedUpCredential>, PortError> {
            Err(PortError::unavailable("down"))
        }

        async fn touch(&self, _: TenantId, _: &[CredentialUse]) -> Result<(), PortError> {
            Err(PortError::unavailable("down"))
        }
    }

    let world = world();
    let token = world
        .api_token(501, TokenKind::Tenant, &[Scope::PrincipalsRead], None)
        .await;
    let auth = LocalAuthenticator::new(
        deps(
            Arc::new(Broken),
            Arc::clone(&world.hasher),
            &world.clock,
            Arc::new(SeqIds::new()),
        ),
        &world.config,
    );
    let hint = AuthHint {
        channel: Channel::Api,
        tenant_hint: None,
        client_ip: None,
        request_id: RequestId::from_uuid(Uuid::nil()),
    };
    let error = auth
        .authenticate(&PresentedCredential::Bearer(token.presented.clone()), &hint)
        .await
        .unwrap_err();
    assert_eq!(error.kind, davhaven_ports::PortErrorKind::Unavailable);
}

#[tokio::test]
async fn the_noop_authenticator_recognises_nothing() {
    let hint = AuthHint {
        channel: Channel::Api,
        tenant_hint: None,
        client_ip: None,
        request_id: RequestId::from_uuid(Uuid::nil()),
    };
    let outcome = NoopAuthenticator
        .authenticate(&PresentedCredential::Bearer(secret("dvh_pat_x")), &hint)
        .await
        .unwrap();
    assert_eq!(outcome, AuthOutcome::NotApplicable);
}

// ---------------------------------------------------------------------------------------------------------------
// Re-hash on use
// ---------------------------------------------------------------------------------------------------------------

/// A hasher in the middle of a key rotation: it hashes under the active key and verifies what the active and the retired
/// key made, like the production hasher over a key ring that still lists the retired key.
struct Rotating {
    active: FixedHasher,
    retired: FixedHasher,
    verifies: AtomicUsize,
}

impl Rotating {
    /// A hasher whose active key is [`NEW_KID`] and whose retired key is [`OLD_KID`].
    fn new() -> Self {
        Self {
            active: FixedHasher::new(NEW_KID),
            retired: FixedHasher::new(OLD_KID),
            verifies: AtomicUsize::new(0),
        }
    }
}

impl CredentialHasher for Rotating {
    fn hash(&self, kind: CredentialKind, secret: &SecretString) -> StoredHash {
        self.active.hash(kind, secret)
    }

    fn verify(&self, stored: &StoredHash, secret: &SecretString) -> bool {
        self.verifies.fetch_add(1, Ordering::SeqCst);
        self.active.verify(stored, secret) || self.retired.verify(stored, secret)
    }
}

/// The key id the credentials of [`World`] are hashed under.
const OLD_KID: &str = "test";

/// The key id of the active key of a rotated deployment.
const NEW_KID: &str = "next";

/// The dependencies of an authenticator over `source` whose active pepper key is [`NEW_KID`] and whose retired key
/// [`OLD_KID`] still verifies.
fn rotated_deps(world: &World, source: Arc<dyn CredentialSource>) -> LocalDeps {
    LocalDeps {
        source,
        hasher: Arc::new(Rotating::new()),
        keyring: Arc::new(FixedKeyRing::new(NEW_KID).with_retired_kid(OLD_KID)),
        clock: Arc::new(world.clock.clone()),
        ids: Arc::new(SeqIds::new()),
    }
}

/// An authenticator over the credentials of `world` after a key rotation.
fn rotated(world: &World) -> LocalAuthenticator {
    LocalAuthenticator::new(rotated_deps(world, Arc::<Fake>::clone(&world.source)), &world.config)
}

fn hint(channel: Channel) -> AuthHint {
    AuthHint {
        channel,
        tenant_hint: None,
        client_ip: None,
        request_id: RequestId::from_uuid(Uuid::nil()),
    }
}

fn basic(password: &Generated) -> PresentedCredential {
    PresentedCredential::Basic {
        username: "anna@acme.example".to_owned(),
        password: password.presented.clone(),
    }
}

impl World {
    /// The key id a stored credential names.
    async fn kid_of(&self, kind: CredentialKind, prefix: &str) -> String {
        self.stored(kind, prefix).await.pepper_kid
    }

    /// The stored hash of a credential.
    async fn stored(&self, kind: CredentialKind, prefix: &str) -> StoredHash {
        let credentials = self.source.credentials.lock().await;
        stored_hash_of(&credentials.get(&(kind, prefix.to_owned())).unwrap().record)
    }

    async fn rehashes(&self) -> Vec<(TenantId, Rehash)> {
        self.source.rehashed.lock().await.clone()
    }
}

#[tokio::test]
async fn a_credential_moves_to_the_active_pepper_key_when_it_is_used() {
    let world = world();
    let password = world.app_password(500).await;
    let token = world
        .api_token(501, TokenKind::Principal, &[Scope::EventsRead], None)
        .await;
    let feed = world.feed_token(502).await;
    let auth = rotated(&world);
    let before = world.stored(CredentialKind::AppPassword, &password.prefix).await;
    assert_eq!(before.pepper_kid, OLD_KID);

    let outcome = auth.authenticate(&basic(&password), &hint(Channel::Dav)).await.unwrap();
    assert!(matches!(outcome, AuthOutcome::Accepted(_)), "{outcome:?}");
    let swaps = world.rehashes().await;
    assert_eq!(swaps.len(), 1);
    assert_eq!(swaps[0].0, id(ACME), "the swap is made in the tenant of the credential");
    let swap = &swaps[0].1;
    assert_eq!(
        (
            swap.credential.kind,
            swap.credential.id,
            swap.from_kid.as_str(),
            swap.to.pepper_kid.as_str()
        ),
        (CredentialKind::AppPassword, Uuid::from_u128(500), OLD_KID, NEW_KID)
    );
    assert_eq!(
        swap.to.kind,
        CredentialKind::AppPassword,
        "the hash is of the kind of the credential"
    );
    let after = world.stored(CredentialKind::AppPassword, &password.prefix).await;
    assert_eq!(after.pepper_kid, NEW_KID);
    assert_ne!(after.hash, before.hash, "the hash is a new one");
    assert!(
        !world.hasher.verify(&after, &password.secret),
        "it depends on the active key now: the retired key is not needed for this credential"
    );

    // The moved credential keeps working, and a credential on the active key is not touched again.
    for _ in 0..3 {
        assert!(matches!(
            auth.authenticate(&basic(&password), &hint(Channel::Dav)).await.unwrap(),
            AuthOutcome::Accepted(_)
        ));
    }
    assert_eq!(world.rehashes().await.len(), 1, "once per credential");

    // Tokens and feed links move the same way.
    let bearer = PresentedCredential::Bearer(token.presented.clone());
    assert!(matches!(
        auth.authenticate(&bearer, &hint(Channel::Api)).await.unwrap(),
        AuthOutcome::Accepted(_)
    ));
    let link = PresentedCredential::Feed(feed.presented.clone());
    assert!(matches!(
        auth.authenticate(&link, &hint(Channel::Feed)).await.unwrap(),
        AuthOutcome::Accepted(_)
    ));
    assert_eq!(world.rehashes().await.len(), 3);
    assert_eq!(world.kid_of(CredentialKind::ApiToken, &token.prefix).await, NEW_KID);
    assert_eq!(world.kid_of(CredentialKind::FeedToken, &feed.prefix).await, NEW_KID);

    // What was stored is the hash of the secret of each kind under the new key alone (a hasher that knows only the new
    // key accepts it), so no credential needs the retired key once it has been used. A re-hash of the wrong input, such
    // as the whole text of a token, would stop it from verifying at its next use after the key is gone.
    let only_new = FixedHasher::new(NEW_KID);
    for (kind, generated) in [
        (CredentialKind::AppPassword, &password),
        (CredentialKind::ApiToken, &token),
        (CredentialKind::FeedToken, &feed),
    ] {
        let stored = world.stored(kind, &generated.prefix).await;
        assert_eq!(stored.kind, kind);
        assert!(only_new.verify(&stored, &generated.secret), "{kind}");
        if kind != CredentialKind::AppPassword {
            // The text of a token is `dvh_..._{prefix}_{secret}`: the hash is of the secret part alone. (An app password
            // is hashed as the text that is typed.)
            assert!(
                !only_new.verify(&stored, &generated.presented),
                "{kind}: the hash is of the secret, not of the text that was presented"
            );
        }
    }
}

#[tokio::test]
async fn what_the_cache_remembers_after_a_move_is_the_verification_of_the_new_hash() {
    let world = world();
    let password = world.app_password(500).await;
    let hasher = Arc::new(Rotating::new());
    let auth = LocalAuthenticator::new(
        LocalDeps {
            source: Arc::<Fake>::clone(&world.source),
            hasher: Arc::<Rotating>::clone(&hasher),
            keyring: Arc::new(FixedKeyRing::new(NEW_KID).with_retired_kid(OLD_KID)),
            clock: Arc::new(world.clock.clone()),
            ids: Arc::new(SeqIds::new()),
        },
        &world.config,
    );

    assert!(matches!(
        auth.authenticate(&basic(&password), &hint(Channel::Dav)).await.unwrap(),
        AuthOutcome::Accepted(_)
    ));
    assert_eq!(world.rehashes().await.len(), 1);
    let verified = hasher.verifies.load(Ordering::SeqCst);
    assert_eq!(verified, 1, "one verification of the secret against the old hash");

    // The cached verification covers the row as the move left it: no second verification, no second move.
    for _ in 0..3 {
        assert!(matches!(
            auth.authenticate(&basic(&password), &hint(Channel::Dav)).await.unwrap(),
            AuthOutcome::Accepted(_)
        ));
    }
    assert_eq!(
        hasher.verifies.load(Ordering::SeqCst),
        verified,
        "answered from the cache"
    );
    assert_eq!(world.rehashes().await.len(), 1);
}

#[tokio::test]
async fn only_an_accepted_credential_is_moved() {
    let world = world();
    let password = world.app_password(500).await;
    let revoked = world.app_password(501).await;
    let suspended = world.app_password(502).await;
    let expired = world
        .api_token(
            503,
            TokenKind::Principal,
            &[Scope::EventsRead],
            Some(now() + Chrono::hours(1)),
        )
        .await;
    world
        .edit(CredentialKind::AppPassword, &revoked.prefix, |found| {
            if let CredentialRecord::AppPassword(row) = &mut found.record {
                row.revoked_at = Some(now());
            }
        })
        .await;
    world
        .edit(CredentialKind::AppPassword, &suspended.prefix, |found| {
            found.principal_status = Some(PrincipalStatus::Suspended);
        })
        .await;
    world.clock.advance(Chrono::hours(2));
    let auth = rotated(&world);

    // A wrong secret under the right prefix.
    let text = password.presented.expose_secret().to_owned();
    let (head, _) = text.rsplit_once('-').unwrap();
    let tail = if text.ends_with("zzzz") { "yyyy" } else { "zzzz" };
    let wrong = PresentedCredential::Basic {
        username: "anna@acme.example".to_owned(),
        password: SecretString::from(format!("{head}-{tail}")),
    };
    assert_eq!(
        auth.authenticate(&wrong, &hint(Channel::Dav)).await.unwrap(),
        rejected(RejectReason::BadSecret)
    );
    // A revoked credential, a suspended principal, an expired token and a login that is not the owner's.
    assert_eq!(
        auth.authenticate(&basic(&revoked), &hint(Channel::Dav)).await.unwrap(),
        rejected(RejectReason::Revoked)
    );
    assert_eq!(
        auth.authenticate(&basic(&suspended), &hint(Channel::Dav))
            .await
            .unwrap(),
        rejected(RejectReason::Suspended)
    );
    let bearer = PresentedCredential::Bearer(expired.presented.clone());
    assert_eq!(
        auth.authenticate(&bearer, &hint(Channel::Api)).await.unwrap(),
        rejected(RejectReason::Expired)
    );
    let stranger = PresentedCredential::Basic {
        username: "bert@acme.example".to_owned(),
        password: password.presented.clone(),
    };
    assert_eq!(
        auth.authenticate(&stranger, &hint(Channel::Dav)).await.unwrap(),
        rejected(RejectReason::UnknownCredential)
    );
    assert!(world.rehashes().await.is_empty(), "nothing was moved");
    for prefix in [&password.prefix, &revoked.prefix, &suspended.prefix] {
        assert_eq!(world.kid_of(CredentialKind::AppPassword, prefix).await, OLD_KID);
    }
}

#[tokio::test]
async fn a_failing_store_does_not_fail_the_request_and_the_cache_does_not_move_credentials() {
    let world = world();
    let password = world.app_password(500).await;
    let auth = rotated(&world);

    // The swap fails: the request is accepted all the same and the credential keeps its key.
    world.source.fail_rehash.store(true, Ordering::SeqCst);
    assert!(matches!(
        auth.authenticate(&basic(&password), &hint(Channel::Dav)).await.unwrap(),
        AuthOutcome::Accepted(_)
    ));
    assert!(world.rehashes().await.is_empty(), "the swap failed");
    assert_eq!(
        world.kid_of(CredentialKind::AppPassword, &password.prefix).await,
        OLD_KID
    );

    // A verification that the cache remembers is not a verification of the secret against the row: nothing moves.
    world.source.fail_rehash.store(false, Ordering::SeqCst);
    assert!(matches!(
        auth.authenticate(&basic(&password), &hint(Channel::Dav)).await.unwrap(),
        AuthOutcome::Accepted(_)
    ));
    assert!(
        world.rehashes().await.is_empty(),
        "the second request was answered from the cache"
    );

    // When the cache has forgotten it, the next use moves the credential.
    world
        .clock
        .advance(Chrono::from_std(world.config.cache_ttl).unwrap() + Chrono::seconds(1));
    assert!(matches!(
        auth.authenticate(&basic(&password), &hint(Channel::Dav)).await.unwrap(),
        AuthOutcome::Accepted(_)
    ));
    assert_eq!(world.rehashes().await.len(), 1);
    assert_eq!(
        world.kid_of(CredentialKind::AppPassword, &password.prefix).await,
        NEW_KID
    );
}

#[test]
fn a_store_without_the_method_means_nothing_changed_and_other_failures_stay_failures() {
    assert!(matches!(swapped(Ok(true)), Ok(true)));
    assert!(matches!(swapped(Ok(false)), Ok(false)));
    assert!(matches!(swapped(Err(StoreError::Unsupported)), Ok(false)));
    assert!(swapped(Err(StoreError::Unavailable)).is_err());
}

#[tokio::test]
async fn a_source_that_cannot_rehash_changes_nothing() {
    // The default of the trait: the credential keeps verifying under its old key.
    struct ReadOnly(Arc<Fake>);

    #[async_trait]
    impl CredentialSource for ReadOnly {
        async fn find(&self, kind: CredentialKind, prefix: &str) -> Result<Option<LookedUpCredential>, PortError> {
            self.0.find(kind, prefix).await
        }

        async fn touch(&self, tenant: TenantId, uses: &[CredentialUse]) -> Result<(), PortError> {
            self.0.touch(tenant, uses).await
        }
    }

    let world = world();
    let password = world.app_password(500).await;
    let auth = LocalAuthenticator::new(
        rotated_deps(&world, Arc::new(ReadOnly(Arc::clone(&world.source)))),
        &world.config,
    );
    assert!(matches!(
        auth.authenticate(&basic(&password), &hint(Channel::Dav)).await.unwrap(),
        AuthOutcome::Accepted(_)
    ));
    assert_eq!(
        world.kid_of(CredentialKind::AppPassword, &password.prefix).await,
        OLD_KID
    );
}
