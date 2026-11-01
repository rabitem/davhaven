//! The local authenticator and the failure backoff, on the memory store and on PostgreSQL, with the production
//! cryptography.
//!
//! The contract suites of the `Authenticator` port need a database, and an adapter may not depend on another one
//! (`ENGINEERING_RULES` R1), so they run here, where every adapter is available: `davhaven-auth-local` over
//! `davhaven-store-memory` and over `davhaven-store-postgres`, hashing with `davhaven-crypto-local`. The suites are run
//! twice per store: the one every authenticator passes (`noop` included) and the one of the authenticators that verify
//! the credentials of the store. On PostgreSQL the credential lookup by prefix (before the tenant of a request is
//! known) runs in system scope, the lookups of the tenant and the bookkeeping of a use run in tenant transactions of
//! the bound runtime role, so row-level security and the policies of the system scope are what the authenticator is
//! checked against (backlog item 20; the database is a clone of the migrated template, as the `TestApp` of the
//! harness has it). The same file proves that the suites catch an authenticator that does not keep its promises, that
//! the plugin builds with a database and hands out its worker, and that failed logins, through the real edge layer,
//! the real authenticator and the real limiter, back off with `Retry-After` and recover.

#![expect(
    clippy::unwrap_used,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use davhaven_testkit::axum::Router;
use davhaven_testkit::axum::body::Body;
use davhaven_testkit::axum::extract::ConnectInfo;
use davhaven_testkit::axum::middleware::from_fn_with_state;
use davhaven_testkit::axum::routing::any;
use davhaven_testkit::davhaven_app::error::{AppError, AppResult};
use davhaven_testkit::davhaven_app::services::{AuthRequest, AuthService, PresentedCredential as AppCredential};
use davhaven_testkit::davhaven_auth_local::authenticator::{
    DatabaseSource, LocalAuthenticator, LocalDeps, NoopAuthenticator,
};
use davhaven_testkit::davhaven_auth_local::config::AuthConfig;
use davhaven_testkit::davhaven_crypto_local::hasher::LocalHasher;
use davhaven_testkit::davhaven_crypto_local::keyring::{KeyMaterial, LocalCrypto, LocalKeyRing};
use davhaven_testkit::davhaven_domain::{
    ApiToken, AppPassword, AppPasswordText, CredentialKind, FeedMode, FeedToken, RequestContext, Scope, ScopeSet,
    TokenId, TokenKind, TokenText,
};
use davhaven_testkit::davhaven_http::{Edge, HeaderAuth, SequentialRequestIds, Surface, authenticate_header};
use davhaven_testkit::davhaven_port_tests::auth::{AuthRig, run, run_all, run_store_backed, run_store_backed_all};
use davhaven_testkit::davhaven_port_tests::store::fixtures::seed;
use davhaven_testkit::davhaven_ports::testing::{ManualClock, SeqIds};
use davhaven_testkit::davhaven_ports::{
    AuthHint, AuthOutcome, Authenticator, Clock as _, ConfigTree, CredentialHasher as _, Database, IdGenerator,
    PluginContext, PluginRegistry, PortKind, PresentedCredential, RateKey, RateLimiter, RunMode, TxMode,
    bucket_address,
};
use davhaven_testkit::davhaven_ratelimit_memory::config::MemoryRateLimitConfig;
use davhaven_testkit::davhaven_ratelimit_memory::memory::MemoryRateLimiter;
use davhaven_testkit::davhaven_store_memory::database::MemoryDatabase;
use davhaven_testkit::http::{Request, StatusCode};
use davhaven_testkit::postgres::{ClonedDatabase, require_database};
use secrecy::SecretString;
use tower::ServiceExt as _;
use uuid::Uuid;

/// The keys of the tests: two keys, `active` of them signs.
fn material(active: &str) -> KeyMaterial {
    KeyMaterial::new(
        active,
        vec![
            (
                "2027-01".to_owned(),
                SecretString::from("0123456789abcdef0123456789abcdef-key-one"),
            ),
            (
                "2026-07".to_owned(),
                SecretString::from("fedcba9876543210fedcba9876543210-key-two"),
            ),
        ],
    )
    .unwrap()
}

/// A fresh memory database with the production cryptography and the local authenticator.
async fn local_rig() -> AuthRig {
    let clock = ManualClock::default();
    let ids: Arc<dyn IdGenerator> = Arc::new(SeqIds::starting_at(0x10_0000));
    let database: Arc<dyn Database> = Arc::new(MemoryDatabase::new(Arc::new(clock.clone()), Arc::clone(&ids)));
    rig_on(database, clock, ids)
}

/// A fresh PostgreSQL database (a clone of the migrated template, reached as the bound runtime role, dropped with the
/// rig) with the production cryptography and the local authenticator.
async fn local_rig_on_postgres() -> AuthRig {
    let clock = ManualClock::default();
    let ids: Arc<dyn IdGenerator> = Arc::new(SeqIds::starting_at(0x10_0000));
    let database = ClonedDatabase::create()
        .await
        .and_then(|clone| clone.into_database(Arc::new(clock.clone()), Arc::clone(&ids)))
        .unwrap();
    rig_on(database, clock, ids)
}

/// The production cryptography and the local authenticator over `database`.
fn rig_on(database: Arc<dyn Database>, clock: ManualClock, ids: Arc<dyn IdGenerator>) -> AuthRig {
    let crypto = LocalCrypto::new(&material("2027-01"), Arc::clone(&ids));
    let authenticator = LocalAuthenticator::new(
        LocalDeps {
            source: Arc::new(DatabaseSource::new(Arc::clone(&database))),
            hasher: Arc::<LocalHasher>::clone(&crypto.hasher),
            keyring: Arc::<LocalKeyRing>::clone(&crypto.keyring),
            clock: Arc::new(clock.clone()),
            ids,
        },
        &AuthConfig::default(),
    );
    AuthRig {
        flush: Some(authenticator.flusher()),
        authenticator: Arc::new(authenticator),
        database,
        hasher: crypto.hasher,
        clock,
    }
}

#[tokio::test]
async fn the_local_authenticator_satisfies_both_contracts() {
    run_all(local_rig).await;
    assert_eq!(run(local_rig).await.case_count(), 3);
    run_store_backed_all(local_rig).await;
    assert_eq!(run_store_backed(local_rig).await.case_count(), 10);
}

#[tokio::test]
async fn the_local_authenticator_satisfies_both_contracts_on_postgres() {
    if !require_database() {
        return;
    }
    // Every case gets a database of its own (a clone of the template, created and dropped), so each suite runs once and
    // its report is both asserted and counted.
    let common = run(local_rig_on_postgres).await;
    common.assert_ok();
    assert_eq!(common.case_count(), 3);
    let store_backed = run_store_backed(local_rig_on_postgres).await;
    store_backed.assert_ok();
    assert_eq!(store_backed.case_count(), 10);
}

#[tokio::test]
async fn an_authenticator_that_recognises_nothing_passes_the_common_contract_and_fails_the_store_backed_one() {
    let noop = || async {
        let rig = local_rig().await;
        AuthRig {
            authenticator: Arc::new(NoopAuthenticator),
            flush: None,
            ..rig
        }
    };
    // It never accepts what it cannot verify, passes foreign values on and does not break on odd input.
    run_all(noop).await;
    let report = run_store_backed(noop).await;
    let failed = report.failed_cases();
    assert!(
        failed.contains(&"every kind of credential authenticates on its surface"),
        "{report}"
    );
    assert!(
        failed.contains(&"logins are checked and the tenant of the path is not a reason to refuse a credential"),
        "{report}"
    );
    assert!(
        !failed.contains(&"uses are recorded in batches"),
        "a rig without a flush worker skips the recording case: {report}"
    );
}

#[tokio::test]
async fn an_authenticator_that_accepts_what_it_cannot_verify_is_caught_by_the_common_contract() {
    /// Accepts every bearer token: the worst thing an authenticator can do.
    struct Gullible;

    #[async_trait]
    impl Authenticator for Gullible {
        async fn authenticate(
            &self,
            _credential: &PresentedCredential,
            _hint: &AuthHint,
        ) -> Result<AuthOutcome, davhaven_testkit::davhaven_ports::PortError> {
            Ok(AuthOutcome::Accepted(davhaven_testkit::davhaven_ports::Authenticated {
                tenant: None,
                actor: davhaven_testkit::davhaven_domain::Actor::Anonymous,
                scopes: davhaven_testkit::davhaven_domain::ScopeSet::empty(),
                credential: davhaven_testkit::davhaven_domain::CredentialRef::api_token(
                    TokenId::from_uuid(Uuid::nil()),
                ),
                label: None,
            }))
        }
    }

    let report = run(|| async {
        let rig = local_rig().await;
        AuthRig {
            authenticator: Arc::new(Gullible),
            flush: None,
            ..rig
        }
    })
    .await;
    assert_eq!(report.failed_cases().len(), 3, "{report}");
}

#[tokio::test]
async fn the_plugin_builds_with_a_database_and_hands_out_its_worker() {
    let mut registry = PluginRegistry::new();
    davhaven_testkit::davhaven_auth_local::plugin::register(&mut registry).unwrap();
    let rig = local_rig().await;
    let context = PluginContext::for_tests().with_database(rig.database);
    let built = registry
        .build_chain(
            PortKind::AUTHENTICATOR,
            &["local", "noop"],
            &context,
            &ConfigTree::new(),
        )
        .await
        .unwrap();
    assert_eq!(built.len(), 2);
    let workers: Vec<&str> = built[0].workers.iter().map(|worker| worker.name()).collect();
    assert_eq!(workers, vec!["auth_last_used"]);
    assert!(built[1].workers.is_empty());
    // Production mode does not refuse the local authenticator.
    let production = PluginContext::new(
        Arc::clone(&context.clock),
        Arc::clone(&context.ids),
        Arc::clone(&context.keyring),
        Arc::clone(&context.sealer),
        Arc::clone(&context.hasher),
        RunMode::Production,
    )
    .with_database(Arc::clone(context.database.as_ref().unwrap()));
    registry
        .build_chain(PortKind::AUTHENTICATOR, &["local"], &production, &ConfigTree::new())
        .await
        .unwrap();
}

/// Rows are hashed with the key ring as it was before a rotation (`2027-01` active) and authentication runs with
/// the rotated one (`2026-07` active, `2027-01` kept for verification).
async fn rotated_rig() -> AuthRig {
    let clock = ManualClock::default();
    let ids: Arc<dyn IdGenerator> = Arc::new(SeqIds::starting_at(0x20_0000));
    let database: Arc<dyn Database> = Arc::new(MemoryDatabase::new(Arc::new(clock.clone()), Arc::clone(&ids)));
    let before = LocalCrypto::new(&material("2027-01"), Arc::clone(&ids));
    let after = LocalCrypto::new(&material("2026-07"), Arc::clone(&ids));
    let authenticator = LocalAuthenticator::new(
        LocalDeps {
            source: Arc::new(DatabaseSource::new(Arc::clone(&database))),
            hasher: Arc::<LocalHasher>::clone(&after.hasher),
            keyring: Arc::<LocalKeyRing>::clone(&after.keyring),
            clock: Arc::new(clock.clone()),
            ids,
        },
        &AuthConfig::default(),
    );
    AuthRig {
        flush: Some(authenticator.flusher()),
        authenticator: Arc::new(authenticator),
        database,
        hasher: before.hasher,
        clock,
    }
}

#[tokio::test]
async fn credentials_hashed_under_a_retired_pepper_authenticate_after_a_key_rotation() {
    run_store_backed_all(rotated_rig).await;
}

/// An authenticator over `database` whose hasher and key ring are `crypto`.
fn authenticator_over(
    database: &Arc<dyn Database>,
    crypto: &LocalCrypto,
    clock: &ManualClock,
    ids: &Arc<dyn IdGenerator>,
) -> LocalAuthenticator {
    LocalAuthenticator::new(
        LocalDeps {
            source: Arc::new(DatabaseSource::new(Arc::clone(database))),
            hasher: Arc::<LocalHasher>::clone(&crypto.hasher),
            keyring: Arc::<LocalKeyRing>::clone(&crypto.keyring),
            clock: Arc::new(clock.clone()),
            ids: Arc::clone(ids),
        },
        &AuthConfig::default(),
    )
}

/// Stores an app password of Mia hashed by `crypto`, as the application stores what it mints, and returns the
/// password.
async fn mint_password(
    database: &Arc<dyn Database>,
    crypto: &LocalCrypto,
    clock: &ManualClock,
    world: &davhaven_testkit::davhaven_port_tests::store::fixtures::World,
    n: u128,
    ids: &Arc<dyn IdGenerator>,
) -> String {
    let text = AppPasswordText::from_random(
        &ids.random_bytes(davhaven_testkit::davhaven_domain::credential_format::APP_PASSWORD_RANDOM_BYTES),
    )
    .unwrap();
    let stored = crypto.hasher.hash(
        CredentialKind::AppPassword,
        &SecretString::from(text.expose().to_owned()),
    );
    let mut tx = database.begin(world.a, TxMode::ReadWrite).await.unwrap();
    tx.credentials()
        .create_app_password(AppPassword {
            id: davhaven_testkit::davhaven_domain::CredentialId::from_uuid(Uuid::from_u128(n)),
            tenant_id: world.a,
            principal_id: world.mia,
            label: "iPhone".to_owned(),
            prefix: text.prefix().to_owned(),
            hash: stored.hash,
            pepper_kid: stored.pepper_kid,
            last_used_at: None,
            revoked_at: None,
            created_at: clock.now(),
            updated_at: clock.now(),
            version: 1,
        })
        .await
        .unwrap();
    tx.commit().await.unwrap();
    text.expose().to_owned()
}

/// Stores a token of Mia hashed by `crypto` (an API token that acts as her, or a feed token) and returns the text a client
/// presents.
async fn mint_token(
    database: &Arc<dyn Database>,
    crypto: &LocalCrypto,
    clock: &ManualClock,
    world: &davhaven_testkit::davhaven_port_tests::store::fixtures::World,
    kind: CredentialKind,
    n: u128,
    ids: &Arc<dyn IdGenerator>,
) -> String {
    use davhaven_testkit::davhaven_domain::credential_format::{TOKEN_PREFIX_RANDOM_BYTES, TOKEN_SECRET_RANDOM_BYTES};

    let text = TokenText::from_random(
        kind,
        &ids.random_bytes(TOKEN_PREFIX_RANDOM_BYTES),
        &ids.random_bytes(TOKEN_SECRET_RANDOM_BYTES),
    )
    .unwrap();
    // What is stored is the hash of the secret part of the text, as the application mints it.
    let stored = crypto.hasher.hash(kind, &SecretString::from(text.secret().to_owned()));
    let mut tx = database.begin(world.a, TxMode::ReadWrite).await.unwrap();
    match kind {
        CredentialKind::ApiToken => {
            tx.credentials()
                .create_api_token(ApiToken {
                    id: TokenId::from_uuid(Uuid::from_u128(n)),
                    tenant_id: Some(world.a),
                    kind: TokenKind::Principal,
                    principal_id: Some(world.mia),
                    label: "integration".to_owned(),
                    scopes: ScopeSet::of(&[Scope::EventsRead]),
                    prefix: text.prefix().to_owned(),
                    hash: stored.hash,
                    pepper_kid: stored.pepper_kid,
                    expires_at: None,
                    created_by: None,
                    allowed_origins: Vec::new(),
                    last_used_at: None,
                    revoked_at: None,
                    created_at: clock.now(),
                    updated_at: clock.now(),
                    version: 1,
                })
                .await
                .unwrap();
        }
        CredentialKind::FeedToken => {
            tx.credentials()
                .create_feed_token(FeedToken {
                    id: TokenId::from_uuid(Uuid::from_u128(n)),
                    tenant_id: world.a,
                    principal_id: world.mia,
                    mode: FeedMode::Busy,
                    calendar_ids: Vec::new(),
                    prefix: text.prefix().to_owned(),
                    hash: stored.hash,
                    pepper_kid: stored.pepper_kid,
                    revoked_at: None,
                    created_at: clock.now(),
                    updated_at: clock.now(),
                    version: 1,
                })
                .await
                .unwrap();
        }
        CredentialKind::AppPassword | CredentialKind::RsvpToken => unreachable!("not a token of this helper"),
    }
    tx.commit().await.unwrap();
    text.expose().as_str().to_owned()
}

/// The key id the stored hash of app password `n` of the first tenant names.
async fn kid_of_password(
    database: &Arc<dyn Database>,
    world: &davhaven_testkit::davhaven_port_tests::store::fixtures::World,
    n: u128,
) -> String {
    let mut tx = database.begin(world.a, TxMode::ReadOnly).await.unwrap();
    tx.credentials()
        .get_app_password(davhaven_testkit::davhaven_domain::CredentialId::from_uuid(
            Uuid::from_u128(n),
        ))
        .await
        .unwrap()
        .pepper_kid
}

#[tokio::test]
async fn a_used_credential_moves_to_the_active_key_and_outlives_the_retired_one() {
    use davhaven_testkit::davhaven_domain::{Channel, RequestId};

    let clock = ManualClock::default();
    let ids: Arc<dyn IdGenerator> = Arc::new(SeqIds::starting_at(0x30_0000));
    let database: Arc<dyn Database> = Arc::new(MemoryDatabase::new(Arc::new(clock.clone()), Arc::clone(&ids)));
    let world = seed(&database).await.unwrap();
    let hint = AuthHint {
        channel: Channel::Dav,
        tenant_hint: None,
        client_ip: None,
        request_id: RequestId::from_uuid(Uuid::nil()),
    };
    let login = |password: &str| PresentedCredential::Basic {
        username: "mia@acme.example".to_owned(),
        password: SecretString::from(password.to_owned()),
    };

    // Two app passwords, an API token and a feed link were minted before the rotation, under the key that is active then.
    let before = LocalCrypto::new(&material("2027-01"), Arc::clone(&ids));
    let used = mint_password(&database, &before, &clock, &world, 1, &ids).await;
    let idle = mint_password(&database, &before, &clock, &world, 2, &ids).await;
    let api = mint_token(&database, &before, &clock, &world, CredentialKind::ApiToken, 3, &ids).await;
    let feed = mint_token(&database, &before, &clock, &world, CredentialKind::FeedToken, 4, &ids).await;
    let on = |channel| AuthHint {
        channel,
        tenant_hint: None,
        client_ip: None,
        request_id: RequestId::from_uuid(Uuid::nil()),
    };
    let bearer = || PresentedCredential::Bearer(SecretString::from(api.clone()));
    let link = || PresentedCredential::Feed(SecretString::from(feed.clone()));

    // The rotation: another key is active, the old one stays in the ring.
    let after = LocalCrypto::new(&material("2026-07"), Arc::clone(&ids));
    let rotated = authenticator_over(&database, &after, &clock, &ids);
    assert!(matches!(
        rotated.authenticate(&login(&used), &hint).await.unwrap(),
        AuthOutcome::Accepted(_)
    ));
    assert_eq!(
        kid_of_password(&database, &world, 1).await,
        "2026-07",
        "the password that was used is hashed under the active key now"
    );
    assert_eq!(
        kid_of_password(&database, &world, 2).await,
        "2027-01",
        "the one that was not used waits for its first use"
    );
    assert!(matches!(
        rotated.authenticate(&login(&used), &hint).await.unwrap(),
        AuthOutcome::Accepted(_)
    ));
    // The token and the feed link move on their first use as well.
    assert!(matches!(
        rotated.authenticate(&bearer(), &on(Channel::Api)).await.unwrap(),
        AuthOutcome::Accepted(_)
    ));
    assert!(matches!(
        rotated.authenticate(&link(), &on(Channel::Feed)).await.unwrap(),
        AuthOutcome::Accepted(_)
    ));
    {
        let mut tx = database.begin(world.a, TxMode::ReadOnly).await.unwrap();
        assert_eq!(
            tx.credentials()
                .get_api_token(TokenId::from_uuid(Uuid::from_u128(3)))
                .await
                .unwrap()
                .pepper_kid,
            "2026-07"
        );
        assert_eq!(
            tx.credentials()
                .get_feed_token(TokenId::from_uuid(Uuid::from_u128(4)))
                .await
                .unwrap()
                .pepper_kid,
            "2026-07"
        );
    }

    // The retired key leaves the ring: what was used since the rotation keeps working, the rest does not.
    let only_new = KeyMaterial::new(
        "2026-07",
        vec![(
            "2026-07".to_owned(),
            SecretString::from("fedcba9876543210fedcba9876543210-key-two"),
        )],
    )
    .unwrap();
    let retired = authenticator_over(&database, &LocalCrypto::new(&only_new, Arc::clone(&ids)), &clock, &ids);
    assert!(matches!(
        retired.authenticate(&login(&used), &hint).await.unwrap(),
        AuthOutcome::Accepted(_)
    ));
    assert!(matches!(
        retired.authenticate(&login(&idle), &hint).await.unwrap(),
        AuthOutcome::Rejected(_)
    ));
    // Every kind of credential that moved is still good without the retired key: the hash that was stored is the one of
    // its secret under the new key, not of the text that was presented.
    assert!(matches!(
        retired.authenticate(&bearer(), &on(Channel::Api)).await.unwrap(),
        AuthOutcome::Accepted(_)
    ));
    assert!(matches!(
        retired.authenticate(&link(), &on(Channel::Feed)).await.unwrap(),
        AuthOutcome::Accepted(_)
    ));
}

// ---------------------------------------------------------------------------------------------------------------
// Failed logins back off, through the real layers
// ---------------------------------------------------------------------------------------------------------------

/// What the application's `AuthService` does around the authenticator, in miniature: ask the failure buckets
/// whether the (login, address) pair or the address is blocked before verifying anything, and record a failure in
/// both buckets when the credential is refused. The buckets are named by the constants of the port and keyed by the
/// bucket address, as the contract says. It stands in for the real authentication service; the
/// edge layer, the authenticator and the limiter in front of and behind it are the real ones.
struct Accounting {
    authenticator: Arc<dyn Authenticator>,
    limiter: Arc<dyn RateLimiter>,
}

impl Accounting {
    fn keys(request: &AuthRequest, login: &str) -> Vec<RateKey> {
        let address = request
            .client_ip
            .map_or_else(|| "-".to_owned(), |ip| bucket_address(ip).to_string());
        let mut keys = vec![RateKey::auth_login_ip(format!("{login}|{address}"))];
        if request.client_ip.is_some() {
            keys.push(RateKey::auth_ip(address));
        }
        keys
    }
}

#[async_trait]
impl AuthService for Accounting {
    async fn authenticate(&self, request: AuthRequest) -> AppResult<RequestContext> {
        let AppCredential::Basic { username, password } = &request.credential else {
            return Err(AppError::unauthenticated());
        };
        let login = username.trim().to_ascii_lowercase();
        let keys = Self::keys(&request, &login);
        for key in &keys {
            let decision = self.limiter.check(key, 0).await?;
            if !decision.allowed {
                return Err(AppError::rate_limited(decision.retry_after.unwrap_or_default()));
            }
        }
        let hint = AuthHint {
            channel: request.channel,
            tenant_hint: request.tenant_hint.clone(),
            client_ip: request.client_ip,
            request_id: request.request_id,
        };
        let presented = PresentedCredential::Basic {
            username: username.clone(),
            password: password.clone(),
        };
        match self.authenticator.authenticate(&presented, &hint).await? {
            AuthOutcome::Accepted(auth) => Ok(RequestContext {
                tenant: auth.tenant.ok_or_else(AppError::unauthenticated)?,
                actor: auth.actor,
                scopes: auth.scopes,
                channel: request.channel,
                credential: Some(auth.credential),
                request_id: request.request_id,
                locale: None,
                client_ip: request.client_ip,
            }),
            AuthOutcome::Rejected(_) | AuthOutcome::NotApplicable => {
                for key in &keys {
                    self.limiter.check(key, 1).await?;
                }
                Err(AppError::unauthenticated())
            }
        }
    }
}

const LOGIN: &str = "mia@acme.example";
const PATH: &str = "/dav/calendars/acme/mia/";

/// The DAV edge over a store with Mia's app password, the local authenticator and the memory limiter with the
/// failure backoff a deployment gets without configuration. Returns the app, the clock and the password.
async fn dav_edge() -> (Router, ManualClock, String) {
    let rig = local_rig().await;
    let world = seed(&rig.database).await.unwrap();
    let presented = davhaven_testkit::davhaven_fixtures::world::app_password_secret("mia-iphone");
    let parsed = AppPasswordText::parse(&presented).unwrap();
    let stored = rig
        .hasher
        .hash(CredentialKind::AppPassword, &SecretString::from(parsed.expose()));
    let now = rig.clock.now();
    let mut tx = rig.database.begin(world.a, TxMode::ReadWrite).await.unwrap();
    tx.credentials()
        .create_app_password(AppPassword {
            id: Uuid::from_u128(0x5001).into(),
            tenant_id: world.a,
            principal_id: world.mia,
            label: "iPhone".to_owned(),
            prefix: parsed.prefix().to_owned(),
            hash: stored.hash,
            pepper_kid: stored.pepper_kid,
            last_used_at: None,
            revoked_at: None,
            created_at: now,
            updated_at: now,
            version: 1,
        })
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let limiter: Arc<dyn RateLimiter> = Arc::new(MemoryRateLimiter::new(
        Arc::new(rig.clock.clone()),
        MemoryRateLimitConfig::default(),
    ));
    let service: Arc<dyn AuthService> = Arc::new(Accounting {
        authenticator: rig.authenticator,
        limiter,
    });
    let edge = Edge::new(Surface::Dav, Arc::new(SequentialRequestIds::new()));
    let routes = Router::new()
        .route(PATH, any(|| async { "calendars" }))
        .route_layer(from_fn_with_state(HeaderAuth::dav(service), authenticate_header));
    (edge.apply(routes), rig.clock, presented)
}

async fn login(app: &Router, password: &str, from: &str) -> (StatusCode, String) {
    let credentials = STANDARD.encode(format!("{LOGIN}:{password}"));
    let mut request = Request::get(PATH)
        .header("authorization", format!("Basic {credentials}"))
        .body(Body::empty())
        .unwrap();
    let ip: IpAddr = from.parse().unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(ip, 40_000)));
    let response = app.clone().oneshot(request).await.unwrap();
    let retry_after = response
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    (response.status(), retry_after)
}

#[tokio::test]
async fn failed_logins_back_off_with_a_retry_after_and_the_right_password_recovers() {
    let (app, clock, password) = dav_edge().await;
    let wrong = {
        let mut text = password.clone();
        let last = text.pop().unwrap();
        text.push(if last == 'a' { 'b' } else { 'a' });
        text
    };
    assert_eq!(login(&app, &password, "203.0.113.7").await.0, StatusCode::OK);

    // The first failures are free: ordinary mistyped passwords, answered 401 with the challenge.
    let free = davhaven_testkit::davhaven_ports::FailureBackoff::default().free;
    for attempt in 1..=free + 1 {
        let (status, retry_after) = login(&app, &wrong, "203.0.113.7").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "failure {attempt}");
        assert_eq!(retry_after, "", "no Retry-After for a plain refusal");
    }
    // The failure beyond the free ones blocked the login: 429, whatever is sent, the right password included.
    let (status, retry_after) = login(&app, &wrong, "203.0.113.7").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(retry_after, "1", "bounded by the first block of the backoff");
    assert_eq!(
        login(&app, &password, "203.0.113.7").await.0,
        StatusCode::TOO_MANY_REQUESTS,
        "no hard lockout, but nobody gets in while the block lasts"
    );
    // Another client is not blocked.
    assert_eq!(login(&app, &password, "198.51.100.9").await.0, StatusCode::OK);

    // The block ends; the right password works again, and the next failure blocks for twice as long.
    clock.advance(chrono::Duration::seconds(1));
    assert_eq!(login(&app, &password, "203.0.113.7").await.0, StatusCode::OK);
    assert_eq!(login(&app, &wrong, "203.0.113.7").await.0, StatusCode::UNAUTHORIZED);
    let (status, retry_after) = login(&app, &wrong, "203.0.113.7").await;
    assert_eq!((status, retry_after.as_str()), (StatusCode::TOO_MANY_REQUESTS, "2"));
    clock.advance(chrono::Duration::seconds(2));
    assert_eq!(login(&app, &password, "203.0.113.7").await.0, StatusCode::OK);
}

#[tokio::test]
async fn the_addresses_of_one_ipv6_prefix_share_their_failures() {
    let (app, _clock, password) = dav_edge().await;
    let wrong = format!("{password}x");
    // A client that rotates through the addresses of its /64 gets no fresh budget per address.
    let free = davhaven_testkit::davhaven_ports::FailureBackoff::default().free;
    for attempt in 0..=free {
        let from = format!("2001:db8:1:2:{attempt:x}::1");
        // A malformed password is no credential of ours at all (NotApplicable): it counts as a failure too.
        assert_eq!(login(&app, &wrong, &from).await.0, StatusCode::UNAUTHORIZED, "{from}");
    }
    let (status, retry_after) = login(&app, &wrong, "2001:db8:1:2:ffff::7").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "the whole /64 is blocked");
    assert_eq!(retry_after, "1");
    // Another prefix is another client.
    assert_eq!(login(&app, &password, "2001:db8:1:3::1").await.0, StatusCode::OK);
}
