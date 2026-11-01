//! The `Authenticator` implementation of the local credentials.
//!
//! [`LocalAuthenticator`] verifies app passwords, API tokens, feed tokens and RSVP tokens (PLAN 2.6). The flow for
//! one presented credential:
//!
//! 1. **Shape.** The credential must look like one of ours ([`crate::format`]). A value that carries no marker of
//!    ours is [`AuthOutcome::NotApplicable`], so another authenticator of the chain can try it; one that carries a
//!    marker but is malformed is refused.
//! 2. **Surface.** Credentials are bound to their surface: app passwords work on `dav`, API tokens on `api` and
//!    `mcp`, feed tokens and RSVP tokens on their pages. Anything else is refused as `WrongSurface`.
//! 3. **Lookup.** The credential row is found by its prefix, in **one system query** that also returns the status of
//!    the tenant and the principal and the names a login is compared with ([`LookedUpCredential`]). This is the only
//!    read of a request, whether the credential is new to the process or was verified a minute ago. An unknown
//!    prefix runs a dummy verification of the same cost as a real one, so response time does not tell which
//!    prefixes exist.
//! 4. **Secret.** The keyed hash of the secret is compared in constant time, unless the cache ([`crate::cache`])
//!    remembers that this very secret was verified against this very row (same credential, same stored hash, same
//!    credential generation of the principal) within `cache_ttl`. Only app passwords and principal tokens are
//!    remembered.
//! 5. **State.** The row decides, on every use: a credential is refused when it is revoked or expired, or when its
//!    tenant or principal is suspended or deleted **or cannot be found** (nothing is assumed active). Tokens whose
//!    row contradicts the token model (scopes their kind may not carry, `mcp:*` without an expiry) are refused too.
//!    Because the row is read every time, revoking one credential applies at once; it does not depend on anyone
//!    bumping the principal's `credential_generation`.
//! 6. **Names.** An app password is accepted only for the login of its owner: `name@login_domain`, or the bare name
//!    when the path names the tenant, which then means "this name in that tenant". The tenant named by a request
//!    path is otherwise **not** a condition of authentication: a valid credential of another tenant is
//!    authenticated, and the application answers 404 for the path (the resources of another tenant are invisible to
//!    it, R4, PLAN 2.6), without counting a failed authentication.
//!
//! Failed attempts are never cached. A successful use is noted so that `last_used_at` can be flushed in batches
//! at most every `last_used_flush` ([`LastUsedFlusher`], a worker whose `tick` tests call directly).
//!
//! **Re-hash on use.** A hash records the id of the pepper key that made it, and a key that is retired from the key
//! ring takes the credentials hashed under it along (`docs/operations/keys.md`). The plaintext of a credential is
//! known to the server only while a client presents it, so that is when a credential moves to the active key: after a
//! fresh verification (never after a cached one) of a credential whose hash names another key than the active one,
//! the secret is hashed again and [`CredentialSource::rehash`] swaps the two, once, compare-and-set on the old key id.
//! A credential that is used keeps itself current; the retired key can be removed when no live credential names it any
//! more. A failure to re-hash is logged and never fails the request, and the credential keeps verifying under its old
//! key for as long as that key stays configured. The verification that the cache remembers afterwards is the one of the
//! **new** hash, so the next request is answered from the cache.
//!
//! "The active key" is the one **this instance** was configured with. While a rolling change of
//! `security.active_key_id` is under way, instances that still name the old key move a used credential back to it, and
//! the ones that name the new key move it forward again: every move is a compare-and-set that succeeds, so credentials
//! that are used during the rollout can change keys more than once and each move writes a row and an `info` line.
//! That is harmless (both keys verify throughout) and ends when the rollout does; `docs/operations/keys.md` says to keep
//! the mixed state short.
//!
//! The authenticator reaches the store only through the small [`CredentialSource`] trait, which
//! [`DatabaseSource`] implements over the `Database` port.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use davhaven_domain::{
    Actor, ApiToken, Channel, CredentialKind, CredentialRef, PrincipalId, PrincipalName, PrincipalStatus, Scope,
    ScopeSet, TenantId, TenantStatus, TokenKind,
};
use davhaven_ports::{
    AuthHint, AuthOutcome, Authenticated, Authenticator, Clock, CredentialHasher, CredentialOwner, CredentialRecord,
    CredentialUse, Database, IdGenerator, KeyPurpose, KeyRing, LookedUpCredential, PortError, PortLabel,
    PresentedCredential, Rehash, RejectReason, StoreError, StoredHash, TxMode, WorkReport, Worker, observe,
};
use secrecy::{ExposeSecret as _, SecretString};
use tokio::sync::Mutex;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::cache::{Verified, VerifiedCache, headroom_target, shrink_to};
use crate::config::AuthConfig;
use crate::format::{TokenShape, parse_app_password, parse_token};

/// The label of the adapter in metrics and spans.
const LABEL: PortLabel = PortLabel::new("authenticator", crate::config::PLUGIN);

/// The most credentials the last-use debounce remembers. When it is full, entries that are due again go first, then
/// the oldest down to about nine tenths of this number, so the memory stays bounded however many credentials exist.
const MAX_RECENT: usize = 100_000;

// ---------------------------------------------------------------------------------------------------------------
// The source of credentials
// ---------------------------------------------------------------------------------------------------------------

/// Where the authenticator reads credentials from, and where it records uses.
#[async_trait]
pub trait CredentialSource: Send + Sync {
    /// The credential of `kind` with `prefix`, with the status of its tenant and principal and the names of both;
    /// `None` when there is none. One query answers everything the authenticator needs to know.
    async fn find(&self, kind: CredentialKind, prefix: &str) -> Result<Option<LookedUpCredential>, PortError>;

    /// Records uses of credentials of one tenant (`last_used_at`).
    async fn touch(&self, tenant: TenantId, uses: &[CredentialUse]) -> Result<(), PortError>;

    /// Replaces the hash of a credential of `tenant` with one under the active pepper key, if the stored hash still
    /// names `rehash.from_kid`; says whether a row changed. A source that cannot write hashes keeps the default,
    /// which changes nothing.
    async fn rehash(&self, tenant: TenantId, rehash: &Rehash) -> Result<bool, PortError> {
        let _ = (tenant, rehash);
        Ok(false)
    }
}

/// The [`CredentialSource`] over the `Database` port.
///
/// Every method opens one short transaction and closes it before it returns (a task never holds two, see the
/// documentation of the store port).
#[derive(Clone)]
pub struct DatabaseSource {
    database: Arc<dyn Database>,
}

impl core::fmt::Debug for DatabaseSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DatabaseSource").finish_non_exhaustive()
    }
}

impl DatabaseSource {
    /// A source that reads from `database`.
    pub fn new(database: Arc<dyn Database>) -> Self {
        Self { database }
    }
}

#[async_trait]
impl CredentialSource for DatabaseSource {
    async fn find(&self, kind: CredentialKind, prefix: &str) -> Result<Option<LookedUpCredential>, PortError> {
        let mut tx = self.database.begin_system().await?;
        let found = tx.credential_lookup().find_by_prefix(kind, prefix).await?;
        tx.commit().await?;
        Ok(found)
    }

    async fn touch(&self, tenant: TenantId, uses: &[CredentialUse]) -> Result<(), PortError> {
        let mut tx = self.database.begin(tenant, TxMode::ReadWrite).await?;
        tx.credentials().touch_last_used(uses).await?;
        Ok(tx.commit().await?)
    }

    async fn rehash(&self, tenant: TenantId, rehash: &Rehash) -> Result<bool, PortError> {
        let mut tx = self.database.begin(tenant, TxMode::ReadWrite).await?;
        let changed = swapped(tx.credentials().rehash(rehash).await)?;
        tx.commit().await?;
        Ok(changed)
    }
}

/// What the answer of the store to a re-hash means: a store without the method (`Unsupported`, the default of
/// `CredentialRepo::rehash`) keeps credentials under the key that made them, which is not worth a warning per use, so it
/// is "nothing changed"; every other failure is the store's.
fn swapped(answer: Result<bool, StoreError>) -> Result<bool, PortError> {
    match answer {
        Err(StoreError::Unsupported) => Ok(false),
        other => other.map_err(PortError::from),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Last use
// ---------------------------------------------------------------------------------------------------------------

#[derive(Debug, Default)]
struct LastUsedState {
    /// When a credential was last recorded (pending or flushed), to debounce.
    recent: HashMap<Uuid, DateTime<Utc>>,
    /// Uses waiting for the next flush, by tenant and credential.
    pending: HashMap<(TenantId, Uuid), CredentialUse>,
}

/// The uses of credentials that wait to be written.
///
/// A credential is noted at most once per flush interval, so a client that authenticates a hundred times a minute
/// costs one write per interval, not a hundred.
#[derive(Debug)]
pub struct LastUsed {
    interval: TimeDelta,
    max_recent: usize,
    state: Mutex<LastUsedState>,
}

impl LastUsed {
    fn new(interval: Duration, max_recent: usize) -> Self {
        Self {
            interval: TimeDelta::from_std(interval).unwrap_or(TimeDelta::MAX),
            max_recent: max_recent.max(1),
            state: Mutex::new(LastUsedState::default()),
        }
    }

    /// Notes a successful use at `now`.
    async fn note(&self, tenant: TenantId, credential: CredentialRef, now: DateTime<Utc>) {
        if !matches!(credential.kind, CredentialKind::AppPassword | CredentialKind::ApiToken) {
            return;
        }
        let mut state = self.state.lock().await;
        if state
            .recent
            .get(&credential.id)
            .is_some_and(|last| now.signed_duration_since(*last) < self.interval)
        {
            return;
        }
        if state.recent.len() >= self.max_recent {
            // Entries that are due again carry no information; if that is not enough, the oldest go, to a size that
            // leaves room for the next uses. Forgetting one only costs a second write of its `last_used_at`.
            let interval = self.interval;
            state
                .recent
                .retain(|_, last| now.signed_duration_since(*last) < interval);
            shrink_to(&mut state.recent, headroom_target(self.max_recent), |last| *last);
        }
        state.recent.insert(credential.id, now);
        state.pending.insert(
            (tenant, credential.id),
            CredentialUse {
                kind: credential.kind,
                id: credential.id,
                at: now,
            },
        );
    }

    /// Takes the uses that wait for a flush, grouped by tenant.
    async fn take(&self) -> HashMap<TenantId, Vec<CredentialUse>> {
        let mut state = self.state.lock().await;
        let mut grouped: HashMap<TenantId, Vec<CredentialUse>> = HashMap::new();
        for ((tenant, _), usage) in state.pending.drain() {
            grouped.entry(tenant).or_default().push(usage);
        }
        grouped
    }

    /// Puts uses back after a failed flush, keeping a newer use that arrived in the meantime.
    async fn requeue(&self, tenant: TenantId, uses: Vec<CredentialUse>) {
        let mut state = self.state.lock().await;
        for usage in uses {
            let slot = state.pending.entry((tenant, usage.id)).or_insert(usage);
            if slot.at < usage.at {
                *slot = usage;
            }
        }
    }

    /// How many credentials the debounce remembers.
    #[cfg(test)]
    async fn remembered(&self) -> usize {
        self.state.lock().await.recent.len()
    }
}

/// The worker that writes `last_used_at` in batches.
///
/// One pass takes what has been noted since the last pass and writes it with one transaction per tenant. A tenant
/// whose write fails is retried at the next pass; nothing is lost and nothing blocks authentication.
pub struct LastUsedFlusher {
    last_used: Arc<LastUsed>,
    source: Arc<dyn CredentialSource>,
    interval: Duration,
}

impl core::fmt::Debug for LastUsedFlusher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LastUsedFlusher")
            .field("interval", &self.interval)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl Worker for LastUsedFlusher {
    fn name(&self) -> &'static str {
        "auth_last_used"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    async fn tick(&self) -> WorkReport {
        let mut report = WorkReport::idle();
        for (tenant, uses) in self.last_used.take().await {
            let count = u32::try_from(uses.len()).unwrap_or(u32::MAX);
            match self.source.touch(tenant, &uses).await {
                Ok(()) => report.processed = report.processed.saturating_add(count),
                Err(error) => {
                    tracing::warn!(
                        target: "davhaven::auth",
                        error = %error,
                        credentials = count,
                        "writing last_used_at failed; the next pass retries"
                    );
                    report.failed = report.failed.saturating_add(count);
                    self.last_used.requeue(tenant, uses).await;
                }
            }
        }
        report
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Classification of presented credentials
// ---------------------------------------------------------------------------------------------------------------

/// A presented credential that has the shape of one of ours.
struct Parsed {
    kind: CredentialKind,
    prefix: String,
    secret: SecretString,
    /// The login of a Basic credential.
    login: Option<String>,
}

/// Whether credentials of `kind` are accepted on `channel`.
const fn accepted_on(kind: CredentialKind, channel: Channel) -> bool {
    matches!(
        (kind, channel),
        (CredentialKind::AppPassword, Channel::Dav)
            | (CredentialKind::ApiToken, Channel::Api | Channel::Mcp)
            | (CredentialKind::FeedToken, Channel::Feed)
            | (CredentialKind::RsvpToken, Channel::Rsvp)
    )
}

/// Reads a presented token as the kind the surface expects.
fn parse_expected_token(text: &str, expected: CredentialKind) -> Result<Parsed, AuthOutcome> {
    match parse_token(text) {
        TokenShape::Valid(token) if token.kind == expected => Ok(Parsed {
            kind: expected,
            prefix: token.prefix,
            secret: token.secret,
            login: None,
        }),
        TokenShape::Malformed(kind) if kind == expected => Err(AuthOutcome::Rejected(RejectReason::Malformed)),
        // A well-formed or marked token of another kind: valid somewhere else, not here.
        TokenShape::Valid(_) | TokenShape::Malformed(_) => Err(AuthOutcome::Rejected(RejectReason::WrongSurface)),
        TokenShape::Unrecognized => Err(AuthOutcome::NotApplicable),
    }
}

/// Classifies a presented credential: a shape of ours, or the outcome that ends the chain or passes it on.
fn classify(credential: &PresentedCredential) -> Result<Parsed, AuthOutcome> {
    match credential {
        PresentedCredential::Basic { username, password } => {
            let parsed = parse_app_password(password.expose_secret()).ok_or(AuthOutcome::NotApplicable)?;
            Ok(Parsed {
                kind: CredentialKind::AppPassword,
                prefix: parsed.prefix,
                secret: parsed.secret,
                login: Some(username.clone()),
            })
        }
        PresentedCredential::Bearer(token) => parse_expected_token(token.expose_secret(), CredentialKind::ApiToken),
        PresentedCredential::Feed(token) => parse_expected_token(token.expose_secret(), CredentialKind::FeedToken),
        PresentedCredential::Rsvp(token) => parse_expected_token(token.expose_secret(), CredentialKind::RsvpToken),
    }
}

/// Whether `login` (`name@login_domain`, or a bare name) is the login of the principal named by `owner`, on a request
/// whose path names the tenant `hint`.
///
/// A login with a domain names its tenant itself and does not care about the path. A bare name means "this name in
/// the tenant of the path", so it is a login of `owner` only where the path names exactly the owner's tenant.
fn login_matches(login: &str, owner: &CredentialOwner, hint: &AuthHint) -> bool {
    let login = login.trim();
    let (name, domain) = match login.rsplit_once('@') {
        Some((name, domain)) => (name, Some(domain)),
        None => (login, None),
    };
    let Ok(name) = PrincipalName::from_login(name) else {
        return false;
    };
    if owner.principal_name.as_ref() != Some(&name) {
        return false;
    }
    match domain {
        Some(domain) => {
            davhaven_domain::DomainName::parse(domain).is_ok_and(|domain| owner.login_domain.as_ref() == Some(&domain))
        }
        None => hint.tenant_hint.as_ref() == Some(&owner.tenant_slug),
    }
}

/// Whether a verified credential may be used for this request: an app password only for the login of its owner.
/// Every other kind is the credential of whoever holds it.
fn admits(parsed: &Parsed, found: &LookedUpCredential, hint: &AuthHint) -> bool {
    match parsed.kind {
        CredentialKind::AppPassword => match (&parsed.login, &found.owner) {
            (Some(login), Some(owner)) => login_matches(login, owner, hint),
            _ => false,
        },
        CredentialKind::ApiToken | CredentialKind::FeedToken | CredentialKind::RsvpToken => true,
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The identity a credential row stands for
// ---------------------------------------------------------------------------------------------------------------

/// Who a verified credential row acts as.
struct Subject {
    tenant: Option<TenantId>,
    principal: Option<PrincipalId>,
    actor: Actor,
    scopes: ScopeSet,
    credential: CredentialRef,
    label: Option<String>,
}

/// Whether an API token row agrees with the token model: the scopes its kind may carry, an expiry for `mcp:*`
/// scopes, a tenant for every kind but `system` and a principal for `principal` tokens.
fn token_is_consistent(token: &ApiToken) -> bool {
    let tenant_ok = (token.kind == TokenKind::System) == token.tenant_id.is_none();
    let principal_ok = (token.kind == TokenKind::Principal) == token.principal_id.is_some();
    let scopes_ok = token.scopes.first_not_allowed_for(token.kind).is_none()
        && (token.expires_at.is_some() || !token.scopes.iter().any(Scope::requires_expiry));
    tenant_ok && principal_ok && scopes_ok
}

/// The subject of a credential row.
fn subject_of(record: &CredentialRecord) -> Result<Subject, RejectReason> {
    Ok(match record {
        CredentialRecord::AppPassword(password) => Subject {
            tenant: Some(password.tenant_id),
            principal: Some(password.principal_id),
            actor: Actor::Principal(password.principal_id),
            scopes: ScopeSet::empty(),
            credential: CredentialRef::app_password(password.id),
            label: Some(password.label.clone()),
        },
        CredentialRecord::ApiToken(token) => {
            if !token_is_consistent(token) {
                return Err(RejectReason::Malformed);
            }
            let actor = match (token.kind, token.principal_id) {
                (TokenKind::System, _) => Actor::SystemToken(token.id),
                (TokenKind::Tenant, _) => Actor::TenantToken(token.id),
                (TokenKind::Principal, Some(principal)) => Actor::PrincipalToken {
                    principal,
                    token: token.id,
                },
                (TokenKind::Principal, None) => return Err(RejectReason::Malformed),
            };
            Subject {
                tenant: token.tenant_id,
                principal: token.principal_id,
                actor,
                scopes: token.scopes,
                credential: CredentialRef::api_token(token.id),
                label: Some(token.label.clone()),
            }
        }
        CredentialRecord::FeedToken(token) => Subject {
            tenant: Some(token.tenant_id),
            principal: Some(token.principal_id),
            actor: Actor::FeedReader {
                principal: token.principal_id,
                token: token.id,
            },
            scopes: ScopeSet::empty(),
            credential: CredentialRef::feed_token(token.id),
            label: None,
        },
        CredentialRecord::RsvpToken(token) => Subject {
            tenant: Some(token.tenant_id),
            principal: None,
            actor: Actor::RsvpAttendee {
                object: token.object_id,
                address: token.attendee_address.clone(),
            },
            scopes: ScopeSet::empty(),
            credential: CredentialRef::rsvp_token(token.id),
            label: None,
        },
    })
}

/// The hash and pepper key id stored in a credential row.
fn stored_hash_of(record: &CredentialRecord) -> StoredHash {
    let (hash, pepper_kid) = match record {
        CredentialRecord::AppPassword(row) => (&row.hash, &row.pepper_kid),
        CredentialRecord::ApiToken(row) => (&row.hash, &row.pepper_kid),
        CredentialRecord::FeedToken(row) => (&row.hash, &row.pepper_kid),
        CredentialRecord::RsvpToken(row) => (&row.hash, &row.pepper_kid),
    };
    StoredHash::new(record.kind(), pepper_kid.clone(), hash.clone())
}

/// Whether the tenant and the principal a credential belongs to are in service.
///
/// A credential whose subject names a tenant (or a principal) must find it active: a row the lookup did not find, a
/// join that came back empty, is **not** treated as active. Nothing is assumed.
fn in_standing(found: &LookedUpCredential, subject: &Subject) -> Result<(), RejectReason> {
    if subject.tenant.is_some() {
        match found.tenant_status {
            Some(TenantStatus::Active) => {}
            Some(_) => return Err(RejectReason::Suspended),
            None => return Err(RejectReason::UnknownCredential),
        }
    }
    if subject.principal.is_some() {
        match found.principal_status {
            Some(PrincipalStatus::Active) => {}
            Some(_) => return Err(RejectReason::Suspended),
            None => return Err(RejectReason::UnknownCredential),
        }
    }
    Ok(())
}

/// Why the state of the row refuses the credential at `now`, if it does: revoked or expired.
fn refusal(found: &LookedUpCredential, now: DateTime<Utc>) -> Option<RejectReason> {
    if found.record.revoked_at().is_some() {
        return Some(RejectReason::Revoked);
    }
    found
        .record
        .expires_at()
        .is_some_and(|expires| expires <= now)
        .then_some(RejectReason::Expired)
}

/// Whether a cached verification covers the row that was just read: the same credential with the same stored hash
/// under the same credential generation of the principal.
fn covers(verified: &Verified, found: &LookedUpCredential, stored: &StoredHash) -> bool {
    verified.credential.kind == found.record.kind()
        && verified.credential.id == found.record.id()
        && &verified.stored == stored
        && verified.generation == found.credential_generation
}

// ---------------------------------------------------------------------------------------------------------------
// The authenticator
// ---------------------------------------------------------------------------------------------------------------

/// Everything a [`LocalAuthenticator`] is built from.
pub struct LocalDeps {
    /// Where credentials are read from.
    pub source: Arc<dyn CredentialSource>,
    /// Verifies the keyed hashes of secrets.
    pub hasher: Arc<dyn CredentialHasher>,
    /// Keys the cache.
    pub keyring: Arc<dyn KeyRing>,
    /// Expiry and cache time.
    pub clock: Arc<dyn Clock>,
    /// The randomness of the dummy credentials.
    pub ids: Arc<dyn IdGenerator>,
}

/// The authenticator of app passwords and API, feed and RSVP tokens.
pub struct LocalAuthenticator {
    source: Arc<dyn CredentialSource>,
    hasher: Arc<dyn CredentialHasher>,
    keyring: Arc<dyn KeyRing>,
    clock: Arc<dyn Clock>,
    cache: VerifiedCache,
    last_used: Arc<LastUsed>,
    flush_interval: Duration,
    /// A hash of an unguessable secret per credential kind, verified against when no credential has the prefix.
    dummies: Vec<StoredHash>,
}

impl core::fmt::Debug for LocalAuthenticator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LocalAuthenticator").finish_non_exhaustive()
    }
}

impl LocalAuthenticator {
    /// Builds the authenticator.
    pub fn new(deps: LocalDeps, config: &AuthConfig) -> Self {
        Self::with_recent_limit(deps, config, MAX_RECENT)
    }

    /// [`LocalAuthenticator::new`] with another bound for the last-use debounce (tests use a small one).
    fn with_recent_limit(deps: LocalDeps, config: &AuthConfig, max_recent: usize) -> Self {
        let dummies = CredentialKind::ALL
            .iter()
            .map(|kind| {
                let noise: String = deps
                    .ids
                    .random_bytes(24)
                    .iter()
                    .map(|byte| char::from(b'a' + byte % 26))
                    .collect();
                deps.hasher.hash(*kind, &SecretString::from(noise))
            })
            .collect();
        Self {
            source: deps.source,
            hasher: deps.hasher,
            keyring: deps.keyring,
            clock: deps.clock,
            cache: VerifiedCache::new(config.cache_ttl, config.cache_max_entries),
            last_used: Arc::new(LastUsed::new(config.last_used_flush, max_recent)),
            flush_interval: config.last_used_flush,
            dummies,
        }
    }

    /// The worker that writes `last_used_at`; the server spawns it.
    pub fn flusher(&self) -> Arc<LastUsedFlusher> {
        Arc::new(LastUsedFlusher {
            last_used: Arc::clone(&self.last_used),
            source: Arc::clone(&self.source),
            interval: self.flush_interval,
        })
    }

    /// The key of the cache: an HMAC of the kind, the prefix and the presented secret, each part framed by a zero
    /// byte so that no two triples share an encoding. `None` for the credentials that are not cached, and when the
    /// key ring returns an empty MAC (which it never does): a key that is the same for everyone must not be used.
    fn cache_key(&self, parsed: &Parsed) -> Option<Vec<u8>> {
        if !matches!(parsed.kind, CredentialKind::AppPassword | CredentialKind::ApiToken) {
            return None;
        }
        let secret = parsed.secret.expose_secret().as_bytes();
        let mut framed = Zeroizing::new(Vec::with_capacity(secret.len() + parsed.prefix.len() + 24));
        framed.extend_from_slice(parsed.kind.as_str().as_bytes());
        framed.push(0);
        framed.extend_from_slice(parsed.prefix.as_bytes());
        framed.push(0);
        framed.extend_from_slice(secret);
        let mac = self.keyring.sign(KeyPurpose::CacheKey, &framed).mac;
        (!mac.is_empty()).then_some(mac)
    }

    /// Spends the time of one verification on a secret that matches nothing.
    fn dummy_verification(&self, kind: CredentialKind, secret: &SecretString) {
        let position = CredentialKind::ALL.iter().position(|candidate| *candidate == kind);
        if let Some(dummy) = position.and_then(|index| self.dummies.get(index)) {
            let _matched = self.hasher.verify(dummy, secret);
        }
    }

    /// Hashes `secret` again under the active pepper key and swaps the hash of the credential, when the stored hash
    /// was made under another key (see the module documentation). Best effort: a failure is logged and the credential
    /// keeps verifying under its old key.
    ///
    /// Returns the hash the row has now when this call moved it, so that the verification that is cached afterwards
    /// covers the row as it is; `None` when nothing changed.
    async fn rehash_on_use(
        &self,
        tenant: TenantId,
        credential: CredentialRef,
        stored: &StoredHash,
        secret: &SecretString,
    ) -> Option<StoredHash> {
        if stored.pepper_kid == self.keyring.active_kid(KeyPurpose::CredentialPepper) {
            return None;
        }
        let fresh = self.hasher.hash(stored.kind, secret);
        if fresh.pepper_kid == stored.pepper_kid {
            return None;
        }
        let swap = Rehash {
            credential,
            from_kid: stored.pepper_kid.clone(),
            to: fresh,
        };
        match self.source.rehash(tenant, &swap).await {
            Ok(true) => {
                tracing::info!(
                    target: "davhaven::auth",
                    kind = credential.kind.as_str(),
                    from = %swap.from_kid,
                    to = %swap.to.pepper_kid,
                    "a credential was moved to the active pepper key"
                );
                Some(swap.to)
            }
            Ok(false) => None,
            Err(error) => {
                tracing::warn!(
                    target: "davhaven::auth",
                    error = %error,
                    kind = credential.kind.as_str(),
                    "moving a credential to the active pepper key failed; it keeps verifying under its old key"
                );
                None
            }
        }
    }

    async fn authenticate_inner(
        &self,
        credential: &PresentedCredential,
        hint: &AuthHint,
    ) -> Result<AuthOutcome, PortError> {
        let parsed = match classify(credential) {
            Ok(parsed) => parsed,
            Err(outcome) => return Ok(outcome),
        };
        if !accepted_on(parsed.kind, hint.channel) {
            return Ok(AuthOutcome::Rejected(RejectReason::WrongSurface));
        }
        let now = self.clock.now();
        let cache_key = self.cache_key(&parsed);
        let cached = match &cache_key {
            Some(key) => self.cache.get(key, now).await,
            None => None,
        };

        // The one read of the request. A cached verification saves the check of the secret, never this lookup: the
        // state of the row decides, so revocations, suspensions and expiries apply on the very next request.
        let Some(found) = self.source.find(parsed.kind, &parsed.prefix).await? else {
            self.dummy_verification(parsed.kind, &parsed.secret);
            if let Some(key) = &cache_key {
                self.cache.remove(key).await;
            }
            return Ok(AuthOutcome::Rejected(RejectReason::UnknownCredential));
        };
        if found.record.kind() != parsed.kind {
            return Ok(AuthOutcome::Rejected(RejectReason::UnknownCredential));
        }
        let mut stored = stored_hash_of(&found.record);
        let known_good = cached
            .as_ref()
            .is_some_and(|verified| covers(verified, &found, &stored));
        if !known_good {
            if let Some(key) = cache_key.as_ref().filter(|_| cached.is_some()) {
                // The row changed under the cached verification: verify again, from scratch.
                self.cache.remove(key).await;
            }
            if !self.hasher.verify(&stored, &parsed.secret) {
                return Ok(AuthOutcome::Rejected(RejectReason::BadSecret));
            }
        }
        if let Some(reason) = refusal(&found, now) {
            return Ok(AuthOutcome::Rejected(reason));
        }
        let subject = match subject_of(&found.record) {
            Ok(subject) => subject,
            Err(reason) => return Ok(AuthOutcome::Rejected(reason)),
        };
        if let Err(reason) = in_standing(&found, &subject) {
            return Ok(AuthOutcome::Rejected(reason));
        }
        if !admits(&parsed, &found, hint) {
            return Ok(AuthOutcome::Rejected(RejectReason::UnknownCredential));
        }

        // A credential that verified under a retired pepper key moves to the active one (never after a cached
        // verification: the secret was not checked against the row just now).
        if let (false, Some(tenant)) = (known_good, subject.tenant)
            && let Some(moved) = self
                .rehash_on_use(tenant, subject.credential, &stored, &parsed.secret)
                .await
        {
            // The cached verification is of the hash the row has now.
            stored = moved;
        }

        // Only credentials of a principal are remembered, and only a verification that was just made.
        if let (Some(key), false, Some(_)) = (cache_key, known_good, subject.principal) {
            let verified = Verified {
                credential: subject.credential,
                stored,
                generation: found.credential_generation,
                expires_at: found.record.expires_at(),
            };
            self.cache.insert(key, verified, now).await;
        }
        if let Some(tenant) = subject.tenant {
            self.last_used.note(tenant, subject.credential, now).await;
        }
        Ok(AuthOutcome::Accepted(Authenticated {
            tenant: subject.tenant,
            actor: subject.actor,
            scopes: subject.scopes,
            credential: subject.credential,
            label: subject.label,
        }))
    }
}

#[async_trait]
impl Authenticator for LocalAuthenticator {
    async fn authenticate(&self, credential: &PresentedCredential, hint: &AuthHint) -> Result<AuthOutcome, PortError> {
        observe(LABEL, "authenticate", self.authenticate_inner(credential, hint)).await
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The second selectable implementation
// ---------------------------------------------------------------------------------------------------------------

/// An authenticator that recognises no credential: every answer is [`AuthOutcome::NotApplicable`].
///
/// It is the safe second implementation of the `authenticator` kind: a chain made of it alone authenticates nobody,
/// and as a placeholder in a longer chain it passes everything on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoopAuthenticator;

#[async_trait]
impl Authenticator for NoopAuthenticator {
    async fn authenticate(
        &self,
        _credential: &PresentedCredential,
        _hint: &AuthHint,
    ) -> Result<AuthOutcome, PortError> {
        Ok(AuthOutcome::NotApplicable)
    }
}

#[cfg(test)]
mod tests;
