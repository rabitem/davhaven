//! The RSVP link of an invitation.
//!
//! Every invitation mail carries a link to the RSVP page (`/rsvp/dvh_rsvp_{prefix12}_{secret43}`). The token has
//! the format of every other credential (PLAN 2.6): the *prefix* finds the row, and the row stores the keyed hash
//! of the *secret* only (`CredentialHasher::hash(RsvpToken, secret)`), which is exactly what the authenticator of
//! the web surface verifies. A link that is minted here therefore authenticates there without any special case.
//!
//! # Derived, not random
//!
//! A retried send has to carry the same link as the first attempt, and an update mail has to carry the link of
//! the invitation, but the outbox keeps no rendered content and the row keeps no plaintext. So prefix and secret
//! are *derived* from the key ring instead of drawn at random: both are a keyed function of the tenant and the
//! token id (HMAC with the `rsvp` key), unpredictable without the key and recomputable from the stored row. This
//! deviates from "random, shown once" (`ENGINEERING_RULES` R6). The deviation is recorded in ADR 0007
//! (`docs/adr/0007-derived-rsvp-tokens.md`): the `rsvp` key is as sensitive as the pepper, and a leak of the key
//! together with the ids of the token rows lets an attacker recompute links.
//!
//! # Which token an invitation uses
//!
//! The newest live token of the attendee for the object is reused when it still matches its derivation (so the
//! key ring has not been rotated since) and outlives the event. Anything else mints a **new** token and leaves the
//! old ones alone: links in mails that were sent earlier keep working until their own expiry (a rotation of the
//! key ring or a reschedule never silently kills them), and removing the attendee, cancelling or deleting the
//! event revokes all of them (`RsvpRepo::revoke_for_attendee`, `revoke_for_object`).
//!
//! # Expiry
//!
//! A link expires seven days after the last instance of the event ended, at most a year after it was minted. The
//! test whether a token is still good compares against a bound that does not move with the clock: the end of the
//! event plus the grace period, capped at the token's own creation time plus a year. An event without an end
//! therefore keeps its token for the whole year instead of getting a fresh one on every send.

use chrono::{DateTime, Duration, Utc};
use davhaven_domain::credential_format::TOKEN_PREFIX_RANDOM_BYTES;
use davhaven_domain::{CalendarUserAddress, CredentialKind, RsvpToken, StoredObject, TenantId, TokenId, TokenText};
use davhaven_ports::{KeyPurpose, KeyRing, StoreError, StoredHash, Tx};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};

use crate::wiring::AppCore;

/// How long an RSVP link stays valid after the last instance of the event ended.
const GRACE_DAYS: i64 = 7;

/// The longest validity of a link, whatever the event says (events without an end included).
const MAX_DAYS: i64 = 365;

/// How often a prefix collision is retried with a fresh id (a collision has a chance of about 2^-60).
const ATTEMPTS: u32 = 3;

/// The parts of a token: the prefix that finds the row and the secret that is hashed.
pub(crate) struct Parts {
    pub(crate) prefix: String,
    pub(crate) secret: SecretString,
}

impl Parts {
    /// The whole token as it appears in the link, in the format that `davhaven_domain::credential_format` defines
    /// and every authenticator verifies.
    pub(crate) fn token(&self) -> SecretString {
        match TokenText::from_parts(CredentialKind::RsvpToken, &self.prefix, self.secret.expose_secret()) {
            Some(token) => SecretString::from(token.expose().as_str()),
            // Parts that `derive` made always have the shape; an empty link is what any other parts get.
            None => SecretString::from(String::new()),
        }
    }
}

/// The prefix and the secret derived for token `id`.
///
/// The bytes of the keyed MACs become a token through `TokenText::from_random`, the one definition of the formats:
/// 8 bytes make the prefix, 32 bytes the 43 character secret. (This is bit for bit what the derivation produced
/// before the format moved to the domain, so links that were mailed earlier keep working.)
pub(crate) fn derive(keyring: &dyn KeyRing, tenant: TenantId, id: TokenId) -> Parts {
    let label = |part: &str| format!("davhaven/rsvp-token/v1/{part}/{tenant}/{id}");
    let prefix_mac = keyring.sign(KeyPurpose::Rsvp, label("prefix").as_bytes()).mac;
    let secret_mac = keyring.sign(KeyPurpose::Rsvp, label("secret").as_bytes()).mac;
    // Whatever the length of the MAC, a SHA-256 digest of it has the 32 bytes that the token needs.
    let prefix_digest = Sha256::digest(&prefix_mac);
    let secret_digest = Sha256::digest(&secret_mac);
    let token = TokenText::from_random(
        CredentialKind::RsvpToken,
        prefix_digest.get(..TOKEN_PREFIX_RANDOM_BYTES).unwrap_or_default(),
        secret_digest.as_slice(),
    );
    token.map_or_else(
        || Parts {
            prefix: String::new(),
            secret: SecretString::from(String::new()),
        },
        |token| Parts {
            prefix: token.prefix().to_owned(),
            secret: SecretString::from(token.secret()),
        },
    )
}

/// When the link of a token minted at `now` for `object` expires: seven days after the last instance ended, at
/// most a year from `now`.
pub(crate) fn expiry(object: &StoredObject, now: DateTime<Utc>) -> DateTime<Utc> {
    let horizon = now + Duration::days(MAX_DAYS);
    let end = object.last_end.unwrap_or(horizon).max(now);
    (end + Duration::days(GRACE_DAYS)).min(horizon)
}

/// The latest expiry `object` can ask of a token that was minted at `created`. It depends on the event and on the
/// token, never on the clock, so a token that was good when it was minted stays good while nothing changes.
fn wanted(object: &StoredObject, created: DateTime<Utc>) -> DateTime<Utc> {
    let cap = created + Duration::days(MAX_DAYS);
    object
        .last_end
        .map_or(cap, |end| (end + Duration::days(GRACE_DAYS)).min(cap))
}

/// Whether `token` can be used for the mail about `object` at `now`: it is live, matches its derivation and
/// outlives the event.
fn reusable(core: &AppCore, token: &RsvpToken, object: &StoredObject, now: DateTime<Utc>) -> Option<SecretString> {
    if token.revoked_at.is_some() || token.expires_at <= now || token.expires_at < wanted(object, token.created_at) {
        return None;
    }
    let deps = core.deps();
    let parts = derive(deps.keyring.as_ref(), token.tenant_id, token.id);
    let stored = StoredHash::new(CredentialKind::RsvpToken, token.pepper_kid.clone(), token.hash.clone());
    (token.prefix == parts.prefix && deps.hasher.verify(&stored, &parts.secret)).then(|| parts.token())
}

/// The token of `attendee` for the invitation `object`: the newest live one when it is still good, a new one
/// otherwise. Returns the whole token string for the link.
///
/// # Errors
///
/// Store failures; a prefix collision is retried with a fresh id first.
pub(crate) async fn link_token(
    core: &AppCore,
    tx: &mut dyn Tx,
    object: &StoredObject,
    attendee: &CalendarUserAddress,
) -> Result<SecretString, StoreError> {
    let deps = core.deps();
    let now = deps.clock.now();
    // The tokens come in id order, which is the order they were minted in.
    let newest = tx
        .rsvp()
        .for_object(object.id)
        .await?
        .into_iter()
        .rfind(|token| &token.attendee_address == attendee && token.revoked_at.is_none() && token.expires_at > now);
    if let Some(token) = newest.as_ref().and_then(|token| reusable(core, token, object, now)) {
        return Ok(token);
    }
    for attempt in 1..=ATTEMPTS {
        let id = TokenId::from_uuid(deps.ids.new_id());
        let parts = derive(deps.keyring.as_ref(), object.tenant_id, id);
        let hashed = deps.hasher.hash(CredentialKind::RsvpToken, &parts.secret);
        let row = RsvpToken {
            id,
            tenant_id: object.tenant_id,
            object_id: object.id,
            attendee_address: attendee.clone(),
            prefix: parts.prefix.clone(),
            hash: hashed.hash,
            pepper_kid: hashed.pepper_kid,
            expires_at: expiry(object, now),
            revoked_at: None,
            last_used_at: None,
            last_response: None,
            created_at: now,
            updated_at: now,
            version: 1,
        };
        match tx.rsvp().create(row).await {
            Ok(_) => return Ok(parts.token()),
            Err(StoreError::UniqueViolation(_)) if attempt < ATTEMPTS => {}
            Err(error) => return Err(error),
        }
    }
    Err(StoreError::internal("no free RSVP token prefix"))
}

#[cfg(test)]
mod tests;
