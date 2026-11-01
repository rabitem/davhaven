//! Credentials: app passwords, API tokens, feed tokens and RSVP tokens.
//!
//! Only keyed hashes are stored. Revoking stamps `revoked_at` and keeps the row, so a later use of the revoked
//! credential is recognised instead of looking like an unknown one; the first revocation time is kept. Prefixes
//! are unique across the installation (tenants and system tokens), as the credential lookup needs.

use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::{
    ApiToken, AppPassword, CalendarId, CalendarUserAddress, CredentialId, CredentialKind, FeedToken, ObjectId,
    PartStat, PrincipalId, RsvpToken, TokenId, TokenKind,
};
use davhaven_ports::store::ApiTokenFilter;
use davhaven_ports::{CredentialRepo, CredentialUse, PageReq, Rehash, RsvpRepo, StoreError, StorePage, UniqueKey};
use uuid::Uuid;

use super::{micros, misuse, no_nul, paginate};
use crate::state::State;
use crate::tx::MemTx;

/// Whether a prefix is taken by an app password of any tenant.
pub(super) fn app_prefix_taken(state: &State, prefix: &str) -> bool {
    state.tenants.values().any(|entry| {
        entry
            .data
            .app_passwords
            .values()
            .any(|password| password.prefix == prefix)
    })
}

/// Whether a prefix is taken by an API token of any tenant or by a system token.
pub(super) fn token_prefix_taken(state: &State, prefix: &str) -> bool {
    state.system_tokens.values().any(|token| token.prefix == prefix)
        || state
            .tenants
            .values()
            .any(|entry| entry.data.api_tokens.values().any(|token| token.prefix == prefix))
}

/// Whether a prefix is taken by a feed token of any tenant.
fn feed_prefix_taken(state: &State, prefix: &str) -> bool {
    state
        .tenants
        .values()
        .any(|entry| entry.data.feed_tokens.values().any(|token| token.prefix == prefix))
}

/// Whether a prefix is taken by an RSVP token of any tenant.
fn rsvp_prefix_taken(state: &State, prefix: &str) -> bool {
    state
        .tenants
        .values()
        .any(|entry| entry.data.rsvp_tokens.values().any(|token| token.prefix == prefix))
}

/// Stamps a revocation unless the credential is revoked already.
fn revoke(
    revoked_at: &mut Option<DateTime<Utc>>,
    updated_at: &mut DateTime<Utc>,
    version: &mut i64,
    now: DateTime<Utc>,
) {
    if revoked_at.is_none() {
        *revoked_at = Some(now);
        *updated_at = now;
        *version += 1;
    }
}

#[async_trait]
impl CredentialRepo for MemTx {
    async fn create_app_password(&mut self, password: AppPassword) -> Result<AppPassword, StoreError> {
        observed!("credentials.create_app_password", {
            no_nul("credential label", [Some(password.label.as_str())])?;
            let now = self.now();
            let tenant = self.tenant;
            if app_prefix_taken(&self.guard, &password.prefix) {
                return Err(StoreError::UniqueViolation(UniqueKey::CredentialPrefix));
            }
            let data = self.writable()?;
            if !data.principals.contains_key(&password.principal_id) {
                return Err(StoreError::NotFound);
            }
            if data.app_passwords.contains_key(&password.id) {
                return Err(misuse("an app password with this id exists already"));
            }
            let stored = AppPassword {
                tenant_id: tenant,
                last_used_at: password.last_used_at.map(micros),
                revoked_at: password.revoked_at.map(micros),
                created_at: now,
                updated_at: now,
                version: 1,
                ..password
            };
            data.app_passwords.insert(stored.id, stored.clone());
            Ok(stored)
        })
    }

    async fn get_app_password(&mut self, id: CredentialId) -> Result<AppPassword, StoreError> {
        observed!(
            "credentials.get_app_password",
            self.view().app_passwords.get(&id).cloned().ok_or(StoreError::NotFound)
        )
    }

    async fn list_app_passwords(&mut self, principal: PrincipalId) -> Result<Vec<AppPassword>, StoreError> {
        observed!(
            "credentials.list_app_passwords",
            Ok(self
                .view()
                .app_passwords
                .values()
                .filter(|password| password.principal_id == principal)
                .cloned()
                .collect())
        )
    }

    async fn revoke_app_password(&mut self, id: CredentialId) -> Result<(), StoreError> {
        observed!("credentials.revoke_app_password", {
            let now = self.now();
            let stored = self
                .writable()?
                .app_passwords
                .get_mut(&id)
                .ok_or(StoreError::NotFound)?;
            revoke(&mut stored.revoked_at, &mut stored.updated_at, &mut stored.version, now);
            Ok(())
        })
    }

    async fn create_api_token(&mut self, token: ApiToken) -> Result<ApiToken, StoreError> {
        observed!("credentials.create_api_token", {
            no_nul(
                "token text",
                token
                    .allowed_origins
                    .iter()
                    .map(|origin| Some(origin.as_str()))
                    .chain([Some(token.label.as_str())]),
            )?;
            if token.kind == TokenKind::System {
                return Err(misuse("system tokens are created through the credential lookup"));
            }
            let now = self.now();
            let tenant = self.tenant;
            if token_prefix_taken(&self.guard, &token.prefix) {
                return Err(StoreError::UniqueViolation(UniqueKey::CredentialPrefix));
            }
            let creator_known = token.created_by.is_none_or(|creator| {
                self.guard.system_tokens.contains_key(&creator)
                    || self
                        .guard
                        .tenants
                        .values()
                        .any(|entry| entry.data.api_tokens.contains_key(&creator))
            });
            let data = self.writable()?;
            if token
                .principal_id
                .is_some_and(|principal| !data.principals.contains_key(&principal))
                || !creator_known
            {
                return Err(StoreError::NotFound);
            }
            if data.api_tokens.contains_key(&token.id) {
                return Err(misuse("an API token with this id exists already"));
            }
            let stored = ApiToken {
                tenant_id: Some(tenant),
                expires_at: token.expires_at.map(micros),
                last_used_at: token.last_used_at.map(micros),
                revoked_at: token.revoked_at.map(micros),
                created_at: now,
                updated_at: now,
                version: 1,
                ..token
            };
            data.api_tokens.insert(stored.id, stored.clone());
            Ok(stored)
        })
    }

    async fn get_api_token(&mut self, id: TokenId) -> Result<ApiToken, StoreError> {
        observed!(
            "credentials.get_api_token",
            self.view().api_tokens.get(&id).cloned().ok_or(StoreError::NotFound)
        )
    }

    async fn list_api_tokens(
        &mut self,
        filter: &ApiTokenFilter,
        page: PageReq,
    ) -> Result<StorePage<ApiToken>, StoreError> {
        observed!("credentials.list_api_tokens", {
            let matching = self.view().api_tokens.values().filter(|token| {
                filter
                    .principal
                    .is_none_or(|principal| token.principal_id == Some(principal))
                    && filter.kind.is_none_or(|kind| token.kind == kind)
                    && (filter.include_revoked || token.revoked_at.is_none())
            });
            Ok(paginate(matching.cloned(), &page, |token| token.id.as_uuid()))
        })
    }

    async fn revoke_api_token(&mut self, id: TokenId) -> Result<(), StoreError> {
        observed!("credentials.revoke_api_token", {
            let now = self.now();
            let stored = self.writable()?.api_tokens.get_mut(&id).ok_or(StoreError::NotFound)?;
            revoke(&mut stored.revoked_at, &mut stored.updated_at, &mut stored.version, now);
            Ok(())
        })
    }

    async fn create_feed_token(&mut self, token: FeedToken) -> Result<FeedToken, StoreError> {
        observed!("credentials.create_feed_token", {
            let now = self.now();
            let tenant = self.tenant;
            if feed_prefix_taken(&self.guard, &token.prefix) {
                return Err(StoreError::UniqueViolation(UniqueKey::CredentialPrefix));
            }
            let data = self.writable()?;
            let calendars: BTreeSet<CalendarId> = token.calendar_ids.iter().copied().collect();
            if !data.principals.contains_key(&token.principal_id)
                || calendars.iter().any(|calendar| !data.calendar_is_live(*calendar))
            {
                return Err(StoreError::NotFound);
            }
            if data.feed_tokens.contains_key(&token.id) {
                return Err(misuse("a feed token with this id exists already"));
            }
            let stored = FeedToken {
                tenant_id: tenant,
                revoked_at: token.revoked_at.map(micros),
                created_at: now,
                updated_at: now,
                version: 1,
                ..token
            };
            data.feed_tokens.insert(stored.id, stored.clone());
            Ok(stored)
        })
    }

    async fn get_feed_token(&mut self, id: TokenId) -> Result<FeedToken, StoreError> {
        observed!(
            "credentials.get_feed_token",
            self.view().feed_tokens.get(&id).cloned().ok_or(StoreError::NotFound)
        )
    }

    async fn list_feed_tokens(&mut self, principal: PrincipalId) -> Result<Vec<FeedToken>, StoreError> {
        observed!(
            "credentials.list_feed_tokens",
            Ok(self
                .view()
                .feed_tokens
                .values()
                .filter(|token| token.principal_id == principal)
                .cloned()
                .collect())
        )
    }

    async fn revoke_feed_token(&mut self, id: TokenId) -> Result<(), StoreError> {
        observed!("credentials.revoke_feed_token", {
            let now = self.now();
            let stored = self.writable()?.feed_tokens.get_mut(&id).ok_or(StoreError::NotFound)?;
            revoke(&mut stored.revoked_at, &mut stored.updated_at, &mut stored.version, now);
            Ok(())
        })
    }

    async fn revoke_all_for_principal(&mut self, principal: PrincipalId) -> Result<u64, StoreError> {
        observed!("credentials.revoke_all_for_principal", {
            let now = self.now();
            let data = self.writable()?;
            let mut revoked = 0_u64;
            for password in data
                .app_passwords
                .values_mut()
                .filter(|password| password.principal_id == principal)
            {
                if password.revoked_at.is_none() {
                    revoke(
                        &mut password.revoked_at,
                        &mut password.updated_at,
                        &mut password.version,
                        now,
                    );
                    revoked += 1;
                }
            }
            for token in data
                .api_tokens
                .values_mut()
                .filter(|token| token.principal_id == Some(principal) && token.kind == TokenKind::Principal)
            {
                if token.revoked_at.is_none() {
                    revoke(&mut token.revoked_at, &mut token.updated_at, &mut token.version, now);
                    revoked += 1;
                }
            }
            for token in data
                .feed_tokens
                .values_mut()
                .filter(|token| token.principal_id == principal)
            {
                if token.revoked_at.is_none() {
                    revoke(&mut token.revoked_at, &mut token.updated_at, &mut token.version, now);
                    revoked += 1;
                }
            }
            Ok(revoked)
        })
    }

    async fn touch_last_used(&mut self, uses: &[CredentialUse]) -> Result<u64, StoreError> {
        observed!("credentials.touch_last_used", {
            let mut latest: BTreeMap<(CredentialKind, Uuid), DateTime<Utc>> = BTreeMap::new();
            for used in uses {
                let at = micros(used.at);
                latest
                    .entry((used.kind, used.id))
                    .and_modify(|seen| *seen = (*seen).max(at))
                    .or_insert(at);
            }
            let data = self.writable()?;
            let mut changed = 0_u64;
            for ((kind, id), at) in latest {
                let slot = match kind {
                    CredentialKind::AppPassword => data
                        .app_passwords
                        .get_mut(&CredentialId::from_uuid(id))
                        .map(|password| &mut password.last_used_at),
                    CredentialKind::ApiToken => data
                        .api_tokens
                        .get_mut(&TokenId::from_uuid(id))
                        .map(|token| &mut token.last_used_at),
                    CredentialKind::RsvpToken => data
                        .rsvp_tokens
                        .get_mut(&TokenId::from_uuid(id))
                        .map(|token| &mut token.last_used_at),
                    CredentialKind::FeedToken => None,
                };
                if let Some(slot) = slot
                    && slot.is_none_or(|stored| stored < at)
                {
                    *slot = Some(at);
                    changed += 1;
                }
            }
            Ok(changed)
        })
    }

    async fn rehash(&mut self, rehash: &Rehash) -> Result<bool, StoreError> {
        observed!("credentials.rehash", {
            let data = self.writable()?;
            let id = rehash.credential.id;
            let slot = match rehash.credential.kind {
                CredentialKind::AppPassword => data
                    .app_passwords
                    .get_mut(&CredentialId::from_uuid(id))
                    .map(|password| (&mut password.hash, &mut password.pepper_kid)),
                CredentialKind::ApiToken => data
                    .api_tokens
                    .get_mut(&TokenId::from_uuid(id))
                    .map(|token| (&mut token.hash, &mut token.pepper_kid)),
                CredentialKind::FeedToken => data
                    .feed_tokens
                    .get_mut(&TokenId::from_uuid(id))
                    .map(|token| (&mut token.hash, &mut token.pepper_kid)),
                CredentialKind::RsvpToken => data
                    .rsvp_tokens
                    .get_mut(&TokenId::from_uuid(id))
                    .map(|token| (&mut token.hash, &mut token.pepper_kid)),
            };
            match slot {
                Some((hash, pepper_kid)) if *pepper_kid == rehash.from_kid => {
                    hash.clone_from(&rehash.to.hash);
                    pepper_kid.clone_from(&rehash.to.pepper_kid);
                    Ok(true)
                }
                _ => Ok(false),
            }
        })
    }
}

#[async_trait]
impl RsvpRepo for MemTx {
    async fn create(&mut self, token: RsvpToken) -> Result<RsvpToken, StoreError> {
        observed!("rsvp.create", {
            let now = self.now();
            let tenant = self.tenant;
            if rsvp_prefix_taken(&self.guard, &token.prefix) {
                return Err(StoreError::UniqueViolation(UniqueKey::CredentialPrefix));
            }
            let data = self.writable()?;
            if !data.objects.contains_key(&token.object_id) {
                return Err(StoreError::NotFound);
            }
            if data.rsvp_tokens.contains_key(&token.id) {
                return Err(misuse("an RSVP token with this id exists already"));
            }
            let stored = RsvpToken {
                tenant_id: tenant,
                expires_at: micros(token.expires_at),
                revoked_at: token.revoked_at.map(micros),
                last_used_at: token.last_used_at.map(micros),
                created_at: now,
                updated_at: now,
                version: 1,
                ..token
            };
            data.rsvp_tokens.insert(stored.id, stored.clone());
            Ok(stored)
        })
    }

    async fn get(&mut self, id: TokenId) -> Result<RsvpToken, StoreError> {
        observed!(
            "rsvp.get",
            self.view().rsvp_tokens.get(&id).cloned().ok_or(StoreError::NotFound)
        )
    }

    async fn for_object(&mut self, object: ObjectId) -> Result<Vec<RsvpToken>, StoreError> {
        observed!(
            "rsvp.for_object",
            Ok(self
                .view()
                .rsvp_tokens
                .values()
                .filter(|token| token.object_id == object)
                .cloned()
                .collect())
        )
    }

    async fn find_live(
        &mut self,
        object: ObjectId,
        address: &CalendarUserAddress,
    ) -> Result<Option<RsvpToken>, StoreError> {
        observed!(
            "rsvp.find_live",
            Ok(self
                .view()
                .rsvp_tokens
                .values()
                .find(|token| {
                    token.object_id == object && &token.attendee_address == address && token.revoked_at.is_none()
                })
                .cloned())
        )
    }

    async fn record_use(&mut self, id: TokenId, response: Option<PartStat>) -> Result<(), StoreError> {
        observed!("rsvp.record_use", {
            let now = self.now();
            let stored = self.writable()?.rsvp_tokens.get_mut(&id).ok_or(StoreError::NotFound)?;
            stored.last_used_at = Some(now);
            if response.is_some() {
                stored.last_response = response;
            }
            stored.updated_at = now;
            stored.version += 1;
            Ok(())
        })
    }

    async fn revoke(&mut self, id: TokenId) -> Result<(), StoreError> {
        observed!("rsvp.revoke", {
            let now = self.now();
            let stored = self.writable()?.rsvp_tokens.get_mut(&id).ok_or(StoreError::NotFound)?;
            revoke(&mut stored.revoked_at, &mut stored.updated_at, &mut stored.version, now);
            Ok(())
        })
    }

    async fn revoke_for_object(&mut self, object: ObjectId) -> Result<u64, StoreError> {
        observed!("rsvp.revoke_for_object", {
            let now = self.now();
            let data = self.writable()?;
            Ok(revoke_matching(data.rsvp_tokens.values_mut(), now, |token| {
                token.object_id == object
            }))
        })
    }

    async fn revoke_for_attendee(
        &mut self,
        object: ObjectId,
        address: &CalendarUserAddress,
    ) -> Result<u64, StoreError> {
        observed!("rsvp.revoke_for_attendee", {
            let now = self.now();
            let data = self.writable()?;
            Ok(revoke_matching(data.rsvp_tokens.values_mut(), now, |token| {
                token.object_id == object && &token.attendee_address == address
            }))
        })
    }

    async fn revoke_for_address(&mut self, address: &CalendarUserAddress) -> Result<u64, StoreError> {
        observed!("rsvp.revoke_for_address", {
            let now = self.now();
            let data = self.writable()?;
            Ok(revoke_matching(data.rsvp_tokens.values_mut(), now, |token| {
                &token.attendee_address == address
            }))
        })
    }
}

/// Revokes the not yet revoked tokens that match and returns how many were revoked.
fn revoke_matching<'a>(
    tokens: impl Iterator<Item = &'a mut RsvpToken>,
    now: DateTime<Utc>,
    matches: impl Fn(&RsvpToken) -> bool,
) -> u64 {
    let mut revoked = 0;
    for token in tokens {
        if token.revoked_at.is_none() && matches(token) {
            revoke(&mut token.revoked_at, &mut token.updated_at, &mut token.version, now);
            revoked += 1;
        }
    }
    revoked
}
