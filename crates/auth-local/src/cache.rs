//! The verified-credential cache.
//!
//! DAV clients poll, so the same app password arrives many times a minute. Authentication remembers *that a secret
//! was verified* against a credential row for `cache_ttl` (5 minutes), under a key that is an HMAC of the kind, the
//! prefix and the presented secret (`KeyPurpose::CacheKey`): the secret itself is never kept, and the keyed hash is
//! useless without the key ring. What a hit saves is the verification of the secret (the call of the
//! `CredentialHasher`, which a slower hasher than today's HMAC would make expensive). It does **not** save the
//! lookup: every use reads the credential row, with the status of its tenant and principal and the names a login is
//! compared with, in one system query, so the state of the row decides, not the memory of the cache:
//!
//! * revoking one credential, suspending a principal or a tenant, deleting a principal and every expiry apply on the
//!   very next request, whether or not anything bumped the principal's `credential_generation`;
//! * a cached verification covers exactly the row it was made for: the same credential id and the same stored hash.
//!   A row that changed under the same prefix is verified again; so is every credential after a bump of the
//!   principal's `credential_generation` (the generation is part of what a cached entry remembers);
//! * **only successes are cached.** A refusal is decided afresh every time, so a password that was wrong and a
//!   token that expired never turn into something stale;
//! * **an entry never outlives its credential**: it is valid until the earlier of the TTL and the credential's own
//!   expiry;
//! * only credentials of a principal are cached (app passwords and principal tokens); tenant and system tokens,
//!   feed tokens and RSVP tokens are verified every time;
//! * the table is capped. When it is full, expired entries go first, then the least recently used ones down to about
//!   nine tenths of the cap, so the sweep is not repeated for every insert.
//!
//! The cache is per process and holds no secret.

use std::collections::HashMap;
use std::hash::Hash;

use chrono::{DateTime, TimeDelta, Utc};
use davhaven_domain::CredentialRef;
use davhaven_ports::StoredHash;
use tokio::sync::Mutex;

/// What the authenticator remembers of a verified credential.
#[derive(Debug, Clone, PartialEq)]
pub struct Verified {
    /// The credential the secret was verified against.
    pub credential: CredentialRef,
    /// The hash of that row: a row with another hash (a replaced credential under the same prefix) is not covered.
    pub stored: StoredHash,
    /// The credential generation of the principal at that time; another generation is not covered.
    pub generation: Option<i32>,
    /// When the credential expires, if it can.
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
struct Entry {
    verified: Verified,
    valid_until: DateTime<Utc>,
    /// When the entry was last used, for the eviction of the least recently used.
    used_at: DateTime<Utc>,
}

/// The size a table of `max` entries is cut back to when it is full: about nine tenths, never less than one slot
/// free. Cutting back by a tenth at once gives the next inserts headroom, so a full table does not sweep (and sort)
/// itself for every new key.
pub(crate) fn headroom_target(max: usize) -> usize {
    max.saturating_sub((max / 10).max(1))
}

/// Drops the entries with the smallest `age` until `keep` remain.
pub(crate) fn shrink_to<K, V, A>(map: &mut HashMap<K, V>, keep: usize, age: impl Fn(&V) -> A)
where
    K: Eq + Hash + Clone,
    A: Ord,
{
    if map.len() <= keep {
        return;
    }
    let mut order: Vec<(A, K)> = map.iter().map(|(key, value)| (age(value), key.clone())).collect();
    order.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    let surplus = map.len() - keep;
    for (_, key) in order.into_iter().take(surplus) {
        map.remove(&key);
    }
}

/// A bounded cache of verified credentials with a time to live.
#[derive(Debug)]
pub struct VerifiedCache {
    ttl: TimeDelta,
    max_entries: usize,
    entries: Mutex<HashMap<Vec<u8>, Entry>>,
}

impl VerifiedCache {
    /// A cache whose entries live `ttl`, holding at most `max_entries` of them.
    pub fn new(ttl: core::time::Duration, max_entries: usize) -> Self {
        Self {
            ttl: TimeDelta::from_std(ttl).unwrap_or(TimeDelta::MAX),
            max_entries: max_entries.max(1),
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// The entry stored under `key`, unless it has expired at `now` (an expired entry is removed). A hit counts as a
    /// use for the eviction of the least recently used.
    pub async fn get(&self, key: &[u8], now: DateTime<Utc>) -> Option<Verified> {
        let mut entries = self.entries.lock().await;
        match entries.get_mut(key) {
            Some(entry) if entry.valid_until > now => {
                entry.used_at = now;
                Some(entry.verified.clone())
            }
            Some(_) => {
                entries.remove(key);
                None
            }
            None => None,
        }
    }

    /// Stores a verified credential under `key` at `now`; it is valid until the TTL has passed or the credential
    /// expires, whichever comes first. A credential that has expired already is not stored.
    pub async fn insert(&self, key: Vec<u8>, verified: Verified, now: DateTime<Utc>) {
        let ttl_end = now.checked_add_signed(self.ttl).unwrap_or(DateTime::<Utc>::MAX_UTC);
        let valid_until = verified.expires_at.map_or(ttl_end, |expires| expires.min(ttl_end));
        if valid_until <= now {
            return;
        }
        let mut entries = self.entries.lock().await;
        if !entries.contains_key(&key) && entries.len() >= self.max_entries {
            entries.retain(|_, entry| entry.valid_until > now);
            shrink_to(&mut entries, headroom_target(self.max_entries), |entry| entry.used_at);
        }
        entries.insert(
            key,
            Entry {
                verified,
                valid_until,
                used_at: now,
            },
        );
    }

    /// Forgets the entry stored under `key`.
    pub async fn remove(&self, key: &[u8]) {
        self.entries.lock().await.remove(key);
    }

    /// How many entries the cache holds (expired ones included until they are looked up or swept).
    pub async fn len(&self) -> usize {
        self.entries.lock().await.len()
    }

    /// Whether the cache holds no entry.
    pub async fn is_empty(&self) -> bool {
        self.entries.lock().await.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use chrono::TimeZone as _;
    use davhaven_domain::{CredentialKind, TokenId};
    use uuid::Uuid;

    use super::*;

    fn at(minute: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap() + TimeDelta::minutes(minute)
    }

    fn verified(n: u128, expires_at: Option<DateTime<Utc>>) -> Verified {
        let token = TokenId::from_uuid(Uuid::from_u128(n));
        Verified {
            credential: CredentialRef::api_token(token),
            stored: StoredHash::new(CredentialKind::ApiToken, "k1", vec![1, 2, 3]),
            generation: Some(3),
            expires_at,
        }
    }

    #[tokio::test]
    async fn entries_are_served_until_the_ttl_has_passed() {
        let cache = VerifiedCache::new(Duration::from_mins(5), 10);
        cache.insert(b"k".to_vec(), verified(1, None), at(0)).await;
        assert_eq!(cache.get(b"k", at(0)).await, Some(verified(1, None)));
        assert_eq!(cache.get(b"k", at(4)).await, Some(verified(1, None)));
        assert_eq!(cache.get(b"k", at(5)).await, None, "the TTL is exclusive");
        assert_eq!(cache.get(b"k", at(1)).await, None, "an expired entry is gone");
        assert!(cache.is_empty().await);
        assert_eq!(cache.get(b"other", at(0)).await, None);
    }

    #[tokio::test]
    async fn using_an_entry_does_not_extend_its_life() {
        let cache = VerifiedCache::new(Duration::from_mins(5), 10);
        cache.insert(b"k".to_vec(), verified(1, None), at(0)).await;
        for minute in 1..5 {
            assert!(cache.get(b"k", at(minute)).await.is_some());
        }
        assert!(
            cache.get(b"k", at(5)).await.is_none(),
            "a busy credential is verified again every TTL"
        );
    }

    #[tokio::test]
    async fn an_entry_never_outlives_its_credential() {
        let cache = VerifiedCache::new(Duration::from_mins(5), 10);
        cache.insert(b"k".to_vec(), verified(1, Some(at(2))), at(0)).await;
        assert!(cache.get(b"k", at(1)).await.is_some());
        assert!(
            cache.get(b"k", at(2)).await.is_none(),
            "expired with the credential, before the TTL"
        );
        cache.insert(b"old".to_vec(), verified(2, Some(at(0))), at(1)).await;
        assert_eq!(cache.len().await, 0, "an expired credential is not stored at all");
    }

    #[tokio::test]
    async fn removing_an_entry_forgets_it() {
        let cache = VerifiedCache::new(Duration::from_mins(5), 10);
        cache.insert(b"k".to_vec(), verified(1, None), at(0)).await;
        cache.remove(b"k").await;
        assert!(cache.get(b"k", at(0)).await.is_none());
        cache.remove(b"never-there").await;
    }

    #[tokio::test]
    async fn a_full_cache_drops_expired_entries_first() {
        let cache = VerifiedCache::new(Duration::from_mins(5), 3);
        for (n, key) in [b"a", b"b", b"c"].into_iter().enumerate() {
            cache
                .insert(key.to_vec(), verified(1, None), at(i64::try_from(n).unwrap()))
                .await;
        }
        assert_eq!(cache.len().await, 3);
        // Everything but `c` has expired at minute 6; inserting `d` sweeps the expired ones.
        cache.insert(b"d".to_vec(), verified(2, None), at(6)).await;
        assert_eq!(cache.len().await, 2);
        assert!(cache.get(b"c", at(6)).await.is_some(), "c lives until minute 7");
        assert!(cache.get(b"c", at(7)).await.is_none());
    }

    #[tokio::test]
    async fn a_full_cache_of_live_entries_drops_the_least_recently_used_and_leaves_headroom() {
        let cache = VerifiedCache::new(Duration::from_hours(1), 20);
        for n in 0..20_u8 {
            cache.insert(vec![n], verified(1, None), at(i64::from(n))).await;
        }
        // Entries 0 and 1 are used again; they are now the most recently used.
        assert!(cache.get(&[0], at(30)).await.is_some());
        assert!(cache.get(&[1], at(30)).await.is_some());
        cache.insert(vec![99], verified(2, None), at(31)).await;
        // 20 entries were cut back to 18 (nine tenths), then the new one went in.
        assert_eq!(cache.len().await, 19);
        assert!(cache.get(&[0], at(32)).await.is_some(), "used lately, so it stays");
        assert!(cache.get(&[1], at(32)).await.is_some());
        assert!(
            cache.get(&[2], at(32)).await.is_none(),
            "the least recently used went first"
        );
        assert!(cache.get(&[3], at(32)).await.is_none());
        assert!(cache.get(&[4], at(32)).await.is_some());
        // Headroom: the next insert needs no sweep.
        cache.insert(vec![100], verified(2, None), at(33)).await;
        assert_eq!(cache.len().await, 20);
        // Replacing an entry never evicts another.
        cache.insert(vec![100], verified(9, None), at(34)).await;
        assert_eq!(cache.len().await, 20);
    }

    #[test]
    fn the_headroom_is_a_tenth_and_at_least_one_slot() {
        assert_eq!(headroom_target(100_000), 90_000);
        assert_eq!(headroom_target(20), 18);
        assert_eq!(headroom_target(10), 9);
        assert_eq!(headroom_target(3), 2);
        assert_eq!(headroom_target(1), 0);
    }

    #[test]
    fn shrinking_drops_the_oldest_and_keeps_the_rest() {
        let mut map: HashMap<u8, i64> = (0..10).map(|n| (n, i64::from(n) * 10)).collect();
        shrink_to(&mut map, 6, |age| *age);
        let mut kept: Vec<u8> = map.keys().copied().collect();
        kept.sort_unstable();
        assert_eq!(kept, vec![4, 5, 6, 7, 8, 9]);
        shrink_to(&mut map, 20, |age| *age);
        assert_eq!(map.len(), 6, "a map within its target is left alone");
    }
}
