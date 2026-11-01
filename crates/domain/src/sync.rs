//! Sync tokens (`urn:davhaven:sync:...`) used by WebDAV sync and the API changes feed.
//!
//! A token names a collection, the epoch of its change log and the sequence number of the last change the client
//! has seen: `urn:davhaven:sync:{collection_id}:{epoch}:{seq}`. The same string is the collection's `getctag`.
//! Tokens that are foreign (other collection), garbled, from another epoch, from the future or already pruned all
//! answer the same way (403 `DAV:valid-sync-token`, API 410 `sync-token-expired`), so [`SyncToken::resume_from`]
//! reports a single error.

use core::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const PREFIX: &str = "urn:davhaven:sync:";

text_enum!(
    /// The kind of collection a change log belongs to (`collection_changes.collection_kind`).
    CollectionKind [] {
        /// A calendar collection.
        Calendar => "calendar",
        /// A principal's calendar home.
        Home => "home",
        /// A principal's scheduling inbox.
        Inbox => "inbox",
        /// A principal's notification collection.
        Notifications => "notifications",
    }
);

/// Identifies one collection with a change log: a calendar id for calendars, a principal id for the home, the
/// inbox and the notification collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
pub struct CollectionKey {
    /// What kind of collection it is.
    pub kind: CollectionKind,
    /// The calendar id or principal id.
    pub id: Uuid,
}

/// Error for a sync token that cannot be used: garbled, foreign, from another epoch, from the future or pruned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid sync token")]
pub struct SyncTokenError;

/// A parsed sync token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "String", into = "String")]
#[schemars(with = "String")]
pub struct SyncToken {
    /// The collection id (a calendar id or a principal id).
    pub collection: Uuid,
    /// The epoch of the collection's change log; bumped after a restore.
    pub epoch: Uuid,
    /// The sequence number of the last change covered by the token.
    pub seq: u64,
}

impl SyncToken {
    /// Creates a token.
    pub const fn new(collection: Uuid, epoch: Uuid, seq: u64) -> Self {
        Self { collection, epoch, seq }
    }

    /// Parses the canonical form; anything else is rejected.
    ///
    /// # Errors
    ///
    /// Returns [`SyncTokenError`] for foreign prefixes, wrong shapes, non-canonical numbers (signs, leading
    /// zeros, whitespace) and sequence numbers that do not fit the database's `bigint`.
    pub fn parse(input: &str) -> Result<Self, SyncTokenError> {
        let rest = input.strip_prefix(PREFIX).ok_or(SyncTokenError)?;
        let mut parts = rest.split(':');
        let (Some(collection), Some(epoch), Some(seq), None) = (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(SyncTokenError);
        };
        let collection = crate::ids::parse_hyphenated(collection).ok_or(SyncTokenError)?;
        let epoch = crate::ids::parse_hyphenated(epoch).ok_or(SyncTokenError)?;
        let canonical_digits =
            !seq.is_empty() && seq.bytes().all(|b| b.is_ascii_digit()) && (seq == "0" || !seq.starts_with('0'));
        if !canonical_digits {
            return Err(SyncTokenError);
        }
        let seq: u64 = seq.parse().map_err(|_| SyncTokenError)?;
        if i64::try_from(seq).is_err() {
            return Err(SyncTokenError);
        }
        Ok(Self { collection, epoch, seq })
    }

    /// Checks the token against the collection's current state and returns the sequence number to resume after.
    ///
    /// The token is usable only when it names `collection` and `epoch`, and `min_seq <= seq <= current_seq`:
    /// a larger sequence number comes from the future (for example after a restore without an epoch bump), a
    /// smaller one than `min_seq` refers to pruned history.
    ///
    /// # Errors
    ///
    /// Returns [`SyncTokenError`] in every case above.
    pub fn resume_from(
        &self,
        collection: Uuid,
        epoch: Uuid,
        min_seq: u64,
        current_seq: u64,
    ) -> Result<u64, SyncTokenError> {
        if self.collection != collection || self.epoch != epoch || self.seq < min_seq || self.seq > current_seq {
            return Err(SyncTokenError);
        }
        Ok(self.seq)
    }
}

impl fmt::Display for SyncToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{PREFIX}{}:{}:{}",
            self.collection.hyphenated(),
            self.epoch.hyphenated(),
            self.seq
        )
    }
}

impl core::str::FromStr for SyncToken {
    type Err = SyncTokenError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

impl TryFrom<String> for SyncToken {
    type Error = SyncTokenError;

    fn try_from(input: String) -> Result<Self, Self::Error> {
        Self::parse(&input)
    }
}

impl From<SyncToken> for String {
    fn from(token: SyncToken) -> Self {
        token.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COLLECTION: &str = "018f3c1e-7b2a-7c3d-9e4f-0123456789ab";
    const EPOCH: &str = "018f3c1e-7b2a-7c3d-9e4f-0123456789ac";

    fn token(seq: u64) -> SyncToken {
        SyncToken::new(
            Uuid::parse_str(COLLECTION).unwrap(),
            Uuid::parse_str(EPOCH).unwrap(),
            seq,
        )
    }

    #[test]
    fn formats_and_parses_the_canonical_form() {
        let text = format!("urn:davhaven:sync:{COLLECTION}:{EPOCH}:42");
        assert_eq!(token(42).to_string(), text);
        assert_eq!(SyncToken::parse(&text).unwrap(), token(42));
        assert_eq!(text.parse::<SyncToken>().unwrap(), token(42));
        assert_eq!(
            SyncToken::parse(&format!("urn:davhaven:sync:{COLLECTION}:{EPOCH}:0")).unwrap(),
            token(0)
        );
        let max = i64::MAX.to_string();
        assert_eq!(
            SyncToken::parse(&format!("urn:davhaven:sync:{COLLECTION}:{EPOCH}:{max}"))
                .unwrap()
                .seq,
            i64::MAX.unsigned_abs()
        );
    }

    #[test]
    fn rejects_everything_else() {
        let ok = format!("{COLLECTION}:{EPOCH}");
        let bad = [
            String::new(),
            "urn:davhaven:sync:".to_owned(),
            format!("http://example.org/sync/{ok}:1"),
            format!("urn:davhaven:sync:{ok}"),
            format!("urn:davhaven:sync:{ok}:"),
            format!("urn:davhaven:sync:{ok}:1:2"),
            format!("urn:davhaven:sync:{ok}:01"),
            format!("urn:davhaven:sync:{ok}:+1"),
            format!("urn:davhaven:sync:{ok}:-1"),
            format!("urn:davhaven:sync:{ok}: 1"),
            format!("urn:davhaven:sync:{ok}:1 "),
            format!("urn:davhaven:sync:{ok}:1.0"),
            format!("urn:davhaven:sync:{ok}:9223372036854775808"),
            format!("urn:davhaven:sync:{ok}:18446744073709551616"),
            format!("urn:davhaven:sync:{COLLECTION}:not-a-uuid:1"),
            format!("urn:davhaven:sync:not-a-uuid:{EPOCH}:1"),
            format!("urn:davhaven:sync:{}:{EPOCH}:1", COLLECTION.replace('-', "")),
            format!("URN:DAVHAVEN:SYNC:{ok}:1"),
            format!("urn:davhaven:sync:{ok}:1\n"),
        ];
        for input in &bad {
            assert_eq!(SyncToken::parse(input), Err(SyncTokenError), "{input:?}");
        }
    }

    #[test]
    fn resume_checks_collection_epoch_and_range() {
        let collection = Uuid::parse_str(COLLECTION).unwrap();
        let epoch = Uuid::parse_str(EPOCH).unwrap();
        let t = token(10);
        assert_eq!(t.resume_from(collection, epoch, 0, 10), Ok(10));
        assert_eq!(
            t.resume_from(collection, epoch, 10, 50),
            Ok(10),
            "the oldest retained sequence is still valid"
        );
        assert_eq!(t.resume_from(collection, epoch, 11, 50), Err(SyncTokenError), "pruned");
        assert_eq!(
            t.resume_from(collection, epoch, 0, 9),
            Err(SyncTokenError),
            "from the future"
        );
        assert_eq!(
            t.resume_from(Uuid::from_u128(1), epoch, 0, 50),
            Err(SyncTokenError),
            "foreign collection"
        );
        assert_eq!(
            t.resume_from(collection, Uuid::from_u128(1), 0, 50),
            Err(SyncTokenError),
            "wrong epoch"
        );
    }

    #[test]
    fn serde_uses_the_string_form() {
        let t = token(7);
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, format!("\"urn:davhaven:sync:{COLLECTION}:{EPOCH}:7\""));
        assert_eq!(serde_json::from_str::<SyncToken>(&json).unwrap(), t);
        assert!(serde_json::from_str::<SyncToken>("\"garbage\"").is_err());
    }

    #[test]
    fn collection_kinds() {
        let names: Vec<&str> = CollectionKind::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(names, vec!["calendar", "home", "inbox", "notifications"]);
        let key = CollectionKey {
            kind: CollectionKind::Calendar,
            id: Uuid::from_u128(5),
        };
        assert_eq!(
            serde_json::from_str::<CollectionKey>(&serde_json::to_string(&key).unwrap()).unwrap(),
            key
        );
    }

    mod props {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            #[test]
            fn format_and_parse_are_inverse(collection in any::<u128>(), epoch in any::<u128>(), seq in 0..=i64::MAX) {
                let token = SyncToken::new(Uuid::from_u128(collection), Uuid::from_u128(epoch), seq.unsigned_abs());
                prop_assert_eq!(SyncToken::parse(&token.to_string()).unwrap(), token);
            }

            #[test]
            fn parsing_never_panics(input in ".{0,120}") {
                let _ = SyncToken::parse(&input);
            }
        }
    }
}
