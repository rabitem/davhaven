//! Cursor pagination: `Page<T>` and opaque `Cursor`s.
//!
//! Every list in the management API and in the MCP tools is a cursor page (PLAN 2.10): `{items, next_cursor}`,
//! ordered by id, with a `limit` (default 50, maximum 200). A cursor is opaque to clients: the application signs it
//! with the key ring (purpose `Cursor`), so a client cannot forge a position and a cursor of one listing is
//! useless for another. This module only carries the text; creating and checking it is the application's job.

use core::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// The longest cursor accepted from a client, in bytes.
pub const MAX_CURSOR_LEN: usize = 1024;

/// Why text is not a plausible cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CursorError;

impl fmt::Display for CursorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a cursor must be 1 to {MAX_CURSOR_LEN} printable ASCII characters")
    }
}

impl std::error::Error for CursorError {}

/// An opaque pagination cursor: printable ASCII, at most [`MAX_CURSOR_LEN`] bytes.
///
/// Whether the cursor is genuine (signed by this server for this listing) is decided by the application when the
/// cursor is used; deserializing only checks the shape.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(try_from = "String", into = "String")]
#[schemars(with = "String")]
pub struct Cursor(String);

impl Cursor {
    /// Wraps cursor text after checking its shape.
    ///
    /// # Errors
    ///
    /// Returns [`CursorError`] for empty text, text longer than [`MAX_CURSOR_LEN`] and non-printable or
    /// non-ASCII characters.
    pub fn parse(text: &str) -> Result<Self, CursorError> {
        let printable = text.bytes().all(|b| b.is_ascii_graphic());
        if text.is_empty() || text.len() > MAX_CURSOR_LEN || !printable {
            return Err(CursorError);
        }
        Ok(Self(text.to_owned()))
    }

    /// The cursor text, as sent to and received from clients.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Cursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for Cursor {
    type Error = CursorError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text)
    }
}

impl From<Cursor> for String {
    fn from(cursor: Cursor) -> Self {
        cursor.0
    }
}

/// One page of a listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct Page<T> {
    /// The items of this page, in the order of the listing.
    pub items: Vec<T>,
    /// The cursor of the next page; absent on the last page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Cursor>,
}

impl<T> Page<T> {
    /// A page with the given items and the cursor of the page after it.
    pub const fn new(items: Vec<T>, next_cursor: Option<Cursor>) -> Self {
        Self { items, next_cursor }
    }

    /// A last page without items.
    pub const fn empty() -> Self {
        Self {
            items: Vec::new(),
            next_cursor: None,
        }
    }

    /// Converts every item and keeps the cursor.
    pub fn map<U>(self, convert: impl FnMut(T) -> U) -> Page<U> {
        Page {
            items: self.items.into_iter().map(convert).collect(),
            next_cursor: self.next_cursor,
        }
    }

    /// Whether another page follows.
    pub const fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }
}

impl<T> Default for Page<T> {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursors_accept_printable_ascii_only() {
        assert!(Cursor::parse("abc.DEF-123_xyz~").is_ok());
        for bad in ["", "with space", "tab\t", "umlaut-ä", "line\nbreak"] {
            assert!(Cursor::parse(bad).is_err(), "{bad:?}");
        }
        assert!(Cursor::parse(&"a".repeat(MAX_CURSOR_LEN)).is_ok());
        assert!(Cursor::parse(&"a".repeat(MAX_CURSOR_LEN + 1)).is_err());
    }

    #[test]
    fn cursors_serialize_as_plain_strings_and_validate_on_input() {
        let cursor = Cursor::parse("opaque-token").unwrap();
        assert_eq!(serde_json::to_string(&cursor).unwrap(), "\"opaque-token\"");
        assert_eq!(serde_json::from_str::<Cursor>("\"opaque-token\"").unwrap(), cursor);
        assert!(serde_json::from_str::<Cursor>("\"has space\"").is_err());
        assert_eq!(cursor.to_string(), "opaque-token");
    }

    #[test]
    fn pages_omit_an_absent_cursor_and_map_items() {
        let last: Page<u32> = Page::new(vec![1, 2], None);
        assert_eq!(serde_json::to_string(&last).unwrap(), r#"{"items":[1,2]}"#);
        assert!(!last.has_more());
        let next = Page::new(vec![1], Some(Cursor::parse("c1").unwrap()));
        assert!(next.has_more());
        let mapped = next.map(|n| n.to_string());
        assert_eq!(mapped.items, vec!["1".to_owned()]);
        assert_eq!(mapped.next_cursor.unwrap().as_str(), "c1");
        assert_eq!(Page::<u8>::default(), Page::empty());
        let parsed: Page<u32> = serde_json::from_str(r#"{"items":[3]}"#).unwrap();
        assert_eq!(parsed.items, vec![3]);
    }
}
