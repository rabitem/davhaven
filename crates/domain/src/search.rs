//! The vocabulary of principal search: which properties a criterion looks into and how its text is compared.
//!
//! Principal search is one of the few places where the same rule has to hold in three layers: the store matches in
//! its query (so that the limit cuts what matched and not what was looked up), the in-memory store and the fake
//! application match in Rust, and the protocol crates say what the client asked for. [`SearchCriterion::matches`] is
//! the reference of the matching rule; the PostgreSQL store implements the same rule in SQL, and the store contract
//! suite runs the same cases against both.

use crate::keys::CalendarUserAddress;

/// A property of a principal that a search can look into.
///
/// Only what the application stores can be searched: the principal URL and the `urn:uuid:` address of a principal
/// are derived from its name and id when the address set is rendered, and no search finds a principal by them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SearchField {
    /// The immutable login name.
    Name,
    /// The display name.
    DisplayName,
    /// The stored calendar user addresses, with their scheme (`mailto:ben@acme.example`).
    Address,
    /// The e-mail part of the stored `mailto:` addresses, without the scheme (`ben@acme.example`).
    Email,
}

impl SearchField {
    /// Where a criterion that names no field looks: the name, the display name and the stored addresses.
    pub const DEFAULT: [Self; 3] = [Self::Name, Self::DisplayName, Self::Address];
}

/// How the text of a criterion is compared with a value, ignoring case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TextMatch {
    /// The value contains the text.
    #[default]
    Contains,
    /// The value starts with the text.
    StartsWith,
    /// The value is the text.
    Equals,
}

impl TextMatch {
    /// Whether `value` matches `needle`; both are in lower case.
    pub fn test(self, value: &str, needle: &str) -> bool {
        match self {
            Self::Contains => value.contains(needle),
            Self::StartsWith => value.starts_with(needle),
            Self::Equals => value == needle,
        }
    }
}

/// One condition of a principal search: a text, the properties to look for it in and how to compare it.
///
/// A principal satisfies the criterion when the text matches (ignoring case) at least one value of one of the
/// properties.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchCriterion {
    /// The text to look for, without the white space around it.
    pub text: String,
    /// The properties to look into; none means [`SearchField::DEFAULT`].
    pub fields: Vec<SearchField>,
    /// How the text is compared.
    pub matching: TextMatch,
}

impl SearchCriterion {
    /// A criterion with all of its parts.
    pub fn new(text: impl Into<String>, fields: Vec<SearchField>, matching: TextMatch) -> Self {
        Self {
            text: text.into(),
            fields,
            matching,
        }
    }

    /// The criterion of a plain text: contained in the name, the display name or a stored address.
    pub fn contains(text: impl Into<String>) -> Self {
        Self::new(text, Vec::new(), TextMatch::Contains)
    }

    /// The properties the criterion looks into: its own, or the default ones.
    pub fn searched(&self) -> &[SearchField] {
        if self.fields.is_empty() {
            &SearchField::DEFAULT
        } else {
            &self.fields
        }
    }

    /// Whether a principal with this name, display name and stored addresses satisfies the criterion.
    pub fn matches(&self, name: &str, display_name: &str, addresses: &[CalendarUserAddress]) -> bool {
        let needle = self.text.to_lowercase();
        self.searched().iter().any(|field| match field {
            SearchField::Name => self.matching.test(&name.to_lowercase(), &needle),
            SearchField::DisplayName => self.matching.test(&display_name.to_lowercase(), &needle),
            SearchField::Address => addresses
                .iter()
                .any(|address| self.matching.test(&address.as_str().to_lowercase(), &needle)),
            SearchField::Email => addresses.iter().any(|address| {
                address
                    .as_str()
                    .strip_prefix("mailto:")
                    .is_some_and(|email| self.matching.test(&email.to_lowercase(), &needle))
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addresses(texts: &[&str]) -> Vec<CalendarUserAddress> {
        texts
            .iter()
            .map(|text| CalendarUserAddress::parse(text).unwrap())
            .collect()
    }

    fn criterion(text: &str, fields: &[SearchField], matching: TextMatch) -> SearchCriterion {
        SearchCriterion::new(text, fields.to_vec(), matching)
    }

    #[test]
    fn a_plain_text_is_looked_for_in_the_name_the_display_name_and_the_addresses() {
        let addresses = addresses(&[
            "mailto:ben@acme.example",
            "urn:uuid:00000000-0000-0000-0000-000000000007",
        ]);
        let find = |text: &str| SearchCriterion::contains(text).matches("ben", "Ben Baker", &addresses);
        for text in [
            "ben",
            "BAKER",
            "ben baker",
            "acme.example",
            "mailto:ben@",
            "b",
            "urn:uuid:0",
        ] {
            assert!(find(text), "{text}");
        }
        for text in ["anna", "clark", "principals"] {
            assert!(!find(text), "{text}");
        }
    }

    #[test]
    fn a_criterion_looks_only_into_the_properties_it_names() {
        use SearchField::{Address, DisplayName, Email, Name};
        use TextMatch::{Contains, Equals, StartsWith};
        let addresses = addresses(&["mailto:ben@acme.example"]);
        let matches = |c: SearchCriterion| c.matches("bnk", "Ben Baker", &addresses);
        assert!(matches(criterion("BAKER", &[DisplayName], Contains)));
        assert!(
            !matches(criterion("baker", &[Address], Contains)),
            "the name is not an address"
        );
        assert!(matches(criterion("acme.example", &[Address], Contains)));
        assert!(matches(criterion("mailto:ben", &[Address], StartsWith)));
        assert!(
            !matches(criterion("mailto:ben", &[Email], StartsWith)),
            "e-mails come without the scheme"
        );
        assert!(matches(criterion("BEN@acme.example", &[Email], Equals)));
        assert!(matches(criterion("ben@", &[DisplayName, Email], StartsWith)));
        assert!(matches(criterion("bnk", &[Name], Equals)));
        assert!(!matches(criterion("ben", &[DisplayName], Equals)));
        assert!(matches(criterion("ben baker", &[DisplayName], Equals)));
    }

    #[test]
    fn the_addresses_that_are_not_mail_addresses_have_no_email() {
        let addresses = addresses(&[
            "urn:uuid:00000000-0000-0000-0000-000000000007",
            "/dav/principals/acme/ben/",
        ]);
        let found = SearchCriterion::new("principals", vec![SearchField::Email], TextMatch::Contains)
            .matches("ben", "Ben", &addresses);
        assert!(!found);
        let found = SearchCriterion::new("principals", vec![SearchField::Address], TextMatch::Contains)
            .matches("ben", "Ben", &addresses);
        assert!(found, "a stored URL address is an address");
    }

    #[test]
    fn a_criterion_without_fields_searches_the_default_ones() {
        let plain = SearchCriterion::contains("x");
        assert_eq!(plain.searched(), SearchField::DEFAULT);
        assert_eq!(plain.matching, TextMatch::Contains);
        let named = criterion("x", &[SearchField::Email], TextMatch::Equals);
        assert_eq!(named.searched(), [SearchField::Email]);
    }
}
