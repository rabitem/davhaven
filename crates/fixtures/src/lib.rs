//! Test fixtures for Davhaven.
//!
//! Builders for entities and events (`EventBuilder`), the `FixtureWorld` specification (two tenants with every
//! kind of actor and calendar) and the loader for the iCalendar corpus in `testdata/corpus`.
//!
//! The [`world`] module is the shared vocabulary of the test harness: every constant name of the fixture world
//! (`names::OWNER`, `names::SHARED_CALENDAR`, ...), the [`ActorRole`] and [`CalendarRole`] dimensions of the
//! permission matrix, the credentials of every actor and the DAV paths a viewer uses to reach a calendar. The
//! specification is plain data without behaviour, so every backend (the fake application, the real application on
//! the memory or PostgreSQL store, a deployed instance) seeds the same world.

#![forbid(unsafe_code)]

/// Declares an enum whose values have stable text names.
///
/// The generated enum derives `Debug`, `Clone`, `Copy`, `PartialEq`, `Eq`, `Hash`, `PartialOrd`, `Ord`,
/// `serde::Serialize` and `serde::Deserialize` (the text name is the serialized form), and gets `ALL` (every value
/// in declaration order), `as_str`, `Display` and `FromStr` (with [`UnknownName`] as the error). The crate that
/// invokes the macro needs a direct dependency on `serde`.
///
/// The harness uses these enums as the dimensions of its matrices; the text names are the spelling in the
/// expectations file and in scenario files.
#[macro_export]
macro_rules! named_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $( $(#[$vmeta:meta])* $variant:ident => $text:literal ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(
            Debug,
            Clone,
            Copy,
            PartialEq,
            Eq,
            Hash,
            PartialOrd,
            Ord,
            serde::Serialize,
            serde::Deserialize,
        )]
        $vis enum $name {
            $( $(#[$vmeta])* #[serde(rename = $text)] $variant ),+
        }

        impl $name {
            /// Every value, in declaration order.
            pub const ALL: &'static [Self] = &[ $( Self::$variant ),+ ];

            /// The stable text name, as written in expectation and scenario files.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $( Self::$variant => $text ),+
                }
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl ::core::str::FromStr for $name {
            type Err = $crate::UnknownName;

            fn from_str(input: &str) -> ::core::result::Result<Self, Self::Err> {
                Self::ALL
                    .iter()
                    .copied()
                    .find(|value| value.as_str() == input)
                    .ok_or_else(|| $crate::UnknownName::new(stringify!($name), input))
            }
        }
    };
}

/// The error of parsing a text name that no value of an enum declared with [`named_enum!`] has.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("`{input}` is not a {kind}")]
pub struct UnknownName {
    kind: &'static str,
    input: String,
}

impl UnknownName {
    /// Creates the error for `input`, which is not a value of the enum called `kind`.
    pub fn new(kind: &'static str, input: &str) -> Self {
        Self {
            kind,
            input: input.to_owned(),
        }
    }

    /// The name of the enum.
    pub const fn kind(&self) -> &'static str {
        self.kind
    }

    /// The rejected text.
    pub fn input(&self) -> &str {
        &self.input
    }
}

pub mod builders;
pub mod corpus;
pub mod dav;
pub mod event;
pub mod world;

pub use event::{Attendee, EventBuilder, Organizer, When};
pub use world::{
    ActorRole, CalendarRef, CalendarRole, FixtureCalendar, FixtureCredential, FixtureError, FixtureEvent, FixtureGrant,
    FixtureMembership, FixturePrincipal, FixtureTenant, FixtureWorld, PRINCIPAL_TOKEN_SCOPE_LABEL,
    TENANT_TOKEN_SCOPE_LABEL, WorldNames, api_token_secret, app_password_secret, external_key, feed_token_secret,
    names, rsvp_token_secret,
};
