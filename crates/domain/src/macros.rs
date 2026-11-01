//! Internal macros that generate the identifier and validated string newtypes.

/// Defines a UUID-backed identifier newtype (`Copy`, ordered, serialized as the hyphenated UUID string).
macro_rules! uuid_id {
    ($(#[$meta:meta])* $name:ident, $kind:literal) => {
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
            schemars::JsonSchema,
        )]
        #[serde(transparent)]
        pub struct $name(uuid::Uuid);

        impl $name {
            /// Wraps a UUID. Generation is the job of the `IdGenerator` port; this type does not check the version.
            pub const fn from_uuid(uuid: uuid::Uuid) -> Self {
                Self(uuid)
            }

            /// Returns the underlying UUID.
            pub const fn as_uuid(self) -> uuid::Uuid {
                self.0
            }

            /// Parses the canonical hyphenated form (`8-4-4-4-12` hexadecimal digits).
            ///
            /// # Errors
            ///
            /// Returns [`crate::ids::IdError`] when the text is not a hyphenated UUID.
            pub fn parse(input: &str) -> Result<Self, $crate::ids::IdError> {
                $crate::ids::parse_hyphenated(input)
                    .map(Self)
                    .ok_or($crate::ids::IdError::new($kind))
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::Display::fmt(&self.0.hyphenated(), f)
            }
        }

        impl core::str::FromStr for $name {
            type Err = $crate::ids::IdError;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                Self::parse(input)
            }
        }

        impl From<uuid::Uuid> for $name {
            fn from(uuid: uuid::Uuid) -> Self {
                Self(uuid)
            }
        }

        impl From<$name> for uuid::Uuid {
            fn from(id: $name) -> Self {
                id.0
            }
        }
    };
}

/// Defines a validated, normalized string newtype. `$parse` is a `fn(&str) -> Result<String, &'static str>` that
/// validates and normalizes; the error is the human-readable reason.
macro_rules! string_key {
    ($(#[$meta:meta])* $name:ident, $kind:literal, $parse:path) => {
        $(#[$meta])*
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            Hash,
            PartialOrd,
            Ord,
            serde::Serialize,
            serde::Deserialize,
            schemars::JsonSchema,
        )]
        #[serde(try_from = "String", into = "String")]
        #[schemars(with = "String")]
        pub struct $name(String);

        impl $name {
            /// Validates (and normalizes) the text.
            ///
            /// # Errors
            ///
            /// Returns a [`crate::keys::KeyError`] naming the rejected rule.
            pub fn parse(input: &str) -> Result<Self, $crate::keys::KeyError> {
                $parse(input)
                    .map(Self)
                    .map_err(|reason| $crate::keys::KeyError::new($kind, reason))
            }

            /// Returns the normalized text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl core::str::FromStr for $name {
            type Err = $crate::keys::KeyError;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                Self::parse(input)
            }
        }

        impl TryFrom<String> for $name {
            type Error = $crate::keys::KeyError;

            fn try_from(input: String) -> Result<Self, Self::Error> {
                Self::parse(&input)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = $crate::keys::KeyError;

            fn try_from(input: &str) -> Result<Self, Self::Error> {
                Self::parse(input)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl core::borrow::Borrow<str> for $name {
            fn borrow(&self) -> &str {
                &self.0
            }
        }
    };
}

/// Defines a closed enum whose JSON and database spelling is a fixed lowercase token.
macro_rules! text_enum {
    (
        $(#[$meta:meta])*
        $name:ident [$($extra:ident),*] {
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
            schemars::JsonSchema
            $(, $extra)*
        )]
        pub enum $name {
            $( $(#[$vmeta])* #[serde(rename = $text)] $variant ),+
        }

        impl $name {
            /// Every value, in declaration order.
            pub const ALL: &'static [Self] = &[ $( Self::$variant ),+ ];

            /// The JSON and database spelling.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $( Self::$variant => $text ),+
                }
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl core::str::FromStr for $name {
            type Err = $crate::vocab::UnknownVariant;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                Self::ALL
                    .iter()
                    .copied()
                    .find(|value| value.as_str() == input)
                    .ok_or($crate::vocab::UnknownVariant::new(stringify!($name)))
            }
        }
    };
}
