//! Typed, versioned tenant settings.
//!
//! Settings are stored as JSON (`tenants.settings`) and read leniently: every field has a serde default and
//! unknown fields are ignored, so a binary can read settings written by a newer release (`ENGINEERING_RULES` R16).
//! Input from the management API goes through [`TenantSettings::normalized`], which validates and canonicalizes.
//! The settings structs are `#[non_exhaustive]`: construct them with `Default::default()` and assign fields.

use std::borrow::Cow;
use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::entities::GrantAccess;
use crate::keys::{CalendarUserAddress, DomainName, Email, Locale, TimeZoneName};
use crate::vocab::{ComponentKind, ItipMethod};

/// The schema version written by this release.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// The longest text of a busy block, in characters (`busy_text`).
pub const MAX_BUSY_TEXT_CHARS: usize = 100;

/// The most languages a tenant can name a busy text for (`busy_text_by_locale`).
pub const MAX_BUSY_TEXT_LOCALES: usize = 20;

/// The longest language tag in characters: the limit of [`Locale`], which the schema of `busy_text_by_locale` states for its keys.
const MAX_LANGUAGE_TAG_CHARS: usize = 35;

/// The shape of a language tag that [`Locale`] accepts (a two or three letter language and subtags of up to eight letters or
/// digits, separated by `-` or `_`), for the keys of `busy_text_by_locale` in the schema.
const LANGUAGE_TAG_PATTERN: &str = "^[A-Za-z]{2,3}([-_][A-Za-z0-9]{1,8})*$";

/// What the error says when one document writes the same language tag twice in different spellings (`de-DE` and `de_de`):
/// the tags are canonical after reading, so the map cannot hold both, and which one won would be the order of the keys.
const REPEATED_TAG: &str = "busy_text_by_locale writes one language tag twice";

/// Whether `error`, the text of a deserialization error of [`TenantSettings`], says that `busy_text_by_locale` writes one
/// language tag twice. The edge uses it to point at the member (`/settings/busy_text_by_locale`) instead of the whole body.
pub fn busy_texts_repeat_a_tag(error: &str) -> bool {
    error.contains(REPEATED_TAG)
}

/// Reads `busy_text_by_locale`: the keys are language tags in any spelling, which become canonical (`de_de` is `de-DE`), and a
/// document that spells one tag twice is refused instead of letting the later key win.
fn deserialize_busy_texts<'de, D: Deserializer<'de>>(deserializer: D) -> Result<BTreeMap<Locale, String>, D::Error> {
    struct Texts;

    impl<'de> Visitor<'de> for Texts {
        type Value = BTreeMap<Locale, String>;

        fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("a map from language tags to texts")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut entries: A) -> Result<Self::Value, A::Error> {
            let mut texts = BTreeMap::new();
            while let Some((tag, text)) = entries.next_entry::<String, String>()? {
                let locale = Locale::parse(&tag).map_err(de::Error::custom)?;
                if texts.insert(locale.clone(), text).is_some() {
                    return Err(de::Error::custom(format!("{REPEATED_TAG}: `{locale}`")));
                }
            }
            Ok(texts)
        }
    }

    deserializer.deserialize_map(Texts)
}

/// Error returned when tenant settings are invalid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid tenant setting `{field}`: {reason}")]
pub struct SettingsError {
    field: &'static str,
    reason: Cow<'static, str>,
}

impl SettingsError {
    const fn new(field: &'static str, reason: &'static str) -> Self {
        Self {
            field,
            reason: Cow::Borrowed(reason),
        }
    }

    /// An error whose reason names a value of the rule (a limit), so that the text cannot drift from the constant.
    fn formatted(field: &'static str, reason: String) -> Self {
        Self {
            field,
            reason: Cow::Owned(reason),
        }
    }

    /// The dotted name of the offending setting, for example `scheduling.external_allowlist`.
    pub const fn field(&self) -> &'static str {
        self.field
    }

    /// The rule that was violated.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// The RFC 6901 JSON pointer of the offending setting in a tenant body, for example `/settings/busy_text` or
    /// `/settings/client_config/organization_name`: the dotted name with its dots as slashes. `/settings` for a setting
    /// that this function does not know, so that a new rule is never answered with a wrong pointer.
    pub fn pointer(&self) -> &'static str {
        match self.field {
            "theme" => "/settings/theme",
            "busy_text" => "/settings/busy_text",
            "busy_text_by_locale" => "/settings/busy_text_by_locale",
            "dav_base_url" => "/settings/dav_base_url",
            "public_base_url" => "/settings/public_base_url",
            "allowed_components" => "/settings/allowed_components",
            "sender.local_part" => "/settings/sender/local_part",
            "scheduling.external_allowlist" => "/settings/scheduling/external_allowlist",
            "scheduling.inbound_methods" => "/settings/scheduling/inbound_methods",
            "client_config.apple_identifier_prefix" => "/settings/client_config/apple_identifier_prefix",
            "client_config.organization_name" => "/settings/client_config/organization_name",
            _ => "/settings",
        }
    }
}

text_enum!(
    /// Whether attendees outside the tenant may be invited.
    ExternalPolicy [] {
        /// Any external address may be invited.
        Allow => "allow",
        /// Only addresses and domains in `external_allowlist` may be invited.
        Allowlist => "allowlist",
        /// No external address may be invited.
        Deny => "deny",
    }
);

/// Sender identity of outgoing iMIP mail (`"{organizer} via {display name}" <local_part@domain>`).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct SenderSettings {
    /// Name shown after "via"; the tenant display name when unset.
    pub display_name: Option<String>,
    /// Local part of the sender address.
    pub local_part: String,
    /// Sender domain; mail cannot be sent for the tenant while unset.
    pub domain: Option<DomainName>,
}

impl Default for SenderSettings {
    fn default() -> Self {
        Self {
            display_name: None,
            local_part: "noreply".to_owned(),
            domain: None,
        }
    }
}

impl SenderSettings {
    /// The sender address, when a domain is configured and the local part is valid.
    pub fn address(&self) -> Option<Email> {
        let domain = self.domain.as_ref()?;
        Email::parse(&format!("{}@{domain}", self.local_part)).ok()
    }
}

/// Calendar sharing from client apps.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct SharingSettings {
    /// Whether clients may share calendars (CalendarServer sharing).
    pub enabled: bool,
    /// Skip the notification step: invitations are accepted automatically.
    pub auto_accept: bool,
}

impl Default for SharingSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_accept: false,
        }
    }
}

/// Scheduling behavior (PLAN 2.8).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct SchedulingSettings {
    /// Whether invitations are added to internal attendees' calendars automatically.
    pub auto_add_invitations: bool,
    /// Policy for attendees outside the tenant.
    pub external: ExternalPolicy,
    /// Lowercase domains (`example.org`) and addresses (`anna@example.org`) allowed under `allowlist`.
    pub external_allowlist: Vec<String>,
    /// Give attendees who already have a binding to the organizer's calendar an inbox item instead of a copy.
    pub suppress_duplicate_copies: bool,
    /// iTIP methods accepted by the inbound endpoint (`reply` only unless `request` or `cancel` are enabled).
    pub inbound_methods: Vec<ItipMethod>,
}

impl Default for SchedulingSettings {
    fn default() -> Self {
        Self {
            auto_add_invitations: true,
            external: ExternalPolicy::Allow,
            external_allowlist: Vec::new(),
            suppress_duplicate_copies: true,
            inbound_methods: vec![ItipMethod::Reply],
        }
    }
}

impl SchedulingSettings {
    /// Whether the external policy permits inviting `address`.
    ///
    /// `allow` permits everything, `deny` nothing. `allowlist` permits an address that is listed or whose domain
    /// is listed. Addresses without an e-mail form (URNs, principal URLs) are never external recipients and are
    /// never permitted by an allowlist.
    pub fn external_permits(&self, address: &CalendarUserAddress) -> bool {
        match self.external {
            ExternalPolicy::Allow => true,
            ExternalPolicy::Deny => false,
            ExternalPolicy::Allowlist => address.email().is_some_and(|email| {
                self.external_allowlist
                    .iter()
                    .any(|entry| entry == email.as_str() || entry == email.domain())
            }),
        }
    }
}

/// Branding used in generated client configuration.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ClientConfigSettings {
    /// Reverse-DNS prefix of Apple configuration profile identifiers (`{prefix}.caldav.{principal id}`).
    pub apple_identifier_prefix: Option<String>,
    /// Organization name shown in configuration profiles.
    pub organization_name: Option<String>,
}

/// Per-tenant settings (`tenants.settings`).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent feature toggles of the settings document"
)]
pub struct TenantSettings {
    /// Version of this document's schema; readers ignore fields they do not know.
    pub schema_version: u32,
    /// Default locale for mail and pages.
    pub locale: Locale,
    /// Default time zone for principals without one.
    pub timezone: TimeZoneName,
    /// Name of the template theme. Unset (the default) means the theme the deployment names in
    /// `templates.default_theme`, which is `default` unless the operator chose another: a tenant that has no
    /// branding of its own follows the deployment, and a tenant that names a theme keeps it whatever the deployment
    /// chooses later. Serialized as `null` when unset, like the other optional settings.
    pub theme: Option<String>,
    /// Sender identity of outgoing mail.
    pub sender: SenderSettings,
    /// Base URL of the DAV service when it differs from the public base URL.
    pub dav_base_url: Option<Url>,
    /// Per-tenant override of `server.public_base_url` for links in mail and feeds.
    pub public_base_url: Option<Url>,
    /// Access members of a group get on the group's calendars.
    pub group_default_access: GrantAccess,
    /// Create a personal calendar when a user principal is created.
    pub auto_create_personal_calendar: bool,
    /// Calendar sharing.
    pub sharing: SharingSettings,
    /// Scheduling behavior.
    pub scheduling: SchedulingSettings,
    /// Whether subscription feeds can be created and served.
    pub feeds_enabled: bool,
    /// The summary of the busy blocks of busy-mode feeds (PLAN 2.13), the same text in every language: "In a meeting",
    /// "Nicht verfügbar". It overrides the `feed_busy` template, and `busy_text_by_locale` overrides it for the languages
    /// that map names. Unset (the default) the summary is that template of the tenant's theme in the language of the feed's
    /// owner ("Busy", "Beschäftigt"). One to 100 characters, surrounding white space is removed; control characters, line
    /// and paragraph separators and invisible or bidirectional formatting characters are refused.
    #[schemars(length(min = 1, max = 100))]
    pub busy_text: Option<String>,
    /// The summary of the busy blocks of busy-mode feeds in each language the tenant names, as a map from a language tag
    /// (`de`, `en-GB`) to the text: `{"de": "Nicht verfügbar", "en": "Unavailable"}`. The reader of a feed gets the text of
    /// its own language, which is the language of the feed's owner (the principal's locale, else the tenant's): the tag is
    /// looked up as it is and then without its last subtag (`de-AT` finds `de`; `zh-Hant-TW` tries `zh-Hant`, then `zh`),
    /// and the first text found wins. A language the map does not name gets `busy_text` when that is set, and else the
    /// `feed_busy` template of the theme. Every text follows the rules of `busy_text`; at most 20 languages. Empty (the
    /// default) names none. A merge patch changes one language with its tag and removes it with `null`; a document that
    /// writes one tag twice in different spellings (`de-DE` and `de_de`) is refused.
    #[schemars(extend(
        "maxProperties" = MAX_BUSY_TEXT_LOCALES,
        "propertyNames" = {"type": "string", "maxLength": MAX_LANGUAGE_TAG_CHARS, "pattern": LANGUAGE_TAG_PATTERN},
        "additionalProperties" = {"type": "string", "minLength": 1, "maxLength": MAX_BUSY_TEXT_CHARS}
    ))]
    #[serde(deserialize_with = "deserialize_busy_texts")]
    pub busy_text_by_locale: BTreeMap<Locale, String>,
    /// Whether the MCP server is available to the tenant.
    pub mcp_enabled: bool,
    /// Branding for client configuration profiles.
    pub client_config: ClientConfigSettings,
    /// Component types calendars of the tenant may hold.
    pub allowed_components: Vec<ComponentKind>,
    /// Whether the login address counts as a calendar user address of the principal.
    pub login_address_is_cua: bool,
}

impl Default for TenantSettings {
    fn default() -> Self {
        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            locale: Locale::en(),
            timezone: TimeZoneName::utc(),
            theme: None,
            sender: SenderSettings::default(),
            dav_base_url: None,
            public_base_url: None,
            group_default_access: GrantAccess::ReadWrite,
            auto_create_personal_calendar: true,
            sharing: SharingSettings::default(),
            scheduling: SchedulingSettings::default(),
            feeds_enabled: true,
            busy_text: None,
            busy_text_by_locale: BTreeMap::new(),
            mcp_enabled: false,
            client_config: ClientConfigSettings::default(),
            allowed_components: ComponentKind::ALL.to_vec(),
            login_address_is_cua: false,
        }
    }
}

fn validate_theme(theme: &str) -> Result<(), SettingsError> {
    let ok = !theme.is_empty()
        && theme.len() <= 64
        && theme
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(SettingsError::new(
            "theme",
            "must be 1 to 64 characters of a-z, 0-9, - and _",
        ))
    }
}

/// Whether `c` has no place in a text that reaches every subscriber's calendar: a control character, a line or paragraph
/// separator, or an invisible or bidirectional formatting character that changes how a reader sees the text (a right-to-left
/// override reverses what follows it, a zero-width space hides a difference). The joiners that emoji and some scripts need
/// (U+200C, U+200D) stay allowed.
fn is_unfit_for_a_label(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}'            // Arabic letter mark
            | '\u{200B}'          // zero-width space
            | '\u{200E}' | '\u{200F}' // left-to-right and right-to-left marks
            | '\u{2028}' | '\u{2029}' // line and paragraph separators
            | '\u{202A}'..='\u{202E}' // bidirectional embeddings and overrides
            | '\u{2060}'          // word joiner
            | '\u{2066}'..='\u{2069}' // bidirectional isolates
            | '\u{FEFF}' // byte-order mark
        )
}

/// What is wrong with the text of a busy block. One rule for `busy_text` and for every text of `busy_text_by_locale`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BusyTextFault {
    Blank,
    TooLong,
    Unfit,
}

impl BusyTextFault {
    /// The first rule that `text` breaks.
    fn of(text: &str) -> Option<Self> {
        if text.trim().is_empty() {
            Some(Self::Blank)
        } else if text.chars().count() > MAX_BUSY_TEXT_CHARS {
            Some(Self::TooLong)
        } else if text.chars().any(is_unfit_for_a_label) {
            Some(Self::Unfit)
        } else {
            None
        }
    }

    /// The rule as a sentence that continues a subject; `blank` says what to do instead of leaving the text blank.
    fn reason(self, blank: &'static str) -> String {
        match self {
            Self::Blank => format!("must not be blank ({blank})"),
            Self::TooLong => format!("must be at most {MAX_BUSY_TEXT_CHARS} characters"),
            Self::Unfit => "must not contain control, line separator or invisible formatting characters".to_owned(),
        }
    }
}

fn validate_busy_text(text: &str) -> Result<(), SettingsError> {
    match BusyTextFault::of(text) {
        None => Ok(()),
        Some(fault) => Err(SettingsError::formatted(
            "busy_text",
            fault.reason("leave it unset to use the theme's text"),
        )),
    }
}

/// The texts per language: at most [`MAX_BUSY_TEXT_LOCALES`] of them, each under the rules of `busy_text`. The language tags
/// are valid by their type. The reason names the language of the first text that is refused, and the pointer is the map: a
/// pointer names a member of the body, and the tag is not a field of the settings.
fn validate_busy_texts(texts: &BTreeMap<Locale, String>) -> Result<(), SettingsError> {
    const FIELD: &str = "busy_text_by_locale";
    if texts.len() > MAX_BUSY_TEXT_LOCALES {
        return Err(SettingsError::formatted(
            FIELD,
            format!("must name at most {MAX_BUSY_TEXT_LOCALES} languages"),
        ));
    }
    for (locale, text) in texts {
        if let Some(fault) = BusyTextFault::of(text) {
            return Err(SettingsError::formatted(
                FIELD,
                format!(
                    "the text for `{locale}` {}",
                    fault.reason("remove the language to use `busy_text` or the theme's text instead")
                ),
            ));
        }
    }
    Ok(())
}

fn validate_url(field: &'static str, url: &Url) -> Result<(), SettingsError> {
    crate::urls::validate_base_url(url).map_err(|reason| SettingsError::new(field, reason))
}

fn validate_allowlist_entry(entry: &str) -> bool {
    if entry.contains('@') {
        Email::parse(entry).is_ok_and(|email| email.as_str() == entry)
    } else {
        DomainName::parse(entry).is_ok_and(|domain| domain.as_str() == entry)
    }
}

impl TenantSettings {
    /// The theme to ask a template renderer for: the name the tenant chose, or the empty string when it chose none,
    /// which a renderer answers with the default theme of the deployment (`templates.default_theme`).
    pub fn theme_name(&self) -> &str {
        self.theme.as_deref().unwrap_or_default()
    }

    /// The text the tenant named for the busy blocks of a reader whose language is `locale`, if it named one.
    ///
    /// The map `busy_text_by_locale` wins where it has the language: the tag is looked up as it is and then without its last
    /// subtag, until one is found (`de-AT` finds `de`; `zh-Hant-TW` tries `zh-Hant`, then `zh`). Where it has none the text is
    /// `busy_text`, the one text for every language. `None` leaves the summary to the `feed_busy` template. The text is
    /// returned as stored: the caller cleans it for the place it goes to.
    pub fn busy_text_for(&self, locale: &Locale) -> Option<&str> {
        let mut tag = locale.as_str();
        loop {
            if let Some(text) = self.busy_text_by_locale.get(tag) {
                return Some(text);
            }
            match tag.rsplit_once('-') {
                Some((shorter, _)) => tag = shorter,
                None => return self.busy_text.as_deref(),
            }
        }
    }

    /// Applies `edit` to the settings and returns them. Because the struct is `#[non_exhaustive]`, this is the
    /// way for other crates to build settings from the defaults in one expression.
    #[must_use]
    pub fn modified(mut self, edit: impl FnOnce(&mut Self)) -> Self {
        edit(&mut self);
        self
    }

    /// Checks the rules for settings written through the API.
    ///
    /// # Errors
    ///
    /// Returns a [`SettingsError`] naming the first invalid setting.
    pub fn validate(&self) -> Result<(), SettingsError> {
        if let Some(theme) = &self.theme {
            validate_theme(theme)?;
        }
        if let Some(text) = &self.busy_text {
            validate_busy_text(text)?;
        }
        validate_busy_texts(&self.busy_text_by_locale)?;
        if let Some(url) = &self.dav_base_url {
            validate_url("dav_base_url", url)?;
        }
        if let Some(url) = &self.public_base_url {
            validate_url("public_base_url", url)?;
        }
        if self.sender.domain.is_some() && self.sender.address().is_none() {
            return Err(SettingsError::new(
                "sender.local_part",
                "must form a valid address with the sender domain",
            ));
        }
        if self.allowed_components.is_empty() {
            return Err(SettingsError::new("allowed_components", "must not be empty"));
        }
        if self
            .scheduling
            .external_allowlist
            .iter()
            .any(|entry| !validate_allowlist_entry(entry))
        {
            return Err(SettingsError::new(
                "scheduling.external_allowlist",
                "entries must be lowercase domains or e-mail addresses",
            ));
        }
        if self.scheduling.external == ExternalPolicy::Allowlist && self.scheduling.external_allowlist.is_empty() {
            return Err(SettingsError::new(
                "scheduling.external_allowlist",
                "must not be empty when the external policy is allowlist",
            ));
        }
        if self
            .scheduling
            .inbound_methods
            .iter()
            .any(|method| !matches!(method, ItipMethod::Reply | ItipMethod::Request | ItipMethod::Cancel))
        {
            return Err(SettingsError::new(
                "scheduling.inbound_methods",
                "only reply, request and cancel can be accepted",
            ));
        }
        if let Some(prefix) = &self.client_config.apple_identifier_prefix {
            let ok = !prefix.is_empty()
                && prefix.len() <= 100
                && prefix
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
                && !prefix.starts_with('.')
                && !prefix.ends_with('.');
            if !ok {
                return Err(SettingsError::new(
                    "client_config.apple_identifier_prefix",
                    "must be a reverse-DNS prefix such as com.example",
                ));
            }
        }
        if self
            .client_config
            .organization_name
            .as_ref()
            .is_some_and(|name| name.len() > 100)
        {
            return Err(SettingsError::new(
                "client_config.organization_name",
                "must be at most 100 bytes",
            ));
        }
        Ok(())
    }

    /// Canonicalizes the settings (lowercase and deduplicated allowlist, deduplicated components and methods, the busy
    /// texts without their surrounding white space, the current schema version) and validates the result.
    ///
    /// # Errors
    ///
    /// Returns a [`SettingsError`] naming the first invalid setting.
    pub fn normalized(mut self) -> Result<Self, SettingsError> {
        self.schema_version = CURRENT_SCHEMA_VERSION;
        for entry in &mut self.scheduling.external_allowlist {
            *entry = entry.trim().to_ascii_lowercase();
        }
        self.scheduling.external_allowlist.sort();
        self.scheduling.external_allowlist.dedup();
        if let Some(text) = &mut self.busy_text {
            *text = text.trim().to_owned();
        }
        for text in self.busy_text_by_locale.values_mut() {
            *text = text.trim().to_owned();
        }
        self.allowed_components.sort();
        self.allowed_components.dedup();
        self.scheduling.inbound_methods.sort();
        self.scheduling.inbound_methods.dedup();
        self.validate()?;
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cua(text: &str) -> CalendarUserAddress {
        CalendarUserAddress::parse(text).unwrap()
    }

    #[test]
    fn defaults_follow_the_plan() {
        let settings = TenantSettings::default();
        assert_eq!(settings.schema_version, 1);
        assert_eq!(settings.locale.as_str(), "en");
        assert_eq!(settings.timezone, TimeZoneName::utc());
        assert_eq!(settings.group_default_access, GrantAccess::ReadWrite);
        assert!(settings.auto_create_personal_calendar);
        assert!(settings.sharing.enabled);
        assert!(!settings.sharing.auto_accept);
        assert!(settings.scheduling.auto_add_invitations);
        assert_eq!(settings.scheduling.external, ExternalPolicy::Allow);
        assert!(settings.scheduling.suppress_duplicate_copies);
        assert_eq!(settings.scheduling.inbound_methods, vec![ItipMethod::Reply]);
        assert!(settings.feeds_enabled);
        assert!(!settings.mcp_enabled);
        assert!(!settings.login_address_is_cua);
        assert_eq!(
            settings.allowed_components,
            vec![ComponentKind::Event, ComponentKind::Todo, ComponentKind::Journal]
        );
        settings.validate().unwrap();
    }

    #[test]
    fn an_empty_document_yields_the_defaults() {
        let parsed: TenantSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed, TenantSettings::default());
    }

    #[test]
    fn serde_round_trips_and_applies_defaults_per_field() {
        let parsed: TenantSettings = serde_json::from_str(
            r#"{"locale":"de-de","timezone":"Europe/Berlin","sharing":{"auto_accept":true},
                "scheduling":{"external":"allowlist","external_allowlist":["example.org"]},
                "group_default_access":"read"}"#,
        )
        .unwrap();
        assert_eq!(parsed.locale.as_str(), "de-DE");
        assert_eq!(parsed.timezone.as_str(), "Europe/Berlin");
        assert!(parsed.sharing.enabled, "missing nested field keeps its default");
        assert!(parsed.sharing.auto_accept);
        assert_eq!(parsed.scheduling.external, ExternalPolicy::Allowlist);
        assert_eq!(parsed.group_default_access, GrantAccess::Read);
        assert_eq!(
            parsed.theme, None,
            "a tenant that names no theme follows the deployment"
        );
        let again: TenantSettings = serde_json::from_str(&serde_json::to_string(&parsed).unwrap()).unwrap();
        assert_eq!(again, parsed);
    }

    #[test]
    fn unknown_fields_from_newer_releases_are_ignored() {
        let parsed: TenantSettings =
            serde_json::from_str(r#"{"schema_version":7,"quantum_mode":true,"sharing":{"future":1}}"#).unwrap();
        assert_eq!(parsed.schema_version, 7);
        assert_eq!(parsed.sharing, SharingSettings::default());
    }

    #[test]
    fn invalid_values_are_rejected_when_reading() {
        assert!(serde_json::from_str::<TenantSettings>(r#"{"timezone":"Mars/Base"}"#).is_err());
        assert!(serde_json::from_str::<TenantSettings>(r#"{"locale":"!!"}"#).is_err());
        assert!(serde_json::from_str::<TenantSettings>(r#"{"group_default_access":"owner"}"#).is_err());
    }

    #[test]
    fn external_policy_decisions() {
        let mut scheduling = SchedulingSettings::default();
        assert!(scheduling.external_permits(&cua("mailto:x@anywhere.example")));

        scheduling.external = ExternalPolicy::Deny;
        assert!(!scheduling.external_permits(&cua("mailto:x@anywhere.example")));

        scheduling.external = ExternalPolicy::Allowlist;
        scheduling.external_allowlist = vec!["example.org".to_owned(), "vip@other.example".to_owned()];
        assert!(scheduling.external_permits(&cua("mailto:anyone@example.org")));
        assert!(scheduling.external_permits(&cua("mailto:ANYONE@Example.Org")));
        assert!(scheduling.external_permits(&cua("mailto:vip@other.example")));
        assert!(!scheduling.external_permits(&cua("mailto:nobody@other.example")));
        assert!(!scheduling.external_permits(&cua("mailto:anyone@sub.example.org")));
        assert!(!scheduling.external_permits(&cua("urn:uuid:018f3c1e-7b2a-7c3d-9e4f-0123456789ab")));
        assert!(!scheduling.external_permits(&cua("/dav/principals/acme/anna/")));
    }

    #[test]
    fn sender_address_needs_a_domain() {
        let mut sender = SenderSettings::default();
        assert_eq!(sender.address(), None);
        sender.domain = Some(DomainName::parse("Mail.Example.org").unwrap());
        assert_eq!(sender.address().unwrap().as_str(), "noreply@mail.example.org");
        sender.local_part = "no reply".to_owned();
        assert_eq!(sender.address(), None);
    }

    #[test]
    fn validation_names_the_first_invalid_field() {
        let check = |edit: &dyn Fn(&mut TenantSettings)| {
            let mut settings = TenantSettings::default();
            edit(&mut settings);
            settings.validate().unwrap_err().field()
        };
        assert_eq!(check(&|s| s.theme = Some(String::new())), "theme");
        assert_eq!(check(&|s| s.theme = Some("Big Theme".to_owned())), "theme");
        assert_eq!(
            check(&|s| s.public_base_url = Some(Url::parse("ftp://example.org/").unwrap())),
            "public_base_url"
        );
        assert_eq!(
            check(&|s| s.dav_base_url = Some(Url::parse("https://example.org/prefix/").unwrap())),
            "dav_base_url"
        );
        assert_eq!(check(&|s| s.allowed_components.clear()), "allowed_components");
        assert_eq!(
            check(&|s| {
                s.sender.domain = Some(DomainName::parse("example.org").unwrap());
                s.sender.local_part = "a b".to_owned();
            }),
            "sender.local_part"
        );
        assert_eq!(
            check(&|s| s.scheduling.external_allowlist = vec!["Not A Domain".to_owned()]),
            "scheduling.external_allowlist"
        );
        assert_eq!(
            check(&|s| s.scheduling.external = ExternalPolicy::Allowlist),
            "scheduling.external_allowlist"
        );
        assert_eq!(
            check(&|s| s.scheduling.inbound_methods = vec![ItipMethod::Publish]),
            "scheduling.inbound_methods"
        );
        assert_eq!(
            check(&|s| s.client_config.apple_identifier_prefix = Some("..bad".to_owned())),
            "client_config.apple_identifier_prefix"
        );
        assert_eq!(
            check(&|s| s.client_config.organization_name = Some("x".repeat(101))),
            "client_config.organization_name"
        );
        for bad in [
            String::new(),
            "  \t ".to_owned(),
            "x".repeat(101),
            "Busy\nBcc: x".to_owned(),
            // Characters that hide or reverse what a reader sees, and the separators that end a line without a line break.
            "Busy\u{202E}live".to_owned(),
            "Busy\u{2066}x\u{2069}".to_owned(),
            "Bu\u{200B}sy".to_owned(),
            "Busy\u{200E}".to_owned(),
            "Busy\u{2028}x".to_owned(),
            "Busy\u{2029}x".to_owned(),
            "\u{FEFF}Busy".to_owned(),
            "Bu\u{2060}sy".to_owned(),
            "Busy\u{85}x".to_owned(),
        ] {
            assert_eq!(check(&|s| s.busy_text = Some(bad.clone())), "busy_text", "{bad:?}");
        }
    }

    #[test]
    fn the_busy_text_keeps_the_characters_that_emoji_and_scripts_need() {
        for good in [
            "In a meeting",
            "Nicht verfügbar – zurück um 14:00",
            "Out, back soon; a\\b",
            "会議中",
            "😀 busy",
            "👨\u{200D}👩\u{200D}👧 family time",
            "می\u{200C}خواهم",
        ] {
            TenantSettings::default()
                .modified(|s| s.busy_text = Some(good.to_owned()))
                .validate()
                .unwrap_or_else(|error| panic!("{good:?}: {error}"));
        }
    }

    #[test]
    fn the_message_of_the_limit_names_the_constant() {
        let error = TenantSettings::default()
            .modified(|s| s.busy_text = Some("x".repeat(MAX_BUSY_TEXT_CHARS + 1)))
            .validate()
            .unwrap_err();
        assert_eq!(
            error.reason(),
            format!("must be at most {MAX_BUSY_TEXT_CHARS} characters"),
            "the text follows the constant"
        );
        assert_eq!(
            error.to_string(),
            format!("invalid tenant setting `busy_text`: must be at most {MAX_BUSY_TEXT_CHARS} characters")
        );
    }

    #[test]
    fn the_schema_states_the_bounds_of_the_busy_text() {
        let schema = schemars::schema_for!(TenantSettings);
        let busy_text = &schema.as_value()["properties"]["busy_text"];
        assert_eq!(
            busy_text["maxLength"], MAX_BUSY_TEXT_CHARS,
            "the API contract says what the validation enforces: {busy_text}"
        );
        assert_eq!(busy_text["minLength"], 1, "{busy_text}");
    }

    #[test]
    fn every_invalid_setting_names_the_pointer_of_the_setting() {
        let edits: [fn(&mut TenantSettings); 11] = [
            |s| s.theme = Some(String::new()),
            |s| s.busy_text = Some(String::new()),
            |s| {
                s.busy_text_by_locale.insert(Locale::de(), String::new());
            },
            |s| s.public_base_url = Some(Url::parse("ftp://example.org/").unwrap()),
            |s| s.dav_base_url = Some(Url::parse("https://example.org/prefix/").unwrap()),
            |s| s.allowed_components.clear(),
            |s| {
                s.sender.domain = Some(DomainName::parse("example.org").unwrap());
                s.sender.local_part = "a b".to_owned();
            },
            |s| s.scheduling.external_allowlist = vec!["Not A Domain".to_owned()],
            |s| s.scheduling.inbound_methods = vec![ItipMethod::Publish],
            |s| s.client_config.apple_identifier_prefix = Some("..bad".to_owned()),
            |s| s.client_config.organization_name = Some("x".repeat(101)),
        ];
        for edit in edits {
            let mut settings = TenantSettings::default();
            edit(&mut settings);
            let error = settings.validate().unwrap_err();
            let expected = format!("/settings/{}", error.field().replace('.', "/"));
            assert_eq!(
                error.pointer(),
                expected,
                "the pointer of `{}` is the field with its dots as slashes",
                error.field()
            );
        }
        // A setting this function does not know is answered with the settings as a whole, never with another field.
        assert_eq!(SettingsError::new("future.setting", "x").pointer(), "/settings");
    }

    #[test]
    fn the_busy_text_is_unset_by_default_trimmed_and_bounded() {
        let settings = TenantSettings::default();
        assert_eq!(
            settings.busy_text, None,
            "the theme's text applies unless the tenant names its own"
        );
        settings.validate().unwrap();
        let named = TenantSettings::default().modified(|s| s.busy_text = Some("  In a meeting \t".to_owned()));
        assert_eq!(
            named.normalized().unwrap().busy_text.as_deref(),
            Some("In a meeting"),
            "surrounding white space is not part of the text"
        );
        let longest = "ä".repeat(MAX_BUSY_TEXT_CHARS);
        TenantSettings::default()
            .modified(|s| s.busy_text = Some(longest.clone()))
            .validate()
            .unwrap();
        // Read from the stored document as the other settings are: absent is unset, null is unset.
        for document in ["{}", r#"{"busy_text":null}"#] {
            assert_eq!(
                serde_json::from_str::<TenantSettings>(document).unwrap().busy_text,
                None
            );
        }
        let stored: TenantSettings = serde_json::from_str(r#"{"busy_text":"Nicht verfügbar"}"#).unwrap();
        assert_eq!(stored.busy_text.as_deref(), Some("Nicht verfügbar"));
    }

    /// Settings whose busy texts are `texts` (language tag, text) and whose single text is `single`.
    fn with_busy_texts(single: Option<&str>, texts: &[(&str, &str)]) -> TenantSettings {
        TenantSettings::default().modified(|s| {
            s.busy_text = single.map(str::to_owned);
            s.busy_text_by_locale = texts
                .iter()
                .map(|(tag, text)| (Locale::parse(tag).unwrap(), (*text).to_owned()))
                .collect();
        })
    }

    #[test]
    fn the_busy_text_of_a_language_wins_over_the_single_text() {
        let locale = |tag: &str| Locale::parse(tag).unwrap();
        let settings = with_busy_texts(
            Some("Busy"),
            &[("de", "Nicht verfügbar"), ("en-GB", "Unavailable"), ("zh-Hant", "忙碌")],
        );
        // The tag as it is, and then without its last subtag.
        assert_eq!(settings.busy_text_for(&locale("de")), Some("Nicht verfügbar"));
        assert_eq!(settings.busy_text_for(&locale("de-AT")), Some("Nicht verfügbar"));
        assert_eq!(settings.busy_text_for(&locale("en-GB")), Some("Unavailable"));
        assert_eq!(settings.busy_text_for(&locale("zh-Hant-TW")), Some("忙碌"));
        // A language that the map does not name, or names only in another region, gets the single text.
        assert_eq!(settings.busy_text_for(&locale("fr")), Some("Busy"));
        assert_eq!(
            settings.busy_text_for(&locale("en")),
            Some("Busy"),
            "`en-GB` is a narrower tag than `en`: it does not answer for the language as a whole"
        );
        assert_eq!(settings.busy_text_for(&locale("zh")), Some("Busy"));

        // The most specific tag wins, whatever the order of the map.
        let both = with_busy_texts(None, &[("de", "Allgemein"), ("de-AT", "Österreich")]);
        assert_eq!(both.busy_text_for(&locale("de-AT")), Some("Österreich"));
        assert_eq!(both.busy_text_for(&locale("de-CH")), Some("Allgemein"));
        assert_eq!(both.busy_text_for(&locale("de")), Some("Allgemein"));

        // Without a single text a language that is not named has none: the template speaks.
        assert_eq!(both.busy_text_for(&locale("fr")), None);
        assert_eq!(TenantSettings::default().busy_text_for(&locale("de")), None);
        // Without a map the single text is the text of every language, as before the map existed.
        let single = with_busy_texts(Some("In a meeting"), &[]);
        assert_eq!(single.busy_text_for(&locale("de")), Some("In a meeting"));
        assert_eq!(single.busy_text_for(&locale("zh-Hant-TW")), Some("In a meeting"));
    }

    #[test]
    fn the_busy_texts_per_language_are_empty_by_default_and_read_like_the_other_settings() {
        let defaults = TenantSettings::default();
        assert!(defaults.busy_text_by_locale.is_empty());
        defaults.validate().unwrap();
        // A document stored before the map existed has none, and a newer one is read as it is written.
        assert!(
            serde_json::from_str::<TenantSettings>(r#"{"busy_text":"Busy"}"#)
                .unwrap()
                .busy_text_by_locale
                .is_empty()
        );
        let stored: TenantSettings = serde_json::from_str(
            r#"{"busy_text":"Busy","busy_text_by_locale":{"de":"Nicht verfügbar","en-GB":"Out"}}"#,
        )
        .unwrap();
        assert_eq!(stored.busy_text.as_deref(), Some("Busy"), "the single text stays valid");
        assert_eq!(
            stored.busy_text_by_locale,
            with_busy_texts(None, &[("de", "Nicht verfügbar"), ("en-GB", "Out")]).busy_text_by_locale
        );
        let written = serde_json::to_value(&stored).unwrap();
        assert_eq!(
            written["busy_text_by_locale"],
            serde_json::json!({"de": "Nicht verfügbar", "en-GB": "Out"}),
            "the map is written as an object of tags"
        );
        assert_eq!(serde_json::from_value::<TenantSettings>(written).unwrap(), stored);
        // The tags are normalized like every locale, and one that is none is refused when reading.
        let spelled: TenantSettings =
            serde_json::from_str(r#"{"busy_text_by_locale":{"de_at":"Nicht verfügbar"}}"#).unwrap();
        assert_eq!(
            spelled
                .busy_text_by_locale
                .keys()
                .map(Locale::as_str)
                .collect::<Vec<_>>(),
            ["de-AT"]
        );
        assert!(serde_json::from_str::<TenantSettings>(r#"{"busy_text_by_locale":{"!!":"x"}}"#).is_err());
        assert!(serde_json::from_str::<TenantSettings>(r#"{"busy_text_by_locale":{"de":1}}"#).is_err());
    }

    #[test]
    fn every_text_of_the_map_follows_the_rules_of_the_single_text() {
        let too_long = "x".repeat(MAX_BUSY_TEXT_CHARS + 1);
        let check = |texts: &[(&str, &str)]| with_busy_texts(None, texts).validate().unwrap_err();
        for bad in [
            String::new(),
            "  \t ".to_owned(),
            too_long.clone(),
            "Busy\nBcc: x".to_owned(),
            "Busy\u{202E}live".to_owned(),
            "Bu\u{200B}sy".to_owned(),
        ] {
            let error = check(&[("en", "Fine"), ("de", bad.as_str())]);
            assert_eq!(error.field(), "busy_text_by_locale", "{bad:?}");
            assert_eq!(error.pointer(), "/settings/busy_text_by_locale", "{bad:?}");
            assert!(
                error.reason().starts_with("the text for `de` must "),
                "the reason names the language: {error}"
            );
        }
        // The same texts are no problem in a language of their own when they are fine.
        let longest = "ä".repeat(MAX_BUSY_TEXT_CHARS);
        for good in ["In a meeting", "会議中", "😀 busy", "می\u{200C}خواهم", longest.as_str()] {
            with_busy_texts(None, &[("de", good)])
                .validate()
                .unwrap_or_else(|error| panic!("{good:?}: {error}"));
        }
        assert_eq!(
            check(&[("de", too_long.as_str())]).reason(),
            format!("the text for `de` must be at most {MAX_BUSY_TEXT_CHARS} characters"),
            "the text follows the constant"
        );
    }

    #[test]
    fn the_map_names_a_bounded_number_of_languages() {
        let tags = [
            "aa", "ab", "af", "ak", "am", "an", "ar", "as", "av", "ay", "az", "ba", "be", "bg", "bi", "bm", "bn", "bo",
            "br", "bs", "ca",
        ];
        assert_eq!(tags.len(), MAX_BUSY_TEXT_LOCALES + 1);
        let texts: Vec<(&str, &str)> = tags.iter().map(|tag| (*tag, "Busy")).collect();
        let allowed = with_busy_texts(None, &texts[..MAX_BUSY_TEXT_LOCALES]);
        allowed.validate().unwrap();
        let error = with_busy_texts(None, &texts).validate().unwrap_err();
        assert_eq!(
            (error.field(), error.reason()),
            (
                "busy_text_by_locale",
                format!("must name at most {MAX_BUSY_TEXT_LOCALES} languages").as_str()
            )
        );
    }

    #[test]
    fn the_texts_of_the_map_are_trimmed_by_normalization() {
        let normalized = with_busy_texts(None, &[("de", "  Nicht verfügbar \t"), ("en", "Out")])
            .normalized()
            .unwrap();
        assert_eq!(
            normalized.busy_text_by_locale,
            with_busy_texts(None, &[("de", "Nicht verfügbar"), ("en", "Out")]).busy_text_by_locale
        );
        // A text that is only white space is blank after the trim and refused, not stored as an empty summary.
        assert!(with_busy_texts(None, &[("de", "   ")]).normalized().is_err());
    }

    #[test]
    fn the_schema_states_the_bounds_of_the_busy_texts_per_language() {
        let schema = schemars::schema_for!(TenantSettings);
        let map = &schema.as_value()["properties"]["busy_text_by_locale"];
        assert_eq!(map["type"], "object", "{map}");
        assert_eq!(
            map["maxProperties"], MAX_BUSY_TEXT_LOCALES,
            "the API contract says what the validation enforces: {map}"
        );
        let text = &map["additionalProperties"];
        assert_eq!(text["type"], "string", "{map}");
        assert_eq!(text["minLength"], 1, "{map}");
        assert_eq!(text["maxLength"], MAX_BUSY_TEXT_CHARS, "{map}");
        // The keys are language tags: the schema says what `Locale` accepts, and the limit is the one of the type.
        let tags = &map["propertyNames"];
        assert_eq!(tags["type"], "string", "{map}");
        assert_eq!(tags["maxLength"], MAX_LANGUAGE_TAG_CHARS, "{map}");
        assert_eq!(tags["pattern"], LANGUAGE_TAG_PATTERN, "{map}");
        let longest = format!("de{}", "-aaaaaaaa".repeat(3) + "-aaaaa");
        assert_eq!(longest.len(), MAX_LANGUAGE_TAG_CHARS);
        assert!(
            Locale::parse(&longest).is_ok() && Locale::parse(&format!("{longest}a")).is_err(),
            "the limit that the schema repeats is the one of the type"
        );
    }

    #[test]
    fn one_tag_in_two_spellings_is_refused_instead_of_the_later_key_winning() {
        // The tags are canonical after reading, so `de-DE` and `de_de` are one key. Reading them as a map would keep one text
        // and drop the other without a word, which one depending on the order of the keys.
        for document in [
            r#"{"busy_text_by_locale":{"de-DE":"a","de_de":"b"}}"#,
            r#"{"busy_text_by_locale":{"EN":"a","en":"b"}}"#,
        ] {
            let error = serde_json::from_str::<TenantSettings>(document)
                .unwrap_err()
                .to_string();
            assert!(busy_texts_repeat_a_tag(&error), "{document}: {error}");
        }
        // Another failure of the map is not that one, and different tags are no repetition.
        assert!(!busy_texts_repeat_a_tag(
            &serde_json::from_str::<TenantSettings>(r#"{"busy_text_by_locale":{"!!":"a"}}"#)
                .unwrap_err()
                .to_string()
        ));
        let two: TenantSettings =
            serde_json::from_str(r#"{"busy_text_by_locale":{"de":"a","de-AT":"b","de_ch":"c"}}"#).unwrap();
        assert_eq!(two.busy_text_by_locale.len(), 3);
    }

    #[test]
    fn normalization_canonicalizes_before_validating() {
        let settings = TenantSettings::default().modified(|s| {
            s.schema_version = 0;
            s.scheduling.external = ExternalPolicy::Allowlist;
            s.scheduling.external_allowlist = vec![
                " Example.ORG ".to_owned(),
                "example.org".to_owned(),
                "A@B.example".to_owned(),
            ];
            s.allowed_components = vec![ComponentKind::Todo, ComponentKind::Event, ComponentKind::Todo];
            s.scheduling.inbound_methods = vec![ItipMethod::Reply, ItipMethod::Reply];
        });
        let normalized = settings.normalized().unwrap();
        assert_eq!(normalized.schema_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(
            normalized.scheduling.external_allowlist,
            vec!["a@b.example", "example.org"]
        );
        assert_eq!(
            normalized.allowed_components,
            vec![ComponentKind::Event, ComponentKind::Todo]
        );
        assert_eq!(normalized.scheduling.inbound_methods, vec![ItipMethod::Reply]);

        let bad = TenantSettings::default().modified(|s| s.theme = Some("NO".to_owned()));
        assert!(bad.normalized().is_err());
    }

    #[test]
    fn error_text_names_field_and_reason() {
        let err = SettingsError::new("theme", "must be tidy");
        assert_eq!(err.to_string(), "invalid tenant setting `theme`: must be tidy");
        assert_eq!(err.reason(), "must be tidy");
    }
}
