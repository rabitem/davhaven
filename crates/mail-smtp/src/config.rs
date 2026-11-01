//! Configuration of the SMTP transport.
//!
//! The `[plugin.smtp]` table. Credentials follow the secret convention: only the file of the password is named
//! in the configuration. The transport always uses rustls with the ring provider; `tls = "none"` exists for a
//! capture server (Mailpit). In production mode the plugin refuses it for a relay on another host, where mail
//! would cross the network in the clear, unless `allow_insecure_transport` accepts that for a capture server on a
//! private network; a login is never accepted over it (see [`check_transport`](crate::plugin::check_transport)).
//!
//! # Time
//!
//! `timeout` bounds connecting and every command; `total_timeout` bounds the whole mail. The outbox cancels a
//! handler after 80 % of its lease, and the iMIP handler gives the send 60 % of it, so `total_timeout` must stay
//! below 60 % of `outbox.lease` (30 s of the default minute). A relay that is slow but never fails is then cut off
//! by the transport itself, reported as a timeout and counted towards the circuit breaker.

use core::fmt;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use davhaven_ports::{PluginError, read_secret_file};
use schemars::JsonSchema;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

/// The name of the plugin.
pub const PLUGIN: &str = "smtp";

/// How the connection to the relay is secured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SmtpTls {
    /// Connect in plain text and upgrade with `STARTTLS` (port 587); the upgrade is mandatory.
    #[default]
    Starttls,
    /// TLS from the first byte (port 465). `tls` is accepted as another spelling of it.
    #[serde(alias = "tls")]
    Implicit,
    /// No encryption: for a capture server (Mailpit) on the same host. A relay on another host is refused in
    /// production mode unless `allow_insecure_transport` accepts it for a capture server on a private network, and
    /// then without a login: a capture server needs none, and a login over `none` would be sent in the clear.
    None,
}

/// The `[plugin.smtp]` table.
#[derive(Clone, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct SmtpConfig {
    /// The relay's host name.
    pub host: String,
    /// The relay's port.
    pub port: u16,
    /// The login name; set together with `password_file`.
    pub username: Option<String>,
    /// A file that contains the password.
    pub password_file: Option<PathBuf>,
    /// How the connection is secured.
    pub tls: SmtpTls,
    /// The name the server gives itself in `EHLO`. Relays judge it (some refuse or penalize a name that is not a
    /// fully qualified domain), so set it to a name of this deployment that resolves, for example the domain of the
    /// sender address. Without it the transport says `localhost`; the name of the machine is never used, because in a
    /// container it is a random identifier.
    pub ehlo_name: Option<String>,
    /// The timeout of connecting and of each SMTP command.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub timeout: Duration,
    /// The longest one mail may take from the first byte to the answer to the end of the data. It has to stay
    /// below 60 % of `outbox.lease` (the handler gives a send that share and counts a longer one as a failure of
    /// the relay); the default of 30 s fits the default lease of a minute.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub total_timeout: Duration,
    /// Production only: accepts `tls = "none"` to a relay on another host, for a capture server on a private
    /// network such as the mail catcher of a staging deployment. Invitations and RSVP links then travel
    /// unencrypted, so production refuses that combination unless this is set. It never accepts a login: with
    /// `username` and `password_file` set, production refuses `tls = "none"` to another host whatever this says.
    /// A relay on this host (`localhost` or a loopback address) is never flagged; in `dev` mode the finding is
    /// only logged.
    pub allow_insecure_transport: bool,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            host: "localhost".to_owned(),
            port: 587,
            username: None,
            password_file: None,
            tls: SmtpTls::Starttls,
            ehlo_name: None,
            timeout: Duration::from_secs(8),
            total_timeout: Duration::from_secs(30),
            allow_insecure_transport: false,
        }
    }
}

impl fmt::Debug for SmtpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmtpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username.as_ref().map(|_| "<redacted>"))
            .field("password_file", &self.password_file)
            .field("tls", &self.tls)
            .field("ehlo_name", &self.ehlo_name)
            .field("timeout", &self.timeout)
            .field("total_timeout", &self.total_timeout)
            .field("allow_insecure_transport", &self.allow_insecure_transport)
            .finish()
    }
}

impl SmtpConfig {
    /// Checks the values: a host, a port, a timeout and credentials that come as a pair.
    ///
    /// # Errors
    ///
    /// [`PluginError::InvalidConfig`] naming the offending key.
    pub fn validate(&self) -> Result<(), PluginError> {
        let invalid = |message: &str| PluginError::invalid_config(PLUGIN, message);
        if self.host.trim().is_empty() || self.host.contains(char::is_whitespace) {
            return Err(invalid("`host` must be a host name"));
        }
        if self.port == 0 {
            return Err(invalid("`port` must be between 1 and 65535"));
        }
        if let Some(name) = &self.ehlo_name {
            let plausible = !name.is_empty()
                && name.len() <= 253
                && name.is_ascii()
                && !name.starts_with(['.', '-'])
                && !name.ends_with(['.', '-'])
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
            if !plausible {
                return Err(invalid(
                    "`ehlo_name` must be a host name (letters, digits, dots and dashes)",
                ));
            }
        }
        if self.timeout.is_zero() {
            return Err(invalid("`timeout` must be greater than zero"));
        }
        if self.total_timeout < self.timeout {
            return Err(invalid("`total_timeout` must not be shorter than `timeout`"));
        }
        match (&self.username, &self.password_file) {
            (Some(_), None) => Err(invalid("`password_file` is required when `username` is set")),
            (None, Some(_)) => Err(invalid("`username` is required when `password_file` is set")),
            _ => Ok(()),
        }
    }

    /// Whether mail leaves this host unencrypted: `tls = "none"` to a relay on another host.
    pub(crate) fn sends_in_the_clear(&self) -> bool {
        self.tls == SmtpTls::None && !is_local(&self.host)
    }

    /// The password, read from `password_file`; `None` for relays without authentication.
    ///
    /// # Errors
    ///
    /// [`PluginError::InvalidConfig`] when the file cannot be read.
    pub fn password(&self) -> Result<Option<SecretString>, PluginError> {
        self.password_file
            .as_deref()
            .map(|path| read_secret_file(PLUGIN, "password_file", path))
            .transpose()
    }
}

/// Whether `host` names this machine, where an unencrypted connection stays on it: `localhost` or a loopback address
/// (all of `127.0.0.0/8`, `::1`, and an IPv4-mapped loopback address), the same rule as for the database. Any other
/// host is "another host", including a name that merely starts like these (`localhost.example.org`) and one that
/// resolves to this machine: names are not resolved.
pub(crate) fn is_local(host: &str) -> bool {
    let host = host.trim().trim_matches(['[', ']']);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.to_canonical().is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> SmtpConfig {
        davhaven_ports::parse_config(PLUGIN, serde_json::from_str(text).unwrap()).unwrap()
    }

    #[test]
    fn defaults_describe_a_submission_port_with_starttls() {
        let config = parse("{}");
        assert_eq!((config.host.as_str(), config.port), ("localhost", 587));
        assert_eq!(config.tls, SmtpTls::Starttls);
        assert_eq!(config.ehlo_name, None);
        assert_eq!(config.timeout, Duration::from_secs(8));
        assert_eq!(config.total_timeout, Duration::from_secs(30));
        assert!(!config.allow_insecure_transport);
        config.validate().unwrap();
        assert!(config.password().unwrap().is_none());
    }

    #[test]
    fn keys_parse_and_typos_are_refused() {
        let config = parse(
            r#"{"host": "smtp.example.org", "port": 465, "username": "davhaven", "password_file": "/run/secrets/smtp",
                "tls": "implicit", "timeout": "10s", "total_timeout": "40s", "ehlo_name": "mail.example.org"}"#,
        );
        assert_eq!(config.ehlo_name.as_deref(), Some("mail.example.org"));
        assert_eq!(config.tls, SmtpTls::Implicit);
        assert_eq!(config.timeout, Duration::from_secs(10));
        assert_eq!(config.total_timeout, Duration::from_secs(40));
        config.validate().unwrap();
        assert!(davhaven_ports::parse_config::<SmtpConfig>(PLUGIN, serde_json::json!({"passwort_file": "x"})).is_err());
        assert!(davhaven_ports::parse_config::<SmtpConfig>(PLUGIN, serde_json::json!({"tls": "ssl"})).is_err());
    }

    #[test]
    fn tls_is_accepted_as_another_spelling_of_implicit_tls_and_the_schema_shows_the_default() {
        assert_eq!(parse(r#"{"tls": "tls"}"#).tls, SmtpTls::Implicit);
        assert_eq!(parse(r#"{"tls": "implicit"}"#).tls, SmtpTls::Implicit);
        let schema = schemars::schema_for!(SmtpConfig);
        let tls = schema.as_value()["properties"]["tls"].to_string();
        assert!(
            tls.contains("starttls"),
            "the generated reference shows the default of `tls`: {tls}"
        );
    }
    #[test]
    fn validation_names_the_key() {
        for (text, key) in [
            (r#"{"host": ""}"#, "host"),
            (r#"{"host": "a b"}"#, "host"),
            (r#"{"port": 0}"#, "port"),
            (r#"{"ehlo_name": ""}"#, "ehlo_name"),
            (r#"{"ehlo_name": "mail example.org"}"#, "ehlo_name"),
            (r#"{"ehlo_name": "mail@example.org"}"#, "ehlo_name"),
            (r#"{"ehlo_name": "-example.org"}"#, "ehlo_name"),
            (r#"{"timeout": "0s"}"#, "timeout"),
            (r#"{"timeout": "20s", "total_timeout": "10s"}"#, "total_timeout"),
            (r#"{"username": "u"}"#, "password_file"),
            (r#"{"password_file": "/x"}"#, "username"),
        ] {
            let error = parse(text).validate().unwrap_err().to_string();
            assert!(error.contains(key), "{text}: {error}");
        }
    }

    #[test]
    fn debug_output_hides_the_login() {
        let shown = format!("{:?}", parse(r#"{"username": "secret-login", "password_file": "/x"}"#));
        assert!(!shown.contains("secret-login"), "{shown}");
    }
}
