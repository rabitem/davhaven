//! Registration of the adapter in the plugin registry.
//!
//! One plugin of the `mail_transport` kind: `smtp`. In production mode a relay without encryption is refused unless
//! it runs on this host or `allow_insecure_transport` accepts the risk: invitations, RSVP links and attendee data
//! would travel in the clear. A login is never accepted without encryption (the password of a relay that needs
//! one would travel in the clear too), whatever the opt-in says. [`check_transport`] is that rule; `config check`
//! applies it as well.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use davhaven_ports::{
    Built, MailTransport, PluginCheck, PluginContext, PluginDescriptor, PluginError, PluginRegistry, PortKind, RunMode,
    parse_config,
};
use schemars::Schema;

use crate::config::{PLUGIN, SmtpConfig};
use crate::transport::SmtpMailTransport;

/// Registers the `smtp` mail transport.
///
/// # Errors
///
/// [`PluginError::DuplicateName`] when the registry has it already.
pub fn register(registry: &mut PluginRegistry) -> Result<(), PluginError> {
    registry.register(
        PortKind::MAIL_TRANSPORT,
        PluginDescriptor::new(
            PLUGIN,
            "Sends mail to an SMTP relay with lettre over rustls (STARTTLS or implicit TLS), one connection per mail, \
             with an optional login.",
            schema,
            build,
        )
        .with_check(check_config),
    )
}

/// The check of `davhaven config check`: the table parses and validates as `build` would have it, the password file is
/// read, and the transport rule of production ([`check_transport`]) is applied. Nothing connects.
///
/// # Errors
///
/// [`PluginError::InvalidConfig`] for what `build` would refuse before it connects.
fn check_config(check: &PluginCheck<'_>) -> Result<Vec<String>, PluginError> {
    let config = config(check.table.clone())?;
    config.password()?;
    check_transport(&config, check.mode)
}

/// The table of the transport as a validated configuration: the one reading that `build` and the check of
/// `davhaven config check` share, so that the check says what `serve` will say.
fn config(table: serde_json::Value) -> Result<SmtpConfig, PluginError> {
    let config: SmtpConfig = parse_config(PLUGIN, table)?;
    config.validate()?;
    Ok(config)
}

fn schema() -> Schema {
    schemars::schema_for!(SmtpConfig)
}

/// The future a plugin build returns.
type Building = Pin<Box<dyn Future<Output = Result<Built<dyn MailTransport>, PluginError>> + Send>>;

/// The transport rule of production mode, without connecting; the plugin build and `config check` both apply it.
///
/// A relay on another host (`localhost` and loopback addresses are this host; any other name is not, and names are
/// never resolved) must be reached with TLS (`starttls` or `implicit`). `tls = "none"` to such a relay is refused in
/// production unless
/// `plugin.smtp.allow_insecure_transport` accepts it for a capture server on a private network, and a login is
/// refused over it even then: a capture server needs none, and the password would travel in the clear. In `dev` mode
/// the choice is the operator's, and a relay on this host never leaves the machine.
///
/// The warnings are for the operator and are not errors: mail that travels unencrypted (in `dev` mode, or because
/// the opt-in accepted it), and an opt-in that has no effect because the relay is reached with TLS or runs on this
/// host, which would accept a later change of `tls` or `host` without a word.
///
/// # Errors
///
/// [`PluginError::InvalidConfig`] where production would refuse to start.
pub fn check_transport(config: &SmtpConfig, mode: RunMode) -> Result<Vec<String>, PluginError> {
    if !config.sends_in_the_clear() {
        let stale = config.allow_insecure_transport.then(|| {
            "`plugin.smtp.allow_insecure_transport` is set but has no effect: the relay is reached with TLS or runs on \
             this host. Remove it, so that a later change of `tls` or `host` is not accepted silently"
                .to_owned()
        });
        return Ok(stale.into_iter().collect());
    }
    let login = config.username.is_some() || config.password_file.is_some();
    if mode.is_production() {
        if login {
            return Err(PluginError::invalid_config(
                PLUGIN,
                "`tls = \"none\"` for a relay on another host would send the login in the clear; use `starttls` or \
                 `implicit`. A capture server needs no login: remove `plugin.smtp.username` and \
                 `plugin.smtp.password_file` (`plugin.smtp.allow_insecure_transport` never accepts a login)",
            ));
        }
        if !config.allow_insecure_transport {
            return Err(PluginError::invalid_config(
                PLUGIN,
                "`tls = \"none\"` for a relay on another host would send invitations and RSVP links in the clear; use \
                 `starttls` or `implicit`, or set `plugin.smtp.allow_insecure_transport = true` for a capture server \
                 on a private network",
            ));
        }
    }
    Ok(vec![format!(
        "`tls = \"none\"` to the relay `{}` on another host: invitations and RSVP links{} travel unencrypted",
        config.host.trim(),
        if login { " and the login" } else { "" }
    )])
}

fn build(context: PluginContext, table: serde_json::Value) -> Building {
    Box::pin(async move {
        let config = config(table)?;
        for warning in check_transport(&config, context.mode)? {
            tracing::warn!(
                plugin = PLUGIN,
                mode = %context.mode,
                allowed = config.allow_insecure_transport,
                "{warning}"
            );
        }
        let password = config.password()?;
        let transport: Arc<dyn MailTransport> = Arc::new(SmtpMailTransport::new(
            &config,
            password.as_ref(),
            Arc::clone(&context.clock),
        )?);
        Ok(Built::new(transport))
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use davhaven_ports::testing::{FixedHasher, FixedKeyRing, ManualClock, PlainSealer, SeqIds};
    use davhaven_ports::{ConfigTree, RunMode};
    use serde_json::json;

    use super::*;
    use crate::config::is_local;

    fn registry() -> PluginRegistry {
        let mut registry = PluginRegistry::new();
        register(&mut registry).unwrap();
        registry
    }

    fn production() -> PluginContext {
        PluginContext::new(
            Arc::new(ManualClock::default()),
            Arc::new(SeqIds::new()),
            Arc::new(FixedKeyRing::default()),
            Arc::new(PlainSealer),
            Arc::new(FixedHasher::default()),
            RunMode::Production,
        )
    }

    /// A password file in the temp directory that is removed when the test ends.
    struct PasswordFile(std::path::PathBuf);

    impl PasswordFile {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!("davhaven-smtp-{}-{name}", std::process::id()));
            let mut file = std::fs::File::create(&path).unwrap();
            file.write_all(b"s3cret\n").unwrap();
            Self(path)
        }
    }

    impl Drop for PasswordFile {
        fn drop(&mut self) {
            drop(std::fs::remove_file(&self.0));
        }
    }

    async fn build_with(context: &PluginContext, config: serde_json::Value) -> Result<(), PluginError> {
        let tree = ConfigTree::new().with("smtp", config);
        registry()
            .build_single(PortKind::MAIL_TRANSPORT, "smtp", context, &tree)
            .await
            .map(|_| ())
    }

    #[test]
    fn the_plugin_is_registered_once_with_a_schema() {
        let mut registry = registry();
        assert_eq!(registry.names(PortKind::MAIL_TRANSPORT), vec!["smtp"]);
        assert!(matches!(
            register(&mut registry),
            Err(PluginError::DuplicateName { .. })
        ));
        let schema = &registry.schemas()[0];
        assert_eq!(schema.schema.as_value()["properties"]["port"]["type"], "integer");
    }

    #[tokio::test]
    async fn the_defaults_and_a_complete_configuration_build() {
        let context = PluginContext::for_tests();
        build_with(&context, json!({})).await.unwrap();
        let file = PasswordFile::new("ok");
        build_with(
            &context,
            json!({"host": "smtp.example.org", "port": 465, "tls": "implicit", "username": "davhaven",
                   "password_file": file.0, "timeout": "10s"}),
        )
        .await
        .unwrap();
        // Production accepts the same encrypted configuration.
        build_with(
            &production(),
            json!({"host": "smtp.example.org", "username": "u", "password_file": file.0}),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn invalid_configuration_names_the_key_and_never_the_secret() {
        let context = PluginContext::for_tests();
        for (config, key) in [
            (json!({"port": 0}), "port"),
            (json!({"hostt": "x"}), "hostt"),
            (json!({"username": "u"}), "password_file"),
            (
                json!({"username": "u", "password_file": "/nonexistent/davhaven-password"}),
                "password_file",
            ),
            (json!({"tls": "ssl"}), "ssl"),
        ] {
            let error = build_with(&context, config).await.unwrap_err().to_string();
            assert!(error.contains(key), "{key}: {error}");
            assert!(!error.contains("s3cret"), "{error}");
        }
    }

    #[tokio::test]
    async fn a_login_over_an_unencrypted_connection_is_refused_in_production_unless_local() {
        let file = PasswordFile::new("none");
        let remote = json!({"host": "smtp.example.org", "tls": "none", "username": "u", "password_file": file.0});
        let error = build_with(&production(), remote.clone()).await.unwrap_err().to_string();
        assert!(
            error.contains("plugin `smtp`") && error.contains("tls") && error.contains("login"),
            "{error}"
        );
        build_with(&PluginContext::for_tests(), remote).await.unwrap();
        build_with(
            &production(),
            json!({"host": "localhost", "tls": "none", "username": "u", "password_file": file.0}),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn an_unencrypted_relay_on_another_host_is_refused_in_production_with_or_without_a_login() {
        let error = build_with(&production(), json!({"host": "relay.internal.example", "tls": "none"}))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("plugin `smtp`")
                && error.contains("tls")
                && error.contains("clear")
                && error.contains("`plugin.smtp.allow_insecure_transport = true`"),
            "{error}"
        );
        // Outside production (a capture server in a test, a staging copy) the choice is the operator's.
        build_with(
            &PluginContext::for_tests(),
            json!({"host": "relay.internal.example", "tls": "none"}),
        )
        .await
        .unwrap();
        // The relay on this host never leaves the machine.
        for host in ["localhost", "127.0.0.1", "::1"] {
            build_with(&production(), json!({"host": host, "tls": "none"}))
                .await
                .unwrap();
        }
        // Encrypted relays are fine.
        for tls in ["starttls", "implicit"] {
            build_with(&production(), json!({"host": "relay.internal.example", "tls": tls}))
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn the_operator_can_accept_an_unencrypted_relay_on_a_private_network_in_production() {
        build_with(
            &production(),
            json!({"host": "mail-catcher", "port": 1025, "tls": "none", "allow_insecure_transport": true}),
        )
        .await
        .unwrap();
        // The flag relaxes nothing else: the values are still checked.
        let error = build_with(
            &production(),
            json!({"host": "mail-catcher", "port": 0, "tls": "none", "allow_insecure_transport": true}),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("port"), "{error}");
    }

    #[tokio::test]
    async fn the_opt_in_never_accepts_a_login_in_the_clear() {
        let file = PasswordFile::new("opt-in");
        let capture = json!({"host": "mail-catcher", "port": 1025, "tls": "none", "allow_insecure_transport": true,
                             "username": "u", "password_file": file.0});
        let error = build_with(&production(), capture.clone())
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("plugin `smtp`")
                && error.contains("login")
                && error.contains("`plugin.smtp.username`")
                && error.contains("`plugin.smtp.password_file`"),
            "{error}"
        );
        // The same capture server without a login is what the opt-in is for, and outside production the choice is the
        // operator's.
        build_with(
            &production(),
            json!({"host": "mail-catcher", "port": 1025, "tls": "none", "allow_insecure_transport": true}),
        )
        .await
        .unwrap();
        build_with(&PluginContext::for_tests(), capture).await.unwrap();
        // A login over TLS, or to this host, is no concern of the rule.
        for (host, tls) in [("smtp.example.org", "starttls"), ("localhost", "none")] {
            build_with(
                &production(),
                json!({"host": host, "tls": tls, "allow_insecure_transport": true,
                       "username": "u", "password_file": file.0}),
            )
            .await
            .unwrap();
        }
    }

    fn config_of(value: serde_json::Value) -> SmtpConfig {
        parse_config(PLUGIN, value).unwrap()
    }

    fn refusal(config: &SmtpConfig, mode: RunMode) -> String {
        match check_transport(config, mode).unwrap_err() {
            PluginError::InvalidConfig { plugin, message } => {
                assert_eq!(plugin, PLUGIN);
                message
            }
            other => panic!("an invalid configuration was expected, not {other}"),
        }
    }

    #[test]
    fn the_transport_rule_refuses_in_production_what_would_cross_the_network_in_the_clear() {
        let remote = config_of(json!({"host": "mail-catcher", "tls": "none"}));
        let message = refusal(&remote, RunMode::Production);
        assert!(
            message.contains("`plugin.smtp.allow_insecure_transport = true`") && !message.contains("login"),
            "{message}"
        );
        // With a login the opt-in is not offered: it would not help.
        let login = config_of(json!({"host": "mail-catcher", "tls": "none", "username": "u", "password_file": "/x"}));
        let message = refusal(&login, RunMode::Production);
        assert!(
            message.contains("login")
                && message.contains("`plugin.smtp.username`")
                && !message.contains("allow_insecure_transport = true"),
            "{message}"
        );
        let opted_in = config_of(
            json!({"host": "mail-catcher", "tls": "none", "allow_insecure_transport": true,
                                         "username": "u", "password_file": "/x"}),
        );
        assert!(refusal(&opted_in, RunMode::Production).contains("login"));
    }

    #[test]
    fn the_transport_rule_warns_where_it_does_not_refuse() {
        for (config, mode) in [
            (
                config_of(json!({"host": "mail-catcher", "tls": "none", "allow_insecure_transport": true})),
                RunMode::Production,
            ),
            (config_of(json!({"host": "mail-catcher", "tls": "none"})), RunMode::Dev),
        ] {
            let warnings = check_transport(&config, mode).unwrap();
            assert_eq!(warnings.len(), 1, "{mode}: {warnings:?}");
            assert!(
                warnings[0].contains("mail-catcher") && warnings[0].contains("unencrypted"),
                "{warnings:?}"
            );
            assert!(!warnings[0].contains("login"), "{warnings:?}");
        }
        let login = config_of(json!({"host": "mail-catcher", "tls": "none", "username": "u", "password_file": "/x"}));
        let warnings = check_transport(&login, RunMode::Dev).unwrap();
        assert!(warnings[0].contains("and the login"), "{warnings:?}");
    }

    #[test]
    fn the_transport_rule_is_silent_for_encrypted_and_local_relays() {
        for value in [
            json!({"host": "smtp.example.org"}),
            json!({"host": "smtp.example.org", "tls": "implicit"}),
            json!({"host": "localhost", "tls": "none"}),
            json!({"host": "127.0.0.1", "tls": "none"}),
            json!({"host": "[::1]", "tls": "none"}),
        ] {
            let config = config_of(value.clone());
            for mode in [RunMode::Production, RunMode::Dev] {
                assert_eq!(check_transport(&config, mode).unwrap(), Vec::<String>::new(), "{value}");
            }
        }
    }

    #[test]
    fn an_opt_in_that_changes_nothing_is_reported_as_stale() {
        for value in [
            json!({"host": "smtp.example.org", "allow_insecure_transport": true}),
            json!({"host": "smtp.example.org", "tls": "implicit", "allow_insecure_transport": true}),
            json!({"host": "localhost", "tls": "none", "allow_insecure_transport": true}),
        ] {
            let config = config_of(value.clone());
            for mode in [RunMode::Production, RunMode::Dev] {
                let warnings = check_transport(&config, mode).unwrap();
                assert_eq!(warnings.len(), 1, "{value}: {warnings:?}");
                assert!(
                    warnings[0].contains("`plugin.smtp.allow_insecure_transport`") && warnings[0].contains("no effect"),
                    "{warnings:?}"
                );
            }
        }
    }

    #[test]
    fn local_hosts_are_recognised() {
        for local in [
            "localhost",
            "LOCALHOST",
            "127.0.0.1",
            "127.0.0.2",
            "127.1.2.3",
            "::1",
            "[::1]",
            "::ffff:127.0.0.1",
            " localhost ",
        ] {
            assert!(is_local(local), "{local}");
        }
        for remote in [
            "smtp.example.org",
            "localhost.example.org",
            "127.example.net",
            "10.0.0.5",
            "2001:db8::1",
            "[2001:db8::1]",
            "",
        ] {
            assert!(!is_local(remote), "{remote}");
        }
    }
}
