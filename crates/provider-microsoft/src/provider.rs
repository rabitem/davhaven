//! The Microsoft provider: the OAuth flow and the calendar API of one app registration, and whether the deployment switched it on.

use std::sync::Arc;

use davhaven_ports::{Clock, HttpClient, OAuthProvider, PluginError, Provider, RemoteCalendarApi};

use crate::api::MicrosoftCalendars;
use crate::config::{MicrosoftConfig, PLUGIN};
use crate::oauth::MicrosoftOAuth;

/// The provider `microsoft`.
#[derive(Debug)]
pub struct MicrosoftProvider {
    enabled: bool,
    oauth: MicrosoftOAuth,
    calendars: MicrosoftCalendars,
}

impl MicrosoftProvider {
    /// Builds the provider from its table. A provider that is switched off is built without credentials (nothing is read from
    /// disk), answers `enabled() == false`, and refuses to start an authorization.
    ///
    /// # Errors
    ///
    /// [`PluginError::InvalidConfig`] when the table is invalid, or when it is enabled and the client secret cannot be read.
    pub fn new(
        config: &MicrosoftConfig,
        http: Arc<dyn HttpClient>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, PluginError> {
        config.validate()?;
        let (client_id, client_secret) = if config.enabled {
            (config.client_id.clone(), Some(config.client_secret()?))
        } else {
            (None, None)
        };
        Ok(Self {
            enabled: config.enabled,
            oauth: MicrosoftOAuth::new(
                config.directory.clone(),
                client_id,
                client_secret,
                Arc::clone(&http),
                Arc::clone(&clock),
            ),
            calendars: MicrosoftCalendars::new(http, clock, config.history_days, config.future_days),
        })
    }
}

impl Provider for MicrosoftProvider {
    fn name(&self) -> &'static str {
        PLUGIN
    }

    fn display_name(&self) -> &'static str {
        "Microsoft"
    }

    fn enabled(&self) -> bool {
        self.enabled
    }

    fn oauth(&self) -> &dyn OAuthProvider {
        &self.oauth
    }

    fn calendars(&self) -> &dyn RemoteCalendarApi {
        &self.calendars
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use davhaven_ports::testing::{ManualClock, ReplayHttp};
    use url::Url;

    use super::*;

    fn build(config: &MicrosoftConfig) -> Result<MicrosoftProvider, PluginError> {
        MicrosoftProvider::new(config, Arc::new(ReplayHttp::new()), Arc::new(ManualClock::default()))
    }

    #[test]
    fn a_provider_that_is_off_is_built_without_credentials_and_refuses_to_start() {
        let provider = build(&MicrosoftConfig::default()).unwrap();
        assert!(!provider.enabled());
        assert_eq!((provider.name(), provider.display_name()), ("microsoft", "Microsoft"));
        let redirect = Url::parse("https://cal.example.org/oauth/microsoft/callback").unwrap();
        assert!(provider.oauth().authorize_url("s", "c", &redirect).is_err());
    }

    #[test]
    fn a_provider_that_is_on_reads_its_secret_and_starts_authorizations_in_its_directory() {
        let path = std::env::temp_dir().join(format!("davhaven-microsoft-secret-{}", std::process::id()));
        std::fs::File::create(&path)
            .unwrap()
            .write_all(b"client-secret\n")
            .unwrap();
        let config = MicrosoftConfig {
            enabled: true,
            client_id: Some("11111111-2222-3333-4444-555555555555".to_owned()),
            client_secret_file: Some(path.clone()),
            redirect_uri: Some(Url::parse("https://cal.example.org/oauth/microsoft/callback").unwrap()),
            directory: "contoso.onmicrosoft.com".to_owned(),
            ..MicrosoftConfig::default()
        };
        let provider = build(&config).unwrap();
        assert!(provider.enabled());
        let redirect = config.redirect_uri.clone().unwrap();
        let url = provider.oauth().authorize_url("s", "c", &redirect).unwrap();
        assert_eq!(url.path(), "/contoso.onmicrosoft.com/oauth2/v2.0/authorize");
        std::fs::remove_file(&path).unwrap();
        let missing = build(&config).map(|_| ()).unwrap_err().to_string();
        assert!(
            missing.contains("client_secret_file") && !missing.contains("client-secret"),
            "{missing}"
        );
    }

    #[test]
    fn an_invalid_table_is_refused_by_the_provider_too() {
        let config = MicrosoftConfig {
            enabled: true,
            ..MicrosoftConfig::default()
        };
        assert!(
            build(&config)
                .map(|_| ())
                .unwrap_err()
                .to_string()
                .contains("client_id")
        );
        let config = MicrosoftConfig {
            directory: "evil.example/x".to_owned(),
            ..MicrosoftConfig::default()
        };
        assert!(
            build(&config)
                .map(|_| ())
                .unwrap_err()
                .to_string()
                .contains("directory")
        );
    }
}
