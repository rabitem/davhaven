//! A recording `HttpClient` fake for tests.
//!
//! [`RecordingHttpClient`] sends nothing: it applies the URL part of the egress policy (so a test cannot pass a URL
//! the real client would refuse), remembers every accepted request and answers from a script. Tests of webhooks,
//! OAuth and the provider clients use it to assert what would have been sent. It is selectable as the
//! `http_client` plugin `recording` (development and staging copies that must not call out), and refused in
//! production mode.

use std::collections::VecDeque;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use davhaven_ports::{HttpClient, OutboundRequest, OutboundResponse, PluginError, PortError, PortLabel, observe};
use http::{HeaderMap, StatusCode};
use schemars::JsonSchema;
use serde::Deserialize;
use tokio::sync::Mutex;
use url::Url;

use crate::config::EgressConfig;
use crate::policy::{EgressPolicy, PolicyViolation};

/// The name of the plugin.
pub const PLUGIN: &str = "recording";

/// The `[plugin.recording]` table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct RecordingConfig {
    /// The status the client answers with when no answer is scripted.
    pub status: u16,
    /// How many requests the client remembers; when there are more the oldest are dropped, so a copy of a
    /// deployment that runs for weeks does not grow without limit.
    pub max_requests: usize,
}

impl Default for RecordingConfig {
    fn default() -> Self {
        Self {
            status: 200,
            max_requests: 1000,
        }
    }
}

impl RecordingConfig {
    /// Checks that the status is a valid HTTP status code.
    ///
    /// # Errors
    ///
    /// [`PluginError::InvalidConfig`] for `status` outside 100 to 599 and for `max_requests = 0`.
    pub fn validate(&self) -> Result<(), PluginError> {
        if !(100..=599).contains(&self.status) {
            return Err(PluginError::invalid_config(
                PLUGIN,
                "`status` must be an HTTP status between 100 and 599",
            ));
        }
        if self.max_requests == 0 {
            return Err(PluginError::invalid_config(
                PLUGIN,
                "`max_requests` must be greater than zero",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
struct State {
    sent: VecDeque<OutboundRequest>,
    script: VecDeque<Result<OutboundResponse, PortError>>,
}

/// An `HttpClient` that records instead of sending.
#[derive(Debug, Clone)]
pub struct RecordingHttpClient {
    policy: Arc<EgressPolicy>,
    default_status: StatusCode,
    max_requests: usize,
    state: Arc<Mutex<State>>,
}

impl RecordingHttpClient {
    /// A client with the default egress policy that answers `200 OK` with an empty body.
    pub fn new() -> Self {
        Self::with_config(&EgressConfig::default(), StatusCode::OK)
    }

    /// A client with the policy of `config` that answers `default_status` when nothing is scripted.
    pub fn with_config(config: &EgressConfig, default_status: StatusCode) -> Self {
        Self {
            policy: Arc::new(EgressPolicy::new(config)),
            default_status,
            max_requests: RecordingConfig::default().max_requests,
            state: Arc::default(),
        }
    }

    /// Remembers at most `max_requests` requests (at least one); the oldest are dropped first.
    #[must_use]
    pub fn with_max_requests(mut self, max_requests: usize) -> Self {
        self.max_requests = max_requests.max(1);
        self
    }

    /// Scripts the answer to the next request that has no scripted answer yet (answers are used in order).
    pub async fn push_response(&self, status: u16, body: &'static str) {
        let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let response = OutboundResponse {
            status,
            headers: HeaderMap::new(),
            body: Bytes::from_static(body.as_bytes()),
        };
        self.state.lock().await.script.push_back(Ok(response));
    }

    /// Scripts a failure for the next request without a scripted answer.
    pub async fn push_error(&self, error: PortError) {
        self.state.lock().await.script.push_back(Err(error));
    }

    /// The accepted requests so far, in sending order.
    pub async fn requests(&self) -> Vec<OutboundRequest> {
        self.state.lock().await.sent.iter().cloned().collect()
    }

    /// Forgets the recorded requests (the script stays).
    pub async fn clear(&self) {
        self.state.lock().await.sent.clear();
    }
}

impl Default for RecordingHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

fn refused(violation: PolicyViolation) -> PortError {
    match violation {
        PolicyViolation::Unresolvable => PortError::unavailable(violation.to_string()),
        other => PortError::rejected(other.to_string()),
    }
}

/// What `observe` labels the recording client with.
const LABEL: PortLabel = PortLabel::new("http_client", PLUGIN);

#[async_trait]
impl HttpClient for RecordingHttpClient {
    async fn send(&self, request: OutboundRequest) -> Result<OutboundResponse, PortError> {
        observe(LABEL, "send", async {
            self.policy.check_url(&request.url).map_err(refused)?;
            let mut state = self.state.lock().await;
            state.sent.push_back(request);
            while state.sent.len() > self.max_requests {
                state.sent.pop_front();
            }
            state.script.pop_front().unwrap_or_else(|| {
                Ok(OutboundResponse {
                    status: self.default_status,
                    headers: HeaderMap::new(),
                    body: Bytes::new(),
                })
            })
        })
        .await
    }

    async fn validate_url(&self, url: &Url) -> Result<(), PortError> {
        observe(LABEL, "validate_url", async {
            self.policy.check_url(url).map(|_| ()).map_err(refused)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use davhaven_ports::{HttpPurpose, PortErrorKind};
    use http::Method;

    use super::*;

    fn post(url: &str) -> OutboundRequest {
        OutboundRequest::new(Method::POST, Url::parse(url).unwrap(), HttpPurpose::Webhook)
            .with_body(Bytes::from_static(b"x"))
    }

    #[tokio::test]
    async fn requests_are_recorded_and_answered_from_the_script_then_the_default() {
        let client = RecordingHttpClient::new();
        client.push_response(500, "boom").await;
        client.push_error(PortError::timeout("slow")).await;

        let first = client.send(post("https://hooks.example.org/a")).await.unwrap();
        assert_eq!(
            (first.status, first.body.as_ref()),
            (StatusCode::INTERNAL_SERVER_ERROR, b"boom".as_ref())
        );
        let second = client.send(post("https://hooks.example.org/b")).await.unwrap_err();
        assert_eq!(second.kind, PortErrorKind::Timeout);
        let third = client.send(post("https://hooks.example.org/c")).await.unwrap();
        assert_eq!(third.status, StatusCode::OK);

        let urls: Vec<String> = client
            .requests()
            .await
            .iter()
            .map(|r| r.url.path().to_owned())
            .collect();
        assert_eq!(urls, vec!["/a", "/b", "/c"]);
        client.clear().await;
        assert!(client.requests().await.is_empty());
    }

    #[tokio::test]
    async fn the_fake_refuses_what_the_real_client_refuses() {
        let client = RecordingHttpClient::new();
        for url in [
            "http://hooks.example.org/",
            "https://127.0.0.1/",
            "https://10.0.0.1/",
            "https://u:p@hooks.example.org/",
        ] {
            let error = client.send(post(url)).await.unwrap_err();
            assert_eq!(error.kind, PortErrorKind::Rejected, "{url}");
            assert_eq!(
                client.validate_url(&Url::parse(url).unwrap()).await.unwrap_err().kind,
                PortErrorKind::Rejected
            );
        }
        assert!(client.requests().await.is_empty(), "refused requests are not recorded");
        assert!(
            client
                .validate_url(&Url::parse("https://hooks.example.org/").unwrap())
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn the_default_status_is_configurable_and_scripted_statuses_are_sanitized() {
        let client = RecordingHttpClient::with_config(&EgressConfig::default(), StatusCode::NO_CONTENT);
        assert_eq!(
            client.send(post("https://hooks.example.org/")).await.unwrap().status,
            StatusCode::NO_CONTENT
        );
        client.push_response(42, "").await;
        assert_eq!(
            client.send(post("https://hooks.example.org/")).await.unwrap().status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "an impossible status becomes a 500 instead of a panic"
        );
    }

    #[test]
    fn the_configuration_checks_the_status() {
        assert!(RecordingConfig::default().validate().is_ok());
        let error = RecordingConfig {
            status: 99,
            ..RecordingConfig::default()
        }
        .validate()
        .unwrap_err()
        .to_string();
        assert!(error.contains("status"), "{error}");
        let error = RecordingConfig {
            max_requests: 0,
            ..RecordingConfig::default()
        }
        .validate()
        .unwrap_err()
        .to_string();
        assert!(error.contains("max_requests"), "{error}");
        assert!(davhaven_ports::parse_config::<RecordingConfig>(PLUGIN, serde_json::json!({"code": 200})).is_err());
    }

    #[tokio::test]
    async fn only_the_newest_requests_are_remembered() {
        let client = RecordingHttpClient::new().with_max_requests(3);
        for n in 0..10 {
            client
                .send(post(&format!("https://hooks.example.org/{n}")))
                .await
                .unwrap();
        }
        let paths: Vec<String> = client
            .requests()
            .await
            .iter()
            .map(|request| request.url.path().to_owned())
            .collect();
        assert_eq!(paths, vec!["/7", "/8", "/9"], "the oldest were dropped");
        assert_eq!(RecordingHttpClient::new().with_max_requests(0).max_requests, 1);
        assert_eq!(RecordingConfig::default().max_requests, 1000);
    }

    #[tokio::test]
    async fn the_fake_passes_the_http_client_contract() {
        davhaven_port_tests::http_client::run_all(|| Arc::new(RecordingHttpClient::new())).await;
    }
}
