//! The `HttpClient` implementation based on reqwest with rustls (ring).
//!
//! [`EgressHttpClient`] is the only way the server talks HTTP to the outside (`ENGINEERING_RULES` R6). Around
//! reqwest it enforces, for every request:
//!
//! * the URL policy before anything is sent: `https` only (unless configured), no credentials in the URL, and
//!   literal addresses in the allowed ranges;
//! * the address policy at connect time: host names resolve through [`PolicyResolver`], so the client connects
//!   only to addresses the policy permits and a second lookup cannot change them (DNS rebinding);
//! * no redirects (a `3xx` is returned as it is), no proxies from the environment, a connect timeout, a total
//!   timeout and a cap on the response size. The cap and the total timeout depend on the purpose of the request:
//!   a webhook answer is read for its status only (its body is cut at the cap, never a reason to fail a delivery
//!   the receiver accepted), OAuth answers are small, and a page of events from a provider is large.
//!
//! Errors carry no URL, query string, header value or body, because webhook URLs and signatures are secrets.

use core::fmt;
use std::error::Error as StdError;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::BytesMut;
use davhaven_ports::{
    HttpClient, HttpPurpose, OutboundRequest, OutboundResponse, PluginError, PortError, PortLabel, observe,
};
use url::Url;

use crate::config::{EgressConfig, PLUGIN};
use crate::policy::{EgressPolicy, PolicyViolation, Target};
use crate::resolver::{HostLookup, PolicyResolver, ResolveError, SystemLookup};

/// The label of the adapter in metrics and spans.
const LABEL: PortLabel = PortLabel::new("http_client", PLUGIN);

/// The `HttpClient` of the egress adapter.
#[derive(Clone)]
pub struct EgressHttpClient {
    client: reqwest::Client,
    policy: Arc<EgressPolicy>,
    resolver: PolicyResolver,
    limits: Limits,
}

/// What the configuration says about size and time per purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Limits {
    webhook_bytes: u64,
    oauth_bytes: u64,
    provider_bytes: u64,
    total_timeout: Duration,
    provider_timeout: Duration,
}

impl Limits {
    fn of(config: &EgressConfig) -> Self {
        Self {
            webhook_bytes: config.max_response_bytes,
            oauth_bytes: config.oauth_max_response_bytes,
            provider_bytes: config.provider_api_max_response_bytes,
            total_timeout: config.total_timeout,
            provider_timeout: config.provider_api_total_timeout,
        }
    }

    /// The most body bytes read for `purpose`.
    const fn bytes(&self, purpose: HttpPurpose) -> u64 {
        match purpose {
            HttpPurpose::OAuth => self.oauth_bytes,
            HttpPurpose::ProviderApi => self.provider_bytes,
            _ => self.webhook_bytes,
        }
    }

    /// The timeout of the whole request for `purpose`.
    const fn timeout(&self, purpose: HttpPurpose) -> Duration {
        match purpose {
            HttpPurpose::ProviderApi => self.provider_timeout,
            _ => self.total_timeout,
        }
    }
}

impl EgressHttpClient {
    /// A client that resolves host names with the operating system's resolver.
    ///
    /// # Errors
    ///
    /// [`PluginError::InvalidConfig`] for an invalid `config`; [`PluginError::Build`] when the TLS stack cannot
    /// be initialised.
    pub fn new(config: &EgressConfig) -> Result<Self, PluginError> {
        Self::with_lookup(
            config,
            Arc::new(SystemLookup::new(config.connect_timeout, config.max_concurrent_lookups)),
        )
    }

    /// A client that resolves host names with `lookup` (tests answer from a table).
    ///
    /// # Errors
    ///
    /// As [`EgressHttpClient::new`].
    pub fn with_lookup(config: &EgressConfig, lookup: Arc<dyn HostLookup>) -> Result<Self, PluginError> {
        config.validate()?;
        install_crypto_provider();
        let policy = Arc::new(EgressPolicy::new(config));
        let resolver = PolicyResolver::new(lookup, Arc::clone(&policy));
        let client = reqwest::Client::builder()
            .user_agent(concat!("Davhaven/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .https_only(!config.allow_http)
            .connect_timeout(config.connect_timeout)
            .timeout(config.total_timeout)
            .pool_idle_timeout(Duration::from_secs(30))
            .dns_resolver(resolver.clone())
            .build()
            .map_err(|error| {
                PluginError::build(
                    PLUGIN,
                    PortError::internal(format!("cannot build the HTTP client: {}", describe(&error))),
                )
            })?;
        Ok(Self {
            client,
            policy,
            resolver,
            limits: Limits::of(config),
        })
    }

    async fn send_checked(&self, request: OutboundRequest) -> Result<OutboundResponse, PortError> {
        let OutboundRequest {
            method,
            url,
            headers,
            body,
            purpose,
        } = request;
        self.policy.check_url(&url).map_err(refused)?;
        let mut response = self
            .client
            .request(method, url)
            .headers(headers)
            .body(body)
            .timeout(self.limits.timeout(purpose))
            .send()
            .await
            .map_err(|error| map_error(&error))?;
        let status = response.status();
        let headers = response.headers().clone();
        // The status of a webhook answer is all that counts: its body is cut, not a reason to fail the delivery.
        let cut_instead_of_refusing = purpose == HttpPurpose::Webhook;
        let max = self.limits.bytes(purpose);
        if !cut_instead_of_refusing && response.content_length().is_some_and(|length| length > max) {
            return Err(too_large());
        }
        let cap = usize::try_from(max).unwrap_or(usize::MAX);
        let mut body = BytesMut::new();
        while let Some(chunk) = response.chunk().await.map_err(|error| map_error(&error))? {
            let room = cap.saturating_sub(body.len());
            if chunk.len() > room {
                if cut_instead_of_refusing {
                    body.extend_from_slice(chunk.get(..room).unwrap_or_default());
                    break;
                }
                return Err(too_large());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(OutboundResponse {
            status,
            headers,
            body: body.freeze(),
        })
    }

    async fn validate_checked(&self, url: &Url) -> Result<(), PortError> {
        match self.policy.check_url(url).map_err(refused)? {
            Target::Address(_) => Ok(()),
            Target::Name(host) => self
                .resolver
                .resolve_allowed(&host)
                .await
                .map(|_| ())
                .map_err(|error| from_resolve(&error)),
        }
    }
}

impl fmt::Debug for EgressHttpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EgressHttpClient")
            .field("max_response_bytes", &self.limits.webhook_bytes)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl HttpClient for EgressHttpClient {
    async fn send(&self, request: OutboundRequest) -> Result<OutboundResponse, PortError> {
        observe(LABEL, operation(request.purpose), self.send_checked(request)).await
    }

    async fn validate_url(&self, url: &Url) -> Result<(), PortError> {
        observe(LABEL, "validate_url", self.validate_checked(url)).await
    }
}

/// The operation label of a request: one per purpose, so dashboards separate webhooks from provider calls.
fn operation(purpose: HttpPurpose) -> &'static str {
    match purpose {
        HttpPurpose::Webhook => "send.webhook",
        HttpPurpose::OAuth => "send.oauth",
        HttpPurpose::ProviderApi => "send.provider_api",
        _ => "send.other",
    }
}

/// Installs the ring crypto provider as the process default, which reqwest (built with `rustls-no-provider`)
/// needs. An error only says that a provider is installed already.
fn install_crypto_provider() {
    drop(rustls::crypto::ring::default_provider().install_default());
}

/// The answer is larger than the cap of its purpose. The refusal is the size cap, not the egress policy, and the
/// text says so.
fn too_large() -> PortError {
    PortError::rejected("the response is larger than the maximum for this kind of request")
}

fn refused(violation: PolicyViolation) -> PortError {
    match violation {
        PolicyViolation::Unresolvable => PortError::unavailable(violation.to_string()),
        other => PortError::rejected(other.to_string()),
    }
}

fn from_resolve(error: &ResolveError) -> PortError {
    match error {
        ResolveError::Denied(violation) => refused(violation.clone()),
        ResolveError::Lookup(std::io::ErrorKind::TimedOut) => PortError::timeout("the host name lookup timed out"),
        ResolveError::Lookup(_) => PortError::unavailable("the host name could not be resolved"),
    }
}

/// The class of a reqwest error without its URL.
fn describe(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else if error.is_dns() {
        "dns"
    } else if error.is_builder() {
        "builder"
    } else if error.is_body() || error.is_decode() {
        "body"
    } else {
        "request"
    }
}

/// Maps a reqwest error to a port error: a refusal of the policy during name resolution is `Rejected`, time-outs
/// are `Timeout`, everything else the remote did or did not do is `Unavailable`.
fn map_error(error: &reqwest::Error) -> PortError {
    let mut source: Option<&(dyn StdError + 'static)> = Some(error);
    while let Some(current) = source {
        if let Some(resolve) = current.downcast_ref::<ResolveError>() {
            return from_resolve(resolve);
        }
        source = current.source();
    }
    if error.is_timeout() {
        PortError::timeout("the request timed out")
    } else if error.is_builder() {
        PortError::invalid("the request cannot be sent")
    } else if error.is_connect() || error.is_dns() {
        PortError::unavailable("the target could not be reached")
    } else if error.is_body() || error.is_decode() {
        PortError::unavailable("the response could not be read")
    } else {
        PortError::unavailable("the request failed")
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;
    use davhaven_ports::PortErrorKind;
    use http::{HeaderName, HeaderValue, Method, StatusCode};
    use wiremock::matchers::{body_bytes, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::resolver::testing::TableLookup;

    /// A configuration that reaches the wiremock servers on the loopback interface over plain HTTP.
    fn loopback() -> EgressConfig {
        EgressConfig {
            allow_http: true,
            allow_cidrs: vec!["127.0.0.0/8".parse().unwrap()],
            ..EgressConfig::default()
        }
    }

    fn client(config: &EgressConfig) -> EgressHttpClient {
        EgressHttpClient::with_lookup(config, TableLookup::of(&[])).unwrap()
    }

    fn request(method: Method, url: &str) -> OutboundRequest {
        OutboundRequest::new(method, Url::parse(url).unwrap(), HttpPurpose::Webhook)
    }

    #[expect(clippy::disallowed_types, reason = "a test double with synchronous accessors")]
    type StdMutex<T> = std::sync::Mutex<T>;

    /// A lookup that answers from a script, one answer per call (the last one repeats), and counts its calls: the
    /// way a DNS server that changes its answer is played.
    struct ScriptedLookup {
        answers: StdMutex<Vec<Vec<std::net::IpAddr>>>,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl ScriptedLookup {
        fn new(answers: &[&[&str]]) -> Arc<Self> {
            Arc::new(Self {
                answers: StdMutex::new(
                    answers
                        .iter()
                        .map(|answer| answer.iter().map(|address| address.parse().unwrap()).collect())
                        .collect(),
                ),
                calls: std::sync::atomic::AtomicUsize::new(0),
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl HostLookup for ScriptedLookup {
        async fn lookup(&self, _host: &str) -> std::io::Result<Vec<std::net::IpAddr>> {
            let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let answers = self.answers.lock().unwrap();
            Ok(answers
                .get(call)
                .or_else(|| answers.last())
                .cloned()
                .unwrap_or_default())
        }
    }

    #[tokio::test]
    async fn a_name_that_was_public_when_it_was_checked_and_is_loopback_when_it_is_used_is_refused() {
        // DNS rebinding: the registration of a webhook (validate_url) sees a public address, the delivery that
        // follows would connect to the loopback interface if it trusted the first answer.
        let lookup = ScriptedLookup::new(&[&["93.184.216.34"], &["127.0.0.1"]]);
        let client =
            EgressHttpClient::with_lookup(&EgressConfig::default(), Arc::<ScriptedLookup>::clone(&lookup)).unwrap();
        let url = Url::parse("https://rebind.example.org/hook").unwrap();

        client.validate_url(&url).await.expect("the first answer is public");
        assert_eq!(lookup.calls(), 1);
        let error = client
            .send(OutboundRequest::new(Method::POST, url, HttpPurpose::Webhook))
            .await
            .unwrap_err();
        assert_eq!(error.kind, PortErrorKind::Rejected, "{error}");
        assert_eq!(
            lookup.calls(),
            2,
            "the delivery resolved the name again, and the answer was judged afresh"
        );
        assert!(!error.message.contains("rebind.example.org"), "quiet: {error}");
    }

    #[tokio::test]
    async fn a_send_resolves_the_name_once_and_connects_to_what_it_got() {
        let server = MockServer::start().await;
        Mock::given(path("/hook"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let port = server.address().port();
        // The first answer is the server; a second lookup would find the metadata address.
        let lookup = ScriptedLookup::new(&[&["127.0.0.1"], &["169.254.169.254"]]);
        let client = EgressHttpClient::with_lookup(&loopback(), Arc::<ScriptedLookup>::clone(&lookup)).unwrap();
        let url = format!("http://hooks.example.org:{port}/hook");
        let answered = client.send(request(Method::POST, &url)).await.unwrap();
        assert_eq!(answered.status, StatusCode::OK);
        assert_eq!(
            lookup.calls(),
            1,
            "one resolution per connection, so nothing can change between check and use"
        );
    }

    #[tokio::test]
    async fn requests_reach_the_target_with_headers_and_body_and_the_answer_comes_back() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .and(header("webhook-id", "msg_1"))
            .and(body_bytes(b"{\"a\":1}".to_vec()))
            .respond_with(
                ResponseTemplate::new(202)
                    .insert_header("x-answer", "yes")
                    .set_body_string("accepted"),
            )
            .expect(1)
            .mount(&server)
            .await;

        let outbound = request(Method::POST, &format!("{}/hook", server.uri()))
            .with_header(HeaderName::from_static("webhook-id"), HeaderValue::from_static("msg_1"))
            .with_body(Bytes::from_static(b"{\"a\":1}"));
        let response = client(&loopback()).send(outbound).await.unwrap();
        assert_eq!(response.status, StatusCode::ACCEPTED);
        assert_eq!(response.headers.get("x-answer").unwrap(), "yes");
        assert_eq!(response.body, Bytes::from_static(b"accepted"));
        let received = server.received_requests().await.unwrap();
        assert_eq!(received.len(), 1);
        let agent = received[0]
            .headers
            .get("user-agent")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert!(agent.starts_with("Davhaven/"), "{agent}");
    }

    #[tokio::test]
    async fn redirects_are_returned_and_never_followed() {
        let target = MockServer::start().await;
        let origin = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&target)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", format!("{}/secret", target.uri())))
            .mount(&origin)
            .await;

        let response = client(&loopback())
            .send(request(Method::GET, &origin.uri()))
            .await
            .unwrap();
        assert_eq!(response.status, StatusCode::FOUND);
        assert!(response.headers.get("location").is_some());
        assert!(
            target.received_requests().await.unwrap().is_empty(),
            "the redirect target was never contacted"
        );
    }

    #[tokio::test]
    async fn the_policy_refuses_before_any_connection_is_made() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        // The default policy: https only, no loopback.
        let strict = client(&EgressConfig::default());
        let plain = strict.send(request(Method::GET, &server.uri())).await.unwrap_err();
        assert_eq!(plain.kind, PortErrorKind::Rejected, "{plain}");
        let port = server.address().port();
        let loopback_https = strict
            .send(request(Method::GET, &format!("https://127.0.0.1:{port}/")))
            .await
            .unwrap_err();
        assert_eq!(loopback_https.kind, PortErrorKind::Rejected, "{loopback_https}");
        // Plain http is allowed here but loopback is not.
        let http_only = client(&EgressConfig {
            allow_http: true,
            ..EgressConfig::default()
        });
        let denied = http_only.send(request(Method::GET, &server.uri())).await.unwrap_err();
        assert_eq!(denied.kind, PortErrorKind::Rejected, "{denied}");
        let credentials = client(&loopback())
            .send(request(Method::GET, &format!("http://user:pw@127.0.0.1:{port}/")))
            .await
            .unwrap_err();
        assert_eq!(credentials.kind, PortErrorKind::Rejected, "{credentials}");
        assert!(
            server.received_requests().await.unwrap().is_empty(),
            "nothing reached the server"
        );
    }

    #[tokio::test]
    async fn host_names_connect_only_to_addresses_the_policy_permits() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let port = server.address().port();
        let lookup = TableLookup::of(&[
            ("hooks.example.test", &["127.0.0.1"]),
            ("rebind.example.test", &["93.184.216.34", "127.0.0.1"]),
        ]);

        // With the loopback range allowed, the name resolves and the connection goes to the resolved address.
        let allowed = EgressHttpClient::with_lookup(&loopback(), Arc::clone(&lookup)).unwrap();
        let ok = allowed
            .send(request(Method::GET, &format!("http://hooks.example.test:{port}/")))
            .await
            .unwrap();
        assert_eq!(ok.status, StatusCode::OK);
        let seen = server.received_requests().await.unwrap();
        assert_eq!(
            seen[0].headers.get("host").unwrap().to_str().unwrap(),
            format!("hooks.example.test:{port}")
        );

        // Without it the same name is refused at resolution; so is an answer that mixes in a denied address.
        let strict = EgressHttpClient::with_lookup(
            &EgressConfig {
                allow_http: true,
                ..EgressConfig::default()
            },
            Arc::clone(&lookup),
        )
        .unwrap();
        for host in ["hooks.example.test", "rebind.example.test"] {
            let error = strict
                .send(request(Method::GET, &format!("http://{host}:{port}/")))
                .await
                .unwrap_err();
            assert_eq!(error.kind, PortErrorKind::Rejected, "{host}: {error}");
        }
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            1,
            "only the permitted request arrived"
        );

        let unknown = client(&loopback())
            .send(request(Method::GET, &format!("http://nowhere.example.test:{port}/")))
            .await
            .unwrap_err();
        assert_eq!(unknown.kind, PortErrorKind::Unavailable, "{unknown}");
    }

    #[tokio::test]
    async fn oversized_responses_are_refused() {
        let server = MockServer::start().await;
        Mock::given(path("/small"))
            .respond_with(ResponseTemplate::new(200).set_body_string("0123456789"))
            .mount(&server)
            .await;
        Mock::given(path("/large"))
            .respond_with(ResponseTemplate::new(200).set_body_string("0123456789abcdef"))
            .mount(&server)
            .await;
        let capped = client(&EgressConfig {
            max_response_bytes: 10,
            oauth_max_response_bytes: 10,
            ..loopback()
        });
        let for_oauth = |url: String| OutboundRequest::new(Method::GET, Url::parse(&url).unwrap(), HttpPurpose::OAuth);
        let small = capped.send(for_oauth(format!("{}/small", server.uri()))).await.unwrap();
        assert_eq!(small.body.len(), 10, "a body exactly at the cap is fine");
        let large = capped
            .send(for_oauth(format!("{}/large", server.uri())))
            .await
            .unwrap_err();
        assert_eq!(large.kind, PortErrorKind::Rejected, "{large}");
        assert!(
            large.message.contains("maximum"),
            "the refusal says what it is: {large}"
        );
    }

    #[tokio::test]
    async fn a_webhook_answer_that_is_too_large_is_cut_and_still_has_its_status() {
        let server = MockServer::start().await;
        Mock::given(path("/echo"))
            .respond_with(ResponseTemplate::new(200).set_body_string("0123456789abcdef"))
            .mount(&server)
            .await;
        Mock::given(path("/gone"))
            .respond_with(ResponseTemplate::new(410).set_body_string("x".repeat(5000)))
            .mount(&server)
            .await;
        let capped = client(&EgressConfig {
            max_response_bytes: 10,
            ..loopback()
        });
        let echoed = capped
            .send(request(Method::POST, &format!("{}/echo", server.uri())))
            .await
            .unwrap();
        assert_eq!(echoed.status, StatusCode::OK, "the receiver accepted the event");
        assert_eq!(
            echoed.body,
            Bytes::from_static(b"0123456789"),
            "the body is cut at the cap"
        );
        let gone = capped
            .send(request(Method::POST, &format!("{}/gone", server.uri())))
            .await
            .unwrap();
        assert_eq!(
            (gone.status, gone.body.len()),
            (StatusCode::GONE, 10),
            "an answer that announces its length is cut as well, and its status still counts"
        );
    }

    #[tokio::test]
    async fn provider_answers_may_be_larger_and_slower_than_webhook_answers() {
        let server = MockServer::start().await;
        let page = "e".repeat(300_000);
        Mock::given(path("/events"))
            .respond_with(ResponseTemplate::new(200).set_body_string(page.clone()))
            .mount(&server)
            .await;
        let client = client(&loopback());
        let url = format!("{}/events", server.uri());
        let for_provider = OutboundRequest::new(Method::GET, Url::parse(&url).unwrap(), HttpPurpose::ProviderApi);
        let events = client.send(for_provider).await.unwrap();
        assert_eq!(events.body.len(), page.len(), "the provider cap is far above 256 KiB");
        let for_oauth = OutboundRequest::new(Method::GET, Url::parse(&url).unwrap(), HttpPurpose::OAuth);
        assert_eq!(
            client.send(for_oauth).await.unwrap_err().kind,
            PortErrorKind::Rejected,
            "an OAuth answer of that size is not a token document"
        );
        let for_webhook = client.send(request(Method::GET, &url)).await.unwrap();
        assert_eq!(for_webhook.body.len(), 65_536, "a webhook answer is cut at 64 KiB");
    }

    #[tokio::test]
    async fn provider_calls_have_their_own_timeout() {
        let server = MockServer::start().await;
        Mock::given(path("/slow"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(400)))
            .mount(&server)
            .await;
        let client = client(&EgressConfig {
            connect_timeout: Duration::from_millis(100),
            total_timeout: Duration::from_millis(150),
            provider_api_total_timeout: Duration::from_secs(5),
            ..loopback()
        });
        let url = format!("{}/slow", server.uri());
        let webhook = client.send(request(Method::GET, &url)).await.unwrap_err();
        assert_eq!(webhook.kind, PortErrorKind::Timeout, "{webhook}");
        let provider = OutboundRequest::new(Method::GET, Url::parse(&url).unwrap(), HttpPurpose::ProviderApi);
        assert_eq!(client.send(provider).await.unwrap().status, StatusCode::OK);
    }

    #[tokio::test]
    async fn slow_receivers_time_out() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
            .mount(&server)
            .await;
        let impatient = client(&EgressConfig {
            connect_timeout: Duration::from_millis(100),
            total_timeout: Duration::from_millis(200),
            ..loopback()
        });
        let error = impatient.send(request(Method::GET, &server.uri())).await.unwrap_err();
        assert_eq!(error.kind, PortErrorKind::Timeout, "{error}");
    }

    #[tokio::test]
    async fn unreachable_targets_are_unavailable_and_errors_hide_the_url() {
        let port = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap().port()
        };
        let error = client(&loopback())
            .send(request(
                Method::GET,
                &format!("http://127.0.0.1:{port}/path?token=s3cret"),
            ))
            .await
            .unwrap_err();
        assert_eq!(error.kind, PortErrorKind::Unavailable, "{error}");
        let shown = error.to_string();
        assert!(!shown.contains("s3cret") && !shown.contains("127.0.0.1"), "{shown}");
    }

    #[tokio::test]
    async fn validation_applies_the_same_policy_without_sending() {
        let lookup = TableLookup::of(&[
            ("hooks.example.org", &["93.184.216.34"]),
            ("internal.example.org", &["10.1.2.3"]),
            ("empty.example.org", &[]),
        ]);
        let client = EgressHttpClient::with_lookup(&EgressConfig::default(), lookup).unwrap();
        let check = |text: &str| {
            let url = Url::parse(text).unwrap();
            let client = client.clone();
            async move { client.validate_url(&url).await }
        };
        assert_eq!(check("https://hooks.example.org/in").await, Ok(()));
        assert_eq!(check("https://8.8.8.8/").await, Ok(()));
        for refused in [
            "http://hooks.example.org/",
            "https://internal.example.org/",
            "https://127.0.0.1/",
            "https://[::1]/",
            "https://user:pw@hooks.example.org/",
        ] {
            assert_eq!(
                check(refused).await.unwrap_err().kind,
                PortErrorKind::Rejected,
                "{refused}"
            );
        }
        assert_eq!(
            check("https://empty.example.org/").await.unwrap_err().kind,
            PortErrorKind::Unavailable
        );
        assert_eq!(
            check("https://unknown.example.org/").await.unwrap_err().kind,
            PortErrorKind::Unavailable
        );
    }

    /// A lookup that fails with one kind of I/O error for every name.
    struct FailingLookup(std::io::ErrorKind);

    #[async_trait::async_trait]
    impl HostLookup for FailingLookup {
        async fn lookup(&self, _host: &str) -> std::io::Result<Vec<std::net::IpAddr>> {
            Err(std::io::Error::new(self.0, "scripted failure"))
        }
    }

    #[tokio::test]
    async fn a_lookup_that_times_out_is_a_timeout_and_one_that_fails_is_unavailable() {
        // Callers retry a timeout and an unavailable target, but they report them apart; neither is a refusal of
        // the policy, which would make a webhook registration fail for good.
        let url = Url::parse("https://hooks.example.org/in").unwrap();
        for (kind, expected) in [
            (std::io::ErrorKind::TimedOut, PortErrorKind::Timeout),
            (std::io::ErrorKind::ConnectionRefused, PortErrorKind::Unavailable),
            (std::io::ErrorKind::NotFound, PortErrorKind::Unavailable),
        ] {
            let client =
                EgressHttpClient::with_lookup(&EgressConfig::default(), Arc::new(FailingLookup(kind))).unwrap();
            let validated = client.validate_url(&url).await.unwrap_err();
            assert_eq!(validated.kind, expected, "validate_url, {kind:?}: {validated}");
            let sent = client
                .send(OutboundRequest::new(Method::POST, url.clone(), HttpPurpose::Webhook))
                .await
                .unwrap_err();
            assert_eq!(sent.kind, expected, "send, {kind:?}: {sent}");
            assert!(!sent.message.contains("hooks.example.org"), "quiet: {sent}");
        }
    }

    #[tokio::test]
    async fn the_adapter_passes_the_http_client_contract() {
        davhaven_port_tests::http_client::run_all(|| Arc::new(client(&EgressConfig::default()))).await;
    }

    #[test]
    fn invalid_configuration_is_reported_by_key() {
        let bad = EgressConfig {
            max_response_bytes: 0,
            ..EgressConfig::default()
        };
        let error = EgressHttpClient::new(&bad).unwrap_err();
        assert!(error.to_string().contains("max_response_bytes"), "{error}");
        assert_eq!(
            format!("{:?}", client(&EgressConfig::default())),
            "EgressHttpClient { max_response_bytes: 65536, .. }"
        );
    }
}
