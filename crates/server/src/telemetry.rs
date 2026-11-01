//! Structured logging, metrics and optional OTLP trace export.
//!
//! This module defines the `[observability]` table (PLAN 2.17, `ENGINEERING_RULES` R8) and starts what it
//! configures: JSON logs with request id, trace id, tenant id and principal id (never secrets, bodies, iCalendar
//! data or e-mail addresses), Prometheus metrics with the `davhaven_` prefix, an optional OTLP exporter and the
//! settings of the opt-in DAV capture that produces fixtures for the client-flow suite.
//!
//! * **Logs** go to standard error, one JSON object per line (`log_format = "json"`, the default) or compact text
//!   for development. The filter is `observability.log_filter` (`info` by default, the syntax of `tracing`
//!   directives such as `info,davhaven_app=debug`); the `RUST_LOG` environment variable overrides it for a debugging
//!   session without a configuration change.
//! * **Metrics** are recorded by the `metrics` crate wherever the code counts something and rendered by the
//!   Prometheus recorder on `/metrics` of the ops listener. Duration histograms use fixed buckets so that they
//!   aggregate across instances.
//! * **Traces** are exported over plain OTLP/gRPC (the collector's port 4317) when `observability.otlp.endpoint` is set;
//!   the sample ratio applies to traces that start here, the decision of the caller wins for traces that arrive with
//!   a W3C `traceparent`. Every request gets a server span ([`request_spans`]) whose parent is the caller's span, taken from
//!   the `traceparent` header by the W3C propagator that [`init`] installs, so the `port_call` spans of the adapters (see
//!   `davhaven_ports::observe`) nest under the request and the trace continues the caller's.

use std::path::PathBuf;

use axum::Router;
use axum::extract::{MatchedPath, Request};
use axum::http::HeaderMap;
use axum::middleware::{Next, from_fn};
use axum::response::Response;
use davhaven_app::config::ConfigError;
use davhaven_domain::TenantSlug;
use davhaven_http::trace::method_label;
use metrics_exporter_prometheus::{BuildError, Matcher, PrometheusBuilder, PrometheusHandle};
use opentelemetry::propagation::Extractor;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::Instrument as _;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use tracing_subscriber::filter::Directive;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{EnvFilter, Layer as _, Registry};
use url::Url;

/// The format of the log lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    /// One JSON object per line.
    #[default]
    Json,
    /// Human-readable lines for development.
    Text,
}

/// The `[observability.metrics]` table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct MetricsConfig {
    /// Reserved for metrics labelled with the tenant (off by default because of label cardinality; see
    /// `docs/ENGINEERING_RULES.md` R8). No metric carries the label yet, so `true` is **refused** (`docs/ROADMAP.md`)
    /// instead of accepted and ignored.
    pub tenant_label: bool,
}

/// The `[observability.otlp]` table.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct OtlpConfig {
    /// The OTLP/gRPC endpoint of the collector, an `http` URL with the collector's gRPC port
    /// (`http://otel-collector:4317`); traces are not exported when absent. The export is plain gRPC: run the collector
    /// on the local network (a sidecar or the same host) and let it carry the traffic onwards with TLS.
    pub endpoint: Option<Url>,
    /// The fraction of traces that are sampled, between 0 and 1.
    pub sample_ratio: f64,
}

impl Default for OtlpConfig {
    fn default() -> Self {
        Self {
            endpoint: None,
            sample_ratio: 0.1,
        }
    }
}

/// The `[observability.dav_capture]` table: records DAV exchanges of selected tenants as fixtures for the
/// client-flow suite. Credentials and bodies are redacted by the capture layer.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct DavCaptureConfig {
    /// Whether the capture middleware is active.
    pub enabled: bool,
    /// The tenants that are captured; capture needs an explicit allowlist.
    pub tenants: Vec<TenantSlug>,
    /// The directory the captures are written to.
    pub dir: Option<PathBuf>,
    /// Production mode refuses the capture, because it writes the calendar data of tenants to files. A staging instance that
    /// runs in production mode and captures on purpose sets this to `true`; the directory is then part of the data that
    /// must be protected like the database.
    pub allow_in_production: bool,
}

/// The `[observability]` table.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ObservabilityConfig {
    /// The format of the log lines.
    pub log_format: LogFormat,
    /// Which log lines are written: a `tracing` filter such as `info` or `info,davhaven_app=debug`. The
    /// `RUST_LOG` environment variable takes precedence.
    pub log_filter: String,
    /// Metrics options.
    pub metrics: MetricsConfig,
    /// Trace export.
    pub otlp: OtlpConfig,
    /// The DAV capture.
    pub dav_capture: DavCaptureConfig,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            log_format: LogFormat::Json,
            log_filter: "info".to_owned(),
            metrics: MetricsConfig::default(),
            otlp: OtlpConfig::default(),
            dav_capture: DavCaptureConfig::default(),
        }
    }
}

impl ObservabilityConfig {
    /// Checks the log filter, the sampling ratio, the OTLP endpoint and the capture settings.
    ///
    /// # Errors
    ///
    /// A [`ConfigError`] for the first unusable key of `observability`.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if EnvFilter::try_new(&self.log_filter).is_err() {
            return Err(ConfigError::new(
                "observability",
                "log_filter",
                "must be a tracing filter such as `info` or `info,davhaven_app=debug`",
            ));
        }
        if self.metrics.tenant_label {
            return Err(ConfigError::new(
                "observability.metrics",
                "tenant_label",
                "is reserved: no metric carries a tenant label in this release (docs/ROADMAP.md), so `true` would promise what \
                 this build does not do; leave it off",
            ));
        }
        if !(0.0..=1.0).contains(&self.otlp.sample_ratio) {
            return Err(ConfigError::new(
                "observability.otlp",
                "sample_ratio",
                "must be between 0 and 1",
            ));
        }
        if let Some(endpoint) = &self.otlp.endpoint
            && (!endpoint.username().is_empty() || endpoint.password().is_some())
        {
            return Err(ConfigError::new(
                "observability.otlp",
                "endpoint",
                "must not carry credentials in the URL (they would show up in logs and process listings); run the collector on a network that needs none",
            ));
        }
        if let Some(endpoint) = &self.otlp.endpoint
            && (endpoint.scheme() != "http" || endpoint.host_str().is_none())
        {
            return Err(ConfigError::new(
                "observability.otlp",
                "endpoint",
                "must be an http URL of the collector's gRPC port (TLS is not supported), for example http://otel-collector:4317",
            ));
        }
        if self.dav_capture.enabled {
            if self.dav_capture.tenants.is_empty() {
                return Err(ConfigError::new(
                    "observability.dav_capture",
                    "tenants",
                    "must list the captured tenants when the capture is enabled",
                ));
            }
            if self.dav_capture.dir.is_none() {
                return Err(ConfigError::new(
                    "observability.dav_capture",
                    "dir",
                    "is required when the capture is enabled",
                ));
            }
        }
        Ok(())
    }
}

/// Why logging, metrics or tracing could not be started.
#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    /// The log filter is not valid.
    #[error("the log filter is not valid: {0}")]
    Filter(String),
    /// A global subscriber or recorder is installed already.
    #[error("{0} is installed already")]
    AlreadyInstalled(&'static str),
    /// The metrics recorder could not be built.
    #[error("cannot start the metrics recorder: {0}")]
    Metrics(String),
    /// The trace exporter could not be built.
    #[error("cannot start the OTLP trace exporter: {0}")]
    Otlp(String),
}

impl From<BuildError> for TelemetryError {
    fn from(error: BuildError) -> Self {
        Self::Metrics(error.to_string())
    }
}

/// The buckets of every `*_duration_seconds` histogram: 1 ms to one minute.
pub const DURATION_BUCKETS: [f64; 14] = [
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 15.0, 60.0,
];

/// Installs the Prometheus recorder as the global `metrics` recorder and returns the handle that renders it.
///
/// The caller runs [`PrometheusHandle::run_upkeep`] periodically (the server does, every few seconds).
///
/// # Errors
///
/// [`TelemetryError::Metrics`] when the buckets are unusable or a recorder is installed already.
pub fn install_metrics() -> Result<PrometheusHandle, TelemetryError> {
    let builder = PrometheusBuilder::new()
        .set_buckets_for_metric(Matcher::Suffix("_duration_seconds".to_owned()), &DURATION_BUCKETS)?;
    Ok(builder.install_recorder()?)
}

/// What [`init`] started: the trace exporter, which must be flushed when the process ends.
#[derive(Default)]
pub struct Telemetry {
    #[cfg(feature = "otlp")]
    provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

impl core::fmt::Debug for Telemetry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut shown = f.debug_struct("Telemetry");
        #[cfg(feature = "otlp")]
        shown.field("exporting_traces", &self.provider.is_some());
        shown.finish_non_exhaustive()
    }
}

impl Telemetry {
    /// Flushes and stops the trace exporter. Logs and metrics need nothing.
    pub fn shutdown(self) {
        #[cfg(feature = "otlp")]
        if let Some(provider) = self.provider
            && let Err(error) = provider.shutdown()
        {
            tracing::warn!(%error, "the OTLP exporter did not shut down cleanly");
        }
        #[cfg(not(feature = "otlp"))]
        let _ = self;
    }
}

/// The directive that keeps the MCP transport library from logging what it carries (R8). `rmcp` logs the parsed request
/// and the result of every call at `debug` and the raw message at `trace`, which are event titles, descriptions and the
/// addresses of attendees, so whatever the filter says, the library does not log below `info`. A deployment that needs the
/// transport's own diagnostics names a more specific target (`rmcp::service=debug`) and takes the consequence knowingly.
const MCP_TRANSPORT_DIRECTIVE: &str = "rmcp=info";

/// The filter of the log: `RUST_LOG` when set, else the configured one, and always [`MCP_TRANSPORT_DIRECTIVE`].
fn log_filter(config: &ObservabilityConfig) -> Result<EnvFilter, TelemetryError> {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&config.log_filter))
        .map_err(|error| TelemetryError::Filter(error.to_string()))?;
    let directive = MCP_TRANSPORT_DIRECTIVE
        .parse::<Directive>()
        .map_err(|error| TelemetryError::Filter(error.to_string()))?;
    Ok(filter.add_directive(directive))
}

/// Builds the layer that exports spans over OTLP/gRPC. Must run inside the Tokio runtime: the exporter's channel
/// is created on it.
#[cfg(feature = "otlp")]
fn otlp_layer(
    config: &OtlpConfig,
    endpoint: &Url,
) -> Result<
    (
        opentelemetry_sdk::trace::SdkTracerProvider,
        Box<dyn tracing_subscriber::Layer<Registry> + Send + Sync + 'static>,
    ),
    TelemetryError,
> {
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::WithExportConfig as _;
    use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint.as_str())
        .build()
        .map_err(|error| TelemetryError::Otlp(error.to_string()))?;
    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
            config.sample_ratio,
        ))))
        .with_resource(
            opentelemetry_sdk::Resource::builder()
                .with_service_name("davhaven")
                .build(),
        )
        .build();
    let tracer = provider.tracer("davhaven");
    let layer = tracing_opentelemetry::layer().with_tracer(tracer).boxed();
    Ok((provider, layer))
}

/// The headers of a request as the carrier of a propagator.
struct HeaderCarrier<'a>(&'a HeaderMap);

impl Extractor for HeaderCarrier<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|value| value.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(axum::http::HeaderName::as_str).collect()
    }
}

/// Wraps `router` so that every request runs inside a server span.
///
/// The span is named after the method and the route template (`GET /dav/calendars/{tenant}/{principal}/`), never the raw
/// path, which can carry tokens. Its parent is the span the caller named in a W3C `traceparent` header, so the trace of a
/// caller that propagates its context continues here and the sampling decision of the caller wins (the sampler is
/// parent-based); a request without the header starts a trace that is sampled by `observability.otlp.sample_ratio`. The
/// adapters' `port_call` spans are children of this span because the rest of the request runs inside it.
///
/// Apply it as the outermost layer of a listener, so that the edge layers (authentication, rate limits) run inside the
/// span too.
pub fn request_spans(router: Router) -> Router {
    router.layer(from_fn(request_span))
}

async fn request_span(request: Request, next: Next) -> Response {
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or("unmatched", MatchedPath::as_str)
        .to_owned();
    let method = method_label(request.method());
    let span = tracing::info_span!(
        "http_request",
        otel.name = format!("{method} {route}"),
        otel.kind = "server",
        otel.status_code = tracing::field::Empty,
        http.request.method = method,
        http.route = route,
        http.response.status_code = tracing::field::Empty,
    );
    if request.headers().contains_key("traceparent") {
        let parent = opentelemetry::global::get_text_map_propagator(|propagator| {
            propagator.extract(&HeaderCarrier(request.headers()))
        });
        // Only fails for a span that is disabled by the filter, which has nothing to attach a parent to.
        drop(span.set_parent(parent));
    }
    let response = next.run(request).instrument(span.clone()).await;
    let status = response.status();
    span.record("http.response.status_code", status.as_u16());
    if status.is_server_error() {
        span.record("otel.status_code", "ERROR");
    }
    response
}

/// Installs the global tracing subscriber: the log lines and, when an OTLP endpoint is configured, the span
/// exporter.
///
/// # Errors
///
/// [`TelemetryError`] for an invalid filter, an exporter that cannot be built or a subscriber that is installed
/// already (the process initialises logging once).
pub fn init(config: &ObservabilityConfig) -> Result<Telemetry, TelemetryError> {
    let filter = log_filter(config)?;
    // The W3C trace context is read from every request, whether or not this instance exports traces: the spans of a
    // request then carry the caller's trace id, and the same id is in the logs of the edge.
    opentelemetry::global::set_text_map_propagator(opentelemetry_sdk::propagation::TraceContextPropagator::new());
    let writer = std::io::stderr;
    let lines: Box<dyn tracing_subscriber::Layer<Registry> + Send + Sync + 'static> = match config.log_format {
        LogFormat::Json => tracing_subscriber::fmt::layer()
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .with_span_list(false)
            .with_writer(writer)
            .boxed(),
        LogFormat::Text => tracing_subscriber::fmt::layer()
            .compact()
            .with_ansi(false)
            .with_writer(writer)
            .boxed(),
    };
    #[cfg_attr(
        not(feature = "otlp"),
        expect(unused_mut, reason = "layers are added only when traces are exported")
    )]
    let mut layers = vec![lines];
    #[cfg_attr(
        not(feature = "otlp"),
        expect(unused_mut, reason = "the exporter is recorded only when traces are exported")
    )]
    let mut telemetry = Telemetry::default();
    #[cfg(feature = "otlp")]
    if let Some(endpoint) = &config.otlp.endpoint {
        let (provider, layer) = otlp_layer(&config.otlp, endpoint)?;
        layers.push(layer);
        telemetry.provider = Some(provider);
    }
    Registry::default()
        .with(layers)
        .with(filter)
        .try_init()
        .map_err(|_| TelemetryError::AlreadyInstalled("a global tracing subscriber"))?;
    #[cfg(not(feature = "otlp"))]
    if config.otlp.endpoint.is_some() {
        tracing::warn!("observability.otlp.endpoint is set, but this build does not include the `otlp` feature");
    }
    Ok(telemetry)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> ObservabilityConfig {
        serde_json::from_str(text).unwrap()
    }

    #[test]
    fn defaults_are_the_plan_values() {
        let config = ObservabilityConfig::default();
        assert_eq!(config.log_format, LogFormat::Json);
        assert_eq!(config.log_filter, "info");
        assert!(!config.metrics.tenant_label);
        assert!(!config.dav_capture.enabled);
        assert!(config.otlp.endpoint.is_none());
        assert!((config.otlp.sample_ratio - 0.1).abs() < f64::EPSILON);
        config.validate().unwrap();
        assert_eq!(parse("{}"), config);
    }

    #[test]
    fn the_transport_of_mcp_never_logs_below_info_whatever_the_filter_says() {
        // The library logs what it carries (event titles, attendee addresses) at debug and trace (R8).
        for text in ["debug", "trace", "info,davhaven_app=debug", "rmcp=trace"] {
            let config = ObservabilityConfig {
                log_filter: text.to_owned(),
                ..ObservabilityConfig::default()
            };
            let filter = log_filter(&config).unwrap();
            assert!(
                filter.to_string().contains(MCP_TRANSPORT_DIRECTIVE),
                "the directive survives `{text}`: {filter}"
            );
        }
        assert!(MCP_TRANSPORT_DIRECTIVE.parse::<Directive>().is_ok());
    }

    #[test]
    fn tables_parse_and_typos_fail() {
        let config = parse(
            r#"{"log_format": "text", "log_filter": "debug,hyper=warn",
                "metrics": {"tenant_label": false},
                "otlp": {"endpoint": "http://otel:4317", "sample_ratio": 0.5},
                "dav_capture": {"enabled": true, "tenants": ["acme"], "dir": "/var/capture"}}"#,
        );
        assert_eq!(config.log_format, LogFormat::Text);
        assert!(!config.metrics.tenant_label);
        config.validate().unwrap();
        assert!(serde_json::from_str::<ObservabilityConfig>(r#"{"log": "json"}"#).is_err());
        assert!(serde_json::from_str::<ObservabilityConfig>(r#"{"log_format": "xml"}"#).is_err());
        assert!(
            serde_json::from_str::<ObservabilityConfig>(r#"{"dav_capture": {"tenants": ["Not A Slug"]}}"#).is_err()
        );
    }

    #[test]
    fn validation_names_the_key() {
        for (text, key) in [
            (r#"{"log_filter": "info,=="}"#, "log_filter"),
            (r#"{"metrics": {"tenant_label": true}}"#, "tenant_label"),
            (r#"{"otlp": {"sample_ratio": 1.5}}"#, "sample_ratio"),
            (r#"{"otlp": {"sample_ratio": -0.1}}"#, "sample_ratio"),
            (r#"{"otlp": {"endpoint": "ftp://otel"}}"#, "endpoint"),
            (r#"{"otlp": {"endpoint": "https://otel:4317"}}"#, "endpoint"),
            (r#"{"otlp": {"endpoint": "http://user:pw@otel:4317"}}"#, "endpoint"),
            (r#"{"otlp": {"endpoint": "http://token@otel:4317"}}"#, "endpoint"),
            (r#"{"dav_capture": {"enabled": true, "dir": "/x"}}"#, "tenants"),
            (r#"{"dav_capture": {"enabled": true, "tenants": ["acme"]}}"#, "dir"),
        ] {
            let error = parse(text).validate().unwrap_err();
            assert_eq!(error.key(), key, "{text}");
        }
    }

    /// The trace of the caller in the `traceparent` header of the tests, and its span.
    const TRACE: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
    const CALLER_SPAN: &str = "00f067aa0ba902b7";

    /// The spans a request leaves behind when the adapter call in its handler runs under the request span: the sampler
    /// follows the caller and samples no trace of its own (ratio 0).
    async fn spans_of(traceparent: Option<String>) -> Vec<opentelemetry_sdk::trace::SpanData> {
        spans_for("/api/v1/tenants/acme", axum::http::StatusCode::OK, traceparent).await
    }

    /// [`spans_of`] for a request to `uri`, which answers with `status`.
    async fn spans_for(
        uri: &str,
        status: axum::http::StatusCode,
        traceparent: Option<String>,
    ) -> Vec<opentelemetry_sdk::trace::SpanData> {
        use opentelemetry::trace::TracerProvider as _;
        use opentelemetry_sdk::trace::{InMemorySpanExporter, Sampler, SdkTracerProvider};
        use tower::ServiceExt as _;

        opentelemetry::global::set_text_map_propagator(opentelemetry_sdk::propagation::TraceContextPropagator::new());
        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(0.0))))
            .build();
        let subscriber = Registry::default().with(tracing_opentelemetry::layer().with_tracer(provider.tracer("test")));
        let _installed = tracing::subscriber::set_default(subscriber);
        let app = request_spans(
            Router::new()
                .route(
                    "/api/v1/tenants/{tenant}",
                    axum::routing::get(|| async {
                        davhaven_ports::observe(
                            davhaven_ports::PortLabel::new("database", "memory"),
                            "tenants.get",
                            async { Ok::<_, davhaven_ports::StoreError>(()) },
                        )
                        .await
                        .map_or("failed", |()| "ok")
                    }),
                )
                .route(
                    "/api/v1/tenants/{tenant}/fail",
                    axum::routing::get(|| async { axum::http::StatusCode::INTERNAL_SERVER_ERROR }),
                ),
        );
        let mut request = Request::builder().uri(uri);
        if let Some(value) = traceparent {
            request = request.header("traceparent", value);
        }
        let response = app
            .oneshot(request.body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        exporter.get_finished_spans().unwrap()
    }

    /// The value of the attribute `name` of `span`.
    fn attribute_of(span: &opentelemetry_sdk::trace::SpanData, name: &str) -> Option<String> {
        span.attributes
            .iter()
            .find(|attribute| attribute.key.as_str() == name)
            .map(|attribute| attribute.value.to_string())
    }

    #[tokio::test]
    async fn a_server_error_marks_the_request_span_as_failed() {
        let spans = spans_for(
            "/api/v1/tenants/acme/fail",
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Some(format!("00-{TRACE}-{CALLER_SPAN}-01")),
        )
        .await;
        let [request] = spans.as_slice() else {
            panic!("one span: {spans:?}");
        };
        assert_eq!(request.name, "GET /api/v1/tenants/{tenant}/fail");
        assert_eq!(
            attribute_of(request, "http.response.status_code").as_deref(),
            Some("500")
        );
        assert!(
            matches!(request.status, opentelemetry::trace::Status::Error { .. }),
            "{:?}",
            request.status
        );
        // A success leaves the status alone.
        let spans = spans_of(Some(format!("00-{TRACE}-{CALLER_SPAN}-01"))).await;
        let request = spans.iter().find(|span| span.name.starts_with("GET ")).unwrap();
        assert_eq!(request.status, opentelemetry::trace::Status::Unset);
    }

    #[tokio::test]
    async fn a_path_that_matches_no_route_never_names_the_span() {
        // A path can carry a secret (the token of a feed, a mistyped one included): without a route template the span says
        // `unmatched` and nothing of the path.
        let spans = spans_for(
            "/feed/dvh_feed_secret123/calendar.ics",
            axum::http::StatusCode::NOT_FOUND,
            Some(format!("00-{TRACE}-{CALLER_SPAN}-01")),
        )
        .await;
        let [request] = spans.as_slice() else {
            panic!("one span: {spans:?}");
        };
        assert_eq!(request.name, "GET unmatched");
        assert_eq!(attribute_of(request, "http.route").as_deref(), Some("unmatched"));
        assert!(!format!("{request:?}").contains("secret123"), "{request:?}");
        assert_eq!(
            request.status,
            opentelemetry::trace::Status::Unset,
            "a 404 is no failure of the server"
        );
    }

    #[tokio::test]
    async fn a_request_continues_the_trace_of_its_caller_and_port_calls_nest_under_it() {
        let spans = spans_of(Some(format!("00-{TRACE}-{CALLER_SPAN}-01"))).await;
        let request = spans
            .iter()
            .find(|span| span.name == "GET /api/v1/tenants/{tenant}")
            .unwrap_or_else(|| {
                panic!(
                    "no request span, the spans are {:?}",
                    spans.iter().map(|s| s.name.clone()).collect::<Vec<_>>()
                )
            });
        assert_eq!(
            request.span_context.trace_id().to_string(),
            TRACE,
            "the trace of the caller"
        );
        assert_eq!(
            request.parent_span_id.to_string(),
            CALLER_SPAN,
            "the caller's span is the parent"
        );
        assert_eq!(request.span_kind, opentelemetry::trace::SpanKind::Server);
        let port = spans
            .iter()
            .find(|span| span.name == "port_call")
            .expect("a port call span");
        assert_eq!(port.span_context.trace_id(), request.span_context.trace_id());
        assert_eq!(
            port.parent_span_id,
            request.span_context.span_id(),
            "the adapter call is a child of the request"
        );
        let attribute = |name: &str| {
            request
                .attributes
                .iter()
                .find(|attribute| attribute.key.as_str() == name)
                .map(|attribute| attribute.value.to_string())
        };
        assert_eq!(attribute("http.route").as_deref(), Some("/api/v1/tenants/{tenant}"));
        assert_eq!(attribute("http.response.status_code").as_deref(), Some("200"));
        assert!(
            !format!("{request:?}").contains("acme"),
            "the span is named after the route template, not the raw path"
        );
    }

    #[tokio::test]
    async fn the_sampling_decision_of_the_caller_wins_and_a_request_without_context_follows_the_ratio() {
        let unsampled = spans_of(Some(format!("00-{TRACE}-{CALLER_SPAN}-00"))).await;
        assert!(
            unsampled.is_empty(),
            "the caller did not sample the trace: {unsampled:?}"
        );
        let alone = spans_of(None).await;
        assert!(alone.is_empty(), "no context and a ratio of zero: {alone:?}");
        // A header that is not a trace context is ignored, never an error.
        let garbled = spans_of(Some("not a trace context".to_owned())).await;
        assert!(garbled.is_empty(), "{garbled:?}");
    }

    #[test]
    fn the_buckets_ascend() {
        assert!(DURATION_BUCKETS.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn metrics_render_with_histogram_buckets() {
        let recorder = PrometheusBuilder::new()
            .set_buckets_for_metric(Matcher::Suffix("_duration_seconds".to_owned()), &DURATION_BUCKETS)
            .unwrap()
            .build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            metrics::counter!("davhaven_test_total", "kind" => "x").increment(2);
            metrics::histogram!("davhaven_test_duration_seconds").record(0.2);
        });
        let text = handle.render();
        assert!(text.contains("davhaven_test_total{kind=\"x\"} 2"), "{text}");
        assert!(
            text.contains("davhaven_test_duration_seconds_bucket{le=\"0.25\"} 1"),
            "{text}"
        );
    }
}
