//! The fixture of the unit tests of the outbox, the iMIP composer and the asset service: an application core whose
//! ports are inert doubles (a database that is never reachable, a mail transport that never sends, ...), a deterministic
//! clock, ids, key ring and sealer, and a metrics recorder.
//!
//! The behavior that needs a store (the dispatcher, the services, the handlers) is tested against the in-memory
//! store in `davhaven-it`: the application layer cannot depend on an adapter, and a second implementation of the
//! `Database` port in the tests would only prove that the double agrees with itself.

use std::sync::{Arc, PoisonError};

use async_trait::async_trait;
use davhaven_domain::{CalendarUserAddress, Limits, OutgoingMail, PartStat, PublicUrls, TenantId};
use davhaven_ports::testing::{FixedHasher, FixedKeyRing, ManualClock, PlainSealer, SeqIds};
use davhaven_ports::{
    AuthHint, AuthOutcome, Authenticator, Database, FreeBusy, Health, HttpClient, Invite, MailTransport,
    OutboundRequest, OutboundResponse, PolicyTenant, PortError, PresentedCredential, RateDecision, RateKey,
    RateLimiter, RenderRequest, Rendered, ResourceRequest, SchedulingPolicy, SendReceipt, StoreError, SystemTx,
    TemplateName, TemplateRenderer, Tx, TxMode,
};
use url::Url;

use crate::config::AppConfig;
use crate::wiring::{AppCore, AppDeps};

/// The doubles lock for an instant and never across an await.
#[expect(clippy::disallowed_types, reason = "test doubles with synchronous accessors")]
type Mutex<T> = std::sync::Mutex<T>;

/// A database that refuses every transaction.
struct NoDatabase;

#[async_trait]
impl Database for NoDatabase {
    async fn begin(&self, _tenant: TenantId, _mode: TxMode) -> Result<Box<dyn Tx>, StoreError> {
        Err(StoreError::Unavailable)
    }

    async fn begin_system(&self) -> Result<Box<dyn SystemTx>, StoreError> {
        Err(StoreError::Unavailable)
    }

    async fn health(&self) -> Health {
        Health::Unhealthy("no database".to_owned())
    }
}

struct NoMail;

#[async_trait]
impl MailTransport for NoMail {
    async fn send(&self, _mail: &OutgoingMail) -> Result<SendReceipt, PortError> {
        Err(PortError::internal("the test double does not send"))
    }
}

struct NoHttp;

#[async_trait]
impl HttpClient for NoHttp {
    async fn send(&self, _request: OutboundRequest) -> Result<OutboundResponse, PortError> {
        Err(PortError::internal("the test double does not send"))
    }
}

struct NoTemplates;

#[async_trait]
impl TemplateRenderer for NoTemplates {
    async fn render(&self, _request: RenderRequest) -> Result<Rendered, PortError> {
        Err(PortError::unsupported())
    }

    fn catalog(&self) -> Vec<TemplateName> {
        Vec::new()
    }
}

struct AllowAll;

#[async_trait]
impl RateLimiter for AllowAll {
    async fn check(&self, _key: &RateKey, _cost: u32) -> Result<RateDecision, PortError> {
        Ok(RateDecision::allow(u32::MAX))
    }
}

struct NeverAuto;

#[async_trait]
impl SchedulingPolicy for NeverAuto {
    async fn auto_add(&self, _invite: &Invite) -> bool {
        false
    }

    async fn resource_reply(&self, _request: &ResourceRequest, _free_busy: &FreeBusy) -> Option<PartStat> {
        None
    }

    async fn external_allowed(&self, _tenant: &PolicyTenant, _address: &CalendarUserAddress) -> bool {
        false
    }
}

struct NoAuthenticator;

#[async_trait]
impl Authenticator for NoAuthenticator {
    async fn authenticate(
        &self,
        _credential: &PresentedCredential,
        _hint: &AuthHint,
    ) -> Result<AuthOutcome, PortError> {
        Ok(AuthOutcome::NotApplicable)
    }
}

/// An application core on inert doubles.
pub(crate) struct Fixture {
    pub(crate) core: AppCore,
}

impl Fixture {
    pub(crate) fn new() -> Self {
        Self::with(|_| {})
    }

    /// Builds the core after `adjust` changed the dependencies (the configuration, the renderer).
    pub(crate) fn with(adjust: impl FnOnce(&mut AppDeps)) -> Self {
        let mut deps = AppDeps {
            clock: Arc::new(ManualClock::default()),
            ids: Arc::new(SeqIds::starting_at(0x1000)),
            keyring: Arc::new(FixedKeyRing::default()),
            sealer: Arc::new(PlainSealer),
            hasher: Arc::new(FixedHasher::default()),
            database: Arc::new(NoDatabase),
            http: Arc::new(NoHttp),
            mail: Arc::new(NoMail),
            templates: Arc::new(NoTemplates),
            rate_limiter: Arc::new(AllowAll),
            scheduling_policy: Arc::new(NeverAuto),
            authenticators: vec![Arc::new(NoAuthenticator)],
            event_sinks: Vec::new(),
            outbox_handlers: Vec::new(),
            providers: Vec::new(),
            content_scanners: Vec::new(),
            profile_signer: None,
            urls: PublicUrls::new(Url::parse("https://cal.example.org").unwrap()).unwrap(),
            limits: Limits::default(),
            config: AppConfig::default(),
        };
        adjust(&mut deps);
        Self {
            core: AppCore::new(deps),
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------------------------------------------

/// A metrics recorder for tests: counters add up, gauges keep the last value and histograms count their samples,
/// all under the series name `name{label=value,...}` (labels sorted).
#[derive(Default, Clone)]
pub(crate) struct MetricsCapture {
    values: Arc<Mutex<std::collections::BTreeMap<String, f64>>>,
}

struct Series {
    name: String,
    values: Arc<Mutex<std::collections::BTreeMap<String, f64>>>,
}

impl Series {
    fn update(&self, change: impl FnOnce(&mut f64)) {
        let mut values = self.values.lock().unwrap_or_else(PoisonError::into_inner);
        change(values.entry(self.name.clone()).or_insert(0.0));
    }
}

impl metrics::CounterFn for Series {
    fn increment(&self, value: u64) {
        self.update(|slot| *slot += f64::from(u32::try_from(value).unwrap_or(u32::MAX)));
    }

    fn absolute(&self, value: u64) {
        self.update(|slot| *slot = f64::from(u32::try_from(value).unwrap_or(u32::MAX)));
    }
}

impl metrics::GaugeFn for Series {
    fn increment(&self, value: f64) {
        self.update(|slot| *slot += value);
    }

    fn decrement(&self, value: f64) {
        self.update(|slot| *slot -= value);
    }

    fn set(&self, value: f64) {
        self.update(|slot| *slot = value);
    }
}

impl metrics::HistogramFn for Series {
    fn record(&self, _value: f64) {
        self.update(|slot| *slot += 1.0);
    }
}

impl MetricsCapture {
    fn series(&self, key: &metrics::Key) -> Arc<Series> {
        let mut labels: Vec<String> = key
            .labels()
            .map(|label| format!("{}={}", label.key(), label.value()))
            .collect();
        labels.sort();
        let name = if labels.is_empty() {
            key.name().to_owned()
        } else {
            format!("{}{{{}}}", key.name(), labels.join(","))
        };
        Arc::new(Series {
            name,
            values: Arc::clone(&self.values),
        })
    }

    /// The value of a series, if anything was recorded.
    pub(crate) fn get(&self, series: &str) -> Option<f64> {
        self.values
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(series)
            .copied()
    }
}

impl metrics::Recorder for MetricsCapture {
    fn describe_counter(
        &self,
        _key: metrics::KeyName,
        _unit: Option<metrics::Unit>,
        _description: metrics::SharedString,
    ) {
    }

    fn describe_gauge(
        &self,
        _key: metrics::KeyName,
        _unit: Option<metrics::Unit>,
        _description: metrics::SharedString,
    ) {
    }

    fn describe_histogram(
        &self,
        _key: metrics::KeyName,
        _unit: Option<metrics::Unit>,
        _description: metrics::SharedString,
    ) {
    }

    fn register_counter(&self, key: &metrics::Key, _metadata: &metrics::Metadata<'_>) -> metrics::Counter {
        metrics::Counter::from_arc(self.series(key))
    }

    fn register_gauge(&self, key: &metrics::Key, _metadata: &metrics::Metadata<'_>) -> metrics::Gauge {
        metrics::Gauge::from_arc(self.series(key))
    }

    fn register_histogram(&self, key: &metrics::Key, _metadata: &metrics::Metadata<'_>) -> metrics::Histogram {
        metrics::Histogram::from_arc(self.series(key))
    }
}
