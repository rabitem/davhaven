//! `observe`: latency histogram, outcome counter and span around every adapter call.
//!
//! Every adapter method wraps its body in [`observe`] (`ENGINEERING_RULES` R8), so all ports report the same
//! signals without each adapter inventing its own:
//!
//! * `davhaven_port_calls_total{port,adapter,op,outcome}`, a counter; `outcome` is `ok` or the error class
//!   ([`ErrorClass::outcome`]);
//! * `davhaven_port_call_duration_seconds{port,adapter,op}`, a histogram of the call's wall-clock time;
//! * a `port_call` tracing span with the same labels, so traces show port calls under the request span.
//!
//! Labels are static strings chosen by the adapter, never request data: no tenant, principal, address or id ever
//! becomes a label.

use std::future::Future;
use std::time::Instant;

use tracing::Instrument;

use crate::error::{HandlerError, PortError, StoreError};

/// The metric name of the call counter.
pub const CALLS_TOTAL: &str = "davhaven_port_calls_total";

/// The metric name of the call latency histogram.
pub const CALL_DURATION_SECONDS: &str = "davhaven_port_call_duration_seconds";

/// Identifies the adapter a call goes through: the port (`database`, `mail_transport`, ...) and the adapter's
/// registered name (`postgres`, `smtp`, ...). Adapters define one constant and pass it to every [`observe`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortLabel {
    /// The port, for example `database`.
    pub port: &'static str,
    /// The adapter, for example `postgres`.
    pub adapter: &'static str,
}

impl PortLabel {
    /// Creates a label.
    pub const fn new(port: &'static str, adapter: &'static str) -> Self {
        Self { port, adapter }
    }
}

/// Classifies an error for the `outcome` label.
pub trait ErrorClass {
    /// A stable `snake_case` class with few distinct values; never error text.
    fn outcome(&self) -> &'static str;
}

impl ErrorClass for StoreError {
    fn outcome(&self) -> &'static str {
        self.as_str()
    }
}

impl ErrorClass for PortError {
    fn outcome(&self) -> &'static str {
        self.kind.as_str()
    }
}

impl ErrorClass for HandlerError {
    fn outcome(&self) -> &'static str {
        match self {
            Self::Retryable(_) => "retryable",
            Self::Permanent(_) => "permanent",
            Self::Defer { .. } => "deferred",
        }
    }
}

/// Runs `call`, recording its latency, its outcome and a tracing span.
///
/// `op` names the operation with a static string such as `objects.put`.
///
/// # Errors
///
/// Returns the error of `call` unchanged; it only influences the `outcome` label.
pub async fn observe<T, E, F>(label: PortLabel, op: &'static str, call: F) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
    E: ErrorClass,
{
    let span = tracing::info_span!("port_call", port = label.port, adapter = label.adapter, op);
    let started = Instant::now();
    let result = call.instrument(span).await;
    let outcome = match &result {
        Ok(_) => "ok",
        Err(error) => error.outcome(),
    };
    metrics::counter!(
        CALLS_TOTAL,
        "port" => label.port,
        "adapter" => label.adapter,
        "op" => op,
        "outcome" => outcome
    )
    .increment(1);
    metrics::histogram!(
        CALL_DURATION_SECONDS,
        "port" => label.port,
        "adapter" => label.adapter,
        "op" => op
    )
    .record(started.elapsed().as_secs_f64());
    result
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, RwLock};

    use metrics::{
        Counter, CounterFn, Gauge, Histogram, HistogramFn, Key, KeyName, Metadata, Recorder, SharedString, Unit,
    };

    use super::*;

    type Store = Arc<RwLock<BTreeMap<String, u64>>>;

    /// Counts increments and histogram samples per series (`name{label=value,...}`).
    #[derive(Default)]
    struct Capture {
        counters: Store,
        histograms: Store,
    }

    struct Series {
        name: String,
        store: Store,
    }

    impl CounterFn for Series {
        fn increment(&self, value: u64) {
            *self.store.write().unwrap().entry(self.name.clone()).or_insert(0) += value;
        }

        fn absolute(&self, value: u64) {
            self.store.write().unwrap().insert(self.name.clone(), value);
        }
    }

    impl HistogramFn for Series {
        fn record(&self, value: f64) {
            assert!(value >= 0.0, "latency is never negative");
            *self.store.write().unwrap().entry(self.name.clone()).or_insert(0) += 1;
        }
    }

    fn series_name(key: &Key) -> String {
        let mut labels: Vec<String> = key
            .labels()
            .map(|label| format!("{}={}", label.key(), label.value()))
            .collect();
        labels.sort();
        format!("{}{{{}}}", key.name(), labels.join(","))
    }

    impl Recorder for Capture {
        fn describe_counter(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

        fn describe_gauge(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

        fn describe_histogram(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

        fn register_counter(&self, key: &Key, _metadata: &Metadata<'_>) -> Counter {
            Counter::from_arc(Arc::new(Series {
                name: series_name(key),
                store: Arc::clone(&self.counters),
            }))
        }

        fn register_gauge(&self, _key: &Key, _metadata: &Metadata<'_>) -> Gauge {
            Gauge::noop()
        }

        fn register_histogram(&self, key: &Key, _metadata: &Metadata<'_>) -> Histogram {
            Histogram::from_arc(Arc::new(Series {
                name: series_name(key),
                store: Arc::clone(&self.histograms),
            }))
        }
    }

    const LABEL: PortLabel = PortLabel::new("database", "postgres");

    fn run<T>(capture: &Capture, future: impl Future<Output = T>) -> T {
        metrics::with_local_recorder(capture, || futures::executor::block_on(future))
    }

    #[test]
    fn successful_calls_count_ok_and_record_latency() {
        let capture = Capture::default();
        let value = run(&capture, async {
            observe(LABEL, "objects.get", async { Ok::<_, StoreError>(42) }).await
        });
        assert_eq!(value, Ok(42));
        let counters = capture.counters.read().unwrap().clone();
        let expected = "davhaven_port_calls_total{adapter=postgres,op=objects.get,outcome=ok,port=database}";
        assert_eq!(counters.get(expected), Some(&1), "{counters:?}");
        let histograms = capture.histograms.read().unwrap().clone();
        let expected = "davhaven_port_call_duration_seconds{adapter=postgres,op=objects.get,port=database}";
        assert_eq!(histograms.get(expected), Some(&1), "{histograms:?}");
    }

    #[test]
    fn failures_are_labelled_with_their_error_class_and_pass_through() {
        let capture = Capture::default();
        let results = run(&capture, async {
            let not_found = observe(LABEL, "objects.get", async { Err::<(), _>(StoreError::NotFound) }).await;
            let again = observe(LABEL, "objects.get", async { Err::<(), _>(StoreError::NotFound) }).await;
            let mail = observe(PortLabel::new("mail_transport", "smtp"), "send", async {
                Err::<(), _>(PortError::timeout("slow relay"))
            })
            .await;
            let handler = observe(PortLabel::new("outbox_handler", "webhook"), "handle", async {
                Err::<(), _>(HandlerError::permanent("gone"))
            })
            .await;
            (not_found, again, mail, handler)
        });
        assert_eq!(results.0, Err(StoreError::NotFound));
        assert_eq!(results.2, Err(PortError::timeout("slow relay")));
        assert_eq!(results.3, Err(HandlerError::permanent("gone")));

        let counters = capture.counters.read().unwrap().clone();
        let count = |name: &str| counters.get(name).copied().unwrap_or(0);
        assert_eq!(
            count("davhaven_port_calls_total{adapter=postgres,op=objects.get,outcome=not_found,port=database}"),
            2
        );
        assert_eq!(
            count("davhaven_port_calls_total{adapter=smtp,op=send,outcome=timeout,port=mail_transport}"),
            1
        );
        assert_eq!(
            count("davhaven_port_calls_total{adapter=webhook,op=handle,outcome=permanent,port=outbox_handler}"),
            1
        );
    }

    #[test]
    fn error_classes_have_few_stable_values() {
        assert_eq!(
            StoreError::UniqueViolation(crate::error::UniqueKey::Grant).outcome(),
            "unique_violation"
        );
        assert_eq!(PortError::invalid("x").outcome(), "invalid");
        assert_eq!(HandlerError::retryable("x").outcome(), "retryable");
    }
}
