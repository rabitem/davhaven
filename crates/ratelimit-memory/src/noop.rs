//! The `noop` rate limiter: allows everything.
//!
//! For tests and benchmarks that must not be slowed down or influenced by limits (the permission matrix runs with
//! it) and for deployments that rate-limit in front of Davhaven. It never denies, keeps no state and reports an
//! unlimited allowance. Production mode refuses it, because a forgotten `noop` would silently remove the failure
//! backoff of authentication.

use async_trait::async_trait;
use davhaven_ports::{PortError, PortLabel, RateDecision, RateKey, RateLimiter, observe};

/// The label of the limiter in metrics and spans.
const LABEL: PortLabel = PortLabel::new("rate_limiter", crate::plugin::NOOP);

/// A rate limiter that allows every request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoopRateLimiter;

#[async_trait]
impl RateLimiter for NoopRateLimiter {
    async fn check(&self, _key: &RateKey, _cost: u32) -> Result<RateDecision, PortError> {
        observe(LABEL, "check", async { Ok(RateDecision::allow(u32::MAX)) }).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use davhaven_port_tests::rate_limit::{BackoffRig, run, run_all, run_backoff, run_limited};
    use davhaven_ports::testing::ManualClock;

    use super::*;

    #[tokio::test]
    async fn the_noop_limiter_satisfies_the_common_contract_and_limits_nothing() {
        run_all(|| Arc::new(NoopRateLimiter)).await;
        assert_eq!(run(|| Arc::new(NoopRateLimiter)).await.case_count(), 3);
        let report = run_limited(|| Arc::new(NoopRateLimiter)).await;
        assert_eq!(
            report.failed_cases(),
            vec!["the bucket runs dry after a bounded number of checks"],
            "it must not pass the cases of a limiter that limits"
        );
    }

    #[tokio::test]
    async fn the_noop_limiter_does_not_back_off_and_the_backoff_contract_says_so() {
        let report = run_backoff(|| BackoffRig {
            limiter: Arc::new(NoopRateLimiter),
            clock: ManualClock::default(),
        })
        .await;
        assert!(
            report
                .failed_cases()
                .contains(&"failures end in a block with a positive wait"),
            "a limiter without backoff must not pass the backoff cases: {report}"
        );
    }

    #[tokio::test]
    async fn every_check_is_allowed_with_an_unlimited_allowance() {
        let decision = NoopRateLimiter
            .check(&RateKey::new("auth_failure", "k"), u32::MAX)
            .await
            .unwrap();
        assert_eq!(decision, RateDecision::allow(u32::MAX));
    }
}
