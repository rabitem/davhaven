use chrono::TimeZone;
use davhaven_domain::DomainName;

use super::*;
use crate::outbox::fixture::MetricsCapture;

fn at(seconds: i64) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap() + Duration::seconds(seconds)
}

fn mail(per_minute: u32, failures: u32) -> MailConfig {
    MailConfig {
        rate_limit_per_minute: per_minute,
        max_consecutive_failures: failures,
        ..MailConfig::default()
    }
}

fn outbox(base: u64, max: u64) -> OutboxConfig {
    OutboxConfig {
        backoff_base: std::time::Duration::from_secs(base),
        backoff_max: std::time::Duration::from_secs(max),
        ..OutboxConfig::default()
    }
}

#[tokio::test]
async fn the_rate_limit_is_a_token_bucket_that_refills_over_a_minute() {
    let guard = MailGuard::default();
    let config = mail(3, 5);
    for _ in 0..3 {
        assert_eq!(
            guard.admit_without_shared_limit(at(0), &config).await.kind(),
            GateKind::Go
        );
    }
    assert_eq!(
        guard.admit_without_shared_limit(at(0), &config).await.kind(),
        GateKind::RateLimited
    );
    assert_eq!(
        guard.admit_without_shared_limit(at(19), &config).await.kind(),
        GateKind::RateLimited,
        "one token takes 20 s"
    );
    assert_eq!(
        guard.admit_without_shared_limit(at(20), &config).await.kind(),
        GateKind::Go
    );
    assert_eq!(
        guard.admit_without_shared_limit(at(20), &config).await.kind(),
        GateKind::RateLimited
    );
    // A long pause never saves up more than a full bucket.
    for _ in 0..3 {
        assert_eq!(
            guard.admit_without_shared_limit(at(10_000), &config).await.kind(),
            GateKind::Go
        );
    }
    assert_eq!(
        guard.admit_without_shared_limit(at(10_000), &config).await.kind(),
        GateKind::RateLimited
    );
}

#[tokio::test]
async fn a_held_mail_is_told_how_long_to_wait() {
    let guard = MailGuard::default();
    let config = mail(3, 1);
    let waits = outbox(30, 3600);
    for _ in 0..3 {
        assert_eq!(guard.admit_without_shared_limit(at(0), &config).await, Gate::Go);
    }
    assert_eq!(
        guard.admit_without_shared_limit(at(0), &config).await,
        Gate::RateLimited {
            retry_after: Wait::from_secs(20)
        },
        "the next token takes 20 s"
    );

    let guard = MailGuard::default();
    let config = mail(1000, 1);
    guard.failed(at(0), &config, &waits).await;
    assert_eq!(
        guard.admit_without_shared_limit(at(10), &config).await,
        Gate::BreakerOpen {
            retry_after: Wait::from_secs(20)
        },
        "the cooldown of 30 s has 20 s to go"
    );
    assert_eq!(
        guard.admit_without_shared_limit(at(30), &config).await,
        Gate::Go,
        "the probe"
    );
    assert_eq!(
        guard.admit_without_shared_limit(at(31), &config).await,
        Gate::BreakerOpen {
            retry_after: PROBE_HOLD
        },
        "another mail waits for the probe"
    );
    guard.failed(at(31), &config, &waits).await;
    let Gate::BreakerOpen { retry_after } = guard.admit_without_shared_limit(at(31 + 59), &config).await else {
        panic!("the breaker opened again");
    };
    assert_eq!(retry_after, MIN_HOLD, "a hold is never shorter than a second");
}

#[tokio::test]
async fn the_breaker_opens_after_consecutive_failures_and_probes_after_the_cooldown() {
    let guard = MailGuard::default();
    let config = mail(1000, 3);
    let waits = outbox(30, 3600);

    for _ in 0..2 {
        assert_eq!(
            guard.admit_without_shared_limit(at(0), &config).await.kind(),
            GateKind::Go
        );
        guard.failed(at(0), &config, &waits).await;
    }
    assert!(!guard.is_open().await, "two failures are not enough");
    assert_eq!(
        guard.admit_without_shared_limit(at(0), &config).await.kind(),
        GateKind::Go
    );
    guard.failed(at(0), &config, &waits).await;
    assert!(guard.is_open().await);

    assert_eq!(
        guard.admit_without_shared_limit(at(10), &config).await.kind(),
        GateKind::BreakerOpen
    );
    assert_eq!(
        guard.admit_without_shared_limit(at(29), &config).await.kind(),
        GateKind::BreakerOpen
    );
    assert_eq!(
        guard.admit_without_shared_limit(at(30), &config).await.kind(),
        GateKind::Go,
        "the probe"
    );
    assert_eq!(
        guard.admit_without_shared_limit(at(30), &config).await.kind(),
        GateKind::BreakerOpen,
        "only one probe at a time"
    );

    // The probe fails: open again, for twice as long.
    guard.failed(at(31), &config, &waits).await;
    assert_eq!(
        guard.admit_without_shared_limit(at(31 + 59), &config).await.kind(),
        GateKind::BreakerOpen
    );
    assert_eq!(
        guard.admit_without_shared_limit(at(31 + 60), &config).await.kind(),
        GateKind::Go
    );

    // The probe succeeds: closed, and the next opening starts from the base again.
    guard.reachable().await;
    assert!(!guard.is_open().await);
    assert_eq!(
        guard.admit_without_shared_limit(at(100), &config).await.kind(),
        GateKind::Go
    );
    assert_eq!(
        guard.admit_without_shared_limit(at(100), &config).await.kind(),
        GateKind::Go
    );
    for _ in 0..3 {
        guard.failed(at(100), &config, &waits).await;
    }
    assert_eq!(
        guard.admit_without_shared_limit(at(129), &config).await.kind(),
        GateKind::BreakerOpen
    );
    assert_eq!(
        guard.admit_without_shared_limit(at(130), &config).await.kind(),
        GateKind::Go,
        "30 s again, not 120 s"
    );
}

#[tokio::test]
async fn an_answer_of_the_relay_resets_the_count_of_failures() {
    let guard = MailGuard::default();
    let config = mail(1000, 3);
    let waits = outbox(30, 3600);
    for _ in 0..10 {
        guard.failed(at(0), &config, &waits).await;
        guard.failed(at(0), &config, &waits).await;
        guard.reachable().await;
    }
    assert!(
        !guard.is_open().await,
        "failures that are not consecutive never open the breaker"
    );
    assert_eq!(
        guard.admit_without_shared_limit(at(0), &config).await.kind(),
        GateKind::Go
    );
}

#[tokio::test]
async fn the_cooldown_doubles_up_to_the_outbox_maximum() {
    let guard = MailGuard::default();
    let config = mail(1000, 1);
    let waits = outbox(30, 100);
    let mut now = 0;
    let mut cooldowns = Vec::new();
    for _ in 0..5 {
        guard.failed(at(now), &config, &waits).await;
        let mut waited = 0;
        while guard.admit_without_shared_limit(at(now + waited), &config).await.kind() == GateKind::BreakerOpen {
            waited += 1;
        }
        cooldowns.push(waited);
        now += waited;
    }
    assert_eq!(cooldowns, vec![30, 60, 100, 100, 100]);
}

#[tokio::test]
async fn failures_that_were_already_under_way_do_not_escalate_an_open_breaker() {
    let guard = MailGuard::default();
    let config = mail(1000, 1);
    let waits = outbox(30, 3600);
    guard.failed(at(0), &config, &waits).await;
    // Sends that started before the breaker opened report back one after the other.
    guard.failed(at(1), &config, &waits).await;
    guard.failed(at(2), &config, &waits).await;
    assert_eq!(
        guard.admit_without_shared_limit(at(30), &config).await.kind(),
        GateKind::Go,
        "still the first cooldown"
    );
}

#[tokio::test]
async fn a_lost_probe_is_replaced_after_a_while() {
    let guard = MailGuard::default();
    let config = mail(1000, 1);
    let waits = outbox(30, 3600);
    guard.failed(at(0), &config, &waits).await;
    assert_eq!(
        guard.admit_without_shared_limit(at(30), &config).await.kind(),
        GateKind::Go,
        "the probe, which never reports back"
    );
    assert_eq!(
        guard.admit_without_shared_limit(at(60), &config).await.kind(),
        GateKind::BreakerOpen
    );
    assert_eq!(
        guard.admit_without_shared_limit(at(30 + 120), &config).await.kind(),
        GateKind::Go,
        "another probe after two minutes"
    );
}

#[tokio::test]
async fn a_rate_limited_mail_does_not_use_up_the_probe() {
    let guard = MailGuard::default();
    let config = mail(1, 1);
    let waits = outbox(30, 3600);
    assert_eq!(
        guard.admit_without_shared_limit(at(0), &config).await.kind(),
        GateKind::Go
    );
    guard.failed(at(0), &config, &waits).await;
    assert_eq!(
        guard.admit_without_shared_limit(at(30), &config).await.kind(),
        GateKind::RateLimited,
        "the bucket of one per minute is still empty"
    );
    assert_eq!(
        guard.admit_without_shared_limit(at(60), &config).await.kind(),
        GateKind::Go,
        "the probe is still available"
    );
}

#[tokio::test]
async fn the_breaker_is_visible_as_a_gauge() {
    let metrics = MetricsCapture::default();
    let _installed = metrics::set_default_local_recorder(&metrics);
    let guard = MailGuard::default();
    let config = mail(1000, 1);
    let waits = outbox(30, 3600);
    guard.failed(at(0), &config, &waits).await;
    assert_eq!(metrics.get(CIRCUIT_OPEN), Some(1.0));
    guard.reachable().await;
    assert_eq!(metrics.get(CIRCUIT_OPEN), Some(0.0));
}

fn email(text: &str) -> Email {
    Email::parse(text).unwrap()
}

#[test]
fn the_domain_allow_list_matches_domains_and_their_subdomains() {
    let open = MailConfig::default();
    assert!(
        recipient_allowed(&open, &email("anyone@example.net")),
        "an empty list allows everything"
    );
    let staging = MailConfig {
        allowed_recipient_domains: vec![
            DomainName::parse("example.org").unwrap(),
            DomainName::parse("test.example.net").unwrap(),
        ],
        ..MailConfig::default()
    };
    for allowed in [
        "a@example.org",
        "a@mail.example.org",
        "A@Example.ORG",
        "a@x.y.test.example.net",
        "a@test.example.net",
    ] {
        assert!(recipient_allowed(&staging, &email(allowed)), "{allowed}");
    }
    for refused in [
        "a@notexample.org",
        "a@example.org.evil.net",
        "a@example.net",
        "a@example.com",
    ] {
        assert!(!recipient_allowed(&staging, &email(refused)), "{refused}");
    }
}

fn at_millis(millis: i64) -> DateTime<Utc> {
    at(0) + Duration::milliseconds(millis)
}

#[tokio::test]
async fn the_bucket_refills_under_dense_traffic() {
    // 120 a minute is two tokens a second. Callers every 500 ms must each find a token: a bucket that credits
    // whole seconds only (and moves its clock on every call) would never refill.
    let guard = MailGuard::default();
    let config = mail(120, 5);
    for _ in 0..120 {
        assert_eq!(
            guard.admit_without_shared_limit(at_millis(0), &config).await.kind(),
            GateKind::Go
        );
    }
    assert_eq!(
        guard.admit_without_shared_limit(at_millis(0), &config).await.kind(),
        GateKind::RateLimited,
        "drained"
    );
    for step in 1..=40 {
        assert_eq!(
            guard
                .admit_without_shared_limit(at_millis(step * 500), &config)
                .await
                .kind(),
            GateKind::Go,
            "step {step}: one token has been credited since the last call"
        );
    }
    assert_eq!(
        guard
            .admit_without_shared_limit(at_millis(40 * 500 + 100), &config)
            .await
            .kind(),
        GateKind::RateLimited,
        "100 ms credit a fifth of a token"
    );
}

#[tokio::test]
async fn fractions_of_a_second_add_up_to_the_configured_rate() {
    // 60 a minute is one a second; calls 700 ms apart credit 0.7 of a token each.
    let guard = MailGuard::default();
    let config = mail(60, 5);
    for _ in 0..60 {
        guard.admit_without_shared_limit(at_millis(0), &config).await;
    }
    let mut admitted = 0;
    for step in 1..=100 {
        if guard
            .admit_without_shared_limit(at_millis(step * 700), &config)
            .await
            .kind()
            == GateKind::Go
        {
            admitted += 1;
        }
    }
    // 70 seconds pass: 70 tokens are credited and all but a fraction of one are used.
    assert!((69..=70).contains(&admitted), "{admitted}");
}

#[expect(clippy::disallowed_types, reason = "a test double with synchronous accessors")]
type StdMutex<T> = std::sync::Mutex<T>;

/// A limiter that answers from a script and remembers what it was asked.
#[derive(Default)]
struct Limiter {
    denials: StdMutex<Vec<std::time::Duration>>,
    broken: bool,
    asked: StdMutex<Vec<RateKey>>,
}

#[async_trait::async_trait]
impl RateLimiter for Limiter {
    async fn check(&self, key: &RateKey, cost: u32) -> Result<davhaven_ports::RateDecision, davhaven_ports::PortError> {
        assert_eq!(cost, 1);
        self.asked.lock().unwrap().push(key.clone());
        if self.broken {
            return Err(davhaven_ports::PortError::unavailable("down"));
        }
        Ok(match self.denials.lock().unwrap().pop() {
            Some(wait) => davhaven_ports::RateDecision::deny(wait),
            None => davhaven_ports::RateDecision::allow(10),
        })
    }
}

#[tokio::test]
async fn the_shared_limiter_has_a_say_and_its_refusal_costs_nothing_locally() {
    let guard = MailGuard::default();
    let config = mail(2, 5);
    let limiter = Limiter::default();
    limiter.denials.lock().unwrap().push(std::time::Duration::from_secs(45));
    assert_eq!(
        guard.admit(at(0), &config, &limiter).await,
        Gate::RateLimited {
            retry_after: Wait::from_secs(45)
        },
        "the limiter's retry_after is honoured"
    );
    assert_eq!(
        limiter.asked.lock().unwrap().as_slice(),
        &[RateKey::new("mail", "relay")],
        "the `mail` bucket of the port"
    );
    // The refused mail gave its local token back: both of the two tokens are still there.
    assert_eq!(guard.admit(at(0), &config, &limiter).await, Gate::Go);
    assert_eq!(guard.admit(at(0), &config, &limiter).await, Gate::Go);
    assert_eq!(
        guard.admit(at(0), &config, &limiter).await.kind(),
        GateKind::RateLimited,
        "the local bucket is empty now"
    );
    assert_eq!(
        limiter.asked.lock().unwrap().len(),
        3,
        "a mail the local checks refuse never reaches the shared limiter"
    );
}

#[tokio::test]
async fn a_limiter_that_is_down_does_not_stop_the_mail() {
    let guard = MailGuard::default();
    let config = mail(1, 5);
    let limiter = Limiter {
        broken: true,
        ..Limiter::default()
    };
    assert_eq!(guard.admit(at(0), &config, &limiter).await, Gate::Go);
    assert_eq!(
        guard.admit(at(1), &config, &limiter).await.kind(),
        GateKind::RateLimited,
        "the local bucket still limits"
    );
}

#[tokio::test]
async fn a_probe_that_the_shared_limiter_refuses_is_not_lost() {
    let guard = MailGuard::default();
    let config = mail(1000, 1);
    let waits = outbox(30, 3600);
    guard.failed(at(0), &config, &waits).await;
    let limiter = Limiter::default();
    limiter.denials.lock().unwrap().push(std::time::Duration::from_secs(5));
    assert_eq!(
        guard.admit(at(30), &config, &limiter).await.kind(),
        GateKind::RateLimited
    );
    assert_eq!(
        guard.admit(at(31), &config, &limiter).await,
        Gate::Go,
        "the probe slot was given back"
    );
}
