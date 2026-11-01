//! The answers of a host that is too busy, and the bounded retry that the matrices make for them.
//!
//! The PostgreSQL matrices run in CI on a host that other builds and test suites share. When that host is overloaded the store
//! answers "timed out" or "unavailable" now and then, and the application maps both to a transient 503
//! (`StoreError::is_retryable`, `ENGINEERING_RULES` R5): the answer a client is meant to repeat. A case whose own request was
//! answered that way has not found out what it asks about, and a matrix that calls it a failure is a flaky test.
//!
//! The harness therefore sends such a request again, and only such a request:
//!
//! * **Only a busy answer** ([`is_busy`]): a 503, or the same answer in the vocabulary of MCP (a failed tool result whose
//!   problem is `unavailable`). Every other status is an answer and is judged as it is.
//! * **Only when nothing was lost** ([`Effect`]): a request that reads is sent again, and so is one that only replaces a resource
//!   by the same content; a request that changes something is sent again only when the world shows that it did not change
//!   anything, because a 503 does not say whether the transaction committed. A world that changed, or that cannot be looked at,
//!   keeps the answer, and the case fails with it. A case that runs on a world of its own is sent again on a new world
//!   ([`Effect::Discarded`]).
//! * **A few times** ([`Policy`]): four attempts with pauses that double. A 503 that persists is a failure of the case.
//! * **Visibly**: every result carries the number of repeats it needed, the reports list the cases that needed any, and a run
//!   in which more than one case in [`ONE_IN`] needed one fails ([`excessive`]): a server that is unavailable now and then, as
//!   opposed to a host that is, is a regression and must not hide behind the retry.
//!
//! [`repeat_while_busy`] is the loop; [`again`] is the decision it makes after each attempt, a pure function that the tests of
//! this module cover case by case.

use core::future::Future;
use core::time::Duration;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use async_trait::async_trait;
use http::Method;

use crate::permissions::mcp;
use crate::transport::{TestRequest, TestResponse, Transport, TransportError};

/// How often something is sent again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// How often it is sent in all: the first time and the repeats.
    pub attempts: u32,
    /// The pause before the first repeat; every further pause is twice as long as the one before.
    pub first_pause: Duration,
}

impl Policy {
    /// Four attempts with pauses of half a second, one second and two seconds: a host that is overloaded for a moment recovers
    /// within that, and a server that does not is not waited for.
    pub const STANDARD: Self = Self {
        attempts: 4,
        first_pause: Duration::from_millis(500),
    };

    /// `attempts` attempts without a pause, for the tests of the harness itself, which never sleep.
    #[must_use]
    pub const fn without_pauses(attempts: u32) -> Self {
        Self {
            attempts,
            first_pause: Duration::ZERO,
        }
    }

    /// The pause before the repeat that follows the attempt number `made` (the first attempt is number 1); none when the
    /// attempts are used up.
    #[must_use]
    pub fn pause_after(self, made: u32) -> Option<Duration> {
        if made == 0 || made >= self.attempts {
            return None;
        }
        Some(self.first_pause.saturating_mul(2_u32.saturating_pow(made - 1)))
    }
}

/// What the world shows about a request that was answered "busy": whether sending it again can do harm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Sending it again does no harm: the request reads, or it replaces a resource by the same content.
    Repeatable,
    /// The world is as it was before the request: the request did nothing.
    Unchanged,
    /// The world differs from what it was before the request: the request, or a part of it, took effect, and sending it again
    /// would do it twice.
    Changed,
    /// The world could not be looked at, so nothing is known.
    Unknown,
    /// The world is thrown away and the next attempt runs on a new one: whatever this attempt did is gone with it.
    Discarded,
}

impl Effect {
    /// Whether the request may be sent again.
    #[must_use]
    pub const fn allows_repeat(self) -> bool {
        matches!(self, Self::Repeatable | Self::Unchanged | Self::Discarded)
    }

    /// What the world shows about a request that was sent between the observation `before` and the observation `after`, when
    /// `changes` says whether the request may change something at all.
    #[must_use]
    pub fn of_request(
        changes: bool,
        before: Option<&crate::observe::Observation>,
        after: Option<&crate::observe::Observation>,
    ) -> Self {
        if !changes {
            return Self::Repeatable;
        }
        match (before, after) {
            (Some(before), Some(after)) if before.diff(after).is_empty() => Self::Unchanged,
            (Some(_), Some(_)) => Self::Changed,
            _ => Self::Unknown,
        }
    }
}

/// Whether a request of this method may be sent again without looking at the world: it reads, or it replaces a resource by the
/// content it carries (RFC 9110 section 9.2.2: the idempotent methods that the harness sends as preparation).
#[must_use]
pub fn is_repeatable_method(method: &Method) -> bool {
    matches!(
        method.as_str(),
        "GET" | "HEAD" | "OPTIONS" | "PUT" | "PROPFIND" | "REPORT"
    )
}

/// Whether the answer says that the server was too busy to answer: a 503 (a store that timed out or could not be reached,
/// `ENGINEERING_RULES` R5), or the same answer of an MCP tool, which is a failed tool result with the problem `unavailable` in an
/// answer that is 200.
#[must_use]
pub fn is_busy(response: &TestResponse) -> bool {
    match response.status.as_u16() {
        503 => true,
        200 => mcp::is_unavailable(response),
        _ => false,
    }
}

/// One attempt of something that is sent again while the host is busy.
#[derive(Debug)]
pub struct Attempt<T> {
    /// What the attempt produced; the last attempt's value is the result.
    pub value: T,
    /// `None` when the host was not busy and the attempt stands; otherwise what the world shows about the attempt.
    pub busy: Option<Effect>,
}

/// The decision after an attempt that was answered "busy": the pause before the next one, or `None` when the attempt stands
/// (the attempts are used up, or the request may not be sent again). `made` is the number of attempts so far.
#[must_use]
pub fn again(policy: Policy, made: u32, effect: Effect) -> Option<Duration> {
    if effect.allows_repeat() {
        policy.pause_after(made)
    } else {
        None
    }
}

/// Makes `attempt` until the host is not busy or [`again`] says that it stands, and returns the value of the last attempt and the
/// number of repeats it took (0 when the first attempt stood).
pub async fn repeat_while_busy<T, F, Fut>(policy: Policy, mut attempt: F) -> (T, u32)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Attempt<T>>,
{
    let mut made = 1_u32;
    loop {
        let Attempt { value, busy } = attempt().await;
        match busy.and_then(|effect| again(policy, made, effect)) {
            Some(pause) => {
                tokio::time::sleep(pause).await;
                made += 1;
            }
            None => return (value, made - 1),
        }
    }
}

/// Sends a request; when the answer is busy it is sent again as `effect`, what the world shows about the request, allows. The
/// result is that of the last attempt, with the number of repeats.
pub async fn send_with_effect(
    transport: &dyn Transport,
    request: &TestRequest,
    effect: Effect,
) -> (Result<TestResponse, TransportError>, u32) {
    repeat_while_busy(Policy::STANDARD, || async {
        let response = transport.send(request.clone()).await;
        let busy = match &response {
            Ok(response) if is_busy(response) => Some(effect),
            _ => None,
        };
        Attempt { value: response, busy }
    })
    .await
}

/// Sends a request that may be sent again whatever the world shows ([`Effect::Repeatable`]): a read, or the making of a fixture
/// that another one of the same kind does not harm.
pub async fn send_repeatable(
    transport: &dyn Transport,
    request: &TestRequest,
) -> (Result<TestResponse, TransportError>, u32) {
    send_with_effect(transport, request, Effect::Repeatable).await
}

/// Sends a request that prepares what a case works on: it is sent again when the host is busy if its method reads or replaces
/// ([`is_repeatable_method`]), and left as it is answered otherwise, because nothing shows what it did.
pub async fn send_preparation(
    transport: &dyn Transport,
    request: &TestRequest,
) -> (Result<TestResponse, TransportError>, u32) {
    let effect = if is_repeatable_method(&request.method) {
        Effect::Repeatable
    } else {
        Effect::Unknown
    };
    send_with_effect(transport, request, effect).await
}

/// One case in this many may need a repeat before the run is called a failure ([`excessive`]).
pub const ONE_IN: usize = 20;

/// The cases that may need a repeat whatever the size of the run.
pub const ALWAYS_ALLOWED: usize = 3;

/// Whether a run in which `repeated` of `run` cases needed a repeat repeated too many: a host that is busy makes a few cases
/// slow, a server that answers 503 now and then makes many of them, and that is a finding and not a flake.
#[must_use]
pub const fn excessive(repeated: usize, run: usize) -> bool {
    repeated > ALWAYS_ALLOWED && repeated.saturating_mul(ONE_IN) > run
}

/// A transport that counts the busy answers it carries: the matrices that run a case on a world of their own ask the count after
/// the case, to know whether a failure may be the host's.
pub struct Watched {
    inner: Arc<dyn Transport>,
    busy: AtomicU32,
}

impl Watched {
    /// Wraps `inner`.
    pub fn new(inner: Arc<dyn Transport>) -> Self {
        Self {
            inner,
            busy: AtomicU32::new(0),
        }
    }

    /// How many busy answers ([`is_busy`]) the transport has carried so far.
    pub fn busy_answers(&self) -> u32 {
        self.busy.load(Ordering::Relaxed)
    }
}

impl core::fmt::Debug for Watched {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Watched")
            .field("busy", &self.busy_answers())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl Transport for Watched {
    async fn send(&self, request: TestRequest) -> Result<TestResponse, TransportError> {
        let response = self.inner.send(request).await?;
        if is_busy(&response) {
            self.busy.fetch_add(1, Ordering::Relaxed);
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;
    use crate::observe::Observation;
    use crate::transport::FnTransport;

    fn observation(facts: &[(&str, &str)]) -> Observation {
        let mut observation = Observation::new();
        for (name, value) in facts {
            observation.insert(*name, *value);
        }
        observation
    }

    #[test]
    fn the_pauses_double_and_the_attempts_run_out() {
        let policy = Policy::STANDARD;
        assert_eq!(policy.attempts, 4);
        assert_eq!(policy.pause_after(1), Some(Duration::from_millis(500)));
        assert_eq!(policy.pause_after(2), Some(Duration::from_secs(1)));
        assert_eq!(policy.pause_after(3), Some(Duration::from_secs(2)));
        assert_eq!(policy.pause_after(4), None, "the fourth attempt is the last");
        assert_eq!(policy.pause_after(0), None);
        assert_eq!(policy.pause_after(99), None);
        assert_eq!(Policy::without_pauses(3).pause_after(2), Some(Duration::ZERO));
        assert_eq!(
            Policy::without_pauses(1).pause_after(1),
            None,
            "one attempt is no retry"
        );
    }

    #[test]
    fn a_busy_answer_is_a_503_or_an_mcp_tool_that_is_unavailable_and_nothing_else() {
        assert!(is_busy(&TestResponse::new(503, "")));
        for status in [
            200, 201, 204, 207, 400, 401, 403, 404, 409, 412, 429, 500, 501, 502, 504, 507,
        ] {
            assert!(!is_busy(&TestResponse::new(status, "")), "{status}");
        }
        let tool_failure = |code: &str| {
            let message = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"isError": true, "content": [], "_meta": {"davhaven/problem": {"code": code}}}
            });
            TestResponse::new(200, message.to_string()).with_header("content-type", "application/json")
        };
        assert!(is_busy(&tool_failure("unavailable")));
        for other in [
            "not-found",
            "forbidden",
            "validation-failed",
            "internal",
            "rate-limited",
        ] {
            assert!(!is_busy(&tool_failure(other)), "{other}");
        }
        // A tool that succeeded, and an answer that only talks about the problem in its text, are not busy.
        let success = serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"isError": false, "content": []}});
        assert!(!is_busy(&TestResponse::new(200, success.to_string())));
        assert!(!is_busy(&TestResponse::new(
            200,
            "BEGIN:VEVENT\r\nSUMMARY:davhaven/problem unavailable\r\nEND:VEVENT\r\n"
        )));
    }

    #[test]
    fn what_the_world_shows_decides_whether_a_request_that_changes_something_is_sent_again() {
        let before = observation(&[("objects", "a"), ("seq", "1")]);
        let same = observation(&[("objects", "a"), ("seq", "1")]);
        let changed = observation(&[("objects", ""), ("seq", "2")]);
        // A request that reads is sent again whatever the world shows, even when it could not be looked at.
        assert_eq!(Effect::of_request(false, None, None), Effect::Repeatable);
        assert_eq!(
            Effect::of_request(false, Some(&before), Some(&changed)),
            Effect::Repeatable
        );
        // One that changes something is sent again only when nothing changed.
        assert_eq!(Effect::of_request(true, Some(&before), Some(&same)), Effect::Unchanged);
        assert_eq!(Effect::of_request(true, Some(&before), Some(&changed)), Effect::Changed);
        assert_eq!(Effect::of_request(true, None, Some(&same)), Effect::Unknown);
        assert_eq!(Effect::of_request(true, Some(&before), None), Effect::Unknown);
        assert_eq!(Effect::of_request(true, None, None), Effect::Unknown);
    }

    #[test]
    fn only_an_effect_that_does_no_harm_allows_a_repeat() {
        assert!(Effect::Repeatable.allows_repeat());
        assert!(Effect::Unchanged.allows_repeat());
        assert!(Effect::Discarded.allows_repeat());
        assert!(!Effect::Changed.allows_repeat());
        assert!(!Effect::Unknown.allows_repeat());
    }

    #[test]
    fn the_decision_after_a_busy_answer_follows_the_effect_and_the_attempts_left() {
        let policy = Policy::STANDARD;
        assert_eq!(again(policy, 1, Effect::Unchanged), Some(Duration::from_millis(500)));
        assert_eq!(again(policy, 3, Effect::Repeatable), Some(Duration::from_secs(2)));
        assert_eq!(again(policy, 2, Effect::Discarded), Some(Duration::from_secs(1)));
        // The last attempt stands, whatever it did.
        assert_eq!(again(policy, 4, Effect::Repeatable), None);
        // A request that took effect, or whose effect is not known, is never sent again.
        for made in 1..=4 {
            assert_eq!(again(policy, made, Effect::Changed), None, "{made}");
            assert_eq!(again(policy, made, Effect::Unknown), None, "{made}");
        }
    }

    #[test]
    fn the_repeats_of_a_run_are_few_or_the_run_fails() {
        // One case in the failed run of CI: nothing to see.
        assert!(!excessive(1, 1320));
        assert!(!excessive(0, 0));
        // A few cases are always allowed, even of a small run.
        assert!(!excessive(ALWAYS_ALLOWED, 10));
        // More than a few that are more than one in twenty are a server that answers 503 now and then.
        assert!(excessive(ALWAYS_ALLOWED + 1, 60));
        assert!(!excessive(ALWAYS_ALLOWED + 1, 80));
        assert!(excessive(100, 1320));
        assert!(!excessive(66, 1320));
        assert!(excessive(67, 1320));
        assert!(!excessive(usize::MAX / 2, usize::MAX), "the arithmetic saturates");
    }

    /// The statuses of a scripted server, one answer after the other (the last one repeats), and the number of requests it got.
    fn scripted(statuses: &[u16]) -> (Arc<dyn Transport>, Arc<AtomicUsize>) {
        let statuses: Vec<u16> = statuses.to_vec();
        let seen = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&seen);
        let transport = FnTransport::new(move |_: &TestRequest| {
            let count = counter.fetch_add(1, Ordering::SeqCst);
            let status = statuses.get(count).or(statuses.last()).copied().unwrap_or(200);
            Ok(TestResponse::new(status, ""))
        });
        (Arc::new(transport), seen)
    }

    async fn sent(transport: &dyn Transport, policy: Policy, effect: Effect) -> (u16, u32) {
        let (status, repeats) = repeat_while_busy(policy, || async {
            let response = transport.send(TestRequest::new("DELETE", "/x")).await.unwrap();
            let busy = is_busy(&response).then_some(effect);
            Attempt {
                value: response.status.as_u16(),
                busy,
            }
        })
        .await;
        (status, repeats)
    }

    #[tokio::test]
    async fn a_busy_answer_is_sent_again_until_the_host_answers() {
        let (transport, seen) = scripted(&[503, 503, 204]);
        assert_eq!(
            sent(transport.as_ref(), Policy::without_pauses(4), Effect::Unchanged).await,
            (204, 2)
        );
        assert_eq!(seen.load(Ordering::SeqCst), 3);
        // An answer that is not busy stands at once, whatever it is.
        let (transport, seen) = scripted(&[403]);
        assert_eq!(
            sent(transport.as_ref(), Policy::without_pauses(4), Effect::Unchanged).await,
            (403, 0)
        );
        assert_eq!(seen.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_busy_answer_that_persists_is_the_answer_after_the_attempts() {
        let (transport, seen) = scripted(&[503]);
        let started = tokio::time::Instant::now();
        assert_eq!(
            sent(transport.as_ref(), Policy::STANDARD, Effect::Repeatable).await,
            (503, 3)
        );
        assert_eq!(seen.load(Ordering::SeqCst), 4, "four attempts and no more");
        assert_eq!(
            started.elapsed(),
            Duration::from_millis(3500),
            "the pauses before the repeats: half a second, one second and two"
        );
    }

    #[tokio::test]
    async fn a_request_that_took_effect_or_has_an_unknown_effect_is_not_sent_again() {
        for effect in [Effect::Changed, Effect::Unknown] {
            let (transport, seen) = scripted(&[503, 204]);
            assert_eq!(
                sent(transport.as_ref(), Policy::STANDARD, effect).await,
                (503, 0),
                "{effect:?}"
            );
            assert_eq!(seen.load(Ordering::SeqCst), 1, "{effect:?}");
        }
    }

    #[tokio::test]
    async fn the_effect_is_asked_again_after_every_busy_answer() {
        // The first busy answer left the world as it was, the second one did not: the third attempt is not made.
        let (transport, seen) = scripted(&[503, 503, 204]);
        let effects = [Effect::Unchanged, Effect::Changed];
        let asked = AtomicUsize::new(0);
        let (status, repeats) = repeat_while_busy(Policy::without_pauses(4), || async {
            let response = transport.send(TestRequest::new("DELETE", "/x")).await.unwrap();
            let busy = is_busy(&response).then(|| {
                effects
                    .get(asked.fetch_add(1, Ordering::SeqCst))
                    .copied()
                    .unwrap_or(Effect::Unknown)
            });
            Attempt {
                value: response.status.as_u16(),
                busy,
            }
        })
        .await;
        assert_eq!((status, repeats), (503, 1));
        assert_eq!(seen.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_read_is_sent_again_without_looking_at_the_world() {
        let (transport, seen) = scripted(&[503, 503, 207]);
        let (response, repeats) = send_repeatable(transport.as_ref(), &TestRequest::new("PROPFIND", "/dav/")).await;
        assert_eq!(response.unwrap().status.as_u16(), 207);
        assert_eq!(repeats, 2);
        assert_eq!(seen.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn a_preparation_is_sent_again_only_when_its_method_reads_or_replaces() {
        let (transport, seen) = scripted(&[503, 201]);
        let (response, repeats) = send_preparation(transport.as_ref(), &TestRequest::new("PUT", "/dav/x.ics")).await;
        assert_eq!((response.unwrap().status.as_u16(), repeats), (201, 1));
        assert_eq!(seen.load(Ordering::SeqCst), 2);
        // A POST that created something is left as it was answered: nothing shows whether it did.
        let (transport, seen) = scripted(&[503, 201]);
        let (response, repeats) = send_preparation(transport.as_ref(), &TestRequest::new("POST", "/api/v1/x")).await;
        assert_eq!((response.unwrap().status.as_u16(), repeats), (503, 0));
        assert_eq!(seen.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn the_watched_transport_counts_the_busy_answers_it_carries() {
        let (inner, _) = scripted(&[503, 200, 503, 503, 404]);
        let watched = Watched::new(inner);
        assert_eq!(watched.busy_answers(), 0);
        for _ in 0..5 {
            watched.send(TestRequest::new("GET", "/")).await.unwrap();
        }
        assert_eq!(watched.busy_answers(), 3);
    }

    #[test]
    fn the_methods_that_may_be_sent_again_read_or_replace() {
        for method in ["GET", "HEAD", "OPTIONS", "PUT", "PROPFIND", "REPORT"] {
            let method = Method::from_bytes(method.as_bytes()).unwrap();
            assert!(is_repeatable_method(&method), "{method}");
        }
        for method in [
            "POST",
            "DELETE",
            "PATCH",
            "MOVE",
            "COPY",
            "MKCOL",
            "MKCALENDAR",
            "PROPPATCH",
        ] {
            let method = Method::from_bytes(method.as_bytes()).unwrap();
            assert!(!is_repeatable_method(&method), "{method}");
        }
    }
}
