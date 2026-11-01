//! Rate limiting at the edge: the `Retry-After` of 429 and 503 responses.
//!
//! The limiter decisions are made by the application (failure backoff per login and IP in `AuthService`, request
//! budgets per token in the services) and arrive here as `AppError`s of kind `RateLimited` with the delay the
//! caller must wait. The edge turns them into a 429 problem with a `Retry-After` header (PLAN 2.6, 2.10); this
//! module holds the one conversion of a delay into that header so every surface rounds the same way.

use core::time::Duration;

use axum::http::HeaderValue;

/// The whole seconds of a `Retry-After` header: the delay rounded up, at least one second.
///
/// A delay of zero would tell clients to retry immediately and hammer the server, so the minimum is one second.
pub const fn retry_after_seconds(delay: Duration) -> u64 {
    let whole = delay.as_secs();
    let seconds = if delay.subsec_nanos() > 0 {
        whole.saturating_add(1)
    } else {
        whole
    };
    if seconds == 0 { 1 } else { seconds }
}

/// The `Retry-After` header value for a delay (see [`retry_after_seconds`]).
pub fn retry_after_value(delay: Duration) -> HeaderValue {
    HeaderValue::from(retry_after_seconds(delay))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delays_round_up_to_whole_seconds_with_a_minimum_of_one() {
        let cases = [
            (Duration::ZERO, 1),
            (Duration::from_millis(1), 1),
            (Duration::from_secs(1), 1),
            (Duration::from_millis(1001), 2),
            (Duration::from_secs(30), 30),
            (Duration::from_secs(3600) + Duration::from_nanos(1), 3601),
            (Duration::MAX, u64::MAX),
        ];
        for (delay, seconds) in cases {
            assert_eq!(retry_after_seconds(delay), seconds, "{delay:?}");
        }
        assert_eq!(retry_after_value(Duration::from_secs(7)), "7");
    }
}
