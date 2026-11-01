//! The HTTP side shared by the OAuth flow and the calendar API: requests, and the mapping of what Google answers to port errors.
//!
//! Everything goes through the `HttpClient` port, so the egress policy applies. Error messages name the status and, for OAuth
//! and API errors, the short code Google gives (`invalid_grant`, `rateLimitExceeded`); they never contain a response body, a
//! token or event content.

use bytes::Bytes;
use davhaven_ports::{HttpPurpose, OutboundRequest, OutboundResponse, PortError};
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use http::{HeaderValue, Method, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use url::Url;

/// The `Authorization` header of a bearer token, marked sensitive so that it never shows in a debug print.
///
/// # Errors
///
/// `Invalid` for a token that cannot be a header value.
pub(crate) fn bearer(token: &SecretString) -> Result<HeaderValue, PortError> {
    let mut value = HeaderValue::from_str(&format!("Bearer {}", token.expose_secret()))
        .map_err(|_| PortError::invalid("the access token cannot be sent as a header"))?;
    value.set_sensitive(true);
    Ok(value)
}

/// A form `POST` to `url` (the OAuth endpoints).
pub(crate) fn form_post(url: &Url, pairs: &[(&str, &str)]) -> OutboundRequest {
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in pairs {
        form.append_pair(name, value);
    }
    OutboundRequest::new(Method::POST, url.clone(), HttpPurpose::OAuth)
        .with_header(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        )
        .with_header(ACCEPT, HeaderValue::from_static("application/json"))
        .with_body(Bytes::from(form.finish()))
}

/// A `GET` of the calendar API, authorized by `token`.
///
/// # Errors
///
/// `Invalid` for a token that cannot be sent.
pub(crate) fn api_get(url: Url, token: &SecretString) -> Result<OutboundRequest, PortError> {
    Ok(OutboundRequest::new(Method::GET, url, HttpPurpose::ProviderApi)
        .with_header(AUTHORIZATION, bearer(token)?)
        .with_header(ACCEPT, HeaderValue::from_static("application/json")))
}

/// Reads a JSON answer.
///
/// # Errors
///
/// `Unavailable` when the body is not what Google documents: a proxy page or a half-sent answer is a fault of the moment, not
/// of the account.
pub(crate) fn json<T: serde::de::DeserializeOwned>(response: &OutboundResponse) -> Result<T, PortError> {
    serde_json::from_slice(&response.body)
        .map_err(|_| PortError::unavailable("Google answered something that is not the document the API describes"))
}

/// The short code of an error answer, restricted to what a code looks like so that nothing else leaks into a message.
fn clean_code(code: Option<&str>) -> Option<String> {
    code.filter(|code| {
        !code.is_empty() && code.len() <= 40 && code.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    })
    .map(str::to_owned)
}

#[derive(Deserialize)]
struct OAuthErrorBody {
    error: Option<String>,
}

/// The error for a refused revocation: the token is no longer valid (`Rejected`, for every 4xx: Google answers `invalid_token`
/// for one that is revoked or unknown already, which is what the caller wanted), a Google that is down or throttling is
/// `Unavailable`. The client of the deployment plays no part in a revocation, so there is no `Invalid`.
pub(crate) fn revoke_error(response: &OutboundResponse) -> PortError {
    let code = serde_json::from_slice::<OAuthErrorBody>(&response.body)
        .ok()
        .and_then(|body| clean_code(body.error.as_deref()));
    let status = response.status;
    let detail = code.map_or_else(String::new, |code| format!(" ({code})"));
    if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        PortError::unavailable(format!("Google answered {status} to the revocation{detail}"))
    } else {
        PortError::rejected(format!("Google refused the revocation: {status}{detail}"))
    }
}

/// The error for a refused token request (`exchange`, `refresh`), by what Google says (RFC 6749 section 5.2):
///
/// * `invalid_grant` is `Rejected`: the code or the refresh token is no longer valid. For a refresh that is the one thing that
///   proves that the access is gone, because the person removed it or it was revoked; only a new consent helps;
/// * every other answer of 4xx is `Invalid` (`invalid_client`, `unauthorized_client`, `invalid_request`, `invalid_scope`, or an
///   answer without a code): the client of the deployment is refused, a wrong, rotated or deleted client secret. That is no
///   fault of any account, so it must never switch one off;
/// * a Google that is down or throttling (`429`, `5xx`) is `Unavailable`.
pub(crate) fn token_error(what: &str, response: &OutboundResponse) -> PortError {
    let code = serde_json::from_slice::<OAuthErrorBody>(&response.body)
        .ok()
        .and_then(|body| clean_code(body.error.as_deref()));
    let status = response.status;
    let detail = code.as_ref().map_or_else(String::new, |code| format!(" ({code})"));
    if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        PortError::unavailable(format!("Google answered {status} to the {what}{detail}"))
    } else if code.as_deref() == Some("invalid_grant") {
        PortError::rejected(format!("Google refused the {what}: {status}{detail}"))
    } else {
        PortError::invalid(format!(
            "Google refused the {what} for a reason of the client or the request, not of the grant: {status}{detail}"
        ))
    }
}

#[derive(Deserialize)]
struct ApiErrorBody {
    error: Option<ApiError>,
}

#[derive(Deserialize)]
struct ApiError {
    status: Option<String>,
    #[serde(default)]
    errors: Vec<ApiReason>,
}

#[derive(Deserialize)]
struct ApiReason {
    reason: Option<String>,
}

/// The error for an answer of the calendar API that is not a success.
///
/// * `401` and `404` and the other 4xx are `Rejected`: the token or the calendar is not valid, which the sync engine handles
///   by refreshing the token once and then by marking the account;
/// * `403` is `Rejected` unless Google says that a quota was hit (`rateLimitExceeded`, `userRateLimitExceeded`,
///   `quotaExceeded`), which is `Unavailable`;
/// * `410` is `Invalid` (the cursor is gone; the engine starts again);
/// * `429` and `5xx` are `Unavailable`.
pub(crate) fn api_error(what: &str, response: &OutboundResponse) -> PortError {
    let status = response.status;
    let body = serde_json::from_slice::<ApiErrorBody>(&response.body)
        .ok()
        .and_then(|body| body.error);
    let reason = body
        .as_ref()
        .and_then(|error| error.errors.first())
        .and_then(|first| clean_code(first.reason.as_deref()))
        .or_else(|| body.as_ref().and_then(|error| clean_code(error.status.as_deref())));
    let detail = reason
        .as_ref()
        .map_or_else(String::new, |reason| format!(" ({reason})"));
    let throttled = reason
        .as_deref()
        .is_some_and(|reason| matches!(reason, "rateLimitExceeded" | "userRateLimitExceeded" | "quotaExceeded"));
    if status == StatusCode::GONE {
        PortError::invalid(format!("Google no longer accepts the cursor of the {what}{detail}"))
    } else if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() || throttled {
        PortError::unavailable(format!("Google answered {status} to the {what}{detail}"))
    } else {
        PortError::rejected(format!("Google refused the {what}: {status}{detail}"))
    }
}

#[cfg(test)]
mod tests {
    use davhaven_ports::PortErrorKind;
    use http::HeaderMap;

    use super::*;

    fn answer(status: u16, body: &str) -> OutboundResponse {
        OutboundResponse {
            status: StatusCode::from_u16(status).unwrap(),
            headers: HeaderMap::new(),
            body: Bytes::from(body.to_owned()),
        }
    }

    #[test]
    fn bearer_headers_are_sensitive_and_bad_tokens_are_refused() {
        let header = bearer(&SecretString::from("ya29.token")).unwrap();
        assert!(header.is_sensitive());
        assert_eq!(header.to_str().unwrap(), "Bearer ya29.token");
        assert_eq!(
            bearer(&SecretString::from("line\nbreak")).unwrap_err().kind,
            PortErrorKind::Invalid
        );
    }

    #[test]
    fn forms_are_urlencoded_posts_for_the_oauth_purpose() {
        let request = form_post(
            &Url::parse("https://oauth2.googleapis.com/token").unwrap(),
            &[("code", "4/0A b"), ("client_secret", "s&cret")],
        );
        assert_eq!(request.method, Method::POST);
        assert_eq!(request.purpose, HttpPurpose::OAuth);
        assert_eq!(
            request.headers.get(CONTENT_TYPE).unwrap(),
            "application/x-www-form-urlencoded"
        );
        assert_eq!(
            String::from_utf8_lossy(&request.body),
            "code=4%2F0A+b&client_secret=s%26cret"
        );
        assert!(
            !format!("{request:?}").contains("s%26cret"),
            "debug output hides bodies"
        );
    }

    #[test]
    fn token_errors_say_what_google_said_and_nothing_else() {
        let refused = token_error(
            "code exchange",
            &answer(
                400,
                r#"{"error":"invalid_grant","error_description":"Bad Request: tok123"}"#,
            ),
        );
        assert_eq!(refused.kind, PortErrorKind::Rejected);
        assert!(refused.message.contains("invalid_grant"), "{refused}");
        assert!(!refused.message.contains("tok123"), "{refused}");
        let down = token_error("code exchange", &answer(503, "<html>maintenance</html>"));
        assert_eq!(down.kind, PortErrorKind::Unavailable);
        assert_eq!(
            token_error("refresh", &answer(429, "")).kind,
            PortErrorKind::Unavailable
        );
        let odd = token_error("refresh", &answer(400, r#"{"error":"evil text with spaces"}"#));
        assert!(!odd.message.contains("evil"), "{odd}");
    }

    #[test]
    fn only_invalid_grant_is_a_revoked_grant_and_every_other_refusal_is_the_clients() {
        for code in [
            "invalid_client",
            "unauthorized_client",
            "invalid_request",
            "invalid_scope",
            "unsupported_grant_type",
        ] {
            for status in [400, 401] {
                let refused = token_error("token refresh", &answer(status, &format!(r#"{{"error":"{code}"}}"#)));
                assert_eq!(
                    refused.kind,
                    PortErrorKind::Invalid,
                    "{status} {code}: a client the provider refuses is no revoked refresh token"
                );
                assert!(refused.message.contains(code), "{refused}");
            }
        }
        let bare = token_error("token refresh", &answer(401, ""));
        assert_eq!(
            bare.kind,
            PortErrorKind::Invalid,
            "an answer without a code proves nothing about the grant"
        );
        let revoked = token_error("token refresh", &answer(400, r#"{"error":"invalid_grant"}"#));
        assert_eq!(revoked.kind, PortErrorKind::Rejected);
    }

    #[test]
    fn api_errors_are_mapped_by_status_and_reason() {
        let unauthorized = api_error(
            "event list",
            &answer(401, r#"{"error":{"code":401,"status":"UNAUTHENTICATED"}}"#),
        );
        assert_eq!(unauthorized.kind, PortErrorKind::Rejected);
        assert!(unauthorized.message.contains("UNAUTHENTICATED"));
        let throttled = api_error(
            "event list",
            &answer(
                403,
                r#"{"error":{"errors":[{"reason":"rateLimitExceeded"}],"status":"PERMISSION_DENIED"}}"#,
            ),
        );
        assert_eq!(
            throttled.kind,
            PortErrorKind::Unavailable,
            "a quota is a reason to try later"
        );
        let forbidden = api_error(
            "event list",
            &answer(403, r#"{"error":{"errors":[{"reason":"forbidden"}]}}"#),
        );
        assert_eq!(forbidden.kind, PortErrorKind::Rejected);
        assert_eq!(
            api_error("event list", &answer(404, "{}")).kind,
            PortErrorKind::Rejected
        );
        assert_eq!(api_error("event list", &answer(410, "{}")).kind, PortErrorKind::Invalid);
        assert_eq!(
            api_error("event list", &answer(500, "")).kind,
            PortErrorKind::Unavailable
        );
        assert_eq!(
            api_error("event list", &answer(429, "")).kind,
            PortErrorKind::Unavailable
        );
    }

    #[test]
    fn a_body_that_is_not_json_is_unavailable() {
        let error = json::<serde_json::Value>(&answer(200, "<html>")).unwrap_err();
        assert_eq!(error.kind, PortErrorKind::Unavailable);
    }
}
