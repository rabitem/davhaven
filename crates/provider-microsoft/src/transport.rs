//! The HTTP side shared by the OAuth flow and the calendar API: requests, and the mapping of what Microsoft answers to port errors.
//!
//! Everything goes through the `HttpClient` port, so the egress policy applies. Error messages name the status and, for OAuth
//! and Graph errors, the short code Microsoft gives (`invalid_grant`, `InvalidAuthenticationToken`); they never contain a
//! response body, a token or event content.

use bytes::Bytes;
use davhaven_ports::{HttpPurpose, OutboundRequest, OutboundResponse, PortError};
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use http::{HeaderName, HeaderValue, Method, StatusCode};
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

/// A `GET` of Microsoft Graph, authorized by `token`. Event bodies are asked for as plain text.
///
/// # Errors
///
/// `Invalid` for a token that cannot be sent.
pub(crate) fn graph_get(url: Url, token: &SecretString) -> Result<OutboundRequest, PortError> {
    Ok(OutboundRequest::new(Method::GET, url, HttpPurpose::ProviderApi)
        .with_header(AUTHORIZATION, bearer(token)?)
        .with_header(ACCEPT, HeaderValue::from_static("application/json"))
        .with_header(
            HeaderName::from_static("prefer"),
            HeaderValue::from_static("outlook.body-content-type=\"text\""),
        ))
}

/// Reads a JSON answer.
///
/// # Errors
///
/// `Unavailable` when the body is not what Microsoft documents: a proxy page or a half-sent answer is a fault of the moment,
/// not of the account.
pub(crate) fn json<T: serde::de::DeserializeOwned>(response: &OutboundResponse) -> Result<T, PortError> {
    serde_json::from_slice(&response.body)
        .map_err(|_| PortError::unavailable("Microsoft answered something that is not the document the API describes"))
}

/// The short code of an error answer, restricted to what a code looks like so that nothing else leaks into a message.
fn clean_code(code: Option<&str>) -> Option<String> {
    code.filter(|code| {
        !code.is_empty() && code.len() <= 60 && code.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    })
    .map(str::to_owned)
}

#[derive(Deserialize)]
struct OAuthErrorBody {
    error: Option<String>,
}

/// The error for a refused token request (`exchange`, `refresh`), by what the identity platform says (RFC 6749 section 5.2):
///
/// * `invalid_grant` is `Rejected`: the code or the refresh token is no longer valid. So are `interaction_required` and
///   `consent_required`, which the platform answers when the person has to sign in or consent again (multi-factor
///   authentication, conditional access, consent withdrawn): only a new consent helps. For a refresh that is the one thing
///   that proves that the access is gone;
/// * every other answer of 4xx is `Invalid` (`invalid_client`, `unauthorized_client`, `invalid_request`, `invalid_scope`, or an
///   answer without a code): the client of the deployment is refused, for example because the client secret of the app
///   registration expired (they expire after at most 24 months). That is no fault of any account, so it must never switch one off;
/// * a platform that is down or throttling (`429`, `5xx`) is `Unavailable`.
pub(crate) fn token_error(what: &str, response: &OutboundResponse) -> PortError {
    let code = serde_json::from_slice::<OAuthErrorBody>(&response.body)
        .ok()
        .and_then(|body| clean_code(body.error.as_deref()));
    let status = response.status;
    let detail = code.as_ref().map_or_else(String::new, |code| format!(" ({code})"));
    if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        PortError::unavailable(format!("Microsoft answered {status} to the {what}{detail}"))
    } else if matches!(
        code.as_deref(),
        Some("invalid_grant" | "interaction_required" | "consent_required")
    ) {
        PortError::rejected(format!("Microsoft refused the {what}: {status}{detail}"))
    } else {
        PortError::invalid(format!(
            "Microsoft refused the {what} for a reason of the client or the request, not of the grant: {status}{detail}"
        ))
    }
}

#[derive(Deserialize)]
struct GraphErrorBody {
    error: Option<GraphError>,
}

#[derive(Deserialize)]
struct GraphError {
    code: Option<String>,
}

/// The error for an answer of Microsoft Graph that is not a success: `429` and `5xx` are `Unavailable` (Graph throttles per
/// application and mailbox, and asks to try later), every other status is `Rejected` (the token, the permission, the calendar or
/// the request is not valid, which the sync engine handles by refreshing the token once and then by marking the account).
pub(crate) fn graph_error(what: &str, response: &OutboundResponse) -> PortError {
    let status = response.status;
    let code = serde_json::from_slice::<GraphErrorBody>(&response.body)
        .ok()
        .and_then(|body| body.error)
        .and_then(|error| clean_code(error.code.as_deref()));
    let detail = code.map_or_else(String::new, |code| format!(" ({code})"));
    if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        PortError::unavailable(format!("Microsoft answered {status} to the {what}{detail}"))
    } else {
        PortError::rejected(format!("Microsoft refused the {what}: {status}{detail}"))
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
    fn graph_requests_carry_a_sensitive_token_and_ask_for_text_bodies() {
        let request = graph_get(
            Url::parse("https://graph.microsoft.com/v1.0/me").unwrap(),
            &SecretString::from("EwB.token"),
        )
        .unwrap();
        assert_eq!(request.method, Method::GET);
        assert_eq!(request.purpose, HttpPurpose::ProviderApi);
        assert!(request.headers.get(AUTHORIZATION).unwrap().is_sensitive());
        assert_eq!(
            request.headers.get("prefer").unwrap(),
            "outlook.body-content-type=\"text\""
        );
        assert!(
            !format!("{request:?}").contains("EwB"),
            "debug output shows header names only"
        );
        assert_eq!(
            bearer(&SecretString::from("a\nb")).unwrap_err().kind,
            PortErrorKind::Invalid
        );
    }

    #[test]
    fn forms_are_urlencoded_posts_for_the_oauth_purpose() {
        let request = form_post(
            &Url::parse("https://login.microsoftonline.com/common/oauth2/v2.0/token").unwrap(),
            &[("scope", "offline_access Calendars.Read"), ("client_secret", "s&cret")],
        );
        assert_eq!(request.purpose, HttpPurpose::OAuth);
        assert_eq!(
            String::from_utf8_lossy(&request.body),
            "scope=offline_access+Calendars.Read&client_secret=s%26cret"
        );
    }

    #[test]
    fn token_errors_say_the_code_and_nothing_else() {
        let refused = token_error(
            "code exchange",
            &answer(
                400,
                r#"{"error":"invalid_grant","error_description":"AADSTS70008: The provided authorization code has expired. tok123","error_codes":[70008]}"#,
            ),
        );
        assert_eq!(refused.kind, PortErrorKind::Rejected);
        assert!(refused.message.contains("invalid_grant"), "{refused}");
        assert!(
            !refused.message.contains("AADSTS") && !refused.message.contains("tok123"),
            "{refused}"
        );
        assert_eq!(
            token_error("refresh", &answer(503, "")).kind,
            PortErrorKind::Unavailable
        );
        assert_eq!(
            token_error("refresh", &answer(429, "")).kind,
            PortErrorKind::Unavailable
        );
    }

    #[test]
    fn only_a_grant_that_is_gone_is_a_revoked_grant_and_every_other_refusal_is_the_clients() {
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
        for code in ["interaction_required", "consent_required"] {
            let again = token_error("token refresh", &answer(400, &format!(r#"{{"error":"{code}"}}"#)));
            assert_eq!(
                again.kind,
                PortErrorKind::Rejected,
                "{code}: the person has to sign in again"
            );
        }
    }

    #[test]
    fn graph_errors_are_mapped_by_status() {
        let unauthorized = graph_error(
            "event list",
            &answer(
                401,
                r#"{"error":{"code":"InvalidAuthenticationToken","message":"Access token has expired."}}"#,
            ),
        );
        assert_eq!(unauthorized.kind, PortErrorKind::Rejected);
        assert!(
            unauthorized.message.contains("InvalidAuthenticationToken"),
            "{unauthorized}"
        );
        assert!(!unauthorized.message.contains("expired"), "{unauthorized}");
        for (status, kind) in [
            (403, PortErrorKind::Rejected),
            (404, PortErrorKind::Rejected),
            (400, PortErrorKind::Rejected),
            (429, PortErrorKind::Unavailable),
            (500, PortErrorKind::Unavailable),
            (503, PortErrorKind::Unavailable),
        ] {
            assert_eq!(graph_error("event list", &answer(status, "{}")).kind, kind, "{status}");
        }
    }

    #[test]
    fn a_body_that_is_not_json_is_unavailable() {
        let error = json::<serde_json::Value>(&answer(200, "<html>")).unwrap_err();
        assert_eq!(error.kind, PortErrorKind::Unavailable);
    }
}
