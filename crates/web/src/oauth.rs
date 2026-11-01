//! OAuth callbacks of calendar providers.
//!
//! `GET /oauth/{provider}/callback` is where a provider sends the user back after consent (PLAN 2.10). The
//! request carries no credential: the single-use `state` identifies the tenant, principal and provider, and the
//! application checks and consumes it. The authorization `code` is a secret: it is handed to the service as a
//! `SecretString`, never logged, and the metric and log labels use the route template, so neither the code nor the
//! state appears in observability data. The answer is an HTML result page.

use axum::extract::{Path, Request, State};
use axum::response::Response;
use davhaven_app::services::{CallbackParams, SecretString};
use davhaven_http::problem::{EdgeProblem, ProblemCode};

use crate::router::{Meta, WebState};
use crate::rsvp::html;

/// The longest provider name accepted in the path.
const MAX_PROVIDER_CHARS: usize = 32;
/// The longest authorization code accepted.
const MAX_CODE_BYTES: usize = 4096;
/// The longest `state` or `error` value accepted.
const MAX_SHORT_BYTES: usize = 512;

/// Whether `name` can be a provider: lowercase letters, digits and hyphens.
pub(crate) fn is_provider_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_PROVIDER_CHARS
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The callback parameters of a query string; a parameter that is too long or repeated makes the request invalid.
pub(crate) fn parse_query(query: &str) -> Result<CallbackParams, EdgeProblem> {
    let mut code = None;
    let mut state = None;
    let mut error = None;
    for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
        let (slot, limit) = match name.as_ref() {
            "code" => (&mut code, MAX_CODE_BYTES),
            "state" => (&mut state, MAX_SHORT_BYTES),
            "error" => (&mut error, MAX_SHORT_BYTES),
            _ => continue,
        };
        if value.len() > limit || slot.replace(value.into_owned()).is_some() {
            return Err(EdgeProblem::new(ProblemCode::BadRequest).with_detail("A callback parameter is invalid."));
        }
    }
    Ok(CallbackParams {
        code: code.map(|code| SecretString::from(code.as_str())),
        state,
        error,
    })
}

/// Completes the OAuth flow of a provider and shows the result.
pub(crate) async fn callback(
    State(state): State<WebState>,
    Path(provider): Path<String>,
    meta: Meta,
    request: Request,
) -> Result<Response, EdgeProblem> {
    if !is_provider_name(&provider) {
        return Err(EdgeProblem::new(ProblemCode::NotFound));
    }
    let params = parse_query(request.uri().query().unwrap_or_default())?;
    let ctx = WebState::anonymous(meta.request_id());
    let page = state
        .services
        .external_accounts
        .complete(&ctx, &provider, params)
        .await?;
    Ok(html(page))
}

#[cfg(test)]
mod tests {
    use davhaven_app::services::ExposeSecret;

    use super::*;

    #[test]
    fn providers_are_short_lowercase_names() {
        let too_long = "a".repeat(33);
        let longest = "a".repeat(32);
        for good in ["google", "microsoft", "provider-2", longest.as_str()] {
            assert!(is_provider_name(good), "{good}");
        }
        for bad in ["", "Google", "a/b", "a b", "ä", too_long.as_str()] {
            assert!(!is_provider_name(bad), "{bad}");
        }
    }

    #[test]
    fn callback_parameters_are_decoded_and_the_code_is_a_secret() {
        let params = parse_query("code=4%2F0AbC&state=s-1&scope=ignored").unwrap();
        assert_eq!(params.code.as_ref().map(ExposeSecret::expose_secret), Some("4/0AbC"));
        assert_eq!(params.state.as_deref(), Some("s-1"));
        assert_eq!(params.error, None);
        assert!(
            !format!("{params:?}").contains("0AbC"),
            "the code never shows in debug output"
        );
        let refused = parse_query("error=access_denied&state=s").unwrap();
        assert_eq!(refused.error.as_deref(), Some("access_denied"));
        assert!(refused.code.is_none());
        let empty = parse_query("").unwrap();
        assert!(empty.code.is_none() && empty.state.is_none() && empty.error.is_none());
    }

    #[test]
    fn oversized_and_repeated_parameters_are_refused() {
        // The limits are inclusive: a value of exactly the longest length is a value.
        let longest = parse_query(&format!(
            "code={}&state={}&error={}",
            "c".repeat(4096),
            "s".repeat(512),
            "e".repeat(512)
        ))
        .unwrap();
        assert_eq!(longest.code.map(|code| code.expose_secret().len()), Some(4096));
        assert_eq!(longest.state.map(|state| state.len()), Some(512));
        assert_eq!(longest.error.map(|error| error.len()), Some(512));
        let huge = "a".repeat(MAX_CODE_BYTES + 1);
        for query in [
            format!("code={huge}"),
            "state=a&state=b".to_owned(),
            "code=a&code=b".to_owned(),
            "error=a&error=b".to_owned(),
            format!("state={}", "s".repeat(513)),
            format!("error={}", "e".repeat(513)),
        ] {
            let problem = parse_query(&query).unwrap_err();
            assert_eq!(problem.code(), ProblemCode::BadRequest, "{query:.30}");
        }
    }
}
