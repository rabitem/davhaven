//! Mapping of application errors to web responses.
//!
//! Browsers and feed readers, not API clients, see these responses, so a failure is an HTML page with the status of
//! the problem catalog (the `http` column of `docs/problems.md`). The page contains one fixed text per class of failure
//! and nothing a client or an attacker chose: no path, no token, no message of the application. Pages carry the same
//! security headers as every page of this crate.
//!
//! The page is rendered by the template renderer (the `themed_errors` layer: the `rsvp_unavailable` template, in the theme of
//! the deployment and in the language the visitor asked for, else the deployment's default), so a link that no longer
//! works looks like the rest of the deployment's pages. [`WebProblems`] is the static page the edge falls back to when
//! the renderer is not available, and for the failures of the edge layers that run before the routes (limits, rate
//! limits of the connection).
//!
//! Two rules protect the secret-bearing URLs:
//!
//! * **one answer for every bad token.** Unknown, expired, revoked and wrong-surface tokens, and tokens of
//!   suspended principals, all answer the same 404 ([`token_refusal`]); the page never says which one it was.
//! * **rate limits still show.** The failure backoff answers 429 with `Retry-After`, because hiding it would make
//!   the limiter useless against guessing.

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::{ACCEPT_LANGUAGE, CACHE_CONTROL, CONTENT_TYPE, VARY};
use axum::http::{HeaderMap, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use davhaven_app::{AppError, AppServices};
use davhaven_domain::{ErrorKind, Locale, RequestId};
use davhaven_http::problem::{EdgeProblem, ProblemCode, ProblemRenderer, apply_problem_headers, problem_of};
use davhaven_http::request_id::request_id_of;
use uuid::Uuid;

use crate::router::WebState;

/// The Content-Security-Policy of every page: nothing from anywhere else, no scripts, no framing, forms only to
/// the page's own origin.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; \
                                           form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

/// Adds the security headers every response of the web surface carries, keeping headers a handler set itself.
///
/// `no-store` is the default `Cache-Control` because pages and errors can contain or reveal tokens; feeds and
/// assets set their own policy.
pub fn add_security_headers(headers: &mut HeaderMap) {
    let defaults = [
        ("content-security-policy", CONTENT_SECURITY_POLICY),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
        ("x-robots-tag", "noindex, nofollow"),
        ("cache-control", "no-store"),
    ];
    for (name, value) in defaults {
        if !headers.contains_key(name) {
            headers.insert(
                axum::http::HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
        }
    }
}

/// The failure of a token-bearing request: every refusal of the credential is the same 404, other failures keep
/// their own mapping (rate limit, unavailable service, unsupported operation).
pub fn token_refusal(error: &AppError) -> EdgeProblem {
    if error.kind() == ErrorKind::Unauthenticated {
        EdgeProblem::new(ProblemCode::NotFound)
    } else {
        EdgeProblem::from_app_error(error)
    }
}

/// The sentence below the title: one fixed text per class of status.
const fn explanation(status: u16) -> &'static str {
    match status {
        404 => "There is nothing at this address, or the link is no longer valid.",
        429 => "Too many requests. Please wait a moment and try again.",
        400..=499 => "The request could not be processed.",
        501 => "This page is not available on this server.",
        503 => "The service is temporarily unavailable. Please try again later.",
        _ => "Something went wrong on the server.",
    }
}

/// The HTML page of an error: the catalog title and a fixed sentence.
fn page(title: &str, text: &str) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>{title}</title>\n</head>\n<body>\n<main>\n<h1>{title}</h1>\n<p>{text}</p>\n</main>\n</body>\n</html>\n"
    )
}

/// The renderer of the web surface: a static HTML page with the catalog status and the security headers.
#[derive(Debug, Clone, Copy, Default)]
pub struct WebProblems;

impl ProblemRenderer for WebProblems {
    fn render(&self, problem: &EdgeProblem, _request_id: Option<RequestId>) -> Response {
        let code = problem.code();
        let status = axum::http::StatusCode::from_u16(code.http_status())
            .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        let mut response = Response::new(Body::from(page(code.title(), explanation(code.http_status()))));
        *response.status_mut() = status;
        let headers = response.headers_mut();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        add_security_headers(headers);
        apply_problem_headers(&mut response, problem, None);
        response
    }
}

/// How many languages of the header are read: the header of a browser lists a handful, a long one is not worth reading further.
const MAX_LANGUAGES: usize = 16;

/// The languages the visitor asked for, best first: the entries of `Accept-Language` with a quality above zero, ordered by
/// quality (the order of the header among equals), as language tags. Which of them a page is rendered in is the theme's to
/// say (the renderer takes the first one it has translations for and falls back to the deployment's default language), so
/// nothing here knows which languages exist. Entries that are not language tags (`*`) are skipped.
pub(crate) fn accepted_languages(headers: &HeaderMap) -> Vec<Locale> {
    let Some(header) = headers.get(ACCEPT_LANGUAGE).and_then(|value| value.to_str().ok()) else {
        return Vec::new();
    };
    let mut ranked: Vec<(u32, Locale)> = Vec::new();
    for entry in header.split(',').take(MAX_LANGUAGES) {
        let mut parts = entry.split(';');
        let Ok(language) = Locale::parse(parts.next().unwrap_or_default().trim()) else {
            continue;
        };
        // The quality is `q=0.8`, in thousandths here; a missing one is 1, and one that cannot be read counts as 1 as well.
        let quality = parts
            .find_map(|parameter| parameter.trim().strip_prefix("q="))
            .and_then(thousandths)
            .unwrap_or(1000);
        if quality > 0 && !ranked.iter().any(|(_, known)| known == &language) {
            ranked.push((quality, language));
        }
    }
    // A stable sort keeps the order of the header among entries of the same quality.
    ranked.sort_by_key(|(quality, _)| core::cmp::Reverse(*quality));
    ranked.into_iter().map(|(_, language)| language).collect()
}

/// The value of a quality such as `0.8`, `0.125` or `1` in thousandths; `None` for text that is no such number.
fn thousandths(text: &str) -> Option<u32> {
    let text = text.trim();
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if whole.parse::<u32>().ok()? >= 1 {
        return Some(1000);
    }
    let digits: String = fraction.chars().take(3).collect();
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    format!("{digits:0<3}").parse().ok()
}

/// Renders the failures of the web routes with the template renderer.
///
/// The layer sits between the routes and the edge. A response that stands for a problem (a handler's error, or the bare 4xx
/// or 5xx of the framework for an unknown path or a wrong method: [`problem_of`]) becomes the page of the
/// `rsvp_unavailable` template for the status of the failure, in the theme of the deployment and in the language of the
/// visitor, with the headers the problem asks for (`Retry-After`, `Allow`). The page is the same for every cause of a status:
/// a link that is unknown, expired, revoked or cancelled looks alike, and nothing of the request or the application is in it.
/// The layers outside this one add the security headers and `Cache-Control: no-store` to every response of the surface.
///
/// When the page cannot be rendered the response is left alone, and the edge renders the static page of
/// [`WebProblems`].
pub(crate) async fn themed_errors(State(services): State<AppServices>, request: Request, next: Next) -> Response {
    let languages = accepted_languages(request.headers());
    let request_id = request_id_of(request.extensions()).unwrap_or_else(|| RequestId::from_uuid(Uuid::nil()));
    let response = next.run(request).await;
    let status = response.status();
    if !(status.is_client_error() || status.is_server_error()) {
        return response;
    }
    let Some(problem) = problem_of(&response) else {
        return response;
    };
    let context = WebState::anonymous(request_id);
    let Ok(page) = services
        .assets
        .unavailable_page(&context, problem.code().http_status(), &languages)
        .await
    else {
        return response;
    };
    let mut themed = Response::new(Body::from(page.html));
    *themed.status_mut() = status;
    let headers = themed.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    // The page follows the language of the visitor: caches and the browser keep the pages apart.
    headers.insert(VARY, HeaderValue::from_static("Accept-Language"));
    apply_problem_headers(&mut themed, &problem, None);
    themed
}

#[cfg(test)]
mod tests {
    use axum::http::header::RETRY_AFTER;
    use http_body_util::BodyExt as _;

    use super::*;

    async fn render(problem: EdgeProblem) -> (Response, String) {
        let mut response = WebProblems.render(&problem, None);
        let body = std::mem::take(response.body_mut());
        let bytes = body.collect().await.unwrap().to_bytes();
        (response, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn every_row_renders_a_static_page_with_its_catalog_status_and_the_security_headers() {
        for code in ProblemCode::ALL {
            let (response, body) = render(EdgeProblem::new(*code)).await;
            assert_eq!(response.status().as_u16(), code.http_status(), "{}", code.code());
            assert_eq!(response.headers()[CONTENT_TYPE], "text/html; charset=utf-8");
            assert_eq!(response.headers()["cache-control"], "no-store");
            assert_eq!(response.headers()["referrer-policy"], "no-referrer");
            assert_eq!(response.headers()["x-content-type-options"], "nosniff");
            assert_eq!(response.headers()["x-robots-tag"], "noindex, nofollow");
            assert_eq!(
                response.headers()["content-security-policy"],
                "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
            );
            assert!(body.starts_with("<!doctype html>"), "{body}");
            assert!(body.contains(&format!("<h1>{}</h1>", code.title())), "{body}");
        }
    }

    #[tokio::test]
    async fn pages_contain_nothing_the_request_or_the_application_chose() {
        let problem = EdgeProblem::new(ProblemCode::ValidationFailed)
            .with_detail("<script>alert(1)</script> token dvh_rsvp_abc_secret");
        let (_, body) = render(problem).await;
        assert!(!body.contains("script") && !body.contains("dvh_rsvp"), "{body}");
        assert!(!body.contains("alert"));
    }

    #[tokio::test]
    async fn rate_limits_keep_their_retry_hint() {
        let problem = EdgeProblem::new(ProblemCode::RateLimited).with_retry_after(core::time::Duration::from_secs(9));
        let (response, body) = render(problem).await;
        assert_eq!(response.headers()[RETRY_AFTER], "9");
        assert!(body.contains("Too many requests"));
    }

    #[test]
    fn every_bad_token_is_the_same_404_and_other_failures_keep_their_mapping() {
        let unauthenticated = token_refusal(&AppError::unauthenticated());
        assert_eq!(unauthenticated.code(), ProblemCode::NotFound);
        assert_eq!(unauthenticated.detail(), None);
        let limited = token_refusal(&AppError::rate_limited(core::time::Duration::from_secs(5)));
        assert_eq!(limited.code(), ProblemCode::RateLimited);
        assert_eq!(limited.retry_after(), Some(core::time::Duration::from_secs(5)));
        assert_eq!(token_refusal(&AppError::unavailable()).code(), ProblemCode::Unavailable);
        assert_eq!(
            token_refusal(&AppError::new(ErrorKind::Unsupported)).code(),
            ProblemCode::NotImplemented
        );
        assert_eq!(token_refusal(&AppError::not_found()).code(), ProblemCode::NotFound);
    }

    fn languages(value: &str) -> Vec<String> {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_str(value).unwrap());
        accepted_languages(&headers)
            .iter()
            .map(|locale| locale.as_str().to_owned())
            .collect()
    }

    #[test]
    fn the_languages_of_the_visitor_are_ranked_by_quality_and_nothing_here_knows_which_ones_exist() {
        assert_eq!(languages("de"), ["de"]);
        assert_eq!(languages("de-AT, en;q=0.8"), ["de-AT", "en"]);
        assert_eq!(languages("en-GB,en;q=0.9,de;q=0.8"), ["en-GB", "en", "de"]);
        assert_eq!(
            languages("fr, de;q=0.5, en;q=0.7"),
            ["fr", "en", "de"],
            "a language that no theme ships is the visitor's all the same: the renderer decides what it can serve"
        );
        assert_eq!(
            languages("fr;q=0.2, es;q=0.2, de;q=0.9"),
            ["de", "fr", "es"],
            "equal ones keep their order"
        );
        assert_eq!(
            languages("*;q=0.5, DE"),
            ["de"],
            "`*` names no language and the case is normalized"
        );
        assert_eq!(languages("de;q=0, en;q=0.1"), ["en"], "q=0 refuses a language");
        assert_eq!(languages("de;q=abc"), ["de"], "a quality nobody can read counts as 1");
        assert_eq!(languages("de, de;q=0.5, DE"), ["de"], "each language once");
        assert_eq!(languages("not a tag, de"), ["de"]);
        assert_eq!(languages(""), Vec::<String>::new());
        assert_eq!(languages("de;q=0"), Vec::<String>::new());
        assert_eq!(accepted_languages(&HeaderMap::new()), Vec::<Locale>::new());
        // A long header is read as far as it is worth reading.
        let long: Vec<String> = ('a'..='z').map(|letter| format!("{letter}{letter}")).collect();
        assert_eq!(languages(&long.join(",")).len(), MAX_LANGUAGES);
    }

    #[test]
    fn qualities_are_read_in_thousandths() {
        for (text, expected) in [
            ("1", Some(1000)),
            ("1.000", Some(1000)),
            ("0", Some(0)),
            ("0.8", Some(800)),
            ("0.125", Some(125)),
            ("0.12345", Some(123)),
            ("0.x", None),
            ("x", None),
        ] {
            assert_eq!(thousandths(text), expected, "{text}");
        }
    }

    #[test]
    fn handler_headers_win_over_the_defaults() {
        let mut headers = HeaderMap::new();
        headers.insert("cache-control", HeaderValue::from_static("private, max-age=300"));
        add_security_headers(&mut headers);
        assert_eq!(headers["cache-control"], "private, max-age=300");
        assert_eq!(headers["x-robots-tag"], "noindex, nofollow");
    }
}
