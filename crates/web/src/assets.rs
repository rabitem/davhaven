//! Static theme assets.
//!
//! `GET /assets/{theme}/{file}` serves the style sheet and the images of the themes (PLAN 2.5): the pages link
//! their style sheet from the server's own origin because the page `Content-Security-Policy` allows no inline
//! styles. The files come from the application's [`AssetService`](davhaven_app::services::AssetService), which
//! gets them from the template renderer (the `assets/` directories of the configured theme directories and the
//! built-in theme); this crate never reads the file system and never names an adapter.
//!
//! The path is split into two plain names and anything else is the 404 page before the service is asked, so a path
//! such as `../secret` or `theme/dir/file` cannot even be expressed. Responses carry a strong `ETag` (`304` for
//! clients that have it), `Cache-Control: public, max-age=3600` and the security headers of every page
//! (`nosniff` among them).

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, ETAG, IF_NONE_MATCH};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use davhaven_app::services::StaticAsset;
use davhaven_domain::ETag;
use davhaven_http::problem::{EdgeProblem, ProblemCode};

use crate::router::{Meta, WebState};

/// The cache policy of assets: public, revalidated after an hour (themes change with a deployment).
const ASSET_CACHE_CONTROL: &str = "public, max-age=3600";

/// The longest theme or file name, in bytes.
const MAX_NAME_BYTES: usize = 100;

/// Whether `name` is a plain name: letters, digits, `.`, `_` and `-`, not starting with a dot.
fn plain(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// The theme and the file of an asset path (`theme/file`); `None` for every other shape.
pub(crate) fn split(path: &str) -> Option<(&str, &str)> {
    let (theme, file) = path.split_once('/')?;
    (plain(theme) && plain(file)).then_some((theme, file))
}

/// Whether the client already has `etag`: `If-None-Match` names it (or is `*`).
fn current(headers: &HeaderMap, etag: &ETag) -> bool {
    headers
        .get(IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|text| {
            let text = text.trim();
            text == "*" || ETag::parse(text).is_ok_and(|candidate| &candidate == etag)
        })
}

/// The response for an asset: 304 for a current client copy, the file otherwise.
fn respond(asset: &StaticAsset, headers: &HeaderMap) -> Response {
    let not_modified = current(headers, &asset.etag);
    let (status, body) = if not_modified {
        (StatusCode::NOT_MODIFIED, Body::empty())
    } else {
        (StatusCode::OK, Body::from(asset.body.clone()))
    };
    let mut response = Response::new(body);
    *response.status_mut() = status;
    let out = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(asset.etag.as_str()) {
        out.insert(ETAG, value);
    }
    out.insert(CACHE_CONTROL, HeaderValue::from_static(ASSET_CACHE_CONTROL));
    if !not_modified {
        out.insert(CONTENT_TYPE, HeaderValue::from_static(asset.content_type));
        out.insert(CONTENT_LENGTH, HeaderValue::from(asset.body.len()));
    }
    response
}

/// Serves the asset at `{theme}/{file}`.
pub(crate) async fn asset(
    State(state): State<WebState>,
    Path(path): Path<String>,
    meta: Meta,
    headers: HeaderMap,
) -> Result<Response, EdgeProblem> {
    let Some((theme, file)) = split(&path) else {
        return Err(EdgeProblem::new(ProblemCode::NotFound));
    };
    let ctx = WebState::anonymous(meta.request_id());
    let asset = state.services.assets.get(&ctx, theme, file).await?;
    Ok(respond(&asset, &headers))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    #[test]
    fn a_path_is_a_theme_and_a_file_and_nothing_else() {
        assert_eq!(split("default/page.css"), Some(("default", "page.css")));
        assert_eq!(
            split("corporate-2/logo_v2.min.png"),
            Some(("corporate-2", "logo_v2.min.png"))
        );
        let long = "a".repeat(MAX_NAME_BYTES + 1);
        for bad in [
            "",
            "page.css",
            "default/",
            "/page.css",
            "default/sub/page.css",
            "../page.css",
            "default/../page.css",
            "default/..",
            ".hidden/page.css",
            "default/.hidden",
            "default/page css",
            "default\\page.css",
            "default/pagé.css",
            "default/page.css\0",
            &format!("{long}/page.css"),
            &format!("default/{long}"),
        ] {
            assert_eq!(split(bad), None, "{bad:?}");
        }
    }

    fn asset(body: &'static [u8]) -> StaticAsset {
        StaticAsset {
            content_type: "text/css; charset=utf-8",
            body: Bytes::from_static(body),
            etag: ETag::from_bytes(body),
        }
    }

    fn conditional(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(IF_NONE_MATCH, HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn a_file_is_served_with_its_type_validator_and_cache_policy() {
        let response = respond(&asset(b"body{}"), &HeaderMap::new());
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CONTENT_TYPE], "text/css; charset=utf-8");
        assert_eq!(response.headers()[CONTENT_LENGTH], "6");
        assert_eq!(response.headers()[CACHE_CONTROL], "public, max-age=3600");
        assert_eq!(response.headers()[ETAG], ETag::from_bytes(b"body{}").as_str());
    }

    #[test]
    fn a_client_that_has_the_file_gets_a_304_without_a_body() {
        let tag = ETag::from_bytes(b"body{}");
        for (header, expected) in [
            (tag.as_str(), StatusCode::NOT_MODIFIED),
            ("*", StatusCode::NOT_MODIFIED),
            ("\"other\"", StatusCode::OK),
        ] {
            let response = respond(&asset(b"body{}"), &conditional(header));
            assert_eq!(response.status(), expected, "{header}");
        }
        let response = respond(&asset(b"body{}"), &conditional(tag.as_str()));
        assert!(response.headers().get(CONTENT_TYPE).is_none());
        assert_eq!(response.headers()[ETAG], tag.as_str());
        assert_eq!(response.headers()[CACHE_CONTROL], "public, max-age=3600");
        for stale in ["W/\"abc\"", "abc", "\"a\", \"b\""] {
            assert_eq!(
                respond(&asset(b"body{}"), &conditional(stale)).status(),
                StatusCode::OK,
                "{stale}"
            );
        }
    }
}
