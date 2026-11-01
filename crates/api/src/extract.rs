//! Request extractors: path keys, pagination, preconditions and idempotency keys.
//!
//! Handlers receive typed values, never raw strings. Every extractor rejects with an [`EdgeProblem`], so a malformed
//! request answers with the same RFC 9457 document as any other failure:
//!
//! | Extractor | Reads | Rejects with |
//! | --- | --- | --- |
//! | `Keys` | path segments as natural keys (`TenantSlug`, `PrincipalName`, ids, ...) | 404 `not-found`: no resource can have such a key |
//! | `Params` | the query string as a typed struct | 400 `bad-request` |
//! | `Paging` | `?limit` (1 or more) and `?cursor` | 400 `bad-request` |
//! | `Preconditions` | `If-Match` (`"v7"`) and `If-None-Match: *` of versioned resources | 412 for tags that cannot match, 400 |
//! | `ContentTag` | `If-Match` with a content ETag of an event | 412 |
//! | `IdempotencyKeyHeader` | `Idempotency-Key` | 400 |
//! | `JsonBody`, `BatchBody`, `PatchBody` | the JSON body, read with the limit of the route | 413, 415, 400, 422 |
//!
//! Bodies are read with the limits of the configuration (`limits.api`): 1 MiB for JSON, 10 MiB for batch upserts.
//! A body that is not JSON answers 400, a body that is JSON but does not fit the type answers 422; the message of
//! the second case is the client-safe text of the deserializer, shortened.

use axum::extract::{FromRequest, FromRequestParts, OriginalUri, Path, Query, Request};
use axum::http::HeaderMap;
use axum::http::header::{CONTENT_TYPE, IF_MATCH, IF_NONE_MATCH};
use axum::http::request::Parts;
use davhaven_app::SafeMessage;
use davhaven_app::services::{Conditions, MergePatch, PageRequest};
use davhaven_domain::ETag;
use davhaven_http::EdgeProblem;
use davhaven_http::limits::read_body;
use davhaven_wire::{Cursor, FieldProblem, Page, ProblemCode, version_from_etag};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use utoipa::IntoParams;

use crate::reply::Reply;
use crate::router::ApiState;

/// The longest `Idempotency-Key` accepted, in characters.
const MAX_IDEMPOTENCY_KEY: usize = 255;

/// Path segments as typed keys: a single key or a tuple, in the order of the path template.
///
/// A segment that is not a valid key (an uppercase tenant slug, a malformed UUID) names no resource and answers
/// 404 without echoing the segment.
#[derive(Debug)]
pub(crate) struct Keys<T>(pub T);

impl<S, T> FromRequestParts<S> for Keys<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Send,
{
    type Rejection = EdgeProblem;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Path::<T>::from_request_parts(parts, state)
            .await
            .map(|Path(keys)| Self(keys))
            .map_err(|_| {
                EdgeProblem::new(ProblemCode::NotFound).with_detail("A segment of the path is not a valid key.")
            })
    }
}

/// The query string as a typed struct; unknown parameters are ignored, so additive changes stay compatible.
#[derive(Debug)]
pub(crate) struct Params<T>(pub T);

impl<S, T> FromRequestParts<S> for Params<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = EdgeProblem;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Query::<T>::from_request_parts(parts, state)
            .await
            .map(|Query(params)| Self(params))
            .map_err(|_| EdgeProblem::new(ProblemCode::BadRequest).with_detail("A query parameter is invalid."))
    }
}

/// The `limit` and `cursor` parameters of every listing.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct PageParams {
    /// The page size: 1 to 200, 50 by default. A limit of 0 is a 400; a larger one than the deployment allows
    /// (200 unless it lowered `limits.api.max_page_size`) is lowered to that maximum.
    #[param(minimum = 1, maximum = 200, default = 50)]
    limit: Option<u32>,
    /// The `next_cursor` of the previous page; the first page when absent.
    #[param(value_type = Option<String>)]
    cursor: Option<String>,
}

/// The request of one page and what is needed to link to the next one.
#[derive(Debug)]
pub(crate) struct Paging {
    request: PageRequest,
    /// This request without its cursor, for `Link: rel="next"`.
    base: LinkBase,
}

/// A request without its `cursor`: the path as the client sent it and the other query parameters, from which the
/// reference to the next page is built.
///
/// The reference is **relative** (RFC 8288 allows it): the API is served on the `internal` listener, which the
/// public base URL does not name, so an absolute link built from the configuration would point at an origin that
/// does not serve `/api/v1`. A relative one is resolved by the client against the URL it called, which is right
/// behind any proxy and any private name.
#[derive(Debug)]
struct LinkBase {
    path: String,
    query: Vec<(String, String)>,
}

impl LinkBase {
    fn of(parts: &Parts) -> Self {
        let original = parts
            .extensions
            .get::<OriginalUri>()
            .map_or(&parts.uri, |original| &original.0);
        let query = url::form_urlencoded::parse(original.query().unwrap_or_default().as_bytes())
            .filter(|(name, _)| name.as_ref() != "cursor")
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect();
        Self {
            path: original.path().to_owned(),
            query,
        }
    }

    /// `/api/v1/...?{the other parameters}&cursor={cursor}`.
    fn reference(&self, cursor: &str) -> String {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        for (name, value) in &self.query {
            query.append_pair(name, value);
        }
        query.append_pair("cursor", cursor);
        format!("{}?{}", self.path, query.finish())
    }
}

impl Paging {
    /// The page request to hand to the service.
    pub(crate) fn request(&self) -> PageRequest {
        self.request.clone()
    }

    /// The response for a page: the JSON document, and `Link: <…>; rel="next"` when more pages follow.
    pub(crate) fn reply<T: serde::Serialize>(&self, page: &Page<T>) -> Reply {
        let reply = Reply::json(axum::http::StatusCode::OK, page);
        match &page.next_cursor {
            Some(cursor) => reply.link_next(&self.base.reference(cursor.as_str())),
            None => reply,
        }
    }
}

impl FromRequestParts<ApiState> for Paging {
    type Rejection = EdgeProblem;

    async fn from_request_parts(parts: &mut Parts, state: &ApiState) -> Result<Self, Self::Rejection> {
        let Params(params) = Params::<PageParams>::from_request_parts(parts, state).await?;
        if params.limit == Some(0) {
            return Err(EdgeProblem::new(ProblemCode::BadRequest).with_detail("The limit must be at least 1."));
        }
        let cursor = params
            .cursor
            .map(|text| Cursor::parse(&text))
            .transpose()
            .map_err(|_| EdgeProblem::new(ProblemCode::BadRequest).with_detail("The cursor is invalid."))?;
        Ok(Self {
            request: PageRequest {
                limit: params.limit,
                cursor,
            },
            base: LinkBase::of(parts),
        })
    }
}

/// The conditional headers of a write to a versioned resource: `If-Match: "v7"` and `If-None-Match: *`.
#[derive(Debug)]
pub(crate) struct Preconditions(pub Conditions);

/// Reads the conditional headers of a versioned write.
///
/// An `If-Match` that is not one strong ETag of this API (`"v7"`) cannot match any version, so it fails the
/// precondition (412); `*` is refused for the same reason, because deletes of calendars and principals must name
/// the version they delete. `If-None-Match` accepts only `*`.
pub(crate) fn conditions_from(headers: &HeaderMap) -> Result<Conditions, EdgeProblem> {
    let if_match = headers
        .get(IF_MATCH)
        .map(|value| {
            value.to_str().ok().and_then(version_from_etag).ok_or_else(|| {
                EdgeProblem::new(ProblemCode::PreconditionFailed)
                    .with_detail("If-Match must be one ETag exactly as the API returned it.")
            })
        })
        .transpose()?;
    let if_none_match_any = match headers.get(IF_NONE_MATCH) {
        None => false,
        Some(value) if value.as_bytes() == b"*" => true,
        Some(_) => {
            return Err(EdgeProblem::new(ProblemCode::BadRequest).with_detail("If-None-Match accepts only *."));
        }
    };
    Ok(Conditions {
        if_match,
        if_none_match_any,
    })
}

impl<S: Send + Sync> FromRequestParts<S> for Preconditions {
    type Rejection = EdgeProblem;

    fn from_request_parts(parts: &mut Parts, _state: &S) -> impl Future<Output = Result<Self, Self::Rejection>> {
        std::future::ready(conditions_from(&parts.headers).map(Self))
    }
}

/// The `If-Match` of a write to an event: its content ETag, as returned by the API.
#[derive(Debug)]
pub(crate) struct ContentTag(pub Option<ETag>);

impl<S: Send + Sync> FromRequestParts<S> for ContentTag {
    type Rejection = EdgeProblem;

    fn from_request_parts(parts: &mut Parts, _state: &S) -> impl Future<Output = Result<Self, Self::Rejection>> {
        std::future::ready(content_tag_from(&parts.headers).map(Self))
    }
}

/// Reads the content ETag of `If-Match` and refuses `If-None-Match`, which events do not support.
pub(crate) fn content_tag_from(headers: &HeaderMap) -> Result<Option<ETag>, EdgeProblem> {
    if headers.contains_key(IF_NONE_MATCH) {
        return Err(EdgeProblem::new(ProblemCode::BadRequest).with_detail("If-None-Match is not supported for events."));
    }
    headers
        .get(IF_MATCH)
        .map(|value| {
            value
                .to_str()
                .ok()
                .and_then(|text| ETag::parse(text).ok())
                .ok_or_else(|| {
                    EdgeProblem::new(ProblemCode::PreconditionFailed)
                        .with_detail("If-Match must be one ETag exactly as the API returned it.")
                })
        })
        .transpose()
}

/// The optional `Idempotency-Key` header of a `POST`.
#[derive(Debug)]
pub(crate) struct IdempotencyKeyHeader(pub Option<String>);

impl IdempotencyKeyHeader {
    /// The key of a request that must carry one (batch upserts).
    pub(crate) fn require(self) -> Result<String, EdgeProblem> {
        self.0.ok_or_else(|| {
            EdgeProblem::new(ProblemCode::BadRequest).with_detail("The Idempotency-Key header is required.")
        })
    }
}

impl<S: Send + Sync> FromRequestParts<S> for IdempotencyKeyHeader {
    type Rejection = EdgeProblem;

    fn from_request_parts(parts: &mut Parts, _state: &S) -> impl Future<Output = Result<Self, Self::Rejection>> {
        std::future::ready(idempotency_key_from(&parts.headers).map(Self))
    }
}

/// Reads and validates the `Idempotency-Key`: 1 to 255 visible ASCII characters.
pub(crate) fn idempotency_key_from(headers: &HeaderMap) -> Result<Option<String>, EdgeProblem> {
    let Some(value) = headers.get("idempotency-key") else {
        return Ok(None);
    };
    let key = value.to_str().ok().map(str::trim).filter(|key| {
        !key.is_empty() && key.len() <= MAX_IDEMPOTENCY_KEY && key.bytes().all(|byte| byte.is_ascii_graphic())
    });
    key.map(|key| Some(key.to_owned())).ok_or_else(|| {
        EdgeProblem::new(ProblemCode::BadRequest)
            .with_detail("The Idempotency-Key must be 1 to 255 visible ASCII characters.")
    })
}

/// Whether the `Content-Type` is JSON: `application/json` or a `+json` type such as
/// `application/merge-patch+json`.
fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(|media_type| media_type.trim().to_ascii_lowercase())
        .is_some_and(|media_type| media_type == "application/json" || media_type.ends_with("+json"))
}

/// Deserializes a JSON body; a document that is not JSON is a 400, one that does not fit `T` a 422.
fn parse_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, EdgeProblem> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Err(EdgeProblem::new(ProblemCode::BadRequest).with_detail("The request needs a JSON body."));
    }
    serde_json::from_slice(bytes).map_err(|error| match error.classify() {
        serde_json::error::Category::Data => {
            let text = error.to_string();
            if let Some(member) = davhaven_domain::null_refused_member(&text) {
                return not_nullable(bytes, member);
            }
            let message = SafeMessage::sanitized(&text);
            if davhaven_domain::settings::busy_texts_repeat_a_tag(&text) {
                // The tags of the busy texts of a tenant are canonical once read: one tag written in two spellings is
                // refused at the member that holds them (`TenantWrite`, the only body that carries the settings).
                return EdgeProblem::new(ProblemCode::ValidationFailed)
                    .with_detail("A language tag is written twice in the busy texts.")
                    .with_error(FieldProblem::new(
                        "/settings/busy_text_by_locale",
                        "duplicate-tag",
                        message.as_str(),
                    ));
            }
            EdgeProblem::new(ProblemCode::ValidationFailed)
                .with_detail("The request body does not match the expected shape.")
                .with_error(FieldProblem::new("", "invalid-body", message.as_str()))
        }
        _ => EdgeProblem::new(ProblemCode::BadRequest).with_detail("The request body is not valid JSON."),
    })
}

/// The problem of a `null` for a member of an event that cannot be removed (`uid`, `start`): it names the member by
/// its pointer (`/start`, or `/items/3/event/start` in a batch), so that a client can tell which of its items it is
/// about.
fn not_nullable(bytes: &[u8], member: &str) -> EdgeProblem {
    let pointer = serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|document| null_pointer(&document, member, ""))
        .unwrap_or_default();
    EdgeProblem::new(ProblemCode::ValidationFailed)
        .with_detail("A field that cannot be removed was sent as null.")
        .with_error(FieldProblem::new(
            pointer,
            "not-nullable",
            format!("`{member}` cannot be null: the field cannot be removed"),
        ))
}

/// The JSON pointer of the first member named `member` whose value is `null`, arrays in order. Typed
/// deserialization stops at the first failure, which is the first such member of the document.
fn null_pointer(value: &serde_json::Value, member: &str, path: &str) -> Option<String> {
    match value {
        serde_json::Value::Object(map) => {
            if matches!(map.get(member), Some(serde_json::Value::Null)) {
                return Some(format!("{path}/{member}"));
            }
            map.iter().find_map(|(key, child)| {
                let key = key.replace('~', "~0").replace('/', "~1");
                null_pointer(child, member, &format!("{path}/{key}"))
            })
        }
        serde_json::Value::Array(items) => items
            .iter()
            .enumerate()
            .find_map(|(index, child)| null_pointer(child, member, &format!("{path}/{index}"))),
        _ => None,
    }
}

/// Reads a request body as JSON with the given limit.
async fn read_json<T: DeserializeOwned>(request: Request, limit: u64) -> Result<T, EdgeProblem> {
    if !is_json(request.headers()) {
        return Err(EdgeProblem::new(ProblemCode::UnsupportedMediaType)
            .with_detail("The body must be sent as application/json."));
    }
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let bytes = read_body(request.into_body(), limit).await.map_err(EdgeProblem::from)?;
    parse_json(&bytes)
}

/// A JSON body of up to `limits.api.max_json_body` bytes (1 MiB by default).
#[derive(Debug)]
pub(crate) struct JsonBody<T>(pub T);

impl<T: DeserializeOwned> FromRequest<ApiState> for JsonBody<T> {
    type Rejection = EdgeProblem;

    async fn from_request(request: Request, state: &ApiState) -> Result<Self, Self::Rejection> {
        read_json(request, state.services.limits.api.max_json_body)
            .await
            .map(Self)
    }
}

/// A JSON body of up to `limits.api.max_batch_body` bytes (10 MiB by default), for batch upserts.
#[derive(Debug)]
pub(crate) struct BatchBody<T>(pub T);

impl<T: DeserializeOwned> FromRequest<ApiState> for BatchBody<T> {
    type Rejection = EdgeProblem;

    async fn from_request(request: Request, state: &ApiState) -> Result<Self, Self::Rejection> {
        read_json(request, state.services.limits.api.max_batch_body)
            .await
            .map(Self)
    }
}

/// The body of a `PATCH`: a JSON Merge Patch document (RFC 7396), which must be a JSON object.
#[derive(Debug)]
pub(crate) struct PatchBody(pub MergePatch);

impl FromRequest<ApiState> for PatchBody {
    type Rejection = EdgeProblem;

    async fn from_request(request: Request, state: &ApiState) -> Result<Self, Self::Rejection> {
        let document = read_json::<serde_json::Value>(request, state.services.limits.api.max_json_body).await?;
        MergePatch::new(document).map(Self).map_err(EdgeProblem::from)
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;
    use serde::Serialize;

    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    #[test]
    fn the_link_to_the_next_page_is_relative_and_keeps_the_other_parameters() {
        let parts = |uri: &str| {
            let (parts, ()) = axum::http::Request::get(uri).body(()).unwrap().into_parts();
            parts
        };
        let base = LinkBase::of(&parts("/api/v1/tenants/acme/principals?limit=2&kind=user&cursor=old"));
        assert_eq!(
            base.reference("next"),
            "/api/v1/tenants/acme/principals?limit=2&kind=user&cursor=next"
        );
        let without_query = LinkBase::of(&parts("/api/v1/tenants/acme/principals"));
        assert_eq!(
            without_query.reference("a b"),
            "/api/v1/tenants/acme/principals?cursor=a+b"
        );
        let encoded = LinkBase::of(&parts("/api/v1/x?name=a%26b%3Dc&cursor=1"));
        assert_eq!(encoded.reference("n"), "/api/v1/x?name=a%26b%3Dc&cursor=n");
    }

    #[test]
    fn if_match_takes_one_version_etag_and_nothing_else() {
        assert_eq!(conditions_from(&HeaderMap::new()).unwrap(), Conditions::none());
        assert_eq!(
            conditions_from(&headers(&[("if-match", "\"v7\"")])).unwrap(),
            Conditions::if_match(7)
        );
        assert_eq!(
            conditions_from(&headers(&[("if-none-match", "*")])).unwrap(),
            Conditions::create_only()
        );
        for bad in ["*", "W/\"v7\"", "\"v7\", \"v8\"", "v7", "\"abc\"", "\"v0\""] {
            let problem = conditions_from(&headers(&[("if-match", bad)])).unwrap_err();
            assert_eq!(problem.code(), ProblemCode::PreconditionFailed, "{bad}");
        }
        let problem = conditions_from(&headers(&[("if-none-match", "\"v7\"")])).unwrap_err();
        assert_eq!(problem.code(), ProblemCode::BadRequest);
    }

    #[test]
    fn event_writes_take_content_etags() {
        let etag = ETag::from_bytes(b"BEGIN:VCALENDAR");
        let given = headers(&[("if-match", etag.as_str())]);
        assert_eq!(content_tag_from(&given).unwrap(), Some(etag));
        assert_eq!(content_tag_from(&HeaderMap::new()).unwrap(), None);
        for bad in ["*", "\"v7\", \"v8\"", "abc"] {
            let problem = content_tag_from(&headers(&[("if-match", bad)])).unwrap_err();
            assert_eq!(problem.code(), ProblemCode::PreconditionFailed, "{bad}");
        }
        let problem = content_tag_from(&headers(&[("if-none-match", "*")])).unwrap_err();
        assert_eq!(problem.code(), ProblemCode::BadRequest);
    }

    #[test]
    fn idempotency_keys_are_short_visible_ascii() {
        assert_eq!(idempotency_key_from(&HeaderMap::new()).unwrap(), None);
        let key = idempotency_key_from(&headers(&[("idempotency-key", " abc-123 ")])).unwrap();
        assert_eq!(key.as_deref(), Some("abc-123"));
        let longest = "a".repeat(255);
        let key = idempotency_key_from(&headers(&[("idempotency-key", longest.as_str())])).unwrap();
        assert_eq!(
            key.as_deref(),
            Some(longest.as_str()),
            "255 characters are the limit, not past it"
        );
        let mut opaque = HeaderMap::new();
        opaque.insert("idempotency-key", HeaderValue::from_bytes(b"caf\xe9").unwrap());
        assert_eq!(
            idempotency_key_from(&opaque).unwrap_err().code(),
            ProblemCode::BadRequest,
            "bytes outside ASCII are no key"
        );
        let long = "a".repeat(256);
        for bad in ["", "   ", "has space", "tab\tseparated", long.as_str()] {
            let result = idempotency_key_from(&headers(&[("idempotency-key", bad)]));
            assert_eq!(result.unwrap_err().code(), ProblemCode::BadRequest, "{bad:.20?}");
        }
        assert!(IdempotencyKeyHeader(None).require().is_err());
        assert_eq!(IdempotencyKeyHeader(Some("k".to_owned())).require().unwrap(), "k");
    }

    /// The errors of the problem a body is refused with: `(pointer, code)` of each.
    fn refusal<T: DeserializeOwned>(body: &str) -> Vec<(String, String)> {
        let Err(problem) = parse_json::<T>(body.as_bytes()) else {
            panic!("{body} is accepted");
        };
        assert_eq!(problem.code(), ProblemCode::ValidationFailed, "{body}");
        problem
            .errors()
            .iter()
            .map(|error| (error.pointer.clone(), error.code.clone()))
            .collect()
    }

    #[test]
    fn a_null_for_a_member_that_cannot_be_removed_is_refused_at_its_pointer() {
        use davhaven_wire::{BatchRequest, EventView};

        let not_nullable = |pointer: &str| vec![(pointer.to_owned(), "not-nullable".to_owned())];
        for member in ["uid", "start"] {
            assert_eq!(
                refusal::<EventView>(&format!(r#"{{"summary":"x","{member}":null}}"#)),
                not_nullable(&format!("/{member}"))
            );
        }
        // In a batch the pointer is the one of the item that carries it: the third, not the whole body.
        let batch = r#"{"items":[
            {"external_key":"a","event":{"summary":"A","start":{"date":"2027-03-01"}}},
            {"external_key":"b","event":{"summary":"B","location":null,"start":{"date":"2027-03-01"}}},
            {"external_key":"c","event":{"summary":"C","start":null}}
        ]}"#;
        assert_eq!(
            refusal::<BatchRequest>(batch),
            not_nullable("/items/2/event/start"),
            "a null that removes a field (`location`) is no problem, one that cannot is"
        );
        // Other bodies that do not fit are still refused as a whole, with the text of the parser.
        assert_eq!(
            refusal::<EventView>(r#"{"summary":5}"#),
            vec![(String::new(), "invalid-body".to_owned())]
        );
    }

    #[test]
    fn one_language_tag_in_two_spellings_is_refused_at_the_busy_texts() {
        use davhaven_wire::TenantWrite;

        // The same tag twice would be one key after reading, and the later text would win without a word.
        let body =
            r#"{"display_name":"Acme","settings":{"busy_text_by_locale":{"de-DE":"Nicht verfügbar","de_de":"Weg"}}}"#;
        assert_eq!(
            refusal::<TenantWrite>(body),
            vec![("/settings/busy_text_by_locale".to_owned(), "duplicate-tag".to_owned())]
        );
        // Different tags are no repetition, and a tag that is none is a failure of the body as a whole, as any other.
        assert!(
            parse_json::<TenantWrite>(
                br#"{"display_name":"Acme","settings":{"busy_text_by_locale":{"de":"a","de_AT":"b"}}}"#
            )
            .is_ok()
        );
        assert_eq!(
            refusal::<TenantWrite>(r#"{"display_name":"Acme","settings":{"busy_text_by_locale":{"!!":"a"}}}"#),
            vec![(String::new(), "invalid-body".to_owned())]
        );
    }

    #[test]
    fn json_pointers_escape_the_members_they_pass() {
        let document: serde_json::Value = serde_json::from_str(r#"{"a/b":{"c~d":[{"start":null}]}}"#).unwrap();
        assert_eq!(
            null_pointer(&document, "start", "").as_deref(),
            Some("/a~1b/c~0d/0/start")
        );
        assert_eq!(null_pointer(&document, "uid", ""), None);
    }

    #[test]
    fn json_media_types_include_structured_syntax_suffixes() {
        for good in [
            "application/json",
            "application/json; charset=utf-8",
            "APPLICATION/JSON",
            "application/merge-patch+json",
            "application/problem+json",
        ] {
            assert!(is_json(&headers(&[("content-type", good)])), "{good}");
        }
        for bad in ["text/plain", "application/xml", "application/jsonp", "json", ""] {
            assert!(!is_json(&headers(&[("content-type", bad)])), "{bad}");
        }
        assert!(!is_json(&HeaderMap::new()));
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Sample {
        display_name: String,
    }

    #[test]
    fn json_bodies_fail_with_the_right_class_of_problem() {
        let ok: Sample = parse_json(br#"{"display_name": "Anna"}"#).unwrap();
        assert_eq!(ok.display_name, "Anna");
        for broken in [
            &b""[..],
            &b"   \n"[..],
            &b"{"[..],
            &b"nope"[..],
            &b"{\"display_name\": \"x\""[..],
        ] {
            let problem = parse_json::<Sample>(broken).unwrap_err();
            assert_eq!(problem.code(), ProblemCode::BadRequest, "{broken:?}");
        }
        for wrong in [
            &br"{}"[..],
            &br#"{"display_name": 5}"#[..],
            &br#"{"display_name": "x", "extra": 1}"#[..],
            &br"[]"[..],
        ] {
            let problem = parse_json::<Sample>(wrong).unwrap_err();
            assert_eq!(problem.code(), ProblemCode::ValidationFailed, "{wrong:?}");
            assert_eq!(problem.errors().len(), 1);
            assert_eq!(problem.errors()[0].code, "invalid-body");
        }
    }

    #[test]
    fn deserializer_messages_are_shortened_and_free_of_control_characters() {
        let long_key = "k".repeat(5000);
        let body = format!("{{\"{long_key}\": 1}}");
        let problem = parse_json::<Sample>(body.as_bytes()).unwrap_err();
        let message = &problem.errors()[0].message;
        assert!(message.chars().count() <= 200, "{}", message.len());
        assert!(!message.chars().any(char::is_control));
    }
}
