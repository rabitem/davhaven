//! The request headers of the DAV methods: `Depth`, `Overwrite`, `Destination`, the conditional headers of
//! writes and reads, `Schedule-Reply` and the preferences (`Prefer`, `Brief`).
//!
//! Headers that are malformed answer 400; conditional headers that cannot match (an entity tag the server never
//! issues, a value that is not text) make the precondition fail with 412 instead of being ignored.

use axum::http::uri::Authority;
use axum::http::{HeaderMap, StatusCode};
use davhaven_app::services::{IfMatch, ScheduleReply, WritePrecondition};
use davhaven_domain::{ETag, ResourcePath, ScheduleTag};
use davhaven_http::problem::{EdgeProblem, ProblemCode};

use super::not_implemented;
use crate::xml::requests::bad_request;

/// The `Depth` of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Depth {
    /// The resource itself.
    Zero,
    /// The resource and its members.
    One,
    /// The whole tree below the resource (refused by PROPFIND).
    Infinity,
}

/// The text of a header, `None` when it is absent or not text.
pub(crate) fn text(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get(name)?.to_str().ok().map(str::to_owned)
}

/// The values of every occurrence of a header.
fn values<'a>(headers: &'a HeaderMap, name: &str) -> Vec<&'a str> {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect()
}

/// Reads `Depth`; `default` stands for an absent header.
///
/// # Errors
///
/// 400 for anything but `0`, `1` and `infinity`.
pub(crate) fn depth(headers: &HeaderMap, default: Depth) -> Result<Depth, EdgeProblem> {
    let Some(value) = headers.get("depth") else {
        return Ok(default);
    };
    match value.to_str().map(|text| text.trim().to_ascii_lowercase()).as_deref() {
        Ok("0") => Ok(Depth::Zero),
        Ok("1") => Ok(Depth::One),
        Ok("infinity") => Ok(Depth::Infinity),
        _ => Err(bad_request("The Depth header must be 0, 1 or infinity.")),
    }
}

/// Reads `Overwrite`: `T` (the default) or `F`.
///
/// # Errors
///
/// 400 for any other value.
pub(crate) fn overwrite(headers: &HeaderMap) -> Result<bool, EdgeProblem> {
    match text(headers, "overwrite").as_deref().map(str::trim) {
        None => Ok(true),
        Some(value) if value.eq_ignore_ascii_case("t") => Ok(true),
        Some(value) if value.eq_ignore_ascii_case("f") => Ok(false),
        Some(_) => Err(bad_request("The Overwrite header must be T or F.")),
    }
}

/// Reads `Schedule-Reply` (RFC 6638 section 8.1): `F` suppresses the reply an attendee's deletion would send.
pub(crate) fn schedule_reply(headers: &HeaderMap) -> ScheduleReply {
    match text(headers, "schedule-reply").as_deref().map(str::trim) {
        Some(value) if value.eq_ignore_ascii_case("f") => ScheduleReply::Suppress,
        _ => ScheduleReply::Send,
    }
}

/// Whether the client asked for the minimal representation: `Prefer: return=minimal` (RFC 8144) or the older
/// `Brief: t`.
pub(crate) fn minimal_requested(headers: &HeaderMap) -> bool {
    let brief = text(headers, "brief").is_some_and(|value| value.trim().eq_ignore_ascii_case("t"));
    let prefer = values(headers, "prefer").iter().any(|value| {
        value.split(',').any(|preference| {
            let preference = preference.split(';').next().unwrap_or_default();
            preference.split_once('=').is_some_and(|(name, value)| {
                name.trim().eq_ignore_ascii_case("return")
                    && value.trim().trim_matches('"').eq_ignore_ascii_case("minimal")
            })
        })
    });
    brief || prefer
}

/// The entity tags of an `If-Match` or `If-None-Match` header.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct TagList {
    /// `*` was listed.
    pub(crate) any: bool,
    /// The strong tags as written, with their quotes.
    pub(crate) strong: Vec<String>,
    /// The weak tags (`W/"..."`) as written, with their quotes.
    pub(crate) weak: Vec<String>,
}

/// Reads the value of an entity tag list header (`*`, or tags separated by commas), tolerating whatever else
/// clients put between the tags.
pub(crate) fn parse_tag_list(values: &[&str]) -> TagList {
    let mut list = TagList::default();
    for value in values {
        let mut rest = value.trim();
        loop {
            rest = rest.trim_start_matches(|c: char| c == ',' || c.is_whitespace());
            if rest.is_empty() {
                break;
            }
            if let Some(after) = rest.strip_prefix('*') {
                list.any = true;
                rest = after;
                continue;
            }
            let (weak, tag_start) = match rest.strip_prefix("W/").or_else(|| rest.strip_prefix("w/")) {
                Some(after) => (true, after),
                None => (false, rest),
            };
            let Some(quoted) = tag_start.strip_prefix('"') else {
                // Not a tag: skip to the next comma.
                rest = tag_start.split_once(',').map_or("", |(_, after)| after);
                continue;
            };
            let Some(end) = quoted.find('"') else {
                break;
            };
            let tag = format!("\"{}\"", quoted.get(..end).unwrap_or_default());
            if weak {
                list.weak.push(tag);
            } else {
                list.strong.push(tag);
            }
            rest = quoted.get(end + 1..).unwrap_or_default();
        }
    }
    list
}

fn precondition_failed() -> EdgeProblem {
    EdgeProblem::new(ProblemCode::PreconditionFailed)
}

/// The values of every occurrence of a conditional header (`If-Match`, `If-None-Match`, `If-Schedule-Tag-Match`).
///
/// A value that is not visible ASCII cannot name an entity tag the server issued, and it must not be skipped: a
/// request that carries a condition it cannot express would run unconditionally. The condition fails instead.
///
/// # Errors
///
/// 412 when an occurrence is not text.
pub(crate) fn conditional_values<'a>(headers: &'a HeaderMap, name: &str) -> Result<Vec<&'a str>, EdgeProblem> {
    headers
        .get_all(name)
        .iter()
        .map(|value| value.to_str().map_err(|_| precondition_failed()))
        .collect()
}

/// Reads the conditional headers of a write: `If-Schedule-Tag-Match`, `If-Match` and `If-None-Match: *`.
///
/// # Errors
///
/// 412 for a conditional header that cannot be read or an `If-Schedule-Tag-Match` that is no tag the server issues
/// (it cannot match), 501 for `If-None-Match` with entity tags and for a list of schedule tags, which
/// `WritePrecondition` cannot express.
pub(crate) fn write_precondition(headers: &HeaderMap) -> Result<WritePrecondition, EdgeProblem> {
    let mut preconditions = WritePrecondition::none();
    let schedule_tags = conditional_values(headers, "if-schedule-tag-match")?;
    if !schedule_tags.is_empty() {
        let list = parse_tag_list(&schedule_tags);
        preconditions.if_schedule_tag_match = Some(match (list.strong.as_slice(), list.weak.is_empty() && !list.any) {
            ([tag], true) => ScheduleTag::parse(tag).map_err(|_| precondition_failed())?,
            ([], _) | (_, false) => return Err(precondition_failed()),
            _ => {
                return Err(not_implemented(
                    "A list of schedule tags is not supported in If-Schedule-Tag-Match; send one.",
                ));
            }
        });
    }
    let if_match = conditional_values(headers, "if-match")?;
    if !if_match.is_empty() {
        let list = parse_tag_list(&if_match);
        preconditions.if_match = Some(if list.any {
            IfMatch::Any
        } else {
            IfMatch::Tags(list.strong.iter().filter_map(|tag| ETag::parse(tag).ok()).collect())
        });
    }
    let if_none_match = conditional_values(headers, "if-none-match")?;
    if !if_none_match.is_empty() {
        let list = parse_tag_list(&if_none_match);
        if !list.strong.is_empty() || !list.weak.is_empty() {
            return Err(not_implemented(
                "If-None-Match with entity tags is not supported on writes; use If-None-Match: *.",
            ));
        }
        preconditions.if_none_match_any = list.any;
    }
    Ok(preconditions)
}

/// Evaluates the conditions of a write against a resource that exists (the source of a `COPY`, whose service call
/// takes no conditions): they fail with 412 as the services fail them for `PUT`, `DELETE` and `MOVE`.
///
/// # Errors
///
/// 412 when a condition does not hold.
pub(crate) fn require_conditions(
    conditions: &WritePrecondition,
    etag: &ETag,
    schedule_tag: Option<&ScheduleTag>,
) -> Result<(), EdgeProblem> {
    if let Some(wanted) = &conditions.if_schedule_tag_match
        && schedule_tag != Some(wanted)
    {
        return Err(precondition_failed());
    }
    let holds = match &conditions.if_match {
        None | Some(IfMatch::Any) => true,
        Some(IfMatch::Tags(tags)) => tags.contains(etag),
    };
    if !holds || conditions.if_none_match_any {
        return Err(precondition_failed());
    }
    Ok(())
}

/// Evaluates the conditional headers of a read against the entity tag of the resource: `Some(status)` when the
/// request is answered without the body (412 for a failed `If-Match` or one that cannot be read, 304 for a matching
/// `If-None-Match`).
pub(crate) fn read_condition(headers: &HeaderMap, etag: &ETag) -> Option<StatusCode> {
    let Ok(if_match) = conditional_values(headers, "if-match") else {
        return Some(StatusCode::PRECONDITION_FAILED);
    };
    if !if_match.is_empty() {
        let list = parse_tag_list(&if_match);
        if !list.any && !list.strong.iter().any(|tag| tag == etag.as_str()) {
            return Some(StatusCode::PRECONDITION_FAILED);
        }
    }
    let Ok(if_none_match) = conditional_values(headers, "if-none-match") else {
        return Some(StatusCode::PRECONDITION_FAILED);
    };
    if !if_none_match.is_empty() {
        let list = parse_tag_list(&if_none_match);
        // Reads compare weakly: `W/"x"` matches `"x"`.
        let weak_equal = |tag: &String| tag.as_str() == etag.as_str();
        if list.any || list.strong.iter().any(weak_equal) || list.weak.iter().any(weak_equal) {
            return Some(StatusCode::NOT_MODIFIED);
        }
    }
    None
}

/// A server as a URL names it: the host in lower case and the port, which is the default of the scheme when the URL
/// names none (`https://host` and `https://host:443` name one server).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Origin {
    host: String,
    port: Option<u16>,
}

impl Origin {
    /// The origin of a host and the port of its scheme.
    pub(crate) fn new(host: &str, port: Option<u16>) -> Self {
        Self {
            host: host.to_ascii_lowercase(),
            port,
        }
    }

    /// The origin `authority` names under `scheme`.
    fn of(scheme: &str, authority: &Authority) -> Self {
        let default = match scheme {
            "http" => Some(80),
            "https" => Some(443),
            _ => None,
        };
        Self::new(authority.host(), authority.port_u16().or(default))
    }
}

/// Where the `Destination` of a `MOVE` or `COPY` points.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Destination {
    /// A resource of this server.
    Here(ResourcePath),
    /// Another server: RFC 4918 sections 9.8.5 and 9.9.4 answer 502 (this server does not move to others).
    Elsewhere,
}

/// Reads the `Destination` header of MOVE and COPY: a path of this server or an absolute URL of it.
///
/// An absolute URL names this server when its scheme, host and port are those of the configured DAV base URL or
/// those of the `Host` the client addressed the request to (default ports are the same as none); only the path is
/// used afterwards.
///
/// # Errors
///
/// 400 when the header is missing, is no URL or path, or does not name a resource of the namespace on this server.
pub(crate) fn destination(headers: &HeaderMap, dav_base: &Origin) -> Result<Destination, EdgeProblem> {
    let value = text(headers, "destination").ok_or_else(|| bad_request("A Destination header is required."))?;
    let value = value.trim();
    if let Some((scheme, rest)) = value.split_once("://") {
        let scheme = scheme.to_ascii_lowercase();
        let authority_text = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let authority: Authority = authority_text
            .parse()
            .map_err(|_| bad_request("The Destination does not name a resource of this server."))?;
        let named = Origin::of(&scheme, &authority);
        let asked = text(headers, "host")
            .and_then(|host| host.trim().parse::<Authority>().ok())
            .map(|authority| Origin::of(&scheme, &authority));
        if &named != dav_base && asked.as_ref() != Some(&named) {
            return Ok(Destination::Elsewhere);
        }
    }
    ResourcePath::from_href(value)
        .map(Destination::Here)
        .map_err(|_| bad_request("The Destination does not name a resource of this server."))
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;
    use davhaven_domain::{CalendarSlug, ObjectUri, PrincipalName, TenantSlug};

    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    fn etag() -> ETag {
        ETag::from_bytes(b"data")
    }

    #[test]
    fn depth_is_zero_one_or_infinity() {
        for (value, expected) in [
            ("0", Depth::Zero),
            ("1", Depth::One),
            ("infinity", Depth::Infinity),
            (" Infinity ", Depth::Infinity),
        ] {
            assert_eq!(
                depth(&headers(&[("depth", value)]), Depth::Zero).unwrap(),
                expected,
                "{value}"
            );
        }
        assert_eq!(depth(&HeaderMap::new(), Depth::One).unwrap(), Depth::One);
        for bad in ["2", "", "1,0", "infinite"] {
            assert!(depth(&headers(&[("depth", bad)]), Depth::Zero).is_err(), "{bad}");
        }
    }

    #[test]
    fn overwrite_defaults_to_true() {
        assert!(overwrite(&HeaderMap::new()).unwrap());
        assert!(overwrite(&headers(&[("overwrite", "T")])).unwrap());
        assert!(!overwrite(&headers(&[("overwrite", "f")])).unwrap());
        assert!(overwrite(&headers(&[("overwrite", "maybe")])).is_err());
    }

    #[test]
    fn schedule_reply_suppresses_only_on_f() {
        assert_eq!(schedule_reply(&HeaderMap::new()), ScheduleReply::Send);
        assert_eq!(
            schedule_reply(&headers(&[("schedule-reply", "T")])),
            ScheduleReply::Send
        );
        assert_eq!(
            schedule_reply(&headers(&[("schedule-reply", "F")])),
            ScheduleReply::Suppress
        );
        assert_eq!(
            schedule_reply(&headers(&[("schedule-reply", " f ")])),
            ScheduleReply::Suppress
        );
    }

    #[test]
    fn the_minimal_representation_is_asked_for_in_two_ways() {
        assert!(!minimal_requested(&HeaderMap::new()));
        assert!(minimal_requested(&headers(&[("prefer", "return=minimal")])));
        assert!(minimal_requested(&headers(&[(
            "prefer",
            "respond-async, return=minimal; foo=bar"
        )])));
        assert!(minimal_requested(&headers(&[
            ("prefer", "wait=10"),
            ("prefer", "RETURN=Minimal")
        ])));
        assert!(!minimal_requested(&headers(&[("prefer", "return=representation")])));
        assert!(!minimal_requested(&headers(&[("prefer", "return")])));
        assert!(minimal_requested(&headers(&[("brief", "t")])));
        assert!(minimal_requested(&headers(&[("brief", "T")])));
        assert!(!minimal_requested(&headers(&[("brief", "f")])));
    }

    #[test]
    fn entity_tag_lists_are_read_leniently() {
        let list = parse_tag_list(&[r#""a", W/"b" , "c,d",*"#]);
        assert!(list.any);
        assert_eq!(list.strong, [r#""a""#, r#""c,d""#]);
        assert_eq!(list.weak, [r#""b""#]);
        assert_eq!(parse_tag_list(&[r#"junk, "x""#]).strong, [r#""x""#]);
        assert_eq!(parse_tag_list(&[r#""unterminated"#]), TagList::default());
        assert_eq!(parse_tag_list(&[""]), TagList::default());
        let two = parse_tag_list(&[r#""a""#, r#""b""#]);
        assert_eq!(two.strong.len(), 2, "every occurrence of the header counts");
    }

    #[test]
    fn writes_read_their_conditions_in_the_order_of_the_plan() {
        let tag = etag();
        let conditions = write_precondition(&headers(&[
            ("if-schedule-tag-match", "\"st-1\""),
            ("if-match", tag.as_str()),
            ("if-none-match", "*"),
        ]))
        .unwrap();
        assert_eq!(conditions.if_schedule_tag_match.unwrap().as_str(), "\"st-1\"");
        assert_eq!(conditions.if_match, Some(IfMatch::Tags(vec![tag])));
        assert!(conditions.if_none_match_any);

        assert_eq!(
            write_precondition(&HeaderMap::new()).unwrap(),
            WritePrecondition::none()
        );
        assert_eq!(
            write_precondition(&headers(&[("if-match", "*")])).unwrap().if_match,
            Some(IfMatch::Any)
        );
    }

    #[test]
    fn tags_the_server_never_issues_cannot_match() {
        let conditions = write_precondition(&headers(&[("if-match", r#"W/"weak", "short""#)])).unwrap();
        assert_eq!(
            conditions.if_match,
            Some(IfMatch::Tags(Vec::new())),
            "weak and foreign tags never match an If-Match"
        );
        let problem = write_precondition(&headers(&[("if-schedule-tag-match", "not-a-tag")])).unwrap_err();
        assert_eq!(problem.code(), ProblemCode::PreconditionFailed);
    }

    #[test]
    fn if_none_match_with_tags_is_not_supported_on_writes() {
        let problem = write_precondition(&headers(&[("if-none-match", r#""abc""#)])).unwrap_err();
        assert_eq!(problem.code(), ProblemCode::NotImplemented);
        assert!(
            !write_precondition(&headers(&[("if-none-match", "")]))
                .unwrap()
                .if_none_match_any
        );
    }

    #[test]
    fn reads_answer_if_none_match_with_304_and_a_failed_if_match_with_412() {
        let tag = etag();
        let other = ETag::from_bytes(b"other");
        assert_eq!(read_condition(&HeaderMap::new(), &tag), None);
        assert_eq!(
            read_condition(&headers(&[("if-none-match", tag.as_str())]), &tag),
            Some(StatusCode::NOT_MODIFIED)
        );
        assert_eq!(
            read_condition(&headers(&[("if-none-match", &format!("W/{}", tag.as_str()))]), &tag),
            Some(StatusCode::NOT_MODIFIED)
        );
        assert_eq!(
            read_condition(&headers(&[("if-none-match", "*")]), &tag),
            Some(StatusCode::NOT_MODIFIED)
        );
        assert_eq!(
            read_condition(&headers(&[("if-none-match", other.as_str())]), &tag),
            None
        );
        assert_eq!(read_condition(&headers(&[("if-match", "*")]), &tag), None);
        assert_eq!(read_condition(&headers(&[("if-match", tag.as_str())]), &tag), None);
        assert_eq!(
            read_condition(&headers(&[("if-match", other.as_str())]), &tag),
            Some(StatusCode::PRECONDITION_FAILED)
        );
        assert_eq!(
            read_condition(&headers(&[("if-match", &format!("W/{}", tag.as_str()))]), &tag),
            Some(StatusCode::PRECONDITION_FAILED),
            "a weak tag never satisfies If-Match"
        );
        assert_eq!(
            read_condition(
                &headers(&[("if-match", other.as_str()), ("if-none-match", tag.as_str())]),
                &tag
            ),
            Some(StatusCode::PRECONDITION_FAILED),
            "If-Match is evaluated first"
        );
    }

    fn object_path() -> ResourcePath {
        ResourcePath::Object {
            tenant: TenantSlug::parse("acme").unwrap(),
            principal: PrincipalName::parse("anna").unwrap(),
            binding: CalendarSlug::parse("work").unwrap(),
            object: ObjectUri::parse("a b.ics").unwrap(),
        }
    }

    /// The origin of `https://cal.example.org`.
    fn base() -> Origin {
        Origin::new("cal.example.org", Some(443))
    }

    #[test]
    fn destinations_are_paths_or_urls_of_this_server() {
        let expected = Destination::Here(object_path());
        for value in [
            "/dav/calendars/acme/anna/work/a%20b.ics",
            "https://cal.example.org/dav/calendars/acme/anna/work/a%20b.ics",
            "HTTPS://CAL.EXAMPLE.ORG/dav/calendars/acme/anna/work/a%20b.ics",
            "https://cal.example.org:443/dav/calendars/acme/anna/work/a%20b.ics",
            "https://user@cal.example.org/dav/calendars/acme/anna/work/a%20b.ics",
        ] {
            assert_eq!(
                destination(&headers(&[("destination", value)]), &base()).unwrap(),
                expected,
                "{value}"
            );
        }
        let by_host = headers(&[
            (
                "destination",
                "http://internal:8080/dav/calendars/acme/anna/work/a%20b.ics",
            ),
            ("host", "internal:8080"),
        ]);
        assert_eq!(destination(&by_host, &base()).unwrap(), expected);
        let default_port = headers(&[
            ("destination", "https://internal/dav/calendars/acme/anna/work/a%20b.ics"),
            ("host", "internal:443"),
        ]);
        assert_eq!(
            destination(&default_port, &base()).unwrap(),
            expected,
            "a default port is the same as none"
        );
        let ported_base = Origin::new("cal.example.org", Some(8443));
        let named = headers(&[(
            "destination",
            "https://cal.example.org:8443/dav/calendars/acme/anna/work/a%20b.ics",
        )]);
        assert_eq!(destination(&named, &ported_base).unwrap(), expected);
        assert_eq!(
            destination(&named, &base()).unwrap(),
            Destination::Elsewhere,
            "another port is another server"
        );
    }

    #[test]
    fn destinations_on_other_servers_are_not_ours() {
        for value in [
            "https://evil.example/dav/calendars/acme/anna/work/a.ics",
            "https://evil.example/dav/",
            "http://cal.example.org/dav/calendars/acme/anna/work/a.ics",
            "https://cal.example.org:8443/dav/calendars/acme/anna/work/a.ics",
            "ftp://cal.example.org/dav/calendars/acme/anna/work/a.ics",
        ] {
            assert_eq!(
                destination(&headers(&[("destination", value)]), &base()).unwrap(),
                Destination::Elsewhere,
                "{value}"
            );
        }
    }

    #[test]
    fn destinations_that_name_nothing_of_ours_are_400() {
        for value in [
            "/elsewhere/a.ics",
            "/nowhere",
            "https://cal.example.org/dav/calendars/acme/anna/work/a/b",
            "https://bad host/dav/calendars/acme/anna/work/a.ics",
            "",
        ] {
            let problem = destination(&headers(&[("destination", value)]), &base()).unwrap_err();
            assert_eq!(problem.code(), ProblemCode::BadRequest, "{value:?}");
        }
        let missing = destination(&HeaderMap::new(), &base()).unwrap_err();
        assert_eq!(missing.code(), ProblemCode::BadRequest);
        // A collection is a destination the header can name; the handler refuses it because it is no object.
        let collection = destination(&headers(&[("destination", "/dav/calendars/acme/anna/work/")]), &base()).unwrap();
        assert!(matches!(collection, Destination::Here(ResourcePath::Collection { .. })));
    }

    fn unreadable(name: &str) -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert(
            axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_bytes(b"\"caf\xe9\"").unwrap(),
        );
        map
    }

    #[test]
    fn a_condition_that_cannot_be_read_fails_instead_of_being_ignored() {
        for name in ["if-match", "if-none-match", "if-schedule-tag-match"] {
            let problem = write_precondition(&unreadable(name)).unwrap_err();
            assert_eq!(problem.code(), ProblemCode::PreconditionFailed, "{name}");
        }
        let tag = etag();
        assert_eq!(
            read_condition(&unreadable("if-match"), &tag),
            Some(StatusCode::PRECONDITION_FAILED)
        );
        assert_eq!(
            read_condition(&unreadable("if-none-match"), &tag),
            Some(StatusCode::PRECONDITION_FAILED)
        );
        assert!(conditional_values(&unreadable("if-match"), "if-match").is_err());
        assert_eq!(
            conditional_values(&headers(&[("if-match", "*"), ("if-match", "\"a\"")]), "if-match").unwrap(),
            ["*", "\"a\""],
            "every occurrence counts"
        );
    }

    #[test]
    fn one_schedule_tag_is_a_condition_and_a_list_is_not_supported() {
        let one = write_precondition(&headers(&[("if-schedule-tag-match", " \"st-1\" ")])).unwrap();
        assert_eq!(one.if_schedule_tag_match.unwrap().as_str(), "\"st-1\"");
        let list = write_precondition(&headers(&[("if-schedule-tag-match", "\"a\", \"b\"")])).unwrap_err();
        assert_eq!(list.code(), ProblemCode::NotImplemented);
        for never in ["*", "W/\"a\"", ""] {
            let problem = write_precondition(&headers(&[("if-schedule-tag-match", never)])).unwrap_err();
            assert_eq!(problem.code(), ProblemCode::PreconditionFailed, "{never:?}");
        }
    }

    #[test]
    fn the_conditions_of_a_copy_are_evaluated_against_its_source() {
        let tag = etag();
        let other = ETag::from_bytes(b"other");
        let schedule = ScheduleTag::parse("\"st-1\"").unwrap();
        let none = WritePrecondition::none();
        assert!(require_conditions(&none, &tag, None).is_ok());
        assert!(require_conditions(&WritePrecondition::if_match(tag.clone()), &tag, None).is_ok());
        assert!(
            require_conditions(
                &WritePrecondition {
                    if_match: Some(IfMatch::Any),
                    ..none.clone()
                },
                &tag,
                None
            )
            .is_ok()
        );
        for failing in [
            WritePrecondition::if_match(other.clone()),
            WritePrecondition::create_only(),
            WritePrecondition {
                if_schedule_tag_match: Some(schedule.clone()),
                ..none.clone()
            },
        ] {
            let problem = require_conditions(&failing, &tag, None).unwrap_err();
            assert_eq!(problem.code(), ProblemCode::PreconditionFailed, "{failing:?}");
        }
        let matching = WritePrecondition {
            if_schedule_tag_match: Some(schedule.clone()),
            ..none
        };
        assert!(require_conditions(&matching, &tag, Some(&schedule)).is_ok());
    }
}

#[cfg(test)]
mod robustness {
    use axum::http::HeaderValue;
    use proptest::prelude::*;

    use super::*;

    proptest! {
        /// Header values come from the internet: whatever they say, reading them is a decision, never a panic.
        #[test]
        fn arbitrary_header_text_is_read_or_refused(text in r"\PC{0,200}") {
            let _ = parse_tag_list(&[text.as_str()]);
            if let Ok(value) = HeaderValue::from_str(&text) {
                let mut headers = HeaderMap::new();
                for name in [
                    "depth",
                    "overwrite",
                    "destination",
                    "prefer",
                    "brief",
                    "if-match",
                    "if-none-match",
                    "if-schedule-tag-match",
                    "schedule-reply",
                    "host",
                ] {
                    headers.insert(name, value.clone());
                }
                let _ = depth(&headers, Depth::Zero);
                let _ = overwrite(&headers);
                let _ = schedule_reply(&headers);
                let _ = minimal_requested(&headers);
                let _ = write_precondition(&headers);
                let _ = destination(&headers, &Origin::new("cal.example.org", Some(443)));
                let _ = read_condition(&headers, &ETag::from_bytes(b"data"));
            }
        }
    }
}
