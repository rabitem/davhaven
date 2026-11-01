//! REPORT handlers: `calendar-query`, `calendar-multiget`, `free-busy-query` and `expand-property`
//! (`sync-collection` is in [`crate::sync`]).
//!
//! The body of a REPORT names the report in its root element, so `handle` reads the body first and then picks
//! the handler by the root element and the kind of resource:
//!
//! | Report | Resources | Service call |
//! | --- | --- | --- |
//! | `CALDAV:calendar-query` | calendar collections | `ObjectService::query` with the `CalendarFilter` of the body |
//! | `CALDAV:calendar-multiget` | calendar collections, the scheduling inbox | `ObjectService::multiget`, `SchedulingService::inbox_get_many` |
//! | `CALDAV:free-busy-query` | calendar collections | `SchedulingService::free_busy` |
//! | `DAV:sync-collection` | calendar collections, inbox, notifications | `ObjectService::sync` |
//! | `DAV:expand-property` | principals | `PrincipalService::dav_properties_many` |
//!
//! `calendar-multiget` of the scheduling inbox ([`crate::scheduling`]) and the principal search reports
//! (`DAV:principal-property-search`, `DAV:principal-search-property-set`, `CS:calendarserver-principal-search`,
//! [`crate::principals_search`]) are served by the collaboration modules; every other report answers 403
//! `DAV:supported-report`. The `Depth` header of a report is not evaluated: `calendar-query` and
//! `calendar-multiget` always cover the members of the collection (the depth clients send is 1).
//!
//! Answers are `207 Multi-Status` documents with the responses sorted by `href`. The data of `calendar-data` comes
//! from the services already reduced to what the request selected (components, properties, expansion), so the
//! handlers only write it. An answer stops at `max_response_bytes` with a 507 entry for the request URI;
//! `calendar-multiget` reads its objects in steps so that it never holds more than one step of calendar data
//! besides the document.
//!
//! # Free-busy
//!
//! The answer of `free-busy-query` is a `VCALENDAR` with one `VFREEBUSY` that lists the merged busy periods,
//! rendered by the iCalendar layer. The DAV layer has no clock and no id generator (R9): the `DTSTAMP` is the
//! moment the application made the answer (`FreeBusyResult::generated_at`, from its `Clock`), and the `UID` is
//! derived from the resource and the range, so a repeated query names the same `VFREEBUSY` again.

use std::collections::{HashMap, HashSet};

use axum::body::Body;
use axum::http::StatusCode;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::response::Response;
use davhaven_app::services::{
    FreeBusyRequest, FreeBusyTarget, MultigetEntry, NS_CALDAV, NS_CALENDARSERVER, NS_DAV, ObjectFilter, ObjectView,
    PrincipalProps,
};
use davhaven_domain::{ComponentKind, ErrorKind, ResourcePath, Uid};
use davhaven_http::problem::{EdgeProblem, ProblemCode};
use davhaven_ical::filter::{CalendarFilter, TimeRange};
use davhaven_ical::freebusy::render_collection_freebusy;
use uuid::Uuid;

use crate::discovery::current_principal;
use crate::methods::{Call, data_spec, minimal_requested, multistatus_response, set_header};
use crate::props::{Env, Subject, linked_principals, property_element, propstats, render};
use crate::xml::Element;
use crate::xml::reports::{
    ExpandedProperty, parse_calendar_query, parse_expand_property, parse_free_busy_query, parse_multiget,
};
use crate::xml::requests::{PropList, PropRequest, format_utc, invalid_filter};
use crate::xml::write::{Multistatus, Prefixes, Propstat, response_element};
use crate::{principals_search, scheduling, sync};

/// How many objects a `calendar-multiget` that wants their data reads in one call to the service. The step keeps
/// the calendar data held at once small (up to 1 MiB per object) however many hrefs a request names.
pub(crate) const MULTIGET_STEP: usize = 100;

/// Serves a REPORT.
pub(crate) async fn handle(call: &Call<'_>, body: Body) -> Result<Response, EdgeProblem> {
    let bytes = call.xml_body(body).await?;
    let root = call.parse_xml(bytes).await?;
    match (&*root.namespace, root.local.as_str(), call.resource) {
        (NS_CALDAV, "calendar-query", ResourcePath::Collection { .. }) => calendar_query(call, &root).await,
        (NS_CALDAV, "calendar-multiget", ResourcePath::Collection { .. }) => multiget(call, &root).await,
        (NS_CALDAV, "calendar-multiget", ResourcePath::Inbox { .. }) => scheduling::inbox_multiget(call, &root).await,
        (NS_CALDAV, "free-busy-query", ResourcePath::Collection { .. }) => free_busy(call, &root).await,
        (
            NS_DAV,
            "sync-collection",
            ResourcePath::Collection { .. } | ResourcePath::Inbox { .. } | ResourcePath::Notifications { .. },
        ) => sync::report(call, &root).await,
        (NS_DAV, "expand-property", ResourcePath::Principal { .. }) => expand_property(call, &root).await,
        (NS_DAV, "principal-property-search" | "principal-search-property-set", _)
        | (NS_CALENDARSERVER, "calendarserver-principal-search", _) => principals_search::search(call, &root).await,
        _ => Err(EdgeProblem::new(ProblemCode::UnsupportedReport)),
    }
}

/// The prefixes of the namespaces a request names.
pub(crate) fn prefixes_for(call: &Call<'_>, request: &PropRequest) -> Prefixes {
    Prefixes::of(
        request.names().iter().map(|name| name.namespace.as_str()),
        usize::try_from(call.limits().dav.max_xml_namespaces).unwrap_or(usize::MAX),
    )
}

/// Writes the objects of a query as a multistatus, sorted by href, and cuts the answer off at the budget.
fn object_multistatus(
    call: &Call<'_>,
    env: &Env<'_>,
    hits: Vec<ObjectView>,
    select: &PropRequest,
    minimal: bool,
) -> Response {
    let mut keyed: Vec<(String, ObjectView)> = hits.into_iter().map(|hit| (hit.path.format(), hit)).collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    let budget = call.response_budget();
    let mut multistatus = Multistatus::with_prefixes(env.prefixes);
    let mut cut = false;
    for (href, hit) in keyed {
        if multistatus.len() > budget {
            cut = true;
            break;
        }
        let subject = Subject::Object(hit);
        multistatus.response(&href, &propstats(env, &subject, select, minimal));
    }
    if cut {
        call.truncated(&mut multistatus);
    }
    multistatus_response(multistatus.finish(), minimal)
}

/// The component type every match must have, when the filter says so: a single `VEVENT`, `VTODO` or `VJOURNAL`
/// `comp-filter` that is not negated. It narrows the candidates of the store; the exact evaluation stays with
/// the filter.
fn component_hint(filter: &CalendarFilter) -> Option<ComponentKind> {
    let mut children = filter.root.comp_filters.iter();
    let (Some(only), None) = (children.next(), children.next()) else {
        return None;
    };
    if only.is_not_defined {
        return None;
    }
    ComponentKind::from_ical(&only.name)
}

async fn calendar_query(call: &Call<'_>, root: &Element) -> Result<Response, EdgeProblem> {
    let query = parse_calendar_query(root)?;
    let minimal = minimal_requested(call.headers());
    let current = current_principal(call, &query.select).await?;
    let prefixes = prefixes_for(call, &query.select);
    let env = Env {
        services: call.services(),
        current: current.as_ref(),
        prefixes: &prefixes,
    };
    let filter = ObjectFilter {
        component: component_hint(&query.filter),
        calendar_filter: Some(query.filter),
        ..ObjectFilter::default()
    };
    let hits = call
        .services()
        .objects
        .query(call.ctx, call.resource, filter, data_spec(&query.select))
        .await?;
    Ok(object_multistatus(call, &env, hits, &query.select, minimal))
}

/// One href of a multiget: the resource it names, or the text of an href that names no resource of the namespace.
pub(crate) enum Wanted {
    Resource(ResourcePath),
    Garbage,
}

/// The hrefs of a multiget without repeats, sorted, each with the href it is answered with.
///
/// Two spellings of one resource (`a%40b.ics`, `a@b.ics`, an absolute URL) are one entry, answered with the
/// canonical path of the resource (`ResourcePath::format`); an href that names nothing of the namespace is answered
/// as the client wrote it.
pub(crate) fn wanted_hrefs(hrefs: &[String]) -> Vec<(String, Wanted)> {
    let mut seen_paths: HashSet<ResourcePath> = HashSet::new();
    let mut seen_text: HashSet<&str> = HashSet::new();
    let mut wanted: Vec<(String, Wanted)> = Vec::new();
    for href in hrefs {
        match ResourcePath::from_href(href) {
            Ok(path) => {
                if seen_paths.insert(path.clone()) {
                    wanted.push((path.format(), Wanted::Resource(path)));
                }
            }
            Err(_) => {
                if seen_text.insert(href.as_str()) {
                    wanted.push((href.clone(), Wanted::Garbage));
                }
            }
        }
    }
    wanted.sort_by(|a, b| a.0.cmp(&b.0));
    wanted
}

async fn multiget(call: &Call<'_>, root: &Element) -> Result<Response, EdgeProblem> {
    let request = parse_multiget(root)?;
    let max = usize::try_from(call.limits().dav.max_multiget_hrefs).unwrap_or(usize::MAX);
    if request.hrefs.len() > max {
        return Err(EdgeProblem::new(ProblemCode::TooManyHrefs));
    }
    let wanted = wanted_hrefs(&request.hrefs);
    if !wanted.iter().any(|(_, entry)| matches!(entry, Wanted::Resource(_))) {
        // Nothing that could be found: the services are not asked, so the collection has to be checked here.
        call.services()
            .calendars
            .get_collection(call.ctx, call.resource)
            .await?;
    }
    let minimal = minimal_requested(call.headers());
    let current = current_principal(call, &request.select).await?;
    let prefixes = prefixes_for(call, &request.select);
    let env = Env {
        services: call.services(),
        current: current.as_ref(),
        prefixes: &prefixes,
    };
    let spec = data_spec(&request.select);
    let step = if spec.include_data { MULTIGET_STEP } else { usize::MAX };
    let budget = call.response_budget();
    let mut multistatus = Multistatus::with_prefixes(&prefixes);
    let mut cut = false;
    for chunk in wanted.chunks(step) {
        if multistatus.len() > budget {
            cut = true;
            break;
        }
        let paths: Vec<ResourcePath> = chunk
            .iter()
            .filter_map(|(_, entry)| match entry {
                Wanted::Resource(path) => Some(path.clone()),
                Wanted::Garbage => None,
            })
            .collect();
        // The answers are matched to the hrefs by resource, not by position: a service may order or merge them.
        let mut entries: HashMap<ResourcePath, MultigetEntry> = HashMap::new();
        if !paths.is_empty() {
            let answers = match call
                .services()
                .objects
                .multiget(call.ctx, call.resource, paths, spec.clone())
                .await
            {
                Ok(answers) => answers,
                Err(error) if names_too_many(&error) => return Err(EdgeProblem::new(ProblemCode::TooManyHrefs)),
                Err(error) => return Err(EdgeProblem::from(error)),
            };
            for entry in answers {
                let key = match &entry {
                    MultigetEntry::Found(view) => view.path.clone(),
                    MultigetEntry::Missing(path) => path.clone(),
                };
                entries.insert(key, entry);
            }
        }
        for (href, entry) in chunk {
            let found = match entry {
                Wanted::Resource(path) => entries.remove(path),
                Wanted::Garbage => None,
            };
            match found {
                Some(MultigetEntry::Found(view)) => {
                    let subject = Subject::Object(view);
                    multistatus.response(href, &propstats(&env, &subject, &request.select, minimal));
                }
                Some(MultigetEntry::Missing(_)) | None => {
                    multistatus.status_response(href, 404, None);
                }
            }
        }
    }
    if cut {
        call.truncated(&mut multistatus);
    }
    Ok(multistatus_response(multistatus.finish(), minimal))
}

/// Whether the application refuses a multiget for naming too many resources. The limit of hrefs is one condition with
/// one status: the application reports it with the precondition `number-of-matches-within-limits`, and the answer is
/// the one of the limit the DAV layer checks itself (403, PLAN 2.15), not the 507 of a query that matches too much.
fn names_too_many(error: &davhaven_app::AppError) -> bool {
    error.kind() == ErrorKind::Invalid
        && matches!(
            error.precondition(),
            Some(davhaven_domain::Precondition::NumberOfMatchesWithinLimits)
        )
}

async fn free_busy(call: &Call<'_>, root: &Element) -> Result<Response, EdgeProblem> {
    let range = parse_free_busy_query(root)?;
    let (Some(start), Some(end)) = (range.start, range.end) else {
        return Err(invalid_filter("A free-busy-query needs a start and an end."));
    };
    let range = TimeRange::new(Some(start), Some(end));
    let request = FreeBusyRequest {
        target: FreeBusyTarget::Collection(call.resource.clone()),
        range,
    };
    let result = call.services().scheduling.free_busy(call.ctx, request).await?;
    let stamped_at = result.generated_at;
    let periods = result
        .entries
        .into_iter()
        .next()
        .map(|entry| entry.periods)
        .unwrap_or_default();
    let name = format!("{}|{}|{}", call.resource.format(), format_utc(start), format_utc(end));
    let uid = Uid::from_uuid(Uuid::new_v5(&Uuid::NAMESPACE_URL, name.as_bytes()));
    let text = render_collection_freebusy(&range, &periods, stamped_at, &uid)
        .map_err(|_| EdgeProblem::new(ProblemCode::Internal))?;
    let mut response = Response::new(Body::from(text));
    *response.status_mut() = StatusCode::OK;
    set_header(&mut response, CONTENT_TYPE, "text/calendar; charset=utf-8");
    set_header(&mut response, CACHE_CONTROL, "no-cache");
    Ok(response)
}

/// Every namespace the properties of an `expand-property` request name, nested ones included.
fn expanded_namespaces<'a>(properties: &'a [ExpandedProperty], out: &mut Vec<&'a str>) {
    for property in properties {
        out.push(property.name.namespace.as_str());
        expanded_namespaces(&property.children, out);
    }
}

/// Expands the principals a property points to: one `D:response` per principal with the nested properties. A
/// principal that was not found is left out.
fn expand(
    env: &Env<'_>,
    paths: &[ResourcePath],
    loaded: &HashMap<ResourcePath, PrincipalProps>,
    children: &[ExpandedProperty],
) -> String {
    let nested = PropRequest::Prop(PropList {
        names: children.iter().map(|child| child.name.clone()).collect(),
        calendar_data: None,
    });
    let mut out = String::new();
    for path in paths {
        if let Some(principal) = loaded.get(path) {
            let subject = Subject::Principal(principal.clone());
            out.push_str(&response_element(
                &path.format(),
                &propstats(env, &subject, &nested, false),
            ));
        }
    }
    out
}

async fn expand_property(call: &Call<'_>, root: &Element) -> Result<Response, EdgeProblem> {
    let requested = parse_expand_property(root)?;
    let principal = call
        .services()
        .principals
        .dav_properties(call.ctx, call.resource)
        .await?;
    let names = PropRequest::Prop(PropList {
        names: requested.iter().map(|property| property.name.clone()).collect(),
        calendar_data: None,
    });
    let current = current_principal(call, &names).await?;
    let mut namespaces = Vec::new();
    expanded_namespaces(&requested, &mut namespaces);
    let prefixes = Prefixes::of(
        namespaces,
        usize::try_from(call.limits().dav.max_xml_namespaces).unwrap_or(usize::MAX),
    );
    let env = Env {
        services: call.services(),
        current: current.as_ref(),
        prefixes: &prefixes,
    };
    let subject = Subject::Principal(principal);
    // The principals the properties point to, each loaded once for the whole request, and no more than a multiget
    // may name: a request cannot make the server read the members of a large group again and again.
    let max = usize::try_from(call.limits().dav.max_multiget_hrefs).unwrap_or(usize::MAX);
    let mut linked: Vec<Option<Vec<ResourcePath>>> = Vec::with_capacity(requested.len());
    let mut wanted: Vec<ResourcePath> = Vec::new();
    let mut seen: HashSet<ResourcePath> = HashSet::new();
    let mut total = 0usize;
    for property in &requested {
        let paths = if property.children.is_empty() {
            None
        } else {
            linked_principals(&subject, &property.name)
        };
        if let Some(paths) = &paths {
            total = total.saturating_add(paths.len());
            if total > max {
                return Err(EdgeProblem::new(ProblemCode::TooManyHrefs));
            }
            wanted.extend(paths.iter().filter(|path| seen.insert((*path).clone())).cloned());
        }
        linked.push(paths);
    }
    let loaded: HashMap<ResourcePath, PrincipalProps> = if wanted.is_empty() {
        HashMap::new()
    } else {
        call.services()
            .principals
            .dav_properties_many(call.ctx, &wanted)
            .await?
            .into_iter()
            .map(|principal| (principal.path.clone(), principal))
            .collect()
    };
    let mut found = String::new();
    let mut missing = String::new();
    for (property, paths) in requested.iter().zip(&linked) {
        let Some(value) = render(&env, &subject, &property.name) else {
            missing.push_str(&property_element(&prefixes, &property.name, None));
            continue;
        };
        let value = match paths {
            Some(paths) => expand(&env, paths, &loaded, &property.children),
            None => value,
        };
        found.push_str(&property_element(&prefixes, &property.name, Some(&value)));
    }
    let mut statuses = Vec::new();
    if !found.is_empty() || missing.is_empty() {
        statuses.push(Propstat::found(found));
    }
    if !missing.is_empty() {
        statuses.push(Propstat {
            status: 404,
            props: missing,
            error: None,
        });
    }
    let mut multistatus = Multistatus::with_prefixes(&prefixes);
    multistatus.response(&call.resource.format(), &statuses);
    Ok(multistatus_response(multistatus.finish(), false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::parse;
    use crate::xml::reports::parse_calendar_query;

    fn query(filter: &str) -> CalendarFilter {
        let xml = format!(
            r#"<C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><D:prop/><C:filter>{filter}</C:filter></C:calendar-query>"#
        );
        let root = parse(xml.as_bytes(), &davhaven_domain::DavLimits::default()).unwrap();
        parse_calendar_query(&root).unwrap().filter
    }

    #[test]
    fn a_single_component_filter_narrows_the_candidates() {
        let event = query(r#"<C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT"/></C:comp-filter>"#);
        assert_eq!(component_hint(&event), Some(ComponentKind::Event));
        let todo = query(r#"<C:comp-filter name="VCALENDAR"><C:comp-filter name="vtodo"/></C:comp-filter>"#);
        assert_eq!(component_hint(&todo), Some(ComponentKind::Todo));
    }

    #[test]
    fn other_filters_leave_the_candidates_alone() {
        for filter in [
            r#"<C:comp-filter name="VCALENDAR"/>"#,
            r#"<C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT"><C:is-not-defined/></C:comp-filter></C:comp-filter>"#,
            r#"<C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT"/><C:comp-filter name="VTODO"/></C:comp-filter>"#,
            r#"<C:comp-filter name="VCALENDAR"><C:comp-filter name="VTIMEZONE"/></C:comp-filter>"#,
        ] {
            assert_eq!(component_hint(&query(filter)), None, "{filter}");
        }
    }

    fn hrefs(texts: &[&str]) -> Vec<String> {
        texts.iter().map(|text| (*text).to_owned()).collect()
    }

    #[test]
    fn two_spellings_of_one_resource_are_one_entry_with_the_canonical_href() {
        let wanted = wanted_hrefs(&hrefs(&[
            "/dav/calendars/acme/anna/work/a%40b.ics",
            "/dav/calendars/acme/anna/work/a@b.ics",
            "https://cal.example.test/dav/calendars/acme/anna/work/a%40b.ics",
            "/dav/calendars/acme/anna/work/%73tandup.ics",
            "/dav/calendars/acme/anna/work/standup.ics",
        ]));
        let shown: Vec<&str> = wanted.iter().map(|(href, _)| href.as_str()).collect();
        assert_eq!(
            shown,
            [
                "/dav/calendars/acme/anna/work/a@b.ics",
                "/dav/calendars/acme/anna/work/standup.ics"
            ],
            "sorted, each resource once"
        );
        assert!(wanted.iter().all(|(_, entry)| matches!(entry, Wanted::Resource(_))));
    }

    #[test]
    fn hrefs_that_name_nothing_are_kept_as_written_and_once() {
        let wanted = wanted_hrefs(&hrefs(&["not a path", "/elsewhere", "not a path"]));
        let shown: Vec<&str> = wanted.iter().map(|(href, _)| href.as_str()).collect();
        assert_eq!(shown, ["/elsewhere", "not a path"]);
        assert!(wanted.iter().all(|(_, entry)| matches!(entry, Wanted::Garbage)));
    }

    #[test]
    fn the_limit_of_hrefs_is_recognized_whoever_finds_it() {
        use davhaven_app::AppError;
        use davhaven_domain::Precondition;
        let application =
            AppError::new(ErrorKind::Invalid).with_precondition(Precondition::NumberOfMatchesWithinLimits);
        assert!(names_too_many(&application));
        let other = AppError::new(ErrorKind::Invalid).with_precondition(Precondition::ValidFilter);
        assert!(!names_too_many(&other));
        assert!(!names_too_many(&AppError::not_found()));
        assert!(!names_too_many(&AppError::new(ErrorKind::Invalid)));
    }

    #[test]
    fn namespaces_of_nested_expanded_properties_are_collected() {
        use davhaven_app::services::PropertyName;
        let nested = ExpandedProperty {
            name: PropertyName::new("urn:a", "outer"),
            children: vec![ExpandedProperty {
                name: PropertyName::new("urn:b", "inner"),
                children: Vec::new(),
            }],
        };
        let mut found = Vec::new();
        let list = [nested];
        expanded_namespaces(&list, &mut found);
        assert_eq!(found, ["urn:a", "urn:b"]);
    }
}
