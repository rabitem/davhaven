//! Typed bodies of the REPORT requests: `calendar-query`, `calendar-multiget`, `sync-collection`,
//! `free-busy-query` and `expand-property`.
//!
//! The filter of a `calendar-query` becomes the `CalendarFilter` of the iCalendar layer; the application validates
//! it against the limits and evaluates it. Names of components, properties and parameters are upper-cased here,
//! because iCalendar names are case-insensitive and the iCalendar layer compares them as written.

use davhaven_app::services::{NS_CALDAV, NS_DAV, PropertyName};
use davhaven_http::problem::EdgeProblem;
use davhaven_ical::filter::{CalendarFilter, Collation, CompFilter, ParamFilter, PropFilter, TextMatch, TimeRange};

use super::requests::{MAX_PROPERTIES, PropRequest, bad_request, invalid_filter, parse_time_range, prop_request};
use super::{Element, MAX_NAME_BYTES, MAX_NAMESPACE_BYTES, is_ncname};

/// How many levels of `DAV:property` an `expand-property` request may have: the property of the principal and the
/// properties asked of the resources it points to. Deeper requests are refused rather than silently cut.
const MAX_EXPAND_DEPTH: usize = 2;

/// A `CALDAV:calendar-query`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarQuery {
    /// The properties of every hit.
    pub select: PropRequest,
    /// The filter.
    pub filter: CalendarFilter,
}

/// Reads a `calendar-query`.
///
/// # Errors
///
/// 400 for a malformed request or a missing filter, 403 `valid-filter` for a filter that cannot be read.
pub fn parse_calendar_query(root: &Element) -> Result<CalendarQuery, EdgeProblem> {
    let select = prop_request(root)?;
    let filter = root
        .child(NS_CALDAV, "filter")
        .ok_or_else(|| bad_request("A calendar-query needs a filter."))?;
    Ok(CalendarQuery {
        select,
        filter: parse_filter(filter)?,
    })
}

/// Reads a `CALDAV:filter`: it holds exactly one `comp-filter` for `VCALENDAR`.
///
/// # Errors
///
/// 403 `valid-filter` when the filter is not well formed.
pub fn parse_filter(filter: &Element) -> Result<CalendarFilter, EdgeProblem> {
    let mut roots = filter.children_named(NS_CALDAV, "comp-filter");
    let (Some(root), None) = (roots.next(), roots.next()) else {
        return Err(invalid_filter("A filter holds exactly one comp-filter."));
    };
    Ok(CalendarFilter {
        root: parse_comp_filter(root)?,
    })
}

fn name_of(element: &Element) -> Result<String, EdgeProblem> {
    element
        .attribute("name")
        .map(|name| name.trim().to_ascii_uppercase())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| invalid_filter("A filter element needs a name."))
}

fn parse_comp_filter(element: &Element) -> Result<CompFilter, EdgeProblem> {
    Ok(CompFilter {
        name: name_of(element)?,
        is_not_defined: element.child(NS_CALDAV, "is-not-defined").is_some(),
        time_range: element
            .child(NS_CALDAV, "time-range")
            .map(parse_time_range)
            .transpose()?,
        prop_filters: element
            .children_named(NS_CALDAV, "prop-filter")
            .map(parse_prop_filter)
            .collect::<Result<_, _>>()?,
        comp_filters: element
            .children_named(NS_CALDAV, "comp-filter")
            .map(parse_comp_filter)
            .collect::<Result<_, _>>()?,
    })
}

fn parse_prop_filter(element: &Element) -> Result<PropFilter, EdgeProblem> {
    Ok(PropFilter {
        name: name_of(element)?,
        is_not_defined: element.child(NS_CALDAV, "is-not-defined").is_some(),
        time_range: element
            .child(NS_CALDAV, "time-range")
            .map(parse_time_range)
            .transpose()?,
        text_match: element
            .child(NS_CALDAV, "text-match")
            .map(parse_text_match)
            .transpose()?,
        param_filters: element
            .children_named(NS_CALDAV, "param-filter")
            .map(parse_param_filter)
            .collect::<Result<_, _>>()?,
    })
}

fn parse_param_filter(element: &Element) -> Result<ParamFilter, EdgeProblem> {
    Ok(ParamFilter {
        name: name_of(element)?,
        is_not_defined: element.child(NS_CALDAV, "is-not-defined").is_some(),
        text_match: element
            .child(NS_CALDAV, "text-match")
            .map(parse_text_match)
            .transpose()?,
    })
}

fn parse_text_match(element: &Element) -> Result<TextMatch, EdgeProblem> {
    let collation = match element.attribute("collation").map(str::trim) {
        None | Some("i;ascii-casemap") => Collation::AsciiCasemap,
        Some("i;octet") => Collation::Octet,
        Some("i;unicode-casemap") => Collation::UnicodeCasemap,
        Some(_) => return Err(invalid_filter("The collation is not supported.")),
    };
    Ok(TextMatch {
        value: element.text(),
        collation,
        negate: element
            .attribute("negate-condition")
            .is_some_and(|value| value.trim() == "yes"),
    })
}

/// A `CALDAV:calendar-multiget`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Multiget {
    /// The properties of every resource.
    pub select: PropRequest,
    /// The requested hrefs exactly as the client wrote them, in request order.
    pub hrefs: Vec<String>,
}

/// Reads a `calendar-multiget`.
///
/// # Errors
///
/// 400 for a malformed property selection.
pub fn parse_multiget(root: &Element) -> Result<Multiget, EdgeProblem> {
    Ok(Multiget {
        select: prop_request(root)?,
        hrefs: root
            .children_named(NS_DAV, "href")
            .map(|href| href.text().trim().to_owned())
            .collect(),
    })
}

/// A `DAV:sync-collection`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncCollection {
    /// The sync token of the client's last answer; empty for the initial synchronization.
    pub token: String,
    /// Whether the client asked for `sync-level: infinite`, which Davhaven does not offer.
    pub infinite: bool,
    /// `DAV:nresults`, the most members the client wants.
    pub limit: Option<u32>,
    /// The properties of every changed member.
    pub select: PropRequest,
}

/// Reads a `sync-collection`.
///
/// # Errors
///
/// 400 when the sync token, the level or the property selection is missing or malformed.
pub fn parse_sync_collection(root: &Element) -> Result<SyncCollection, EdgeProblem> {
    let token = root
        .child(NS_DAV, "sync-token")
        .ok_or_else(|| bad_request("A sync-collection needs a sync-token element."))?
        .text()
        .trim()
        .to_owned();
    let level = root
        .child(NS_DAV, "sync-level")
        .ok_or_else(|| bad_request("A sync-collection needs a sync-level."))?
        .text();
    let infinite = match level.trim() {
        "1" => false,
        "infinite" => true,
        _ => return Err(bad_request("The sync-level must be 1 or infinite.")),
    };
    let limit = root
        .child(NS_DAV, "limit")
        .and_then(|limit| limit.child(NS_DAV, "nresults"))
        .map(|results| {
            results
                .text()
                .trim()
                .parse::<u32>()
                .map_err(|_| bad_request("The nresults of a limit must be a number."))
        })
        .transpose()?;
    if root.child(NS_DAV, "prop").is_none() {
        return Err(bad_request("A sync-collection needs a prop element."));
    }
    Ok(SyncCollection {
        token,
        infinite,
        limit,
        select: prop_request(root)?,
    })
}

/// One `DAV:property` of an `expand-property` request, with the properties requested of the resources it points to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpandedProperty {
    /// The property.
    pub name: PropertyName,
    /// The nested `DAV:property` elements.
    pub children: Vec<ExpandedProperty>,
}

/// Reads an `expand-property` request.
///
/// Properties are read once: a name that is listed twice is one property whose nested properties are merged, so that
/// a body of thousands of identical entries asks for what one entry asks for. A name must be an XML name and a
/// namespace must not be longer than [`MAX_NAMESPACE_BYTES`], because both are written back into the answer.
///
/// # Errors
///
/// 400 when a `property` has no valid name, the nesting is deeper than the server follows (one level of expansion)
/// or a list names more than [`MAX_PROPERTIES`] distinct properties.
pub fn parse_expand_property(root: &Element) -> Result<Vec<ExpandedProperty>, EdgeProblem> {
    parse_expanded(root, 0)
}

fn parse_expanded(parent: &Element, depth: usize) -> Result<Vec<ExpandedProperty>, EdgeProblem> {
    let mut merged: Vec<ExpandedProperty> = Vec::new();
    for property in parent.children_named(NS_DAV, "property") {
        let local = property
            .attribute("name")
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| bad_request("A property element needs a name."))?;
        if local.len() > MAX_NAME_BYTES || !is_ncname(local) {
            return Err(bad_request("The name of a property is not an XML name."));
        }
        let namespace = property.attribute("namespace").map_or(NS_DAV, str::trim);
        if namespace.len() > MAX_NAMESPACE_BYTES {
            return Err(bad_request("The namespace of a property is too long."));
        }
        let children = if depth + 1 < MAX_EXPAND_DEPTH {
            parse_expanded(property, depth + 1)?
        } else if property.children_named(NS_DAV, "property").next().is_some() {
            return Err(bad_request("The expand-property request is nested too deeply."));
        } else {
            Vec::new()
        };
        let name = PropertyName::new(namespace, local);
        add_expanded(&mut merged, ExpandedProperty { name, children })?;
    }
    Ok(merged)
}

/// Adds a property to a list, merging it into the entry of the same name. A list holds at most [`MAX_PROPERTIES`]
/// distinct properties; the element limit of the document bounds how often entries repeat.
fn add_expanded(list: &mut Vec<ExpandedProperty>, property: ExpandedProperty) -> Result<(), EdgeProblem> {
    if let Some(existing) = list.iter_mut().find(|existing| existing.name == property.name) {
        for child in property.children {
            add_expanded(&mut existing.children, child)?;
        }
    } else if list.len() >= MAX_PROPERTIES {
        return Err(bad_request("The request names too many properties."));
    } else {
        list.push(property);
    }
    Ok(())
}

/// Reads the time range of a `CALDAV:free-busy-query`.
///
/// # Errors
///
/// 400 when the request has no `time-range`, 403 `valid-filter` for a bad bound.
pub fn parse_free_busy_query(root: &Element) -> Result<TimeRange, EdgeProblem> {
    root.child(NS_CALDAV, "time-range")
        .map(parse_time_range)
        .transpose()?
        .ok_or_else(|| bad_request("A free-busy-query needs a time-range."))
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use davhaven_http::problem::ProblemCode;

    use super::*;
    use crate::xml::parse;
    use davhaven_domain::DavLimits;

    fn root(xml: &str) -> Element {
        parse(xml.as_bytes(), &DavLimits::default()).unwrap()
    }

    const OPEN: &str = r#"xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav""#;

    #[test]
    fn a_calendar_query_becomes_the_filter_of_the_ical_layer() {
        let query = parse_calendar_query(&root(&format!(
            r#"<C:calendar-query {OPEN}>
                 <D:prop><D:getetag/><C:calendar-data/></D:prop>
                 <C:filter>
                   <C:comp-filter name="vcalendar">
                     <C:comp-filter name="VEVENT">
                       <C:time-range start="20260101T000000Z" end="20260201T000000Z"/>
                       <C:prop-filter name="summary">
                         <C:text-match collation="i;octet" negate-condition="yes">Stand</C:text-match>
                         <C:param-filter name="Language"><C:is-not-defined/></C:param-filter>
                       </C:prop-filter>
                       <C:prop-filter name="STATUS"><C:is-not-defined/></C:prop-filter>
                       <C:comp-filter name="VALARM"/>
                     </C:comp-filter>
                   </C:comp-filter>
                 </C:filter>
               </C:calendar-query>"#
        )))
        .unwrap();
        let PropRequest::Prop(list) = &query.select else {
            panic!("{:?}", query.select)
        };
        assert_eq!(list.names.len(), 2);
        let calendar = &query.filter.root;
        assert_eq!(calendar.name, "VCALENDAR", "names are upper-cased");
        let event = &calendar.comp_filters[0];
        assert_eq!(event.name, "VEVENT");
        assert_eq!(
            event.time_range,
            Some(TimeRange::new(
                Some(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()),
                Some(Utc.with_ymd_and_hms(2026, 2, 1, 0, 0, 0).unwrap())
            ))
        );
        let summary = &event.prop_filters[0];
        assert_eq!(summary.name, "SUMMARY");
        let text = summary.text_match.as_ref().unwrap();
        assert_eq!(
            (text.value.as_str(), text.collation, text.negate),
            ("Stand", Collation::Octet, true)
        );
        assert!(summary.param_filters[0].is_not_defined);
        assert_eq!(summary.param_filters[0].name, "LANGUAGE");
        assert!(event.prop_filters[1].is_not_defined);
        assert_eq!(event.comp_filters[0].name, "VALARM");
    }

    #[test]
    fn text_matches_default_to_the_ascii_casemap() {
        let query = parse_calendar_query(&root(&format!(
            r#"<C:calendar-query {OPEN}><D:prop/><C:filter><C:comp-filter name="VCALENDAR"><C:prop-filter name="UID">
                 <C:text-match>abc</C:text-match></C:prop-filter></C:comp-filter></C:filter></C:calendar-query>"#
        )))
        .unwrap();
        let text = query.filter.root.prop_filters[0].text_match.as_ref().unwrap();
        assert_eq!((text.collation, text.negate), (Collation::AsciiCasemap, false));
    }

    #[test]
    fn filters_the_server_cannot_read_are_valid_filter_failures() {
        for filter in [
            "<C:filter/>",
            r#"<C:filter><C:comp-filter name="VCALENDAR"/><C:comp-filter name="VCALENDAR"/></C:filter>"#,
            r"<C:filter><C:comp-filter/></C:filter>",
            r#"<C:filter><C:comp-filter name="VCALENDAR"><C:time-range start="soon"/></C:comp-filter></C:filter>"#,
            r#"<C:filter><C:comp-filter name="VCALENDAR"><C:prop-filter name="UID"><C:text-match collation="i;klingon">x</C:text-match></C:prop-filter></C:comp-filter></C:filter>"#,
        ] {
            let xml = format!("<C:calendar-query {OPEN}><D:prop/>{filter}</C:calendar-query>");
            assert_eq!(
                parse_calendar_query(&root(&xml)).unwrap_err().code(),
                ProblemCode::InvalidFilter,
                "{filter}"
            );
        }
        let no_filter = format!("<C:calendar-query {OPEN}><D:prop/></C:calendar-query>");
        assert_eq!(
            parse_calendar_query(&root(&no_filter)).unwrap_err().code(),
            ProblemCode::BadRequest
        );
    }

    #[test]
    fn a_multiget_keeps_its_hrefs_as_written() {
        let multiget = parse_multiget(&root(&format!(
            r"<C:calendar-multiget {OPEN}><D:prop><D:getetag/></D:prop>
                 <D:href>/dav/calendars/acme/anna/work/a%20b.ics</D:href>
                 <D:href> /elsewhere </D:href></C:calendar-multiget>"
        )))
        .unwrap();
        assert_eq!(
            multiget.hrefs,
            ["/dav/calendars/acme/anna/work/a%20b.ics", "/elsewhere"]
        );
        assert!(matches!(multiget.select, PropRequest::Prop(_)));
    }

    #[test]
    fn a_sync_request_names_token_level_limit_and_properties() {
        let request = parse_sync_collection(&root(&format!(
            r"<D:sync-collection {OPEN}><D:sync-token>urn:davhaven:sync:x</D:sync-token><D:sync-level>1</D:sync-level>
                 <D:limit><D:nresults>50</D:nresults></D:limit><D:prop><D:getetag/></D:prop></D:sync-collection>"
        )))
        .unwrap();
        assert_eq!(request.token, "urn:davhaven:sync:x");
        assert!(!request.infinite);
        assert_eq!(request.limit, Some(50));
        let initial = parse_sync_collection(&root(&format!(
            r"<D:sync-collection {OPEN}><D:sync-token/><D:sync-level>infinite</D:sync-level><D:prop/></D:sync-collection>"
        )))
        .unwrap();
        assert_eq!(initial.token, "");
        assert!(initial.infinite);
        assert_eq!(initial.limit, None);
    }

    #[test]
    fn incomplete_sync_requests_are_400() {
        for body in [
            "<D:sync-level>1</D:sync-level><D:prop/>",
            "<D:sync-token/><D:prop/>",
            "<D:sync-token/><D:sync-level>2</D:sync-level><D:prop/>",
            "<D:sync-token/><D:sync-level>1</D:sync-level>",
            "<D:sync-token/><D:sync-level>1</D:sync-level><D:limit><D:nresults>many</D:nresults></D:limit><D:prop/>",
        ] {
            let xml = format!("<D:sync-collection {OPEN}>{body}</D:sync-collection>");
            assert_eq!(
                parse_sync_collection(&root(&xml)).unwrap_err().code(),
                ProblemCode::BadRequest,
                "{body}"
            );
        }
    }

    #[test]
    fn expand_property_requests_nest() {
        let properties = parse_expand_property(&root(&format!(
            r#"<D:expand-property {OPEN}>
                 <D:property name="group-membership" namespace="DAV:"><D:property name="displayname"/></D:property>
                 <D:property name="calendar-proxy-read-for" namespace="http://calendarserver.org/ns/"/>
               </D:expand-property>"#
        )))
        .unwrap();
        assert_eq!(properties.len(), 2);
        assert_eq!(properties[0].name, PropertyName::new(NS_DAV, "group-membership"));
        assert_eq!(properties[0].children[0].name, PropertyName::new(NS_DAV, "displayname"));
        assert_eq!(properties[1].name.namespace, "http://calendarserver.org/ns/");
        assert_eq!(properties[1].children.len(), 0);
        let nameless = format!("<D:expand-property {OPEN}><D:property/></D:expand-property>");
        assert_eq!(
            parse_expand_property(&root(&nameless)).unwrap_err().code(),
            ProblemCode::BadRequest
        );
    }

    #[test]
    fn the_nesting_of_expand_property_is_bounded() {
        let mut xml = String::new();
        for _ in 0..=MAX_EXPAND_DEPTH {
            xml.push_str(r#"<D:property name="x">"#);
        }
        for _ in 0..=MAX_EXPAND_DEPTH {
            xml.push_str("</D:property>");
        }
        let body = format!("<D:expand-property {OPEN}>{xml}</D:expand-property>");
        assert_eq!(
            parse_expand_property(&root(&body)).unwrap_err().code(),
            ProblemCode::BadRequest
        );
        // One level of expansion is what the server follows, and exactly that is accepted.
        let one_level = format!(
            r#"<D:expand-property {OPEN}><D:property name="group-membership"><D:property name="displayname"/></D:property></D:expand-property>"#
        );
        assert!(parse_expand_property(&root(&one_level)).is_ok());
        let two_levels = format!(
            r#"<D:expand-property {OPEN}><D:property name="a"><D:property name="b"><D:property name="c"/></D:property></D:property></D:expand-property>"#
        );
        assert_eq!(
            parse_expand_property(&root(&two_levels)).unwrap_err().code(),
            ProblemCode::BadRequest
        );
    }

    #[test]
    fn names_that_are_written_back_must_be_xml_names() {
        // The audit's example: markup in the name of a property that would end up in the answer.
        for name in [
            "x&gt;&lt;D:href&gt;/evil&lt;/D:href&gt;&lt;y",
            "a b",
            "a&quot;b",
            "1a",
            "a:b",
            "a/",
        ] {
            let body = format!(r#"<D:expand-property {OPEN}><D:property name="{name}"/></D:expand-property>"#);
            assert_eq!(
                parse_expand_property(&root(&body)).unwrap_err().code(),
                ProblemCode::BadRequest,
                "{name}"
            );
            let nested = format!(
                r#"<D:expand-property {OPEN}><D:property name="ok"><D:property name="{name}"/></D:property></D:expand-property>"#
            );
            assert_eq!(
                parse_expand_property(&root(&nested)).unwrap_err().code(),
                ProblemCode::BadRequest,
                "nested {name}"
            );
        }
        let long_name = "n".repeat(crate::xml::MAX_NAME_BYTES + 1);
        let long_namespace = "u".repeat(crate::xml::MAX_NAMESPACE_BYTES + 1);
        for body in [
            format!(r#"<D:expand-property {OPEN}><D:property name="{long_name}"/></D:expand-property>"#),
            format!(
                r#"<D:expand-property {OPEN}><D:property name="x" namespace="{long_namespace}"/></D:expand-property>"#
            ),
        ] {
            assert_eq!(
                parse_expand_property(&root(&body)).unwrap_err().code(),
                ProblemCode::BadRequest
            );
        }
    }

    #[test]
    fn a_property_that_is_listed_again_is_one_property() {
        let body = format!(
            r#"<D:expand-property {OPEN}>
                 <D:property name="group-member-set"><D:property name="displayname"/></D:property>
                 <D:property name="group-member-set"><D:property name="calendar-user-address-set" namespace="urn:ietf:params:xml:ns:caldav"/><D:property name="displayname"/></D:property>
                 <D:property name="displayname"/>
                 <D:property name="displayname"/>
               </D:expand-property>"#
        );
        let properties = parse_expand_property(&root(&body)).unwrap();
        assert_eq!(properties.len(), 2);
        assert_eq!(properties[0].name, PropertyName::new(NS_DAV, "group-member-set"));
        let nested: Vec<&str> = properties[0]
            .children
            .iter()
            .map(|child| child.name.local.as_str())
            .collect();
        assert_eq!(
            nested,
            ["displayname", "calendar-user-address-set"],
            "merged, once each"
        );
    }

    #[test]
    fn thousands_of_identical_entries_are_one_entry() {
        let entry = r#"<D:property name="group-member-set"><D:property name="displayname"/></D:property>"#;
        let body = format!("<D:expand-property {OPEN}>{}</D:expand-property>", entry.repeat(3_000));
        let properties = parse_expand_property(&root(&body)).unwrap();
        assert_eq!(properties.len(), 1);
        assert_eq!(properties[0].children.len(), 1);
    }

    #[test]
    fn the_number_of_distinct_properties_is_bounded() {
        let many = crate::xml::repeated(MAX_PROPERTIES + 1, |n| format!(r#"<D:property name="p{n}"/>"#));
        let body = format!("<D:expand-property {OPEN}>{many}</D:expand-property>");
        assert_eq!(
            parse_expand_property(&root(&body)).unwrap_err().code(),
            ProblemCode::BadRequest
        );
    }

    #[test]
    fn a_free_busy_query_needs_its_range() {
        let range = parse_free_busy_query(&root(&format!(
            r#"<C:free-busy-query {OPEN}><C:time-range start="20260101T000000Z" end="20260102T000000Z"/></C:free-busy-query>"#
        )))
        .unwrap();
        assert!(range.start.is_some() && range.end.is_some());
        let none = format!("<C:free-busy-query {OPEN}/>");
        assert_eq!(
            parse_free_busy_query(&root(&none)).unwrap_err().code(),
            ProblemCode::BadRequest
        );
    }
}
