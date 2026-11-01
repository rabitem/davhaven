//! Typed requests of the methods with an XML body: PROPFIND, PROPPATCH, MKCALENDAR and extended MKCOL, plus the
//! building blocks the REPORT bodies share: property lists, `calendar-data` selections and time ranges.
//!
//! Parsing happens in two steps: [`parse`] turns the body into an [`Element`] tree under the limits
//! of PLAN 2.15, and the functions here read the tree into typed values. Whatever the body gets wrong is an
//! [`EdgeProblem`] that the handler returns as it is: 400 for malformed requests, 403 with the CalDAV precondition
//! element for filters and calendar data the server cannot evaluate.

use std::collections::HashSet;

use chrono::{DateTime, NaiveDateTime, Utc};
use davhaven_app::services::{NS_CALDAV, NS_DAV, PropertyName};
use davhaven_domain::DavLimits;
use davhaven_http::problem::{EdgeProblem, ProblemCode};
use davhaven_ical::filter::TimeRange;
use davhaven_ical::projection::{ComponentSelection, Projection, PropSelection};

use super::{Element, XmlError, parse};

/// The most distinct properties one request may name (a property list, the changes of a `PROPPATCH`, the
/// properties a collection is created with). Clients ask for a few dozen; the answer to a request repeats every
/// property for every resource it covers.
pub const MAX_PROPERTIES: usize = 1_000;

fn too_many_properties() -> EdgeProblem {
    bad_request("The request names too many properties.")
}

/// Whether a body has nothing but white space: a request without a body.
pub fn is_blank(body: &[u8]) -> bool {
    body.iter().all(u8::is_ascii_whitespace)
}

impl From<XmlError> for EdgeProblem {
    fn from(error: XmlError) -> Self {
        Self::new(ProblemCode::BadRequest).with_detail(error.describe())
    }
}

/// A 400 with a client-safe explanation.
pub fn bad_request(detail: &'static str) -> EdgeProblem {
    EdgeProblem::new(ProblemCode::BadRequest).with_detail(detail)
}

/// The 403 `CALDAV:valid-filter` of a filter the server cannot evaluate.
pub fn invalid_filter(detail: &'static str) -> EdgeProblem {
    EdgeProblem::new(ProblemCode::InvalidFilter).with_detail(detail)
}

/// The properties a request names, and what it asks for of `calendar-data`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PropList {
    /// The requested properties in request order, without duplicates.
    pub names: Vec<PropertyName>,
    /// The selection of the `CALDAV:calendar-data` property when it was requested.
    pub calendar_data: Option<Projection>,
}

/// Which properties a PROPFIND or REPORT asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropRequest {
    /// `DAV:allprop`, with the properties of `DAV:include`.
    AllProp(PropList),
    /// `DAV:propname`: the names of the properties, no values.
    PropName,
    /// `DAV:prop`: the listed properties.
    Prop(PropList),
}

impl PropRequest {
    /// The properties the request names: those of `DAV:prop`, those of `DAV:include`, none for `propname`.
    pub fn names(&self) -> &[PropertyName] {
        match self {
            Self::AllProp(list) | Self::Prop(list) => &list.names,
            Self::PropName => &[],
        }
    }
}

/// Reads a `DAV:prop` element: the names of its children and, for `calendar-data`, its selection.
///
/// # Errors
///
/// 400 for a malformed `calendar-data` selection or more than [`MAX_PROPERTIES`] distinct properties, 403
/// `supported-calendar-data` for another media type.
pub fn parse_prop(prop: &Element) -> Result<PropList, EdgeProblem> {
    let mut list = PropList::default();
    let mut seen: HashSet<PropertyName> = HashSet::new();
    for child in prop.elements() {
        if child.is(NS_CALDAV, "calendar-data") {
            list.calendar_data = Some(parse_calendar_data(child)?);
        }
        let name = PropertyName::new(&child.namespace, &child.local);
        if seen.insert(name.clone()) {
            if list.names.len() >= MAX_PROPERTIES {
                return Err(too_many_properties());
            }
            list.names.push(name);
        }
    }
    Ok(list)
}

/// Finds the property selection of a request element: `DAV:prop`, `DAV:allprop` (with `DAV:include`) or
/// `DAV:propname`. A request without one asks for everything.
///
/// # Errors
///
/// 400 when the request names more than one kind of selection or the selection is malformed.
pub fn prop_request(root: &Element) -> Result<PropRequest, EdgeProblem> {
    let mut found: Option<PropRequest> = None;
    for child in root.elements() {
        let next = if child.is(NS_DAV, "prop") {
            PropRequest::Prop(parse_prop(child)?)
        } else if child.is(NS_DAV, "propname") {
            PropRequest::PropName
        } else if child.is(NS_DAV, "allprop") {
            let include = root
                .child(NS_DAV, "include")
                .map(parse_prop)
                .transpose()?
                .unwrap_or_default();
            PropRequest::AllProp(include)
        } else {
            continue;
        };
        if found.replace(next).is_some() {
            return Err(bad_request("Name one of prop, allprop and propname."));
        }
    }
    Ok(found.unwrap_or_else(|| PropRequest::AllProp(PropList::default())))
}

/// Reads the body of a PROPFIND: a `DAV:propfind` with one selection. An empty body means `allprop`.
///
/// # Errors
///
/// 400 for XML that is malformed or over the limits and for a body that is not a `DAV:propfind`.
pub fn parse_propfind(body: &[u8], limits: &DavLimits) -> Result<PropRequest, EdgeProblem> {
    if is_blank(body) {
        return Ok(PropRequest::AllProp(PropList::default()));
    }
    parse_propfind_root(&parse(body, limits)?)
}

/// Reads the root element of a PROPFIND body (see [`parse_propfind`]; the handlers read the document through
/// `Call::parse_xml`).
///
/// # Errors
///
/// 400 when the element is not a `DAV:propfind` or its selection is malformed.
pub fn parse_propfind_root(root: &Element) -> Result<PropRequest, EdgeProblem> {
    if !root.is(NS_DAV, "propfind") {
        return Err(bad_request("The body must be a DAV:propfind element."));
    }
    prop_request(root)
}

/// One instruction of a PROPPATCH.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Update {
    /// `DAV:set`: the property with its new value (the property element itself).
    Set(PropertyName, Element),
    /// `DAV:remove`.
    Remove(PropertyName),
}

impl Update {
    /// The property the instruction is about.
    pub const fn name(&self) -> &PropertyName {
        match self {
            Self::Set(name, _) | Self::Remove(name) => name,
        }
    }
}

/// Reads the instructions of a `DAV:propertyupdate` in document order.
///
/// # Errors
///
/// 400 when the element is not a `propertyupdate`, has no instruction, an instruction has no `DAV:prop`, or the
/// request changes more than [`MAX_PROPERTIES`] properties.
pub fn parse_propertyupdate(root: &Element) -> Result<Vec<Update>, EdgeProblem> {
    if !root.is(NS_DAV, "propertyupdate") {
        return Err(bad_request("The body must be a DAV:propertyupdate element."));
    }
    let mut updates = Vec::new();
    for instruction in root.elements() {
        let remove = if instruction.is(NS_DAV, "set") {
            false
        } else if instruction.is(NS_DAV, "remove") {
            true
        } else {
            continue;
        };
        let prop = instruction
            .child(NS_DAV, "prop")
            .ok_or_else(|| bad_request("A set or remove needs a DAV:prop element."))?;
        for property in prop.elements() {
            if updates.len() >= MAX_PROPERTIES {
                return Err(too_many_properties());
            }
            let name = PropertyName::new(&property.namespace, &property.local);
            updates.push(if remove {
                Update::Remove(name)
            } else {
                Update::Set(name, property.clone())
            });
        }
    }
    if updates.is_empty() {
        return Err(bad_request("The propertyupdate changes no property."));
    }
    Ok(updates)
}

/// The two ways to create a calendar collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MakeKind {
    /// `MKCALENDAR` (RFC 4791).
    MkCalendar,
    /// `MKCOL` with a body (RFC 5689).
    ExtendedMkcol,
}

/// The properties a collection is created with.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MakeCollection {
    /// The properties of `DAV:set` in document order.
    pub sets: Vec<(PropertyName, Element)>,
}

/// Reads the body of MKCALENDAR (`CALDAV:mkcalendar`) or extended MKCOL (`DAV:mkcol`); an empty body creates the
/// collection with defaults.
///
/// # Errors
///
/// 400 for XML that is malformed or over the limits, for another root element, for `DAV:remove` and for more than
/// [`MAX_PROPERTIES`] properties.
pub fn parse_make_collection(body: &[u8], limits: &DavLimits, kind: MakeKind) -> Result<MakeCollection, EdgeProblem> {
    if is_blank(body) {
        return Ok(MakeCollection::default());
    }
    parse_make_collection_root(&parse(body, limits)?, kind)
}

/// Reads the root element of a MKCALENDAR or MKCOL body (see [`parse_make_collection`]; the handlers read the
/// document through `Call::parse_xml`).
///
/// # Errors
///
/// As [`parse_make_collection`], without the errors of the XML reader.
pub fn parse_make_collection_root(root: &Element, kind: MakeKind) -> Result<MakeCollection, EdgeProblem> {
    let expected = match kind {
        MakeKind::MkCalendar => root.is(NS_CALDAV, "mkcalendar"),
        MakeKind::ExtendedMkcol => root.is(NS_DAV, "mkcol"),
    };
    if !expected {
        return Err(bad_request("The body does not match the method."));
    }
    let mut sets = Vec::new();
    for instruction in root.elements() {
        if instruction.is(NS_DAV, "remove") {
            return Err(bad_request("A collection is created with DAV:set only."));
        }
        if !instruction.is(NS_DAV, "set") {
            continue;
        }
        let prop = instruction
            .child(NS_DAV, "prop")
            .ok_or_else(|| bad_request("A set needs a DAV:prop element."))?;
        for property in prop.elements() {
            if sets.len() >= MAX_PROPERTIES {
                return Err(too_many_properties());
            }
            sets.push((
                PropertyName::new(&property.namespace, &property.local),
                property.clone(),
            ));
        }
    }
    Ok(MakeCollection { sets })
}

/// Reads an iCalendar UTC date-time (`20260101T093000Z`).
pub fn parse_utc(text: &str) -> Option<DateTime<Utc>> {
    let bytes = text.as_bytes();
    let shaped = bytes.len() == 16
        && bytes.get(8) == Some(&b'T')
        && bytes.get(15) == Some(&b'Z')
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 8 | 15) || byte.is_ascii_digit());
    if !shaped {
        return None;
    }
    NaiveDateTime::parse_from_str(text.get(..15)?, "%Y%m%dT%H%M%S")
        .ok()
        .map(|naive| naive.and_utc())
}

/// Formats an instant as an iCalendar UTC date-time.
pub fn format_utc(instant: DateTime<Utc>) -> String {
    instant.format("%Y%m%dT%H%M%SZ").to_string()
}

/// Reads the `start` and `end` attributes of a `time-range`, `expand` or `limit-*` element.
///
/// # Errors
///
/// 403 `valid-filter` for a value that is not a UTC date-time.
pub fn parse_time_range(element: &Element) -> Result<TimeRange, EdgeProblem> {
    let bound = |name: &str| -> Result<Option<DateTime<Utc>>, EdgeProblem> {
        element.attribute(name).map_or(Ok(None), |text| {
            parse_utc(text.trim())
                .map(Some)
                .ok_or_else(|| invalid_filter("A time range bound must be a UTC date-time."))
        })
    };
    Ok(TimeRange::new(bound("start")?, bound("end")?))
}

/// Reads a `CALDAV:calendar-data` element: the component and property selection, `expand`,
/// `limit-recurrence-set` and `limit-freebusy-set`.
///
/// # Errors
///
/// 403 `supported-calendar-data` for a media type other than `text/calendar` version 2.0, 400 for a selection
/// without a component name or with two root selections, 403 `valid-filter` for a bad time range.
pub fn parse_calendar_data(element: &Element) -> Result<Projection, EdgeProblem> {
    let unsupported = element
        .attribute("content-type")
        .is_some_and(|value| !value.trim().eq_ignore_ascii_case("text/calendar"))
        || element.attribute("version").is_some_and(|value| value.trim() != "2.0");
    if unsupported {
        return Err(EdgeProblem::new(ProblemCode::UnsupportedCalendarData));
    }
    let mut projection = Projection::default();
    for child in element.elements().filter(|child| child.namespace == NS_CALDAV) {
        match child.local.as_str() {
            "comp" => {
                if projection.select.replace(parse_component_selection(child)?).is_some() {
                    return Err(bad_request("A calendar-data selection has one root component."));
                }
            }
            "expand" => projection.expand = Some(parse_time_range(child)?),
            "limit-recurrence-set" => projection.limit_recurrence_set = Some(parse_time_range(child)?),
            "limit-freebusy-set" => projection.limit_freebusy_set = Some(parse_time_range(child)?),
            _ => {}
        }
    }
    Ok(projection)
}

fn parse_component_selection(element: &Element) -> Result<ComponentSelection, EdgeProblem> {
    let name = element
        .attribute("name")
        .map(|name| name.trim().to_ascii_uppercase())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| bad_request("A comp element needs a name."))?;
    let mut selection = ComponentSelection {
        name,
        ..ComponentSelection::default()
    };
    for child in element.elements().filter(|child| child.namespace == NS_CALDAV) {
        match child.local.as_str() {
            "allprop" => selection.all_props = true,
            "prop" => {
                let name = child
                    .attribute("name")
                    .map(|name| name.trim().to_ascii_uppercase())
                    .filter(|name| !name.is_empty())
                    .ok_or_else(|| bad_request("A prop element needs a name."))?;
                selection.props.push(PropSelection {
                    name,
                    no_value: child.attribute("novalue").is_some_and(|value| value.trim() == "yes"),
                });
            }
            "allcomp" => selection.all_comps = true,
            "comp" => selection.comps.push(parse_component_selection(child)?),
            _ => {}
        }
    }
    Ok(selection)
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn limits() -> DavLimits {
        DavLimits::default()
    }

    fn root(xml: &str) -> Element {
        parse(xml.as_bytes(), &limits()).unwrap()
    }

    fn propfind(xml: &str) -> Result<PropRequest, EdgeProblem> {
        parse_propfind(xml.as_bytes(), &limits())
    }

    fn name(namespace: &str, local: &str) -> PropertyName {
        PropertyName::new(namespace, local)
    }

    #[test]
    fn an_empty_propfind_asks_for_everything() {
        for body in ["", "  \r\n "] {
            assert_eq!(propfind(body).unwrap(), PropRequest::AllProp(PropList::default()));
        }
    }

    #[test]
    fn propfind_names_its_properties_once_each() {
        let request = propfind(
            r#"<D:propfind xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
                 <D:prop><D:getetag/><C:calendar-data/><D:getetag/><x:foo xmlns:x="urn:x"/></D:prop>
               </D:propfind>"#,
        )
        .unwrap();
        let PropRequest::Prop(list) = request else {
            panic!("{request:?}")
        };
        assert_eq!(
            list.names,
            [
                name(NS_DAV, "getetag"),
                name(NS_CALDAV, "calendar-data"),
                name("urn:x", "foo")
            ]
        );
        assert_eq!(list.calendar_data, Some(Projection::default()));
    }

    #[test]
    fn a_request_names_a_bounded_number_of_distinct_properties() {
        let names = |count: usize| crate::xml::repeated(count, |n| format!(r#"<x:p{n} xmlns:x="urn:x"/>"#));
        let body = |count: usize| {
            format!(
                r#"<D:propfind xmlns:D="DAV:"><D:prop>{}</D:prop></D:propfind>"#,
                names(count)
            )
        };
        let PropRequest::Prop(list) = propfind(&body(MAX_PROPERTIES)).unwrap() else {
            panic!("not a prop request")
        };
        assert_eq!(list.names.len(), MAX_PROPERTIES);
        let problem = propfind(&body(MAX_PROPERTIES + 1)).unwrap_err();
        assert_eq!(problem.code(), ProblemCode::BadRequest);
        // Repeats are free: only distinct properties count.
        let repeated = format!(
            r#"<D:propfind xmlns:D="DAV:"><D:prop>{}</D:prop></D:propfind>"#,
            r"<D:getetag/>".repeat(5_000)
        );
        let PropRequest::Prop(list) = propfind(&repeated).unwrap() else {
            panic!("not a prop request")
        };
        assert_eq!(list.names.len(), 1);
    }

    #[test]
    fn the_names_of_a_request_are_listed_for_the_prefixes_of_the_answer() {
        let request = propfind(
            r#"<D:propfind xmlns:D="DAV:"><D:allprop/><D:include><x:a xmlns:x="urn:x"/></D:include></D:propfind>"#,
        )
        .unwrap();
        assert_eq!(request.names(), [name("urn:x", "a")]);
        assert_eq!(PropRequest::PropName.names(), []);
    }

    #[test]
    fn a_request_changes_or_creates_with_a_bounded_number_of_properties() {
        let many = crate::xml::repeated(MAX_PROPERTIES + 1, |n| format!(r#"<x:p{n} xmlns:x="urn:x">v</x:p{n}>"#));
        let update =
            format!(r#"<D:propertyupdate xmlns:D="DAV:"><D:set><D:prop>{many}</D:prop></D:set></D:propertyupdate>"#);
        assert_eq!(
            parse_propertyupdate(&root(&update)).unwrap_err().code(),
            ProblemCode::BadRequest
        );
        let create = format!(r#"<D:mkcol xmlns:D="DAV:"><D:set><D:prop>{many}</D:prop></D:set></D:mkcol>"#);
        assert_eq!(
            parse_make_collection(create.as_bytes(), &limits(), MakeKind::ExtendedMkcol)
                .unwrap_err()
                .code(),
            ProblemCode::BadRequest
        );
        let fewer = crate::xml::repeated(MAX_PROPERTIES, |n| format!(r#"<x:p{n} xmlns:x="urn:x">v</x:p{n}>"#));
        let update =
            format!(r#"<D:propertyupdate xmlns:D="DAV:"><D:set><D:prop>{fewer}</D:prop></D:set></D:propertyupdate>"#);
        assert_eq!(parse_propertyupdate(&root(&update)).unwrap().len(), MAX_PROPERTIES);
    }

    #[test]
    fn blank_bodies_are_no_bodies() {
        assert!(is_blank(b""));
        assert!(is_blank(b" \r\n\t"));
        assert!(!is_blank(b" <a/>"));
    }

    #[test]
    fn propname_and_allprop_with_include() {
        assert_eq!(
            propfind(r#"<propfind xmlns="DAV:"><propname/></propfind>"#).unwrap(),
            PropRequest::PropName
        );
        let PropRequest::AllProp(include) = propfind(
            r#"<D:propfind xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><D:allprop/><D:include><C:calendar-description/></D:include></D:propfind>"#,
        )
        .unwrap() else {
            panic!("not an allprop")
        };
        assert_eq!(include.names, [name(NS_CALDAV, "calendar-description")]);
    }

    #[test]
    fn propfind_bodies_that_make_no_sense_are_400() {
        for body in [
            r#"<propfind xmlns="DAV:"><prop/><propname/></propfind>"#,
            r#"<other xmlns="DAV:"/>"#,
            r#"<propfind xmlns="urn:x"/>"#,
            "<propfind",
            r#"<!DOCTYPE a [<!ENTITY b "c">]><propfind xmlns="DAV:"/>"#,
        ] {
            let problem = propfind(body).unwrap_err();
            assert_eq!(problem.code(), ProblemCode::BadRequest, "{body}");
        }
        let missing = propfind(r#"<propfind xmlns="DAV:"/>"#).unwrap();
        assert_eq!(
            missing,
            PropRequest::AllProp(PropList::default()),
            "a propfind without a selection asks for everything, as in RFC 4918"
        );
    }

    #[test]
    fn calendar_data_selections_are_read_completely() {
        let element = root(
            r#"<C:calendar-data xmlns:C="urn:ietf:params:xml:ns:caldav" content-type="text/calendar" version="2.0">
                 <C:comp name="vcalendar">
                   <C:prop name="version"/>
                   <C:comp name="VEVENT"><C:prop name="UID" novalue="yes"/><C:allprop/><C:allcomp/></C:comp>
                 </C:comp>
                 <C:limit-recurrence-set start="20260101T000000Z" end="20260201T000000Z"/>
               </C:calendar-data>"#,
        );
        let projection = parse_calendar_data(&element).unwrap();
        let select = projection.select.unwrap();
        assert_eq!(select.name, "VCALENDAR");
        assert_eq!(select.props.len(), 1);
        assert_eq!(select.props[0].name, "VERSION");
        assert!(!select.props[0].no_value);
        let event = &select.comps[0];
        assert_eq!(event.name, "VEVENT");
        assert!(event.all_props && event.all_comps);
        assert!(event.props[0].no_value);
        assert_eq!(
            projection.limit_recurrence_set,
            Some(TimeRange::new(
                Some(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()),
                Some(Utc.with_ymd_and_hms(2026, 2, 1, 0, 0, 0).unwrap())
            ))
        );
        assert!(projection.expand.is_none());
    }

    #[test]
    fn calendar_data_reads_expansion_and_free_busy_limits_and_skips_what_it_does_not_know() {
        let element = root(
            r#"<C:calendar-data xmlns:C="urn:ietf:params:xml:ns:caldav" xmlns:x="urn:example:x">
                 <C:expand start="20260301T000000Z" end="20260308T000000Z"/>
                 <C:limit-freebusy-set start="20260302T000000Z"/>
                 <C:future-extension/>
                 <x:comp name="IGNORED"/>
               </C:calendar-data>"#,
        );
        let projection = parse_calendar_data(&element).unwrap();
        assert_eq!(
            projection.expand,
            Some(TimeRange::new(
                Some(Utc.with_ymd_and_hms(2026, 3, 1, 0, 0, 0).unwrap()),
                Some(Utc.with_ymd_and_hms(2026, 3, 8, 0, 0, 0).unwrap())
            ))
        );
        assert_eq!(
            projection.limit_freebusy_set,
            Some(TimeRange::new(
                Some(Utc.with_ymd_and_hms(2026, 3, 2, 0, 0, 0).unwrap()),
                None
            ))
        );
        assert!(projection.limit_recurrence_set.is_none());
        assert!(
            projection.select.is_none(),
            "a comp of another namespace is no selection, and an unknown CalDAV element is skipped (RFC 4918 17)"
        );
        let bad = root(
            r#"<C:calendar-data xmlns:C="urn:ietf:params:xml:ns:caldav"><C:expand start="soon"/></C:calendar-data>"#,
        );
        assert_eq!(
            parse_calendar_data(&bad).unwrap_err().code(),
            ProblemCode::InvalidFilter,
            "a time range of an expansion is checked like any other"
        );
        let nameless_prop = root(
            r#"<C:calendar-data xmlns:C="urn:ietf:params:xml:ns:caldav"><C:comp name="VCALENDAR"><C:prop name=" "/></C:comp></C:calendar-data>"#,
        );
        assert_eq!(
            parse_calendar_data(&nameless_prop).unwrap_err().code(),
            ProblemCode::BadRequest
        );
    }

    #[test]
    fn unknown_instructions_of_an_update_or_a_creation_are_skipped() {
        // RFC 4918 section 17: a server ignores the elements it does not understand. Only `set` and `remove` change
        // anything, in document order, whatever stands between them.
        let updates = parse_propertyupdate(&root(
            r#"<D:propertyupdate xmlns:D="DAV:" xmlns:x="urn:example:x">
                 <x:audit/>
                 <D:set><D:prop><D:displayname>Work</D:displayname></D:prop></D:set>
                 <D:lockinfo/>
                 <D:remove><D:prop><x:note/></D:prop></D:remove>
               </D:propertyupdate>"#,
        ))
        .unwrap();
        assert_eq!(updates.len(), 2);
        assert!(matches!(&updates[0], Update::Set(n, e) if n == &name(NS_DAV, "displayname") && e.text() == "Work"));
        assert_eq!(updates[1], Update::Remove(name("urn:example:x", "note")));
        assert_eq!(
            parse_propertyupdate(&root(
                r#"<D:propertyupdate xmlns:D="DAV:"><D:lockinfo/></D:propertyupdate>"#
            ))
            .unwrap_err()
            .code(),
            ProblemCode::BadRequest,
            "an update of nothing but unknown instructions changes no property"
        );

        let created = parse_make_collection(
            br#"<C:mkcalendar xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav" xmlns:x="urn:example:x">
                  <x:audit/>
                  <D:set><D:prop><D:displayname>Holidays</D:displayname></D:prop></D:set>
                </C:mkcalendar>"#,
            &limits(),
            MakeKind::MkCalendar,
        )
        .unwrap();
        assert_eq!(created.sets.len(), 1);
        assert_eq!(created.sets[0].0, name(NS_DAV, "displayname"));
        assert_eq!(created.sets[0].1.text(), "Holidays");
    }

    #[test]
    fn calendar_data_in_other_formats_is_unsupported() {
        for attributes in [r#"content-type="application/json""#, r#"version="1.0""#] {
            let element = root(&format!(
                r#"<C:calendar-data xmlns:C="urn:ietf:params:xml:ns:caldav" {attributes}/>"#
            ));
            assert_eq!(
                parse_calendar_data(&element).unwrap_err().code(),
                ProblemCode::UnsupportedCalendarData
            );
        }
        let nameless = root(r#"<C:calendar-data xmlns:C="urn:ietf:params:xml:ns:caldav"><C:comp/></C:calendar-data>"#);
        assert_eq!(
            parse_calendar_data(&nameless).unwrap_err().code(),
            ProblemCode::BadRequest
        );
        let two = root(
            r#"<C:calendar-data xmlns:C="urn:ietf:params:xml:ns:caldav"><C:comp name="A"/><C:comp name="B"/></C:calendar-data>"#,
        );
        assert_eq!(parse_calendar_data(&two).unwrap_err().code(), ProblemCode::BadRequest);
    }

    #[test]
    fn utc_date_times_have_exactly_the_icalendar_form() {
        assert_eq!(
            parse_utc("20260301T101500Z"),
            Some(Utc.with_ymd_and_hms(2026, 3, 1, 10, 15, 0).unwrap())
        );
        for bad in [
            "",
            "20260301T101500",
            "20260301 101500Z",
            "2026-03-01T10:15:00Z",
            "20261301T101500Z",
            "20260301T251500Z",
            "20260301T10150Z0",
            "+0260301T101500Z",
            "２０２６0301T101500Z",
        ] {
            assert_eq!(parse_utc(bad), None, "{bad}");
        }
        let instant = Utc.with_ymd_and_hms(1999, 12, 31, 23, 59, 59).unwrap();
        assert_eq!(format_utc(instant), "19991231T235959Z");
        assert_eq!(parse_utc(&format_utc(instant)), Some(instant));
    }

    #[test]
    fn time_ranges_take_optional_bounds_and_refuse_garbage() {
        let open = root(r#"<time-range xmlns="urn:ietf:params:xml:ns:caldav" start="20260101T000000Z"/>"#);
        let range = parse_time_range(&open).unwrap();
        assert!(range.start.is_some() && range.end.is_none());
        let bad = root(r#"<time-range xmlns="urn:ietf:params:xml:ns:caldav" end="tomorrow"/>"#);
        assert_eq!(parse_time_range(&bad).unwrap_err().code(), ProblemCode::InvalidFilter);
    }

    #[test]
    fn property_updates_keep_their_order_and_kind() {
        let updates = parse_propertyupdate(&root(
            r#"<D:propertyupdate xmlns:D="DAV:" xmlns:A="http://apple.com/ns/ical/">
                 <D:set><D:prop><D:displayname>Work</D:displayname><A:calendar-color>#112233FF</A:calendar-color></D:prop></D:set>
                 <D:remove><D:prop><x:note xmlns:x="urn:x"/></D:prop></D:remove>
               </D:propertyupdate>"#,
        ))
        .unwrap();
        assert_eq!(updates.len(), 3);
        assert!(matches!(&updates[0], Update::Set(n, e) if n == &name(NS_DAV, "displayname") && e.text() == "Work"));
        assert!(matches!(&updates[1], Update::Set(n, _) if n.local == "calendar-color"));
        assert_eq!(updates[2], Update::Remove(name("urn:x", "note")));
        assert_eq!(updates[2].name(), &name("urn:x", "note"));
    }

    #[test]
    fn property_updates_without_substance_are_400() {
        for xml in [
            r#"<propertyupdate xmlns="DAV:"/>"#,
            r#"<propertyupdate xmlns="DAV:"><set/></propertyupdate>"#,
            r#"<propertyupdate xmlns="DAV:"><set><prop/></set></propertyupdate>"#,
            r#"<propfind xmlns="DAV:"/>"#,
        ] {
            assert_eq!(
                parse_propertyupdate(&root(xml)).unwrap_err().code(),
                ProblemCode::BadRequest,
                "{xml}"
            );
        }
    }

    #[test]
    fn collections_are_created_from_the_matching_body() {
        let calendar = parse_make_collection(
            br#"<C:mkcalendar xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
                  <D:set><D:prop><D:displayname>Holidays</D:displayname><C:calendar-description>x</C:calendar-description></D:prop></D:set>
                </C:mkcalendar>"#,
            &limits(),
            MakeKind::MkCalendar,
        )
        .unwrap();
        assert_eq!(calendar.sets.len(), 2);
        assert_eq!(calendar.sets[0].0, name(NS_DAV, "displayname"));
        let defaults = parse_make_collection(b"", &limits(), MakeKind::MkCalendar).unwrap();
        assert_eq!(defaults.sets.len(), 0);
        let mkcol = parse_make_collection(
            br#"<D:mkcol xmlns:D="DAV:"><D:set><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop></D:set></D:mkcol>"#,
            &limits(),
            MakeKind::ExtendedMkcol,
        )
        .unwrap();
        assert_eq!(mkcol.sets[0].0, name(NS_DAV, "resourcetype"));
        for (body, kind) in [
            (&br#"<D:mkcol xmlns:D="DAV:"/>"#[..], MakeKind::MkCalendar),
            (
                &br#"<C:mkcalendar xmlns:C="urn:ietf:params:xml:ns:caldav"/>"#[..],
                MakeKind::ExtendedMkcol,
            ),
            (
                &br#"<D:mkcol xmlns:D="DAV:"><D:remove><D:prop/></D:remove></D:mkcol>"#[..],
                MakeKind::ExtendedMkcol,
            ),
            (&b"<broken"[..], MakeKind::MkCalendar),
        ] {
            assert_eq!(
                parse_make_collection(body, &limits(), kind).unwrap_err().code(),
                ProblemCode::BadRequest
            );
        }
    }
}
