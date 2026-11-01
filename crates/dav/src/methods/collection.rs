//! Calendar collections: MKCALENDAR, extended MKCOL and DELETE (RFC 4791 section 5.3.1, RFC 5689, RFC 4918
//! section 9.6).
//!
//! `MKCALENDAR` creates the calendar at the URL it is sent to, with the properties of its body. An extended `MKCOL`
//! does the same for a body that sets `DAV:resourcetype` to a calendar; every other resource type is refused (the
//! server makes calendars, nothing else). The URL must be a free binding slug of the caller's home: an existing
//! resource answers 405 `DAV:resource-must-be-null`, which includes the home itself.
//!
//! The home must be visible to the caller before anything about the request is judged: in the home of another user
//! or of another tenant every `MKCALENDAR` and `MKCOL` answers 404, whatever the body says (PLAN 2.6).
//!
//! A request that cannot create the calendar (a protected property, a value that does not fit, a value that is too
//! large, more dead properties than allowed, a `MKCOL` that does not ask for a calendar) answers **403** with the
//! per-property statuses RFC 4791 and RFC 5689 define: a `CALDAV:mkcalendar-response` or `DAV:mkcol-response` whose
//! `propstat`s give every property its status (403 with the precondition element for the properties that are
//! refused, 409 for a value that does not fit, 424 for the properties that were fine). The statuses are those of
//! `PROPPATCH`, and nothing is created.
//!
//! `DELETE` of a collection removes the calendar for its owner and everyone it was shared with, or only the
//! caller's binding (shares, group and managed calendars): the service decides which (PLAN 2.9). Collections have
//! no entity tag, so `If-Match` with anything but `*` fails with 412, and `If-None-Match: *` fails because the
//! collection exists.

use axum::body::Body;
use axum::http::StatusCode;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::response::Response;
use davhaven_app::services::{Conditions, DeadProperty, MkCalendar, NS_CALDAV, NS_DAV, PropertyChange, PropertyName};
use davhaven_domain::ResourcePath;
use davhaven_http::problem::{EdgeProblem, ProblemCode};

use super::headers::{conditional_values, parse_tag_list};
use super::proppatch::{PropResult, prefixes_of, propstats, protected};
use super::{Call, set_header, status_only};
use crate::errors::PreconditionElement;
use crate::props::{Interpreted, interpret_set, limit_dead_properties};
use crate::xml::Element;
use crate::xml::requests::{MakeKind, is_blank, parse_make_collection_root};
use crate::xml::write::Multistatus;

/// The element next to the 403 of an extended `MKCOL` that does not ask for a calendar.
fn valid_resourcetype() -> PreconditionElement {
    PreconditionElement::dav("valid-resourcetype")
}

/// An empty request to create the calendar at `path`.
fn blank(path: &ResourcePath) -> MkCalendar {
    MkCalendar {
        path: path.clone(),
        display_name: None,
        description: None,
        color: None,
        sort_order: None,
        components: None,
        timezone_ics: None,
        schedule_transp: None,
        dead_properties: Vec::new(),
    }
}

/// Applies a change of a property to the request that creates the calendar. A property that is set twice has the
/// value of the last `DAV:set`, as in a `PROPPATCH`.
fn apply(request: &mut MkCalendar, change: PropertyChange) {
    match change {
        PropertyChange::DisplayName(value) => request.display_name = value,
        PropertyChange::Description(value) => request.description = value,
        PropertyChange::Color(value) => request.color = value,
        PropertyChange::Order(value) => request.sort_order = value,
        PropertyChange::Timezone(value) => request.timezone_ics = value,
        PropertyChange::ScheduleTransparency(value) => request.schedule_transp = value,
        PropertyChange::Dead { name, value_xml } => {
            request.dead_properties.retain(|existing| existing.name != name);
            if let Some(value_xml) = value_xml {
                request.dead_properties.push(DeadProperty { name, value_xml });
            }
        }
    }
}

/// What the properties of a creation body come to: the request for the service, and whether the body asks for a
/// calendar.
struct Creation {
    request: MkCalendar,
    calendar: bool,
}

/// Reads the instructions into the request that creates the calendar.
fn creation(path: &ResourcePath, kind: MakeKind, interpreted: &[Interpreted]) -> Creation {
    let calendar_type = PropertyName::new(NS_CALDAV, "calendar");
    let mut request = blank(path);
    let mut calendar = kind == MakeKind::MkCalendar;
    for instruction in interpreted {
        match instruction {
            Interpreted::Change(change) => apply(&mut request, change.clone()),
            Interpreted::Components(kinds) => request.components = Some(kinds.clone()),
            Interpreted::ResourceType(types) => calendar |= types.contains(&calendar_type),
            Interpreted::Protected | Interpreted::Invalid | Interpreted::TooLarge => {}
        }
    }
    Creation { request, calendar }
}

/// The status of a property of a creation that cannot succeed: the properties that are refused say why, those that
/// were fine depend on them.
fn failure_status(instruction: &Interpreted, kind: MakeKind, calendar: bool) -> (u16, Option<PreconditionElement>) {
    match instruction {
        Interpreted::ResourceType(_) if kind == MakeKind::ExtendedMkcol && !calendar => {
            (403, Some(valid_resourcetype()))
        }
        Interpreted::Change(_) | Interpreted::Components(_) | Interpreted::ResourceType(_) => (424, None),
        Interpreted::Protected => (403, Some(protected())),
        Interpreted::Invalid => (409, None),
        Interpreted::TooLarge => (403, None),
    }
}

/// The per-property statuses of a creation that cannot succeed, or `None` when the body can create the calendar.
fn failures(
    sets: &[(PropertyName, Element)],
    interpreted: &[Interpreted],
    kind: MakeKind,
    calendar: bool,
) -> Option<Vec<PropResult>> {
    let refused = interpreted.iter().any(|instruction| {
        matches!(
            instruction,
            Interpreted::Protected | Interpreted::Invalid | Interpreted::TooLarge
        )
    });
    let not_a_calendar = kind == MakeKind::ExtendedMkcol && !calendar;
    if !refused && !not_a_calendar {
        return None;
    }
    let mut results: Vec<PropResult> = sets
        .iter()
        .zip(interpreted)
        .map(|((name, _), instruction)| {
            let (status, error) = failure_status(instruction, kind, calendar);
            PropResult {
                name: name.clone(),
                status,
                error,
            }
        })
        .collect();
    let names_resourcetype = sets
        .iter()
        .any(|(name, _)| name.namespace == NS_DAV && name.local == "resourcetype");
    if not_a_calendar && !names_resourcetype {
        // The body does not say what it makes: the type it would have is the one that is refused.
        results.push(PropResult {
            name: PropertyName::new(NS_DAV, "resourcetype"),
            status: 403,
            error: Some(valid_resourcetype()),
        });
    }
    Some(results)
}

/// The answer to a creation that cannot succeed: 403 with the statuses of the properties.
fn refused(call: &Call<'_>, kind: MakeKind, results: &[PropResult]) -> Response {
    let prefixes = prefixes_of(call, results.iter().map(|result| &result.name));
    let (namespace, local) = match kind {
        MakeKind::MkCalendar => (NS_CALDAV, "mkcalendar-response"),
        MakeKind::ExtendedMkcol => (NS_DAV, "mkcol-response"),
    };
    let mut document = Multistatus::rooted(namespace, local, &prefixes);
    for propstat in propstats(results, &prefixes) {
        document.propstat(&propstat);
    }
    let mut response = Response::new(Body::from(document.finish()));
    *response.status_mut() = StatusCode::FORBIDDEN;
    set_header(&mut response, CONTENT_TYPE, "application/xml; charset=utf-8");
    set_header(&mut response, CACHE_CONTROL, "no-store");
    response
}

/// Serves MKCALENDAR and extended MKCOL.
pub(crate) async fn make(call: &Call<'_>, body: Body, kind: MakeKind) -> Result<Response, EdgeProblem> {
    if !matches!(call.resource, ResourcePath::Collection { .. }) {
        // The home and the other collections of a principal exist already, for those who can see them.
        call.services()
            .calendars
            .get_collection(call.ctx, call.resource)
            .await?;
        return Err(EdgeProblem::new(ProblemCode::ResourceExists));
    }
    // The home decides what the caller may know: nothing about the request is judged before it is visible.
    let home = call
        .resource
        .parent()
        .ok_or_else(|| EdgeProblem::new(ProblemCode::NotFound))?;
    call.services().calendars.get_collection(call.ctx, &home).await?;

    let bytes = call.xml_body(body).await?;
    let sets = if is_blank(&bytes) {
        Vec::new()
    } else {
        parse_make_collection_root(&call.parse_xml(bytes).await?, kind)?.sets
    };
    let mut interpreted: Vec<Interpreted> = sets
        .iter()
        .map(|(name, element)| interpret_set(name, element, call.limits()))
        .collect();
    limit_dead_properties(&mut interpreted, call.limits().dav.max_dead_properties);
    let Creation { request, calendar } = creation(call.resource, kind, &interpreted);
    if let Some(results) = failures(&sets, &interpreted, kind, calendar) {
        return Ok(refused(call, kind, &results));
    }
    call.services().calendars.mkcalendar(call.ctx, request).await?;
    let mut response = status_only(StatusCode::CREATED);
    set_header(&mut response, CACHE_CONTROL, "no-cache");
    Ok(response)
}

/// Serves a DELETE of a calendar collection.
pub(crate) async fn delete(call: &Call<'_>) -> Result<Response, EdgeProblem> {
    let precondition_failed = || EdgeProblem::new(ProblemCode::PreconditionFailed);
    let if_match = conditional_values(call.headers(), "if-match")?;
    if !if_match.is_empty() && !parse_tag_list(&if_match).any {
        return Err(precondition_failed());
    }
    // The collection exists: a request that only wants to create it fails. No entity tag can match it.
    let if_none_match = conditional_values(call.headers(), "if-none-match")?;
    if !if_none_match.is_empty() && parse_tag_list(&if_none_match).any {
        return Err(precondition_failed());
    }
    call.services()
        .calendars
        .delete_collection(call.ctx, call.resource, Conditions::none())
        .await?;
    Ok(status_only(StatusCode::NO_CONTENT))
}

#[cfg(test)]
mod tests {
    use davhaven_domain::{CalendarSlug, PrincipalName, TenantSlug, Transparency};

    use super::*;

    fn path() -> ResourcePath {
        ResourcePath::Collection {
            tenant: TenantSlug::parse("acme").unwrap(),
            principal: PrincipalName::parse("anna").unwrap(),
            binding: CalendarSlug::parse("holidays").unwrap(),
        }
    }

    fn dead(local: &str, value: &str) -> PropertyChange {
        PropertyChange::Dead {
            name: PropertyName::new("urn:x", local),
            value_xml: Some(value.to_owned()),
        }
    }

    #[test]
    fn properties_land_in_the_request_that_creates_the_calendar() {
        let mut request = blank(&path());
        apply(&mut request, PropertyChange::DisplayName(Some("Holidays".to_owned())));
        apply(&mut request, PropertyChange::Description(Some("Days off".to_owned())));
        apply(&mut request, PropertyChange::Color(Some("#00FF00FF".to_owned())));
        apply(&mut request, PropertyChange::Order(Some(3)));
        apply(&mut request, PropertyChange::Timezone(Some("tz".to_owned())));
        apply(
            &mut request,
            PropertyChange::ScheduleTransparency(Some(Transparency::Transparent)),
        );
        apply(&mut request, dead("note", "v"));
        apply(
            &mut request,
            PropertyChange::Dead {
                name: PropertyName::new("urn:x", "removed"),
                value_xml: None,
            },
        );
        assert_eq!(request.display_name.as_deref(), Some("Holidays"));
        assert_eq!(request.description.as_deref(), Some("Days off"));
        assert_eq!(request.color.as_deref(), Some("#00FF00FF"));
        assert_eq!(request.sort_order, Some(3));
        assert_eq!(request.timezone_ics.as_deref(), Some("tz"));
        assert_eq!(request.schedule_transp, Some(Transparency::Transparent));
        assert_eq!(request.dead_properties.len(), 1, "a removal creates nothing");
        assert_eq!(request.path, path());
        assert!(request.components.is_none());
    }

    #[test]
    fn a_property_that_is_set_twice_has_the_last_value() {
        let mut request = blank(&path());
        apply(&mut request, dead("note", "first"));
        apply(&mut request, dead("other", "o"));
        apply(&mut request, dead("note", "second"));
        let values: Vec<(&str, &str)> = request
            .dead_properties
            .iter()
            .map(|property| (property.name.local.as_str(), property.value_xml.as_str()))
            .collect();
        assert_eq!(values, [("other", "o"), ("note", "second")]);
    }

    #[test]
    fn only_a_refused_property_or_a_missing_calendar_type_fails_a_creation() {
        let named = |local: &str| (PropertyName::new(NS_DAV, local), Element::new(NS_DAV, local));
        let sets = [named("displayname"), named("getetag")];
        let fine = [
            Interpreted::Change(PropertyChange::DisplayName(None)),
            Interpreted::Change(PropertyChange::Order(None)),
        ];
        assert!(failures(&sets, &fine, MakeKind::MkCalendar, true).is_none());
        assert!(failures(&sets, &fine, MakeKind::ExtendedMkcol, true).is_none());

        let refused = [
            Interpreted::Change(PropertyChange::DisplayName(None)),
            Interpreted::Protected,
        ];
        let results = failures(&sets, &refused, MakeKind::MkCalendar, true).unwrap();
        let shape: Vec<(u16, Option<&str>)> = results
            .iter()
            .map(|result| (result.status, result.error.as_ref().map(PreconditionElement::as_str)))
            .collect();
        assert_eq!(
            shape,
            [(424, None), (403, Some("<D:cannot-modify-protected-property/>"))]
        );

        let statuses = |instruction: Interpreted| failure_status(&instruction, MakeKind::MkCalendar, true);
        assert_eq!(statuses(Interpreted::Invalid), (409, None));
        assert_eq!(statuses(Interpreted::TooLarge), (403, None));
        assert_eq!(statuses(Interpreted::Protected), (403, Some(protected())));

        let plain = [Interpreted::Change(PropertyChange::DisplayName(None))];
        let results = failures(&sets[..1], &plain, MakeKind::ExtendedMkcol, false).unwrap();
        let shape: Vec<(u16, Option<&str>)> = results
            .iter()
            .map(|result| (result.status, result.error.as_ref().map(PreconditionElement::as_str)))
            .collect();
        assert_eq!(
            shape,
            [(424, None), (403, Some("<D:valid-resourcetype/>"))],
            "the type that the body does not name is the one that is refused"
        );
    }
}
