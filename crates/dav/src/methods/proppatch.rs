//! PROPPATCH (RFC 4918 section 9.2): changing the properties of a calendar collection.
//!
//! The six properties clients set (`displayname`, `calendar-description`, `calendar-color`, `calendar-order`,
//! `calendar-timezone`, `schedule-calendar-transp`) and the dead properties are applied through
//! `CalendarService::proppatch`, which stores the per-binding ones on the binding of the principal and the shared
//! ones on the calendar (PLAN 2.6). The request is **atomic**: when one property cannot be changed, nothing is
//! applied and the others answer 424 Failed Dependency.
//!
//! What the server decides itself, before the service is asked (and only after the resource turned out to be
//! visible to the caller: an invisible calendar answers 404 whatever the body says):
//!
//! * a live property clients cannot change (`getetag`, `sync-token`, `supported-calendar-component-set`, ...)
//!   answers 403 with `DAV:cannot-modify-protected-property`;
//! * a value that does not fit the property (a `calendar-order` that is no number) answers 409;
//! * a value larger than the server stores (a dead property above `max_dead_property_size`, more dead properties in
//!   one request than `max_dead_properties`) answers 403, like the limit of the application when the binding
//!   already holds too many (PLAN 2.15).
//!
//! Calendar objects have no properties a client may change, and neither has the home or the inbox: the data model
//! keeps properties per calendar and per binding, not per home, so what clients set there (default alarms, the
//! default calendar for invitations of RFC 6638) is not stored and a PROPPATCH of those answers 403 for every
//! property (`docs/interop.md`, `ROADMAP.md`).

use axum::body::Body;
use axum::response::Response;
use davhaven_app::services::{PropPatch, PropertyChange, PropertyName, PropertyOutcome, PropertyStatus};
use davhaven_domain::{Precondition, ResourcePath};
use davhaven_http::problem::{EdgeProblem, ProblemCode};

use super::{Call, multistatus_response};
use crate::errors::{PreconditionElement, catalog_element};
use crate::props::{Interpreted, interpret, limit_dead_properties};
use crate::xml::requests::{Update, parse_propertyupdate};
use crate::xml::write::{Multistatus, Prefixes, Propstat, XmlWriter};

/// The protected-property element shown next to the 403 of a property the server owns.
pub(super) fn protected() -> PreconditionElement {
    PreconditionElement::dav("cannot-modify-protected-property")
}

/// The status of one property in the answer.
///
/// A property limit of the application (`InsufficientStorage`) is a 403 like every other limit of PLAN 2.15, so that
/// a client sees one status whether the DAV layer or the application finds the limit exceeded.
const fn status_of(status: PropertyStatus) -> u16 {
    match status {
        PropertyStatus::Applied => 200,
        PropertyStatus::Forbidden | PropertyStatus::InsufficientStorage => 403,
        PropertyStatus::Conflict => 409,
        PropertyStatus::FailedDependency => 424,
    }
}

/// One property of the answer.
pub(super) struct PropResult {
    /// The property.
    pub(super) name: PropertyName,
    /// Its status.
    pub(super) status: u16,
    /// The precondition element that explains the status.
    pub(super) error: Option<PreconditionElement>,
}

/// The element the catalog names for a precondition that the application reports for one property (the value of
/// `calendar-timezone` is not valid calendar data); `None` for a precondition the catalog has no row for.
fn element_of(precondition: &Precondition) -> Option<PreconditionElement> {
    catalog_element(ProblemCode::from_precondition(precondition)?, Some(precondition))
}

/// Groups the results by status, in the order the statuses first appear, with the names written with the prefixes
/// the document declares.
pub(super) fn propstats(results: &[PropResult], prefixes: &Prefixes) -> Vec<Propstat> {
    let mut groups: Vec<(u16, Option<PreconditionElement>, XmlWriter)> = Vec::new();
    for result in results {
        let existing = groups
            .iter()
            .position(|(status, error, _)| *status == result.status && *error == result.error);
        let index = existing.unwrap_or_else(|| {
            groups.push((result.status, result.error.clone(), XmlWriter::with_prefixes(prefixes)));
            groups.len().saturating_sub(1)
        });
        if let Some((_, _, writer)) = groups.get_mut(index) {
            writer.empty(&result.name.namespace, &result.name.local);
        }
    }
    groups
        .into_iter()
        .map(|(status, error, writer)| Propstat {
            status,
            props: writer.into_string(),
            error,
        })
        .collect()
}

/// The prefixes of the namespaces of the properties of a request.
pub(super) fn prefixes_of<'a>(call: &Call<'_>, names: impl IntoIterator<Item = &'a PropertyName>) -> Prefixes {
    Prefixes::of(
        names.into_iter().map(|name| name.namespace.as_str()),
        usize::try_from(call.limits().dav.max_xml_namespaces).unwrap_or(usize::MAX),
    )
}

/// Whether the caller may see the resource: the problem of the service (404 for an invisible resource) when not.
///
/// A handler that refuses a request for a reason of its own calls this first, so that a refusal never tells the
/// caller that a resource exists.
pub(super) async fn visible(call: &Call<'_>) -> Result<(), EdgeProblem> {
    let seen = match call.resource {
        ResourcePath::Object { .. } => call.services().objects.get(call.ctx, call.resource).await.map(|_| ()),
        _ => call
            .services()
            .calendars
            .get_collection(call.ctx, call.resource)
            .await
            .map(|_| ()),
    };
    seen.map_err(EdgeProblem::from)
}

/// What a request body comes to: the instructions and what the server makes of each.
struct Read {
    updates: Vec<Update>,
    interpreted: Vec<Interpreted>,
}

async fn read(call: &Call<'_>, body: Body) -> Result<Read, EdgeProblem> {
    let bytes = call.xml_body(body).await?;
    let root = call.parse_xml(bytes).await?;
    let updates = parse_propertyupdate(&root)?;
    let mut interpreted: Vec<Interpreted> = updates.iter().map(|update| interpret(update, call.limits())).collect();
    limit_dead_properties(&mut interpreted, call.limits().dav.max_dead_properties);
    Ok(Read { updates, interpreted })
}

/// Serves a PROPPATCH.
pub(crate) async fn handle(call: &Call<'_>, body: Body) -> Result<Response, EdgeProblem> {
    let read = match read(call, body).await {
        Ok(read) => read,
        Err(problem) => {
            // A body that cannot be read says nothing about the resource, unless the caller cannot see it.
            visible(call).await?;
            return Err(problem);
        }
    };
    let results = match call.resource {
        ResourcePath::Collection { .. } => collection(call, &read.updates, read.interpreted).await?,
        _ => refuse_all(call, &read.updates).await?,
    };
    let prefixes = prefixes_of(call, read.updates.iter().map(Update::name));
    let mut multistatus = Multistatus::with_prefixes(&prefixes);
    multistatus.response(&call.resource.format(), &propstats(&results, &prefixes));
    Ok(multistatus_response(multistatus.finish(), false))
}

/// The answer for a resource without properties a client may change (an object, the home, the inbox): every property
/// is refused. A resource the caller cannot see is not refused but not found, like everywhere else (PLAN 2.6).
async fn refuse_all(call: &Call<'_>, updates: &[Update]) -> Result<Vec<PropResult>, EdgeProblem> {
    visible(call).await?;
    Ok(updates
        .iter()
        .map(|update| PropResult {
            name: update.name().clone(),
            status: 403,
            error: Some(protected()),
        })
        .collect())
}

/// The change an interpreted instruction asks the service for.
fn change_of(interpreted: &Interpreted) -> Option<PropertyChange> {
    match interpreted {
        Interpreted::Change(change) => Some(change.clone()),
        _ => None,
    }
}

/// The status of an instruction the server refuses itself.
pub(super) fn refusal(interpreted: &Interpreted) -> Option<(u16, Option<PreconditionElement>)> {
    match interpreted {
        Interpreted::Change(_) => None,
        Interpreted::Invalid => Some((409, None)),
        Interpreted::TooLarge => Some((403, None)),
        Interpreted::Protected | Interpreted::Components(_) | Interpreted::ResourceType(_) => {
            Some((403, Some(protected())))
        }
    }
}

async fn collection(
    call: &Call<'_>,
    updates: &[Update],
    interpreted: Vec<Interpreted>,
) -> Result<Vec<PropResult>, EdgeProblem> {
    if interpreted.iter().any(|instruction| refusal(instruction).is_some()) {
        // The server refuses before the service is asked, so it has to know that the caller may see the calendar.
        visible(call).await?;
        // Nothing is applied: the properties that failed say why, the others depend on them.
        return Ok(updates
            .iter()
            .zip(&interpreted)
            .map(|(update, instruction)| {
                let (status, error) = refusal(instruction).unwrap_or((424, None));
                PropResult {
                    name: update.name().clone(),
                    status,
                    error,
                }
            })
            .collect());
    }
    let changes: Vec<PropertyChange> = interpreted.iter().filter_map(change_of).collect();
    let outcome = call
        .services()
        .calendars
        .proppatch(call.ctx, call.resource, PropPatch { changes })
        .await?;
    if outcome.results.len() != updates.len() {
        return Err(EdgeProblem::new(ProblemCode::Internal));
    }
    Ok(outcome
        .results
        .into_iter()
        .map(
            |PropertyOutcome {
                 name,
                 status,
                 precondition,
             }| PropResult {
                name,
                status: status_of(status),
                error: precondition.as_ref().and_then(element_of),
            },
        )
        .collect())
}

#[cfg(test)]
mod tests {
    use davhaven_app::services::NS_DAV;

    use super::*;

    fn result(local: &str, status: u16, error: Option<PreconditionElement>) -> PropResult {
        PropResult {
            name: PropertyName::new(NS_DAV, local),
            status,
            error,
        }
    }

    #[test]
    fn results_are_grouped_by_status_in_order_of_appearance() {
        let grouped = propstats(
            &[
                result("a", 424, None),
                result("b", 403, Some(protected())),
                result("c", 424, None),
                result("d", 403, None),
            ],
            &Prefixes::default(),
        );
        let shape: Vec<(u16, Option<&str>, &str)> = grouped
            .iter()
            .map(|propstat| {
                (
                    propstat.status,
                    propstat.error.as_ref().map(PreconditionElement::as_str),
                    propstat.props.as_str(),
                )
            })
            .collect();
        assert_eq!(
            shape,
            [
                (424, None, "<D:a/><D:c/>"),
                (403, Some("<D:cannot-modify-protected-property/>"), "<D:b/>"),
                (403, None, "<D:d/>"),
            ]
        );
    }

    #[test]
    fn a_precondition_of_the_application_becomes_the_element_of_the_catalog() {
        let element = |precondition: &Precondition| element_of(precondition).map(|element| element.as_str().to_owned());
        assert_eq!(
            element(&Precondition::ValidCalendarData("not a VTIMEZONE".to_owned())).as_deref(),
            Some("<C:valid-calendar-data/>")
        );
        assert_eq!(
            element(&Precondition::CannotModifyProtectedProperty).as_deref(),
            Some("<D:cannot-modify-protected-property/>")
        );
        assert_eq!(
            element(&Precondition::SharingNotAllowed),
            None,
            "a row without an element names none"
        );
        // The properties that answer 409 for different reasons are not one group.
        let grouped = propstats(
            &[
                PropResult {
                    name: PropertyName::new(NS_DAV, "displayname"),
                    status: 409,
                    error: None,
                },
                PropResult {
                    name: PropertyName::new(davhaven_app::services::NS_CALDAV, "calendar-timezone"),
                    status: 409,
                    error: element_of(&Precondition::ValidCalendarData("not a VTIMEZONE".to_owned())),
                },
            ],
            &Prefixes::default(),
        );
        let shape: Vec<(u16, Option<&str>)> = grouped
            .iter()
            .map(|propstat| {
                (
                    propstat.status,
                    propstat.error.as_ref().map(PreconditionElement::as_str),
                )
            })
            .collect();
        assert_eq!(shape, [(409, None), (409, Some("<C:valid-calendar-data/>"))]);
    }

    #[test]
    fn names_in_other_namespaces_use_the_prefixes_of_the_document() {
        let prefixes = Prefixes::of(["urn:example:x"], 8);
        let grouped = propstats(
            &[PropResult {
                name: PropertyName::new("urn:example:x", "note"),
                status: 200,
                error: None,
            }],
            &prefixes,
        );
        assert_eq!(grouped[0].props, "<n0:note/>");
    }

    #[test]
    fn service_statuses_map_to_http_statuses() {
        assert_eq!(status_of(PropertyStatus::Applied), 200);
        assert_eq!(status_of(PropertyStatus::Forbidden), 403);
        assert_eq!(status_of(PropertyStatus::Conflict), 409);
        assert_eq!(status_of(PropertyStatus::FailedDependency), 424);
        assert_eq!(
            status_of(PropertyStatus::InsufficientStorage),
            403,
            "a limit is 403 whoever finds it (PLAN 2.15)"
        );
    }

    #[test]
    fn the_server_refuses_what_it_cannot_apply_itself() {
        assert_eq!(refusal(&Interpreted::Invalid), Some((409, None)));
        assert_eq!(refusal(&Interpreted::TooLarge), Some((403, None)));
        assert_eq!(refusal(&Interpreted::Protected), Some((403, Some(protected()))));
        assert_eq!(
            refusal(&Interpreted::Components(Vec::new())),
            Some((403, Some(protected())))
        );
        assert_eq!(
            refusal(&Interpreted::ResourceType(Vec::new())),
            Some((403, Some(protected())))
        );
        assert_eq!(refusal(&Interpreted::Change(PropertyChange::Order(None))), None);
        assert!(change_of(&Interpreted::Protected).is_none());
    }
}
