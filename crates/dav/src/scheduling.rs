//! Scheduling inbox and outbox collections (RFC 6638) and Schedule-Tag handling.
//!
//! Server-side scheduling (PLAN 2.8) delivers iTIP messages to the **inbox** of internal attendees and takes
//! free-busy requests at the **outbox**. This module is the DAV face of both:
//!
//! | Method | Resource | Answer |
//! | --- | --- | --- |
//! | `POST` | the outbox | `text/calendar` with a `VFREEBUSY` request; the answer is a `CALDAV:schedule-response` |
//! | `PROPFIND` | the inbox | the collection, with `Depth: 1` its items sorted by href |
//! | `PROPFIND` | an inbox item | `getetag`, `getcontenttype`, `getcontentlength`, `getlastmodified`, `calendar-data` |
//! | `GET`, `HEAD` | an inbox item | the iTIP message as `text/calendar`, with `ETag` |
//! | `DELETE` | an inbox item | 204; conditional like every write (the conditions are evaluated before the removal, see below) |
//! | `REPORT` | the inbox | `sync-collection` ([`crate::sync`]) and `calendar-multiget` for the items |
//!
//! Quarantined messages (replies that could not be matched, PLAN 2.8) are not in the listing; the application never
//! hands them to this layer.
//!
//! # The outbox
//!
//! A free-busy request is a `VCALENDAR` with `METHOD:REQUEST` and one `VFREEBUSY` whose `ORGANIZER` is the
//! requester and whose `ATTENDEE`s are the people asked about. RFC 6638 section 5 takes the originator from the
//! `ORGANIZER` (which has to be an address of the owner of the outbox) and the recipients from the `ATTENDEE`s of
//! the message: there are no separate request headers for them, so none is read, and the application checks the
//! organizer against the addresses of the principal. Other kinds of message are refused by the application
//! (`valid-scheduling-message`).
//!
//! The `schedule-response` has one `response` per recipient:
//!
//! | Application status | `request-status` | `calendar-data` |
//! | --- | --- | --- |
//! | `Delivered` (1.2) | `2.0;Success` | the `VFREEBUSY` reply, when there is one |
//! | `Queued` (1.0) | `1.0;Pending` | |
//! | `ImipSent` (1.1) | `1.1;Sent` | |
//! | `UnknownAddress` (3.7) | `3.7;Invalid Calendar User` | |
//! | `Failed` (5.1) | `5.1;Service unavailable` | |
//!
//! # Reading the messages
//!
//! A listing of the application carries no messages but everything else a request can ask for (the entity tag, the
//! size, the dates, the privileges), so only a request for `calendar-data` reads the messages, and reads them in
//! steps with one call of the service for each (`SchedulingService::inbox_get_many`), never message by message
//! (R14). The bulk read depends on the service: one that does not implement it answers 501 to the requests that need
//! it. The `calendar-data` selection of the request (components, properties, expansion) goes to the service with
//! the paths, which cuts the message down to it like the data of a calendar object. A step holds as many messages
//! of the largest size as `max_response_bytes` can take, so what is held at once is bounded: `PROPFIND` stops
//! reading when the messages so far exceed that size and the answer ends with the 507 entry for the request URI,
//! like any other answer that grows too large; `sync-collection` limits the members it asks for accordingly
//! ([`crate::sync`]); `calendar-multiget` cuts its answer the same way. The changed members of a `sync-collection`
//! that asks for more than the entity tag are read by path, with the same bulk read and without their messages
//! when `calendar-data` is not asked for: only the changed members are read, whatever the size of the inbox.
//!
//! # Conditional `DELETE`
//!
//! `SchedulingService::inbox_delete` takes no conditions, so the conditions of the request are evaluated here
//! against the entity tag of the item as it is read just before. An inbox item is never rewritten (the store has no
//! update of an item, only creation and deletion), so its entity tag cannot change between the comparison and the
//! deletion: unlike the notifications ([`crate::notifications`]), whose invitations are rewritten in place, there is
//! no newer version to remove by mistake.
//!
//! # Schedule-Tag
//!
//! The `Schedule-Tag` of a scheduling object resource (RFC 6638 section 3.2.10) comes from the application and is
//! passed on unchanged: as a response header of `GET`, `HEAD` and `PUT` (`methods::object`, `methods::headers`), as
//! the property `CALDAV:schedule-tag` ([`crate::props`]), and back as the condition `If-Schedule-Tag-Match` of
//! writes. The tag changes when the organizer changes the event and when an attendee changes their own copy; it
//! does not change when the server merges a reply or a `SCHEDULE-STATUS` into the organizer's copy (PLAN 2.7), so a
//! client that holds the tag can write on top of the merges. `Schedule-Reply: F` suppresses the reply an attendee's
//! `DELETE` would send.

use std::collections::HashMap;

use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
use davhaven_app::services::{
    CalendarDataSpec, ChangeKind, InboxEntry, InboxItemView, NS_CALDAV, NS_DAV, ScheduleResponse, ScheduleStatus,
    SyncChange,
};
use davhaven_domain::ResourcePath;
use davhaven_http::problem::{EdgeProblem, ProblemCode};

use crate::discovery::current_principal;
use crate::methods::collaboration::{
    Listing, conditions_of, home_owner, require_calendar, require_conditions, visible, xml_document, xml_response,
};
use crate::methods::{
    Call, Representation, data_spec, minimal_requested, multistatus_response, read_text_body, represent, status_only,
};
use crate::props::{Env, Subject, propstats};
use crate::reports::{MULTIGET_STEP, Wanted, prefixes_for, wanted_hrefs};
use crate::xml::Element;
use crate::xml::reports::parse_multiget;
use crate::xml::requests::PropRequest;
use crate::xml::write::Multistatus;

/// The media type of an inbox item: an iTIP message.
pub const ITEM_CONTENT_TYPE: &str = "text/calendar; charset=utf-8";

/// The `request-status` of one recipient in a `schedule-response` (RFC 6638 section 3.2.9 and RFC 5546).
pub const fn request_status(status: ScheduleStatus) -> &'static str {
    match status {
        ScheduleStatus::Delivered => "2.0;Success",
        ScheduleStatus::Queued => "1.0;Pending",
        ScheduleStatus::ImipSent => "1.1;Sent",
        ScheduleStatus::UnknownAddress => "3.7;Invalid Calendar User",
        ScheduleStatus::Failed => "5.1;Service unavailable",
    }
}

/// The `CALDAV:schedule-response` document that answers a request to the outbox.
pub fn schedule_response(response: &ScheduleResponse) -> String {
    xml_document(NS_CALDAV, "schedule-response", |writer| {
        for entry in &response.responses {
            writer.start(NS_CALDAV, "response");
            writer.start(NS_CALDAV, "recipient");
            writer.text_element(NS_DAV, "href", entry.recipient.as_str());
            writer.end(NS_CALDAV, "recipient");
            writer.text_element(NS_CALDAV, "request-status", request_status(entry.status));
            if let (ScheduleStatus::Delivered, Some(data)) = (entry.status, &entry.calendar_data) {
                writer.text_element(NS_CALDAV, "calendar-data", data);
            }
            writer.end(NS_CALDAV, "response");
        }
    })
}

/// Serves a `POST` to the outbox.
pub(crate) async fn outbox_post(call: &Call<'_>, body: Body) -> Result<Response, EdgeProblem> {
    require_calendar(call.headers())?;
    // The service is handed the name of the owner, not the path of the outbox, and a name says nothing about the
    // tenant of the path or whether the caller may use the outbox: only resolving the outbox checks both (404 for
    // another tenant's and another principal's outbox, PLAN 2.6). It comes before the body is read, so a stranger
    // is refused the same way whatever the body is.
    visible(call).await?;
    let message = read_text_body(
        call,
        body,
        ProblemCode::InvalidSchedulingMessage,
        "The scheduling message must be UTF-8.",
    )
    .await?;
    let owner = home_owner(call)?;
    let response = call
        .services()
        .scheduling
        .outbox_post(call.ctx, &owner, message)
        .await?;
    Ok(xml_response(schedule_response(&response)))
}

// ---------------------------------------------------------------------------------------------------------------
// Inbox items
// ---------------------------------------------------------------------------------------------------------------

async fn read(call: &Call<'_>) -> Result<InboxItemView, EdgeProblem> {
    Ok(call.services().scheduling.inbox_get(call.ctx, call.resource).await?)
}

/// Serves `GET` and `HEAD` of an inbox item.
pub(crate) async fn get(call: &Call<'_>, head: bool) -> Result<Response, EdgeProblem> {
    let InboxItemView {
        etag, created_at, data, ..
    } = read(call).await?;
    // `inbox_get` returns the message; an item without one is a defect of the service, not of the request.
    let body = data.ok_or_else(|| EdgeProblem::new(ProblemCode::Internal))?;
    represent(
        call.headers(),
        head,
        Representation {
            content_type: ITEM_CONTENT_TYPE,
            etag: &etag,
            last_modified: created_at,
            body,
        },
    )
}

/// Serves `DELETE` of an inbox item. The conditions are evaluated against the item as it is read just before:
/// `SchedulingService::inbox_delete` takes none (see `docs/interop.md`).
pub(crate) async fn delete(call: &Call<'_>) -> Result<Response, EdgeProblem> {
    if let Some(conditions) = conditions_of(call.headers())? {
        require_conditions(&conditions, &read(call).await?.etag)?;
    }
    call.services().scheduling.inbox_delete(call.ctx, call.resource).await?;
    Ok(status_only(StatusCode::NO_CONTENT))
}

/// The resource of a `PROPFIND` of one inbox item.
pub(crate) async fn propfind_item(call: &Call<'_>) -> Result<Vec<(String, Subject)>, EdgeProblem> {
    let view = read(call).await?;
    Ok(vec![(view.path.format(), Subject::InboxItem(view))])
}

// ---------------------------------------------------------------------------------------------------------------
// Reading messages in bulk
// ---------------------------------------------------------------------------------------------------------------

/// Whether a request needs the messages of the inbox items: it asks for `calendar-data`. Everything else a request
/// can ask for (the size included) is in the listing of the application, and `propname` only names the properties.
pub(crate) fn wants_data(request: &PropRequest) -> bool {
    data_spec(request).include_data
}

/// Whether answering `request` on `resource` reads inbox messages: the resource is an inbox and the request needs
/// them. A `sync-collection` that does is limited in the number of members it asks for ([`crate::sync`]).
pub(crate) fn reads_messages(resource: &ResourcePath, request: &PropRequest) -> bool {
    matches!(resource, ResourcePath::Inbox { .. }) && wants_data(request)
}

/// How many messages one call of the service reads: as many of the largest size as `max_response_bytes` holds, at
/// least one, and no more than a multiget may name or [`MULTIGET_STEP`].
fn step_size(max_response_bytes: u64, max_resource_size: u64, max_multiget_hrefs: u32) -> usize {
    let fitting = usize::try_from(max_response_bytes / max_resource_size.max(1)).unwrap_or(usize::MAX);
    let named = usize::try_from(max_multiget_hrefs).unwrap_or(usize::MAX);
    fitting.min(MULTIGET_STEP).min(named).max(1)
}

fn read_step(call: &Call<'_>) -> usize {
    step_size(
        call.limits().dav.max_response_bytes,
        call.limits().ical.max_resource_size,
        call.limits().dav.max_multiget_hrefs,
    )
}

/// The size of the message of a view, which is what a read of it holds in memory.
fn message_size(view: &InboxItemView) -> usize {
    view.data.as_ref().map_or(0, String::len)
}

/// Reads one step of items of the inbox, with one call of the service: with their messages as far as `spec` asks for
/// them, in the selection it names. An item that cannot be read any more (deleted since it was listed or named) is
/// absent from the answer.
async fn read_items(
    call: &Call<'_>,
    paths: Vec<ResourcePath>,
    spec: &CalendarDataSpec,
) -> Result<HashMap<ResourcePath, InboxItemView>, EdgeProblem> {
    let entries = call
        .services()
        .scheduling
        .inbox_get_many(call.ctx, call.resource, paths, spec)
        .await?;
    Ok(entries
        .into_iter()
        .filter_map(|entry| match entry {
            InboxEntry::Found(view) => Some((view.path.clone(), view)),
            // What is missing, and whatever a later version of the contract adds, is no item to show.
            _ => None,
        })
        .collect())
}

/// The items of the inbox for `Depth: 1`, sorted by href. The messages are read only when the request needs them,
/// in the order of the hrefs and in steps, and reading stops when the messages so far exceed `max_response_bytes`:
/// the list is then a prefix of the inbox and says so ([`Listing::truncated`]), and the client synchronizes the rest
/// in smaller steps with `sync-collection` and `calendar-multiget`.
///
/// The `PROPFIND` handler has resolved the inbox with the tenant of the request before this is called; the listing
/// names the home owner alone.
pub(crate) async fn propfind_members(call: &Call<'_>, request: &PropRequest) -> Result<Listing, EdgeProblem> {
    let owner = home_owner(call)?;
    let mut listed: Vec<(String, InboxItemView)> = call
        .services()
        .scheduling
        .inbox_list(call.ctx, &owner)
        .await?
        .into_iter()
        .map(|item| (item.path.format(), item))
        .collect();
    listed.sort_by(|a, b| a.0.cmp(&b.0));
    if !wants_data(request) {
        return Ok(Listing::complete(
            listed
                .into_iter()
                .map(|(href, item)| (href, Subject::InboxItem(item)))
                .collect(),
        ));
    }
    let spec = data_spec(request);
    let budget = call.response_budget();
    let mut loaded = 0_usize;
    let mut truncated = false;
    let mut members = Vec::with_capacity(listed.len());
    for step in listed.chunks(read_step(call)) {
        if loaded > budget {
            truncated = true;
            break;
        }
        let mut read = read_items(call, step.iter().map(|(_, item)| item.path.clone()).collect(), &spec).await?;
        for (href, item) in step {
            // Deleted between the listing and the read: it is not in the answer, as if the listing were later.
            let Some(view) = read.remove(&item.path) else {
                continue;
            };
            loaded = loaded.saturating_add(message_size(&view));
            members.push((href.clone(), Subject::InboxItem(view)));
        }
    }
    Ok(Listing { members, truncated })
}

/// The inbox items `sync-collection` reports as changed, with the properties of an inbox item (the messages when
/// the request needs them): read by path with the bulk read, so that what is read is the changed members and not the
/// inbox, and without their messages when `calendar-data` is not asked for.
///
/// `ObjectService::sync` has resolved the inbox with the tenant of the request before this is called. The answer of
/// a synchronization cannot be cut anywhere (its token stands for everything it reports), so what is read is
/// bounded by the number of members the report asked for ([`crate::sync`] limits it for requests that read
/// messages); exceeding `max_response_bytes` nevertheless is refused rather than held.
pub(crate) async fn sync_subjects(
    call: &Call<'_>,
    changes: &[SyncChange],
    select: &PropRequest,
) -> Result<HashMap<String, Subject>, EdgeProblem> {
    let wanted: Vec<ResourcePath> = changes
        .iter()
        .filter(|change| change.kind == ChangeKind::Upsert)
        .map(|change| change.path.clone())
        .collect();
    // Nothing changed or only deletions: there is nothing to read.
    if wanted.is_empty() {
        return Ok(HashMap::new());
    }
    let spec = data_spec(select);
    let step = if spec.include_data {
        read_step(call)
    } else {
        // No message is held: a step is as large as a multiget may be.
        MULTIGET_STEP.min(
            usize::try_from(call.limits().dav.max_multiget_hrefs)
                .unwrap_or(usize::MAX)
                .max(1),
        )
    };
    let budget = call.response_budget();
    let mut loaded = 0_usize;
    let mut found = HashMap::new();
    for paths in wanted.chunks(step) {
        for (path, view) in read_items(call, paths.to_vec(), &spec).await? {
            loaded = loaded.saturating_add(message_size(&view));
            if loaded > budget {
                return Err(EdgeProblem::new(ProblemCode::TooManyMatches));
            }
            found.insert(path.format(), Subject::InboxItem(view));
        }
    }
    Ok(found)
}

/// Whether `path` is an item of the inbox `inbox`.
fn is_item_of(inbox: &ResourcePath, path: &ResourcePath) -> bool {
    matches!(inbox, ResourcePath::Inbox { .. }) && path.parent().as_ref() == Some(inbox)
}

/// Serves a `calendar-multiget` of the inbox: the named items, each with the properties of an inbox item. An href
/// that names no item of this inbox (another inbox's item, a calendar object, garbage) is a 404 entry that says
/// nothing more, like in a calendar.
///
/// The inbox has to be visible, whatever the request says: that is judged first, so that a stranger gets the same
/// 404 for every body and a refusal of the body never tells that the inbox exists.
pub(crate) async fn inbox_multiget(call: &Call<'_>, root: &Element) -> Result<Response, EdgeProblem> {
    visible(call).await?;
    let request = parse_multiget(root)?;
    let most = usize::try_from(call.limits().dav.max_multiget_hrefs).unwrap_or(usize::MAX);
    if request.hrefs.len() > most {
        return Err(EdgeProblem::new(ProblemCode::TooManyHrefs));
    }
    let minimal = minimal_requested(call.headers());
    let current = current_principal(call, &request.select).await?;
    let prefixes = prefixes_for(call, &request.select);
    let env = Env {
        services: call.services(),
        current: current.as_ref(),
        prefixes: &prefixes,
    };
    let wanted = wanted_hrefs(&request.hrefs);
    let spec = data_spec(&request.select);
    let budget = call.response_budget();
    let mut multistatus = Multistatus::with_prefixes(&prefixes);
    let mut cut = false;
    for step in wanted.chunks(read_step(call)) {
        if multistatus.len() > budget {
            cut = true;
            break;
        }
        let paths: Vec<ResourcePath> = step
            .iter()
            .filter_map(|(_, entry)| match entry {
                Wanted::Resource(path) if is_item_of(call.resource, path) => Some(path.clone()),
                Wanted::Resource(_) | Wanted::Garbage => None,
            })
            .collect();
        let mut read = if paths.is_empty() {
            HashMap::new()
        } else {
            read_items(call, paths, &spec).await?
        };
        // The answers are matched to the hrefs by resource, not by position: a service may order or merge them.
        for (href, entry) in step {
            let found = match entry {
                Wanted::Resource(path) => read.remove(path),
                Wanted::Garbage => None,
            };
            if let Some(view) = found {
                multistatus.response(
                    href,
                    &propstats(&env, &Subject::InboxItem(view), &request.select, minimal),
                );
            } else {
                multistatus.status_response(href, 404, None);
            }
        }
    }
    if cut {
        call.truncated(&mut multistatus);
    }
    Ok(multistatus_response(multistatus.finish(), minimal))
}

#[cfg(test)]
mod tests {
    use davhaven_app::services::RecipientResponse;
    use davhaven_domain::{CalendarUserAddress, DavLimits, PrincipalName, TenantSlug};

    use super::*;
    use crate::testing::fixture;
    use crate::xml::parse;
    use crate::xml::requests::PropList;
    use crate::xml::write::Prefixes;

    fn recipient(text: &str, status: ScheduleStatus, data: Option<&str>) -> RecipientResponse {
        RecipientResponse {
            recipient: CalendarUserAddress::parse(text).unwrap(),
            status,
            calendar_data: data.map(str::to_owned),
        }
    }

    #[test]
    fn every_schedule_status_has_a_request_status() {
        let expected = [
            (ScheduleStatus::Delivered, "2.0;Success"),
            (ScheduleStatus::Queued, "1.0;Pending"),
            (ScheduleStatus::ImipSent, "1.1;Sent"),
            (ScheduleStatus::UnknownAddress, "3.7;Invalid Calendar User"),
            (ScheduleStatus::Failed, "5.1;Service unavailable"),
        ];
        for (status, text) in expected {
            assert_eq!(request_status(status), text, "{status:?}");
        }
    }

    #[test]
    fn a_schedule_response_has_one_response_per_recipient() {
        let reply = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VFREEBUSY\r\nEND:VFREEBUSY\r\nEND:VCALENDAR\r\n";
        let document = schedule_response(&ScheduleResponse {
            responses: vec![
                recipient("mailto:ben@acme.example", ScheduleStatus::Delivered, Some(reply)),
                recipient(
                    "mailto:ghost@acme.example",
                    ScheduleStatus::UnknownAddress,
                    Some("ignored"),
                ),
                recipient("mailto:guest@elsewhere.example", ScheduleStatus::Delivered, None),
            ],
        });
        let root = parse(document.as_bytes(), &DavLimits::default()).unwrap();
        assert!(root.is(NS_CALDAV, "schedule-response"), "{document}");
        let responses: Vec<&Element> = root.children_named(NS_CALDAV, "response").collect();
        assert_eq!(responses.len(), 3);
        let texts = |response: &Element| {
            (
                response
                    .child(NS_CALDAV, "recipient")
                    .and_then(|recipient| recipient.child(NS_DAV, "href"))
                    .map(Element::text)
                    .unwrap(),
                response.child(NS_CALDAV, "request-status").map(Element::text).unwrap(),
                response.child(NS_CALDAV, "calendar-data").map(Element::text),
            )
        };
        assert_eq!(
            texts(responses[0]),
            (
                "mailto:ben@acme.example".to_owned(),
                "2.0;Success".to_owned(),
                Some(reply.to_owned())
            ),
            "calendar data survives the XML with its CRLF line ends"
        );
        assert_eq!(
            texts(responses[1]),
            (
                "mailto:ghost@acme.example".to_owned(),
                "3.7;Invalid Calendar User".to_owned(),
                None
            ),
            "only a delivered answer carries data"
        );
        assert_eq!(texts(responses[2]).2, None);
        let empty = schedule_response(&ScheduleResponse::default());
        assert!(
            parse(empty.as_bytes(), &DavLimits::default())
                .unwrap()
                .elements()
                .next()
                .is_none()
        );
    }

    #[test]
    fn only_the_inbox_that_holds_an_item_names_it() {
        let tenant = TenantSlug::parse("acme").unwrap();
        let anna = PrincipalName::parse("anna").unwrap();
        let ben = PrincipalName::parse("ben").unwrap();
        let inbox = ResourcePath::Inbox {
            tenant: tenant.clone(),
            principal: anna.clone(),
        };
        let item = |principal: &PrincipalName| {
            ResourcePath::parse(&format!("/dav/calendars/acme/{principal}/inbox/a.ics")).unwrap()
        };
        assert!(is_item_of(&inbox, &item(&anna)));
        assert!(!is_item_of(&inbox, &item(&ben)));
        assert!(!is_item_of(
            &inbox,
            &ResourcePath::parse("/dav/calendars/acme/anna/work/a.ics").unwrap()
        ));
        assert!(!is_item_of(&ResourcePath::Root, &item(&anna)));
    }

    #[test]
    fn messages_are_read_only_for_requests_that_need_them() {
        use davhaven_app::services::PropertyName;
        let named = |local: &str, data: bool| {
            PropRequest::Prop(PropList {
                names: vec![PropertyName::new(NS_DAV, local)],
                calendar_data: data.then(davhaven_app::services::Projection::default),
            })
        };
        assert!(!wants_data(&named("getetag", false)));
        assert!(!wants_data(&named("getcontenttype", false)));
        assert!(
            !wants_data(&named("getcontentlength", false)),
            "the size is in the listing of the application"
        );
        assert!(wants_data(&named("getetag", true)));
        // `propname` names the properties and `allprop` has the DAV: ones: neither needs a message, which only
        // `calendar-data` does.
        assert!(!wants_data(&PropRequest::PropName));
        assert!(!wants_data(&PropRequest::AllProp(PropList::default())));
        assert!(wants_data(&PropRequest::AllProp(PropList {
            names: Vec::new(),
            calendar_data: Some(davhaven_app::services::Projection::default()),
        })));
    }

    #[test]
    fn only_a_request_to_the_inbox_that_needs_messages_reads_them() {
        use davhaven_app::services::PropertyName;
        let inbox = ResourcePath::parse("/dav/calendars/acme/anna/inbox/").unwrap();
        let notifications = ResourcePath::parse("/dav/calendars/acme/anna/notifications/").unwrap();
        let data = PropRequest::Prop(PropList {
            names: vec![PropertyName::new(NS_DAV, "getetag")],
            calendar_data: Some(davhaven_app::services::Projection::default()),
        });
        let sizes = PropRequest::Prop(PropList {
            names: vec![
                PropertyName::new(NS_DAV, "getetag"),
                PropertyName::new(NS_DAV, "getcontentlength"),
            ],
            calendar_data: None,
        });
        assert!(reads_messages(&inbox, &data));
        assert!(
            !reads_messages(&inbox, &sizes),
            "the size comes with the listing: an initial synchronization that asks for it is not refused for it"
        );
        assert!(
            !reads_messages(&notifications, &data),
            "a notification has everything in the listing"
        );
    }

    #[test]
    fn a_step_holds_what_the_response_budget_can_take_of_the_largest_messages() {
        let mib = 1024 * 1024;
        // 32 MiB of answer, 1 MiB per message: 32 at once.
        assert_eq!(step_size(32 * mib, mib, 1000), 32);
        // Small messages are read a hundred at a time at most, like the objects of a multiget.
        assert_eq!(step_size(32 * mib, 1024, 1000), MULTIGET_STEP);
        // A multiget never names more than the configured number of hrefs.
        assert_eq!(step_size(32 * mib, 1024, 10), 10);
        // A message larger than the whole answer is still read, alone; so is a configuration with zeros.
        assert_eq!(step_size(mib, 2 * mib, 1000), 1);
        assert_eq!(step_size(0, 0, 0), 1);
        assert_eq!(step_size(u64::MAX, 0, u32::MAX), MULTIGET_STEP);
    }

    #[test]
    fn the_answer_to_a_free_busy_request_is_the_document_clients_read() {
        let reply = fixture("outbox-freebusy-request.ics");
        // A request of Apple Calendar is an iTIP message with CRLF line ends: the fixture is byte-exact.
        assert!(reply.contains("METHOD:REQUEST\r\nBEGIN:VFREEBUSY\r\n"));
        let answer = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Davhaven//EN\r\nMETHOD:REPLY\r\nBEGIN:VFREEBUSY\r\n\
                      UID:1D7A1C2B-5E1B-4B3C-8D49-0A4F5A6E8C11\r\nDTSTAMP:20270301T090000Z\r\n\
                      DTSTART:20270301T000000Z\r\nDTEND:20270302T000000Z\r\nORGANIZER:mailto:anna@acme.example\r\n\
                      ATTENDEE:mailto:ben@acme.example\r\nFREEBUSY;FBTYPE=BUSY:20270301T100000Z/20270301T110000Z\r\n\
                      END:VFREEBUSY\r\nEND:VCALENDAR\r\n";
        let document = schedule_response(&ScheduleResponse {
            responses: vec![
                recipient("mailto:ben@acme.example", ScheduleStatus::Delivered, Some(answer)),
                recipient("mailto:ghost@acme.example", ScheduleStatus::UnknownAddress, None),
            ],
        });
        assert_eq!(document, fixture("schedule-response-freebusy.xml"));
        // What a client reads back is the iCalendar text it was sent, carriage returns included.
        let root = parse(document.as_bytes(), &DavLimits::default()).unwrap();
        let data = root
            .elements()
            .next()
            .and_then(|response| response.child(NS_CALDAV, "calendar-data"))
            .map(Element::text)
            .unwrap();
        assert_eq!(data, answer);
    }

    #[test]
    fn the_item_a_client_fetches_by_multiget_has_its_entity_tag_and_its_message() {
        use chrono::{TimeZone, Utc};
        use davhaven_app::AppServices;
        use davhaven_app_fake::AppServicesExt as _;
        use davhaven_domain::{ETag, InboxItemId};
        use uuid::Uuid;

        let message = fixture("outbox-freebusy-request.ics");
        let root = parse(fixture("inbox-multiget.xml").as_bytes(), &DavLimits::default()).unwrap();
        let request = parse_multiget(&root).unwrap();
        let item = InboxItemView {
            path: ResourcePath::parse("/dav/calendars/acme/anna/inbox/request-1.ics").unwrap(),
            id: InboxItemId::from_uuid(Uuid::from_u128(1)),
            etag: ETag::from_bytes(message.as_bytes()),
            size: u64::try_from(message.len()).unwrap(),
            data: Some(message.clone()),
            privileges: davhaven_domain::privileges(
                davhaven_domain::Access::Owner,
                davhaven_domain::CalendarKind::Personal,
                davhaven_domain::ResourceKind::InboxItem,
            ),
            created_at: Utc.with_ymd_and_hms(2027, 3, 1, 9, 0, 0).unwrap(),
        };
        let services = AppServices::fake();
        let prefixes = Prefixes::default();
        let env = Env {
            services: &services,
            current: None,
            prefixes: &prefixes,
        };
        let mut multistatus = Multistatus::with_prefixes(&prefixes);
        multistatus.response(
            &item.path.format(),
            &propstats(&env, &Subject::InboxItem(item.clone()), &request.select, false),
        );
        let document = multistatus.finish();
        let answer = parse(document.as_bytes(), &DavLimits::default()).unwrap();
        let prop = answer
            .child(NS_DAV, "response")
            .and_then(|response| response.child(NS_DAV, "propstat"))
            .and_then(|propstat| propstat.child(NS_DAV, "prop"))
            .unwrap();
        assert_eq!(prop.child(NS_DAV, "getetag").unwrap().text(), item.etag.as_str());
        assert_eq!(
            prop.child(NS_CALDAV, "calendar-data").unwrap().text(),
            message,
            "the message arrives with its carriage returns: {document}"
        );
    }

    #[test]
    fn the_multiget_of_clients_names_items_of_the_inbox_and_things_that_are_not() {
        let root = parse(fixture("inbox-multiget.xml").as_bytes(), &DavLimits::default()).unwrap();
        let request = parse_multiget(&root).unwrap();
        let inbox = ResourcePath::parse("/dav/calendars/acme/anna/inbox/").unwrap();
        let kinds: Vec<(String, bool)> = wanted_hrefs(&request.hrefs)
            .into_iter()
            .map(|(href, entry)| match entry {
                Wanted::Resource(path) => (href, is_item_of(&inbox, &path)),
                Wanted::Garbage => (href, false),
            })
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("/dav/calendars/acme/anna/inbox/request-1.ics".to_owned(), true),
                ("/dav/calendars/acme/anna/work/standup.ics".to_owned(), false),
                ("/dav/calendars/acme/ben/inbox/request-1.ics".to_owned(), false),
                ("/somewhere/else.ics".to_owned(), false),
            ],
            "only an item of this inbox is an item: another inbox's, a calendar object and a stranger are not"
        );
    }
}
