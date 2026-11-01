//! The requests of the permission matrix on the DAV surface.
//!
//! Every operation of the matrix is performed with the requests a CalDAV client sends for it: the methods (`PROPFIND`,
//! `GET`, `PUT`, `DELETE`, `MOVE`, `COPY`, `MKCALENDAR`, `MKCOL`, `PROPPATCH`, `POST`) and the reports (`calendar-query`,
//! `calendar-multiget`, `sync-collection`, `free-busy-query`). An operation that clients perform with several
//! requests (listing objects) is performed with all of them, and every request must give the expected outcome.
//!
//! The paths are those the actor uses: its own binding for a calendar it has one for, the home of the calendar's owner
//! otherwise (see [`Addressing`]).
//!
//! The writes also carry conditions that are false (`If-Match` with a tag that nothing has, `If-None-Match: *` on something that
//! exists, `If-Schedule-Tag-Match`): where the case is allowed the answer is 412, and where it is refused the refusal comes
//! first (RFC 9110 section 13.2.1: a condition is evaluated only when the answer would otherwise be a success), so a stale
//! condition cannot be used to find out whether a resource exists.

use davhaven_fixtures::{ActorRole, CalendarRole, EventBuilder, When};

use super::{Addressing, MatrixEnv, Plan, Probe, request};
use crate::busy;
use crate::handles::Actor;
use crate::matrix::{Case, Expectation, Operation, Resolution, Surface};
use crate::transport::TestRequest;
use crate::xml::Document;

const XML: &str = "application/xml; charset=utf-8";
const ICS: &str = "text/calendar; charset=utf-8";

/// Why `DELETE` of a bound collection has no request of the operation `delete_calendar`: it removes the binding.
pub const DELETE_IS_REMOVE_BINDING: &str =
    "DELETE of a bound collection by a principal that does not own it removes the binding (remove_binding)";

/// Why `DELETE` of a collection has no request of the operation `remove_binding`: its owner deletes the calendar.
pub const DELETE_IS_DELETE_CALENDAR: &str =
    "DELETE of a collection by its owner deletes the calendar (delete_calendar)";

const PROPFIND_COLLECTION: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<D:propfind xmlns:D="DAV:"><D:prop><D:displayname/><D:resourcetype/></D:prop></D:propfind>"#;

const PROPFIND_OBJECT: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<D:propfind xmlns:D="DAV:"><D:prop><D:getetag/><D:getcontenttype/></D:prop></D:propfind>"#;

const PROPFIND_PRINCIPAL: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<D:propfind xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><D:prop><D:displayname/><C:calendar-home-set/></D:prop></D:propfind>"#;

const CALENDAR_QUERY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<C:calendar-query xmlns:C="urn:ietf:params:xml:ns:caldav" xmlns:D="DAV:">
  <D:prop><D:getetag/><C:calendar-data/></D:prop>
  <C:filter><C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT"/></C:comp-filter></C:filter>
</C:calendar-query>"#;

const SYNC_COLLECTION: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<D:sync-collection xmlns:D="DAV:">
  <D:sync-token/><D:sync-level>1</D:sync-level><D:prop><D:getetag/></D:prop>
</D:sync-collection>"#;

const FREE_BUSY_REPORT: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<C:free-busy-query xmlns:C="urn:ietf:params:xml:ns:caldav"><C:time-range start="20270301T000000Z" end="20270401T000000Z"/></C:free-busy-query>"#;

const PROPPATCH_BINDING: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<A:propertyupdate xmlns:A="DAV:"><A:set><A:prop>
<D:calendar-color xmlns:D="http://apple.com/ns/ical/">#44A703FF</D:calendar-color>
</A:prop></A:set></A:propertyupdate>"#;

const PROPPATCH_SHARED: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<A:propertyupdate xmlns:A="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><A:set><A:prop>
<C:calendar-description>Changed by the matrix</C:calendar-description>
</A:prop></A:set></A:propertyupdate>"#;

/// An extended `MKCOL` (RFC 5689) that makes a calendar collection.
const MKCOL_CALENDAR: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<D:mkcol xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><D:set><D:prop>
<D:resourcetype><D:collection/><C:calendar/></D:resourcetype><D:displayname>Created by the matrix</D:displayname>
</D:prop></D:set></D:mkcol>"#;

/// The `CS:share` request that invites the other user (read access).
fn share_request(address: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<CS:share xmlns:CS="http://calendarserver.org/ns/">
  <CS:set><D:href xmlns:D="DAV:">{address}</D:href><CS:read/></CS:set>
</CS:share>"#
    )
}

/// The `CS:invite-reply` that accepts the invitation `uid` to the calendar at `host_url`.
fn invite_reply(uid: &str, host_url: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<CS:invite-reply xmlns:CS="http://calendarserver.org/ns/">
  <CS:invite-accepted/>
  <CS:hosturl><D:href xmlns:D="DAV:">{host_url}</D:href></CS:hosturl>
  <CS:in-reply-to>{uid}</CS:in-reply-to>
</CS:invite-reply>"#
    )
}

/// The `calendar-multiget` for one resource.
fn multiget(href: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<C:calendar-multiget xmlns:C="urn:ietf:params:xml:ns:caldav" xmlns:D="DAV:">
  <D:prop><D:getetag/><C:calendar-data/></D:prop><D:href>{href}</D:href>
</C:calendar-multiget>"#
    )
}

/// A VFREEBUSY request of `organizer` for `attendee`.
fn free_busy_message(seq: usize, organizer: &str, attendee: &str) -> String {
    [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//Davhaven//matrix//EN",
        "METHOD:REQUEST",
        "BEGIN:VFREEBUSY",
        &format!("UID:mx-fb-{seq}@acme.example"),
        "DTSTAMP:20270101T000000Z",
        "DTSTART:20270301T000000Z",
        "DTEND:20270401T000000Z",
        &format!("ORGANIZER:{organizer}"),
        &format!("ATTENDEE:{attendee}"),
        "END:VFREEBUSY",
        "END:VCALENDAR",
        "",
    ]
    .join("\r\n")
}

/// A new event for `PUT`.
fn new_event(seq: usize) -> String {
    EventBuilder::event(&format!("mx-{seq}@acme.example"))
        .summary("Created by the matrix")
        .starts(When::utc(2027, 6, 1, 9, 0))
        .ends(When::utc(2027, 6, 1, 10, 0))
        .build()
}

/// The fixture event of the calendar with another summary: an update that keeps the `UID` and the times.
fn changed_event(at: Addressing<'_>, calendar: CalendarRole) -> String {
    let event = at.event(calendar);
    event
        .ics
        .replace(&format!("SUMMARY:{}", event.summary), "SUMMARY:Changed by the matrix")
}

fn put(actor: &Actor, target: &str, ics: &str) -> TestRequest {
    request(actor, "PUT", target).content(ICS, ics.to_owned())
}

fn propfind(actor: &Actor, target: &str, depth: &str, body: &str) -> TestRequest {
    request(actor, "PROPFIND", target)
        .header("depth", depth)
        .content(XML, body.to_owned())
}

fn report(actor: &Actor, target: &str, depth: &str, body: &str) -> TestRequest {
    request(actor, "REPORT", target)
        .header("depth", depth)
        .content(XML, body.to_owned())
}

/// The members of a collection as `actor` lists them: the hrefs below the collection itself.
pub async fn list_hrefs(env: &dyn MatrixEnv, actor: &Actor, collection: &str) -> Vec<String> {
    // A listing reads: when the host is too busy to answer it, it is asked again.
    let (sent, _) = busy::send_repeatable(
        env.transport().as_ref(),
        &propfind(actor, collection, "1", PROPFIND_OBJECT),
    )
    .await;
    let Ok(response) = sent else {
        return Vec::new();
    };
    let Ok(document) = Document::parse(&response.text()) else {
        return Vec::new();
    };
    document
        .multistatus()
        .map(|entries| {
            entries
                .into_iter()
                .map(|entry| entry.href)
                .filter(|href| href.trim_end_matches('/') != collection.trim_end_matches('/'))
                .collect()
        })
        .unwrap_or_default()
}

/// Delivers an invitation to the owner of the world (an event of another user that names the owner as an attendee) and
/// returns the resource name of the resulting item in the owner's scheduling inbox.
pub async fn deliver_inbox_item(env: &dyn MatrixEnv, seq: usize) -> Option<String> {
    let at = Addressing::new(env.world());
    let organizer = env.book().actor(ActorRole::OtherUser, Surface::Dav, None)?;
    let owner = env.book().actor(ActorRole::Owner, Surface::Dav, None)?;
    let other = at.actor_address(ActorRole::OtherUser)?;
    let owner_address = at.actor_address(ActorRole::Owner)?;
    let target = format!("{}invitation-{seq}.ics", at.dav_own_personal(ActorRole::OtherUser)?);
    let ics = EventBuilder::event(&format!("invitation-{seq}@acme.example"))
        .summary("Invitation of the matrix")
        .starts(When::utc(2027, 6, 2, 9, 0))
        .ends(When::utc(2027, 6, 2, 10, 0))
        .organizer(davhaven_fixtures::Organizer::new(&other))
        .attendee(davhaven_fixtures::Attendee::new(&owner_address))
        .build();
    let (sent, _) = busy::send_preparation(env.transport().as_ref(), &put(&organizer, &target, &ics)).await;
    let response = sent.ok()?;
    if !response.status.is_success() {
        return None;
    }
    let inbox = format!("{}inbox/", at.dav_own_home(ActorRole::Owner)?);
    list_hrefs(env, &owner, &inbox).await.into_iter().find(|href| {
        std::path::Path::new(href)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("ics"))
    })
}

/// The reads of one resource of a home that a client does: `GET`, `HEAD` and `PROPFIND`.
fn reads_of(actor: &Actor, what: &str, target: &str) -> Vec<Probe> {
    vec![
        Probe::new(format!("GET of {what}"), request(actor, "GET", target)),
        Probe::new(format!("HEAD of {what}"), request(actor, "HEAD", target)),
        Probe::new(
            format!("PROPFIND of {what}"),
            propfind(actor, target, "0", PROPFIND_OBJECT),
        ),
    ]
}

/// Plans a case on DAV.
#[expect(
    clippy::too_many_lines,
    reason = "one arm per operation of the matrix, each a short list of requests"
)]
pub async fn plan(env: &dyn MatrixEnv, case: &Case, resolution: &Resolution, seq: usize) -> Plan {
    let at = Addressing::new(env.world());
    let Some(actor) = env.book().actor(case.actor, Surface::Dav, case.token_scope.as_deref()) else {
        return Plan::Skip(format!("the role `{}` has no credential on DAV", case.actor));
    };
    let role = case.calendar;
    let collection = at.dav_collection_path(case.actor, role);
    let object = at.dav_object_path(case.actor, role);
    let owner_home = at.dav_owner_home(role);
    let own_home = at
        .dav_own_home(case.actor)
        .unwrap_or_else(|| at.dav_owner_home(CalendarRole::Personal));
    // Where the actor keeps the resources it moves or copies from and to: its own personal calendar, or when that is
    // the calendar under test (a copy into the same calendar clashes with the UID) the other calendar of the owner.
    let own_personal = format!("{own_home}personal/");
    let scratch = if collection == own_personal {
        format!("{own_home}projects/")
    } else {
        own_personal
    };
    let allowed = resolution.expectation == Expectation::Allow;
    let event = at.event(role);
    let uid = event.uid.as_str().to_owned();
    let summary = event.summary.clone();
    let name = event.uri.as_str().to_owned();

    let probes = match case.operation {
        Operation::ReadCollection => vec![Probe::new(
            "PROPFIND of the collection",
            propfind(&actor, &collection, "0", PROPFIND_COLLECTION),
        )],
        Operation::ListObjects => vec![
            Probe::new(
                "PROPFIND of the members",
                propfind(&actor, &collection, "1", PROPFIND_OBJECT),
            )
            .showing(&[&name]),
            Probe::new("calendar-query", report(&actor, &collection, "1", CALENDAR_QUERY)).showing(&[&uid]),
            Probe::new(
                "calendar-multiget",
                report(&actor, &collection, "1", &multiget(&object)),
            )
            .showing(&[&uid]),
            Probe::new("sync-collection", report(&actor, &collection, "0", SYNC_COLLECTION)).showing(&[&name]),
            Probe::new("free-busy-query", report(&actor, &collection, "1", FREE_BUSY_REPORT)),
        ],
        Operation::ReadObject => vec![
            Probe::new("GET", request(&actor, "GET", &object)).showing(&[&uid, &summary]),
            Probe::new("HEAD", request(&actor, "HEAD", &object)),
            Probe::new(
                "PROPFIND of the object",
                propfind(&actor, &object, "0", PROPFIND_OBJECT),
            ),
        ],
        Operation::FreeBusyQuery => {
            let target = format!("{own_home}outbox/");
            let organizer = at
                .actor_address(case.actor)
                .or_else(|| at.actor_address(ActorRole::Owner))
                .unwrap_or_default();
            let attendee = at
                .owner_address(role)
                .unwrap_or_else(|| format!("/dav/principals/{}/{}/", at.tenant(role), at.owner(role)));
            let probe = Probe::new(
                "POST of a VFREEBUSY to the own outbox",
                request(&actor, "POST", &target).content(ICS, free_busy_message(seq, &organizer, &attendee)),
            );
            // Somebody of another tenant is answered, and the answer shows no busy time of the people of this one.
            vec![if case.actor == ActorRole::OtherTenantUser {
                probe.without_busy_time()
            } else {
                probe
            }]
        }
        Operation::CreateObject => {
            let target = at.dav_new_object_path(case.actor, role, &format!("mx-{seq}.ics"));
            vec![Probe::new(
                "PUT of a new resource",
                put(&actor, &target, &new_event(seq)).header("if-none-match", "*"),
            )]
        }
        Operation::UpdateObject => vec![
            // A condition that is false does not matter to somebody who may not write, and stops somebody who may.
            Probe::new(
                "PUT with a stale If-Match",
                put(&actor, &object, &changed_event(at, role)).header("if-match", "\"stale-etag\""),
            )
            .stale(),
            Probe::new(
                "PUT with a stale If-Schedule-Tag-Match",
                put(&actor, &object, &changed_event(at, role))
                    .header("if-schedule-tag-match", "\"stale-schedule-tag\""),
            )
            .stale(),
            Probe::new(
                "PUT over the event with If-None-Match: * (a stale condition, the event exists)",
                put(&actor, &object, &changed_event(at, role)).header("if-none-match", "*"),
            )
            .stale(),
            Probe::new("PUT over the event", put(&actor, &object, &changed_event(at, role))),
        ],
        Operation::DeleteObject => vec![
            Probe::new(
                "DELETE of the event with a stale If-Match",
                request(&actor, "DELETE", &object).header("if-match", "\"stale-etag\""),
            )
            .stale(),
            Probe::new("DELETE of the event", request(&actor, "DELETE", &object)),
        ],
        Operation::MoveObjectFrom => vec![Probe::new(
            "MOVE of the event to the own calendar",
            request(&actor, "MOVE", &object).header("destination", &format!("{scratch}moved-{seq}.ics")),
        )],
        Operation::CopyObjectFrom => vec![Probe::new(
            "COPY of the event to the own calendar",
            request(&actor, "COPY", &object).header("destination", &format!("{scratch}copied-{seq}.ics")),
        )],
        Operation::MoveObjectTo => {
            let source = format!("{scratch}source-{seq}.ics");
            let target = at.dav_new_object_path(case.actor, role, &format!("moved-{seq}.ics"));
            vec![
                Probe::new(
                    "MOVE of an own event into the calendar",
                    request(&actor, "MOVE", &source).header("destination", &target),
                )
                .after(put(&actor, &source, &new_event(seq))),
            ]
        }
        Operation::CopyObjectTo => {
            let source = format!("{scratch}source-{seq}.ics");
            let target = at.dav_new_object_path(case.actor, role, &format!("copied-{seq}.ics"));
            vec![
                Probe::new(
                    "COPY of an own event into the calendar",
                    request(&actor, "COPY", &source).header("destination", &target),
                )
                .after(put(&actor, &source, &new_event(seq))),
            ]
        }
        Operation::PropPatchBinding => vec![Probe::new(
            "PROPPATCH of a per-binding property",
            request(&actor, "PROPPATCH", &collection).content(XML, PROPPATCH_BINDING.to_owned()),
        )],
        Operation::UpdateCalendar => vec![Probe::new(
            "PROPPATCH of a shared property",
            request(&actor, "PROPPATCH", &collection).content(XML, PROPPATCH_SHARED.to_owned()),
        )],
        Operation::CreateCalendar => vec![
            Probe::new(
                "MKCALENDAR in the home of the calendar's owner",
                request(&actor, "MKCALENDAR", &format!("{owner_home}mx-{seq}/")),
            ),
            Probe::new(
                "MKCOL (extended) in the home of the calendar's owner",
                request(&actor, "MKCOL", &format!("{owner_home}mx-{seq}-col/")).content(XML, MKCOL_CALENDAR.to_owned()),
            ),
        ],
        Operation::DeleteCalendar => {
            if at.is_bound(case.actor, role) && at.owner(role) != case.actor.principal_name().unwrap_or_default() {
                return Plan::NotApplicable(DELETE_IS_REMOVE_BINDING.to_owned());
            }
            vec![Probe::new(
                "DELETE of the collection",
                request(&actor, "DELETE", &collection),
            )]
        }
        Operation::RemoveBinding => {
            if at.owner(role) == case.actor.principal_name().unwrap_or_default() {
                return Plan::NotApplicable(DELETE_IS_DELETE_CALENDAR.to_owned());
            }
            vec![Probe::new(
                "DELETE of the binding",
                request(&actor, "DELETE", &collection),
            )]
        }
        Operation::ShareCalendar => {
            let Some(address) = at.actor_address(ActorRole::OtherUser) else {
                return Plan::Skip("the world has no other user to share with".to_owned());
            };
            vec![Probe::new(
                "POST of a CS:share request",
                request(&actor, "POST", &collection).content(XML, share_request(&address)),
            )]
        }
        Operation::ReplyInvite => {
            let host = format!("{}{}/", at.dav_owner_home(CalendarRole::Shared), at.slug(role));
            let uid = if role == CalendarRole::Shared {
                match env.invitation_uid().await {
                    Ok(Some(uid)) => uid,
                    Ok(None) => return Plan::Skip("the pending sharee has no invitation".to_owned()),
                    Err(error) => return Plan::Skip(format!("the invitation cannot be found: {error}")),
                }
            } else {
                "00000000-0000-4000-8000-0000000000aa".to_owned()
            };
            vec![Probe::new(
                "POST of a CS:invite-reply to the own home",
                request(&actor, "POST", &own_home).content(XML, invite_reply(&uid, &host)),
            )]
        }
        Operation::ReadInbox => {
            let inbox = format!("{owner_home}inbox/");
            let item = if allowed {
                match deliver_inbox_item(env, seq).await {
                    Some(item) => item,
                    None => return Plan::Skip("no invitation could be delivered to the inbox of the owner".to_owned()),
                }
            } else {
                format!("{inbox}item-{seq}.ics")
            };
            let mut probes = vec![
                Probe::new(
                    "PROPFIND of the scheduling inbox",
                    propfind(&actor, &inbox, "1", PROPFIND_COLLECTION),
                ),
                Probe::new(
                    "sync-collection of the scheduling inbox",
                    report(&actor, &inbox, "0", SYNC_COLLECTION),
                ),
            ];
            probes.extend(reads_of(&actor, "an inbox item", &item));
            probes
        }
        Operation::DeleteInboxItem => {
            let item = if allowed {
                match deliver_inbox_item(env, seq).await {
                    Some(item) => item,
                    None => return Plan::Skip("no invitation could be delivered to the inbox of the owner".to_owned()),
                }
            } else {
                format!("{owner_home}inbox/item-{seq}.ics")
            };
            vec![Probe::new("DELETE of an inbox item", request(&actor, "DELETE", &item))]
        }
        Operation::PostOutbox => {
            let organizer = at.actor_address(ActorRole::Owner).unwrap_or_default();
            let attendee = at.actor_address(ActorRole::OtherUser).unwrap_or_default();
            vec![Probe::new(
                "POST of a VFREEBUSY to the outbox of the calendar's owner",
                request(&actor, "POST", &format!("{owner_home}outbox/"))
                    .content(ICS, free_busy_message(seq, &organizer, &attendee)),
            )]
        }
        Operation::ReadNotifications => {
            let notifications = format!("{owner_home}notifications/");
            let item = if allowed {
                let owner = env.book().actor(ActorRole::Owner, Surface::Dav, None);
                let listed = match owner {
                    Some(owner) => list_hrefs(env, &owner, &notifications).await,
                    None => Vec::new(),
                };
                match listed.into_iter().next() {
                    Some(item) => item,
                    None => return Plan::Skip("the owner has no notification to read".to_owned()),
                }
            } else {
                format!("{notifications}item-{seq}.xml")
            };
            let mut probes = vec![
                Probe::new(
                    "PROPFIND of the notification collection",
                    propfind(&actor, &notifications, "1", PROPFIND_COLLECTION),
                ),
                Probe::new(
                    "sync-collection of the notification collection",
                    report(&actor, &notifications, "0", SYNC_COLLECTION),
                ),
            ];
            probes.extend(reads_of(&actor, "a notification", &item));
            probes
        }
        Operation::DeleteNotification => {
            let item = if allowed {
                let owner = env.book().actor(ActorRole::Owner, Surface::Dav, None);
                let listed = match owner {
                    Some(owner) => list_hrefs(env, &owner, &format!("{owner_home}notifications/")).await,
                    None => Vec::new(),
                };
                match listed.into_iter().next() {
                    Some(item) => item,
                    None => return Plan::Skip("the owner has no notification to delete".to_owned()),
                }
            } else {
                format!("{owner_home}notifications/item-{seq}.xml")
            };
            vec![Probe::new("DELETE of a notification", request(&actor, "DELETE", &item))]
        }
        Operation::ReadHome => {
            // The home lists the bindings of its owner: what somebody else sees of it is what it must not show.
            let shown = format!("{owner_home}{}/", at.slug(role));
            vec![
                Probe::new(
                    "PROPFIND of the home",
                    propfind(&actor, &owner_home, "1", PROPFIND_COLLECTION),
                )
                .showing(&[&shown]),
                // No report is defined on a home (`sync-collection` of a home is 403 `DAV:supported-report` for everybody who asks,
                // `a_report_on_a_home_is_refused_to_everybody_alike`), so the second look is the home itself.
                Probe::new(
                    "PROPFIND of the home itself",
                    propfind(&actor, &owner_home, "0", PROPFIND_COLLECTION),
                ),
            ]
        }
        Operation::ReadPrincipal => {
            let principal = format!("/dav/principals/{}/{}/", at.tenant(role), at.owner(role));
            let display_name = env
                .world()
                .principal_named(&at.tenant(role), &at.owner(role))
                .map(|principal| principal.display_name.clone())
                .unwrap_or_default();
            vec![
                Probe::new(
                    "PROPFIND of the principal",
                    propfind(&actor, &principal, "0", PROPFIND_PRINCIPAL),
                )
                .showing(&[&display_name]),
            ]
        }
        other => return Plan::NotApplicable(format!("{other} does not exist on DAV")),
    };
    Plan::Probes(probes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bodies_are_well_formed_documents() {
        for body in [
            PROPFIND_COLLECTION,
            PROPFIND_OBJECT,
            PROPFIND_PRINCIPAL,
            CALENDAR_QUERY,
            SYNC_COLLECTION,
            FREE_BUSY_REPORT,
            PROPPATCH_BINDING,
            PROPPATCH_SHARED,
            MKCOL_CALENDAR,
            &share_request("mailto:otto@acme.example"),
            &invite_reply("uid-1", "/dav/calendars/acme/olivia/projects/"),
            &multiget("/dav/calendars/acme/olivia/personal/x.ics"),
        ] {
            assert!(Document::parse(body).is_ok(), "{body}");
        }
    }

    #[test]
    fn a_free_busy_message_is_icalendar_with_crlf() {
        let message = free_busy_message(3, "mailto:a@x.example", "mailto:b@x.example");
        assert!(message.starts_with("BEGIN:VCALENDAR\r\n") && message.ends_with("END:VCALENDAR\r\n"));
        assert!(message.contains("UID:mx-fb-3@acme.example\r\n"));
        assert!(message.contains("ORGANIZER:mailto:a@x.example\r\nATTENDEE:mailto:b@x.example\r\n"));
    }

    #[test]
    fn an_update_keeps_the_uid_and_changes_the_summary() {
        let world = davhaven_fixtures::FixtureWorld::standard();
        let at = Addressing::new(&world);
        let changed = changed_event(at, CalendarRole::Personal);
        assert!(changed.contains("SUMMARY:Changed by the matrix"));
        assert!(changed.contains("UID:personal-event@acme.example"));
        assert!(!changed.contains("SUMMARY:Personal event"));
    }

    #[test]
    fn the_reads_of_a_resource_are_get_head_and_propfind() {
        let probes = reads_of(
            &Actor::Anonymous,
            "an inbox item",
            "/dav/calendars/acme/olivia/inbox/x.ics",
        );
        let methods: Vec<&str> = probes.iter().map(|probe| probe.request.method.as_str()).collect();
        assert_eq!(methods, vec!["GET", "HEAD", "PROPFIND"]);
        assert!(probes.iter().all(|probe| probe.when_allowed == Expectation::Allow));
    }
}
