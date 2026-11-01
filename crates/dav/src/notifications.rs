//! The notification collection of a principal and its resources.
//!
//! `/dav/calendars/{tenant}/{principal}/notifications/` holds what the sharing flow tells a principal: the
//! invitations other principals sent (`CS:invite-notification`) and the answers to the invitations the principal
//! sent (`CS:invite-reply`). Clients (Apple Calendar) list the collection, read each resource, show it and delete it
//! afterwards; deleting a notification does not withdraw the invitation, and answering an invitation does not need
//! its notification to exist any more (PLAN 2.9).
//!
//! | Method | Resource | Answer |
//! | --- | --- | --- |
//! | `PROPFIND` | the collection | the collection, with `Depth: 1` its notifications sorted by href |
//! | `PROPFIND` | a notification | `getetag`, `getcontenttype`, `getcontentlength`, `getlastmodified`, `creationdate`, `CS:notificationtype` |
//! | `GET`, `HEAD` | a notification | the XML document the application stored, `text/xml`, with `ETag` and `Last-Modified` |
//! | `DELETE` | a notification | 204; conditional like every write (the conditions are evaluated by the application in the transaction that deletes, see below) |
//! | `REPORT` | the collection | `sync-collection` ([`crate::sync`]) |
//!
//! The XML of a notification is made by the application when the notification is created and served as it is; the
//! DAV layer adds nothing to it. `CS:notificationtype` tells a client what kind of notification a resource is before
//! it reads it: `<CS:invite-notification shared-type="calendar"/>` or `<CS:invite-reply shared-type="calendar"/>`.
//!
//! # Conditional `DELETE`
//!
//! The conditional headers of a `DELETE` go to the application (`SharingService::delete_notification_if`), which
//! evaluates them against the stored entity tag in the transaction that deletes, as `ObjectService::delete` does.
//! That matters here: the application changes an invitation in place when the access of the sharee changes, so a
//! condition that was checked before the deletion could remove a newer version than the client read.
//!
//! # `Last-Modified`
//!
//! `Last-Modified` and `getlastmodified` are the date the notification was last written (`updated_at`), which goes
//! with the entity tag: an invitation that was rewritten has a new body, a new tag and a new date. `creationdate` is
//! the date it was created.

use std::collections::HashMap;

use axum::http::StatusCode;
use axum::response::Response;
use davhaven_app::services::{ChangeKind, NotificationView, SyncChange};
use davhaven_domain::ResourcePath;
use davhaven_http::problem::EdgeProblem;

use crate::methods::collaboration::{Listing, conditions_of, home_owner};
use crate::methods::{Call, Representation, represent, status_only};
use crate::props::Subject;

/// The media type of a notification resource.
pub const CONTENT_TYPE: &str = "text/xml; charset=utf-8";

async fn read(call: &Call<'_>) -> Result<NotificationView, EdgeProblem> {
    Ok(call
        .services()
        .sharing
        .get_notification(call.ctx, call.resource)
        .await?)
}

/// Serves `GET` and `HEAD` of a notification.
pub(crate) async fn get(call: &Call<'_>, head: bool) -> Result<Response, EdgeProblem> {
    let NotificationView {
        etag,
        updated_at,
        body_xml,
        ..
    } = read(call).await?;
    represent(
        call.headers(),
        head,
        Representation {
            content_type: CONTENT_TYPE,
            etag: &etag,
            last_modified: updated_at,
            body: body_xml,
        },
    )
}

/// Serves `DELETE` of a notification.
pub(crate) async fn delete(call: &Call<'_>) -> Result<Response, EdgeProblem> {
    // A plain `DELETE` has no conditions and costs one call; the conditions of the request are the application's to
    // judge, in the transaction that deletes.
    let conditions = conditions_of(call.headers())?.unwrap_or_default();
    call.services()
        .sharing
        .delete_notification_if(call.ctx, call.resource, conditions)
        .await?;
    Ok(status_only(StatusCode::NO_CONTENT))
}

/// The resource of a `PROPFIND` of one notification.
pub(crate) async fn propfind_item(call: &Call<'_>) -> Result<Vec<(String, Subject)>, EdgeProblem> {
    let view = read(call).await?;
    Ok(vec![(view.path.format(), Subject::Notification(view))])
}

/// The notifications of the collection for `Depth: 1`, sorted by href. They come whole: a notification is a small
/// document and the list is what the application keeps for the principal.
pub(crate) async fn propfind_members(call: &Call<'_>) -> Result<Listing, EdgeProblem> {
    let owner = home_owner(call)?;
    let mut members: Vec<(String, Subject)> = call
        .services()
        .sharing
        .list_notifications(call.ctx, &owner)
        .await?
        .into_iter()
        .map(|view| (view.path.format(), Subject::Notification(view)))
        .collect();
    members.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(Listing::complete(members))
}

/// The notifications `sync-collection` reports as changed, with the properties of a notification.
pub(crate) async fn sync_subjects(
    call: &Call<'_>,
    changes: &[SyncChange],
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
    // Only the changed members are read, by path and in steps a multiget may take, whatever the size of the
    // collection; the collection is named by its path, which the application resolves with the tenant of the request.
    let step = usize::try_from(call.limits().dav.max_multiget_hrefs)
        .unwrap_or(usize::MAX)
        .max(1);
    let mut found = HashMap::new();
    for paths in wanted.chunks(step) {
        let views = call
            .services()
            .sharing
            .get_notifications_many(call.ctx, call.resource, paths.to_vec())
            .await?;
        found.extend(
            views
                .into_iter()
                .map(|view| (view.path.format(), Subject::Notification(view))),
        );
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use davhaven_app::AppServices;
    use davhaven_app::services::{NS_CALENDARSERVER, NS_DAV, PropertyName};
    use davhaven_app_fake::AppServicesExt as _;
    use davhaven_domain::{
        Access, CalendarKind, DavLimits, ETag, NotificationId, NotificationKind, ResourceKind, ResourcePath, Uid,
        privileges,
    };
    use uuid::Uuid;

    use super::*;
    use crate::props::{Env, propstats};
    use crate::xml::Element;
    use crate::xml::parse;
    use crate::xml::reports::parse_sync_collection;
    use crate::xml::requests::{PropList, PropRequest, parse_propfind};
    use crate::xml::write::{Multistatus, Prefixes};

    use crate::testing::fixture;

    const INVITATION: &str = "7b2c4f10-4d2e-4f55-9a3e-0d3b2a6c1e11";

    /// The notification the application stores for a fixture: the strong entity tag is the hash of the bytes.
    fn stored(file: &str, kind: NotificationKind, number: u128) -> NotificationView {
        let body = fixture(file);
        NotificationView {
            path: ResourcePath::parse(&format!("/dav/calendars/acme/anna/notifications/n{number}.xml")).unwrap(),
            id: NotificationId::from_uuid(Uuid::from_u128(number)),
            uid: Uid::parse(INVITATION).unwrap(),
            etag: ETag::from_bytes(body.as_bytes()),
            kind,
            size: u64::try_from(body.len()).unwrap(),
            body_xml: body,
            privileges: privileges(Access::Owner, CalendarKind::Personal, ResourceKind::Notification),
            created_at: Utc.with_ymd_and_hms(2027, 1, 1, 0, 3, 0).unwrap(),
            updated_at: Utc.with_ymd_and_hms(2027, 1, 2, 9, 30, 0).unwrap(),
        }
    }

    fn answer(views: &[NotificationView], select: &PropRequest) -> String {
        let services = AppServices::fake();
        let prefixes = Prefixes::of(select.names().iter().map(|name| name.namespace.as_str()), 64);
        let env = Env {
            services: &services,
            current: None,
            prefixes: &prefixes,
        };
        let mut multistatus = Multistatus::with_prefixes(&prefixes);
        for view in views {
            let subject = Subject::Notification(view.clone());
            multistatus.response(&view.path.format(), &propstats(&env, &subject, select, false));
        }
        multistatus.finish()
    }

    fn only(names: &[(&str, &str)]) -> PropRequest {
        PropRequest::Prop(PropList {
            names: names
                .iter()
                .map(|(namespace, local)| PropertyName::new(namespace, local))
                .collect(),
            calendar_data: None,
        })
    }

    #[test]
    fn the_fixtures_are_notification_documents_of_the_kind_the_application_says() {
        for (file, kind, element) in [
            (
                "notification-invite.xml",
                NotificationKind::Invite,
                "invite-notification",
            ),
            (
                "notification-invite-reply.xml",
                NotificationKind::InviteReply,
                "invite-reply",
            ),
        ] {
            let root = parse(fixture(file).as_bytes(), &DavLimits::default()).unwrap();
            assert!(root.is(NS_CALENDARSERVER, "notification"), "{file}");
            let what: Vec<&str> = root
                .elements()
                .filter(|child| child.namespace.as_str() == NS_CALENDARSERVER && child.local != "dtstamp")
                .map(|child| child.local.as_str())
                .collect();
            assert_eq!(what, [element], "{file}");
            // What a client reads in `CS:notificationtype` names the same element before it reads the body.
            let listed = answer(
                &[stored(file, kind, 1)],
                &only(&[(NS_CALENDARSERVER, "notificationtype")]),
            );
            assert!(
                listed.contains(&format!("<CS:{element} shared-type=\"calendar\"/>")),
                "{file}: {listed}"
            );
        }
    }

    #[test]
    fn apple_calendar_lists_the_notification_collection() {
        let select = parse_propfind(fixture("propfind-notifications.xml").as_bytes(), &DavLimits::default()).unwrap();
        let invite = stored("notification-invite.xml", NotificationKind::Invite, 1);
        let reply = stored("notification-invite-reply.xml", NotificationKind::InviteReply, 2);
        let document = answer(&[invite.clone(), reply.clone()], &select);
        let root = parse(document.as_bytes(), &DavLimits::default()).unwrap();
        let responses: Vec<&Element> = root.children_named(NS_DAV, "response").collect();
        assert_eq!(responses.len(), 2, "{document}");
        for (response, view, element) in [
            (responses[0], &invite, "invite-notification"),
            (responses[1], &reply, "invite-reply"),
        ] {
            assert_eq!(response.child(NS_DAV, "href").unwrap().text(), view.path.format());
            let propstat = response.child(NS_DAV, "propstat").unwrap();
            assert_eq!(
                propstat.child(NS_DAV, "status").unwrap().text(),
                "HTTP/1.1 200 OK",
                "{document}"
            );
            let prop = propstat.child(NS_DAV, "prop").unwrap();
            assert_eq!(prop.child(NS_DAV, "getetag").unwrap().text(), view.etag.as_str());
            assert_eq!(
                prop.child(NS_DAV, "getcontenttype").unwrap().text(),
                "text/xml; charset=utf-8"
            );
            assert_eq!(
                prop.child(NS_DAV, "resourcetype").unwrap().elements().count(),
                0,
                "a notification is no collection"
            );
            let kind = prop
                .child(NS_CALENDARSERVER, "notificationtype")
                .and_then(|kind| kind.elements().next())
                .unwrap();
            assert_eq!(kind.local, element);
            assert_eq!(kind.attribute("shared-type"), Some("calendar"));
        }
    }

    #[test]
    fn the_size_of_a_notification_is_the_size_of_its_document() {
        let view = stored("notification-invite.xml", NotificationKind::Invite, 1);
        let select = only(&[
            (NS_DAV, "getcontentlength"),
            (NS_DAV, "getlastmodified"),
            (NS_DAV, "creationdate"),
        ]);
        let document = answer(std::slice::from_ref(&view), &select);
        let root = parse(document.as_bytes(), &DavLimits::default()).unwrap();
        let prop = root
            .child(NS_DAV, "response")
            .and_then(|response| response.child(NS_DAV, "propstat"))
            .and_then(|propstat| propstat.child(NS_DAV, "prop"))
            .unwrap();
        assert_eq!(
            prop.child(NS_DAV, "getcontentlength").unwrap().text(),
            view.body_xml.len().to_string()
        );
        assert_eq!(
            prop.child(NS_DAV, "getlastmodified").unwrap().text(),
            "Sat, 02 Jan 2027 09:30:00 GMT",
            "the date of the last write goes with the entity tag"
        );
        assert_eq!(
            prop.child(NS_DAV, "creationdate").unwrap().text(),
            "2027-01-01T00:03:00Z"
        );
    }

    #[test]
    fn apple_calendar_synchronizes_the_collection_with_the_properties_of_a_notification() {
        let root = parse(fixture("sync-notifications.xml").as_bytes(), &DavLimits::default()).unwrap();
        let request = parse_sync_collection(&root).unwrap();
        assert_eq!(request.token, "", "the first synchronization has no token");
        assert!(!request.infinite);
        let names: Vec<&str> = request.select.names().iter().map(|name| name.local.as_str()).collect();
        assert_eq!(names, ["getetag", "getcontenttype", "notificationtype"]);
    }
}
