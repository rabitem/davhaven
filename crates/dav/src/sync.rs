//! The `sync-collection` report (RFC 6578, `sync-level` 1).
//!
//! A client asks for what changed in a collection since the `DAV:sync-token` of its last answer (an empty token
//! asks for every member) and receives one `D:response` per changed member plus the token for the next request:
//!
//! * a member that exists is reported with the properties the request asked for (usually `getetag`);
//! * a member that was deleted is reported with a **404** status and no properties;
//! * a token the server cannot use (another collection, garbled, from another epoch, from the future, or older
//!   than the log that is kept) answers 403 `DAV:valid-sync-token`, and the client starts over with an empty token;
//! * when the answer is **truncated** (`DAV:limit`, or the server's own limit) the request URI gets a 507 response
//!   with `DAV:number-of-matches-within-limits` and the token that continues where the answer stopped.
//!
//! `sync-level: infinite` is refused with 403 `DAV:sync-traversal-supported` (RFC 6578 sections 3.2 and 3.3). The change
//! log, the token format (`urn:davhaven:sync:{collection}:{epoch}:{seq}`) and the epoch rules are the services'
//! (PLAN 2.7); this module renders what they return. The `getctag` of a collection is the same string as its token.
//!
//! Members are reported by name and entity tag, which is all the change log knows. When the request asks for more
//! (`calendar-data`, `getcontenttype`, ...) the changed members are read with `calendar-multiget` semantics, in
//! batches of `max_multiget_hrefs`. A request that makes the answer carry the data of its members (the calendar data
//! of objects, the messages of inbox items, which `getcontentlength` needs as well) limits their number so that
//! the data they can hold fits `max_response_bytes`.

use std::collections::HashMap;

use axum::response::Response;
use davhaven_app::services::{CalendarDataSpec, ChangeKind, MultigetEntry, NS_DAV, ObjectView, SyncChange};
use davhaven_domain::{ResourcePath, SyncToken};
use davhaven_http::problem::{EdgeProblem, ProblemCode};

use crate::discovery::current_principal;
use crate::methods::{Call, collaboration, data_spec, minimal_requested, multistatus_response};
use crate::props::{Env, Subject, propstats};
use crate::scheduling;
use crate::xml::Element;
use crate::xml::reports::parse_sync_collection;
use crate::xml::requests::PropRequest;
use crate::xml::write::{Multistatus, Prefixes};

/// Whether the request asks for nothing but the entity tag of the members, which the change log answers.
fn only_etag(select: &PropRequest) -> bool {
    match select {
        PropRequest::Prop(list) => {
            list.calendar_data.is_none()
                && list
                    .names
                    .iter()
                    .all(|name| name.namespace == NS_DAV && name.local == "getetag")
        }
        PropRequest::AllProp(_) | PropRequest::PropName => false,
    }
}

/// Reads the members that changed, when the request asks for more than their entity tag: the calendar objects of a
/// calendar, the items of the inbox and the notifications of the notification collection.
async fn member_subjects(
    call: &Call<'_>,
    changes: &[SyncChange],
    select: &PropRequest,
) -> Result<HashMap<String, Subject>, EdgeProblem> {
    if matches!(
        call.resource,
        ResourcePath::Inbox { .. } | ResourcePath::Notifications { .. }
    ) {
        return collaboration::sync_subjects(call, changes, select).await;
    }
    let views = member_views(call, changes, &data_spec(select)).await?;
    Ok(views
        .into_iter()
        .map(|(href, view)| (href, Subject::Object(view)))
        .collect())
}

/// Reads the calendar objects that changed.
async fn member_views(
    call: &Call<'_>,
    changes: &[SyncChange],
    spec: &CalendarDataSpec,
) -> Result<HashMap<String, ObjectView>, EdgeProblem> {
    let paths: Vec<ResourcePath> = changes
        .iter()
        .filter(|change| change.kind == ChangeKind::Upsert)
        .map(|change| change.path.clone())
        .collect();
    let batch = usize::try_from(call.limits().dav.max_multiget_hrefs)
        .unwrap_or(usize::MAX)
        .max(1);
    let mut views = HashMap::new();
    for part in paths.chunks(batch) {
        let entries = call
            .services()
            .objects
            .multiget(call.ctx, call.resource, part.to_vec(), spec.clone())
            .await?;
        for entry in entries {
            if let MultigetEntry::Found(view) = entry {
                views.insert(view.path.format(), view);
            }
        }
    }
    Ok(views)
}

/// The most members one answer reports, and so the `limit` the service is asked for.
///
/// An answer cannot be cut anywhere: the token that comes with it stands for everything it reports. So the size
/// of an answer is bounded by the number of members, which is asked of the service and which makes it report the
/// truncation (507 for the request URI and a token that continues). That is `max_multiget_hrefs`, and for an answer
/// that carries the data of the members (which may be as large as `max_resource_size` each) as many as fit into
/// `max_response_bytes`.
fn member_cap(call: &Call<'_>, with_data: bool) -> u32 {
    let dav = &call.limits().dav;
    cap_for(
        dav.max_multiget_hrefs,
        dav.max_response_bytes,
        call.limits().ical.max_resource_size,
        with_data,
    )
}

/// [`member_cap`] for the limits it is made of.
fn cap_for(max_multiget_hrefs: u32, max_response_bytes: u64, max_resource_size: u64, with_data: bool) -> u32 {
    if !with_data {
        return max_multiget_hrefs;
    }
    let fitting = max_response_bytes / max_resource_size.max(1);
    u32::try_from(fitting.max(1))
        .unwrap_or(u32::MAX)
        .min(max_multiget_hrefs)
}

/// A member of the answer: present with its subject, or gone.
enum Member {
    Present(Box<Subject>),
    Gone,
}

/// Serves a `sync-collection` REPORT.
pub(crate) async fn report(call: &Call<'_>, root: &Element) -> Result<Response, EdgeProblem> {
    let request = parse_sync_collection(root)?;
    if request.infinite {
        return Err(EdgeProblem::new(ProblemCode::SyncTraversalUnsupported));
    }
    let since = if request.token.is_empty() {
        None
    } else {
        Some(SyncToken::parse(&request.token).map_err(|_| EdgeProblem::new(ProblemCode::SyncTokenExpired))?)
    };
    let detailed = !only_etag(&request.select);
    let spec = data_spec(&request.select);
    // The data of the members is what makes an answer large: the calendar data of objects, and for the inbox the
    // messages, which are read for their size and for `calendar-data` alike.
    let with_data = spec.include_data || scheduling::reads_messages(call.resource, &request.select);
    let cap = member_cap(call, detailed && with_data);
    let limit = Some(request.limit.map_or(cap, |wanted| wanted.min(cap)));
    let result = call
        .services()
        .objects
        .sync(call.ctx, call.resource, since, limit)
        .await?;
    let minimal = minimal_requested(call.headers());
    let current = current_principal(call, &request.select).await?;
    let prefixes = Prefixes::of(
        request.select.names().iter().map(|name| name.namespace.as_str()),
        usize::try_from(call.limits().dav.max_xml_namespaces).unwrap_or(usize::MAX),
    );
    let env = Env {
        services: call.services(),
        current: current.as_ref(),
        prefixes: &prefixes,
    };
    let mut views = if detailed {
        member_subjects(call, &result.changes, &request.select).await?
    } else {
        HashMap::new()
    };
    let mut members: Vec<(String, Member)> = Vec::with_capacity(result.changes.len());
    for change in result.changes {
        let href = change.path.format();
        let member = match change.kind {
            ChangeKind::Delete => Member::Gone,
            ChangeKind::Upsert => {
                let subject = if detailed {
                    views.remove(&href)
                } else {
                    change.etag.map(|etag| Subject::Member {
                        path: change.path.clone(),
                        etag,
                    })
                };
                // A member that vanished between the change log and the read is reported as deleted.
                subject.map_or(Member::Gone, |subject| Member::Present(Box::new(subject)))
            }
        };
        members.push((href, member));
    }
    members.sort_by(|a, b| a.0.cmp(&b.0));
    let mut multistatus = Multistatus::with_prefixes(&prefixes);
    for (href, member) in &members {
        match member {
            Member::Present(subject) => {
                multistatus.response(href, &propstats(&env, subject, &request.select, minimal));
            }
            Member::Gone => {
                multistatus.status_response(href, 404, None);
            }
        }
    }
    if result.truncated {
        multistatus.status_response(&call.resource.format(), 507, Some("number-of-matches-within-limits"));
    }
    multistatus.sync_token(&result.sync_token.to_string());
    Ok(multistatus_response(multistatus.finish(), minimal))
}

#[cfg(test)]
mod tests {
    use davhaven_app::services::PropertyName;

    use super::*;
    use crate::xml::requests::PropList;

    fn select(names: &[(&str, &str)], data: bool) -> PropRequest {
        PropRequest::Prop(PropList {
            names: names.iter().map(|(ns, local)| PropertyName::new(ns, local)).collect(),
            calendar_data: data.then(davhaven_app::services::Projection::default),
        })
    }

    #[test]
    fn an_answer_with_data_holds_as_many_members_as_fit_the_response_size() {
        let mib = 1024 * 1024;
        assert_eq!(
            cap_for(1000, 32 * mib, mib, false),
            1000,
            "the change log answers the tags"
        );
        assert_eq!(cap_for(1000, 32 * mib, mib, true), 32);
        assert_eq!(
            cap_for(10, 32 * mib, mib, true),
            10,
            "never more than a multiget may name"
        );
        assert_eq!(
            cap_for(1000, mib, 2 * mib, true),
            1,
            "a member larger than the answer is still reported alone"
        );
        assert_eq!(cap_for(1000, 32 * mib, 0, true), 1000);
    }

    #[test]
    fn the_messages_of_the_inbox_are_read_for_calendar_data_and_for_nothing_else() {
        let inbox = ResourcePath::parse("/dav/calendars/acme/anna/inbox/").unwrap();
        let calendar = ResourcePath::parse("/dav/calendars/acme/anna/work/").unwrap();
        // `getetag` and `getcontentlength`: the size is the application's, in its listing, so no message is read for
        // it; the changed members are read all the same (the change log knows names and tags only).
        let sizes = select(&[(NS_DAV, "getetag"), (NS_DAV, "getcontentlength")], false);
        assert!(!data_spec(&sizes).include_data);
        assert!(!scheduling::reads_messages(&inbox, &sizes));
        assert!(!only_etag(&sizes));
        // `calendar-data` is what needs the message.
        let data = select(&[(NS_DAV, "getetag")], true);
        assert!(data_spec(&data).include_data);
        assert!(scheduling::reads_messages(&inbox, &data));
        assert!(
            !scheduling::reads_messages(&calendar, &data),
            "only the inbox reads messages that way: a calendar reads objects"
        );
    }

    #[test]
    fn the_change_log_answers_requests_for_the_etag_alone() {
        assert!(only_etag(&select(&[(NS_DAV, "getetag")], false)));
        assert!(only_etag(&select(&[], false)));
        assert!(!only_etag(&select(
            &[(NS_DAV, "getetag"), (NS_DAV, "getcontenttype")],
            false
        )));
        assert!(!only_etag(&select(&[(NS_DAV, "getetag")], true)));
        assert!(!only_etag(&PropRequest::PropName));
        assert!(!only_etag(&PropRequest::AllProp(PropList::default())));
    }
}
