//! PROPFIND (RFC 4918 section 9.1, RFC 4791 section 5.2): the properties of a resource and, at `Depth: 1`, of its
//! members.
//!
//! The handler reads the request, collects the resources it covers from the application services and renders
//! each of them with [`crate::props`]:
//!
//! | Resource | `Depth: 0` | `Depth: 1` adds |
//! | --- | --- | --- |
//! | `/dav/` | the entry point | nothing |
//! | principal | the principal | nothing |
//! | calendar home | the home | every calendar of the principal, the inbox, the outbox and the notification collection |
//! | calendar collection | the calendar | every calendar object |
//! | outbox | the outbox | nothing |
//! | inbox, notification collection | the collection | the items ([`crate::scheduling`], [`crate::notifications`]); the inbox as many as can be read within `max_response_bytes` |
//! | calendar object | the object | nothing |
//!
//! `Depth: infinity`, and a missing `Depth` header, which means the same, are refused with 403
//! `DAV:propfind-finite-depth` (PLAN 2.15). Responses are sorted by `href`, the requested resource first, so that
//! the output is deterministic. `Prefer: return=minimal` and `Brief: t` leave the 404 `propstat`s out.
//!
//! The home is listed with one call that loads the authorization facts once (`list_home_collections`, R14), and an
//! answer that grows beyond `max_response_bytes` ends with a 507 entry for the request URI. The inbox is cut the same
//! way when reading the messages its listing needs would go beyond that size.

use axum::body::Body;
use axum::response::Response;
use davhaven_app::services::{CollectionView, MultigetEntry, ObjectFilter};
use davhaven_domain::ResourcePath;
use davhaven_http::problem::{EdgeProblem, ProblemCode};

use super::collaboration::Listing;
use super::headers::{self, Depth};
use super::{Call, collaboration, data_spec, multistatus_response};
use crate::discovery::current_principal;
use crate::props::{Env, Subject, home_detail, propstats};
use crate::xml::requests::{PropList, PropRequest, is_blank, parse_propfind_root};
use crate::xml::write::{Multistatus, Prefixes};

/// The resources of an answer with their hrefs, formatted once: the addressed one first, its members after it
/// sorted by href.
type Members = Vec<(String, Subject)>;

/// Serves a PROPFIND.
pub(crate) async fn handle(call: &Call<'_>, body: Body) -> Result<Response, EdgeProblem> {
    let depth = headers::depth(call.headers(), Depth::Infinity)?;
    if depth == Depth::Infinity {
        return Err(EdgeProblem::new(ProblemCode::DepthInfinityRefused));
    }
    let bytes = call.xml_body(body).await?;
    let request = if is_blank(&bytes) {
        PropRequest::AllProp(PropList::default())
    } else {
        parse_propfind_root(&call.parse_xml(bytes).await?)?
    };
    let minimal = headers::minimal_requested(call.headers());
    let current = current_principal(call, &request).await?;
    let prefixes = Prefixes::of(
        request.names().iter().map(|name| name.namespace.as_str()),
        usize::try_from(call.limits().dav.max_xml_namespaces).unwrap_or(usize::MAX),
    );
    let env = Env {
        services: call.services(),
        current: current.as_ref(),
        prefixes: &prefixes,
    };
    let Listing { members, truncated } = collect(call, depth, &request).await?;
    let budget = call.response_budget();
    let mut multistatus = Multistatus::with_prefixes(&prefixes);
    let mut cut = truncated;
    for (href, subject) in &members {
        if multistatus.len() > budget {
            cut = true;
            break;
        }
        multistatus.response(href, &propstats(&env, subject, &request, minimal));
    }
    if cut {
        call.truncated(&mut multistatus);
    }
    Ok(multistatus_response(multistatus.finish(), minimal))
}

/// The resource as an answer lists it.
fn member(subject: Subject) -> (String, Subject) {
    (subject.path().format(), subject)
}

/// The resources the request covers: the addressed one first, its members after it sorted by href.
async fn collect(call: &Call<'_>, depth: Depth, request: &PropRequest) -> Result<Listing, EdgeProblem> {
    let services = call.services();
    let path = call.resource;
    match path {
        ResourcePath::Root => Ok(Listing::complete(vec![member(Subject::Root)])),
        ResourcePath::Principal { .. } => {
            let principal = services.principals.dav_properties(call.ctx, path).await?;
            Ok(Listing::complete(vec![member(Subject::Principal(principal))]))
        }
        ResourcePath::Home { .. } => home(call, depth, request).await.map(Listing::complete),
        ResourcePath::Collection { .. } => calendar(call, depth, request).await.map(Listing::complete),
        ResourcePath::Inbox { .. } | ResourcePath::Notifications { .. } => {
            // The collection is resolved with the tenant of the request first: the listing of its members names the
            // home owner alone.
            let mut members = special(call).await?;
            let mut truncated = false;
            if depth == Depth::One {
                let listing = collaboration::propfind_members(call, request).await?;
                members.extend(listing.members);
                truncated = listing.truncated;
            }
            Ok(Listing { members, truncated })
        }
        ResourcePath::Outbox { .. } => special(call).await.map(Listing::complete),
        ResourcePath::Object { .. } => object(call, request).await.map(Listing::complete),
        ResourcePath::InboxItem { .. } | ResourcePath::Notification { .. } => {
            collaboration::propfind_item(call).await.map(Listing::complete)
        }
    }
}

/// The inbox, the outbox or the notification collection itself.
async fn special(call: &Call<'_>) -> Result<Members, EdgeProblem> {
    let view: CollectionView = call
        .services()
        .calendars
        .get_collection(call.ctx, call.resource)
        .await?;
    Ok(vec![member(Subject::Collection(view))])
}

async fn home(call: &Call<'_>, depth: Depth, request: &PropRequest) -> Result<Members, EdgeProblem> {
    let services = call.services();
    let view = services.calendars.get_collection(call.ctx, call.resource).await?;
    let mut members = vec![member(Subject::Collection(view))];
    if depth != Depth::One {
        return Ok(members);
    }
    // One call for the whole home, with the dead properties and invitations only when the request can ask for
    // them: the application loads the authorization facts once and the collections with one query.
    let mut listed: Members = services
        .calendars
        .list_home_collections(call.ctx, call.resource, home_detail(request))
        .await?
        .into_iter()
        .map(|view| member(Subject::Collection(view)))
        .collect();
    listed.sort_by(|a, b| a.0.cmp(&b.0));
    members.extend(listed);
    Ok(members)
}

async fn calendar(call: &Call<'_>, depth: Depth, request: &PropRequest) -> Result<Members, EdgeProblem> {
    let services = call.services();
    let view = services.calendars.get_collection(call.ctx, call.resource).await?;
    let mut members = vec![member(Subject::Collection(view))];
    if depth == Depth::One {
        let hits = services
            .objects
            .query(call.ctx, call.resource, ObjectFilter::default(), data_spec(request))
            .await?;
        let mut listed: Members = hits.into_iter().map(|hit| member(Subject::Object(hit))).collect();
        listed.sort_by(|a, b| a.0.cmp(&b.0));
        members.extend(listed);
    }
    Ok(members)
}

async fn object(call: &Call<'_>, request: &PropRequest) -> Result<Members, EdgeProblem> {
    let services = call.services();
    let spec = data_spec(request);
    if spec.include_data && !spec.projection.is_identity() {
        // Only a multiget applies the projection of the request to the data.
        let Some(collection) = call.resource.parent() else {
            return Err(EdgeProblem::new(ProblemCode::NotFound));
        };
        let entries = services
            .objects
            .multiget(call.ctx, &collection, vec![call.resource.clone()], spec)
            .await?;
        return match entries.into_iter().next() {
            Some(MultigetEntry::Found(view)) => Ok(vec![member(Subject::Object(view))]),
            _ => Err(EdgeProblem::new(ProblemCode::NotFound)),
        };
    }
    let view = services.objects.get(call.ctx, call.resource).await?;
    Ok(vec![member(Subject::Object(view))])
}
