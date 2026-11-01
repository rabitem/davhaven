//! The collaboration modules of the DAV crate (sharing, notifications, scheduling inbox and outbox, principal search)
//! over the real services of the application on the in-memory store (PLAN 4.2).
//!
//! The router of `davhaven-dav` is mounted on the same services the application tests use, behind the edge layers
//! that authenticate a request, and driven with the request bodies of the clients (`testdata/dav/sharing`). The
//! flows run end to end: an invitation is posted to a calendar, shows up in the notification collection of the
//! sharee, is answered with a `CS:invite-reply`, and the sharee finds the shared calendar in their home; the owner
//! reads the answer as a notification and deletes it, conditionally; principal search runs over principals the
//! application created.
//!
//! The scheduling inbox and the outbox are served by the real `SchedulingService`; [`Recording`] wraps it only to
//! count and to record what the DAV layer asks of it (how many reads a request costs, which arguments reach the
//! service). Messages are delivered into the real store, as the scheduling application does.

use std::sync::Arc;

use async_trait::async_trait;
use davhaven_testkit::axum::Router;
use davhaven_testkit::axum::body::{Body, to_bytes};
use davhaven_testkit::davhaven_app::error::AppResult;
use davhaven_testkit::davhaven_app::services::{
    CalendarDataSpec, Conditions, CsrfToken, FindSlotsRequest, FindSlotsResult, FreeBusyRequest, FreeBusyResult,
    GrantSpec, InboxEntry, InboxItemView, InvitationResponse, NS_CALDAV, NS_CALENDARSERVER, NS_DAV, ObjectRef,
    Projection, RenderedPage, RsvpAnswer, ScheduleResponse, SchedulingService,
};
use davhaven_testkit::davhaven_dav;
use davhaven_testkit::davhaven_domain::{
    Actor, CalendarKind, CredentialId, CredentialRef, DavLimits, ETag, ErrorKind, GrantAccess, InboxItem, InboxItemId,
    ObjectUri, PrincipalId, PrincipalKind, PrincipalName, PrincipalStatus, RequestContext, ResourcePath, ScopeSet,
};
use davhaven_testkit::davhaven_http::{Edge, SequentialRequestIds, Surface};
use davhaven_testkit::davhaven_ports::{Authenticated, IdGenerator, TxMode};
use davhaven_testkit::davhaven_wire::{EventView, GrantWrite, InboundItipRequest, InboundItipResponse};
use davhaven_testkit::http::{HeaderMap, Request, StatusCode};
use tower::ServiceExt as _;
use uuid::Uuid;

use super::support::{CountingDatabase, Mutex, Org, Person, World, locked, principal_body};

// ---------------------------------------------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------------------------------------------

/// What a client reads back.
struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Reply {
    fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
    }

    fn xml(&self) -> davhaven_dav::xml::Element {
        read(&self.body)
    }

    /// The `(href, status)` of every `response` of a `207`, in document order; the status is that of the response
    /// itself, `None` for a response with `propstat`s.
    fn responses(&self) -> Vec<(String, Option<u16>)> {
        assert_eq!(self.status, StatusCode::MULTI_STATUS, "{}", self.body);
        self.xml()
            .children_named(NS_DAV, "response")
            .map(|response| {
                (
                    response.child(NS_DAV, "href").unwrap().text(),
                    response.child(NS_DAV, "status").map(|status| code_of(&status.text())),
                )
            })
            .collect()
    }

    /// The hrefs of the `response`s, in document order.
    fn hrefs(&self) -> Vec<String> {
        self.responses().into_iter().map(|(href, _)| href).collect()
    }

    /// The property of the response for `href` that answered 200.
    fn prop(&self, href: &str, namespace: &str, local: &str) -> Option<davhaven_dav::xml::Element> {
        let root = self.xml();
        let response = root
            .children_named(NS_DAV, "response")
            .find(|response| {
                response
                    .child(NS_DAV, "href")
                    .map(davhaven_dav::xml::Element::text)
                    .as_deref()
                    == Some(href)
            })
            .unwrap_or_else(|| panic!("no response for {href}: {}", self.body));
        response
            .children_named(NS_DAV, "propstat")
            .filter(|propstat| {
                propstat
                    .child(NS_DAV, "status")
                    .is_some_and(|status| code_of(&status.text()) == 200)
            })
            .filter_map(|propstat| propstat.child(NS_DAV, "prop"))
            .flat_map(davhaven_dav::xml::Element::elements)
            .find(|prop| prop.is(namespace, local))
            .cloned()
    }
}

fn code_of(status_line: &str) -> u16 {
    status_line.split(' ').nth(1).unwrap().parse().unwrap()
}

fn read(xml: &str) -> davhaven_dav::xml::Element {
    davhaven_dav::xml::parse(xml.as_bytes(), &DavLimits::default()).unwrap_or_else(|_| panic!("not XML: {xml}"))
}

/// A user who can log in to DAV.
#[derive(Clone)]
struct Login {
    login: String,
    secret: String,
}

impl Login {
    fn authorization(&self) -> String {
        use base64::Engine as _;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", self.login, self.secret))
        )
    }
}

/// The router of the DAV crate on the services of `world`.
struct Dav {
    router: Router,
}

impl Dav {
    fn new(world: &World) -> Self {
        Self::on(world.services.clone())
    }

    fn on(services: davhaven_testkit::davhaven_app::AppServices) -> Self {
        let edge = Edge::new(Surface::Dav, Arc::new(SequentialRequestIds::new()));
        Self {
            router: davhaven_dav::router(services, &edge),
        }
    }

    async fn send(&self, method: &str, path: &str, who: Option<&Login>, headers: &[(&str, &str)], body: &str) -> Reply {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(who) = who {
            request = request.header("authorization", who.authorization());
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = self
            .router
            .clone()
            .oneshot(request.body(Body::from(body.to_owned())).unwrap())
            .await
            .unwrap();
        let (parts, body) = response.into_parts();
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: String::from_utf8_lossy(&to_bytes(body, usize::MAX).await.unwrap()).into_owned(),
        }
    }

    async fn get(&self, path: &str, who: &Login) -> Reply {
        self.send("GET", path, Some(who), &[], "").await
    }

    async fn post_xml(&self, path: &str, who: &Login, body: &str) -> Reply {
        self.send(
            "POST",
            path,
            Some(who),
            &[("content-type", "application/xml; charset=utf-8")],
            body,
        )
        .await
    }

    async fn propfind(&self, path: &str, who: &Login, depth: &str, body: &str) -> Reply {
        self.send(
            "PROPFIND",
            path,
            Some(who),
            &[("depth", depth), ("content-type", "application/xml; charset=utf-8")],
            body,
        )
        .await
    }

    async fn report(&self, path: &str, who: &Login, body: &str) -> Reply {
        self.send(
            "REPORT",
            path,
            Some(who),
            &[("depth", "0"), ("content-type", "application/xml; charset=utf-8")],
            body,
        )
        .await
    }
}

fn fixture(name: &str) -> String {
    davhaven_testkit::davhaven_fixtures::dav::sharing(name).unwrap_or_else(|error| panic!("{name}: {error}"))
}

const NS: &str = r#"xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav" xmlns:CS="http://calendarserver.org/ns/""#;

/// The pieces of text, one after the other: the bodies of the requests are built from lists.
fn join<I, S>(pieces: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut out = String::new();
    for piece in pieces {
        out.push_str(piece.as_ref());
    }
    out
}

fn props(names: &[&str]) -> String {
    let elements = join(names.iter().map(|name| format!("<{name}/>")));
    format!("<D:propfind {NS}><D:prop>{elements}</D:prop></D:propfind>")
}

fn sync_body(token: &str, names: &[&str]) -> String {
    let elements = join(names.iter().map(|name| format!("<{name}/>")));
    format!(
        "<D:sync-collection {NS}><D:sync-token>{token}</D:sync-token><D:sync-level>1</D:sync-level>\
         <D:prop>{elements}</D:prop></D:sync-collection>"
    )
}

fn token_search(attributes: &str, tokens: &[&str]) -> String {
    let tokens = join(
        tokens
            .iter()
            .map(|token| format!("<CS:search-token>{token}</CS:search-token>")),
    );
    format!(
        "<CS:calendarserver-principal-search {NS} {attributes}>{tokens}\
         <D:prop><D:displayname/><C:calendar-user-address-set/></D:prop></CS:calendarserver-principal-search>"
    )
}

// ---------------------------------------------------------------------------------------------------------------
// The world
// ---------------------------------------------------------------------------------------------------------------

/// A principal with a display name, which `World::user` does not give.
async fn person(world: &World, org: &Org, name: &str, display: &str, kind: PrincipalKind) -> Person {
    let mut body = principal_body(org, name, kind);
    display.clone_into(&mut body.display_name);
    let view = world.principal_write(org, name, body).await.unwrap();
    Person {
        id: view.id,
        name: view.name,
    }
}

/// The login of `who`, who authenticates with `{name}-secret`.
fn login(world: &World, org: &Org, who: &Person) -> Login {
    let secret = format!("{}-secret", who.name);
    world.auth.accept(
        &secret,
        Authenticated {
            tenant: Some(org.id),
            actor: Actor::Principal(who.id),
            scopes: ScopeSet::empty(),
            credential: CredentialRef::app_password(CredentialId::from_uuid(Uuid::from_u128(
                who.id.as_uuid().as_u128(),
            ))),
            label: Some("test".to_owned()),
        },
    );
    Login {
        login: format!("{}@{}.example", who.name, org.slug),
        secret,
    }
}

/// Two tenants: `acme` with Anna (owner of the calendar `work`) and Ben, `globex` with Gina.
struct Scene {
    world: World,
    acme: Org,
    anna: Person,
    ben: Person,
    anna_login: Login,
    ben_login: Login,
    gina_login: Login,
    dav: Dav,
}

async fn scene() -> Scene {
    scene_on(World::new()).await
}

async fn scene_on(world: World) -> Scene {
    let acme = world.org("acme").await;
    let globex = world.org("globex").await;
    let anna = person(&world, &acme, "anna", "Anna Acme", PrincipalKind::User).await;
    let ben = person(&world, &acme, "ben", "Ben Baker", PrincipalKind::User).await;
    let gina = person(&world, &globex, "gina", "Gina Globex", PrincipalKind::User).await;
    world.calendar(&acme, &anna, "work", CalendarKind::User).await;
    let anna_login = login(&world, &acme, &anna);
    let ben_login = login(&world, &acme, &ben);
    let gina_login = login(&world, &globex, &gina);
    let dav = Dav::new(&world);
    Scene {
        world,
        acme,
        anna,
        ben,
        anna_login,
        ben_login,
        gina_login,
        dav,
    }
}

const WORK: &str = "/dav/calendars/acme/anna/work/";
const ANNA_NOTIFICATIONS: &str = "/dav/calendars/acme/anna/notifications/";
const BEN_NOTIFICATIONS: &str = "/dav/calendars/acme/ben/notifications/";
const BEN_HOME: &str = "/dav/calendars/acme/ben/";
const INVITATION_IN_FIXTURE: &str = "7b2c4f10-4d2e-4f55-9a3e-0d3b2a6c1e11";

/// The hrefs of the notifications of a collection: the answer to `propfind-notifications.xml` without the collection.
async fn notification_hrefs(scene: &Scene, collection: &str, who: &Login) -> Vec<String> {
    let reply = scene
        .dav
        .propfind(collection, who, "1", &fixture("propfind-notifications.xml"))
        .await;
    reply.hrefs().into_iter().filter(|href| href != collection).collect()
}

// ---------------------------------------------------------------------------------------------------------------
// Sharing and notifications
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_flow_of_apple_calendar_from_the_invitation_to_the_shared_calendar() {
    let scene = scene().await;
    let Scene {
        dav,
        anna_login,
        ben_login,
        ..
    } = &scene;

    // 1. Anna shares `work` with Ben, read-write, as Apple Calendar sends it.
    let shared = dav
        .post_xml(WORK, anna_login, &fixture("share-set-read-write.xml"))
        .await;
    assert_eq!(shared.status, StatusCode::OK, "{}", shared.body);
    assert_eq!(shared.body, "");

    // 2. The invitation is in Ben's notification collection, listed the way Apple Calendar lists it.
    let listing = dav
        .propfind(
            BEN_NOTIFICATIONS,
            ben_login,
            "1",
            &fixture("propfind-notifications.xml"),
        )
        .await;
    let hrefs = listing.hrefs();
    assert_eq!(hrefs.len(), 2, "the collection and the invitation: {}", listing.body);
    assert_eq!(hrefs[0], BEN_NOTIFICATIONS);
    let invitation = hrefs[1].clone();
    assert!(invitation.starts_with(BEN_NOTIFICATIONS), "{invitation}");
    let kind = listing
        .prop(&invitation, NS_CALENDARSERVER, "notificationtype")
        .and_then(|kind| kind.elements().next().map(|element| element.local.clone()));
    assert_eq!(kind.as_deref(), Some("invite-notification"), "{}", listing.body);

    // 3. Ben reads it: the document of the application, with its validators.
    let read_it = dav.get(&invitation, ben_login).await;
    assert_eq!(read_it.status, StatusCode::OK);
    assert!(read_it.header("content-type").starts_with("text/xml"));
    let etag = read_it.header("etag").to_owned();
    assert!(etag.starts_with('"'), "{etag}");
    let document = read_it.xml();
    assert!(document.is(NS_CALENDARSERVER, "notification"), "{}", read_it.body);
    let notice = document.child(NS_CALENDARSERVER, "invite-notification").unwrap();
    let uid = notice.child(NS_CALENDARSERVER, "uid").unwrap().text();
    assert_eq!(
        notice
            .child(NS_CALENDARSERVER, "hosturl")
            .and_then(|host| host.child(NS_DAV, "href"))
            .map(davhaven_dav::xml::Element::text)
            .as_deref(),
        Some(WORK)
    );
    assert!(
        notice
            .child(NS_CALENDARSERVER, "access")
            .unwrap()
            .child(NS_CALENDARSERVER, "read-write")
            .is_some()
    );
    let head = dav.send("HEAD", &invitation, Some(ben_login), &[], "").await;
    assert_eq!(head.status, StatusCode::OK);
    assert_eq!(head.body, "");
    assert_eq!(head.header("content-length"), read_it.body.len().to_string());
    assert_eq!(head.header("etag"), etag);
    let unchanged = dav
        .send("GET", &invitation, Some(ben_login), &[("if-none-match", &etag)], "")
        .await;
    assert_eq!(unchanged.status, StatusCode::NOT_MODIFIED);
    let stale = dav
        .send("GET", &invitation, Some(ben_login), &[("if-match", "\"other\"")], "")
        .await;
    assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);

    // 4. Ben synchronizes the collection: one member, and a token for the next time.
    let first = dav
        .report(BEN_NOTIFICATIONS, ben_login, &fixture("sync-notifications.xml"))
        .await;
    assert_eq!(first.hrefs(), vec![invitation.clone()], "{}", first.body);
    let token = first.xml().child(NS_DAV, "sync-token").unwrap().text();

    // 5. Ben accepts. The answer names the calendar in his home.
    let answer = fixture("invite-reply-accepted.xml").replace(INVITATION_IN_FIXTURE, &uid);
    let accepted = dav.post_xml(BEN_HOME, ben_login, &answer).await;
    assert_eq!(accepted.status, StatusCode::OK, "{}", accepted.body);
    let shared_as = accepted.xml();
    assert!(shared_as.is(NS_CALENDARSERVER, "shared-as"), "{}", accepted.body);
    let collection = shared_as.child(NS_DAV, "href").unwrap().text();
    assert!(
        collection.starts_with(BEN_HOME) && collection.ends_with('/'),
        "{collection}"
    );

    // 6. The shared calendar is a collection of Ben's with the resource type of a share and the privileges of a
    //    read-write sharee; Anna's has the resource type of an owner who shares.
    let seen = dav
        .propfind(
            &collection,
            ben_login,
            "0",
            &props(&["D:resourcetype", "D:current-user-privilege-set"]),
        )
        .await;
    let types: Vec<String> = seen
        .prop(&collection, NS_DAV, "resourcetype")
        .unwrap()
        .elements()
        .map(|element| element.local.clone())
        .collect();
    assert!(
        types.contains(&"shared".to_owned()) && types.contains(&"calendar".to_owned()),
        "{types:?}"
    );
    let privileges: Vec<String> = seen
        .prop(&collection, NS_DAV, "current-user-privilege-set")
        .unwrap()
        .children_named(NS_DAV, "privilege")
        .filter_map(|privilege| privilege.elements().next().map(|element| element.local.clone()))
        .collect();
    assert!(privileges.contains(&"write-content".to_owned()), "{privileges:?}");
    let owner_side = dav.propfind(WORK, anna_login, "0", &props(&["D:resourcetype"])).await;
    let types: Vec<String> = owner_side
        .prop(WORK, NS_DAV, "resourcetype")
        .unwrap()
        .elements()
        .map(|element| element.local.clone())
        .collect();
    assert!(types.contains(&"shared-owner".to_owned()), "{types:?}");

    // 7. Anna is told: the answer of Ben is a notification of her own.
    let hers = notification_hrefs(&scene, ANNA_NOTIFICATIONS, anna_login).await;
    assert_eq!(hers.len(), 1, "{hers:?}");
    let reply_notice = dav.get(&hers[0], anna_login).await;
    assert_eq!(reply_notice.status, StatusCode::OK);
    let reply_etag = reply_notice.header("etag").to_owned();
    let reply_document = reply_notice.xml();
    let reply_body = reply_document.child(NS_CALENDARSERVER, "invite-reply").unwrap();
    assert!(
        reply_body.child(NS_CALENDARSERVER, "invite-accepted").is_some(),
        "{}",
        reply_notice.body
    );
    assert_eq!(
        reply_body.child(NS_CALENDARSERVER, "in-reply-to").unwrap().text(),
        uid,
        "the answer names the invitation it answers"
    );

    // 8. She deletes it as Apple Calendar does, with the entity tag she read; a stale tag is refused and nothing is
    //    deleted.
    let wrong = dav
        .send("DELETE", &hers[0], Some(anna_login), &[("if-match", "\"stale\"")], "")
        .await;
    assert_eq!(wrong.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(dav.get(&hers[0], anna_login).await.status, StatusCode::OK);
    let anna_sync = dav
        .report(ANNA_NOTIFICATIONS, anna_login, &sync_body("", &["D:getetag"]))
        .await;
    let anna_token = anna_sync.xml().child(NS_DAV, "sync-token").unwrap().text();
    let deleted = dav
        .send("DELETE", &hers[0], Some(anna_login), &[("if-match", &reply_etag)], "")
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    assert_eq!(dav.get(&hers[0], anna_login).await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        dav.send("DELETE", &hers[0], Some(anna_login), &[], "").await.status,
        StatusCode::NOT_FOUND,
        "a second deletion finds nothing"
    );
    assert!(
        notification_hrefs(&scene, ANNA_NOTIFICATIONS, anna_login)
            .await
            .is_empty()
    );
    // A client that synchronized before hears of the deletion as a 404 entry.
    let after = dav
        .report(ANNA_NOTIFICATIONS, anna_login, &sync_body(&anna_token, &["D:getetag"]))
        .await;
    assert_eq!(after.responses(), [(hers[0].clone(), Some(404))], "{}", after.body);

    // 9. Ben's own invitation is still there (answering does not need it to go) until he deletes it.
    let still = notification_hrefs(&scene, BEN_NOTIFICATIONS, ben_login).await;
    assert_eq!(still, vec![invitation.clone()]);
    let removed = dav.send("DELETE", &invitation, Some(ben_login), &[], "").await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT);
    let synced = dav
        .report(BEN_NOTIFICATIONS, ben_login, &sync_body(&token, &["D:getetag"]))
        .await;
    assert_eq!(synced.responses(), [(invitation.clone(), Some(404))], "{}", synced.body);
    assert_eq!(
        dav.propfind(&collection, ben_login, "0", &props(&["D:displayname"]))
            .await
            .status,
        StatusCode::MULTI_STATUS,
        "the share outlives the notification"
    );
}

#[tokio::test]
async fn a_share_request_with_an_outside_address_is_a_207_with_one_response_for_every_item() {
    let scene = scene().await;
    let body = r#"<CS:share xmlns:D="DAV:" xmlns:CS="http://calendarserver.org/ns/">
             <CS:set><D:href>mailto:Guest@Elsewhere.example</D:href><CS:read/></CS:set>
             <CS:set><D:href>mailto:Ben@Acme.example</D:href><CS:read-write/></CS:set>
           </CS:share>"#;
    let reply = scene.dav.post_xml(WORK, &scene.anna_login, body).await;
    assert_eq!(reply.status, StatusCode::MULTI_STATUS, "{}", reply.body);
    // Sorted, and named as the client named them.
    assert_eq!(
        reply.responses(),
        [
            ("mailto:Ben@Acme.example".to_owned(), Some(200)),
            ("mailto:Guest@Elsewhere.example".to_owned(), Some(403)),
        ],
        "{}",
        reply.body
    );
    // The item that could be applied was: Ben has the invitation.
    assert_eq!(
        notification_hrefs(&scene, BEN_NOTIFICATIONS, &scene.ben_login)
            .await
            .len(),
        1
    );
    // Applying the same request again changes nothing: every item is answered again.
    let again = scene.dav.post_xml(WORK, &scene.anna_login, body).await;
    assert_eq!(again.status, StatusCode::MULTI_STATUS);
    assert_eq!(
        notification_hrefs(&scene, BEN_NOTIFICATIONS, &scene.ben_login)
            .await
            .len(),
        1,
        "one invitation, not two"
    );
}

#[tokio::test]
async fn strangers_and_other_tenants_see_nothing_of_a_share_and_change_nothing_by_asking() {
    let scene = scene().await;
    let Scene {
        dav,
        anna_login,
        ben_login,
        gina_login,
        ..
    } = &scene;
    // Anna invites Ben, so that there are notifications to ask for, and Ben answers: both have one.
    assert_eq!(
        dav.post_xml(WORK, anna_login, &fixture("share-set-read-write.xml"))
            .await
            .status,
        StatusCode::OK
    );
    let invitation = notification_hrefs(&scene, BEN_NOTIFICATIONS, ben_login).await.remove(0);
    let uid = dav.get(&invitation, ben_login).await.xml();
    let uid = uid
        .child(NS_CALENDARSERVER, "invite-notification")
        .and_then(|notice| notice.child(NS_CALENDARSERVER, "uid"))
        .map(davhaven_dav::xml::Element::text)
        .unwrap();
    let accepted = fixture("invite-reply-accepted.xml").replace(INVITATION_IN_FIXTURE, &uid);
    assert_eq!(
        dav.post_xml(BEN_HOME, ben_login, &accepted).await.status,
        StatusCode::OK
    );
    let hers = notification_hrefs(&scene, ANNA_NOTIFICATIONS, anna_login)
        .await
        .remove(0);

    // The state before the denied requests.
    let calendar_token = |reply: &Reply| {
        reply
            .prop(WORK, "http://calendarserver.org/ns/", "getctag")
            .unwrap()
            .text()
    };
    let before = calendar_token(&dav.propfind(WORK, anna_login, "0", &props(&["CS:getctag"])).await);
    let sync_before = dav
        .report(ANNA_NOTIFICATIONS, anna_login, &sync_body("", &["D:getetag"]))
        .await
        .xml()
        .child(NS_DAV, "sync-token")
        .unwrap()
        .text();
    let bens_before = notification_hrefs(&scene, BEN_NOTIFICATIONS, ben_login).await;

    // Anna's notification: nobody else reads, lists, synchronizes or deletes it, whoever they are.
    for (who, name) in [(ben_login, "ben"), (gina_login, "gina")] {
        for method in ["GET", "HEAD", "DELETE", "PROPFIND"] {
            let answer = dav.send(method, &hers, Some(who), &[("depth", "0")], "").await;
            assert_eq!(answer.status, StatusCode::NOT_FOUND, "{name} {method}");
        }
        for method in ["PROPFIND", "REPORT"] {
            let answer = dav
                .send(
                    method,
                    ANNA_NOTIFICATIONS,
                    Some(who),
                    &[("depth", "1"), ("content-type", "application/xml")],
                    &if method == "REPORT" {
                        fixture("sync-notifications.xml")
                    } else {
                        fixture("propfind-notifications.xml")
                    },
                )
                .await;
            assert_eq!(
                answer.status,
                StatusCode::NOT_FOUND,
                "{name} {method} of the collection"
            );
        }
        // Sharing Anna's calendar, answering for Anna, posting to her outbox: no.
        assert_eq!(
            dav.post_xml(WORK, who, &fixture("share-set-read.xml")).await.status,
            StatusCode::NOT_FOUND,
            "{name} shares"
        );
        let reply = fixture("invite-reply-declined.xml").replace(INVITATION_IN_FIXTURE, &uid);
        assert_eq!(
            dav.post_xml("/dav/calendars/acme/anna/", who, &reply).await.status,
            StatusCode::NOT_FOUND,
            "{name} replies in the home of Anna"
        );
        let outbox = dav
            .send(
                "POST",
                "/dav/calendars/acme/anna/outbox/",
                Some(who),
                &[("content-type", "text/calendar")],
                &fixture("outbox-freebusy-request.ics"),
            )
            .await;
        assert_eq!(
            outbox.status,
            StatusCode::NOT_FOUND,
            "{name} posts to the outbox of Anna"
        );
    }
    // Ben's notification collection, asked for by somebody of another tenant.
    assert_eq!(
        dav.propfind(
            BEN_NOTIFICATIONS,
            gina_login,
            "1",
            &fixture("propfind-notifications.xml")
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
    // And nothing changed.
    assert_eq!(
        before,
        calendar_token(&dav.propfind(WORK, anna_login, "0", &props(&["CS:getctag"])).await)
    );
    let sync_after = dav
        .report(ANNA_NOTIFICATIONS, anna_login, &sync_body("", &["D:getetag"]))
        .await
        .xml()
        .child(NS_DAV, "sync-token")
        .unwrap()
        .text();
    assert_eq!(sync_before, sync_after);
    assert_eq!(
        bens_before,
        notification_hrefs(&scene, BEN_NOTIFICATIONS, ben_login).await
    );
    assert_eq!(
        dav.get(&hers, anna_login).await.status,
        StatusCode::OK,
        "Anna's notification is still there"
    );
}

#[tokio::test]
async fn a_share_request_that_names_too_many_sharees_is_refused_only_to_those_who_see_the_calendar() {
    let scene = scene().await;
    let most = usize::try_from(DavLimits::default().max_sharees_per_request).unwrap();
    let body = format!(
        r#"<CS:share xmlns:D="DAV:" xmlns:CS="http://calendarserver.org/ns/">{}</CS:share>"#,
        join((0..=most).map(|n| format!("<CS:set><D:href>mailto:user{n}@acme.example</D:href><CS:read/></CS:set>")))
    );
    let owner = scene.dav.post_xml(WORK, &scene.anna_login, &body).await;
    assert_eq!(owner.status, StatusCode::FORBIDDEN);
    assert!(owner.body.contains("number-of-matches-within-limits"), "{}", owner.body);
    for who in [&scene.ben_login, &scene.gina_login] {
        assert_eq!(scene.dav.post_xml(WORK, who, &body).await.status, StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn a_post_that_a_web_page_could_have_sent_does_not_reach_the_application() {
    let scene = scene().await;
    let before = notification_hrefs(&scene, BEN_NOTIFICATIONS, &scene.ben_login).await;
    for media_type in [
        "text/plain",
        "application/x-www-form-urlencoded",
        "multipart/form-data; boundary=x",
    ] {
        let reply = scene
            .dav
            .send(
                "POST",
                WORK,
                Some(&scene.anna_login),
                &[("content-type", media_type)],
                &fixture("share-set-read-write.xml"),
            )
            .await;
        assert_eq!(reply.status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{media_type}");
    }
    assert_eq!(
        before,
        notification_hrefs(&scene, BEN_NOTIFICATIONS, &scene.ben_login).await
    );
}

// ---------------------------------------------------------------------------------------------------------------
// The sharee: who may act, as against who may see (R4, R9, PLAN 3.2)
// ---------------------------------------------------------------------------------------------------------------

/// A `CS:share` document that invites `address` with `access` (`read` or `read-write`).
fn share_of(address: &str, access: &str) -> String {
    format!(
        "<CS:share xmlns:D=\"DAV:\" xmlns:CS=\"http://calendarserver.org/ns/\">\
         <CS:set><D:href>{address}</D:href><CS:{access}/></CS:set></CS:share>"
    )
}

/// The `CS:invite-reply` with which `who` answers the invitation in their notification collection.
async fn answer_invitation(scene: &Scene, who: &Login, home: &str, template: &str) -> Reply {
    let invitation = notification_hrefs(scene, &format!("{home}notifications/"), who)
        .await
        .remove(0);
    let document = scene.dav.get(&invitation, who).await.xml();
    let uid = document
        .child(NS_CALENDARSERVER, "invite-notification")
        .and_then(|notice| notice.child(NS_CALENDARSERVER, "uid"))
        .map(davhaven_dav::xml::Element::text)
        .unwrap();
    let answer = fixture(template).replace(INVITATION_IN_FIXTURE, &uid);
    scene.dav.post_xml(home, who, &answer).await
}

/// Invites `address` to `work` with `access` as Anna and answers as `who`: the collection in the home of the sharee.
async fn share_and_accept(scene: &Scene, who: &Login, home: &str, address: &str, access: &str) -> String {
    let shared = scene
        .dav
        .post_xml(WORK, &scene.anna_login, &share_of(address, access))
        .await;
    assert_eq!(shared.status, StatusCode::OK, "{}", shared.body);
    let accepted = answer_invitation(scene, who, home, "invite-reply-accepted.xml").await;
    assert_eq!(accepted.status, StatusCode::OK, "{}", accepted.body);
    accepted.xml().child(NS_DAV, "href").unwrap().text()
}

/// What a share request that is denied must not touch: the state of the calendar as its owner sees it (the change
/// token and the sharees), and the notification collections of everybody who could be told something.
async fn sharing_state(scene: &Scene, others: &[(&str, &Login)]) -> Vec<String> {
    let owner = scene
        .dav
        .propfind(WORK, &scene.anna_login, "0", &props(&["CS:getctag", "CS:invite"]))
        .await;
    let mut state = vec![owner.body];
    for (collection, who) in others {
        state.push(notification_hrefs(scene, collection, who).await.join(","));
    }
    state
}

#[tokio::test]
async fn a_sharee_who_may_read_or_write_may_not_share_the_calendar_further_and_nothing_happens() {
    let scene = scene().await;
    let rita = person(&scene.world, &scene.acme, "rita", "Rita Rose", PrincipalKind::User).await;
    let rita_login = login(&scene.world, &scene.acme, &rita);
    let rita_notifications = "/dav/calendars/acme/rita/notifications/";
    let Scene {
        dav,
        anna_login,
        ben_login,
        gina_login,
        ..
    } = &scene;
    let ben_binding = share_and_accept(&scene, ben_login, BEN_HOME, "mailto:ben@acme.example", "read").await;

    // Ben sees the calendar through his own binding, as a reader; the other people he could invite are somebody's
    // business only when they are told. The state before the requests Ben is not allowed to make:
    let watched = [
        (ANNA_NOTIFICATIONS, anna_login),
        (BEN_NOTIFICATIONS, ben_login),
        (rita_notifications, &rita_login),
    ];
    let before = sharing_state(&scene, &watched).await;

    let invite_rita = share_of("mailto:rita@acme.example", "read");
    let too_many = {
        let most = usize::try_from(DavLimits::default().max_sharees_per_request).unwrap();
        format!(
            r#"<CS:share xmlns:D="DAV:" xmlns:CS="http://calendarserver.org/ns/">{}</CS:share>"#,
            join(
                (0..=most).map(|n| format!("<CS:set><D:href>mailto:user{n}@acme.example</D:href><CS:read/></CS:set>"))
            )
        )
    };
    let remove_anna = "<CS:share xmlns:D=\"DAV:\" xmlns:CS=\"http://calendarserver.org/ns/\">\
                       <CS:remove><D:href>mailto:anna@acme.example</D:href></CS:remove></CS:share>";
    for access in ["read", "read-write"] {
        if access == "read-write" {
            // Anna raises the access of Ben: the same binding, more rights, still no right to share.
            let raised = dav
                .post_xml(WORK, anna_login, &share_of("mailto:ben@acme.example", "read-write"))
                .await;
            assert_eq!(raised.status, StatusCode::OK, "{}", raised.body);
        }
        let state_before = sharing_state(&scene, &watched).await;
        // A sharee sees the calendar, so a refusal tells them what they lack; it does not tell anybody anything else.
        for (what, body) in [("invite", &invite_rita), ("remove the owner", &remove_anna.to_owned())] {
            let denied = dav.post_xml(&ben_binding, ben_login, body).await;
            assert_eq!(denied.status, StatusCode::FORBIDDEN, "{access} {what}: {}", denied.body);
            assert!(
                denied.body.contains("need-privileges") && denied.body.contains("<CS:share/>"),
                "{access} {what}: the missing privilege is `share`: {}",
                denied.body
            );
        }
        // A body that cannot be read is the sharee's 400, and a request over the limit their 403: they can see the
        // calendar, and nothing is applied either way.
        let malformed = dav.post_xml(&ben_binding, ben_login, "<CS:share").await;
        assert_eq!(malformed.status, StatusCode::BAD_REQUEST, "{access}");
        let nobody = dav
            .post_xml(
                &ben_binding,
                ben_login,
                "<CS:share xmlns:CS=\"http://calendarserver.org/ns/\"/>",
            )
            .await;
        assert_eq!(nobody.status, StatusCode::BAD_REQUEST, "{access}");
        let crowd = dav.post_xml(&ben_binding, ben_login, &too_many).await;
        assert_eq!(crowd.status, StatusCode::FORBIDDEN, "{access}");
        assert!(crowd.body.contains("number-of-matches-within-limits"), "{}", crowd.body);
        // Answering for somebody else is no better: Anna's invitation is nobody's but hers to answer for.
        assert_eq!(
            sharing_state(&scene, &watched).await,
            state_before,
            "{access}: no token, sharee or notification changed"
        );
        // A stranger is not told that the binding exists, whatever they ask.
        assert_eq!(
            dav.post_xml(&ben_binding, gina_login, &invite_rita).await.status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            dav.post_xml(&ben_binding, anna_login, &invite_rita).await.status,
            StatusCode::NOT_FOUND,
            "not even the owner of the calendar acts through the home of somebody else"
        );
    }
    assert_ne!(
        before,
        sharing_state(&scene, &watched).await,
        "only the raising of the access changed something"
    );
}

#[tokio::test]
async fn an_administrator_of_a_calendar_may_share_it_and_a_sharee_who_has_not_accepted_cannot_reach_it() {
    let scene = scene().await;
    let rita = person(&scene.world, &scene.acme, "rita", "Rita Rose", PrincipalKind::User).await;
    let rita_login = login(&scene.world, &scene.acme, &rita);
    let rita_home = "/dav/calendars/acme/rita/";
    let Scene {
        world,
        acme,
        anna,
        dav,
        anna_login,
        ben_login,
        ..
    } = &scene;
    let ben_binding = share_and_accept(&scene, ben_login, BEN_HOME, "mailto:ben@acme.example", "read-write").await;
    // The management API makes Ben an administrator of the calendar: the privilege `share` is his now.
    world
        .services
        .sharing
        .put_grant(
            &world.admin(acme),
            GrantSpec {
                calendar: world.key(anna, "work"),
                grantee: scene.ben.name.clone(),
                body: GrantWrite {
                    access: GrantAccess::Admin,
                    required: false,
                },
            },
            Conditions::none(),
        )
        .await
        .unwrap();
    let token_before = dav.propfind(WORK, anna_login, "0", &props(&["CS:getctag"])).await.body;
    let invited = dav
        .post_xml(&ben_binding, ben_login, &share_of("mailto:rita@acme.example", "read"))
        .await;
    assert_eq!(invited.status, StatusCode::OK, "{}", invited.body);
    assert_eq!(
        notification_hrefs(&scene, &format!("{rita_home}notifications/"), &rita_login)
            .await
            .len(),
        1,
        "the administrator's invitation arrived"
    );
    assert_ne!(
        token_before,
        dav.propfind(WORK, anna_login, "0", &props(&["CS:getctag"])).await.body,
        "and the calendar changed"
    );

    // Rita was invited and has not answered: she has no binding, so there is nothing to POST to, whatever she
    // guesses; Anna's calendar is not at her path either.
    for path in [
        "/dav/calendars/acme/rita/annas-work/",
        "/dav/calendars/acme/rita/work/",
        WORK,
    ] {
        let answer = dav
            .post_xml(path, &rita_login, &share_of("mailto:cara@acme.example", "read"))
            .await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{path}");
    }
    // She accepts: now there is a binding, and a reader's. Leaving the share ends it again.
    let accepted = answer_invitation(&scene, &rita_login, rita_home, "invite-reply-accepted.xml").await;
    assert_eq!(accepted.status, StatusCode::OK, "{}", accepted.body);
    let binding = accepted.xml().child(NS_DAV, "href").unwrap().text();
    let denied = dav
        .post_xml(&binding, &rita_login, &share_of("mailto:cara@acme.example", "read"))
        .await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN, "{}", denied.body);
    let left = dav.send("DELETE", &binding, Some(&rita_login), &[], "").await;
    assert_eq!(left.status, StatusCode::NO_CONTENT, "{}", left.body);
    let gone = dav
        .post_xml(&binding, &rita_login, &share_of("mailto:cara@acme.example", "read"))
        .await;
    assert_eq!(
        gone.status,
        StatusCode::NOT_FOUND,
        "a sharee who has left has no binding to act through"
    );
}

#[tokio::test]
async fn a_managed_calendar_cannot_be_shared_through_dav_and_nothing_is_sent() {
    let scene = scene().await;
    let managed = "/dav/calendars/acme/anna/managed/";
    scene
        .world
        .calendar(&scene.acme, &scene.anna, "managed", CalendarKind::Managed)
        .await;
    let denied = scene
        .dav
        .post_xml(managed, &scene.anna_login, &share_of("mailto:ben@acme.example", "read"))
        .await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN, "{}", denied.body);
    assert!(
        notification_hrefs(&scene, BEN_NOTIFICATIONS, &scene.ben_login)
            .await
            .is_empty()
    );
    for stranger in [&scene.ben_login, &scene.gina_login] {
        let answer = scene
            .dav
            .post_xml(managed, stranger, &share_of("mailto:ben@acme.example", "read"))
            .await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn with_sharing_switched_off_only_those_who_see_the_calendar_are_told() {
    let scene = scene_on(World::with(|deps| deps.config.sharing.enabled = false)).await;
    let body = share_of("mailto:ben@acme.example", "read");
    let owner = scene.dav.post_xml(WORK, &scene.anna_login, &body).await;
    assert_eq!(owner.status, StatusCode::FORBIDDEN, "{}", owner.body);
    // Everybody else gets what they get when sharing is on: a calendar that is not there, whether it exists or not.
    for (path, who) in [
        (WORK, &scene.ben_login),
        (WORK, &scene.gina_login),
        ("/dav/calendars/acme/anna/nothing/", &scene.anna_login),
        ("/dav/calendars/globex/anna/work/", &scene.anna_login),
        ("/dav/calendars/acme/ben/nothing/", &scene.ben_login),
    ] {
        let answer = scene.dav.post_xml(path, who, &body).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{path}");
    }
    assert!(
        notification_hrefs(&scene, BEN_NOTIFICATIONS, &scene.ben_login)
            .await
            .is_empty()
    );
}

// ---------------------------------------------------------------------------------------------------------------
// Conditional deletion of a notification that is rewritten in place
// ---------------------------------------------------------------------------------------------------------------

/// The dates of a notification as its owner reads them.
async fn dates_of(scene: &Scene, notification: &str) -> Reply {
    scene
        .dav
        .propfind(
            notification,
            &scene.ben_login,
            "0",
            &props(&["D:creationdate", "D:getlastmodified", "D:getetag"]),
        )
        .await
}

#[tokio::test]
async fn an_if_match_that_was_true_when_the_client_read_the_invitation_does_not_delete_a_newer_one() {
    let scene = scene().await;
    let Scene {
        dav,
        anna_login,
        ben_login,
        ..
    } = &scene;
    let shared = dav
        .post_xml(WORK, anna_login, &share_of("mailto:ben@acme.example", "read-write"))
        .await;
    assert_eq!(shared.status, StatusCode::OK, "{}", shared.body);
    let invitation = notification_hrefs(&scene, BEN_NOTIFICATIONS, ben_login).await.remove(0);
    let first = dav.get(&invitation, ben_login).await;
    let (first_tag, first_date) = (
        first.header("etag").to_owned(),
        first.header("last-modified").to_owned(),
    );
    let created = |reply: &Reply| reply.prop(&invitation, NS_DAV, "creationdate").unwrap().text();
    let created_first = created(&dates_of(&scene, &invitation).await);

    // The application rewrites the invitation in place when the access of the sharee changes: a new document, a new
    // entity tag and a new date, at the same address; the date of creation stays.
    scene.world.clock.advance(chrono::Duration::hours(2));
    let changed = dav
        .post_xml(WORK, anna_login, &share_of("mailto:ben@acme.example", "read"))
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.body);
    let second = dav.get(&invitation, ben_login).await;
    let second_tag = second.header("etag").to_owned();
    assert_ne!(first_tag, second_tag, "rewritten in place");
    assert_ne!(
        first_date,
        second.header("last-modified"),
        "the date goes with the entity tag: a client that compares dates sees the change"
    );
    let after = dates_of(&scene, &invitation).await;
    assert_eq!(
        created(&after),
        created_first,
        "the date of creation is the date of creation"
    );
    assert_ne!(
        after.prop(&invitation, NS_DAV, "getlastmodified").unwrap().text(),
        first_date
    );

    // The client still holds the old tag: it must not delete what it has not read.
    let stale = dav
        .send("DELETE", &invitation, Some(ben_login), &[("if-match", &first_tag)], "")
        .await;
    assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED, "{}", stale.body);
    assert_eq!(
        dav.get(&invitation, ben_login).await.status,
        StatusCode::OK,
        "still there"
    );
    let current = dav
        .send("DELETE", &invitation, Some(ben_login), &[("if-match", &second_tag)], "")
        .await;
    assert_eq!(current.status, StatusCode::NO_CONTENT, "{}", current.body);
    assert_eq!(dav.get(&invitation, ben_login).await.status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------------------------------------------
// Principal search over real data
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn principal_search_finds_rooms_and_people_in_a_tenant_where_more_than_fifty_match_the_text() {
    let scene = scene().await;
    let Scene {
        world,
        acme,
        dav,
        anna_login,
        gina_login,
        ..
    } = &scene;
    for number in 0..60 {
        person(
            world,
            acme,
            &format!("rosa{number:02}"),
            &format!("Anna Aaron Rosa {number:02}"),
            PrincipalKind::User,
        )
        .await;
    }
    person(world, acme, "abauer", "Anna Bauer", PrincipalKind::User).await;
    person(world, acme, "room1", "Meeting Room 1", PrincipalKind::Resource).await;
    person(world, acme, "robot", "Robot Service", PrincipalKind::Service).await;
    let mut suspended = principal_body(acme, "carl", PrincipalKind::User);
    "Carl Rosario".clone_into(&mut suspended.display_name);
    suspended.status = Some(PrincipalStatus::Suspended);
    world.principal_write(acme, "carl", suspended).await.unwrap();
    let globex = world.org("globex").await;
    person(world, &globex, "rosa-globex", "Rosa Globex", PrincipalKind::User).await;

    let found = |reply: Reply| reply.hrefs();
    // The location picker: the room, although the first 50 people by display name all match "ro".
    for attributes in [
        "context=\"location\"",
        "context=\"resource\"",
        "context=\"attendee\" type=\"ROOM\"",
    ] {
        assert_eq!(
            found(
                dav.report("/dav/", anna_login, &token_search(attributes, &["ro"]))
                    .await
            ),
            ["/dav/principals/acme/room1/"],
            "{attributes}"
        );
    }
    // The person of a two-word search, however many are called Anna. Sixty are, and Anna Bauer sorts behind them all
    // by display name: what Apple Calendar sends while the user types "Anna B", "Anna Bau" and "Anna Baue" is
    // answered from one search whose conditions are all applied before the cut at 50, so she is found at the first
    // letter of her surname (an application that looked up the longest token, `anna`, and checked the others on its
    // first 50 hits would find nobody before `bauer`).
    let cases: [&[&str]; 8] = [
        &["anna", "b"],
        &["anna", "bau"],
        &["anna", "baue"],
        &["anna", "bauer"],
        &["bauer", "a"],
        &["a", "anna", "bauer"],
        &["Anna", "BAUER"],
        &["anna", "abauer@"],
    ];
    for tokens in cases {
        assert_eq!(
            found(dav.report("/dav/", anna_login, &token_search("", tokens)).await),
            ["/dav/principals/acme/abauer/"],
            "{tokens:?}"
        );
    }
    // The answer is at most 50 principals, sorted by href, and never a service, a suspended user or another tenant's.
    let everyone = found(
        dav.report("/dav/", anna_login, &token_search("context=\"user\"", &["ro"]))
            .await,
    );
    assert_eq!(
        everyone.len(),
        51,
        "50 principals and the entry that says the answer was cut"
    );
    assert_eq!(everyone.last().map(String::as_str), Some("/dav/"));
    let everyone = &everyone[..50];
    let mut sorted = everyone.to_vec();
    sorted.sort();
    assert_eq!(everyone, sorted);
    for href in everyone {
        assert!(href.starts_with("/dav/principals/acme/rosa"), "{href}");
    }
    assert!(
        found(dav.report("/dav/", anna_login, &token_search("", &["robot"])).await).is_empty(),
        "a service is no one to invite"
    );
    assert!(
        found(dav.report("/dav/", anna_login, &token_search("", &["carl"])).await).is_empty(),
        "a suspended user cannot be invited"
    );
    assert_eq!(
        found(dav.report("/dav/", gina_login, &token_search("", &["rosa"])).await),
        ["/dav/principals/globex/rosa-globex/"],
        "Gina finds the people of her own tenant only"
    );
    assert!(
        found(dav.report("/dav/", anna_login, &token_search("", &["globex"])).await).is_empty(),
        "and Anna none of Gina's"
    );
    // What a hit tells: the display name and the addresses.
    let one = dav.report("/dav/", anna_login, &token_search("", &["abauer"])).await;
    let href = "/dav/principals/acme/abauer/";
    assert_eq!(one.prop(href, NS_DAV, "displayname").unwrap().text(), "Anna Bauer");
    let addresses: Vec<String> = one
        .prop(href, "urn:ietf:params:xml:ns:caldav", "calendar-user-address-set")
        .unwrap()
        .children_named(NS_DAV, "href")
        .map(davhaven_dav::xml::Element::text)
        .collect();
    assert!(
        addresses.contains(&"mailto:abauer@acme.example".to_owned()),
        "{addresses:?}"
    );
}

#[tokio::test]
async fn a_property_search_looks_into_the_properties_it_names_over_real_principals() {
    let scene = scene().await;
    let search = format!(
        "<D:principal-property-search {NS} test=\"allof\">\
           <D:property-search><D:prop><D:displayname/></D:prop><D:match>baker</D:match></D:property-search>\
           <D:property-search><D:prop><C:calendar-user-address-set/></D:prop>\
             <D:match match-type=\"starts-with\">mailto:ben@</D:match></D:property-search>\
           <D:prop><D:displayname/></D:prop></D:principal-property-search>"
    );
    for path in ["/dav/", "/dav/principals/acme/anna/"] {
        let reply = scene.dav.report(path, &scene.anna_login, &search).await;
        assert_eq!(reply.hrefs(), ["/dav/principals/acme/ben/"], "{path}");
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The scheduling inbox and outbox
// ---------------------------------------------------------------------------------------------------------------

/// The real scheduling service of the application with a record of what the DAV layer asks of it.
///
/// Every call is delegated: who may see an inbox, which items it holds and how a message is cut down to the selection
/// of a request are the application's (`SchedulingServiceImpl`), so what these tests show about the isolation of the
/// inbox and about the bulk read is the production code's. The wrapper only counts and records, so that a test can say
/// how many reads a request costs and which arguments reach the service.
struct Recording {
    inner: Arc<dyn SchedulingService>,
    db: Arc<CountingDatabase>,
    org: Org,
    /// The owner of the inbox that the next race removes an item from.
    owner: PrincipalId,
    /// The sizes of the calls of `inbox_get_many`.
    bulk_reads: Mutex<Vec<usize>>,
    /// What the calls of `inbox_get_many` asked for of the messages.
    specs: Mutex<Vec<CalendarDataSpec>>,
    /// How often `inbox_get` was called.
    single_reads: Mutex<usize>,
    /// How often `inbox_list` was called.
    listings: Mutex<usize>,
    /// The items `inbox_delete` removed.
    deleted: Mutex<Vec<ResourcePath>>,
    /// The `(owner, body)` of the outbox requests that were answered.
    posts: Mutex<Vec<(PrincipalName, String)>>,
    /// An item that is deleted right after the next listing, as another request would delete it.
    vanishes_after_list: Mutex<Option<ObjectUri>>,
}

#[async_trait]
impl SchedulingService for Recording {
    async fn free_busy(&self, ctx: &RequestContext, request: FreeBusyRequest) -> AppResult<FreeBusyResult> {
        self.inner.free_busy(ctx, request).await
    }

    async fn find_free_slots(&self, ctx: &RequestContext, request: FindSlotsRequest) -> AppResult<FindSlotsResult> {
        self.inner.find_free_slots(ctx, request).await
    }

    async fn outbox_post(
        &self,
        ctx: &RequestContext,
        principal: &PrincipalName,
        body: String,
    ) -> AppResult<ScheduleResponse> {
        let answer = self.inner.outbox_post(ctx, principal, body.clone()).await?;
        locked(&self.posts).push((principal.clone(), body));
        Ok(answer)
    }

    async fn inbox_list(&self, ctx: &RequestContext, principal: &PrincipalName) -> AppResult<Vec<InboxItemView>> {
        *locked(&self.listings) += 1;
        let listed = self.inner.inbox_list(ctx, principal).await?;
        let vanished = locked(&self.vanishes_after_list).take();
        if let Some(uri) = vanished {
            let mut tx = self.db.store().begin(self.org.id, TxMode::ReadWrite).await?;
            let item = tx.inbox().get_by_uri(self.owner, &uri).await?;
            tx.inbox().delete(item.id).await?;
            tx.commit().await?;
        }
        Ok(listed)
    }

    async fn inbox_get(&self, ctx: &RequestContext, path: &ResourcePath) -> AppResult<InboxItemView> {
        *locked(&self.single_reads) += 1;
        self.inner.inbox_get(ctx, path).await
    }

    async fn inbox_get_many(
        &self,
        ctx: &RequestContext,
        inbox: &ResourcePath,
        paths: Vec<ResourcePath>,
        spec: &CalendarDataSpec,
    ) -> AppResult<Vec<InboxEntry>> {
        locked(&self.bulk_reads).push(paths.len());
        locked(&self.specs).push(spec.clone());
        self.inner.inbox_get_many(ctx, inbox, paths, spec).await
    }

    async fn inbox_delete(&self, ctx: &RequestContext, path: &ResourcePath) -> AppResult<()> {
        self.inner.inbox_delete(ctx, path).await?;
        locked(&self.deleted).push(path.clone());
        Ok(())
    }

    async fn respond(
        &self,
        ctx: &RequestContext,
        object: ObjectRef,
        response: InvitationResponse,
    ) -> AppResult<EventView> {
        self.inner.respond(ctx, object, response).await
    }

    async fn inbound_itip(&self, ctx: &RequestContext, request: InboundItipRequest) -> AppResult<InboundItipResponse> {
        self.inner.inbound_itip(ctx, request).await
    }

    async fn rsvp_page(&self, ctx: &RequestContext) -> AppResult<RenderedPage> {
        self.inner.rsvp_page(ctx).await
    }

    async fn rsvp_answer(&self, ctx: &RequestContext, answer: RsvpAnswer, csrf: CsrfToken) -> AppResult<RenderedPage> {
        self.inner.rsvp_answer(ctx, answer, csrf).await
    }
}

/// A scene whose DAV layer asks the real scheduling service through a [`Recording`].
async fn scene_with_inbox(
    adjust: impl FnOnce(&mut davhaven_testkit::davhaven_app::AppDeps),
) -> (Scene, Arc<Recording>) {
    let mut scene = scene_on(World::with(adjust)).await;
    let scheduling = Arc::new(Recording {
        inner: Arc::clone(&scene.world.services.scheduling),
        db: Arc::clone(&scene.world.db),
        org: scene.acme.clone(),
        owner: scene.anna.id,
        bulk_reads: Mutex::new(Vec::new()),
        specs: Mutex::new(Vec::new()),
        single_reads: Mutex::new(0),
        listings: Mutex::new(0),
        deleted: Mutex::new(Vec::new()),
        posts: Mutex::new(Vec::new()),
        vanishes_after_list: Mutex::new(None),
    });
    let mut services = scene.world.services.clone();
    services.scheduling = Arc::<Recording>::clone(&scheduling);
    scene.dav = Dav::on(services);
    (scene, scheduling)
}

/// Delivers a message of `size` bytes to the inbox of `to`, as the scheduling application will, and returns its href.
async fn deliver_to(scene: &Scene, to: &Person, name: &str, size: usize) -> String {
    let frame = |filler: &str| {
        format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Davhaven//tests//EN\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\n\
             UID:{name}\r\nDTSTAMP:20270301T090000Z\r\nDTSTART:20270301T100000Z\r\nDTEND:20270301T110000Z\r\n\
             SUMMARY:{filler}\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
        )
    };
    let data = frame(&"x".repeat(size - frame("").len()));
    assert_eq!(data.len(), size);
    let now = scene.world.now();
    let mut tx = scene
        .world
        .db
        .store()
        .begin(scene.acme.id, TxMode::ReadWrite)
        .await
        .unwrap();
    tx.inbox()
        .create(InboxItem {
            id: InboxItemId::from_uuid(scene.world.ids.new_id()),
            tenant_id: scene.acme.id,
            principal_id: to.id,
            uri: ObjectUri::parse(name).unwrap(),
            etag: ETag::from_bytes(data.as_bytes()),
            data,
            quarantined: false,
            created_at: now,
            updated_at: now,
            version: 1,
        })
        .await
        .unwrap();
    tx.commit().await.unwrap();
    format!("/dav/calendars/acme/{}/inbox/{name}", to.name)
}

/// Delivers a message of `size` bytes to the inbox of Anna and returns its href.
async fn deliver(scene: &Scene, name: &str, size: usize) -> String {
    deliver_to(scene, &scene.anna, name, size).await
}

const INBOX: &str = "/dav/calendars/acme/anna/inbox/";

#[tokio::test]
async fn the_inbox_is_listed_synchronized_and_fetched_with_one_read_per_step_and_not_one_per_item() {
    let (scene, scheduling) = scene_with_inbox(|_| {}).await;
    let mut hrefs = Vec::new();
    for number in 0..7 {
        hrefs.push(deliver(&scene, &format!("m{number}.ics"), 400).await);
    }
    let Scene { dav, anna_login, .. } = &scene;
    let reads = || {
        (
            locked(&scheduling.bulk_reads).clone(),
            *locked(&scheduling.single_reads),
        )
    };

    // The listing of the entity tags is the listing of the application and reads no message.
    let listing = dav.propfind(INBOX, anna_login, "1", &props(&["D:getetag"])).await;
    assert_eq!(listing.hrefs()[0], INBOX);
    assert_eq!(listing.hrefs()[1..], hrefs[..]);
    assert_eq!(reads(), (Vec::new(), 0));

    // The size is the application's too: it is in the listing, so no message is read for it, nor for `allprop`, nor
    // for `propname` (which only names the properties).
    let sized = dav
        .propfind(
            INBOX,
            anna_login,
            "1",
            &props(&["D:getetag", "D:getcontentlength", "D:current-user-privilege-set"]),
        )
        .await;
    assert_eq!(sized.hrefs()[1..], hrefs[..], "sorted by href");
    for href in &hrefs {
        assert_eq!(sized.prop(href, NS_DAV, "getcontentlength").unwrap().text(), "400");
        assert!(sized.prop(href, NS_DAV, "current-user-privilege-set").is_some());
    }
    let all = dav.propfind(INBOX, anna_login, "1", "").await;
    assert_eq!(all.hrefs().len(), 8);
    assert_eq!(all.prop(&hrefs[0], NS_DAV, "getcontentlength").unwrap().text(), "400");
    let names = dav
        .propfind(
            INBOX,
            anna_login,
            "1",
            &format!("<D:propfind {NS}><D:propname/></D:propfind>"),
        )
        .await;
    assert_eq!(names.hrefs().len(), 8);
    assert!(
        names.prop(&hrefs[0], NS_DAV, "getcontentlength").is_some()
            && names
                .prop(&hrefs[0], "urn:ietf:params:xml:ns:caldav", "calendar-data")
                .is_some(),
        "propname names the message without reading it: {}",
        names.body
    );
    assert_eq!(reads(), (Vec::new(), 0), "none of the three read a message");

    // The message is read when it is asked for, in one call for all of them.
    let data = dav
        .propfind(INBOX, anna_login, "1", &props(&["D:getetag", "C:calendar-data"]))
        .await;
    assert!(
        data.prop(&hrefs[0], "urn:ietf:params:xml:ns:caldav", "calendar-data")
            .unwrap()
            .text()
            .starts_with("BEGIN:VCALENDAR")
    );
    assert_eq!(reads(), (vec![7], 0), "one call, not seven");

    // A multiget names three items, an item of somebody else's inbox and garbage: one read for the three.
    locked(&scheduling.bulk_reads).clear();
    let multiget = format!(
        "<C:calendar-multiget {NS}><D:prop><D:getetag/><C:calendar-data/></D:prop>\
         <D:href>{}</D:href><D:href>{}</D:href><D:href>{}</D:href>\
         <D:href>/dav/calendars/acme/ben/inbox/m0.ics</D:href><D:href>/somewhere/else.ics</D:href></C:calendar-multiget>",
        hrefs[0], hrefs[3], hrefs[6]
    );
    let fetched = dav
        .send(
            "REPORT",
            INBOX,
            Some(anna_login),
            &[("depth", "1"), ("content-type", "application/xml")],
            &multiget,
        )
        .await;
    assert_eq!(
        fetched
            .responses()
            .iter()
            .map(|(_, status)| *status)
            .collect::<Vec<_>>(),
        [None, None, None, Some(404), Some(404)],
        "{}",
        fetched.body
    );
    assert!(
        fetched
            .prop(&hrefs[3], "urn:ietf:params:xml:ns:caldav", "calendar-data")
            .unwrap()
            .text()
            .starts_with("BEGIN:VCALENDAR")
    );
    assert_eq!(reads(), (vec![3], 0));

    // The synchronization reads the changed items by path, in one call, and without their messages when it does not
    // ask for them: the listing of the application is not read for it.
    locked(&scheduling.bulk_reads).clear();
    locked(&scheduling.specs).clear();
    let listings_before = *locked(&scheduling.listings);
    let synced = dav
        .report(INBOX, anna_login, &sync_body("", &["D:getetag", "D:getcontentlength"]))
        .await;
    assert_eq!(synced.hrefs(), hrefs);
    assert_eq!(reads(), (vec![7], 0));
    assert_eq!(
        *locked(&scheduling.specs),
        [CalendarDataSpec::metadata_only()],
        "no message is read for the entity tags and the sizes"
    );
    assert_eq!(
        *locked(&scheduling.listings),
        listings_before,
        "the inbox was not listed"
    );
    for href in &hrefs {
        assert_eq!(synced.prop(href, NS_DAV, "getcontentlength").unwrap().text(), "400");
    }
    let token = synced.xml().child(NS_DAV, "sync-token").unwrap().text();
    locked(&scheduling.bulk_reads).clear();
    let nothing = dav
        .report(
            INBOX,
            anna_login,
            &sync_body(&token, &["D:getetag", "D:getcontentlength"]),
        )
        .await;
    assert!(nothing.hrefs().is_empty(), "{}", nothing.body);
    assert_eq!(reads(), (Vec::new(), 0), "a poll with no change reads nothing at all");
    assert_eq!(*locked(&scheduling.listings), listings_before);
    // One new item: only that one is read.
    let fresh = deliver(&scene, "m7.ics", 400).await;
    let one = dav
        .report(
            INBOX,
            anna_login,
            &sync_body(&token, &["D:getetag", "D:getcontentlength"]),
        )
        .await;
    assert_eq!(one.hrefs(), std::slice::from_ref(&fresh));
    assert_eq!(
        reads(),
        (vec![1], 0),
        "the changed member alone is read, whatever the size of the inbox"
    );

    // An item that is deleted between the listing and the read is not in the answer: no error and no entry, as if
    // the listing had been made a moment later.
    *locked(&scheduling.vanishes_after_list) = Some(ObjectUri::parse("m3.ics").unwrap());
    let racing = dav
        .propfind(INBOX, anna_login, "1", &props(&["D:getetag", "C:calendar-data"]))
        .await;
    let mut expected = vec![INBOX.to_owned()];
    expected.extend(
        hrefs
            .iter()
            .chain(std::iter::once(&fresh))
            .filter(|href| !href.ends_with("/m3.ics"))
            .cloned(),
    );
    assert_eq!(racing.hrefs(), expected, "{}", racing.body);
}

#[tokio::test]
async fn the_selection_of_calendar_data_is_handed_to_the_bulk_read() {
    let (scene, scheduling) = scene_with_inbox(|_| {}).await;
    let href = deliver(&scene, "m0.ics", 400).await;
    let Scene { dav, anna_login, .. } = &scene;
    let select = "<C:calendar-data><C:comp name=\"VCALENDAR\"><C:prop name=\"METHOD\"/></C:comp></C:calendar-data>";
    let multiget = format!(
        "<C:calendar-multiget {NS}><D:prop><D:getetag/>{select}</D:prop><D:href>{href}</D:href></C:calendar-multiget>"
    );
    let fetched = dav
        .send(
            "REPORT",
            INBOX,
            Some(anna_login),
            &[("depth", "1"), ("content-type", "application/xml")],
            &multiget,
        )
        .await;
    assert_eq!(fetched.status, StatusCode::MULTI_STATUS, "{}", fetched.body);
    let specs = locked(&scheduling.specs).clone();
    assert_eq!(specs.len(), 1);
    assert!(specs[0].include_data);
    assert_ne!(
        specs[0].projection,
        Projection::default(),
        "the components and properties the client selected reach the service, which cuts the message down to them"
    );
}

#[tokio::test]
async fn what_the_inbox_reads_is_bounded_by_the_size_of_the_response() {
    // A response of 20 000 bytes and messages of up to 4 000: five are read at a time.
    let (scene, scheduling) = scene_with_inbox(|deps| {
        deps.limits.dav.max_response_bytes = 20_000;
        deps.limits.ical.max_resource_size = 4_000;
    })
    .await;
    let mut hrefs = Vec::new();
    for number in 0..12 {
        hrefs.push(deliver(&scene, &format!("m{number:02}.ics"), 3_000).await);
    }
    let Scene { dav, anna_login, .. } = &scene;

    // A listing that carries the messages stops reading when they exceed the budget and says so like every other
    // answer that is too large: the members so far, sorted, and a 507 entry for the request URI.
    let listing = dav
        .propfind(INBOX, anna_login, "1", &props(&["D:getetag", "C:calendar-data"]))
        .await;
    let responses = listing.responses();
    let listed = listing.hrefs();
    assert_eq!(
        responses.last(),
        Some(&(INBOX.to_owned(), Some(507))),
        "the answer says that it was cut: {}",
        listing.body
    );
    assert!(listing.body.contains("number-of-matches-within-limits"));
    // The members before the 507 are a prefix of the sorted listing: as many as fit into the answer (the messages
    // are part of it), which is fewer than were read.
    let items = &listed[1..listed.len() - 1];
    assert_eq!(listed[0], INBOX);
    assert!(
        (5..=10).contains(&items.len()),
        "{} items: {}",
        items.len(),
        listing.body
    );
    assert_eq!(items, &hrefs[..items.len()], "a prefix of the sorted listing");
    assert_eq!(
        *locked(&scheduling.bulk_reads),
        vec![5, 5],
        "two steps, then it stopped"
    );
    assert_eq!(*locked(&scheduling.single_reads), 0);

    // The sizes are in the listing, which is not cut for them: asking for them is no reason to refuse or to cut.
    locked(&scheduling.bulk_reads).clear();
    let sizes = dav
        .propfind(INBOX, anna_login, "1", &props(&["D:getetag", "D:getcontentlength"]))
        .await;
    assert_eq!(sizes.hrefs().len(), 13, "{}", sizes.body);
    assert!(locked(&scheduling.bulk_reads).is_empty());

    // An initial synchronization lists everything the inbox holds (the application does not cut it). One that asks
    // for the sizes is answered, with a read of the changed members that holds no message...
    let initial_sizes = dav
        .report(INBOX, anna_login, &sync_body("", &["D:getetag", "D:getcontentlength"]))
        .await;
    assert_eq!(initial_sizes.hrefs(), hrefs, "{}", initial_sizes.body);
    assert_eq!(*locked(&scheduling.bulk_reads), vec![12], "metadata only: one step");
    // ... one that asks for the messages is refused when they do not fit, and what was read is bounded: the client
    // asks for the entity tags and fetches the messages in steps.
    locked(&scheduling.bulk_reads).clear();
    let initial = dav
        .report(INBOX, anna_login, &sync_body("", &["D:getetag", "C:calendar-data"]))
        .await;
    assert_eq!(initial.status, StatusCode::INSUFFICIENT_STORAGE, "{}", initial.body);
    assert!(
        initial.body.contains("number-of-matches-within-limits"),
        "{}",
        initial.body
    );
    assert_eq!(
        *locked(&scheduling.bulk_reads),
        vec![5, 5],
        "what was read is what the budget holds and one step more"
    );

    // The entity tags alone read nothing and have no such limit.
    locked(&scheduling.bulk_reads).clear();
    let tags = dav.report(INBOX, anna_login, &sync_body("", &["D:getetag"])).await;
    assert_eq!(tags.hrefs().len(), 12, "{}", tags.body);
    assert!(locked(&scheduling.bulk_reads).is_empty());
    let token = tags.xml().child(NS_DAV, "sync-token").unwrap().text();

    // The changes since a token are cut at as many members as fit: five, a 507 entry for the request URI and the
    // token that continues.
    for number in 12..20 {
        deliver(&scene, &format!("m{number:02}.ics"), 3_000).await;
    }
    let changes = dav
        .report(INBOX, anna_login, &sync_body(&token, &["D:getetag", "C:calendar-data"]))
        .await;
    assert_eq!(
        changes.hrefs().len(),
        6,
        "five members and the 507 entry: {}",
        changes.body
    );
    assert_eq!(changes.responses().last().unwrap().1, Some(507), "{}", changes.body);
    assert!(
        changes.xml().child(NS_DAV, "sync-token").is_some(),
        "with the token that continues"
    );
    assert_eq!(*locked(&scheduling.bulk_reads), vec![5]);

    // A multiget is cut at the budget as well, in the same steps.
    locked(&scheduling.bulk_reads).clear();
    let multiget = format!(
        "<C:calendar-multiget {NS}><D:prop><D:getetag/><C:calendar-data/></D:prop>{}</C:calendar-multiget>",
        join(hrefs.iter().map(|href| format!("<D:href>{href}</D:href>")))
    );
    let fetched = dav
        .send(
            "REPORT",
            INBOX,
            Some(anna_login),
            &[("depth", "1"), ("content-type", "application/xml")],
            &multiget,
        )
        .await;
    let answers = fetched.responses();
    assert_eq!(answers.last().unwrap().1, Some(507), "{}", fetched.body);
    assert!(
        locked(&scheduling.bulk_reads).iter().all(|size| *size <= 5),
        "{:?}",
        locked(&scheduling.bulk_reads)
    );
}

#[tokio::test]
async fn an_inbox_item_is_read_and_deleted_by_its_owner_only_and_deletion_is_conditional() {
    let (scene, scheduling) = scene_with_inbox(|_| {}).await;
    let item = deliver(&scene, "request-1.ics", 500).await;
    let Scene {
        dav,
        anna_login,
        ben_login,
        gina_login,
        ..
    } = &scene;

    let read_it = dav.get(&item, anna_login).await;
    assert_eq!(read_it.status, StatusCode::OK);
    assert!(read_it.header("content-type").starts_with("text/calendar"));
    assert_eq!(read_it.body.len(), 500);
    let etag = read_it.header("etag").to_owned();
    assert_eq!(
        dav.send("GET", &item, Some(anna_login), &[("if-none-match", &etag)], "")
            .await
            .status,
        StatusCode::NOT_MODIFIED
    );
    // The properties of the item, and the privileges that the application says it has.
    let seen = dav
        .propfind(
            &item,
            anna_login,
            "0",
            &props(&["D:getcontentlength", "D:current-user-privilege-set"]),
        )
        .await;
    assert_eq!(seen.prop(&item, NS_DAV, "getcontentlength").unwrap().text(), "500");
    let mut privileges: Vec<String> = seen
        .prop(&item, NS_DAV, "current-user-privilege-set")
        .unwrap()
        .children_named(NS_DAV, "privilege")
        .filter_map(|privilege| privilege.elements().next().map(|element| element.local.clone()))
        .collect();
    privileges.sort();
    assert_eq!(privileges, ["read", "read-current-user-privilege-set"]);

    // Nobody else sees it: the inbox is resolved by the application, which answers 404 to every other principal, to
    // the tenant administrator's namesakes and to the other tenant.
    for (who, name) in [(ben_login, "ben"), (gina_login, "gina")] {
        for method in ["GET", "HEAD", "DELETE", "PROPFIND"] {
            let answer = dav.send(method, &item, Some(who), &[("depth", "0")], "").await;
            assert_eq!(answer.status, StatusCode::NOT_FOUND, "{name} {method}");
        }
    }
    assert!(locked(&scheduling.deleted).is_empty());

    // A stale tag deletes nothing, a current one does.
    let stale = dav
        .send("DELETE", &item, Some(anna_login), &[("if-match", "\"stale\"")], "")
        .await;
    assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);
    assert!(locked(&scheduling.deleted).is_empty());
    let gone = dav
        .send("DELETE", &item, Some(anna_login), &[("if-match", &etag)], "")
        .await;
    assert_eq!(gone.status, StatusCode::NO_CONTENT);
    assert_eq!(locked(&scheduling.deleted).len(), 1);
    assert_eq!(dav.get(&item, anna_login).await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_inbox_of_a_principal_is_read_by_that_principal_alone_through_the_application() {
    // Ben has an inbox with an item of his own; the double reads the inbox of the principal the path names, and
    // the application decides who may ask for it.
    let (scene, scheduling) = scene_with_inbox(|_| {}).await;
    let ben = scene.ben.clone();
    let bens = deliver_to(&scene, &ben, "for-ben.ics", 300).await;
    let annas = deliver(&scene, "for-anna.ics", 300).await;
    let Scene {
        dav,
        anna_login,
        ben_login,
        ..
    } = &scene;
    assert_eq!(dav.get(&bens, ben_login).await.status, StatusCode::OK);
    assert_eq!(dav.get(&annas, anna_login).await.status, StatusCode::OK);
    assert_eq!(dav.get(&bens, anna_login).await.status, StatusCode::NOT_FOUND);
    assert_eq!(dav.get(&annas, ben_login).await.status, StatusCode::NOT_FOUND);
    for (path, who) in [
        ("/dav/calendars/acme/ben/inbox/", anna_login),
        ("/dav/calendars/acme/anna/inbox/", ben_login),
    ] {
        for method in ["PROPFIND", "REPORT"] {
            let answer = dav
                .send(
                    method,
                    path,
                    Some(who),
                    &[("depth", "1"), ("content-type", "application/xml")],
                    &if method == "PROPFIND" {
                        props(&["D:getetag"])
                    } else {
                        sync_body("", &["D:getetag"])
                    },
                )
                .await;
            assert_eq!(answer.status, StatusCode::NOT_FOUND, "{method} {path}");
        }
    }
    assert!(locked(&scheduling.deleted).is_empty());
}

#[tokio::test]
async fn the_notifications_and_the_inbox_of_a_principal_are_not_there_under_the_slug_of_another_tenant() {
    // Anna is a principal of `acme`. A request for `/dav/calendars/globex/anna/…` names a home of another tenant: the
    // services that take the name of the home owner alone would find Anna all the same, so the tenant of the path
    // is judged first. Real sharing service and the double of the scheduling service that resolves through the
    // application, with data in the collections to be leaked.
    let (scene, scheduling) = scene_with_inbox(|_| {}).await;
    let Scene {
        dav,
        anna_login,
        ben_login,
        ..
    } = &scene;
    assert_eq!(
        dav.post_xml(WORK, anna_login, &fixture("share-set-read-write.xml"))
            .await
            .status,
        StatusCode::OK
    );
    let ben_note = notification_hrefs(&scene, BEN_NOTIFICATIONS, ben_login).await;
    assert_eq!(ben_note.len(), 1);
    let item = deliver(&scene, "m0.ics", 300).await;
    assert_eq!(dav.get(&item, anna_login).await.status, StatusCode::OK);
    let calls = |scheduling: &Recording| (*locked(&scheduling.listings), locked(&scheduling.bulk_reads).len());
    let before = calls(&scheduling);
    // Anna's own collections, under the slug of the other tenant.
    let notifications = "/dav/calendars/globex/anna/notifications/";
    let inbox = "/dav/calendars/globex/anna/inbox/";
    let multiget = fixture("inbox-multiget.xml").replace("/acme/", "/globex/");
    for (method, path, depth, body) in [
        ("PROPFIND", notifications, "1", fixture("propfind-notifications.xml")),
        ("PROPFIND", notifications, "0", fixture("propfind-notifications.xml")),
        ("REPORT", notifications, "0", fixture("sync-notifications.xml")),
        ("PROPFIND", inbox, "1", props(&["D:getetag", "C:calendar-data"])),
        ("PROPFIND", inbox, "0", props(&["D:getetag"])),
        ("REPORT", inbox, "0", sync_body("", &["D:getetag", "C:calendar-data"])),
        ("REPORT", inbox, "1", multiget),
    ] {
        let answer = dav
            .send(
                method,
                path,
                Some(anna_login),
                &[("depth", depth), ("content-type", "application/xml")],
                &body,
            )
            .await;
        assert_eq!(
            answer.status,
            StatusCode::NOT_FOUND,
            "{method} {path} {depth}: {}",
            answer.body
        );
        assert!(!answer.body.contains("m0.ics"), "{}", answer.body);
    }
    assert_eq!(calls(&scheduling), before, "the double was not even asked");
    // The same for Ben under the slug of the other tenant, for the notification he does have.
    let foreign_note = ben_note[0].replace("/acme/", "/globex/");
    for method in ["GET", "HEAD", "DELETE", "PROPFIND"] {
        let answer = dav
            .send(method, &foreign_note, Some(ben_login), &[("depth", "0")], "")
            .await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{method}");
    }
    assert_eq!(notification_hrefs(&scene, BEN_NOTIFICATIONS, ben_login).await, ben_note);
}

#[tokio::test]
async fn a_free_busy_request_reaches_the_outbox_of_its_owner_and_of_nobody_else() {
    let (scene, scheduling) = scene_with_inbox(|_| {}).await;
    let Scene {
        dav,
        anna_login,
        ben_login,
        gina_login,
        ..
    } = &scene;
    let message = fixture("outbox-freebusy-request.ics");
    let outbox = "/dav/calendars/acme/anna/outbox/";
    let post = |who: &Login, path: &str| {
        let message = message.clone();
        let path = path.to_owned();
        let who = who.clone();
        async move {
            dav.send(
                "POST",
                &path,
                Some(&who),
                &[("content-type", "text/calendar; charset=utf-8")],
                &message,
            )
            .await
        }
    };
    let answered = post(anna_login, outbox).await;
    assert_eq!(answered.status, StatusCode::OK, "{}", answered.body);
    let root = answered.xml();
    assert!(
        root.is("urn:ietf:params:xml:ns:caldav", "schedule-response"),
        "{}",
        answered.body
    );
    assert!(answered.body.contains("2.0;Success"));
    assert_eq!(
        *locked(&scheduling.posts),
        [(scene.anna.name.clone(), message.clone())],
        "the service got the name of the owner and the message, byte for byte"
    );
    // The same message to the outbox of Anna, asked by somebody else, or to an outbox that is not there: not found,
    // and the service is not asked.
    for (who, path) in [
        (ben_login, outbox),
        (gina_login, outbox),
        (anna_login, "/dav/calendars/globex/anna/outbox/"),
        (anna_login, "/dav/calendars/acme/nobody/outbox/"),
        (gina_login, "/dav/calendars/globex/anna/outbox/"),
    ] {
        let answer = post(who, path).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{path}");
    }
    assert_eq!(locked(&scheduling.posts).len(), 1);
    // And a message that is no iCalendar text is the owner's 400 and nobody else's business.
    let bad = dav
        .send(
            "POST",
            outbox,
            Some(anna_login),
            &[("content-type", "text/calendar")],
            "\u{fffd}",
        )
        .await;
    assert_ne!(bad.status, StatusCode::NOT_FOUND);
    let stranger = dav
        .send(
            "POST",
            outbox,
            Some(ben_login),
            &[("content-type", "text/calendar")],
            "\u{fffd}",
        )
        .await;
    assert_eq!(stranger.status, StatusCode::NOT_FOUND);
}

/// One `propstat` of a PROPPATCH answer: the status, the element of its error as "{namespace}{local name}" and the names
/// of its properties.
type Seen = (u16, Option<String>, Vec<String>);

#[tokio::test]
async fn a_calendar_timezone_that_is_no_vtimezone_is_refused_with_valid_calendar_data() {
    let scene = scene().await;
    let proppatch = |value: &str| {
        let body = format!(
            "<D:propertyupdate {NS}><D:set><D:prop><C:calendar-timezone>{value}</C:calendar-timezone>\
             <D:displayname>Work</D:displayname></D:prop></D:set></D:propertyupdate>"
        );
        let scene = &scene;
        async move {
            scene
                .dav
                .send(
                    "PROPPATCH",
                    WORK,
                    Some(&scene.anna_login),
                    &[("content-type", "application/xml; charset=utf-8")],
                    &body,
                )
                .await
        }
    };
    let refused = proppatch("this is not iCalendar").await;
    assert_eq!(refused.status, StatusCode::MULTI_STATUS, "{}", refused.body);
    let root = refused.xml();
    let response = root.child(NS_DAV, "response").expect("one response");
    let propstats: Vec<Seen> = response
        .children_named(NS_DAV, "propstat")
        .map(|propstat| {
            let status = code_of(&propstat.child(NS_DAV, "status").unwrap().text());
            let error = propstat
                .child(NS_DAV, "error")
                .and_then(|error| error.elements().next())
                .map(|element| format!("{}{}", element.namespace, element.local));
            let names = propstat
                .child(NS_DAV, "prop")
                .map(|prop| prop.elements().map(|element| element.local.clone()).collect())
                .unwrap_or_default();
            (status, error, names)
        })
        .collect();
    assert_eq!(
        propstats,
        [
            (
                409,
                Some(format!("{NS_CALDAV}valid-calendar-data")),
                vec!["calendar-timezone".to_owned()]
            ),
            (424, None, vec!["displayname".to_owned()]),
        ],
        "the value names the precondition it breaks; the property that was fine only depends on it: {}",
        refused.body
    );
    // Nothing was applied, and a real time zone is accepted.
    let applied = proppatch(&BERLIN_VTIMEZONE.replace("\r\n", "\n")).await;
    assert_eq!(applied.status, StatusCode::MULTI_STATUS, "{}", applied.body);
    assert!(
        applied.body.contains("HTTP/1.1 200 OK") && !applied.body.contains("Conflict"),
        "{}",
        applied.body
    );
}

/// A calendar with the one `VTIMEZONE` that `calendar-timezone` takes.
const BERLIN_VTIMEZONE: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VTIMEZONE\r\nTZID:Europe/Berlin\r\n\
BEGIN:STANDARD\r\nDTSTART:19701025T030000\r\nTZOFFSETFROM:+0200\r\nTZOFFSETTO:+0100\r\n\
RRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU\r\nEND:STANDARD\r\nBEGIN:DAYLIGHT\r\nDTSTART:19700329T020000\r\n\
TZOFFSETFROM:+0100\r\nTZOFFSETTO:+0200\r\nRRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU\r\nEND:DAYLIGHT\r\n\
END:VTIMEZONE\r\nEND:VCALENDAR\r\n";

#[tokio::test]
async fn a_free_busy_query_is_stamped_with_the_clock_of_the_server() {
    let scene = scene().await;
    let query = format!(
        "<C:free-busy-query {NS}><C:time-range start=\"20270301T000000Z\" end=\"20270401T000000Z\"/></C:free-busy-query>"
    );
    let stamp_of = |reply: &Reply| {
        reply
            .body
            .lines()
            .find_map(|line| line.trim_end().strip_prefix("DTSTAMP:"))
            .unwrap_or_else(|| panic!("no DTSTAMP: {}", reply.body))
            .to_owned()
    };
    let uid_of = |reply: &Reply| {
        reply
            .body
            .lines()
            .find_map(|line| line.trim_end().strip_prefix("UID:"))
            .unwrap_or_else(|| panic!("no UID: {}", reply.body))
            .to_owned()
    };
    let first = scene.dav.report(WORK, &scene.anna_login, &query).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    assert_eq!(first.header("content-type"), "text/calendar; charset=utf-8");
    let at_first = scene.world.now().format("%Y%m%dT%H%M%SZ").to_string();
    assert_eq!(stamp_of(&first), at_first, "the DTSTAMP is the moment of the answer");
    assert_ne!(
        stamp_of(&first),
        "20270301T000000Z",
        "and not the start of the range, which the DAV layer used before it had a clock"
    );
    // Later the stamp is later; the UID, which names the resource and the range, stays.
    scene.world.clock.advance(chrono::Duration::hours(7));
    let later = scene.dav.report(WORK, &scene.anna_login, &query).await;
    assert_eq!(later.status, StatusCode::OK, "{}", later.body);
    assert_eq!(stamp_of(&later), scene.world.now().format("%Y%m%dT%H%M%SZ").to_string());
    assert_ne!(stamp_of(&later), stamp_of(&first));
    assert_eq!(uid_of(&later), uid_of(&first));
}

// ---------------------------------------------------------------------------------------------------------------
// The bulk read of the real scheduling service (SchedulingService::inbox_get_many)
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_bulk_read_of_the_inbox_is_one_transaction_that_resolves_the_home_once() {
    let scene = scene().await;
    let mut paths = Vec::new();
    for number in 0..5 {
        paths.push(ResourcePath::parse(&deliver(&scene, &format!("m{number}.ics"), 400).await).unwrap());
    }
    let ctx = scene.world.dav(&scene.acme, &scene.anna);
    let inbox = ResourcePath::parse(INBOX).unwrap();
    let (begins, facts) = (scene.world.db.begins(), scene.world.fact_loads());
    let entries = scene
        .world
        .services
        .scheduling
        .inbox_get_many(&ctx, &inbox, paths, &CalendarDataSpec::default())
        .await
        .unwrap();
    assert_eq!(entries.len(), 5);
    assert_eq!(
        scene.world.db.begins() - begins,
        1,
        "one transaction for all five items, not one per item (R14)"
    );
    assert!(
        scene.world.fact_loads() - facts <= 1,
        "and the authorization facts are loaded at most once"
    );
}

#[tokio::test]
async fn the_bulk_read_of_the_inbox_shows_the_owner_the_delivered_items_of_that_inbox_only() {
    let scene = scene().await;
    let ben = scene.ben.clone();
    let mine = ResourcePath::parse(&deliver(&scene, "mine.ics", 400).await).unwrap();
    let bens = ResourcePath::parse(&deliver_to(&scene, &ben, "bens.ics", 400).await).unwrap();
    // A message that was quarantined (inbound iTIP that was not applied) is never shown to its owner.
    let now = scene.world.now();
    let mut tx = scene
        .world
        .db
        .store()
        .begin(scene.acme.id, TxMode::ReadWrite)
        .await
        .unwrap();
    tx.inbox()
        .create(InboxItem {
            id: InboxItemId::from_uuid(scene.world.ids.new_id()),
            tenant_id: scene.acme.id,
            principal_id: scene.anna.id,
            uri: ObjectUri::parse("held.ics").unwrap(),
            etag: ETag::from_bytes(b"held"),
            data: "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n".to_owned(),
            quarantined: true,
            created_at: now,
            updated_at: now,
            version: 1,
        })
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let held = ResourcePath::parse("/dav/calendars/acme/anna/inbox/held.ics").unwrap();
    let unknown = ResourcePath::parse("/dav/calendars/acme/anna/inbox/unknown.ics").unwrap();
    let annas_inbox = ResourcePath::parse(INBOX).unwrap();
    let bens_inbox = ResourcePath::parse("/dav/calendars/acme/ben/inbox/").unwrap();
    let anna = scene.world.dav(&scene.acme, &scene.anna);
    let ben_ctx = scene.world.dav(&scene.acme, &ben);
    let service = &scene.world.services.scheduling;

    // The owner: the delivered item of this inbox is there; another inbox's item, a quarantined message, a name that
    // is nothing and a calendar object are `Missing`, each in its place.
    let asked = vec![
        mine.clone(),
        bens.clone(),
        held.clone(),
        unknown.clone(),
        ResourcePath::parse("/dav/calendars/acme/anna/work/standup.ics").unwrap(),
    ];
    let entries = service
        .inbox_get_many(&anna, &annas_inbox, asked.clone(), &CalendarDataSpec::default())
        .await
        .unwrap();
    assert_eq!(entries.len(), 5);
    let InboxEntry::Found(found) = &entries[0] else {
        panic!("{entries:?}");
    };
    assert_eq!((found.path.clone(), found.size), (mine.clone(), 400));
    assert!(found.data.as_deref().is_some_and(|data| data.len() == 400));
    assert_eq!(
        found.privileges.iter().count(),
        2,
        "read and read-current-user-privilege-set"
    );
    for (entry, path) in entries[1..].iter().zip(&asked[1..]) {
        assert_eq!(entry, &InboxEntry::Missing(path.clone()), "{path:?}");
    }

    // No message wanted: the same item without it, with its size and tag.
    let heads = service
        .inbox_get_many(
            &anna,
            &annas_inbox,
            vec![mine.clone()],
            &CalendarDataSpec::metadata_only(),
        )
        .await
        .unwrap();
    let InboxEntry::Found(bare) = &heads[0] else {
        panic!("{heads:?}");
    };
    assert_eq!((bare.data.as_deref(), bare.size, &bare.etag), (None, 400, &found.etag));

    // A selection of the request: the message is cut down to it, the size and the tag stay those of the stored one.
    let selection = CalendarDataSpec {
        include_data: true,
        projection: method_only(),
    };
    let cut = service
        .inbox_get_many(&anna, &annas_inbox, vec![mine.clone()], &selection)
        .await
        .unwrap();
    let InboxEntry::Found(cut) = &cut[0] else {
        panic!("{cut:?}");
    };
    let data = cut.data.as_deref().unwrap();
    assert!(data.contains("METHOD:REQUEST") && !data.contains("SUMMARY"), "{data}");
    assert_eq!((cut.size, &cut.etag), (400, &found.etag));

    // Nobody else reads it: another principal of the tenant, the other tenant's slug, and the limit of a multiget is
    // told to the owner only.
    for (who, inbox, what) in [
        (&ben_ctx, &annas_inbox, "Ben asks for the inbox of Anna"),
        (&anna, &bens_inbox, "Anna asks for the inbox of Ben"),
        (
            &anna,
            &ResourcePath::parse("/dav/calendars/globex/anna/inbox/").unwrap(),
            "Anna under the slug of another tenant",
        ),
    ] {
        let error = service
            .inbox_get_many(who, inbox, asked.clone(), &CalendarDataSpec::default())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotFound, "{what}");
    }
    let bens_view = service
        .inbox_get_many(
            &ben_ctx,
            &bens_inbox,
            vec![bens.clone(), mine.clone()],
            &CalendarDataSpec::default(),
        )
        .await
        .unwrap();
    assert!(matches!(&bens_view[0], InboxEntry::Found(view) if view.path == bens));
    assert_eq!(
        bens_view[1],
        InboxEntry::Missing(mine),
        "Anna's item is not an item of Ben's inbox"
    );
    let most = usize::try_from(DavLimits::default().max_multiget_hrefs).unwrap();
    let too_many: Vec<ResourcePath> = (0..=most)
        .map(|n| ResourcePath::parse(&format!("/dav/calendars/acme/anna/inbox/i{n}.ics")).unwrap())
        .collect();
    assert_eq!(
        service
            .inbox_get_many(&anna, &annas_inbox, too_many.clone(), &CalendarDataSpec::default())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Forbidden
    );
    assert_eq!(
        service
            .inbox_get_many(&ben_ctx, &annas_inbox, too_many, &CalendarDataSpec::default())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound,
        "a caller who cannot see the inbox is not told how many items it may name"
    );
}

/// The selection `<C:comp name="VCALENDAR"><C:prop name="METHOD"/></C:comp>` of a `calendar-data` element, read the way
/// the DAV layer reads it.
fn method_only() -> Projection {
    let element = read(&format!(
        "<C:calendar-data {NS}><C:comp name=\"VCALENDAR\"><C:prop name=\"METHOD\"/></C:comp></C:calendar-data>"
    ));
    davhaven_dav::xml::requests::parse_calendar_data(&element).unwrap()
}
