//! Helpers shared by the protocol tests: requests, answers, the multistatus reader and calendar texts.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use base64::Engine as _;
use davhaven_app::AppServices;
use davhaven_app_fake::AppServicesExt as _;
use davhaven_app_fake::recorder::Recorder;
use davhaven_app_fake::seed::{ANNA_PASSWORD, BEN_PASSWORD, CARA_PASSWORD, GINA_PASSWORD, standard_world};
use davhaven_dav::xml::{Element, parse};
use davhaven_domain::{
    CalendarKind, CalendarSlug, DavLimits, Email, GrantAccess, GrantStatus, Limits, PrincipalKind, PrincipalName,
    TenantSlug,
};
use davhaven_http::{Edge, SequentialRequestIds, Surface};
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;

pub(crate) use davhaven_app::services::{NS_APPLE_ICAL, NS_CALDAV, NS_CALENDARSERVER, NS_DAV};

/// The namespace declarations every request body of the tests uses: `D`, `C`, `CS` and `A` (Apple).
pub(crate) const NS: &str = r#"xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav" xmlns:CS="http://calendarserver.org/ns/" xmlns:A="http://apple.com/ns/ical/""#;

/// Anna's home.
pub(crate) const HOME: &str = "/dav/calendars/acme/anna/";
/// Anna's calendar `work`, which holds `standup.ics`.
pub(crate) const WORK: &str = "/dav/calendars/acme/anna/work/";
/// Anna's personal calendar.
pub(crate) const PERSONAL: &str = "/dav/calendars/acme/anna/personal/";
/// The event of `work`.
pub(crate) const STANDUP: &str = "/dav/calendars/acme/anna/work/standup.ics";
/// The event of the seed, as it is stored.
pub(crate) use davhaven_app_fake::seed::STANDUP_ICS;

/// Rita's password (the shared world of [`Dav::shared`]).
const RITA_PASSWORD: &str = "rita-secret-pass";
/// Walt's password.
const WALT_PASSWORD: &str = "walt-secret-pass";
/// Pia's password.
const PIA_PASSWORD: &str = "pia-secret-pass";
/// Dora's password.
const DORA_PASSWORD: &str = "dora-secret-pass";
/// The name of the share in the home of each sharee.
pub(crate) const SHARE: &str = "annas-work";
/// Anna's calendar of kind managed (read-only for her over DAV).
pub(crate) const MANAGED: &str = "/dav/calendars/acme/anna/managed/";

/// A user of the standard world.
#[derive(Debug, Clone, Copy)]
pub(crate) enum User {
    /// `anna@acme.example`, owner of `work` and `personal`.
    Anna,
    /// `ben@acme.example`, a user without access to Anna's calendars.
    Ben,
    /// `gina@globex.example` of the other tenant.
    Gina,
    /// `cara@acme.example`, suspended: cannot log in.
    Cara,
    /// `rita@acme.example` of [`Dav::shared`]: reads Anna's `work` through an accepted share.
    Rita,
    /// `walt@acme.example` of [`Dav::shared`]: reads and writes Anna's `work` through an accepted share.
    Walt,
    /// `pia@acme.example` of [`Dav::shared`]: was invited to Anna's `work` and has not answered.
    Pia,
    /// `dora@acme.example` of [`Dav::shared`]: declined the invitation to Anna's `work`.
    Dora,
}

impl User {
    fn authorization(self) -> String {
        let (login, password) = match self {
            Self::Anna => ("anna@acme.example", ANNA_PASSWORD),
            Self::Ben => ("ben@acme.example", BEN_PASSWORD),
            Self::Gina => ("gina@globex.example", GINA_PASSWORD),
            Self::Cara => ("cara@acme.example", CARA_PASSWORD),
            Self::Rita => ("rita@acme.example", RITA_PASSWORD),
            Self::Walt => ("walt@acme.example", WALT_PASSWORD),
            Self::Pia => ("pia@acme.example", PIA_PASSWORD),
            Self::Dora => ("dora@acme.example", DORA_PASSWORD),
        };
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{login}:{password}"))
        )
    }
}

/// A request under construction.
#[derive(Debug, Clone)]
pub(crate) struct Req {
    method: String,
    path: String,
    user: Option<User>,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
}

impl Req {
    /// An anonymous request.
    pub(crate) fn new(method: &str, path: &str) -> Self {
        Self {
            method: method.to_owned(),
            path: path.to_owned(),
            user: None,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// A request of Anna.
    pub(crate) fn anna(method: &str, path: &str) -> Self {
        Self::new(method, path).by(User::Anna)
    }

    /// Authenticates as `user`.
    #[must_use]
    pub(crate) fn by(mut self, user: User) -> Self {
        self.user = Some(user);
        self
    }

    /// Adds a header.
    #[must_use]
    pub(crate) fn header(self, name: &str, value: &str) -> Self {
        self.raw_header(name, value.as_bytes())
    }

    /// Adds a header whose value is not necessarily text.
    #[must_use]
    pub(crate) fn raw_header(mut self, name: &str, value: &[u8]) -> Self {
        self.headers.push((name.to_owned(), value.to_vec()));
        self
    }

    /// Sets `Depth`.
    #[must_use]
    pub(crate) fn depth(self, value: &str) -> Self {
        self.header("depth", value)
    }

    /// Sets an XML body.
    #[must_use]
    pub(crate) fn xml(mut self, body: &str) -> Self {
        self.body = body.as_bytes().to_vec();
        self.header("content-type", "application/xml; charset=utf-8")
    }

    /// Sets an iCalendar body.
    #[must_use]
    pub(crate) fn ics(mut self, body: &str) -> Self {
        self.body = body.as_bytes().to_vec();
        self.header("content-type", "text/calendar; charset=utf-8")
    }

    /// Sets raw body bytes.
    #[must_use]
    pub(crate) fn bytes(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }
}

/// What the server answered.
#[derive(Debug)]
pub(crate) struct Answer {
    /// The status.
    pub(crate) status: StatusCode,
    /// The headers.
    pub(crate) headers: HeaderMap,
    /// The body as text.
    pub(crate) body: String,
}

/// One property of a `mkcalendar-response` or `mkcol-response`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Failure {
    /// The local name of the property.
    pub(crate) name: String,
    /// Its status.
    pub(crate) status: u16,
    /// The local name of the `DAV:error` element of its `propstat`.
    pub(crate) error: Option<String>,
}

impl Answer {
    /// The properties of a `CALDAV:mkcalendar-response` or `DAV:mkcol-response` with their statuses, in document order.
    pub(crate) fn failures(&self) -> Vec<Failure> {
        let root = parse(self.body.as_bytes(), &DavLimits::default()).unwrap();
        assert!(
            root.is(NS_CALDAV, "mkcalendar-response") || root.is(NS_DAV, "mkcol-response"),
            "not a creation failure: {}",
            self.body
        );
        let mut failures = Vec::new();
        for stat in root.children_named(NS_DAV, "propstat") {
            let status = status_code(&stat.child(NS_DAV, "status").unwrap().text());
            let error = error_name(stat);
            for property in stat.child(NS_DAV, "prop").into_iter().flat_map(Element::elements) {
                failures.push(Failure {
                    name: property.local.clone(),
                    status,
                    error: error.clone(),
                });
            }
        }
        failures
    }

    /// The value of a header, empty when it is absent.
    pub(crate) fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
    }

    /// The local name of the first element inside `DAV:error`, for a precondition answer.
    pub(crate) fn precondition(&self) -> Option<String> {
        let root = parse(self.body.as_bytes(), &DavLimits::default()).ok()?;
        if !root.is(NS_DAV, "error") {
            return None;
        }
        root.elements().next().map(|element| element.local.clone())
    }

    /// The text of the `D:href` inside the precondition element.
    pub(crate) fn precondition_href(&self) -> Option<String> {
        let root = parse(self.body.as_bytes(), &DavLimits::default()).ok()?;
        let element = root.elements().next()?;
        element.child(NS_DAV, "href").map(Element::text)
    }

    /// The `(href, privilege)` pairs of a `DAV:need-privileges` answer: which resource lacked which privilege.
    pub(crate) fn needed(&self) -> Vec<(String, String)> {
        let Ok(root) = parse(self.body.as_bytes(), &DavLimits::default()) else {
            return Vec::new();
        };
        let Some(element) = root.child(NS_DAV, "need-privileges") else {
            return Vec::new();
        };
        element
            .children_named(NS_DAV, "resource")
            .map(|resource| {
                let href = resource.child(NS_DAV, "href").map(Element::text).unwrap_or_default();
                let privilege = resource
                    .child(NS_DAV, "privilege")
                    .and_then(|privilege| privilege.elements().next())
                    .map(|element| element.local.clone())
                    .unwrap_or_default();
                (href, privilege)
            })
            .collect()
    }

    /// Reads a 207 answer.
    pub(crate) fn multistatus(&self) -> Multi {
        assert_eq!(self.status, StatusCode::MULTI_STATUS, "{}", self.body);
        assert!(
            self.header("content-type").starts_with("application/xml"),
            "{}",
            self.header("content-type")
        );
        Multi::parse(&self.body)
    }
}

/// A DAV server on the fake application.
pub(crate) struct Dav {
    router: Router,
}

impl Dav {
    /// The standard world of the fake.
    pub(crate) fn new() -> Self {
        Self::with(AppServices::fake())
    }

    /// The standard world with the sharing and scheduling services replaced by a [`Recorder`]: what the layer hands
    /// to them is what the recorder kept, and a request that does not reach them leaves it empty.
    pub(crate) fn recording() -> (Self, Arc<Recorder>) {
        Self::recording_on(AppServices::fake())
    }

    /// The standard world with the limits changed by `adjust`.
    pub(crate) fn configured(adjust: impl FnOnce(&mut Limits)) -> Self {
        let mut services = AppServices::fake();
        adjust(&mut services.limits);
        Self::with(services)
    }

    /// [`Dav::recording`] with the limits changed by `adjust`.
    pub(crate) fn recording_configured(adjust: impl FnOnce(&mut Limits)) -> (Self, Arc<Recorder>) {
        let mut services = AppServices::fake();
        adjust(&mut services.limits);
        Self::recording_on(services)
    }

    /// [`Dav::recording`] on services the test prepared.
    pub(crate) fn recording_on(mut services: AppServices) -> (Self, Arc<Recorder>) {
        let recorder = Recorder::install(&mut services);
        (Self::with(services), recorder)
    }

    /// A server on services the test prepared.
    pub(crate) fn with(services: AppServices) -> Self {
        let edge = Edge::new(Surface::Dav, Arc::new(SequentialRequestIds::new()));
        Self {
            router: davhaven_dav::router(services, &edge),
        }
    }

    /// A server on the standard world with Anna's `work` shared: Rita reads it, Walt reads and writes it, Pia was
    /// invited and has not answered, Dora declined; every one of them has the share as `annas-work` in the home.
    /// Anna also has a calendar `managed` of kind managed, which DAV can only read.
    pub(crate) fn shared() -> Self {
        let tenant = TenantSlug::parse("acme").unwrap();
        let mut world = standard_world();
        let acme = world.tenant_by_slug(&tenant).unwrap().id;
        let anna = world
            .principal_id(&tenant, &PrincipalName::parse("anna").unwrap())
            .unwrap();
        let work = world
            .find_calendar(anna, &CalendarSlug::parse("work").unwrap())
            .unwrap();
        for (name, display, password, access, status) in [
            (
                "rita",
                "Rita Read",
                RITA_PASSWORD,
                GrantAccess::Read,
                GrantStatus::Accepted,
            ),
            (
                "walt",
                "Walt Write",
                WALT_PASSWORD,
                GrantAccess::ReadWrite,
                GrantStatus::Accepted,
            ),
            (
                "pia",
                "Pia Pending",
                PIA_PASSWORD,
                GrantAccess::Read,
                GrantStatus::Pending,
            ),
            (
                "dora",
                "Dora Declined",
                DORA_PASSWORD,
                GrantAccess::Read,
                GrantStatus::Declined,
            ),
        ] {
            let user = world.add_principal(
                acme,
                PrincipalKind::User,
                PrincipalName::parse(name).unwrap(),
                display,
                Some(Email::parse(&format!("{name}@acme.example")).unwrap()),
            );
            world.add_app_password(user, password);
            world.add_grant(work, user, access, status);
            world.add_binding(acme, user, work, CalendarSlug::parse(SHARE).unwrap());
        }
        world.add_calendar(
            anna,
            CalendarSlug::parse("managed").unwrap(),
            CalendarKind::Managed,
            "Managed",
        );
        Self::with(AppServices::fake_with(world))
    }

    /// The standard world with a crowd in the tenant `acme`: sixty people called `Anna Aaron Rosa 00` to
    /// `Anna Aaron Rosa 59` (`rosa00` to `rosa59`), and `Anna Bauer` (`abauer`). The crowd mentions `anna` and `ro`
    /// and sorts before `Anna Bauer` and before the meeting room, so a lookup of the application that is cut at 50
    /// hits holds the crowd and nobody else.
    pub(crate) fn crowded() -> Self {
        let tenant = TenantSlug::parse("acme").unwrap();
        let mut world = standard_world();
        let acme = world.tenant_by_slug(&tenant).unwrap().id;
        for number in 0..60 {
            world.add_principal(
                acme,
                PrincipalKind::User,
                PrincipalName::parse(&format!("rosa{number:02}")).unwrap(),
                &format!("Anna Aaron Rosa {number:02}"),
                Some(Email::parse(&format!("rosa{number:02}@acme.example")).unwrap()),
            );
        }
        world.add_principal(
            acme,
            PrincipalKind::User,
            PrincipalName::parse("abauer").unwrap(),
            "Anna Bauer",
            Some(Email::parse("abauer@acme.example").unwrap()),
        );
        Self::with(AppServices::fake_with(world))
    }

    /// The `getctag` of a calendar as `user` reads it: it changes with every change of the calendar.
    pub(crate) async fn ctag(&self, user: User, path: &str) -> String {
        let answer = self
            .send(
                Req::new("PROPFIND", path)
                    .by(user)
                    .depth("0")
                    .xml(&propfind(&["CS:getctag"])),
            )
            .await;
        answer
            .multistatus()
            .responses
            .first()
            .unwrap()
            .text(NS_CALENDARSERVER, "getctag")
    }

    /// Sends a request.
    pub(crate) async fn send(&self, request: Req) -> Answer {
        let mut builder = Request::builder().method(request.method.as_str()).uri(&request.path);
        if let Some(user) = request.user {
            builder = builder.header("authorization", user.authorization());
        }
        for (name, value) in &request.headers {
            builder = builder.header(name.as_str(), HeaderValue::from_bytes(value).unwrap());
        }
        let response = self
            .router
            .clone()
            .oneshot(builder.body(Body::from(request.body)).unwrap())
            .await
            .unwrap();
        let (parts, body) = response.into_parts();
        Answer {
            status: parts.status,
            headers: parts.headers,
            body: String::from_utf8_lossy(&body.collect().await.unwrap().to_bytes()).into_owned(),
        }
    }

    /// Puts an event as Anna and returns its entity tag.
    pub(crate) async fn put_event(&self, path: &str, uid: &str, summary: &str) -> String {
        let answer = self
            .send(
                Req::anna("PUT", path)
                    .ics(&event(uid, summary))
                    .header("if-none-match", "*"),
            )
            .await;
        assert_eq!(answer.status, StatusCode::CREATED, "{path}: {}", answer.body);
        answer.header("etag").to_owned()
    }
}

/// A `VEVENT` object resource.
pub(crate) fn event(uid: &str, summary: &str) -> String {
    format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Davhaven//tests//EN\r\nBEGIN:VEVENT\r\nUID:{uid}\r\n\
         DTSTAMP:20270101T000000Z\r\nSUMMARY:{summary}\r\nDTSTART:20270301T100000Z\r\nDTEND:20270301T110000Z\r\n\
         END:VEVENT\r\nEND:VCALENDAR\r\n"
    )
}

/// A `VTODO` object resource.
pub(crate) fn todo(uid: &str, summary: &str) -> String {
    format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Davhaven//tests//EN\r\nBEGIN:VTODO\r\nUID:{uid}\r\n\
         DTSTAMP:20270101T000000Z\r\nSUMMARY:{summary}\r\nEND:VTODO\r\nEND:VCALENDAR\r\n"
    )
}

/// A `PROPFIND` body asking for the properties (`D:displayname`, `C:calendar-data`, ...) written as prefixed names.
pub(crate) fn propfind(props: &[&str]) -> String {
    let elements = repeat(props.len(), |index| {
        format!("<{}/>", props.get(index).copied().unwrap_or_default())
    });
    format!("<D:propfind {NS}><D:prop>{elements}</D:prop></D:propfind>")
}

/// `count` pieces of text, the `index`th made by `piece`, concatenated.
pub(crate) fn repeat(count: usize, piece: impl Fn(usize) -> String) -> String {
    let mut out = String::new();
    for index in 0..count {
        out.push_str(&piece(index));
    }
    out
}

/// A status line and its properties inside a response.
#[derive(Debug)]
pub(crate) struct Stat {
    /// The status of the `propstat`.
    pub(crate) status: u16,
    /// The property elements.
    pub(crate) props: Vec<Element>,
    /// The local name of the `DAV:error` element of the `propstat`.
    pub(crate) error: Option<String>,
}

/// One `D:response`.
#[derive(Debug)]
pub(crate) struct Resp {
    /// The `D:href`.
    pub(crate) href: String,
    /// The status of a response without `propstat`s.
    pub(crate) status: Option<u16>,
    /// The local name of the `DAV:error` element of the response.
    pub(crate) error: Option<String>,
    /// The `propstat`s.
    pub(crate) stats: Vec<Stat>,
}

impl Resp {
    /// The property in the `propstat` with status 200.
    pub(crate) fn prop(&self, namespace: &str, local: &str) -> Option<&Element> {
        self.stats
            .iter()
            .filter(|stat| stat.status == 200)
            .flat_map(|stat| &stat.props)
            .find(|prop| prop.is(namespace, local))
    }

    /// The text of a property of the 200 `propstat`; the test fails when it is absent.
    pub(crate) fn text(&self, namespace: &str, local: &str) -> String {
        self.prop(namespace, local)
            .unwrap_or_else(|| panic!("{} has no {local}: {self:?}", self.href))
            .text()
    }

    /// The hrefs inside a property of the 200 `propstat` (`calendar-home-set`, `group-membership`, ...).
    pub(crate) fn hrefs_of(&self, namespace: &str, local: &str) -> Vec<String> {
        self.prop(namespace, local)
            .unwrap_or_else(|| panic!("{} has no {local}: {self:?}", self.href))
            .children_named(NS_DAV, "href")
            .map(Element::text)
            .collect()
    }

    /// The status of the `propstat` that holds the property.
    pub(crate) fn status_of(&self, namespace: &str, local: &str) -> Option<u16> {
        self.stats
            .iter()
            .find(|stat| stat.props.iter().any(|prop| prop.is(namespace, local)))
            .map(|stat| stat.status)
    }

    /// The privileges inside a `current-user-privilege-set`, by the local name of their element, sorted.
    pub(crate) fn privileges(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .prop(NS_DAV, "current-user-privilege-set")
            .map(|set| {
                set.children_named(NS_DAV, "privilege")
                    .filter_map(|privilege| privilege.elements().next())
                    .map(|inner| inner.local.clone())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    /// The reports of a `DAV:supported-report-set` as `(namespace, local name)`, in document order.
    pub(crate) fn reports(&self) -> Vec<(String, String)> {
        self.prop(NS_DAV, "supported-report-set")
            .unwrap_or_else(|| panic!("{} has no supported-report-set: {self:?}", self.href))
            .children_named(NS_DAV, "supported-report")
            .filter_map(|supported| supported.child(NS_DAV, "report")?.elements().next())
            .map(|report| (report.namespace.as_str().to_owned(), report.local.clone()))
            .collect()
    }

    /// The `name`s of the `C:comp` elements of a `C:supported-calendar-component-set`, in document order.
    pub(crate) fn components(&self) -> Vec<String> {
        self.prop(NS_CALDAV, "supported-calendar-component-set")
            .unwrap_or_else(|| panic!("{} has no supported-calendar-component-set: {self:?}", self.href))
            .children_named(NS_CALDAV, "comp")
            .map(|comp| comp.attribute("name").unwrap_or_default().to_owned())
            .collect()
    }

    /// The local names of the children of a property, for resource types and privilege sets.
    pub(crate) fn children(&self, namespace: &str, local: &str) -> Vec<String> {
        self.prop(namespace, local)
            .map(|prop| prop.elements().map(|child| child.local.clone()).collect())
            .unwrap_or_default()
    }
}

/// A parsed `D:multistatus`.
#[derive(Debug)]
pub(crate) struct Multi {
    /// The responses in document order.
    pub(crate) responses: Vec<Resp>,
    /// The `D:sync-token` of a `sync-collection` answer.
    pub(crate) sync_token: Option<String>,
}

fn status_code(text: &str) -> u16 {
    text.split(' ').nth(1).unwrap().parse().unwrap()
}

fn error_name(element: &Element) -> Option<String> {
    element
        .child(NS_DAV, "error")
        .and_then(|error| error.elements().next())
        .map(|inner| inner.local.clone())
}

impl Multi {
    /// Reads the XML of a multistatus.
    pub(crate) fn parse(body: &str) -> Self {
        let root = parse(body.as_bytes(), &DavLimits::default()).unwrap();
        assert!(root.is(NS_DAV, "multistatus"), "{body}");
        let responses = root
            .children_named(NS_DAV, "response")
            .map(|response| Resp {
                href: response.child(NS_DAV, "href").unwrap().text(),
                status: response
                    .child(NS_DAV, "status")
                    .map(|status| status_code(&status.text())),
                error: error_name(response),
                stats: response
                    .children_named(NS_DAV, "propstat")
                    .map(|stat| Stat {
                        status: status_code(&stat.child(NS_DAV, "status").unwrap().text()),
                        props: stat
                            .child(NS_DAV, "prop")
                            .map(|prop| prop.elements().cloned().collect())
                            .unwrap_or_default(),
                        error: error_name(stat),
                    })
                    .collect(),
            })
            .collect();
        Self {
            responses,
            sync_token: root.child(NS_DAV, "sync-token").map(Element::text),
        }
    }

    /// The hrefs in document order.
    pub(crate) fn hrefs(&self) -> Vec<&str> {
        self.responses.iter().map(|response| response.href.as_str()).collect()
    }

    /// The response of an href; the test fails when there is none.
    pub(crate) fn response(&self, href: &str) -> &Resp {
        self.responses
            .iter()
            .find(|response| response.href == href)
            .unwrap_or_else(|| panic!("no response for {href} in {:?}", self.hrefs()))
    }
}
