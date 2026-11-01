//! The credential dimensions of the permission matrix (PLAN 3.2): which surface accepts which kind of credential, in
//! which state.
//!
//! The permission matrix asks what an *authenticated* actor may do. This matrix asks who is authenticated at all:
//! every kind of credential (app password, principal token, tenant token, system token, feed token, RSVP token) is
//! presented on every surface (DAV, API, MCP, feed, RSVP page) in every state (valid, wrong secret, unknown prefix,
//! malformed, revoked, expired, principal suspended, tenant suspended, an app password with another user's login, a
//! deleted principal, an API token that is not in a `Bearer` header). The expectations are the `[[credential_surface]]` and
//! `[[credential_state]]` rows of the hand-reviewed expectations file (`crates/testkit/matrix/expectations.toml`), which
//! is PLAN 2.6 written down: a credential is bound to its surface, only a valid credential of an active principal and
//! tenant authenticates, and the pages that take their token from the URL answer a refusal with the 404 of an unknown
//! token. A state that does not exist for a kind is `n/a` in the file with the reason, and is not run.
//!
//! Everything is done through the public surfaces: credentials are issued and revoked with the management API, the
//! states are produced with the API calls an operator would make (revoke, suspend, delete) and with the manual clock
//! (expiry). An RSVP token is issued the way a guest gets one: the organizer invites somebody outside the tenant, the
//! outbox is delivered and the link is taken out of the mail; it is revoked when the organizer deletes the event.
//!
//! A credential that is valid is presented once before the states that a verification cache could hold on to (revoked,
//! expired, suspended, deleted): the cache of verified credentials (5 minutes, PLAN 2.6) must not outlive them. The
//! oracle itself is tested too: a file that says the opposite of what the server does fails the matrix.

#![expect(
    clippy::unwrap_used,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

use chrono::Duration;
use davhaven_testkit::davhaven_domain::{AppPasswordText, CredentialKind, TokenText};
use davhaven_testkit::davhaven_fixtures::{ActorRole, Attendee, CalendarRole, EventBuilder, Organizer, When};
use davhaven_testkit::davhaven_ports::Clock as _;
use davhaven_testkit::matrix::{CredentialExpectation, CredentialState, CredentialType, Expectations, Surface};
use davhaven_testkit::scheduling::text::rsvp_tokens_in;
use davhaven_testkit::{Actor, TestApp, TestAppError, TestResponse};
use serde_json::{Value, json};

/// How a credential is revoked.
enum Revocation {
    /// With a `DELETE` of the management API.
    Api(String),
    /// By the organizer, who deletes the event the credential belongs to.
    DeleteEvent(String),
}

/// A credential that was issued, with the way to revoke it.
struct Issued {
    secret: String,
    revoke: Option<Revocation>,
}

/// How a credential is put into the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// The way its kind is presented: `Basic` with the login of the owner, `Bearer`, or in the URL.
    Plain,
    /// As the password of an HTTP `Basic` header (an API token that is not in a `Bearer` header).
    BasicPassword,
}

/// What is presented: the secret, and how.
struct Presented {
    secret: String,
    /// The login of a DAV request, when it is not the owner's.
    login: Option<String>,
    mode: Mode,
}

impl Presented {
    fn plain(secret: String) -> Self {
        Self {
            secret,
            login: None,
            mode: Mode::Plain,
        }
    }
}

fn json_of(response: &TestResponse) -> Value {
    response.json().unwrap_or(Value::Null)
}

/// The text at `pointer` of an answer.
fn text<'a>(body: &'a Value, pointer: &str) -> Result<&'a str, String> {
    body.pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("the answer has no `{pointer}`: {body}"))
}

/// The path of the event that invites the guest.
const INVITATION: &str = "/dav/calendars/acme/olivia/personal/rsvp-matrix.ics";

/// An RSVP token the way a guest gets one: the organizer invites somebody outside the tenant, the outbox is delivered and the
/// link is in the mail.
async fn issue_rsvp_token(app: &TestApp) -> Result<Issued, String> {
    let owner = app.actor(ActorRole::Owner).map_err(|e| e.to_string())?;
    let ics = EventBuilder::event("rsvp-matrix@acme.example")
        .summary("Planning")
        .organizer(Organizer::new("mailto:olivia@acme.example"))
        .attendee(Attendee::new("mailto:guest@example.net"))
        .starts(When::utc(2027, 6, 1, 9, 0))
        .ends(When::utc(2027, 6, 1, 10, 0))
        .build();
    let created = app
        .dav(&owner)
        .put(INVITATION, &ics)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !created.status.is_success() {
        return Err(format!(
            "the invitation was refused: {} {}",
            created.status,
            created.text()
        ));
    }
    app.run_workers_until_idle().await.map_err(|e| e.to_string())?;
    let mails = app.mails().to("guest@example.net").await;
    let secret = mails
        .iter()
        .rev()
        .find_map(|captured| {
            let body = format!(
                "{}\n{}",
                captured.mail.text,
                captured.mail.html.clone().unwrap_or_default()
            );
            rsvp_tokens_in(&body).pop()
        })
        .ok_or("the invitation mail has no RSVP link")?;
    Ok(Issued {
        secret,
        revoke: Some(Revocation::DeleteEvent(INVITATION.to_owned())),
    })
}

async fn issue(
    app: &TestApp,
    kind: CredentialType,
    expires: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<Issued, String> {
    let admin = app.api(&app.token(ActorRole::TenantToken).map_err(|e| e.to_string())?);
    let expires = expires.map(|at| at.to_rfc3339());
    match kind {
        CredentialType::AppPassword => {
            let response = admin
                .post_json(
                    "/api/v1/tenants/acme/principals/olivia/app-passwords",
                    &json!({"label": "matrix"}),
                )
                .map_err(|e| e.to_string())?
                .send()
                .await
                .map_err(|e| e.to_string())?;
            let body = json_of(&response);
            Ok(Issued {
                secret: text(&body, "/password")?.to_owned(),
                revoke: Some(Revocation::Api(format!(
                    "/api/v1/tenants/acme/principals/olivia/app-passwords/{}",
                    text(&body, "/id")?
                ))),
            })
        }
        CredentialType::PrincipalToken | CredentialType::TenantToken => {
            let mut request = json!({
                "kind": if kind == CredentialType::PrincipalToken { "principal" } else { "tenant" },
                "label": "matrix",
                "scopes": ["calendars:read", "events:read"],
            });
            if let Some(fields) = request.as_object_mut() {
                if kind == CredentialType::PrincipalToken {
                    fields.insert("principal".to_owned(), json!("olivia"));
                }
                if let Some(expires) = expires {
                    fields.insert("expires_at".to_owned(), json!(expires));
                }
            }
            let response = admin
                .post_json("/api/v1/tenants/acme/api-tokens", &request)
                .map_err(|e| e.to_string())?
                .send()
                .await
                .map_err(|e| e.to_string())?;
            let body = json_of(&response);
            Ok(Issued {
                secret: text(&body, "/secret")?.to_owned(),
                revoke: Some(Revocation::Api(format!(
                    "/api/v1/tenants/acme/api-tokens/{}",
                    text(&body, "/token/id")?
                ))),
            })
        }
        CredentialType::SystemToken => Ok(Issued {
            secret: app.world().system_token().map_err(|e| e.to_string())?.secret.clone(),
            revoke: None,
        }),
        CredentialType::RsvpToken => issue_rsvp_token(app).await,
        CredentialType::FeedToken => {
            let calendar = app
                .world()
                .calendar(CalendarRole::Personal)
                .map_err(|e| e.to_string())?
                .key
                .clone();
            let id = app
                .index()
                .calendars
                .get(&calendar)
                .ok_or("the calendar is not seeded")?;
            let response = admin
                .post_json(
                    "/api/v1/tenants/acme/principals/olivia/feed-tokens",
                    &json!({"mode": "full", "calendar_ids": [id.to_string()]}),
                )
                .map_err(|e| e.to_string())?
                .send()
                .await
                .map_err(|e| e.to_string())?;
            let body = json_of(&response);
            let url = text(&body, "/feed_url")?;
            let secret = url
                .rsplit('/')
                .next()
                .and_then(|name| name.strip_suffix(".ics"))
                .ok_or("the feed url has no token")?
                .to_owned();
            Ok(Issued {
                secret,
                revoke: Some(Revocation::Api(format!(
                    "/api/v1/tenants/acme/principals/olivia/feed-tokens/{}",
                    text(&body, "/token/id")?
                ))),
            })
        }
    }
}

/// The credential with another prefix: one character of the prefix that finds the row changes to another character of the same
/// alphabet (lowercase base32), so that the text is still a credential of its kind and only its prefix is unknown. For an app
/// password the prefix is the first two groups; for a token it follows `dvh_{kind}_`.
fn with_unknown_prefix(secret: &str) -> Option<String> {
    let start = ["dvh_pat_", "dvh_feed_", "dvh_rsvp_"]
        .iter()
        .find(|marker| secret.starts_with(**marker))
        .map_or(0, |marker| marker.len());
    let original = secret.get(start..=start)?.chars().next()?;
    let replaced = if original == 'a' { 'b' } else { 'a' };
    let mut changed = secret.to_owned();
    changed.replace_range(start..=start, &replaced.to_string());
    Some(changed)
}

/// Whether a text has the format of a credential of the kind (the case "unknown prefix" is not the case "malformed").
fn is_well_formed(kind: CredentialType, secret: &str) -> bool {
    match kind {
        CredentialType::AppPassword => AppPasswordText::parse(secret).is_some(),
        CredentialType::PrincipalToken | CredentialType::TenantToken | CredentialType::SystemToken => {
            TokenText::parse(CredentialKind::ApiToken, secret).is_some()
        }
        CredentialType::FeedToken => TokenText::parse(CredentialKind::FeedToken, secret).is_some(),
        CredentialType::RsvpToken => TokenText::parse(CredentialKind::RsvpToken, secret).is_some(),
    }
}

/// Whether the harness can bring a credential of the kind into the state at all; the file says why where it cannot (`n/a`).
const fn producible(kind: CredentialType, state: CredentialState) -> bool {
    // A system token is revoked with an operator command that the harness does not run.
    !matches!((kind, state), (CredentialType::SystemToken, CredentialState::Revoked))
}

/// The states that a cache of verified credentials could hold on to: the credential is presented once while it is valid.
const fn needs_a_warm_cache(state: CredentialState) -> bool {
    matches!(
        state,
        CredentialState::Revoked
            | CredentialState::Expired
            | CredentialState::PrincipalSuspended
            | CredentialState::TenantSuspended
            | CredentialState::DeletedPrincipal
    )
}

/// The states that only some kinds have: the harness runs them for the kinds the file does not mark `n/a`.
const fn is_special(state: CredentialState) -> bool {
    matches!(
        state,
        CredentialState::CrossLogin | CredentialState::DeletedPrincipal | CredentialState::NotBearer
    )
}

/// The text that is presented after the state was produced; `None` when the state cannot be produced for the kind.
async fn produce(app: &TestApp, kind: CredentialType, issued: &Issued, state: CredentialState) -> Option<Presented> {
    let admin = app.api(&app.token(ActorRole::TenantToken).ok()?);
    match state {
        CredentialState::Valid | CredentialState::Expired => Some(Presented::plain(issued.secret.clone())),
        CredentialState::WrongSecret => {
            let mut text = issued.secret.clone();
            let last = text.pop()?;
            text.push(if last == 'a' { 'b' } else { 'a' });
            Some(Presented::plain(text))
        }
        CredentialState::UnknownPrefix => {
            let changed = with_unknown_prefix(&issued.secret)?;
            // The text is still a credential of its kind: a case that degrades to "malformed" is no case.
            is_well_formed(kind, &changed).then(|| Presented::plain(changed))
        }
        CredentialState::Malformed => Some(Presented::plain("not a credential at all".to_owned())),
        CredentialState::Revoked => {
            let response = match issued.revoke.as_ref()? {
                Revocation::Api(path) => admin.delete(path, None).send().await.ok()?,
                Revocation::DeleteEvent(path) => {
                    let owner = app.actor(ActorRole::Owner).ok()?;
                    app.dav(&owner).delete(path).send().await.ok()?
                }
            };
            if matches!(issued.revoke, Some(Revocation::DeleteEvent(_))) {
                // The cancellation is delivered and the links of the invitation are revoked with it.
                app.run_workers_until_idle().await.ok()?;
            }
            response
                .status
                .is_success()
                .then(|| Presented::plain(issued.secret.clone()))
        }
        CredentialState::PrincipalSuspended => {
            let response = admin
                .patch_json(
                    "/api/v1/tenants/acme/principals/olivia",
                    &json!({"status": "suspended"}),
                )
                .ok()?
                .send()
                .await
                .ok()?;
            response
                .status
                .is_success()
                .then(|| Presented::plain(issued.secret.clone()))
        }
        CredentialState::TenantSuspended => {
            let system = app.api(&app.token(ActorRole::SystemToken).ok()?);
            let response = system
                .patch_json("/api/v1/tenants/acme", &json!({"status": "suspended"}))
                .ok()?
                .send()
                .await
                .ok()?;
            response
                .status
                .is_success()
                .then(|| Presented::plain(issued.secret.clone()))
        }
        CredentialState::CrossLogin => Some(Presented {
            secret: issued.secret.clone(),
            login: Some("otto@acme.example".to_owned()),
            mode: Mode::Plain,
        }),
        CredentialState::DeletedPrincipal => {
            let path = "/api/v1/tenants/acme/principals/olivia";
            let etag = admin.get(path).send().await.ok()?.etag()?.to_owned();
            let response = admin
                .delete(&format!("{path}?purge=true"), Some(&etag))
                .send()
                .await
                .ok()?;
            response
                .status
                .is_success()
                .then(|| Presented::plain(issued.secret.clone()))
        }
        CredentialState::NotBearer => Some(Presented {
            secret: issued.secret.clone(),
            login: None,
            mode: Mode::BasicPassword,
        }),
    }
}

/// The status of a request that presents a credential on a surface.
async fn present(app: &TestApp, surface: Surface, presented: &Presented) -> Result<u16, TestAppError> {
    let secret = presented.secret.as_str();
    let response = match surface {
        Surface::Dav => {
            let login = presented.login.as_deref().unwrap_or("olivia@acme.example");
            app.dav(&Actor::basic(login, secret))
                .propfind("/dav/calendars/acme/olivia/", "0", "")
                .send()
                .await?
        }
        Surface::Api => {
            let actor = match presented.mode {
                Mode::Plain => Actor::bearer(secret),
                Mode::BasicPassword => Actor::basic("olivia", secret),
            };
            app.api_as(&actor)
                .get("/api/v1/tenants/acme/principals/olivia/calendars")
                .send()
                .await?
        }
        Surface::Mcp => {
            let actor = match presented.mode {
                Mode::Plain => Actor::bearer(secret),
                Mode::BasicPassword => Actor::basic("olivia", secret),
            };
            app.mcp_as(&actor)
                .list_tools()
                .map_err(TestAppError::Transport)?
                .send()
                .await?
        }
        // A token in a URL is percent-encoded like a client would.
        Surface::Feed => app.feed(&secret.replace(' ', "%20")).get().send().await?,
        Surface::Rsvp => app.rsvp().view(&secret.replace(' ', "%20")).send().await?,
    };
    Ok(response.status.as_u16())
}

/// Whether a status is the refusal of a credential on a surface: 401 at the doors that take credentials in a header, the 404
/// of an unknown token on the pages.
const fn is_refusal(surface: Surface, status: u16) -> bool {
    match surface {
        Surface::Dav | Surface::Api | Surface::Mcp => status == 401,
        Surface::Feed | Surface::Rsvp => status == 404,
    }
}

/// Whether a status is what a credential that authenticates gets for the request of this matrix: the multistatus of the home on
/// DAV, a listing (or the refusal of a token that has no scope for it: a system token carries none that reads calendars) on the
/// API, the tools a token is offered on MCP (every token that authenticates is answered, the ones that act as nobody get none),
/// and the page of the feed or the invitation.
fn is_acceptance(surface: Surface, status: u16) -> bool {
    match surface {
        Surface::Dav => status == 207,
        Surface::Api => matches!(status, 200 | 403),
        Surface::Mcp | Surface::Feed | Surface::Rsvp => status == 200,
    }
}

/// The surfaces that take credentials of a kind, as the file says.
fn taken_by(expectations: &Expectations, kind: CredentialType) -> Vec<Surface> {
    Surface::ALL
        .iter()
        .copied()
        .filter(|surface| expectations.surface_takes(*surface, kind))
        .collect()
}

/// Runs the matrix against `expectations` for the combinations of kind and state that `wanted` selects, and returns the
/// combinations that differ and how many were checked.
async fn run(
    expectations: &Expectations,
    wanted: &dyn Fn(CredentialType, CredentialState) -> bool,
) -> (Vec<String>, usize) {
    let mut differences = Vec::new();
    let mut checked = 0_usize;
    for kind in CredentialType::ALL {
        for state in CredentialState::ALL {
            if !wanted(*kind, *state) {
                continue;
            }
            let rule = expectations.credential_state_rule(*kind, *state);
            if is_special(*state) && matches!(rule, Some((CredentialExpectation::NotApplicable, _))) {
                continue;
            }
            for warm in [false, true] {
                if warm && !needs_a_warm_cache(*state) {
                    continue;
                }
                // A fresh application per credential and state: the states change the world.
                let app = TestApp::builder().build().await.unwrap();
                let expires = (*state == CredentialState::Expired).then(|| app.clock().now() + Duration::hours(1));
                let label = format!("{kind} {state}{}", if warm { " (warm cache)" } else { "" });
                let issued = match issue(&app, *kind, expires).await {
                    Ok(issued) => issued,
                    Err(error) => {
                        differences.push(format!("{label}: the credential cannot be issued: {error}"));
                        continue;
                    }
                };
                if warm {
                    // The credential is valid and is presented once, on the surface that takes it: the verified credential is
                    // now in the cache.
                    let Some(home) = taken_by(expectations, *kind).first().copied() else {
                        differences.push(format!("{label}: no surface takes the kind"));
                        continue;
                    };
                    let status = present(&app, home, &Presented::plain(issued.secret.clone()))
                        .await
                        .unwrap();
                    if is_refusal(home, status) {
                        differences.push(format!(
                            "{label}: the valid credential was refused on {home} ({status})"
                        ));
                        continue;
                    }
                }
                if *state == CredentialState::Expired {
                    // An RSVP link outlives the event it invites to by seven days; the others expire after an hour.
                    app.advance(if *kind == CredentialType::RsvpToken {
                        Duration::days(400)
                    } else {
                        Duration::hours(2)
                    });
                }
                let Some(presented) = produce(&app, *kind, &issued, *state).await else {
                    if !producible(*kind, *state) {
                        continue;
                    }
                    differences.push(format!("{label}: the state cannot be produced"));
                    continue;
                };
                for surface in Surface::ALL {
                    let Some(expectation) = expectations.credential_expectation(*surface, *kind, *state) else {
                        differences.push(format!("{label} on {surface}: the file has no rule"));
                        continue;
                    };
                    if expectation == CredentialExpectation::NotApplicable {
                        continue;
                    }
                    let status = present(&app, *surface, &presented).await.unwrap();
                    checked += 1;
                    let (verdict, holds) = match expectation {
                        CredentialExpectation::Refused => ("refused", is_refusal(*surface, status)),
                        CredentialExpectation::Accepted => ("accepted", is_acceptance(*surface, status)),
                        CredentialExpectation::NotApplicable => continue,
                    };
                    if !holds {
                        differences.push(format!(
                            "{label} on {surface}: answered {status}, the credential should be {verdict}"
                        ));
                    }
                }
            }
        }
    }
    (differences, checked)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_credential_is_checked_on_every_surface_in_every_state() {
    let expectations = Expectations::bundled().unwrap();
    let (differences, checked) = run(&expectations, &|_, _| true).await;
    assert!(checked > 300, "only {checked} combinations were checked");
    assert!(
        differences.is_empty(),
        "{} of {checked} combinations differ:\n{}",
        differences.len(),
        differences.join("\n")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_that_says_the_opposite_of_the_server_fails_the_matrix() {
    // The file says that a valid app password is refused, and the server accepts it on DAV.
    let wrong = davhaven_testkit::matrix::BUNDLED.replacen(
        "state = \"valid\"
kind = \"*\"
result = \"accepted\"",
        "state = \"valid\"
kind = \"*\"
result = \"refused\"",
        1,
    );
    assert_ne!(wrong, davhaven_testkit::matrix::BUNDLED, "the row to change was found");
    let wrong = Expectations::parse(&wrong).unwrap();
    let (differences, checked) = run(&wrong, &|kind, state| {
        kind == CredentialType::AppPassword && state == CredentialState::Valid
    })
    .await;
    assert!(checked > 0);
    assert!(
        differences
            .iter()
            .any(|line| line.contains("app_password valid on dav")),
        "{differences:?}"
    );
}

#[test]
fn the_file_says_something_about_every_kind_in_every_state_and_the_new_states_are_reached() {
    let expectations = Expectations::bundled().unwrap();
    for kind in CredentialType::ALL {
        for state in CredentialState::ALL {
            assert!(
                expectations.credential_state_rule(*kind, *state).is_some(),
                "{kind} {state}"
            );
        }
        assert!(
            Surface::ALL
                .iter()
                .any(|surface| expectations.surface_takes(*surface, *kind)),
            "no surface takes {kind}"
        );
    }
    // The states that were not in the first version of the matrix apply to at least one kind each.
    for state in [
        CredentialState::CrossLogin,
        CredentialState::DeletedPrincipal,
        CredentialState::NotBearer,
    ] {
        assert!(
            CredentialType::ALL.iter().any(|kind| matches!(
                expectations.credential_state_rule(*kind, state),
                Some((CredentialExpectation::Refused, _))
            )),
            "{state}"
        );
    }
}

#[test]
fn an_unknown_prefix_is_a_credential_of_the_kind_with_another_prefix() {
    let world = davhaven_testkit::davhaven_fixtures::FixtureWorld::standard();
    for (kind, secret) in [
        (
            CredentialType::AppPassword,
            world.app_password(ActorRole::Owner).unwrap().secret.clone(),
        ),
        (
            CredentialType::PrincipalToken,
            world.principal_token(ActorRole::Owner).unwrap().secret.clone(),
        ),
        (
            CredentialType::SystemToken,
            world.system_token().unwrap().secret.clone(),
        ),
        (
            CredentialType::FeedToken,
            davhaven_testkit::davhaven_fixtures::feed_token_secret("a"),
        ),
        (
            CredentialType::RsvpToken,
            davhaven_testkit::davhaven_fixtures::rsvp_token_secret("a"),
        ),
    ] {
        assert!(is_well_formed(kind, &secret), "{kind}: the original is well formed");
        let changed = with_unknown_prefix(&secret).unwrap();
        assert_ne!(changed, secret, "{kind}");
        assert!(
            is_well_formed(kind, &changed),
            "{kind}: `{changed}` is still a credential of its kind"
        );
        assert_eq!(changed.len(), secret.len(), "{kind}");
        // Exactly one character differs, inside the prefix (never the type marker of a token, which would make it malformed).
        let differing: Vec<usize> = changed
            .char_indices()
            .zip(secret.chars())
            .filter(|((_, new), old)| new != old)
            .map(|((index, _), _)| index)
            .collect();
        assert_eq!(differing.len(), 1, "{kind}: {changed}");
    }
}
