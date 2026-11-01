# Testing and the test harness

The levels of testing are defined in [`PLAN.md`](PLAN.md) section 3.1; this page describes the test crates that
carry them and the file formats they read. The rules for writing tests (determinism, no sleeping, regression tests
for every fix) are in [`ENGINEERING_RULES.md`](ENGINEERING_RULES.md) R9.

| Crate | Purpose | May depend on |
| --- | --- | --- |
| `davhaven-fixtures` | The fixture world with constant names (and the names of the world of one run), `EventBuilder`, deterministic secrets, the DAV collaboration documents of `testdata/dav/sharing` (`fixtures::dav::sharing`), the corpus loader | domain, ical, ports (testing) |
| `davhaven-port-tests` | Contract suites: every adapter of a port runs the suite of the port | ports, domain, fixtures |
| `davhaven-app-fake` | In-memory fake of the application services for protocol crate tests, and a recording double of the sharing and scheduling services (`recorder::Recorder`) that keeps what a protocol layer hands them. The harness does not use it: `TestApp` runs the real application | app, domain, wire |
| `davhaven-testkit` | `TestApp` (the real application), transports, surface handles, the permission, administration, credential and scheduling matrices, the coverage check, the client-flow runner and the capture converter, the staging runner | everything except `it` and `conformance` |
| `davhaven-it` | Integration tests (`tests/` only); the only consumer of `testkit` besides `conformance` | testkit |
| `davhaven-conformance` | Binary: the matrices and the client flows over HTTP against a deployed instance, the capture converter, the checks of the harness' own files | testkit |

**Timeouts and CI.** `.config/nextest.toml` fails a test that runs for three minutes (the `default` profile: reported as slow
after 60 s, killed after three such periods), so a hung test cannot hold a runner. The `nightly` profile, which the nightly
workflow uses, allows half an hour, because the property tests with 20000 cases and the full PostgreSQL matrices have single
tests that run for many minutes. Three kinds of test have a longer limit in the `default` profile: the PostgreSQL tests of
`davhaven-it` (`*_on_postgres`, fifteen minutes), the `on_postgres` copy of the application suite (fifteen minutes as well: each of
its tests makes a database and drops it, which waits for every backend of the cluster to let go of it, and that can take a minute
on a host that is busy with other builds), and the permission matrix over HTTP of the staging runner (ten minutes: a sample takes about
two and a half on a warm runner, every case several times that). The suites that run a sample on pull requests (the permission and
administration matrices on PostgreSQL, the client flows and the scheduling matrix over the calendar client surface, and the permission
matrix over HTTP, see below) run them in full when `CONFORMANCE_FULL=1`, which the nightly workflow sets. The image smoke test (`scripts/image-smoke.sh`) needs only
Docker: it starts its own PostgreSQL in a private network without a route to the outside and publishes no port of the host.

## The fixture world

`FixtureWorld::standard()` is plain data that every backend seeds the same way: the real application on the memory and
PostgreSQL stores (`TestApp`), a deployed instance for `conformance` (with the tenants `{run}-a` and `{run}-b` of
`FixtureWorld::with_names(WorldNames::for_run(..))`, so that runs on one instance do not meet). All names are constants
in `davhaven_fixtures::names`.

| Tenant `acme` (login domain `acme.example`) | |
| --- | --- |
| `olivia` (`ActorRole::Owner`) | owns the `personal` calendar, the shared user calendar `projects` and the mirror calendar `google` |
| `mia` (`GroupMember`) | member of the group `team`, which owns the group calendar `team-calendar`; `team` also has an accepted read grant on the managed calendar `holidays`. Both grants of `team` are **required** (a member cannot delete the calendar from their home: `403` with `DAV:need-privileges`), the grants of the sharees and of `viewers` are optional (a delete hides the calendar for the person who made it) |
| `rita`, `wanda`, `gary` | accepted sharees of `projects`: read, read-write, and read through the group `viewers` |
| `paul`, `dora` | a pending and a declined invitation to `projects` (they have no access) |
| `otto` (`OtherUser`) | a user without any access |
| `sven` (`SuspendedUser`) | a suspended user: every login is refused |
| `robot` (`ServicePrincipal`) | a service principal; owns `holidays` (managed) |
| `assistant` (`ServiceGrantee`) | a service principal that is **granted** (through the management API, which grants to service principals; client sharing does not) the calendar of the group `team-calendar` for reading and writing and `holidays` for reading |
| `importer` (`ServiceWriter`) | a service principal that is granted `holidays` for reading and writing: the API and MCP write there, where DAV caps a managed calendar at read for everybody |
| `room1` | a resource |

Tenant `globex` has one user, `gina` (`OtherTenantUser`). Every calendar holds one event (constants
`PERSONAL_EVENT_URI`, `SHARED_EVENT_UID`, ...). Every user has an app password, every principal and tenant an API
token, and there is a system token; secrets are constants derived from labels in the formats of PLAN 2.6, so they are
the same in every run. `FixtureWorld::collection_path(viewer, calendar)` gives the DAV path a viewer uses: the own
home for the owner, the binding in the own home for sharees and members, and the owner's home (to be probed, and to
stay invisible) for everybody else.

## `TestApp`

`TestApp` is the **real application**, assembled the way `davhaven serve` assembles it: the plugin registry of the server
builds the ports from a development configuration (the memory or PostgreSQL store, the local authenticator, the template
renderer, the default scheduling policy, the recording HTTP client, the `noop` rate limiter that is the matrix profile of
PLAN 3.2), the clock and the id generator are the manual ones of the builder, and the routers are those of the server with
every route group on one listener behind the shared edge layers. The fixture world is seeded through the services, the way a
provisioning system and calendar clients make it (`crates/testkit/src/seed.rs`); only the credentials (the constant secrets
of the world are stored as the credential service stores what it issues) and the mirror calendar (a sync engine makes those)
are written to the store.

```rust
let clock = ManualClock::default();
let app = TestApp::builder()
    .store(StoreKind::Memory)   // Postgres: a database cloned from the migrated template; with CI=true a missing DATABASE_URL fails, never skips
    .clock(clock.clone())
    .ids(SeqIds::new())
    .config(AppConfig::default())
    .build()
    .await?;

let owner = app.actor(ActorRole::Owner)?;                   // HTTP Basic with the app password
let response = app.dav(&owner).propfind("/dav/", "0", body).send().await?;
let token = app.token(ActorRole::TenantToken)?;             // bearer token
let response = app.api(&token).get("/api/v1/tenants/acme/principals").send().await?;

app.advance(Duration::hours(1));                            // moves the manual clock the application is built on
let summary = app.run_workers_until_idle().await?;          // ticks every worker; never sleeps
let before = app.observe().await?;                          // the whole state: sequences, objects, grants, bindings, inboxes, outbox, mails, events
```

Handles (`dav`, `api`, `mcp`, `feed`, `rsvp`) build requests and send them through a `Transport`: in process through an axum
router (`InProcess`, `tower::ServiceExt::oneshot`), or over the network (`HttpTransport` with a base URL). The same handles
work with both, so a test written for `TestApp` also runs from `conformance`; `app.serve()` listens on a socket of the loopback
interface for the tests that need a server that is really reached over HTTP (the staging runner, the capture loop).
`app.services()` gives the application services directly, `app.login(role)` authenticates a role through the authentication
service. `app.mails()` and `app.events()` are the capture doubles (a `MailTransport` and an `EventSink`) that are part of the
`AppDeps` the services and the workers are built from, so every mail the application composes and every domain event it
delivers is observable. `.empty()` starts without a world, `.world(..)` seeds another one (`FixtureWorld::with_names` for the
two tenants of a run), `.tenant_settings(..)` changes the settings of a tenant before it is seeded, `.configure(..)` the
application configuration and `.server_config(..)` the configuration of the server, for example `[observability.dav_capture]`.
`TestApp::observe` reads the state through the store ports (`observe.rs`): a request that was refused is shown to have changed
nothing by comparing two observations. `.database_layer(..)` wraps the store before anything of the application receives it:
`crates/it/tests/transactions.rs` wraps it in `RollbackWatch` of `ports::testing` and drives a representative happy path of
each surface (each kind of credential, DAV discovery, listings, reports, reads and writes, the reads of the API, MCP, a feed,
an RSVP page) and the workers with and without work (a superseded invitation among it), failing on any transaction that ends
without a commit (the store port's rule, which keeps the rollback counter of PostgreSQL for failures). Observations
(`app.observe()`) commit their reads too, so they can be combined with the watch.

## Port contract suites

Every port has `port_tests::<port>::run(factory)` (returns the `ContractReport`) and `run_all(factory)` (fails the
running test and lists every violated expectation). The factory builds a fresh implementation; for the key ring it
takes a `KeyRingSpec` (active and retired key ids). Suites with cases today: `clock`, `ids`, `keyring`, `sealer`
(plus `run_authenticated` for production sealers), `hasher`, `event_sink`, `mail`, `scanner`, `outbox` and
`rate_limit` (plus `run_limited`), `http_client` (schemes, credentials in URLs, the table of forbidden targets, quiet
errors, the fail-closed default of `validate_url`) and `templates` (rendering, escaping, fallbacks, assets); `store`
has the cases of the storage adapter, including the outbox settlement (claims, leases, deferral), and the "clocked" cases
(`store_clocked_contract_tests!`, `run_clocked_case`) that are handed the manual clock of their database and move it between
writes, for answers that depend on when things happened (the oldest audit record of all tenants); `profile_signer` has the cases
of the signer of Apple profiles, which the reloading signer of `davhaven-crypto-local` runs too (its own tests renew the files
in a scratch directory); `policy` has the
cases of the scheduling policy (repeatable answers, a resource's answer is an answer), run for both shipped
policies (what a collision with busy time means is the policy's decision and has cases of its own); `provider` runs the contract of a calendar provider against every implementation (a fake and the adapters of Google and
Microsoft over recorded HTTP: the consent URL with its state, challenge and redirect, the exchange and a refused code, the renewal
and a revoked refresh token, exactly one primary calendar, events as well-formed iCalendar, a snapshot for an answer without a cursor, a
cursor the provider no longer accepts, a calendar that does not exist, and the push direction as unsupported); `auth` is the contract of the authenticators (see below). A suite never sleeps and is tested against deliberately
broken doubles, so it is known to detect violations.

```rust
#[test]
fn the_system_clock_satisfies_the_contract() {
    port_tests::clock::run_all(|| Arc::new(SystemClock));
}
```

## Outbox, mail and webhooks: `crates/it/tests/outbox`

The dispatcher, the iMIP handler, the webhook handler and the webhook and outbox services are tested in one
integration binary, `cargo nextest run -p davhaven-it outbox`, on the **real memory store**. There is no database
double in `davhaven-ports`: a double that reimplements the store would hide exactly what these tests are about (leases
that run out, records that disappear, transactions that fail). Unit tests of the application (`crates/app/src/outbox/**/tests.rs`,
`crates/app/src/imip/**/tests.rs`, `crates/hooks-webhook/src/webhook/tests.rs`) test pure logic and need no database: the
classification of answers, backoff arithmetic, token buckets, model building, request signing.

The binary starts from `support.rs`:

* `World` is the whole application on the memory store with a `ManualClock` and `SeqIds`: tenants, principals, calendars
  and objects are seeded through the store (`add_tenant`, `add_calendar`, `add_object`, `seed`), and every assertion reads
  back through the store (`outbox()`, `deliveries()`, `audit()`), so a test says what is stored and not what a double saw.
* `FlakyDatabase` wraps the memory store and fails on demand: an outage of the whole store or of one tenant, commits that
  fail, a settlement that fails once. The dispatcher tests use it for the paths a healthy store never takes.
* The ports the world does not need to implement are scripted doubles: a handler with a queue of results (or one that
  hangs, panics, or waits at a barrier), a mail transport and an HTTP client that answer from a script and record what they
  were sent, a rate limiter, a renderer that records its requests, an event sink and a backend for the calendar layer.

What the modules cover:

| Module | What it checks |
| --- | --- |
| `dispatcher` | claims and leases (a record whose lease ran out is not settled over another dispatcher's claim), the batch deadline and the start margin, deferral without an attempt, retry and dead-lettering, panics and hangs, graceful release, the announcement of dead mails and its idempotence, configuration of concurrency and polling, outages |
| `fan_out` | one delivery per event and subscription, filters, repeated fan-out, details for managed and group calendars only (never for personal, user or mirror calendars), summaries cut to one line, sinks |
| `webhook_delivery` | signing, what each answer of the receiver means, the retry window, which failures count against a subscription (25 simultaneous first failures do not disable it), disabling, skipped deliveries, secret rotation and opening, the oversized answer |
| `webhook_service` | the nine management operations: validation, normalization, optimistic concurrency, the subscription cap, ping, redelivery, audit records, and for every operation every actor kind and the other tenant's ids |
| `operators` | the outbox listing and retry, cursors bound to their listing, scopes, tenants |
| `imip_mail` | the composer and the handler end to end: headers, `From` modes, snapshots, dropped invitations, deferral by the limiter and the breaker, failure classes, staging rules |
| `imip_templates` | the real renderer and the real MIME assembler against the model the composer builds (the seam between the application and the themes) |
| `rsvp_links` | the derived token: the same link on every attempt, reuse, rotation of the key ring, rescheduling, expiry, revoked tokens, prefix collisions |

Everything runs under paused tokio time where time matters (`#[tokio::test(start_paused = true)]`) and never sleeps.

## The server and the retention worker: `crates/server`, `crates/it/tests/retention`

| Where | What it covers |
| --- | --- |
| `crates/server/src` (unit tests) | the configuration and its redaction, the per-kind plugin tables (`[plugin.mail_transport.memory]` and `[plugin.rate_limiter.memory]` set together in a development configuration), the check of a plugin the server has never heard of against its own schema, the registry rules (every kind has two implementations or one plus the documented empty set; the production refusals are exactly the plugins that refuse themselves), the listeners' connection limits under paused time (a client that sends nothing, a part of the HTTP/2 preface, the whole preface and nothing more), the shutdown budget, the supervisor and its heartbeats, the request spans (an in-memory exporter: the trace id and parent of the caller's `traceparent`, the nesting of `port_call` spans, the caller's sampling decision), the administrative commands against the memory store (bootstrap, system tokens, `rotate-keys` with a two-key ring and a webhook sealed under the old key, sync epochs of two tenants) |
| `crates/server/tests/serve.rs` | the assembled server over real sockets: which route group answers on which listener, merged listeners, the scenario of the image smoke test (API write read over DAV and back), the connection limits, the capture (authenticated exchanges only, no buffering of an oversized body), and on PostgreSQL the **production setup**: an owner role that migrates and a `NOBYPASSRLS` runtime role created for the test (`support::Roles`), production mode starting with a healthy database, a second tenant that sees nothing of the first (404 over the API and over DAV), the retention worker skipping the audit purge as the runtime role, `admin purge-audit` as the owner, and production refusing a superuser unless `allow_unbound_role` is set |
| `crates/server/tests/binary.rs` | the `davhaven` binary as a process: exit codes, `config check` with `*_file` secrets and unknown variables, `serve` until `SIGTERM` with `healthcheck` before and after, the administrative commands against a database of their own, the OTLP exporter speaking HTTP/2 to a stand-in collector |
| `crates/server/tests/lease_release.rs` | the supervisor drives the application's workers against an outbox handler that never finishes; at the stop the pass is dropped and the shutdown hook hands the claim back (pending again, due at once, the attempt not counted) |
| `crates/server/tests/deploy.rs` | the alert rules and the dashboard: every metric they use is a string literal of the **production code** (`crates/*/src` without test modules), every alert is complete and links to a heading of the runbook |
| `crates/it/tests/retention` | the cleanup worker over `store-memory` with a manual clock: periods and cut-offs (a `Spy` around the store records the cut-off every step receives, with periods that all differ), outbox, audit and change-log data kept the day before the period ends and removed the day after (the change-log prune raises `sync_min_seq`, an old sync token is refused), a connection that may not purge the audit log (`NotPermitted`) or a store without the delivery purge are skipped and not failures, a backlog longer than one pass reports `more` and the next pass finishes it |

**Process tests and time.** A server process says what it does on standard error, and the process tests read that stream: the line
`davhaven started` is the signal that the listeners are bound, the end of the stream is the signal that the process exited. Nothing
polls and nothing sleeps; the only clock is the upper bound of each wait, which turns a hang into a failure. Tests of the assembled
server that need time (`start_paused`, `ManualClock`) build it through `assembly::assemble_with_ports`. The one wait that is real time is
the header read timeout of the end-to-end test (one second), because it checks that the configuration reaches the listener; the logic of
the timer is tested under paused time in the unit tests.

## The edge, the management API and the web pages

Protocol tests (L4, PLAN 3.1) drive the complete router of a surface in process, with the edge layers, authentication,
handlers and problem rendering, over the fake application or small service doubles. They never need a database.

| Where | What it covers |
| --- | --- |
| `crates/http/src` (unit tests of each layer) | request ids, the client address behind trusted proxies, origin guard and CORS, body and time limits, load shedding, panics, token redaction, problem rendering of every catalog row, credential parsing and challenges per surface |
| `crates/api/tests/router.rs` | every operation is wired and answers only statuses its documentation lists; bodies, keys, preconditions and pagination; batches all or nothing; replay of a repeated batch, a failed batch freeing its key, the `feature-not-enabled` row end to end, relative `Link` headers and page limits, and every operation that returns a secret (found in the document by its `Cache-Control` header) driven with an `Idempotency-Key`: `no-store`, 409 `secret-not-replayable` with the status and `Location` of the first answer on the repeat, nothing stored |
| `crates/api/src/router/idempotency/tests.rs` | the idempotency layer on a small router with handlers that count runs, wait at a gate, carry secrets, fail and panic: replays, reuse, scoping by tenant and token, in-flight requests, a client that disconnects, work that is cut off at the request timeout and a settlement of an attempt that lost its claim (fencing), the lease the layer asks for, an unavailable service (503), oversized bodies (413 before a key is reserved), responses that cannot be stored, a keyed `POST` without a context (500), a handler that forgot to mark its response replayable, fingerprints |
| `crates/api/tests/support` | `MemoryIdempotency`, an in-memory `IdempotencyService` with the semantics of PLAN 2.10 and the lease and fence of ADR-0006 (the fake application leaves the service unsupported) |
| `crates/api/src/openapi/tests.rs` | the route table and the registered routes are the same set, every operation carries the scopes of the plan, every reference of the document resolves, problems and parameters are components, the names of the parameter components are pinned (they are the published contract), the problems of an operation follow from what it accepts, every `POST` declares the form of `Idempotency-Key` that is true for it, enumerations keep their values, `ProblemCode` lists the codes clients receive, no component is unreachable, the document stays small |
| `crates/web/tests/router.rs` | one 404 for every bad token, the RSVP form rules, feeds with `ETag` and `304`, the OAuth callback, assets, the security headers of every response |
| `crates/mcp/src` (unit tests) | the rules of a call's arguments (ranges, limits, the length of a search text, addresses, unknown members), the field mapping of events and calendars (text only as `untrusted_text`, attendees redacted, the busy form of the application mapped as it is, `writable` for every kind of calendar, an incomplete service view is an internal error), the JSON-RPC check of a body (one parse, `413` against `400`), the table from problem to retry hint (against the catalog) and the placement of the problem in `_meta`, the tool catalog (every tool's scope is the one the domain gives its operations), the protocol revision list, the configuration |
| `crates/mcp/tests/mcp/` | the MCP server in process over the fake application with doubles that record what the tools hand the services (`router.rs`: authentication, a valid app password refused as Basic and as Bearer, `Origin`, methods, bodies, headers; `protocol.rs`: handshake and version negotiation (every revision is answered with `2025-06-18`), tool list per scope, protocol errors; `tools.rs`: what each tool hands the services, scopes, limits, write-only tokens; `conformance.rs`: an independent JSON-RPC client that validates every result against the announced `outputSchema`, compares the catalog and the vendor `_meta` with `docs/contracts/mcp-tools.json` and holds the insta snapshots). What a double cannot honestly answer is tested in `crates/it/tests/mcp` |
| `crates/it/tests/mcp/` | the MCP server over the **real** services (`davhaven-app` on the memory store, `crypto-local`, the local authenticator that verifies tokens the credential service minted, the memory rate limiter, a manual clock): `tools.rs` every tool, a token with only `mcp:write`, creation that is made once (a repeated or reused `client_request_id`, a key an integration manages), deletion of what is not there and of what the person may not delete, cursors that belong to their search, external attendees and `mcp:schedule_external`; `privacy.rs` private and confidential events of others as busy time (reads, searches, recurring series, writes), a text search that cannot be used to read them, updates that cannot unmask them; `isolation.rs` another tenant and a stranger through every tool (404, the same answer as for what does not exist, no side effect), foreign cursors, expired and revoked tokens, tenant and scope-less tokens; `budgets.rs` the per-token budgets of the limiter port, their audit records and the tenant switch; `client.rs` the `rmcp` client library over a socket as an independent MCP client |
| `crates/it/tests/providers/` | calendar providers on the **real** application (`TestApp`, on the memory store and on PostgreSQL) with a fake provider whose remote world the tests write: `connect.rs` the OAuth flow over HTTP (the consent URL with its `S256` challenge and its state, the callback, the mirror calendar and its read-only state, a state that works once, expires after ten minutes and belongs to one provider, a refused consent and a rejected code, an account without calendars, a person suspended at the consent screen, providers that are off or unknown, principals that may not connect, the same account connected again, two accounts of one person, the list of providers); `sync.rs` the sync worker (a first pull, pulls that write nothing when nothing changed, changes, deletions, snapshots and deltas, chunks, events that cannot be stored, a cursor the provider forgot, renewal of an expiring or revoked access token, a rotated refresh token, an account switched off once and told once, a provider that is unavailable and the growing wait, two workers and one account, the account of a deleted principal, no worker for a provider that is off, the accounts of a provider that is switched off meanwhile left alone, a client the provider refuses that switches no account off, a calendar that is too large asked for once, accounts of suspended principals that neither take the places of the others nor make the worker spin, a reconnection during a pull that the pull does not undo, a mirror that is gone and made again, the worker and two tenants); `accounts.rs` the list (paging, no secret), disconnecting (the mirror goes, the provider is asked to revoke unless another account holds the grant, a provider that cannot revoke), a mirror that cannot be deleted on its own, the scope `providers:manage` and no other, another tenant |
| `crates/dav/src` (unit tests) | the method table, the XML reader and writer, the property catalog of every resource kind (including notifications, scheduling inbox items and principals a search found), the mapping of every problem to its DAV status and precondition element, the conditional headers, and the collaboration modules: the documents of `CS:share`, `CS:invite-reply`, `CS:shared-as`, the `schedule-response` and the notifications against the byte-exact fixtures of `testdata/dav/sharing`, the media type rule of `POST`, the principal searches (parsing, matching, kinds, limits) |
| `crates/dav/tests/router.rs`, `crates/dav/tests/protocol/` | the router and the methods over the fake application, request by request: discovery, PROPFIND, PROPPATCH, the object methods, collections, reports, `sync-collection`, permissions, hostile bodies and the request bodies of the clients (`testdata/dav`); `collaboration.rs`: principal search end to end (also in a tenant of more than 50 matching principals: `Anna B`, `Anna Bau` and `Anna Baue` find Anna Bauer behind sixty people called Anna; a cut answer ends with a 507 entry), the media types and visibility rules of `POST` (the outbox of another tenant or principal is 404 whatever the message; the notification collection and the inbox of a home under the slug of another tenant are 404), the limits of share and outbox requests (configured, not constants), `calendar-multiget` of the inbox, the notification collection, and proptest properties of the share and search readers. The fake has no sharing and no scheduling service: where a test wants to know what the layer hands on, it swaps them for the **recording double** of `davhaven_app_fake::recorder` and asserts the exact `ShareRequest`, `InviteReply`, outbox owner and body, bulk-read paths and data selection, and notification conditions it received, and that a stranger's request never reached it. What the real services answer is rendered by the unit tests and exercised against the real application by `crates/it/tests/appcore/dav_collaboration.rs` |
| `crates/it/tests/appcore/dav_collaboration.rs` | the router of `davhaven-dav` over the real services (on both stores, like the rest of `appcore`), with the request bodies of the clients: the flow invitation, notification, `CS:invite-reply`, `CS:shared-as`, notification deletion with `If-Match` and synchronization; the 207 of a share with an outside address; strangers and other tenants (404 everywhere, nothing changes by asking); **the boundary between seeing and acting**: a read and a read-write sharee `POST` `CS:share` to their own binding (403 `need-privileges` with `CS:share`, 400 for a malformed body, 403 for too many sharees, and no token, sharee list or notification changes), an administrator may share, a pending or departed sharee has no binding to act through, a managed calendar cannot be shared, sharing switched off is 403 for the owner and 404 for everybody else; an `If-Match` that was true when a client read an invitation does not delete the newer one the application wrote in place (and `Last-Modified` follows the rewrite); principal search over real principals (rooms and people among more than 50 matches, tenant isolation, no services or suspended users, the cut answer); and the inbox and the outbox of the real `SchedulingService`, wrapped only to count and record what the DAV layer asks of it: one read per step and not per item, the changed members of a synchronization read by path and without messages, what is read bounded by `max_response_bytes`, the data selection that reaches the bulk read, the arguments that reach the outbox; the owner reads an inbox and nobody else does (404 for other principals and other tenants' slugs). `SchedulingService::inbox_get_many` itself is tested directly: one transaction with at most one load of the authorization facts (counted with `CountingDatabase`), the delivered items of that inbox only (another inbox's item, a quarantined message and a calendar object are `Missing`), no message when none is wanted, the message cut down to the selection of the request, and the limit of a multiget told to the owner only. The sharing and notification flows also run on PostgreSQL through the matrices and the client flows of `TestApp` (the share, invite-reply and notification rows of the permission matrix, the share scenarios of the clients). Principal search has no row in the permission matrix (it is no operation on a calendar); its tenant isolation is tested here and by the store contract suite (foreign tenant, with kinds and criteria) |
| `crates/dav/fuzz` | cargo-fuzz targets (nightly): `xml_reader` (the XML reader and every typed request behind it) and `collaboration_xml` (share requests, invitation replies and both principal searches; an accepted share request reads back as written) |
| `crates/wire/src/schema.rs` (tests) | the bridge from the `schemars` schemas of the domain to OpenAPI: enumerations carry the values of the domain (checked against `ALL`), tagged unions keep their tags, named primitives are plain strings |

The credential adapters have their own suites: `crates/auth-local/src/authenticator/tests.rs`; the `Authenticator` contract
suites of `davhaven-port-tests`, which are two because they test two things (`auth::run` is the port contract that every
authenticator meets, `noop` included: values that are no credential are passed on or refused, an unknown credential is never
accepted, no input makes it fail; `auth::run_store_backed` is the contract of an authenticator over the credential store:
surfaces, scopes, logins, tenants of paths, revocation at once, suspension, expiry, caching, last use), both run from `crates/it/tests/auth_local.rs`
with the production cryptography, on the memory store **and on PostgreSQL** (a database cloned from the migrated template, reached as the
bound runtime role, so the credential lookup in system scope and the row-level security of the tenant tables are part of what the
authenticator is checked against; the `it` crate owns cross-crate scenarios and may depend on the adapters; `davhaven-testkit` is the
harness and provides the database, `ClonedDatabase::into_database`); the key ring, sealer and hasher suites for
`crypto-local`; and the rate limiter suites for `ratelimit-memory` (`rate_limit::run` for the budgets and
`rate_limit::run_backoff` for the two failure buckets of the port, which any limiter used in production must pass). A suite
that a second implementation could run is run against it. The `eicar` scanner is an adapter crate (`davhaven-scanner-eicar`) and runs
`scanner::run_all` there; the server hosts no plugin, so it runs no contract suite (`xtask arch-check` refuses a dev-dependency
on `davhaven-port-tests` from it).

The generated contracts are checked by `cargo xtask contracts --check`. Whether generators can use `docs/openapi.json` is
checked by `crates/api/clients/smoke.sh` (workflow `openapi-clients`): it generates a Java client and two TypeScript clients
(OpenAPI Generator and Orval), compiles and type-checks them, and has the generated Java model read and write an event and a
problem exactly as the server writes them (`crates/api/clients/fixtures`, kept equal to the output of the wire types by
`crates/api/tests/client_fixture.rs`), then read both with an enumeration value that this version does not know (the
settings that make that work are in `docs/api.md`). The tools are pinned (`package-lock.json`, installed with
`npm ci --ignore-scripts`; `pom.xml`). It needs the network and runs when the document or the project changes.

## The application core: `crates/it/tests/appcore`

The use cases of `davhaven-app` (tenants, principals, calendars and bindings, objects, JSON events,
batches, sharing, credentials and authentication, feeds, idempotency keys and the audit log) are tested in one integration
binary, `cargo nextest run -p davhaven-it appcore`, on the **real stores**, for the same reason as the outbox tests:
the behavior under test (the write invariant, rollback including the outbox, tenant isolation) is the store's and not a
double's. **The whole suite runs twice**: as the module `on_memory` on the in-memory store and as `on_postgres` on PostgreSQL, as the
bound runtime role, on a database that is cloned from the migrated template for every world (milliseconds), so row-level
security, the composite keys, the system scope and the real transactions are part of what the application is tested against.
`on_memory.rs` and `on_postgres.rs` define `STORE` and invoke the `suite!` macro of `main.rs`, which declares the same test files
in each; the world (`support.rs`) builds its store from `STORE`, and the tests do not know which one they are on (no test depends on
one store). The test `stores::the_world_is_built_on_the_store_its_copy_names` checks, from the port calls, that each copy really
talked to its own adapter. The PostgreSQL copy needs `DATABASE_URL` (CI and the build host have one) and **fails without one**, in
CI as everywhere else (R9); outside CI, `DAVHAVEN_ALLOW_NO_DB=1` lets it run on the memory store instead and says on the error
stream that nothing was tested against PostgreSQL, like the other tests that need the database (`require_database`). The
application's own unit tests (`crates/app/src/**`) cover pure logic: validation, address sets, paging cursors, retry rules, feed
assembly.

`support.rs` builds the world: the real services (`davhaven_app::build`) over the store of its copy, a `ManualClock`, `SeqIds`, a
`FaultyDatabase` that fails commits and begins (the retry rule), and a store wrapper that counts how often authorization facts
are loaded. Tenants, principals and calendars are provisioned *through the services* (`world.org`, `world.user`,
`world.calendar`), so a test starts from state the application created. The doubles are small and each stands in for one
port: an authenticator that knows the secrets the test teaches it, a rate limiter that counts, "unsupported" mail, templates
and HTTP, and a recording `ObjectScheduler` for the seam through which scheduling hooks into object writes.

| Module | What it checks |
| --- | --- |
| `tenants`, `principals` | create-or-replace, no-op writes, conditions, merge patches, deletion and purge, memberships and their events, search, DAV properties, address classification, scopes, paging, other tenants |
| `calendars` | homes and lazy bindings, binding slugs, managed calendars, MKCALENDAR, PROPPATCH (binding versus shared properties, atomicity, limits), deletion of bound collections, special collections, the management API's calendar resources |
| `objects` | verbatim bytes and strong ETags, the sync token moving once per mutation, the CalDAV preconditions of invalid data, UID conflicts with hrefs, Schedule-Tag, permissions, MOVE, COPY, multiget, queries and expansion, sync-collection and its refusals, lost transactions, the scheduler seam (inside the transaction, bytes it rewrites, merging, never for managed calendars) |
| `events` | the JSON interface: deterministic UIDs, no-op writes, merge into the stored component, recurring instances and "this and following", listing, search, the changes feed, MCP audit, and the **equivalence** of API and DAV (same content hash, same change log and events, same permissions) |
| `batch` | one transaction, one event, all or nothing, unchanged entries, `SEQUENCE`, replace scopes, delete guards, request rules, never scheduling, permissions |
| `sharing` | invitation, notification, accept, decline, re-invitation, auto-accept, per-item answers, removal, leaving a share, who may share, API grants and how the two meet in one grant, groups, deleting principals, notifications |
| `credentials` | secret formats and storage, scopes that can only shrink, MCP expiry, origins, revocation and generations, feed tokens, client configuration, the authenticator chain, the failure backoff |
| `feeds` | window, headers, `VTIMEZONE`s, conditional requests, busy mode, restricted events, access checked per request |
| `idempotency`, `audit` | replay, reuse, in-flight keys, secrets, leases and expiry; audit records that commit or vanish with their change, listings, actors, content-free details |
| `facts` | exactly one load of authorization facts per calendar and request, for DAV, API, batches, searches and home listings |
| `isolation` | everything of another tenant is unreachable by id, key and DAV path, and the attempts leave it untouched |
| `batch_reads` | the reads that load many things at once (the collections of a home, `expand-property`, the attendees of a write, whatever the kind of their addresses) cost a fixed number of queries whatever their number, counted from the port calls (`PortCalls`), and answer what the reads of one thing at a time answer |
| `stores` | the world of each copy talks to the adapter its copy names |

The store contract suite (`davhaven_port_tests::store`) checks the adapters themselves. The batch reads of the repositories have default bodies that any other
adapter inherits and that both adapters of this repository override, so `davhaven_port_tests::store::required_methods_only` wraps a
store in one that forwards the required methods only, and the memory store runs the batch cases (and the foreign-tenant reads) through
it: the defaults meet the contract the overrides do. The permission matrices, the credential matrix and the client flows run
the whole application on PostgreSQL through `TestApp` (a sample on pull requests, all of it with `CONFORMANCE_FULL=1`); this
binary runs every one of its tests on both.

## The permission matrix and `matrix/expectations.toml`

The permission matrix (PLAN 3.2) crosses `ActorRole` (17 values), `CalendarRole` (personal, group, managed, shared,
mirror), `Surface` (dav, api, mcp, feed, rsvp) and `Operation` (the 32 rows of the plan, and the read of a home and of a principal resource). The oracle is the
hand-written file `crates/testkit/matrix/expectations.toml`; the harness never imports `davhaven_domain::authz`
(a test of `matrix.rs` reads the source and fails if it does). When the server and the file disagree a person decides which is
wrong, and the file is the one reviewed against PLAN 2.6. The file is **settled** against the real application: the matrix runs
in process on the memory and PostgreSQL stores (`crates/it/tests/permissions.rs`; the cases of an operation that does not exist
on a surface are reported as not applicable) and reports every disagreement at once, grouped by the operation and by what differs.

What a case checks (`crates/testkit/src/permissions.rs`):

* the **status** of the answer in the vocabulary of the status policy (`classify.rs`), and for a refusal its details: the
  `WWW-Authenticate` challenge of the surface for a 401, `DAV:need-privileges` or the problem `forbidden` for a 403;
* the **state** before and after (`Observation`): a refused request changes nothing (no sequence number, object, grant,
  binding, notification, inbox item, outbox record, mail or event, and no tenant setting, principal, membership, credential, API token,
  webhook or audit record), and a request that is allowed to write does change something;
* the **body** of a refusal: it carries nothing of the event of the calendar the caller may not see, and a calendar that is hidden is
  answered like one that does not exist (same status and same kind of body as the request to a calendar that was never made);
* a case that is allowed to change something runs on a world of its own, the others share a few.

Requests are the ones the clients send (`permissions/dav.rs`, `api.rs`, `mcp.rs`, `web.rs`): a MOVE and a COPY with the
`Destination` of the target calendar (so both sides of the operation are decided), PROPPATCH of a per-binding property against
a shared one, `CS:share` and `CS:invite-reply`, free-busy through REPORT, the outbox and MCP, the objects of a calendar by key,
batch writes, the home and the principal resource of the calendar's owner, the scheduling inbox and the notifications with their
items, MKCOL, and the feed and RSVP pages. A write is also asked with a **stale precondition** (`If-Match`,
`If-Schedule-Tag-Match`, `If-None-Match: *` over DAV; `If-Match` on the API): somebody who may write is answered 412, and
somebody who may not is answered as the matrix says, so that an authorization that runs after the precondition is a failure.
Reads must **show** what they are asked for (the event, the calendar), and a user of another tenant who asks for free-busy is answered
without any busy time of the tenant's people.

The matrix runs complete on the memory store. A case costs hundreds of queries on **PostgreSQL**, and a world of its own (the
cases that change something need one each) costs seconds, so that run is a sample: one case in three, chosen so that every actor,
surface and operation is there with some calendar (with the variants that carry one scope), and of the cases that change
something the first of each operation on each surface; the administration matrix runs the first of each operation that changes
something in a world of its own. The report says how many cases the sample left out, and `CONFORMANCE_FULL=1` runs
everything (for a nightly run or before a release). The scheduling matrix over the calendar client surface (`scheduling_http.rs`,
45 cases, each in an application of its own) runs a representative subset on PostgreSQL in the same way
(`SchedulingCase::representative`: every kind of attendee, every change, every reply channel and every answer), and the
administration matrix names every case that its run lost (`AdminReport::missing`): a world that cannot be made is a failed
case, not a case that is missing. A world that cannot be made (a server that is busy drops a connection) is
made again twice before the run says so.
A case that is refused looks at the state **once**, around all its requests; a case that is allowed looks around each request,
because its stale probes change nothing and its last one does.

**A host that is too busy.** CI runs the PostgreSQL matrices on a host that other builds and test suites share. When it is
overloaded the store answers "timed out" or "unavailable", which the application maps to a transient 503, and a case whose own
request got that answer has not found out what it asks about. `davhaven_testkit::busy` sends such a request again, and only such a
request, and keeps the retry from hiding anything:

* **Only a busy answer.** A 503 (or a failed MCP tool whose problem is `unavailable`, which is how MCP says 503). Every other
  status is an answer and is judged as it is.
* **Only when nothing was lost.** A request that reads is sent again, and so is one that only replaces a resource by the same
  content (the preparation of a world). A request that changes something is sent again only when the state of the application
  (`Observation`) shows that it changed nothing, because a 503 does not say whether the transaction committed; a state that
  changed, or that cannot be looked at, keeps the answer and the case fails with it. The scheduling matrix and the client flows run
  every case on an application of their own, so a case that differed while its application had answered 503 is run again on a new
  one (the world of the failed attempt is thrown away with whatever the case did to it).
* **A few times.** Four attempts with pauses of half a second, one second and two seconds (`busy::Policy::STANDARD`). A 503 that
  persists is a failure of the case, with the status in the report.
* **Visibly.** Every result carries how often it was sent again (`CaseResult::repeats`, `AdminResult::repeats`,
  `SurfaceReport::reruns`), the reports list the cases that needed it, and a run in which more than one case in twenty (and more than
  three) needed it fails (`busy::excessive`): a server that is unavailable now and then, as opposed to a host that is, is a
  regression and must not hide behind the retry.

The harness also keeps itself from making the host look busier than it is: the database of a world is dropped when the world is,
and `DROP DATABASE` takes up to a minute on a cluster that other processes keep busy. The cases of a matrix are futures of one task,
so a drop that waited on that thread would keep every other world of the run from being polled for as long, a transaction of
one of them would sit idle past `idle_in_transaction_timeout` and the pool of another would run out of `acquire_timeout`, and
the application would answer 503 to a request that nothing was wrong with. `ClonedDatabase` therefore drops the database on the
blocking pool of the runtime (which the runtime waits for when it ends, so a finished test has cleaned up) and waits for it on the
spot only where there is no runtime.

The MCP column runs for real, in process: the endpoint is part of the application (a route group that is not mounted answers 404,
and that is the failure of every MCP case, not a skip). The service principals that are **granted** calendars (`assistant`: the group
calendar for reading and writing and the managed one for reading, `importer`: the managed one for reading and writing) are two roles
of the matrix on the API and MCP; on DAV they are refused (no app password), and what a grant of `read` and of `read_write` gives them
is what it gives anybody, so that the managed calendar, which DAV caps at read, is written by the API and MCP for a grant of
`read_write` and refused for a grant of `read`. A failed tool result is read only from `_meta["davhaven/problem"]` (ADR-0014);
a failure that carries `structuredContent` is a finding. The tokens that carry one scope are part of the matrix: tenant tokens on the
API, and the owner's principal tokens (one per scope) on the API and on MCP; the run fails when a scope row of the file is reached by
no case. What is left out is **pinned**, and a skip or a "not applicable" with another reason fails the test:
the allowed answer to an invitation over MCP (the fixture world has no invitation for somebody who may write; `mcp::NO_INVITATION`),
and the two DAV deletes that are another operation's request (`DELETE` of a bound collection is `remove_binding` for a sharee and
`delete_calendar` for the owner).

A refusal is also checked for what it **leaks**: the summary of the event, `BEGIN:VEVENT`, for another tenant the start of the event
(and, where free-busy is asked for, any `FREEBUSY` property or busy period), for a refused home or principal resource the calendars of the home and the name and address of the principal. A hidden
calendar or home is compared with a missing one (**same status and same kind of answer**: the problem code, title and detail,
the elements of a `DAV:error`, with the names the requests repeat replaced), and so is an object that is refused to somebody who
may not read it. For somebody who may read the objects of the calendar a refusal may name the privilege it lacks (`write-content`
for a resource that exists, `bind` for one that is made), which says nothing they could not see. A stale `If-Match` that is no tag of
the API is refused with 412 by the edge before anybody is asked who the caller is (documented in `crates/api/src/extract.rs`), so the
probes of the API carry a well-formed tag that nothing has.

The harness is tested against servers that are wrong on purpose (`crates/it/tests/matrix_detectors.rs`): a refusal that changes the
state, a 403 that is a 201, a 403 on DAV without the `DAV:need-privileges` document, an answer that repeats the event, a hidden
calendar that is answered differently from a missing one, busy time of another tenant over DAV and MCP, an administration request
that mints a token although it was refused, and a pending operation whose service has arrived. Each runs against the scripted
server that does the one thing wrong, which must fail with the problem of that detector, and against the one that does it right,
which must pass.

Three more tables complete the matrix:

| What | Where | Cases |
| --- | --- | --- |
| **Administration operations** of the API (tenants, principals and members, the bindings of a home, app passwords, feed tokens, API tokens, client configuration, webhooks, providers, the audit log, the outbox, inbound iTIP, the search for calendars; 47 operations) | `permissions/admin.rs`, `crates/it/tests/admin_matrix.rs` | every operation x every actor, for tenant tokens every scope a tenant token can carry, and for the administrator of another tenant also the ids of the main tenant (a webhook, a token, an outbox item): the token with exactly the scope of the operation is allowed, tokens with any other scope are refused, and what belongs to another tenant answers like what does not exist. **The oracle is the file**: `[[admin_actor]]` gives the rule of every actor (unauthenticated, refused, other tenant, by scope), `[[token_scopes]]` the scopes each kind of token can carry and `[[admin]]` the scopes of each operation, so a wrong row fails the matrix (`a_wrong_scope_in_the_oracle_is_caught_case_by_case`). The tenant, the principals (also the deleted ones), their memberships and credentials, the API tokens, the webhooks with their deliveries and the audit log are observed around every refused or mutating request. The inbound iTIP endpoint is switched on in process, so that its allowed answer is the one of an endpoint that takes a message; where the environment cannot tell (a deployed instance) both 200 and 409 are accepted |
| **Credentials**: every kind (app password, principal token, tenant token, system token, feed token, RSVP token) on every surface in every state (valid, wrong secret, unknown prefix, malformed, revoked, expired, principal suspended, tenant suspended, cross login, deleted principal, not a bearer credential) | `crates/it/tests/credentials_matrix.rs` | the oracle is the file again: `[[credential_surface]]` says which credentials each surface takes and `[[credential_state]]` what every state answers (a state that does not exist for a kind is listed with the reason); credentials are issued and revoked through the management API and DAV, expiry is the manual clock, and the revoked, expired, suspended and deleted ones are used once **before** they are taken away, so that a cache that outlives the revocation is a failure. An unknown prefix is a well-formed credential of a kind that does not exist |
| **Coverage**: every route, method and tool of the server maps to an operation of the matrix | `coverage.rs` | the OpenAPI document (`davhaven_api::document`), the methods of every kind of DAV resource (`davhaven_dav::methods::allowed_methods`), the tools of `davhaven_wire::mcp::TOOLS` and the web routes are compared with the tables of the module and with the oracle: a route nobody listed, a stale row, an operation of the oracle that no way into the server performs, and a scope that the server documents differently from the oracle are test failures (`cargo nextest run -p davhaven-testkit`, `davhaven-conformance check`). The check is **probe-driven** too: every planner is run for every case and the routes its probes really send are compared with the table, so a planner that no longer sends a request fails (`every_route_and_tool_of_the_server_is_sent_by_some_probe`). The web routes are compared one way only, from the tables to the server's routes that the harness lists (`davhaven-web` exports no route table) |

An operation of the management API whose service is not offered yet (none today: every operation is judged by the rules of
the file) is a `[[pending]]` row of the file and is **run**, not skipped: the cases that would be allowed or forbidden must be answered 501 (the cases that are refused at the door,
without credentials or from another tenant, are judged normally), a request that changes the state is a failure, and an answer other
than 501 is the failure "stale pending row", which says to remove the row and judge the operation by its real answers.

`docs/permission-matrix.md` renders the file: the status policy, the actors, the calendars, the operations with their scopes,
the effective access of every actor on every calendar, the expected answer of every operation for every actor on every surface
and calendar (`A` allowed, `U` unauthenticated, `H` hidden, `F` forbidden, `P` precondition failed; `*` marks a case that an
exception row decides), the administration operations, the exception rows, the known deviations and a summary. `cargo xtask
matrix` writes it (through `davhaven-conformance matrix-report`), `cargo xtask matrix --check` (the `contracts` job of CI) and
`crates/it/tests/matrix_report.rs` fail when the committed copy differs from what the file renders.

Format (`Expectations::parse` rejects unknown keys, duplicate and missing rows):

```toml
schema_version = 1

[status.forbidden]              # the status policy: one table per expectation
http = "403"                    # "NNN" or "Nxx"
dav_precondition = "DAV:need-privileges"
problem_code = "forbidden"

[[access]]                      # default rule: effective access of an actor on a calendar (absent = none)
actor = "sharee_read"           # a name, a list of names, or "*"; a missing selector means "*"
calendar = "shared"
level = "read"                  # none < free_busy < read < read_write < admin < owner

[[cap]]                         # default rule: managed and mirror calendars are read-only for principals
actor = ["owner", "group_member"]
calendar = "mirror"
surface = ["dav", "api", "mcp"]
max = "read"

[[needs]]                       # default rule: what each operation needs (every operation exactly once)
operation = ["create_object", "update_object"]
level = "read_write"
target = "calendar"             # or "home" for inbox, outbox, notifications and calendar creation

[[available]]                   # default rule: the operations that exist on each surface (every surface once)
surface = "feed"
operations = ["read_feed"]

[[scope]]                       # default rule: the token scope an operation needs on API and MCP
surface = "api"
operation = "read_object"
scope = "events:read"

[[exception]]                   # explicit rows, first match wins over every default rule
actor = "system_token"
expect = "hidden"               # allow | unauthenticated | hidden | forbidden | precondition_failed
waive_details = "why the precondition element or challenge is not checked for these cases"   # optional

[[known_issue]]                 # a deviation of the server that is tracked: the matrix runs the case against `observed`
operation = "update_object"     # and fails when the server stops deviating, so a fixed deviation does not stay listed
observed = "forbidden"
reason = "where it is tracked"

[[admin]]                       # the scopes of administration operations of the API, by operationId (a token needs one)
operation = ["listWebhooks", "createWebhook"]
scopes = ["webhooks:manage"]

[[admin_actor]]                 # the rule of every actor on the administration operations
actor = ["owner", "group_member"]
rule = "refused"                # unauthenticated | refused | other_tenant | by_scope

[[token_scopes]]                # the scopes each kind of token can carry (tenant, system, principal)
kind = "tenant"
scopes = ["events:read", "webhooks:manage"]

[[pending]]                     # operations whose service is not offered yet: it answers 501 meanwhile
operation = ["listProviders", "listExternalAccounts"]
observed = "not_implemented"
reason = "the provider service is not offered yet"

[[credential_surface]]          # the credential kinds each surface accepts (any other kind is refused there)
surface = "dav"
accepts = ["app_password"]

[[credential_state]]            # what a credential of a kind in a state answers: accepted, refused or n/a (with a note)
state = ["wrong_secret", "unknown_prefix", "malformed"]
kind = "*"
result = "refused"
```

Resolution (`Expectations::resolve` explains every answer): the first matching exception row; an operation that does
not exist on the surface is hidden; a tenant token that carries one scope lacks the operation's scope: forbidden; no
effective access: hidden; access below what the operation needs: forbidden; otherwise allowed. Status policy: no
credentials, a suspended principal or a credential on the wrong surface answer 401; no read visibility, including
other tenants, answers 404; visible but not permitted answers 403 with `DAV:need-privileges` (DAV) or the problem
`forbidden` (API, MCP); a stale precondition answers 412.

## Server-side scheduling: `crates/it/tests/scheduling`

One test binary on the real application (`davhaven_app::build`) over the in-memory store, the real template renderer
and the capturing mail transport, with `ManualClock` and `SeqIds`. `support.rs` is the world: tenants, principals and
calendars are provisioned through the services, the contexts of every surface (`dav`, `api`, `mcp`, `rsvp`,
`gateway`) are built by hand, and `run_outbox()` runs the dispatcher with the handlers of the application, so queued
deliveries are made and mail is composed and captured.

| File | What it covers |
| --- | --- |
| `internal.rs` | organizer and attendee inside one tenant over DAV: delivery, answers, significant and silent changes, removal, deletion, the rules of who may change what, merges by `Schedule-Tag`, answers to one instance |
| `external.rs` | iMIP mail, RSVP links (page, answers, a form that cannot be used shown again with a notice, expiry, revocation), external policy, other tenants and groups, answers to an organizer outside the tenant |
| `limits.rs` | the limits on mail to people outside (per event, per organizer and hour, per tenant and day): they never refuse a write, the status says who was not mailed, cancellations are exempt, failed writes use up nothing, answers by mail are limited and need `mcp:schedule_external` over MCP |
| `integrity.rs` | what a writer who is not the organizer cannot do: reuse the `UID` of somebody's event or booking to overwrite or delete it (DAV, a cancellation, a deletion, the queued handler), turn an event into a colleague's meeting, change or delete a meeting in a group calendar, lean on a stale `If-Match`, or use what two requests with the same `X-Request-Id` share; the delegate who answers for the owner; the organizer's copy when two calendars hold it |
| `copies.rs` | what the organizer's next version does to the attendees' copies: their alarms and `TRANSP` survive, a cancelled series reaches the attendees removed in the same write, a repeated answer with a new remark reaches the organizer |
| `shared_busy.rs` | free-busy of meetings in the calendars of groups and in shared calendars, with and without a binding in the home of the invited person |
| `tenants.rs` | the scheduling operations (`respond`, the outbox, the inbound endpoint, the RSVP page and answer) across tenants: 404 and no effect |
| `surfaces.rs`, `calendars.rs` | writes through the API and MCP (only when asked, the MCP scope, a tenant token that asks is refused), `respond` (who may answer: 403 for everybody else who sees the event), a colleague with write access (`SENT-BY`), group calendars and duplicate suppression by effective access |
| `resources.rs`, `policy.rs` | rooms answer by free-busy, the manual policy, the contract suite of the port for both policies |
| `queue.rs` | delivery above the synchronous cap (the handler is part of every dispatcher), handling a record twice, suspended and removed recipients |
| `inbound.rs` | the inbound endpoint: switches, scope, every quarantine reason, deduplication (also of messages that have nothing to keep), the per-sender and per-gateway limits and a limiter that does not answer, requests and cancellations from outside (without the sender's alarms, past the content scanners, never over somebody else's event), one quarantined copy per message |
| `freebusy.rs` | free-busy, the outbox `POST`, free slots, the scheduling inbox |
| `unscheduled.rs` | what is never scheduled and what an attendee may change on their copy |
| `table.rs`, `matrix.rs` | the scheduling matrix |

## The scheduling matrix

`SchedulingCase::matrix()` takes the full product of organizer surface (dav, api, mcp), attendee kind (internal,
other tenant, group address, resource, external) and change (create, significant, insignificant, add and remove
attendee, cancel instance, cancel series, delete, move) and assigns each cell one combination of reply channel (dav,
rsvp, inbound) and answer (accept, decline, tentative) so that every pair of values of two dimensions occurs at least
once. `SchedulingExpectation` is what a case asserts (inbox items, attendee copies, mails and their `METHOD`, the
organizer's `PARTSTAT`, `SCHEDULE-STATUS`, domain events). The decision table is `crates/it/tests/scheduling/table.rs`
(`expected(case)`): PLAN 2.8 in executable form, written from the rules of the plan and the golden files, knowing
nothing of the application. The driver `crates/it/tests/scheduling/matrix.rs` performs every cell on the real
application (one test per organizer surface, 45 cells each, all differences reported at once): the organizer writes
through the surface, the attendee answers through the channel of the cell if the channel offers them a way to (a copy
to edit, a link to open, a mailbox to write from), and what can be seen is compared with the table: messages in the
inbox, copies, mails and their `METHOD`, the `SCHEDULE-STATUS` and `PARTSTAT` in the organizer's copy and the
scheduling events. The expectation carries the `METHOD` of every message instead of a count, and the events are
compared sorted, because the order inside one transaction is not part of the contract. The table lives in
`davhaven_testkit::scheduling::table`, where the driver over HTTP uses it too. The organizer-side expectations of the change dimension come from the
iTIP golden files in `crates/fixtures/data/itip` (one directory per scenario: the stored copy, the client's version,
the classification, the copy to store and every message that results); see [`ical.md`](ical.md).

### The scheduling matrix over HTTP

`crates/it/tests/scheduling_http.rs` runs the same 45 cells per organizer surface through the surfaces people use, on `TestApp`
(`davhaven_testkit::scheduling::driver`): the organizer writes with a calendar client (`PUT`), through the management API (JSON with
`notify_attendees`) or with an MCP tool, the outbox is delivered, the attendee answers through the channel of the cell (they change
`PARTSTAT` of their copy in a calendar client, open the RSVP link of the invitation mail and press a button, or a mail gateway posts
their reply to the inbound endpoint), and everything that can be seen is compared with the decision table: the messages in the
scheduling inbox, the attendees' copies, the mails and their `METHOD`, the delivery state and the answer in the organizer's copy and
the scheduling events. The driver never looks at what the application decided: what the attendee attempts follows from what exists
(a copy to edit, a link in a mail, a mailbox to write from), and the expectation comes from the table alone. It needs the mail
transport, the event sink and the store of the application, so it is an in-process matrix. All 45 cells of each of the three
surfaces run (the MCP one too: a surface that cannot be driven is a failure of the run, there is no skipped cell).

## Client-flow scenarios

A scenario is a YAML file; `Scenario::from_yaml` validates it and `run_scenario(&env, &scenario)` runs it through any
transport. Steps run in order; after the first failing step the rest is skipped.

```yaml
schema_version: 1                 # must be 1
name: store-and-read-back         # unique
description: A client stores an event and reads it back.
client: python-caldav             # the client of the client-by-feature grid
feature: crud                     # the feature of the grid
origin: synthetic                 # synthetic | captured
provenance: written from RFC 4791 section 5.3.2     # where it comes from (script, test, capture date)
known_issue: why the server fails this scenario today   # optional: see below
actors:                           # logical actor -> role of the fixture world
  olivia: owner
variables:                        # for templates; may use the variables of the environment
  home: /dav/calendars/{{tenant}}/olivia/personal
steps:
  - name: store
    as: olivia                    # omitted: anonymous
    surface: dav                  # dav (default) | api | mcp | feed | rsvp; selects the credential
    request:
      method: PUT
      path: "{{home}}/new.ics"    # {{name}}: environment, scenario variables, then captures
      headers: { If-None-Match: "*", Content-Type: text/calendar }
      body: "BEGIN:VCALENDAR\r\n..."   # or ical: | (plain line breaks, sent as CRLF), or body_file: dav/macos-propfind-home.xml
    capture:
      etag: { header: ETag }      # exactly one source: header | xpath | json (a JSON pointer)
    expect:
      status: [201, 204]          # 207 | [200, 204] | "2xx"
      headers:
        etag: {}                  # present; or a value; or { present: false } / { equals: .. } / { contains: .. } / { not_equals: .. }
  - name: read back
    as: olivia
    request: { method: GET, path: "{{home}}/new.ics" }
    expect:
      status: 200
      headers: { etag: "{{etag}}" }
      body_contains: ["BEGIN:VCALENDAR"]
      body_excludes: ["SECRET"]
      ical_contains: ["SUMMARY:Standup"]                 # after the folding of iCalendar lines is undone; ical_excludes too
      statuses: { "/some/href/": 200 }               # status of an href in a multistatus
      properties:                                     # properties of a multistatus response
        - { href: "/some/href/", name: "{DAV:}getetag", value: "{{etag}}" }
      xpath:                                          # paths on the XML body
        - { path: "/{DAV:}multistatus/{DAV:}response", count: 2 }
      json:                                           # JSON pointers on the body
        - { pointer: /items/0/id, equals: abc }
```

Paths use a small subset of XPath 1.0 with names in Clark notation (`{DAV:}href`, no prefix declarations; a namespace
may contain `/`): `/` and `//` steps, `*`, `[n]`, `[@attr='v']`, `[{DAV:}child='text']`, and a final `text()` or `@attr`.
`ScenarioEnv` carries the transport, the credentials of every role per surface and the base variables
(`TestApp::scenario_env()` and `Deployment::scenario_env()` provide `tenant`, `login_domain`, `other_tenant`,
`other_login_domain` and `base_url`; `body_file`s are read below the `testdata` directory).

**The scenarios of the repository** are `crates/it/tests/scenarios/{client}/{feature}.yaml` and run on a world of their own each,
on the memory and PostgreSQL stores (`crates/it/tests/flows.rs`). The memory store runs all of them; a world costs seconds on
PostgreSQL, so pull requests run a **representative set** there (`flow::representative`: greedily the scenarios that add the
most clients and features that nothing chosen has yet, so every client and every feature is in it, and the same ones are chosen
whatever the order of the files), and `CONFORMANCE_FULL=1` runs all of them. The test prints the chosen files.
The clients are those of PLAN G1 (`apple-calendar` for macOS,
`ios-calendar`, `davx5`, `thunderbird`, `evolution`, `caldav-synchronizer`) and the public suites Davhaven is held against
(`python-caldav`, the functional tests of the python `caldav` library, and `ccs-caldavtester`, the CalendarServer test suite,
whose Apache-2.0 notice is kept next to its scenarios). The features are the columns of the client-by-feature grid of PLAN 3.4:
account setup, CRUD, recurring override, invite internal and external, accept, share, sync after token expiry and a read-only
edit attempt. The test `scenario_names_are_unique_and_every_cell_of_the_grid_has_a_scenario` fails when a cell has no
scenario (the cells a client does not have, such as sharing for DAVx5, are listed in the test with the reason). Scenarios are
**`synthetic`**: written from the requests the client is documented or reported to send (the request bodies are the byte-exact
files of `testdata/dav`, the object bodies of `testdata/corpus`), with the script or test they follow named in the provenance.
`davhaven-conformance check` prints the grid and marks the cells that only have synthetic scenarios: those are the ones no real
client has confirmed. A real client replaces a synthetic scenario through the capture converter below.

**`known_issue`** says that the server fails the scenario today and why. The scenario still states what the client needs; a run of
it passes when it fails and **fails when it passes**, so a deviation that was fixed does not stay listed (`flow::verdict`).
No scenario carries one at present.

## The capture converter

With `observability.dav_capture` a server records the DAV exchanges of the tenants in its allowlist (credentials redacted, see
`davhaven_server::capture`). Point a real client at a staging instance that holds the world of a run, do one thing with it, and
convert the directory:

```sh
davhaven-conformance convert /var/lib/davhaven/capture --name apple-calendar-crud-captured \
    --client apple-calendar --feature crud --provenance "Calendar on macOS 15.1, staging run r42" \
    --login-domain r42-a.example --out crates/it/tests/scenarios/apple-calendar/crud-captured.yaml
```

`davhaven_testkit::convert` turns the files into a scenario marked `captured`: the tenant slug and the login domain become
variables, the entity tags, schedule tags, locations and sync tokens that an answer carries and a later request repeats become
captures, only the headers that mean something to a server are kept, the answers become structural assertions (status, the
entity tags present, the status of each resource of a multistatus, the identifying lines of calendar data), and the free text of
calendar data is replaced by neutral text unless `--keep-text` is given. The scrubber unfolds the lines of the calendar data first,
reads quoted parameter values, matches parameter names without regard to case and replaces the summary, description, location,
comment, contact, URL, attachments, geographic positions and `X-APPLE-STRUCTURED-LOCATION`, the names and addresses of people
(also those outside the login domain) and, in the XML of requests and answers, display names, calendar descriptions and
common names; the schema version of a capture is the one the server writes, so a capture of another version is refused. An
existing output file is never overwritten. A converted scenario replaces the synthetic one of its cell of the grid once a person
has read it; `crates/it/tests/capture_loop.rs` proves the loop end to end (a server records a client, the files are converted, and
the scenario passes in process and over a socket).


## `davhaven-conformance` and the staging run

```sh
davhaven-conformance check [--scenarios DIR] [--expectations FILE]     # validate files and coverage, print the grid; no network
davhaven-conformance matrix-report                                      # print docs/permission-matrix.md
davhaven-conformance run --base-url URL --run-id r42 \
    --tenant-token-file a.token --other-tenant-token-file b.token [--system-token-file s.token] \
    [--principal-token-command COMMAND] \
    [--no-matrix] [--no-flows] [--expectations FILE] \
    [--data-dir DIR] [--scenarios DIR] [--insecure-http] [--reset-between-writes] [--keep]
davhaven-conformance convert CAPTURE_DIR --name N --client C --feature F --provenance P \
    [--login-domain DOMAIN] [--actor ROLE] [--description TEXT] [--keep-text] [--out FILE]
```

The exit status is 0 when everything passed, 1 when a case or a scenario failed and 2 when the runner itself could not run (bad
arguments, unreadable files, an instance that cannot be prepared).

**`run` is the staging run** (PLAN 3.1 L7): the same fixture world, requests and oracle as the in-process tests, against an
instance that is reached over HTTP only, on an ephemeral pair of tenants of the run's own. The operator prepares two tenants and
hands over their administration tokens, because the management API cannot mint the first administration token of a tenant:

```sh
davhaven admin bootstrap --tenant r42-a --login-domain r42-a.example --mcp-enabled --print-token > a.token
davhaven admin bootstrap --tenant r42-b --login-domain r42-b.example --mcp-enabled --print-token > b.token
davhaven admin system-token create --label conformance --token-file s.token     # optional
```

With a system token the runner aligns the tenants (the login domain, the sender domain) and deletes both at the end; without one it
only checks them and leaves them in place (`--keep` also leaves them with a system token). Tokens can come from the environment
instead of files (`CONFORMANCE_TENANT_TOKEN`, `CONFORMANCE_OTHER_TENANT_TOKEN`, `CONFORMANCE_SYSTEM_TOKEN`), and the instance from
`CONFORMANCE_BASE_URL`. Nothing prints a token, and no report, error or captured answer shows one: whatever of an answer reaches
a message goes through `davhaven_testkit::redact`, which replaces the secrets of the formats the server issues (`dvh_pat_`,
`dvh_feed_`, `dvh_rsvp_`, `whsec_`, app passwords) and the secret fields of JSON bodies. The tokens travel in every request, so the
runner refuses an instance that is neither reached over https nor on this machine unless `--insecure-http` says so, and it refuses
a request target that could leave the instance (`//host`, a backslash) and an answer that is larger than the cap of the transport.
`--data-dir` names the directory the `body_file`s of the scenarios are read from (the default is `testdata` of the checkout the
binary was built from), `--scenarios` the scenario files; a binary that runs elsewhere needs both, or `--no-flows`.

**`--principal-token-command`** (or `CONFORMANCE_PRINCIPAL_TOKEN_COMMAND`) is how the MCP column gets the tokens of users. It is a
shell command that prints the secret of a new principal token on its standard output and nothing else, which is what
`davhaven admin principal-token create ... --print-token` does on the host of the instance. The run builds its principals itself,
so it runs the command once for each token it needs, after the principal exists, with the placeholders `{tenant}`, `{principal}`,
`{label}`, `{scopes}` (as `--scope mcp:read --scope mcp:write ...`) and `{expires_in}` (`1d`: the tokens are for the minutes
of the run, and a run that leaves its tenants in place leaves nothing that works for a month) filled in. A command that lacks one of
the placeholders is a usage error at startup, because without `{scopes}` the tokens would carry the scopes the operator wrote and the
one-scope tokens of the matrix would be none, and without `{label}` the second token of a principal would find the label of the
first taken and print nothing:

```sh
davhaven-conformance run --base-url https://calendar.example --run-id r42 --tenant-token-file a.token \
    --other-tenant-token-file b.token --system-token-file s.token \
    --principal-token-command 'ssh staging docker exec davhaven davhaven admin principal-token create \
        --tenant {tenant} --principal {principal} --label {label} {scopes} --expires-in {expires_in} --print-token'
```

Every value that goes into the command is a slug, a label of the run or the name of a scope, and one that does not start with a
letter or a digit (it would be an option of the command) or has a character outside letters, digits and `-_.:` is refused, so
nothing of a world or an instance can become shell syntax. The command's standard output is the secret and is never shown, not even
when it is not what a token looks like (the error says what is wrong with it); its standard error, the report of the command,
reaches the terminal. The command runs without a terminal in a process group of its own, so it cannot ask for a passphrase (use a
key in an agent, `ssh -o BatchMode=yes`). A command that fails, that prints nothing (for example because a token with the label
exists already and its secret cannot be shown again) or that takes more than two minutes stops the run before any case is asked, and
what the run had built is taken down again; at two minutes the whole process group is killed, `ssh` included, so that nothing the
command started goes on to make a token after the run has deleted its world. A world that is built again
(`--reset-between-writes`) asks for its tokens again, because deleting a principal revokes its tokens: with the command that is an
`ssh` and a `docker exec` for every user token of the world (about ten principals and the three tokens of one scope of the owner),
which adds some tens of seconds to every case that is run on a world of its own, so a run with `--reset-between-writes` and the
command is the slow one of the options.

What `run` does (`davhaven_testkit::staging`):

1. **Provisions** the world through the management API and DAV, the way a provisioning system and calendar clients do:
   principals, memberships, calendars, events (a batch per calendar, written by the owner), accepted grants through the API, the
   invitations that are still pending or were declined through the CalendarServer sharing flow (the API only makes accepted
   grants), the bindings every client creates by listing its home, app passwords, principal tokens and tenant tokens of every
   scope, and the suspension of the suspended user. The credentials the instance issued are collected into a `CredentialBook`.
      The owner also gets a token per scope (a principal token that carries exactly one scope) for the matrix of scopes. A deployed
   world has no mirror calendars (a sync engine makes those, so their cases are left out). **Tokens that open MCP** (`mcp:read`,
   `mcp:write`, `mcp:schedule_external`) come in two ways, because a token only mints tokens with a subset of its own scopes and no
   tenant token carries the scopes of MCP: the administration token of the tenant issues them to **service principals** (the one
   exception, ADR-0015), so the three service principals of the world have theirs without an operator; a **user** gets one only
   from `davhaven admin principal-token create`, which runs on the host of the instance, and the principals do not exist before
   the run builds them. The run therefore asks the command of the operator for each token once the principal is made
   (`--principal-token-command`, below), the whole principal token of a user and, for the owner, the three tokens of one MCP scope
   each. Both ways need a tenant that has MCP switched on (`admin bootstrap --mcp-enabled`; with a system token the run switches it
   on itself); the run stops when it has the command and a tenant has MCP switched off, and says how to create the tenant. Without
   the command the MCP cases of the users are reported as skipped with the reason
   `mcp::NO_MCP_CREDENTIALS` (the cases that the credential alone decides still run), and a tenant without MCP gives nobody a
   token that opens it. The runner says so when the administration token of a tenant is too weak.
   **Before it writes anything** the runner checks that the two tenants are the ones it was made for: each token reads its tenant
   (a token of another tenant, or a tenant that is not there, stops the run), the login domain is the one of the run, and the tenant
   holds no principal that a run did not make (a wrong `--run-id` that names a real tenant stops here, even with a system token,
   which could replace the settings of a tenant). Everything a run makes carries the label `conformance` (the principals of the
   harness are `conformance-*`, tokens and webhooks are labelled), so that a reset deletes only that. If the provisioning dies half
   way, what was built is taken down again and the tenants are deleted unless `--keep` is given.

2. **Runs the permission matrix and the administration matrix** with `Deployment` as the environment. What it can observe over HTTP
   is what the management API shows: the calendars with their sync tokens (every change of an object, a property, a share or a
   binding moves the token of its calendar), the principals with their versions and the outbox, the tenant, the members of
   the groups, the app passwords, feed tokens and API tokens, the webhooks and the audit log (without the records that a refused
   request may add: failures and tripped limits). A refusal that changed something
   is still caught; a mail that was sent or an event that was delivered is not seen (staging redirects mail anyway). Observing
   costs requests, so it happens around the requests that can change something.
3. **Resets between cases that change something, if asked.** A case that is allowed to write needs a world of its own; a deployed
   instance has one world, which a reset replaces (the principals of the fixture world and of the harness are deleted with their
   calendars, the tokens and webhooks of the harness are revoked and deleted, a principal that no run made makes the reset refuse,
   and the world is provisioned again with new secrets, several hundred requests). By default the cases that must change nothing run, which is what a deployment can
   get wrong that the in-process run cannot see (proxy and TLS behaviour, headers, the real database roles and row-level
   security), and the others are reported as skipped; `--reset-between-writes` runs them all.
4. **Runs the client flows**, each on a world of its own (the world is built again before every scenario that follows a run
   that changed it), and judges them like the in-process run does (`known_issue`).
5. **Deletes the tenants** (with a system token), also when a step failed.

`crates/it/tests/staging.rs` runs all of this against an application that listens on a socket: the tenants are made with the same
functions the commands above call, and the matrices and flows run over HTTP.

`check` validates the expectations file (every row is reached, none is shadowed), the scenario files (valid, unique names) and the
coverage of the matrix, and prints the grid. `matrix-report` is what `cargo xtask matrix` runs.
