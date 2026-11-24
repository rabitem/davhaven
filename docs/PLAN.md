# Davhaven design reference

Davhaven is a multi-tenant CalDAV and scheduling server written in Rust. It is generic: nothing in this
repository refers to a specific organisation. Deployments supply tenants, branding, templates and adapter
choices through configuration and the management API.

This document is the design reference: goals, architecture, the consistency and security rules, the interface
contracts between crates, and the quality strategy. Sections 1 to 3 describe what the server does and why.
Section 4 lists the interface contracts (numbered F0.1 to F0.11; code comments cite these numbers), the
acceptance criteria per area and the rules for changing a contract. Section 5 records design decisions that depart
from the obvious choice. Rules for all code are in [`ENGINEERING_RULES.md`](ENGINEERING_RULES.md); decisions with
a long rationale are ADRs in [`adr/`](adr/README.md). The configuration reference, the permission matrix and the API
contracts are generated: [`configuration.md`](configuration.md), [`permission-matrix.md`](permission-matrix.md),
[`openapi.json`](openapi.json) and [`contracts/`](contracts/).

## 1. Goals

| # | Goal |
| --- | --- |
| G1 | Standards-compliant CalDAV server for Apple Calendar (macOS, iOS), DAVx⁵, Thunderbird, Evolution and Outlook with CalDav Synchronizer. |
| G2 | Multi-tenant: tenants, users, groups, resources, service principals; isolation enforced by the database schema, not only by code. |
| G3 | Calendar kinds: personal (one default per user), group (owned by a group), managed (read-only for users, written through the API), user-created. |
| G4 | Sharing from client apps (CalendarServer sharing as used by Apple Calendar) and through the API. |
| G5 | Scheduling (RFC 6638 server-side): internal attendees receive invitations in their calendars; external attendees receive iMIP mails from themeable templates and answer through an RSVP page. Cancellations and replies flow back. |
| G6 | Per-device app passwords, scoped API tokens, feed tokens; all revocable. |
| G7 | Subscription feeds (iCalendar over HTTPS), full or busy-only. |
| G8 | Management REST API (OpenAPI 3.1) for provisioning, managed calendars and integrations. |
| G9 | MCP server so AI assistants can read and write calendars with principal-bound, scoped tokens. |
| G10 | Plugin/adapter architecture for every internal and external integration (storage, auth, mail, templates, HTTP egress, providers, webhooks, scanning, rate limiting, scheduling policy). |
| G11 | Production quality: observability, hardening, CI/CD, documentation, port contract suites, client-flow conformance, cartesian permission and scheduling matrices. |

Non-goals for 1.0: CardDAV, an inbound SMTP server (the inbound iTIP HTTP endpoint covers mail gateways), a web
calendar UI, WebDAV LOCK (class 2), RFC 3744 ACL writes.

### 1.1 Scope of 1.0 and backlog

The "1.0" column is the scope of the first release. Everything else is listed in [`ROADMAP.md`](ROADMAP.md) with the
reason it is not in 1.0.

| Area | 1.0 | Backlog (documented) |
| --- | --- | --- |
| CalDAV | Core, sync-collection, scheduling, CS sharing, notifications, principal search, extended MKCOL, VEVENT/VTODO/VJOURNAL storage | Managed attachments (RFC 8607), per-user alarm overlay (ADR-0004), LOCK |
| Scheduling | Internal delivery, iMIP REQUEST/CANCEL/REPLY, RSVP page, inbound iTIP (off by default), resource auto-accept, free-busy | Group-address expansion (CUTYPE=GROUP gets SCHEDULE-STATUS 3.7) |
| Providers | Google and Microsoft: OAuth (PKCE) + pull-only import into a mirror calendar, behind cargo features, disabled in config; `provider-fake` | Push direction (outbox kind `provider_push` reserved) |
| Auth | App passwords, API tokens, feed tokens, RSVP tokens | Token introspection authenticator (the `Authenticator` chain accepts it later), on-behalf-of delegation |
| Scanning | `ContentScanner` port (set, empty by default) applied to inline binary ATTACH | ClamAV adapter (needs managed attachments to be useful) |
| Rate limiting | `ratelimit-memory` (single instance) | Shared limiter (`ratelimit-postgres`) for multi-instance deployments |

1.0 runs as a single instance per database unless a shared rate limiter is configured; the outbox and workers
are already multi-instance safe.

## 2. Architecture

Hexagonal. Dependencies point inwards only.

```
  binary:     davhaven-server (config, registry wiring, listeners, workers, CLI)
  protocols:  dav   api   web   mcp        ── all via davhaven-http (edge layers) ──┐
  app:        davhaven-app (service traits + use cases, authz loading, scheduling,   │
              outbox dispatcher, sync engine)  ◄─────────────────────────────────────┘
  core:       davhaven-domain (pure)   davhaven-ical (pure)   davhaven-wire (DTOs)
  ports:      davhaven-ports (traits, registry, port errors) ── depends on domain only
  adapters:   store-postgres store-memory mail-smtp mail-memory mime templates auth-local
              crypto-local http-egress hooks-webhook ratelimit-memory scanner-eicar provider-{google,microsoft,fake}
  tests:      fixtures port-tests app-fake testkit it conformance   xtask
```

### 2.1 Crates

All crates are named `davhaven-<name>`, live in `crates/<name>/`, edition 2024, and inherit lints and dependency
versions from the workspace.

| Crate | Responsibility | May depend on (workspace crates) |
| --- | --- | --- |
| `domain` | Ids, natural keys, entities, `RequestContext`, `Actor`, scopes, authz (`decide`, `privileges`), `ErrorKind`, `Precondition`, `ResourcePath`, `PublicUrls`, `SyncToken`, `TenantSettings`, `ObjectIndex`, `EventData`, mail model, domain/audit event catalogs, limit structs. No I/O, no async. | – |
| `ical` | Parse/validate/serialize (wraps calcard), index, content hash, timezone resolver, expansion, filters, free-busy, calendar-data projection, iTIP diff/build/apply, busy stripping, EventData merge. No I/O. | domain |
| `ports` | Port traits, `StoreError`, `PortError`, plugin registry, `OutboxMessage`, `observe()`, system `Clock`/`IdGenerator`; `testing` feature: `ManualClock`, `SeqIds`, `FixedKeyRing`, `FixedProfileSigner`. | domain |
| `wire` | API/MCP/webhook DTOs, `ProblemCode` table, `Page<T>`, `EventView`, webhook envelope, schema export. | domain |
| `app` | Service traits (`services`), use-case implementations, authz fact loading, scheduling, outbox dispatcher, iMIP composer, sync engine, workers. | domain, ical, ports, wire |
| `app-fake` | Minimal in-memory implementation of the service traits for protocol-crate tests without a database. | app, domain, wire |
| `http` | Tower layers and edge helpers: request id, tenant resolution, authentication, rate limit, body/header limits, trace + redaction, problem rendering, CORS policy. | app, domain, wire |
| `dav` | WebDAV/CalDAV router. | app, domain, ical, http |
| `api` | `/api/v1` router (utoipa-axum `OpenApiRouter`). | app, domain, wire, http |
| `web` | RSVP pages, feeds, OAuth callback, static assets. | app, domain, wire, http |
| `mcp` | MCP router (rmcp, streamable HTTP). | app, domain, wire, http |
| `store-postgres` | `Database` adapter, migrations, RLS. | ports, domain |
| `store-memory` | `Database` adapter with real transactions (copy-on-write snapshot under one async mutex). | ports, domain |
| `mime` | `OutgoingMail` → RFC 5322 bytes (iMIP structure 2.15). | domain |
| `mail-smtp` | `MailTransport` via lettre (rustls). | ports, domain, mime |
| `mail-memory` | `MailTransport` capture (structured + MIME bytes). | ports, domain, mime |
| `templates` | `TemplateRenderer` (minijinja, strict undefined, auto-escape), default theme, de/en. | ports, domain |
| `auth-local` | `Authenticator` for app passwords, API, feed and RSVP tokens; verified-credential cache. | ports, domain |
| `crypto-local` | `SecretSealer` (XChaCha20-Poly1305), `KeyRing` (HMAC-SHA256, HKDF subkeys), `CredentialHasher` (HMAC; argon2id reserved), `ProfileSigner` (CMS signing of Apple profiles with the deployment's certificate; its `testing` feature holds throwaway certificates and keys for tests, enabled by test crates only). | ports, domain |
| `http-egress` | `HttpClient` (reqwest, rustls) with egress policy; `recording` fake. Only crate allowed to depend on reqwest. | ports, domain |
| `hooks-webhook` | `OutboxHandler` "webhook" (Standard Webhooks signing) + `EventSink` "log". | ports, domain, wire |
| `ratelimit-memory` | `RateLimiter` "memory" and "noop". | ports, domain |
| `scanner-eicar` | `ContentScanner` "eicar": reports the EICAR test string as infected; a fake of the scanning path, refused in production. | ports, domain |
| `provider-google`, `provider-microsoft` | `OAuthProvider` + `RemoteCalendarApi`; cargo features `provider-google`, `provider-microsoft`. | ports, domain |
| `provider-fake` | Scriptable provider for the sync engine tests. | ports, domain |
| `server` | Binary: config, registry wiring, listeners, worker spawning, CLI (`serve`, `migrate`, `config check`, `config reference`, `healthcheck`, `admin bootstrap`, `admin system-token`, `admin principal-token`, `admin rotate-keys`, `admin bump-sync-epoch`, `admin purge-audit`). | everything except test crates |
| `fixtures` | Builders (entities, `EventBuilder`), `FixtureWorld` spec, ICS corpus loader. | domain, ical, ports(testing) |
| `port-tests` | Contract suites for every port (`store::run_all`, `mail::run_all`, …). | ports, domain, fixtures |
| `testkit` | `TestApp`, transports (in-process / HTTP), matrix harness, flow runner. | everything |
| `it` | Integration tests only (`tests/`); the only consumer of `testkit` besides `conformance`. | testkit |
| `conformance` | Binary: matrices + flows over HTTP against a base URL (staging). | testkit |
| `xtask` | `arch-check`, `contracts` (OpenAPI, MCP schemas, event schemas), `matrix`, `config-docs`, `problems-docs`, `unsupported`. | cargo_metadata |

Dependency rules (enforced by `xtask arch-check`, including dev-dependencies): protocol crates never depend on
`ports` or adapters; adapters never depend on other adapters except `mime`; a crate may dev-depend only on
crates that do not depend on it; `testkit` is a dependency of `it` and `conformance` only.

### 2.2 Technology decisions (ADR-0001)

| Topic | Decision |
| --- | --- |
| Async ports | `#[async_trait]` with `Send` futures for every dyn port and service trait; injected as `Arc<dyn Trait>`. Large reads use cursor pages, not streams. |
| Time | `chrono` + `chrono-tz` (bundled tzdb, updated by Dependabot); CLDR Windows-zone table embedded in `ical`. |
| iCalendar | `calcard` pinned exactly, wrapped entirely in `ical` (no calcard type in any public API). Its license is checked by cargo-deny and its behaviour against the corpus in 3.5. Fallback for expansion gaps: `rrule`. |
| HTTP | axum + tower + hyper; DAV routes use `axum::routing::any` and dispatch on `req.method()`. |
| XML | `quick_xml::NsReader` into typed request enums; hand-written escaping writer; no serde derive for DAV XML. |
| DB | sqlx runtime-checked queries (`query_as` + `FromRow`), no `query!` macros, no `.sqlx` cache. |
| TLS | rustls with the ring provider everywhere; `openssl-sys` banned. |
| OpenAPI | utoipa + utoipa-axum `OpenApiRouter`; every route registered regardless of features. |
| MCP | rmcp pinned exactly; protocol revision `2025-06-18`. |
| Mail | lettre (`tokio1-rustls`, `builder`) for transport and MIME. |
| Config | figment (TOML + `DAVHAVEN_` env, `__` nesting), `deny_unknown_fields`, `secrecy::SecretString`. |
| Cancellation | `tokio_util::sync::CancellationToken`. |
| Observability | `tracing` with JSON logs, `metrics` with the Prometheus recorder, OpenTelemetry traces over OTLP/gRPC (tonic) behind the `otlp` feature of `server`: the one recorded exception of R1 (ADR-0013). |

### 2.3 Plugin model

* The registry selects adapters by name for ports a deployment actually chooses: `Database`, `MailTransport`,
  `TemplateRenderer`, `Authenticator` (ordered chain), `EventSink` (set), `OutboxHandler` (set), provider (set),
  `ContentScanner` (set), `RateLimiter`, `HttpClient`, `SchedulingPolicy`.
* `Clock`, `IdGenerator`, `SecretSealer`, `KeyRing`, `CredentialHasher` and `ProfileSigner` (optional: present when the
  deployment names a certificate) are injected directly (production implementation plus test double), not selected by name.
* Each adapter crate exports `pub fn register(reg: &mut PluginRegistry)`; `server` calls it behind
  `#[cfg(feature = "...")]`. No `inventory`/`linkme`.
* Build order is tiered: tier 0 (clock, ids, keyring, sealer, hasher, http), tier 1 (database), tier 2 (all
  others). `PluginContext` exposes the already-built lower tiers.
* Each adapter's config is its own `Deserialize + JsonSchema` struct under `[plugin.<kind>.<name>]` (names repeat across
  kinds); the plugin descriptor also records the dedicated table that F0.9 gives it (`security.auth`; one owner per table,
  and a table belongs to one kind of plugin), its own check of the table for `davhaven config check` and whether
  production refuses it; `xtask config-docs` generates `docs/configuration.md` from the schemas. `[plugin.<name>]` means
  the same as `[plugin.<kind>.<name>]` while no other selected plugin has that name; the server builds one configuration
  tree per kind, so an adapter parses exactly its own table whichever way it was written, and a plugin may not be named
  like a kind (ADR-0013).
* Per-tenant variation (theme, sender, locale, policies) is data passed as arguments, never a separate adapter
  instance per tenant.
* With `server.mode = "production"` the registry refuses every plugin whose descriptor says it drops or fakes work
  (`refused_in_production`; `davhaven config check` reads the same flag): the memory store and mail transport, the `echo`
  renderer, the `noop` rate limiter, the recording HTTP client, the fake provider and the `eicar` scanner. The in-process
  `memory` rate limiter stays allowed: it is the limiter of a single instance (1.1). Production also refuses the DAV capture
  unless `observability.dav_capture.allow_in_production` says that an instance captures on purpose (ADR-0013).
* Customisation points beyond adapters: `SchedulingPolicy` (auto-accept, resource rules, external policy),
  outbound webhooks, `EventSink`s, theme directories, the inbound iTIP endpoint.

### 2.4 Data model (PostgreSQL)

Every tenant table has primary key `(tenant_id, id)` and composite foreign keys `(tenant_id, x_id)`, so
cross-tenant references cannot be inserted (the exceptions are listed under the table). RLS policies on every
tenant table (`tenant_isolation`) compare `tenant_id` with `current_setting('davhaven.tenant_id')`, set by `SET LOCAL`
when a tenant transaction begins. Timestamps that logic depends on come from `Clock`, never `DEFAULT now()`. Mutable rows
carry `version bigint` for ETags/If-Match.

**Roles and row-level security** (ADR-0005). Two login roles. The *owner* owns the schema, runs the migrations and is not
bound by RLS: a table owner is exempt unless the table is `FORCE`d, and the cascading deletes of a tenant or a purged
principal rely on that, so tables are never `FORCE`d. The *runtime* role is `NOSUPERUSER NOBYPASSRLS`, owns nothing and has
data access through the owner's default privileges and nothing else: no `TRUNCATE` (it bypasses RLS), `REFERENCES`,
`TRIGGER` or `CREATE`, no writes to the migration history, no `UPDATE` or `DELETE` on `audit_events`. RLS is a second line
of defence against a statement of the adapter that forgets or mixes up its tenant predicate; it is not a boundary against
code that can run arbitrary SQL as the runtime role, because the binding is a setting that role makes itself. In
`server.mode = "production"` the server refuses a role that is not bound (a superuser, `BYPASSRLS`, the owner of the tables
or a member of such a role, or privileges beyond the role model) and a connection to a remote host without TLS, unless
`database.allow_unbound_role` or `database.allow_insecure_transport` accepts the risk (in `dev` mode both are only logged). Readiness
reports the role findings, a role that is not bound or that holds privileges beyond the role model, as degraded; the transport is
judged when the server starts and not again.
The production recipe is `database.migrate_on_start = false` and a separate `davhaven migrate` with the owner's
credentials. The role model (`role_model.sql`) is applied after every migration run, so a restored database gets it too.

**System scope.** The few operations that cross tenants (tenant management, credential lookup before the tenant is known,
the outbox queue, retention) run in a *system transaction* that sets `davhaven.system = 'on'` instead of a tenant. A second
policy per command (`system_scope*`) admits it on fifteen tables, and only for the commands `repos/system.rs` runs:

| Table | Commands in system scope |
| --- | --- |
| `tenants` | all (tenant management) |
| `principals`, `app_passwords`, `feed_tokens` | `SELECT` (credential lookup; the principals due for purging) |
| `api_tokens` | `SELECT` (lookup of every kind); `INSERT` and `UPDATE` only for system tokens (`tenant_id` NULL, kind `system`) |
| `calendars`, `principals_sync` | `SELECT`, `UPDATE` (sync epochs, minimum sequence numbers, the calendars due for purging) |
| `collection_changes` | `SELECT`, `INSERT`, `DELETE` (retention logs expired inbox items and prunes the log) |
| `scheduling_inbox` | `SELECT`, `DELETE` (retention) |
| `outbox` | `SELECT`, `UPDATE`, `DELETE` (claim, settle, retention); no `INSERT` |
| `rsvp_tokens`, `oauth_states`, `idempotency_keys`, `webhook_deliveries` | `SELECT`, `DELETE` (lookup and retention) |
| `audit_events` | `SELECT` (the oldest record of all tenants, for the monitoring of the audit purge: policy `system_scope_select`); `INSERT` of the actions `tenant.created` and `tenant.settings_changed` only, for a tenant that exists (policy `system_scope_insert`); no `UPDATE` or `DELETE` |

Calendar objects, grants and notifications are unreachable from system scope, and of the audit log it reads the records and
appends the two events of tenant management, nothing else: a tenant is created and changed in a system transaction, and the
record of the change commits and rolls back with it (`SystemTenantRepo::append_audit`, which takes
`TenantAudit::{Created, SettingsChanged}`, so a store never has to refuse another event at runtime). The read is one statement,
the oldest record of all tenants (`RetentionRepo::oldest_audit_at`, `SELECT at FROM audit_events ORDER BY at LIMIT 1` on the
index `audit_events_at_idx`), which the cleanup worker publishes as `davhaven_audit_oldest_event_timestamp_seconds` so that an
operator hears when the purge job (which runs outside the server) stops; the policy admits every row and column of the log in
system scope, which adds no reach a compromised server did not have, because it reads the log of every tenant it names through
tenant scope (ADR-0005). A compromised server in system scope therefore cannot overwrite a credential hash or a principal,
mint or change tenant and principal tokens, create a calendar or delete one directly, forge outbox work, inbox items or RSVP
links, truncate a table, rewrite the migration history, or change or delete the audit trail. It can still do what the
table lists, and two of those reach further than they read: it has every command on `tenants`, so it can create and change a
tenant and delete one, which cascades to everything of that tenant (the audit log excepted: it has no tenant foreign key); and
the `UPDATE` policy of `calendars` limits no column, so it can soft-delete any calendar, which hides the calendar and its
objects. A test pins the list with its commands and proves that every other table-and-command pair is refused; changing it is a
security decision. Through tenant scope a compromised server can do what the application can do for any tenant it names.

| Table | Columns (beyond `tenant_id`, `id`, `created_at`, `updated_at`, `version`) | Constraints |
| --- | --- | --- |
| `tenants` | `slug` (immutable), `display_name`, `login_domain`, `status {active, suspended}`, `settings jsonb` (typed `TenantSettings`, `schema_version`) | unique `slug`, unique `lower(login_domain)` |
| `principals` | `kind {user, group, resource, service}`, `name` (immutable login localpart), `display_name`, `email`, `locale`, `timezone`, `external_ref`, `status {active, suspended, deleted}`, `deleted_at`, `credential_generation int` | unique `(tenant_id, name)`, `(tenant_id, external_ref)` |
| `principal_addresses` | `principal_id`, `address` (normalised calendar-user address), `is_primary bool` (`primary` is reserved) | unique `(tenant_id, lower(address))`, partial unique `(tenant_id, principal_id) WHERE is_primary` |
| `memberships` | `group_id`, `member_id` | PK `(tenant_id, group_id, member_id)` |
| `calendars` | `owner_id`, `slug` (immutable), `kind {personal, group, managed, user, mirror}`, `display_name`, `description`, `color`, `sort_order`, `components`, `timezone_ics`, `sync_seq`, `sync_min_seq`, `sync_epoch uuid`, `deleted_at` | partial unique `(tenant_id, owner_id, slug) WHERE deleted_at IS NULL` |
| `calendar_bindings` | `principal_id`, `calendar_id`, `slug`, `display_name`, `color`, `sort_order`, `schedule_transp`, `hidden` (overrides; NULL = calendar default) | unique `(tenant_id, principal_id, slug)`, `(tenant_id, principal_id, calendar_id)` |
| `collection_properties` | `binding_id` (NULL = shared), `calendar_id`, `ns`, `name`, `value_xml` | unique `(tenant_id, calendar_id, binding_id, ns, name)` |
| `calendar_grants` | `calendar_id`, `grantee_id` (user, group or service principal), `access {read, read_write, admin}`, `status {pending, accepted, declined}`, `source {api, share}`, `invite_uid`, `summary`, `common_name`, `required bool` (2.9) | unique `(tenant_id, calendar_id, grantee_id)` |
| `calendar_objects` | `calendar_id`, `owner_id` (denormalised), `uri` (decoded segment), `uid`, `etag`, `schedule_tag`, `content_hash`, `component`, `data text` (verbatim bytes), `size`, `first_start`, `last_end` (`'infinity'` for unbounded), `is_recurring`, `is_scheduling`, `organizer_address`, `sequence`, `class`, `external_key`, `origin` (provider marker), `live` (false while the calendar is soft-deleted) | unique `(tenant_id, calendar_id, uri)`, `(tenant_id, calendar_id, uid)`, partial unique `(tenant_id, calendar_id, external_key)`, partial unique `(tenant_id, owner_id, uid) WHERE is_scheduling AND live` |
| `object_attendees` | `object_id`, `address`, `principal_id` (resolved at invite time), `partstat` | index `(tenant_id, address)` |
| `collection_changes` | `collection_kind {calendar, home, inbox, notifications}`, `collection_id`, `seq`, `uri`, `kind {upsert, delete}`, `at` | PK `(tenant_id, collection_kind, collection_id, seq)` |
| `principals_sync` | `principal_id`, `home_seq`, `inbox_seq`, `notifications_seq` (+ min/epoch) | one row per principal |
| `notifications` | `principal_id`, `uri`, `uid`, `etag`, `type {invite, invite_reply}`, `body_xml` | unique `(tenant_id, principal_id, uri)` |
| `scheduling_inbox` | `principal_id`, `uri`, `etag`, `data`, `quarantined bool` | unique `(tenant_id, principal_id, uri)` |
| `outbox` | `kind text`, `payload jsonb`, `schema_version int`, `status {pending, in_flight, done, dead}`, `attempts`, `next_attempt_at`, `locked_until`, `last_error` | index `(status, next_attempt_at)` |
| `app_passwords` | `principal_id`, `label`, `prefix`, `hash`, `pepper_kid`, `last_used_at`, `revoked_at` | unique `prefix` |
| `api_tokens` | `kind {system, tenant, principal}`, `principal_id`, `label`, `scopes text[]`, `prefix`, `hash`, `pepper_kid`, `expires_at`, `created_by`, `allowed_origins`, `last_used_at`, `revoked_at` (`tenant_id` NULL only for `system`) | unique `prefix` |
| `feed_tokens` | `principal_id`, `mode {full, busy}`, `calendar_ids uuid[]`, `prefix`, `hash`, `pepper_kid`, `revoked_at` | unique `prefix` |
| `rsvp_tokens` | `object_id`, `attendee_address`, `prefix`, `hash`, `expires_at`, `revoked_at`, `last_used_at`, `last_response` | unique `prefix` |
| `external_accounts` | `principal_id`, `provider`, `account_ref`, `sealed_tokens bytea`, `mirror_calendar_id`, `sync_state jsonb`, `status`, `last_error` | |
| `oauth_states` | `principal_id`, `provider`, `state_hash`, `pkce_verifier_sealed`, `expires_at`, `used_at` | |
| `webhook_subscriptions` | `url`, `description`, `sealed_secret`, `sealed_secret_previous`, `secret_rotated_at`, `events text[]`, `include_details bool`, `active`, `failure_count`, `disabled_reason` | |
| `webhook_deliveries` | `subscription_id`, `event_id`, `status`, `attempts`, `response_status`, `last_error`, `at` | |
| `idempotency_keys` | `token_id`, `key`, `method`, `path`, `fingerprint`, `status {in_flight, done}`, `response_status`, `response jsonb`, `expires_at`, `lease_until` (an in-flight key whose claimant died is taken over after its lease) | unique `(tenant_id, token_id, key)` |
| `audit_events` | `actor jsonb` (`{kind, principal_id, token_id, label, ip_hash}`), `action`, `target`, `details jsonb`, `at` | runtime role: INSERT/SELECT only; no tenant foreign key |

**The audit log is append-only, and its purge is not the runtime role's** (ADR-0005). Retention must still delete old
records, so the migration provides `davhaven_purge_audit(cutoff, max_rows)` as `SECURITY DEFINER` (owner rights,
`search_path = pg_catalog, pg_temp`, `PUBLIC` revoked) and the role model revokes it from every runtime role on every run: a
role that could call it could erase every tenant's trail with one statement, whatever floor the function enforced. The purge
runs as the owner, or as a role that holds that function and nothing else, on a schedule (`davhaven admin purge-audit`, 2.18);
a runtime role that holds it is a finding of the posture check.

**Schema beyond the table** (ADR-0005): `principals_sync` keeps `min_seq` and `epoch` for each of its three collections;
`collection_changes` has no foreign key on `collection_id` (it names a calendar or a principal; the rows are removed
explicitly); `audit_events` has no tenant foreign key, so the record of a deleted tenant outlives it until retention removes
it; extra unique keys exist only as targets of composite foreign keys; checks tie `api_tokens.kind` to `tenant_id` and
`principal_id`. Three deliberate deviations from the composite-key rule, all on tokens: `api_tokens` has the primary key `(id)`
(a system token has no tenant, so `tenant_id` is nullable and cannot be part of a primary key; the unique `(tenant_id, id)` is kept
for the foreign keys of tenant tables, though none references it today); `api_tokens.created_by`, the token that minted another,
is a plain foreign key on `(id)`, so the schema does not tie it to a tenant (the application mints tokens inside one tenant, or
from a system token); and `feed_tokens.calendar_ids` is a `uuid[]` without foreign keys (a feed names several calendars; the
purge of a calendar or of a principal removes the dangling ids explicitly, and a test pins it). The adapter needs PostgreSQL 15
or newer (`ON DELETE SET NULL (column)`) and a Unicode-aware `LC_CTYPE`, because display-name searches lowercase with the
database locale (2.17).

The schema is created by one migration, `crates/store-postgres/migrations/20261101120000_initial_schema.sql`. Later
changes are new timestamp-named, forward-only migrations that follow expand/contract (R16); the adapter crate is the
only place that writes them.

### 2.5 URL layout and listeners

| Path | Purpose | Route group |
| --- | --- | --- |
| `/.well-known/caldav` | 301 to `/dav/` for every method, no auth | `wellknown` |
| `/dav/` | Entry; unauthenticated PROPFIND → 401 with challenge, then `current-user-principal` | `dav` |
| `/dav/principals/{tenant}/{principal}/` | Principal resource | `dav` |
| `/dav/calendars/{tenant}/{principal}/` | Calendar home (lists the principal's bindings) | `dav` |
| `/dav/calendars/{tenant}/{principal}/{binding}/` | Calendar collection via binding | `dav` |
| `/dav/calendars/{tenant}/{principal}/{binding}/{object}` | Calendar object (any single segment ≤ 255 bytes) | `dav` |
| `/dav/calendars/{tenant}/{principal}/inbox/`, `outbox/`, `notifications/` | Scheduling and notification collections | `dav` |
| `/rsvp/{token}` | RSVP page (GET read-only, POST answers) | `web` |
| `/feeds/{token}.ics` | Subscription feed | `web` |
| `/oauth/{provider}/callback` | Provider OAuth callback | `web` |
| `/assets/…` | Static theme assets | `web` |
| `/api/v1/…` | Management API | `api` |
| `/mcp` | MCP endpoint | `mcp` |
| `/healthz`, `/readyz`, `/metrics` | Operations | `ops` |

Listeners: `server.listeners.<name> = { bind, routes = [groups] }`. Defaults: `public` = wellknown, dav, web;
`internal` = api, mcp; `ops` = ops. A deployment may merge or disable listeners. `{tenant}` is the tenant slug,
`{principal}` the immutable principal name; renames change display names only. Reserved home slugs: `inbox`,
`outbox`, `notifications`, `dropbox`, and anything starting with `.`. DAV responses use path-absolute hrefs
encoded by one canonical encoder (`ResourcePath::format`); absolute URLs (mails, feeds, client config) come from
`PublicUrls` (`server.public_base_url`, per-tenant override), never from the `Host` header. Client IP is taken
from `X-Forwarded-For` only when the peer is in `server.trusted_proxies` (rightmost untrusted entry).

### 2.6 Identity, credentials and authorization

**Login and addresses.** DAV login is `name@login_domain` (or the bare name when the tenant is resolved from the
path). `calendar-user-address-set` = `mailto:{primary address}`, further `principal_addresses`, the principal URL,
`urn:uuid:{principal_id}`; the login address is included only if `tenant.settings.login_address_is_cua`. Address
matching is case-insensitive; principal URLs and `urn:uuid` are normalised to `mailto` before any outgoing iTIP.
Addresses of deleted principals stay reserved until purge.

**Credentials** (all server-generated):

| Kind | Format | Accepted on | Storage |
| --- | --- | --- | --- |
| App password | 9 groups of 4 lowercase base32 chars (`abcd-efgh-…`, 180 bits); first 2 groups = prefix (40 bits, stored and listed in clear), the other 7 (140 bits) are the secret | `dav` (Basic; username must equal the owner's login) | HMAC-SHA256(pepper[kid], secret) |
| API token | `dvh_pat_{prefix12}_{secret43}` | `api`, `mcp` (Bearer header only) | HMAC |
| Feed token | `dvh_feed_{prefix12}_{secret43}` in the URL | `web` feeds | HMAC |
| RSVP token | `dvh_rsvp_{prefix12}_{secret43}` in the URL; prefix and secret are **derived** from the key ring's `rsvp` purpose and the token id, not drawn (ADR-0007) | `web` RSVP | HMAC of the secret component |
| Webhook secret | `whsec_{base64}` | outbound signing | sealed |

The format of every credential (markers, lengths, alphabets, parsing, generation, the split into prefix and secret) is
defined once, in `domain::credential_format` (`AppPasswordText`, `TokenText`), which the authenticator, the RSVP derivation, the
fixtures and the contract suite use.

**RSVP links are derived** (ADR-0007; the one exception to "random, shown once" of R6). A mail is composed again on every
attempt of its outbox record and an update mail must carry the link of the invitation, while the outbox keeps no credential:
the prefix and the secret are keyed functions (HMAC with the `rsvp` purpose, over the tenant and the token id), so a retry
recomputes the link from the row's id and the row stores only the keyed hash of the secret component, found by prefix. The
newest live token of an attendee for an object is reused while it still matches its derivation and outlives the event;
otherwise a new one is minted and the earlier ones are left alone, so links in mails that were sent before keep working until
their own expiry, whatever a key rotation or a reschedule does. Whoever holds the `rsvp` key and the ids of the token rows can
recompute every link that was mailed, so the key lives where the pepper lives, under the same rotation procedure.

Unknown prefixes run an equal-cost dummy verification. `auth-local` caches successful verifications of app passwords and
principal tokens for 5 minutes keyed by HMAC(cache key, presented secret); the cache saves the hash verification only: an
entry is valid for the stored hash it was verified against and the `principals.credential_generation` it saw, and the credential
row, the statuses of its principal and tenant and the generation are read on every use (one system query per request,
`LookedUpCredential` carries the owner), so a revocation applies at once; failures are never cached. A credential that is
used after a pepper key rotation is hashed again under the active key, once (compare-and-set on the old key id, after a fresh
verification), so a retired key can be removed when no live credential names it. `last_used_at` is flushed at most every 15
minutes. No hard lockout: failure buckets per (login, IP) and per IP with exponential backoff → 429 `Retry-After`. The backoff
is a property of the `RateLimiter` port, not of one adapter (`RateKey::AUTH_LOGIN_IP`, `AUTH_IP`; `FailureBackoff`; an IPv6
address stands for its /64): `check(key, 0)` asks without consuming and `check(key, 1)` records a failure; the first
`security.auth.backoff_free` (5) failures of a (login, address) pair are free (the per-address bucket allows four times as
many), every further one blocks the key for `backoff_base` (1 s), twice that, and so on up to `backoff_max` (5 min); failures
are forgotten after `backoff_window` (15 min) without a new one, and the `noop` limiter fails the contract suite by design.
Authentication judges the credential, not the visibility of the path: a valid credential of one tenant that names another
tenant in the path is authenticated and the application answers 404 (R4), without counting a failed authentication. Every 401
carries `WWW-Authenticate: Basic realm="{tenant or server}", charset="UTF-8"` on `dav`, `Bearer` on `api`/`mcp`.
Authentication also checks that the principal and tenant are active (a tenant or principal that cannot be found is refused,
nothing is assumed active) and the token is unexpired.

**API tokens.** `system` tokens may only use `system:tenants` and never read calendar data. `tenant` tokens act
as tenant administrator within their scopes; `events:*` on a tenant token reaches managed and group calendars
only, never personal or user calendars. `principal` tokens act as their principal through the same `decide`
function as DAV; `mcp:*` scopes require a principal token with `expires_at` (default max 90 days). A token can only
mint tokens with a subset of its own scopes, with one exception: the `mcp:*` scopes, which a tenant token cannot hold
itself. A tenant token with `credentials:write` may put them on a principal token for a **service principal**, provided
it holds the API scope that reaches the same data (`events:read` for `mcp:read`, `events:write` for `mcp:write` and
`mcp:schedule_external`: MCP does not cap managed calendars at read as DAV does, and `mcp:schedule_external` sends
mail); every other scope still follows the subset rule. `credentials:write` is already the power to act as any
principal of the tenant that can act (it mints app passwords), so the exception adds only the reach of MCP; for a user
the subset rule stays. The operator mints principal tokens for any principal with `davhaven admin principal-token`
(the internal channel is trusted). A minted token never outlives its minter, and `mcp:*` needs a tenant that switched
MCP on. No per-request impersonation in 1.0.

**Scopes:** `system:tenants`, `principals:read`, `principals:write`, `credentials:write`, `calendars:read`,
`calendars:write`, `events:read`, `events:write`, `webhooks:manage`, `providers:manage`, `outbox:manage`,
`audit:read`, `itip:inbound`, `mcp:read`, `mcp:write`, `mcp:schedule_external`.

**Effective access** to a calendar = max of: `Owner` (owner principal); the owning group's
`tenant.settings.group_default_access` (default `read_write`) for current members; accepted grants to the
principal or to a group the principal is currently a member of. Pending/declined grants give nothing. Managed and
mirror calendars cap DAV access at `Read`; writes go through the API (`events:write`) or the sync engine.

| Level | DAV privileges | Also |
| --- | --- | --- |
| `FreeBusy` | `C:read-free-busy` | free-busy only within the tenant |
| `Read` | `read`, `read-current-user-privilege-set`, `C:read-free-busy` | per-binding properties writable |
| `ReadWrite` | + `write-content`, `bind`, `unbind`, `write-properties` | |
| `Admin` | + `CS:share`, rename | no collection delete, no owner change |
| `Owner` | + delete collection | |

`FreeBusy` is what every principal of the tenant has on a calendar of the tenant without a grant: it is the baseline and not a
grant level (`GrantAccess` is `read`, `read_write` or `admin`), so the viewer who sees free-busy only is a principal of the
tenant that holds no grant.

Per-binding properties (displayname, calendar-color, calendar-order, schedule-calendar-transp, default alarms,
unknown dead properties within limits) are always writable by the binding's principal and stored on the binding.

**Decision point.** `domain::authz::decide(&Subject, Channel, &AccessFacts, Operation) -> Decision` is pure;
`app` loads `AccessFacts` once per request (one query) and calls it; DAV derives
`current-user-privilege-set` from `domain::authz::privileges`. Protocol crates never decide.
Status policy: unauthenticated → 401; no read visibility (including other tenants and unknown ids) → 404;
visible but not permitted → 403 with `DAV:need-privileges` / problem `forbidden`; stale precondition → 412;
DAV write to managed calendar → 403.

### 2.7 Consistency contract

* **ETag**: strong, `"` + base64url(SHA-256(stored bytes))[0..22] + `"`; identical in GET, PROPFIND, REPORT and
  the API. The store keeps client bytes verbatim; the server re-serializes only objects it changes. A PUT returns
  `ETag` only when the stored bytes equal the request body (RFC 4791 §5.3.4).
* **Write invariant (store-enforced)**: `ObjectRepo::put/delete/move` run, in the caller's transaction,
  `UPDATE calendars SET sync_seq = sync_seq + 1 … RETURNING sync_seq` (serialises writers per calendar), write the
  change row at that seq, and return the seq and ETag. `CalendarRepo::touch` does the same for collection property,
  sharing and binding changes. Home, inbox and notification collections have the same mechanism.
* **Sync token / CTag**: `urn:davhaven:sync:{collection_id}:{epoch}:{seq}`; getctag is the same string. Foreign,
  garbled, wrong-epoch, future or pruned (`seq < sync_min_seq`) tokens → 403 `DAV:valid-sync-token` (API: 410
  `sync-token-expired`): the store says `StoreError::InvalidSyncToken`, never the `PreconditionFailed` of a stale `If-Match`.
  sync-level 1 only; truncation → 507 for the request URI plus a usable token. Deletions are reported as 404 responses.
  `admin bump-sync-epoch` runs after a restore. A listing that reports members together with a token (a full or initial sync)
  reads `ChangeRepo::state` **first** and lists the members afterwards: a write that commits in between is then in the listing
  and after the token, and the client sees it once more on its next sync (a harmless repeat), where the other order loses it
  for good. A caller that wants the whole read to be one snapshot opens the transaction with `TxMode::Snapshot` (`REPEATABLE
  READ`, read-only); `ChangeRepo::since` bounds its rows by the position it returns and is safe either way (ADR-0003, ADR-0006).
* **Query semantics**: `ObjectRepo::query` returns a superset of matches (index pre-filter: UTC `first_start`,
  `last_end`/infinity, floating values padded ±14 h); `app` filters exactly with `ical`. The pre-filter is **closed at both
  ends** (`first_start <= range end AND last_end >= range start`; an absent bound is open and an undated component matches
  every range): RFC 4791 §9.9 ranges are half-open, but a candidate the pre-filter drops never reaches the exact filter and is
  lost for good, so it keeps both touching ends and the exact filter removes the extras. There is one definition,
  `domain::index::interval_may_overlap`, which both stores use (the in-memory store evaluates it, the SQL mirrors it, and the
  contract suite compares them); the indexer anchors a `DUE`-only and a `COMPLETED`-only to-do at that instant, and a date-valued
  start without an end at `DTSTART + P1D` (ADR-0003 item 4).
* **No-op writes**: API/sync-engine upserts whose `content_hash` (ignores DTSTAMP, LAST-MODIFIED, SEQUENCE,
  PRODID) equals the stored one change nothing (no ETag, no seq bump).
* **Conditional precedence** on PUT/DELETE: `If-Schedule-Tag-Match`, then `If-Match`, then `If-None-Match: *`.
* **Schedule-Tag**: changes on organizer-initiated changes and on attendee changes to their own copy; unchanged by
  server merges (REPLY PARTSTAT, SCHEDULE-STATUS). On a schedule-tag match the attendee's change is merged instead
  of returning 412.
* **UIDs**: unique per calendar (`C:no-uid-conflict` with href); scheduling objects unique per owner
  (`C:unique-scheduling-object-resource` with href). MOVE within an owner is a relocation (no iTIP, schedule-tag
  kept, changes logged in both calendars).
* **Isolation level**: READ COMMITTED, an explicit `FOR NO KEY UPDATE` row lock on calendar rows in ascending id order, bounded
  app retry (3) on `StoreError::SerializationFailure`. The lock is `NO KEY UPDATE` and not `UPDATE`: the foreign-key check of
  an insert that references the calendar (a sharee's binding, a grant, a property) takes only `KEY SHARE`, which does not
  conflict, so such inserts do not queue behind a busy writer, while the writers themselves still serialise on their
  `UPDATE calendars SET sync_seq`; a write that must not outlive a concurrent `soft_delete` of the calendar takes
  `CalendarRepo::lock` first. A lock wait that expires (`lock_timeout`) is `StoreError::Timeout`, which `is_retryable()` for a
  caller that owns the whole transaction; the application does not retry it, because a timeout is the database struggling and
  repeating it would triple the latency and the load at that moment, so only a serialization failure is retried (above) and a
  timeout is answered 503 with `Retry-After` at once. A task holds **one
  transaction at a time**, on every adapter (two at once starve the pool; the in-memory adapter fails fast instead of hanging;
  ADR-0003 item 9, ADR-0006).

### 2.8 Scheduling

* **Actor**: the authenticated principal. A PUT schedules when ORGANIZER is in the actor's addresses, or in the
  owner's addresses while the actor has `ReadWrite` (sent with `SENT-BY` = actor). On group calendars the member
  is the organizer. ORGANIZER = another internal principal on create → 403 `C:organizer-allowed`. Neither
  organizer nor attendee (e.g. imported foreign event) → stored as a non-scheduling object.
* **Attendee copies**: only the actor's own ATTENDEE parameters, PARTSTAT, VALARMs and TRANSP may change, else
  403 `C:allowed-attendee-scheduling-object-change`; REPLY ATTENDEE comes from the context, never the body.
  Attendee DELETE sends REPLY DECLINED unless `Schedule-Reply: F`.
* **Not scheduled**: managed and mirror calendars; VTODO/VJOURNAL; attendees with `SCHEDULE-AGENT` ≠ SERVER;
  MCP/API writes unless the caller asks (`notify_attendees`). Outbox POST accepts VFREEBUSY only.
* **Diff** (`ical::itip::diff`): per instance (master + each RECURRENCE-ID). Significant change (DTSTART, DTEND/
  DURATION, RRULE/RDATE/EXDATE, LOCATION, SUMMARY, STATUS) resets PARTSTAT to NEEDS-ACTION and bumps SEQUENCE if
  the client did not; EXDATE additions and removed overrides → CANCEL with RECURRENCE-ID; removed attendee →
  CANCEL; insignificant edits update internal copies silently and send no mail. The golden fixtures in `crates/fixtures/data/itip/` pin the diff and the mails built from it.
* **Delivery**: address classes internal (same tenant), external (anything else, including other tenants).
  Internal delivery happens in the organizer's transaction up to `scheduling.max_sync_internal_attendees` (calendars
  locked in ascending id order); above that it is queued (`internal_delivery`). SCHEDULE-STATUS written into the
  organizer copy: 1.2 delivered, 1.0 queued, 1.1 iMIP sent, 3.7 unknown/group address, 5.x failed. All SCHEDULE-*
  parameters are stripped from outgoing iTIP. Internal attendees who already have a binding to the organizer's
  calendar get an inbox item instead of a second copy (`scheduling.suppress_duplicate_copies`, default on).
* **Policy hook**: `SchedulingPolicy` (default implementation in `app`) decides auto-add of invitations, resource
  auto-accept/decline by free-busy, and external policy `allow | allowlist | deny`. Quotas: external recipients per
  event (50), per organizer per hour, per tenant per day.
* **Replies**: every REPLY (DAV PARTSTAT change, RSVP, inbound iTIP) goes through one `ItipProcessor`.
* **External organizer**: an internal attendee's PARTSTAT change on a copy whose ORGANIZER is external → iMIP REPLY.
* **Inbound iTIP** (`POST /api/v1/tenants/{tenant}/itip/inbound`, scope `itip:inbound`, disabled by default):
  REPLY only unless the tenant enables REQUEST/CANCEL; requires a gateway-supplied DMARC/DKIM pass
  (`require_dmarc_pass`, default true), From = the replying ATTENDEE, UID and SEQUENCE matching an existing
  organizer object; otherwise quarantined and `scheduling.reply_rejected` emitted. Deduplicated on Message-ID;
  rate-limited per sender.
* **Decision table**: `testkit` holds the scheduling matrix (3.3) as the executable form of these rules.

### 2.9 Sharing and bindings

* Every visible calendar is a binding in the viewer's home: owner bindings at creation; share bindings on
  acceptance; group-member and managed-grantee bindings lazily on first home listing; binding slugs avoid owned
  slugs and reserved names.
* CalendarServer flow (exact XML fixtures in `testdata/dav/sharing/`): owner `POST` `CS:share` (`CS:set` /
  `CS:remove`) → grant `pending` + notification (`CS:invite-notification`) in the sharee's notifications collection
  → sharee `POST` `CS:invite-reply` to their home → 200 with `CS:shared-as` → binding created, owner gets an
  `invite-reply` notification. `tenant.settings.sharing.auto_accept` skips the notification step.
* Calendars expose `CS:allowed-sharing-modes` (`CS:can-be-shared` for owner/admin of non-managed calendars),
  `CS:invite`, `CS:shared-url`; resourcetype adds `CS:shared-owner` (owner) or `CS:shared` (sharee).
* Share rules: owner or admin only; sharees must be same-tenant users or groups (external `mailto` → per-item 403). The
  management API also grants to **service principals** (they hold principal tokens for the API and MCP; the owner and
  resources are refused, with one exception: a group that owns its calendar may be granted it, with access `read`, by a
  tenant token, to mark the calendar `required` for its members), which client sharing does not offer, principal search
  does not find and `CS:invite` does not
  list; managed calendars cannot be shared via DAV; one grant row per (calendar, grantee), last write wins between API
  and DAV, `source` updated, `grant.updated` emitted; clients cannot remove `source = api` grants on group/managed
  calendars, nor the `source = api` grant of a service principal on any calendar (403 `DAV:need-privileges`).
* DELETE of a bound collection: share → binding removed, grant declined, owner notified; group/managed → binding
  hidden; owner → calendar soft-deleted for everyone. A calendar that an accepted grant marks `required` for the caller
  (`calendar_grants.required`, set through the management API by a tenant token only: the grantee, or a group the caller is
  a member of) is none of these: `decide` refuses `RemoveBinding` (403 `DAV:need-privileges` naming `DAV:unbind` on the
  home, the parent of the collection) and nothing changes. Clients cannot change or remove a `required` grant, and neither
  can the token of a principal (a grant it puts keeps the flag it has). The management API lists the bindings of a
  principal's home that their calendar apps can list, hidden ones included (`GET …/principals/{principal}/bindings`: those
  created so far, a calendar of a group or a managed one has its binding from the principal's first listing of the home on),
  and shows a hidden binding again (`POST …/bindings/{binding}/restore`, audited as `binding.restored`; a binding of a
  calendar the principal can no longer reach is neither listed nor restored). A required calendar is always in the home of
  its people: setting `required` on a grant restores what the people it reaches had hidden, and so does joining the grantee
  group later.
* Principal search (`DAV:principal-property-search`, `CS:calendarserver-principal-search`): same tenant, min query
  length 2 (one text of two characters per search, the others may be shorter), max 50 results, returns display name
  and addresses only. The protocol layer builds **one** application search per request (texts, the properties they
  are looked for in, how they are compared, the kinds of principal, all-of or any-of) and the store applies every
  condition before the limit; a search the limit cut says so (507 entry for the request URI).

### 2.10 Management API

Conventions: path segments are the immutable natural keys (tenant slug, principal name, calendar slug,
`external_key` matching `[A-Za-z0-9._:~-]{1,200}`); every body also carries `id` and `dav_url`. snake_case JSON,
RFC 3339 UTC timestamps, operationId `verbNoun`. Problem details (RFC 9457): `type = urn:davhaven:problem:{code}`,
`code`, `request_id`, `errors[{pointer, code, message}]`. Mutable resources return `ETag` from `version`; PUT
replaces (create-or-replace, 201/200), PATCH is JSON Merge Patch, `If-Match` → 412, DELETE of calendars and
principals requires `If-Match` (428). Pagination: `?limit` (default 50, max 200) & `?cursor` (HMAC-signed),
`{items, next_cursor}` + `Link: rel=next`, ordered by id. `Idempotency-Key` optional on POST, required on batch:
scope (tenant, token, key), 24 h, fingerprint mismatch → 422 `idempotency-key-reuse`, in flight → 409
`idempotency-in-progress`, replay sets `Idempotent-Replayed: true`; responses containing secrets are not stored
(replay → 409 `secret-not-replayable`). `X-Request-Id` accepted or generated and echoed. `Cache-Control: no-store`
on every response carrying a secret, feed URL or profile. Bodies ≤ 1 MiB (batch ≤ 10 MiB) → 413. 429 carries
`Retry-After`. v1 is additive only; enums are documented as extensible; deprecation via `Deprecation`/`Sunset`.
Disabled features answer 409 `feature-not-enabled` (routes always exist so the spec is feature-independent); the error
carries the precondition `FeatureNotEnabled` (kind `Conflict`; DAV answers 403 for the same error).

**Replay of repeated `POST`s** (ADR-0011, ADR-0012). A layer of the API, inside bearer authentication, fingerprints the request
and reserves its key with a lease of the request timeout plus 30 s (`IdempotencyService::reserve` and `settle`: only the holder
of the reservation settles, so the fenced store operations ignore the late outcome of an attempt that lost its key); it runs the
handler in a task of its own, bounded by the request timeout and holding the concurrency permit of the edge, so that the outcome
is recorded when the client disconnects. Only a success whose handler marked it replayable is stored (status, `Content-Type`,
`Location`, `ETag`, JSON body), so a secret cannot reach the table by omission. A success that carries a secret (`no-store`), one
that is not marked replayable and one that is too large or of unknown size to be buffered is recorded as **used** and never
stored: the client still gets the original response, and a repeat gets 409 `secret-not-replayable` with the status and `Location`
of the first answer. Only the outcomes that did not produce a result release the key, so that a retry starts afresh: an error
response, a request that outran the request timeout (the work is cancelled first) and a body that failed while it was read. When
the service fails, the request is refused (503) instead of run unprotected.

**The contract documents** (ADR-0011). `docs/openapi.json` is built from components: the problem responses (with the
`WWW-Authenticate` and `Retry-After` headers where the status carries them), the parameters that several operations declare
identically and the shared schemas of the wire crate, and each operation lists the problems that follow from what it accepts.
The domain types that cannot derive `ToSchema` reach the document through a bridge from their `schemars` schemas that keeps the
values of enumerations, makes a named primitive a plain `string`, and writes an internally tagged union as a polymorphic type
with a `discriminator`. The names of the components are published contract: renaming one renames the type in generated clients.
Generators are part of the contract: `crates/api/clients` generates a Java and two TypeScript clients from the committed
document and compiles them (workflow `openapi-clients`, settings in `docs/api.md`).

The resource list is in F0.10. Key semantics:

* **Batch upsert** `POST …/calendars/{calendar}/objects/batch`: `{mode: merge|replace, replace_scope_prefix?,
  allow_empty: false, max_deletes?, items: [{external_key, event?: EventView, ical?: string}], deletes?: [key]}`;
  exactly one of `event`/`ical`; ≤ 1000 items; one transaction, all-or-nothing (422 with per-item problems);
  UID = UUIDv5(calendar_id, external_key) unless given; result `{sync_token, results: [{external_key, outcome:
  created|updated|unchanged|deleted|failed, uid, uri, etag, problem?}]}`; server bumps SEQUENCE; one
  `calendar.objects_changed` event; never schedules.
* **JSON event writes** (API, MCP) merge `EventView` fields into the stored component like a JSON Merge Patch
  (RFC 7396) for the members of the event, and keep unknown properties, alarms and X- properties; they share one app
  use case with DAV PUT (same change log, events, scheduling rules). A field with a value replaces the stored one, an
  absent field keeps it, and `null` removes it (`summary`, `description`, `location`, `end`, `duration`, `status`,
  `transparency`, `class`, `recurrence`, `organizer`, `attendees`, `categories`, `url`, `alarms`). `null` for `uid` and
  `start` is refused (422 at the pointer of the member, code `not-nullable`); for `recurrence_id` and `sequence` it is the
  same as absent. RFC 7396 goes no deeper than the members: an object or a list replaces the stored one as a whole
  (attendees are matched by address), and an organizer cannot be removed while attendees remain. The schemas of `uid` and `start`
  do not list `null`, and the MCP `tools_version` is 2.
* **Deleted principals** keep their name, `external_ref` and addresses reserved until the purge: `PUT …/principals/{name}`
  with `If-None-Match: *` answers 412 for the name (no hint about the hidden principal), a write without it answers 409
  `name-reserved`, and a create or replace whose `external_ref` or address collides with it answers 409
  `external-ref-reserved` / `address-reserved`.
* **Principal DELETE**: revokes credentials, RSVP tokens and shares immediately, hides the principal, purges after
  `retention.principal_purge_days` (or `?purge=true`); owned personal/user calendars are deleted at purge; organizer
  events in group calendars stay, no CANCEL unless `?notify_attendees=true`; later replies to them are quarantined.
* **Client config**: `GET …/client-config/generic` (no secrets); `POST …/client-config/apple-mobileconfig`
  `{app_password_label, include_feed}` mints an app password and returns `application/x-apple-aspen-config` with
  `PayloadIdentifier = {tenant client_config.apple_identifier_prefix}.caldav.{principal_id}` (reinstall replaces);
  `POST …/client-config/davx5` returns a login URI for QR codes; optional CMS signing with an operator certificate
  (`ProfileSigner`, a pure port built from `[security.profile_signing]`: `certificate_file` with the signer first and then
  its chain, `private_key_file`, or one combined PEM that both name (the key, then the chain with the leaf first); off unless
  both are named, the key checked against the certificate at the start). The production signer follows its files: the
  `profile_signing` worker of the server looks at them once a minute (by the `Clock`, on the blocking pool) and swaps in a
  renewed pair that works, never one that does not (a key that does not fit, a damaged file, a certificate that has ended or
  does not say when it ends), so an ACME renewal needs no restart; signing never waits for a file. The files must be reached
  through a mounted directory: a single-file bind mount, a Compose or Swarm secret or a Kubernetes `subPath` pins the file
  that was there at the start and a renewal then needs a restart (`docs/operations/keys.md`).
* **Changes feed** `GET …/calendars/{calendar}/changes?since=` uses the DAV sync token.
* **OAuth**: `POST …/external-accounts {provider, principal}` → `{authorization_url}`; state (single use, 10 min,
  bound to tenant/principal/provider) and sealed PKCE verifier in `oauth_states`; callback in `web`.
  The account list includes optional `last_sync_at` (last successful pull since the latest connection), `next_sync_at`
  (recorded due time, subject to provider/principal availability and leases) and `last_error_code` (an open set of reason
  strings beside the existing `last_error`). No cursor, lease or sealed token is exposed; absent or unreadable sync state
  omits the timestamps. Reconnection clears the times and error until the next pull.

### 2.11 Domain events and webhooks

* App writes `OutboxMessage::DomainEvent(Envelope)` in the same transaction as the change; after commit the
  dispatcher fans it out to `EventSink`s and expands one `webhook_deliveries` row per matching subscription.
* Envelope `{id (UUIDv7), type, version: 1, tenant, occurred_at, actor, data}`; `data` holds ids, calendar, uri,
  uid, external_key, etag, sync_token; details (summary, times) only if the subscription sets `include_details`.
* Catalog (`domain::events::EventType`, JSON Schemas exported and drift-checked): `principal.created|updated|deleted`,
  `membership.changed`, `calendar.created|updated|deleted`, `calendar.objects_changed`,
  `grant.created|updated|deleted`, `share.invited|accepted|declined`, `scheduling.reply_received`,
  `scheduling.reply_rejected`, `rsvp.answered`, `mail.delivery_failed`, `external_account.sync_failed`,
  `webhook.disabled`, and `webhook.ping` (the test event an operator sends to one subscription: it is delivered whatever the
  subscription's filter says and cannot be subscribed to).
* Webhooks follow Standard Webhooks: `webhook-id`, `webhook-timestamp`, `webhook-signature: v1,<base64 HMAC>`;
  multiple signatures during rotation; at-least-once, unordered (consumers dedupe on id); backoff for 24 h, then
  dead; auto-disable after `webhooks.max_consecutive_failures`; https only and egress policy applied at
  registration and on every send.
* **Outbox delivery** (ADR-0008). The dispatcher settles every record with the claim it was handed out under
  (`complete_claimed`, `fail_claimed`, `defer_claimed`) and releases its leases at shutdown; a lost lease or a record that is
  gone means that someone else decided, so the outcome is dropped and counted (`davhaven_outbox_settle_lost_total`) and never
  keeps the rest of the batch from being stored. The handlers of a batch run concurrently (`outbox.concurrency`, default 8)
  under one deadline, 80 % of `outbox.lease` from the claim, and a record whose turn comes with less than a quarter of the
  lease left is deferred and not started; a handler that panics or hangs is an ordinary retryable failure. `HandlerError::Defer
  { after, reason }` puts a claimed record back, due after the given time, with its attempt given back: a hold (the mail rate
  limit, an open circuit breaker) does not use up `outbox.max_attempts`. `OutboxHandler::limits_attempts` says whether the
  dispatcher dead-letters a record claimed `max_attempts` times (the webhook handler bounds its retries by time instead). A dead
  `imip` record is announced first (`mail.delivery_failed`) and settled dead only when that worked, with an outbox id derived
  from the id of the dead record; an event becomes one delivery per matching subscription under an id derived from the event and
  the subscription (`create_delivery` returns the existing row for a repeated pair), so a repeated pass enqueues nothing twice.
* **Webhook failures and details** (ADR-0009). The counter of a subscription counts deliveries that **ended dead because the
  receiver did not accept them** (the 24 h window ran out, or the egress policy now refuses the URL), each event once however
  many attempts it took; a delivery resets it; `410 Gone` disables at once (`endpoint_gone`); `webhooks.max_consecutive_failures`
  (20) dead deliveries in a row disable the subscription (`max_consecutive_failures`, audit and event `webhook.disabled`);
  deliveries of a disabled subscription are skipped (the row is `dead` with the text "the subscription is disabled", nothing
  counts). The store owns the counter (`record_success`, `record_failure`): a patch from a stale copy cannot erase it. The
  application reads the details behind `include_details` when it fans the event out and writes them into the delivery; the
  webhook adapter reads no calendar data. Details are given for objects of **managed and group** calendars only (a webhook
  belongs to the tenant, and a tenant credential never reaches personal, user or mirror calendars), and objects of the classes
  `PRIVATE` and `CONFIDENTIAL` come without a summary (`restricted`). A redelivery starts a new outbox record with a window of
  its own for the stored event; a tenant has at most `outbox.max_webhooks_per_tenant` (50) subscriptions. Creating, changing (the
  names of the changed settings, and the host when the URL changed, never path or query), deleting and rotating a subscription,
  a test event (`webhook.pinged`), a redelivery (`webhook.redelivered`) and an operator's retry of an outbox record
  (`outbox.retried`) are audited in the transaction of the operation.
* **Egress boundary** (ADR-0009). `HttpClient::validate_url` is checked at registration and fails closed: the default answers
  `Unsupported`, which the application treats as an error, so no URL is accepted unchecked by a client that cannot check it. The
  adapter cuts the answer of a webhook receiver at the cap of its purpose (`HttpPurpose`) and the delivery is judged by its
  status; for OAuth and provider calls an oversized answer fails the request. Caps and timeouts are per purpose. A host name is
  resolved once per connection and the connection goes to that answer. The refusal a tenant administrator sees at registration
  is one sentence for every reason, so registration cannot be used to probe the private DNS of the deployment (`docs/egress.md`).

### 2.12 MCP

* Mounted with `nest_service("/mcp")` behind `http` auth; principal tokens with `mcp:read`/`mcp:write`; stateless
  streamable HTTP; `Origin` validated against `mcp.allowed_origins`; `Mcp-Session-Id` is never an auth factor.
* Tools (input/output schemas from `wire`, `outputSchema` + `structuredContent`, snapshot-tested; names stable,
  changes additive, breaking change = new name; `tools_version` in server info): `list_calendars`, `list_events`
  (range ≤ `mcp.max_range_days` = 92, `limit` ≤ 200, `truncated`, `next_cursor`), `get_event`, `search_events`,
  `free_busy`, `find_free_slots`, `create_event` (`client_request_id` → deterministic UID), `update_event` and
  `delete_event` (`if_match`, `scope: this|this_and_future|all`, `recurrence_id`), `respond_to_invitation`.
* Annotations: `readOnlyHint` on reads, `destructiveHint` on `delete_event`, `idempotentHint` on update/respond.
* Safety: user-authored text is returned in `untrusted_text` fields, X-* and ATTACH dropped, attendee e-mails
  redacted unless `include_attendees`; external attendees require `mcp:schedule_external` and
  `notify_attendees: true`; per-token rate limits with a separate budget for writes; every write audited.
* Failures: tool result with `isError: true`, a short text and the problem document (`errors[]` included, with the retry
  hint beside it) in `_meta["davhaven/problem"]`. A failed result has **no** `structuredContent`: every tool announces an
  `outputSchema`, structured content has to conform to it, and a client that validates whenever the field is present would
  turn every failure into an exception of its own, so the model would never see it (ADR-0014). JSON-RPC errors only for
  protocol faults. Static bearer tokens instead of MCP OAuth are documented in `docs/interop.md`.

### 2.13 Feeds and RSVP

* **Feeds**: `text/calendar; charset=utf-8`, strong ETag + 304, `Cache-Control: private, max-age=300`,
  `X-WR-CALNAME`, `REFRESH-INTERVAL`/`X-PUBLISHED-TTL` (`feeds.refresh_interval`), VTIMEZONE per TZID, masters +
  overrides within the window `feeds.window_past_days` before and `feeds.window_future_days` after now (90 and 365 days by default). Busy mode: hashed UID, DTSTART, DTEND/DURATION, RRULE, EXDATE,
  RECURRENCE-ID, localized "Busy" summary (or the tenant's own text, below); TRANSPARENT and CANCELLED skipped.
  CLASS:PRIVATE/CONFIDENTIAL are busy-only for non-owners in every mode. Calendar access is re-checked on each request;
  revoked/unknown → 404. **The summary of a busy block** is named by the tenant in one of two ways, both optional and both
  additive to the `feed_busy` template. `busy_text_by_locale` is a map from a language tag (`de`, `en-GB`) to the text, at
  most 20 languages: the language of the feed's owner (the principal's locale, else the tenant's: the language `feed_busy`
  follows too, and the document of a feed does not vary by request, which its strong ETag and the 304 before the work rely
  on) is looked up as it is and then without its last subtag (`de-AT` finds `de`; `zh-Hant-TW` tries `zh-Hant`, then `zh`),
  and the first text found wins.
  `busy_text` is one text for every language, **the exception to the recipient locale of R15**: a convenience for a tenant with
  one working language, and the answer for a language the map does not name. Where neither names a text the `feed_busy`
  template of the tenant's theme speaks the language of the feed's owner. Every text is one to 100 characters, trimmed, without
  control, line-separator or invisible formatting characters, and is escaped like any text of an iCalendar property.
* **RSVP**: tokens stored hashed, revoked on attendee removal, CANCEL or deletion, expiry = last instance end
  + 7 days (max 1 year). GET is read-only and works without JavaScript; POST takes `partstat ∈ {ACCEPTED,
  DECLINED, TENTATIVE}`, comment ≤ 500 chars, a CSRF token bound to the RSVP token (1 h) and a same-origin check;
  repeatable. Headers: strict CSP (no third-party assets), `Referrer-Policy: no-referrer`, `no-store`,
  `X-Robots-Tag: noindex`. Shows summary, time, location, organizer name only. Unknown/expired/revoked → same 404.
  WCAG 2.1 AA. The comment of an answer is carried in the iTIP `REPLY` (`COMMENT`) and kept on the organizer's copy as
  `X-CALENDARSERVER-ATTENDEE-COMMENT` (cut at 500 characters, never sent to other attendees in iTIP; it is the server's
  like the answer it belongs to, so an organizer's write cannot forge or lose it). It stays on the organizer's copy, so
  everybody who can read that copy sees it (group members, sharees); a subscription feed leaves it out. Every failure of
  the web routes (404 for bad tokens included) is the `rsvp_unavailable` template in the deployment's default theme, in
  the first language of the visitor's `Accept-Language` that the theme ships, else the deployment's default. The link's
  token is derived from the key ring, not drawn (2.6, ADR-0007). The pages link the style sheet of the own origin
  (`/assets/{theme}/page.css`: the CSP forbids inline styles); static theme files reach the web surface **through the
  application** (`AssetService`, `TemplateRenderer::asset`: plain file names only, so a path that could leave the directory
  cannot be expressed; a file that the theme lacks comes from the first theme of its layers that has it, the built-in theme last
  (2.14); 200 with the content type, an ETag and a cache header, 304 for a current `If-None-Match`, a plain 404
  otherwise) and are never read from the file system by the route (ADR-0010).

### 2.14 Mail (iMIP)

* App enqueues `ImipJob` (references: object id, recipient, method, locale, template) — no rendered content in the
  outbox. At dispatch the `imip` handler (`app::imip`) renders the template, builds the iTIP part with `ical` and an
  `OutgoingMail`; `mime` assembles it.
* The template model tells the footer whether a reply reaches a person (`reply_to`, `null` for the no-reply address). An
  organizer without a mail address (a service principal) is named in the iTIP part of a `REQUEST` or `CANCEL` by the
  tenant's sender address instead of its `urn:uuid`. A guest's reply by mail button then goes to that address, which no
  principal has: a gateway that forwards it to the inbound iTIP endpoint has it quarantined (`unknown_event`); the RSVP
  link is the way back for such events.
* Structure: `multipart/mixed` [ `multipart/alternative` [text/plain, text/html, `text/calendar; charset=UTF-8;
  method=…`], `application/ics; name="invite.ics"` ]; `Content-Class: urn:content-classes:calendarmessage`;
  RFC 2047 subjects; one message per external attendee with To = that ATTENDEE; VTIMEZONE for every TZID; VALARM,
  X-APPLE-*, X-MOZ-*, SCHEDULE-* and binary ATTACH stripped.
* Headers: `mail.from_mode = service` (default): `From`/`Sender` = tenant sender (`"{organizer} via {tenant}"
  <noreply@sender_domain>`), `Reply-To` = organizer; `organizer` mode only for verified organizer domains.
  `Message-ID = <{outbox_id}@{sender_domain}>`. Header newtypes reject CR/LF.
* Replies through mail-client buttons reach the organizer's mailbox; they update PARTSTAT only if a gateway forwards
  them to the inbound endpoint. The RSVP link is the tracked path (`docs/interop.md`).
* Staging safety: `mail.redirect_all_to`, `mail.allowed_recipient_domains`, `mail.rate_limit_per_minute`, circuit
  breaker after `mail.max_consecutive_failures`.
* **Held mail** (ADR-0008). The handler does not fail a message that it did not try to send: it defers it (2.11) for the rate
  limit (the process-local bucket, then the `mail` bucket of the `RateLimiter` port, which a deployment can share between
  instances) and for an open circuit breaker (local to an instance: a connection problem is one). A held message shows as
  `pending` with its `last_error` set to the reason and does not count an attempt; a hold that has lasted a week ends and fails
  like a relay error, so mail does not wait for ever. The send timeout of the transport stays below 60 % of `outbox.lease`
  (`plugin.smtp.total_timeout`), which the server checks where the two sections meet.
* **Templates and themes** (ADR-0010). Themes are layered. A request is rendered *in* a theme `T`, and what `T` lacks comes from
  the themes it falls back to, in the order `T`, `templates.default_theme`, `default`, the built-in theme (the theme `default`
  falls back to the built-in theme alone, so that a tenant that names the neutral theme never takes on the branding of the
  deployment's default theme through a partial). A *template* comes whole from the first theme that provides it for the locale;
  a *partial* (a file whose name starts with `_`) file by file, always looked up in `T` first. The layers are flattened when
  the themes are loaded, so `{% extends %}` and `{% include %}` stay a plain lookup inside one theme, and every template of
  every theme, inherited ones included, is rendered with the sample models at startup and in `davhaven config check`; a layout
  that does not render the `content` block of the templates it wraps is refused there. The `theme` variable is the theme the
  request was rendered in, so a page links the style sheet of the theme that was asked for. The renderer takes the time from the
  `Clock` of the server (`now`, `year`), never from the wall clock.

### 2.15 Limits (config `[limits]`, advertised as CalDAV properties)

| Limit | Default | Response |
| --- | --- | --- |
| `max_resource_size` | 1 MiB | 403 `C:max-resource-size` |
| components / properties per component / unfolded value | 1000 / 500 / 64 KiB | 403 `C:valid-calendar-data` |
| `max_attendees_per_instance` | 200 | 403 `C:max-attendees-per-instance` |
| VALARM / RDATE+EXDATE / nesting / VTIMEZONE observances | 10 / 1000 / 4 / 200 | `C:valid-calendar-data` |
| inline binary ATTACH | 256 KiB | `C:valid-calendar-data` |
| FREQ=SECONDLY/MINUTELY | rejected | `C:valid-calendar-data` |
| `max_instances` / iterator steps | 3000 / 100 000 | 403 `C:max-instances` |
| min/max date-time | 1900 / 2100 | `C:min-date-time` / `C:max-date-time` |
| time-range / free-busy span | 10 years | 403 `C:valid-filter` |
| XML: depth / elements / attributes / namespaces | 32 / 10 000 / 32 / 64 | 400; DOCTYPE rejected |
| PROPFIND/PROPPATCH/REPORT body | 256 KiB | 413 |
| multiget hrefs / dead props per binding / dead prop size | 1000 / 50 / 4 KiB | 403 |
| sharees per `CS:share` request / terms of a principal search (`max_sharees_per_request`, `max_search_terms`) | 100 / 8 | 403 `DAV:number-of-matches-within-limits` / 400 |
| PROPFIND `Depth: infinity` | refused | 403 `DAV:propfind-finite-depth` |
| API JSON / batch body | 1 MiB / 10 MiB | 413 |
| headers / header read timeout / request timeout | 16 KiB / 10 s / 60 s | 431 / close / 503 |

Parsing and expansion run in `spawn_blocking` with a wall-clock timeout. DAV POST requires `application/xml` or `text/calendar`; unsafe methods with an `Origin` outside `security.cors.allowed_origins` get 403; no CORS on `dav`; `api` never accepts cookies.

### 2.16 Configuration

Layered TOML plus `DAVHAVEN_*` env (`__` nesting); every secret also accepts `<key>_file`; unknown keys and
unknown `DAVHAVEN_*` variables fail startup; `davhaven config check` prints the effective redacted config.
Precedence: server defaults → tenant settings → principal (locale, timezone). Keys are listed in F0.9.

`davhaven config check` (and `serve`, once, before it builds anything) validates every selected plugin's table through the
plugin's own check (2.3), so that a typo, a missing file or a theme that does not exist fails with the key's name in the pipeline
and not at the first request; the rules that connect two sections stay in the server, which sees both (the SMTP send timeout
against the outbox lease, 2.14, and the `redirect_uri` of a provider that is switched on against `server.public_base_url`, which
must be the callback this server serves, `{public_base_url}/oauth/{name}/callback`, 2.10). It prints the **effective** configuration, the defaults of the build read from the JSON
Schema of every table with the file and the environment laid over them and the table of every selected plugin with its own
defaults, secrets redacted (values under keys named like secrets, and credentials inside any URL); `--explicit` prints only what
was set. A table for an adapter that this build does not contain is an error that lists the adapters it does contain; one for an
adapter that is not selected, and a dedicated table that no adapter of the build reads, are warnings. `davhaven config
reference` renders the reference that `xtask config-docs` writes and checks. A command loads what its task needs: `migrate` and
`admin purge-audit` read the `[database]` table, `admin bump-sync-epoch` builds the store with a key ring that exists only in
the process (no key file is read), `healthcheck` reads the ops address, and `serve`, `config check` and the commands that hash or
seal secrets read everything; those that store a secret (`admin bootstrap`, `admin system-token create`, `admin
principal-token create` and `admin rotate-keys`: `list` and `revoke` store none) refuse to run without `security.keys`, because
development mode makes up a key ring per process and a secret hashed under one process's key could never be verified by another
(ADR-0013).

### 2.17 Operations

* `/healthz`: process alive. `/readyz`: database reachable and its posture in order (a runtime role that RLS does not bind
  or that holds privileges the role model withholds, and a `lower` that does not fold non-ASCII text, are reported degraded; 2.4),
  schema ≥ required version, every worker healthy. The server drives `Worker::tick`, not `run`, so that it has a heartbeat after
  every pass: a worker is unhealthy when it has not completed a pass for twice its interval or one pass has run for more than
  five minutes; a pass that panics is counted, does not take the loop down and does not refresh the heartbeat. `davhaven
  healthcheck` calls `/readyz` for the image `HEALTHCHECK`.
* SIGTERM: `/readyz` answers 503 `draining` at once. The listeners keep accepting for `server.shutdown_delay` (default 0: the
  time a load balancer needs to notice), then stop accepting and give requests in flight and the workers
  `server.shutdown_grace` (20 s); what still runs then, connections included, is cut off. The shutdown hooks of the workers
  (the outbox dispatcher hands its leases back, the unfinished attempt not counted) and of the adapters (in reverse order of
  construction) share one budget of five seconds, traces are flushed within four and the runtime ends within one: the process is
  gone at most `shutdown_delay + shutdown_grace + 10 s` after the signal, which the server logs at start and the runbook asks the
  container's stop timeout to exceed. The `ops` listener stops last, so that the draining is visible. The exit status is 0 even
  when a worker had to be cut off.
* Connection limits act before a request exists: the listeners drive connections with hyper's builder directly and close a
  connection that has had no request in flight for `server.http.header_read_timeout` (whatever the protocol, and whether it ever
  sent a request; HTTP/2 connections are pinged at that interval), and `server.max_connections` (4096) caps the open connections
  of a listener, because `concurrency_limit` counts requests and not sockets. The `ops` endpoints have a small bound of their
  own (16 concurrent requests, ten seconds) instead of the edge layers of the API (ADR-0013).
* Migrations: `davhaven migrate` (owner role from `database.migration_url`); `database.migrate_on_start`
  (default true; the production recipe is `false` and a separate `davhaven migrate` job: 2.4); runtime ignores unknown newer
  migrations and requires `max(applied) ≥ REQUIRED_SCHEMA_VERSION`. The adapter checks `server_version_num` before it migrates and when it
  connects (PostgreSQL 15 or newer).
* Image: distroless `cc` nonroot pinned by digest, UID 65532, read-only rootfs, OCI labels (revision mandatory).
* Metrics (prefix `davhaven_`): `http_requests_total{surface,method,route,status}` + duration (route = template),
  `port_calls_total{port,adapter,op,outcome}` + duration, `outbox_pending`, `outbox_oldest_pending_age_seconds`,
  `outbox_dead_total`, `auth_failures_total{mechanism,reason}`, `audit_oldest_event_timestamp_seconds` (when the oldest
  audit event of all tenants occurred; looked up every 15 minutes by the cleanup worker, one indexed query in system scope;
  absent while the log is empty) with `audit_retention_seconds` (`retention.audit_days`), the two series of the alert on the
  audit purge job (2.18), `profile_signing_certificate_expiry_timestamp_seconds` (the `notAfter` of the certificate that signs
  Apple profiles, in use now; absent while signing is off), tenant label only with
  `observability.metrics.tenant_label` (the key is reserved and refused when it is `true`: `docs/ROADMAP.md`, ADR-0013).
  The database pool gauges (`db_pool_in_use`, `db_pool_waiting`) are not exported yet (`docs/ROADMAP.md`). OTLP export optional, W3C traceparent propagated. JSON logs: request_id,
  trace_id, tenant_id, principal_id, route, status, latency; token paths redacted before logging.
* Shipped: `deploy/prometheus/davhaven-rules.yml`, `deploy/grafana/davhaven-dashboard.json` and the operations guides in
  [`operations/`](operations/runbook.md) (`runbook.md`, `backup.md`, `database.md`, `keys.md`).
* Opt-in capture middleware (`observability.dav_capture`, tenant allowlist, credentials redacted) produces
  fixtures for the client-flow suite.

### 2.18 Lifecycle, retention, privacy

Retention defaults (cleanup worker, `[retention]`): outbox done 7 d, dead 30 d; `collection_changes` 90 d (raises `sync_min_seq`);
audit 365 d; scheduling inbox 30 d; deleted calendars 30 d; principals 30 d; idempotency 24 h; OAuth states 1 d; RSVP tokens
30 d after they expired or were revoked; webhook delivery records 30 d. The keys and defaults are in
[`configuration.md`](configuration.md). Webhook payloads are thin; logs carry ids only; audit details never contain event
bodies or secrets.

The audit log is append-only for the runtime role (2.4), so under the production role model the server does not purge it: the
365 days run as the owner (`davhaven admin purge-audit`, scheduled outside the server, with the credentials of
`database.migration_url` or those of a role that holds the purge function and nothing else; the exit status of the job, and
the gauges of the oldest audit event and of the retention period (2.17), are what to alert on). The retention worker still asks the store, and purges whenever the store lets it: always on the memory store, and on
PostgreSQL only when the connected role may execute the purge function, which the role model withholds and a deployment that
accepts every finding with `database.allow_unbound_role` may have. A role that may not is a state of the deployment, which the
retention port reports as `AuditPurge::NotPermitted` (the plain `purge_audit` removes nothing and returns `0`), and the worker
treats it as a **skip** and not as a failure: an error every tick would hide real ones (ADR-0005, ADR-0006).

## 3. Quality strategy

### 3.1 Test levels

| Level | What | Where | Runs |
| --- | --- | --- | --- |
| L0 Unit | Pure logic, mapping tables (exhaustive) | each crate | PR |
| L1 Property | ical round trip/fixed point, never-panic parse, metamorphic expansion, href round trip, sync state machine vs model | ical, domain, dav, port-tests | PR (256 cases), nightly (20k) |
| L2 Port contract | Every port × every adapter (store on memory and Postgres, mail memory vs SMTP/Mailpit, egress SSRF table, sealer, keyring, limiter, providers vs recorded HTTP) | port-tests, adapter crates | PR |
| L3 App | Services over memory adapters with `ManualClock`/`SeqIds` | app tests, it | PR |
| L4 Protocol | In-process HTTP via `TestApp` (memory and Postgres) | protocol crates (with app-fake), it | PR |
| L5 Matrices | Permission, scheduling, config toggles (pairwise), template × locale × theme | it | PR |
| L6 Client flows | Scenario fixtures (3.5) | it | PR |
| L7 Black-box | `conformance` binary + python `caldav`, vdirsyncer, Litmus, Playwright RSVP (axe) against a deployed instance | conformance | main (staging), nightly |
| L8 Deep | cargo-fuzz (parser, DAV XML, inbound MIME, tokens), cargo-mutants, recurrence differential vs libical | nightly | nightly |

### 3.2 Permission matrix

Oracle: `crates/testkit/matrix/expectations.toml`, hand-reviewed default rules plus explicit exception rows; the
harness never imports `domain::authz`. Dimensions: actor (owner, group member, sharee read, sharee read-write,
grantee via group, pending/declined sharee, other user, other tenant, suspended user, service principals (one without
grants, one granted the group calendar with `read_write` and the managed calendar with `read`, one granted the managed
calendar with `read_write`), tenant token per scope, system token, anonymous) × calendar (personal, group, managed, shared user, mirror) × operation
(every DAV method/report incl. PROPPATCH per-binding vs shared prop, DELETE collection, MOVE/COPY source × target,
share, re-share, invite-reply, inbox/outbox, notifications; every API operation × scope; every MCP tool; feed;
RSVP). Credential × surface and credential state are pairwise dimensions. Every case asserts the status, no side
effects on denial (seq, outbox, events unchanged) and no leakage in the body. Exhaustiveness test: every route,
method and tool maps to an `Operation`. `xtask matrix` renders `docs/permission-matrix.md` (drift-checked).
Matrix profile: no-op rate limiter, verification cache warm.

### 3.3 Scheduling matrix

organizer surface {DAV, API, MCP} × attendee {internal, other tenant, group address, resource, external} × change
{create, significant, insignificant, add/remove attendee, cancel instance, cancel series, delete, move} × reply
channel {DAV, RSVP, inbound} × answer {accept, decline, tentative}; full product on the first three, pairwise on the
rest. Asserts inbox items, attendee copies, mail count/METHOD, organizer PARTSTAT, SCHEDULE-STATUS, events.
MIME snapshots (insta) per template × locale × method; the text/calendar part reparses with matching METHOD.

### 3.4 Client flows

YAML scenarios: templated requests, captures (ETag, sync-token, Location, Schedule-Tag), structural assertions
(status per href, property present/absent, XPath), marked `synthetic` or `captured` with provenance. Sources:
ccs-caldavtester scripts and CalendarServer client templates (Apache-2.0; the NOTICE sits next to the derived scenarios), python `caldav`
functional tests, staging captures. Client × feature grid (account setup, CRUD, recurring override, invite internal
and external, accept, share, sync after token expiry, read-only edit attempt) reports synthetic cells in CI.

### 3.5 Corpus and determinism

`testdata/corpus/` holds real client bodies (Apple, iOS, Thunderbird, DAVx⁵, Evolution, CalDav Synchronizer with
Windows TZIDs, Google/Outlook iMIP) with source notes; `.gitattributes` keeps them byte-exact. Each kind of body has one
place, and the paths that scenarios, tests and fuzz seeds name are relative to it (`body_file: dav/...`): iCalendar bodies
in `testdata/corpus/`, the DAV request and answer documents of the clients (`PROPFIND`, `REPORT`, `MKCALENDAR`, the
CalendarServer sharing flow in `sharing/`) in `testdata/dav/` (there is no `testdata/corpus/dav` and no copy under
`crates/*/`), and the iTIP golden set in `crates/fixtures/data/itip/`. `testdata/README.md` has the
map. RFC 4791 §9.9 time-range tables are test vectors. Workers expose `tick()`; tests never sleep.

### 3.6 Postgres in CI

`docker run --rm` Postgres (`fsync=off`, `max_connections=300`), migrated once into a template DB; default
isolation is a random tenant per test; global-state tests clone the template. Missing DB URL with `CI=true` panics.
The upgrade test (`crates/store-postgres/tests/upgrade.rs`) loads the schema up to the version a fixture file names (`tests/upgrade/<version>.sql`) with fixture rows,
applies the later migrations and reads the data back through the adapter. A fixture is added for every released
version (R16).

### 3.7 CI cadence

| Trigger | Jobs |
| --- | --- |
| PR | `checks` (fmt, clippy with all features and with none, the fuzz packages compile, `hack` on each feature of the server, rustdoc, `arch` (layering, manifests, and that every fuzz target is in the nightly matrix), unused dependencies (`cargo machete`), the container image pins (one digest per image), the `contracts` drift checks (OpenAPI, MCP, event schemas, problems, config docs, matrix report), `unsupported` (warns on `AppError::Unsupported`), `deny`, `actionlint`/`zizmor`), `test` (L0–L6 on memory + Postgres, nextest with a three-minute limit per test, `--locked`, doctests). No pull request builds the image: the smoke test of the release on main is the gate. A newer push cancels the run. Few jobs, one after the other, on purpose: the jobs run on shared runners (ENGINEERING_RULES R18). |
| main, `v*` tags | PR set, then the release (`release.yml`, only after the PR set succeeded for the same commit, which a tag run checks through the check runs of the tagged commit: the image is built once, smoke-tested with `/readyz` and one scenario, and only then pushed; a failing smoke test pushes nothing; then the optional dispatch), and on main coverage (llvm-cov, per-crate floors, ratcheted) |
| nightly | proptest 20k, fuzz 10 min/target (one job per target of every `crates/*/fuzz` package), mutants on authz/recurrence/itip/auth, differential recurrence, python caldav/vdirsyncer/Litmus, latest Postgres, 5× flake run, `cargo update` canary, `hack --feature-powerset --depth 2` |
| weekly | GHCR retention, and `image-pins.yml`: every container image the workflows and the Dockerfile pin by digest is compared with the digest its registry gives the tag now, and a stale pin fails the run (Dependabot reads the Dockerfile and nothing else of this) |
| release tag | `unsupported` is an error |

## 4. Contracts and change rules

### 4.1 Interface contracts (F0)

The contracts below are the interfaces the crates are built against: the domain types, errors, service traits, port
traits, plugin registry, wire types, configuration tables, API resources and test-harness interfaces. The numbers
F0.1 to F0.11 are stable identifiers that code comments and other documents cite ("F0" is the foundation layer that
every other crate depends on). A method added later has a default body that returns `AppError::unsupported()` or
`PortError::unsupported()`; `todo!` is never used.

**F0.1 Repository.** One workspace with every crate of 2.1. All external dependencies are declared once, with exact
versions, in `[workspace.dependencies]` of the root `Cargo.toml` (R11), and lints in `[workspace.lints]`.
Root files: `rust-toolchain.toml` (pinned toolchain with rustfmt, clippy and llvm-tools-preview), `rustfmt.toml`,
`clippy.toml`, `deny.toml`, `.editorconfig`, `.gitattributes`, `LICENSE-MIT` and `LICENSE-APACHE` (MIT OR Apache-2.0),
`SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `README.md`, `.github/CODEOWNERS`,
`.github/dependabot.yml` and the workflows in `.github/workflows/` (3.7, 4.5). Documentation lives in `docs/`
(this file, `ROADMAP.md`, `adr/`, the guides and the generated documents). `scripts/check.sh` runs the same commands as
CI, for any build host.

**F0.2 Application modules.** `crates/app/src` has one module per area: `services` (the service traits, F0.5), `authz`,
`calendars`, `objects`, `sharing`, `principals`, `provisioning`, `managed`, `feeds`, `credentials`, `idempotency`,
`audit`, `scheduling`, `itip`, `rsvp`, `inbound`, `addresses`, `policy`, `outbox`, `imip`, `sync_engine`, `oauth`,
`retention`, `workers`, and the supporting modules `assets`, `maintenance`, `wiring`, `paging` and `texts`.

**F0.3 Domain types** (`davhaven-domain`):

* Ids (UUIDv7 newtypes): `TenantId, PrincipalId, CalendarId, BindingId, GrantId, ObjectId, NotificationId,
  CredentialId, TokenId, WebhookId, DeliveryId, OutboxId, ExternalAccountId, EventId, RequestId`.
* Natural keys (validated newtypes): `TenantSlug, PrincipalName, CalendarSlug, ObjectUri, ExternalKey, Uid,
  CalendarUserAddress, Email, Locale, TimeZoneName, ETag, ScheduleTag, ContentHash`.
* Entities: `Tenant, Principal, Calendar, Binding, Grant, StoredObject, Notification, InboxItem, AppPassword,
  ApiToken, FeedToken, RsvpToken, ExternalAccount, WebhookSubscription` (fields as in 2.4).
* `ObjectIndex { uid, component, first_start, last_end: Option<DateTime<Utc>>, is_recurring, is_scheduling,
  organizer, attendees: Vec<AttendeeRef>, sequence, class, transp }`.
* `EventData` (canonical JSON event model used by `ical` merge and `wire::EventView`).
* `RequestContext { tenant: TenantId, actor: Actor, scopes: ScopeSet, channel: Channel, credential:
  Option<CredentialRef>, request_id: RequestId, locale: Option<Locale>, client_ip: Option<IpAddr> }`.
* `enum Actor { Principal(PrincipalId), PrincipalToken { principal: PrincipalId, token: TokenId },
  TenantToken(TokenId), SystemToken(TokenId), FeedReader { principal: PrincipalId, token: TokenId },
  RsvpAttendee { object: ObjectId, address: CalendarUserAddress }, Anonymous }`.
* `enum CredentialKind { AppPassword, ApiToken, FeedToken, RsvpToken }`, `CredentialRef { kind, id }`,
  `enum Channel { Dav, Api, Mcp, Feed, Rsvp, Internal }`, `enum Scope` (2.6) + `ScopeSet`.
* Authz: `enum Access { FreeBusy, Read, ReadWrite, Admin, Owner }`, `enum Privilege` (DAV privileges + `Share`,
  `ScheduleSend`, `ScheduleDeliver`), `PrivilegeSet`, `enum Operation` (one variant per matrix operation),
  `AccessFacts { calendar_kind, owner, owner_kind, memberships, grants, binding, tenant_settings }`,
  `enum Decision { Allow, Hidden, Forbidden(Privilege) }`, `fn decide(..)`, `fn effective_access(..)`,
  `fn privileges(Access, CalendarKind, ResourceKind) -> PrivilegeSet` (`ResourceKind` is `#[non_exhaustive]` and has `Principal, Home, Collection, Object, Inbox, Outbox, Notifications,
  InboxItem, Notification`).
* `ResourcePath` (`parse(&str)`, `format()`; variants Root, Principal, Home, Collection, Object, Inbox, Outbox,
  Notifications, Notification, InboxItem), `PublicUrls`, `SyncToken { collection, epoch, seq }` (parse/format).
* `TenantSettings` (`#[non_exhaustive]`, serde defaults, `schema_version`): locale, timezone, theme (optional: unset
  follows `templates.default_theme`), sender,
  dav_base_url, public_base_url, group_default_access, auto_create_personal_calendar, sharing {enabled,
  auto_accept}, scheduling {auto_add_invitations, external: allow|allowlist|deny, external_allowlist,
  suppress_duplicate_copies, inbound_methods}, feeds_enabled, busy_text (optional; one text for every language),
  busy_text_by_locale (a map from language tag to text, empty by default, at most 20 languages; both are described in 2.13),
  mcp_enabled, client_config
  {apple_identifier_prefix, organization_name}, allowed_components, login_address_is_cua.
* Mail: `OutgoingMail { message_id, from: Mailbox, sender, reply_to, to: Vec<Mailbox>, subject: HeaderText,
  text, html, calendar: Option<CalendarPart { method, ics }>, attachments, headers }`.
* Events: `EventType`, `Envelope`, payload structs. Audit: `enum AuditEvent` (credential create/revoke,
  use-after-revoke, auth-failure aggregate, token create/revoke, grant/share changes, principal lifecycle, tenant
  settings, webhook and external-account changes, MCP writes, RSVP answers, inbound accept/reject, rate-limit trips,
  key rotation), `AuditActor`.
* Limits: `IcalLimits`, `DavLimits`, `ApiLimits` (2.15 defaults).
* Principal search vocabulary (`domain::search`): `SearchField { Name, DisplayName, Address, Email }`, `TextMatch { Contains,
  StartsWith, Equals }` and `SearchCriterion { text, fields, matching }`, whose `matches` is the reference of the rule
  that the stores implement.
* Credential format (`domain::credential_format`: `AppPasswordText`, `TokenText`): the markers, lengths and alphabets of the
  credentials of 2.6, their parsing and generation and the split into prefix and secret, defined once (ADR-0012).
* Index range rule (`domain::index::interval_may_overlap`): the one definition of the closed pre-filter of 2.7 that
  `ObjectIndex::may_overlap` and `TimeRange::may_overlap` delegate to (ADR-0003, ADR-0006).

**F0.4 Errors.**

* `domain::ErrorKind { NotFound, Unauthenticated, Forbidden, Conflict, PreconditionFailed, PreconditionRequired,
  Invalid, TooLarge, RateLimited, Unavailable, Unsupported, Internal }`.
* `domain::Precondition` (`#[non_exhaustive]`, with payloads): `NeedPrivileges(Vec<(Href, Privilege)>)`,
  `ValidCalendarData(String)`, `ValidCalendarObjectResource`, `SupportedCalendarComponent`,
  `SupportedCalendarData`, `NoUidConflict(Href)`, `MaxResourceSize`, `MinDateTime`, `MaxDateTime`, `MaxInstances`,
  `MaxAttendeesPerInstance`, `UniqueSchedulingObjectResource(Href)`, `SameOrganizerInAllComponents`,
  `OrganizerAllowed`, `AllowedOrganizerSchedulingObjectChange`, `AllowedAttendeeSchedulingObjectChange`,
  `ValidSchedulingMessage`, `ValidSyncToken`, `NumberOfMatchesWithinLimits`, `PropfindFiniteDepth`, `ValidFilter`,
  `ResourceMustBeNull`, `CannotModifyProtectedProperty`, `SharingNotAllowed`, `InvalidSharee(Href)`, `FeatureNotEnabled`
  (ADR-0011: a refinement of `conflict`, 409 on the API and 403 on DAV), `NameReserved`, `ExternalRefReserved`,
  `AddressReserved` (2.10).
* `ports::StoreError` (`#[non_exhaustive]`: a `match` outside `davhaven-ports` needs a catch-all arm) `{ NotFound,
  UniqueViolation(UniqueKey), PreconditionFailed, SerializationFailure, Unavailable, Timeout, InvalidSyncToken (a token the
  store cannot resume: another epoch, below the minimum sequence, from the future; never the `PreconditionFailed` of a stale
  `If-Match`), LeaseLost (the caller no longer holds the lease it tried to settle: nothing changed, it drops its result),
  Unsupported (an additive port method the adapter has not overridden), InvalidData(String) (text with U+0000, which both
  adapters refuse alike), Internal(String) }`, `UniqueKey { CalendarSlug, ObjectUri, ObjectUid, ExternalKey, BindingSlug,
  PrincipalName, Address, … }`.
* `ports::PortError { kind: PortErrorKind { Unavailable, Timeout, Rejected, Invalid, Unsupported, Internal },
  message }`, `ports::HandlerError` (`#[non_exhaustive]`) `{ Retryable(..), Permanent(..), Defer { after, reason } }` (2.11),
  `ports::PluginError`.
* `ical::IcalError { Invalid(String), Limit(LimitKind), Unsupported(String) }`.
* `app::AppError { kind: ErrorKind, precondition: Option<Precondition>, public_message: SafeMessage, source }`,
  `AppError::unsupported()`; `From<StoreError>`, `From<PortError>` and `From<IcalError>` convert into it.
* `wire::ProblemCode` (one per row of the problem catalog, which `cargo xtask problems-docs` renders to `docs/problems.md`: HTTP status, DAV status + precondition element, MCP form);
  mapping tables live in `dav`, `api`, `mcp` and are tested exhaustively. Internal error text never leaves the server.

**F0.5 Application API** (`davhaven-app::services`; every method `async`, first argument `&RequestContext`,
returns `Result<_, AppError>`; DTOs live in the same module):

| Trait | Methods (key types) |
| --- | --- |
| `AuthService` | `authenticate(AuthRequest { channel, tenant_hint, credential: PresentedCredential { Basic, Bearer, Feed, Rsvp }, client_ip, request_id }) -> RequestContext` |
| `TenantService` | `list(Page)`, `get(slug)`, `upsert(TenantSpec)`, `patch`, `delete` |
| `PrincipalService` | `list(PrincipalFilter, Page)`, `get(name)`, `upsert(PrincipalSpec, If)`, `patch`, `delete(DeleteOptions)`, `set_members(group, Vec<PrincipalName>)`, `add_member`, `remove_member`, `search(PrincipalSearch { query, limit, kinds, criteria, any_of }) -> Vec<PrincipalHit>`, `find_principals(PrincipalSearch) -> PrincipalSearchResult { hits, truncated }`, `dav_properties(path) -> PrincipalProps`, `resolve_address(addr) -> AddressClass` |
| `CalendarService` | `list_home(principal) -> Vec<BindingView>`, `get_collection(ResourcePath) -> CollectionView`, `mkcalendar(MkCalendar)`, `upsert(CalendarSpec, If)`, `delete_collection(ResourcePath, If)`, `proppatch(ResourcePath, PropPatch) -> PropPatchOutcome`, `list_tenant(CalendarFilter, Page)` |
| `ObjectService` | `get(ResourcePath) -> ObjectView`, `put(PutRequest { path, body, content_type, preconditions: WritePrecondition { if_match, if_none_match, if_schedule_tag_match }, schedule_reply }) -> PutOutcome { etag: Option<ETag>, schedule_tag, created, schedule: ScheduleOutcome }`, `delete(DeleteRequest) -> DeleteOutcome`, `move_to(MoveRequest) -> MoveOutcome`, `multiget(collection, Vec<ResourcePath>, CalendarDataSpec)`, `query(collection, ObjectFilter, CalendarDataSpec) -> Vec<ObjectHit>`, `sync(collection, Option<SyncToken>, limit) -> SyncResult`, `batch(calendar, BatchRequest) -> BatchResult`, `get_by_key`, `put_event(calendar, EventWrite)`, `delete_by_key`, `list(calendar, ObjectFilter, Page)` |
| `SharingService` | `share(ResourcePath, ShareRequest) -> Vec<ShareItemResult>`, `reply_invite(home, InviteReply) -> SharedAs`, `list_grants`, `put_grant(GrantSpec, If)`, `delete_grant`, `list_notifications(principal)`, `get_notification`, `delete_notification`, `delete_notification_if(path, WritePrecondition)` |
| `SchedulingService` | `free_busy(FreeBusyRequest) -> FreeBusyResult`, `find_free_slots`, `outbox_post(principal, body) -> ScheduleResponse`, `inbox_list/get/delete`, `inbox_get_many(inbox, paths, CalendarDataSpec) -> Vec<InboxEntry>`, `respond(ObjectRef, Response)`, `inbound_itip(InboundItip) -> InboundOutcome`, `rsvp_page(token) -> RenderedPage`, `rsvp_answer(token, RsvpAnswer, CsrfToken) -> RenderedPage` |
| `CredentialService` | `app_passwords: create/list/revoke`, `api_tokens: create/list/revoke`, `feed_tokens: create/list/revoke/rotate`, `client_config(ClientConfigKind, ClientConfigRequest) -> ClientConfigResponse` |
| `FeedService` | `render(token, Conditional) -> FeedResponse` |
| `WebhookService` | `create/list/get/patch/delete`, `rotate_secret`, `ping`, `deliveries(Page)`, `redeliver` |
| `ExternalAccountService` | `providers()`, `start(provider, principal) -> AuthorizationUrl`, `complete(provider, CallbackParams) -> RenderedPage`, `list`, `delete` |
| `AuditService` | `list(AuditFilter, Page)` |
| `OutboxService` | `list_dead(Page)`, `retry(OutboxId)` |
| `IdempotencyService` | `begin(IdempotencyKey, fingerprint) -> IdempotencyState`, `complete(..)`; the fenced pair `reserve(..) -> Reserved` (a `Reservation` is the proof of a claim: the end of its lease) and `settle(Reservation, Settlement)`, which the API layer uses (ADR-0012; the provided methods call `begin` and `complete`, so a service that implements only the first pair keeps working, unfenced) |
| `AssetService` | `get(ctx, theme, file) -> StaticAsset`: the static file of a theme for the web surface, from the first theme of its layers (2.14) that has it, the built-in one last, plain names only (ADR-0010); `unavailable_page(ctx, status, languages) -> RenderedPage`: the `rsvp_unavailable` page of a failed web route (2.13) |

`AppServices` is a struct of `Arc<dyn …>` for every trait plus `PublicUrls` and limits; it is the only state a
protocol router receives. `app::build(AppDeps) -> AppServices` wires the real implementations; `app-fake` provides
`AppServices::fake()` covering principals, calendars, objects and auth with simple semantics.

**F0.6 Port traits** (`davhaven-ports`, all `Send + Sync`, `#[async_trait]`):

| Port | Methods (key types) |
| --- | --- |
| `Clock` | `now() -> DateTime<Utc>` |
| `IdGenerator` | `new_id() -> Uuid`, `random_bytes(len) -> Vec<u8>` |
| `KeyRing` | `sign(KeyPurpose, &[u8]) -> Signature { kid, mac }`, `verify(KeyPurpose, &[u8], &Signature) -> bool`, `active_kid(KeyPurpose)`; purposes: CredentialPepper, Rsvp, Csrf, Cursor, CacheKey |
| `SecretSealer` | `seal(&[u8], &SealAad { tenant, table, row, purpose }) -> Sealed`, `open(&Sealed, &SealAad) -> SecretBytes` |
| `CredentialHasher` | `hash(CredentialKind, &SecretStr) -> StoredHash`, `verify(&StoredHash, &SecretStr) -> bool` |
| `HttpClient` | `send(OutboundRequest { method, url, headers, body, purpose: HttpPurpose { Webhook, OAuth, ProviderApi } }) -> OutboundResponse` (policy enforced inside, caps and timeouts per purpose), `validate_url(&Url)` (what `send` would accept, checked at registration; the default answers `Unsupported`, which the application treats as an error: ADR-0009) |
| `Database` | `begin(TenantId, TxMode) -> Box<dyn Tx>`, `begin_system() -> Box<dyn SystemTx>`, `health()` |
| `Tx` | `tenant()`, `principals()`, `memberships()`, `calendars()`, `bindings()`, `properties()`, `grants()`, `objects()`, `changes()`, `notifications()`, `inbox()`, `credentials()`, `rsvp()`, `outbox()`, `webhooks()`, `external_accounts()`, `oauth_states()`, `idempotency()`, `audit()` (each `&mut dyn XRepo`), `commit(self: Box<Self>)`; drop = rollback, so every transaction that succeeded commits, reads included |
| `SystemTx` | `tenants()` (+ `append_audit(NewTenantAudit)`: the two audit events of tenant management, in the transaction of the change, 2.4), `credential_lookup()` (`find_by_prefix(kind, prefix)`, `create_system_token`), `outbox_claim()` (`claim(limit, lease) -> Vec<OutboxRecord>`, `complete`, `fail`, `release_leases`, and the fenced `complete_claimed`, `fail_claimed`, `defer_claimed`, `release_claimed`), `retention()` (`purge_audit_checked`, `purge_deliveries`, …), `commit` |
| `ObjectRepo` | `get(cal, uri)`, `get_by_uid`, `get_by_external_key`, `find_scheduling_uid(owner, uid)`, `put(cal, NewVersion, Expected) -> WriteResult { object_id, seq, etag, created }`, `delete(cal, uri, Expected) -> u64`, `move_to(src, uri, dst, dst_uri) -> (u64, u64)`, `query(cal, IndexFilter, PageReq)`, `list(cal, PageReq)`, `attendees(object)` |
| `CalendarRepo` | `get`, `get_by_slug(owner, slug)`, `list_owned(owner)`, `create`, `update(Calendar, version)`, `soft_delete`, `lock(&[CalendarId])`, `touch(cal) -> u64` |
| `ChangeRepo` | `since(CollectionKey, epoch, seq, limit) -> ChangeBatch { changes, current, truncated }`, `touch_home/inbox/notifications(principal)` |
| Other repos | CRUD by id and natural key with optimistic `version`: `PrincipalRepo` (+ `find_by_address`, `search(PrincipalQuery { text, kinds, limit, criteria, any_of })`), `MembershipRepo` (`set_members`, `groups_of`), `BindingRepo`, `PropertyRepo`, `GrantRepo` (`for_calendar`, `for_grantee`), `NotificationRepo` (+ `get_many_by_uri`), `InboxRepo` (+ `get_many_by_uri`), `CredentialRepo` (app passwords, API tokens, feed tokens, `touch_last_used` batch, `rehash`: swap a hash while it still names the old pepper key), `RsvpRepo`, `OutboxRepo` (`enqueue(OutboxMessage)`), `WebhookRepo` (+ deliveries), `ExternalAccountRepo`, `OAuthStateRepo`, `IdempotencyRepo`, `AuditRepo` (`append`, `list`) |
| `MailTransport` | `send(&OutgoingMail) -> SendReceipt` |
| `TemplateRenderer` | `render(RenderRequest { template: TemplateName, locale, theme, model: serde_json::Value }) -> Rendered { subject, html, text }`, `catalog() -> Vec<TemplateName>`, `asset(theme, file) -> Option<ThemeAsset>` (a static file of a theme with its media type and a strong ETag; a theme that lacks it falls back through the layers of 2.14, the built-in theme last: ADR-0010) |
| `Authenticator` (chain) | `authenticate(&PresentedCredential, &AuthHint) -> AuthOutcome { Accepted(Authenticated), Rejected(Reason), NotApplicable }` |
| `RateLimiter` | `check(&RateKey, cost: u32) -> RateDecision { allowed, retry_after, remaining }`; the failure backoff of authentication is part of the port (2.6, ADR-0012) |
| `EventSink` (set) | `name()`, `deliver(&Envelope) -> Result<(), HandlerError>` |
| `OutboxHandler` (set) | `kind() -> &'static str`, `handle(&OutboxRecord) -> Result<(), HandlerError>`, `limits_attempts() -> bool` (2.11) |
| `Provider` (set) | `name()`, `display_name()`, `enabled()` (the deployment's switch, `providers.<name>.enabled`), `oauth() -> &dyn OAuthProvider`, `calendars() -> &dyn RemoteCalendarApi` |
| `OAuthProvider` | `authorize_url(state, pkce_challenge, redirect)`, `exchange(code, verifier, redirect)`, `refresh(token)`, `revoke(token)`. Errors by kind: `Rejected` from `refresh` is only "the refresh token is no longer valid" (`invalid_grant`) and switches an account off; `Invalid` is "the provider refuses the client of the deployment" (`invalid_client`, an expired or rotated secret) and switches nothing off |
| `RemoteCalendarApi` | `list_calendars(token) -> Vec<RemoteCalendar { remote_id, display_name, color, primary }>`, `changes_since(token, cal, cursor) -> RemoteChanges { changes: Vec<RemoteChange { remote_id, etag, ics: Option<String> }>, cursor, snapshot }` (a snapshot lists every event **within the window the adapter reads**, so the engine deletes what the snapshot does not name), `upsert`, `delete` (`Unsupported` in 1.0). `Unsupported` from `changes_since` is "the calendar is beyond what the adapter imports" |
| `ContentScanner` (set) | `scan(&[u8], ScanContext) -> ScanVerdict { Clean, Infected(String) }` |
| `SchedulingPolicy` | `auto_add(&Invite) -> bool`, `resource_reply(&ResourceRequest, &FreeBusy) -> Option<PartStat>`, `external_allowed(tenant, &CalendarUserAddress) -> bool` |
| `Worker` | `name()`, `interval()`, `tick() -> WorkReport`, `run(CancellationToken)` |
| `Lifecycle` (optional) | `health() -> Health`, `shutdown()` |

`OutboxMessage` (`#[non_exhaustive]`, serde-tagged, versioned): `Imip(ImipJob)`, `InternalDelivery(DeliveryJob)`,
`Webhook(WebhookDelivery)`, `DomainEvent(Envelope)`, `ProviderPush(Reserved)`. `ports::observe(port, op, fut)`
records the latency histogram, outcome counter and span; every adapter method wraps its body in it.

**Store contract refinements** (ADR-0006). These items refine the first definition of the store ports; read them as part
of the contract. Changes of **meaning**:

| Item | Meaning |
| --- | --- |
| `ObjectIndex::may_overlap`, `TimeRange::may_overlap`, `ObjectRepo::query` | the range is closed at both ends, one definition `interval_may_overlap` (2.7) |
| `CalendarRepo::soft_delete` | also deletes every binding of the calendar (the owner's and the sharees') and logs a `delete` in each affected home; the application must not list or delete bindings afterwards (it would get `NotFound`) |
| `CalendarRepo::lock` | refuses (`Internal`) in a read-only transaction (PostgreSQL refuses row locks there) |
| `OutboxQueue::complete`, `fail` | only an **in-flight** record can be settled, else `StoreError::LeaseLost` (`NotFound` for a missing one); the fenced variants `complete_claimed` and `fail_claimed` also check the claim |
| `IdempotencyRepo::claim` | an in-flight key is **taken over after its lease** (default ten minutes); `claim_with_lease` is required and `claim` provided; the leased variants fence `complete` and `release` |
| `InboxRepo::create`, `delete` | **quarantined** items never move the inbox's token and are not logged |
| `WebhookRepo::update`, `create_delivery` | `update` does not write `failure_count` (the dispatcher owns it: `record_success`, `record_failure`; re-enabling resets it) and keeps event types this release does not know; `create_delivery` returns the existing record for a repeated `(subscription, event)` |
| `RsvpRepo::record_use` | stamps `last_used_at` and also bumps `version` and `updated_at` |
| `ChangeRepo::since` | an unusable token is `StoreError::InvalidSyncToken`; `PreconditionFailed` keeps its single meaning, a stale version |
| `ObjectRepo::delete` with `Expected::Etag` on a missing object | `PreconditionFailed` (RFC 9110: `If-Match` is false when nothing exists); `Any` and `Absent` stay `NotFound` |
| `RetentionRepo::purge_audit` without the privilege | removes nothing and returns `0`; `purge_audit_checked` answers `AuditPurge::NotPermitted` (2.18) |
| `StoreError`, `TxMode` | `#[non_exhaustive]`; `TxMode` gained `Snapshot` (`REPEATABLE READ`, read-only) |
| Transactions | one per task, never two at once (2.7) |

**Additive methods and types** (a new method has a default body, and most answer `StoreError::Unsupported`, while
`defer_claimed` counts the claim like a failure and `purge_audit_checked` calls `purge_audit`, which the adapters override):
`ObjectRepo::list_index`,
`query_index` (heads without the iCalendar text, `ObjectHead`), `uri_for_uid`, `uri_for_scheduling_uid`;
`OutboxQueue::complete_claimed`, `fail_claimed`, `defer_claimed`, `release_claimed` (`OutboxClaim`, `OutboxRecord::claim`);
`IdempotencyRepo::claim_leased`, `complete_leased`, `release_leased` (`LeasedClaim`); `RetentionRepo::purge_audit_checked`
(`AuditPurge`), `purge_deliveries`; `SystemTenantRepo::append_audit`; `CredentialRepo::rehash` (`Rehash`: the compare-and-set swap
of the keyed hash of a credential under another pepper key, in a tenant transaction because system scope may not overwrite a
credential hash); `davhaven_ports::store::{micros, lease_end}`; in `ports::testing` `FaultyDatabase`, which fails commits and
begins on demand so that the application's retry can be tested, and `RollbackWatch`, which records the transactions that end
without a commit. The storage adapter exports `migrate::purge_audit`, which
`davhaven admin purge-audit` calls (2.18).

**F0.7 Plugin registry API** (`davhaven-ports::plugin`):

```
PluginRegistry::register::<P>(&mut self, kind: PortKind<P>, d: PluginDescriptor<P>) -> Result<(), PluginError>
PluginRegistry::{names(kind), schemas() -> Vec<PluginSchema>, dedicated_table(kind, name), dedicated_tables(), check_table(..),
                refused_in_production(kind, name)}
PluginRegistry::build_single / build_chain / build_set(kind, names, &PluginContext, &ConfigTree) -> Built<P>
PluginDescriptor<P> { name: &'static str, description: &'static str, config_schema: fn() -> Schema,
                      build: fn(PluginContext, serde_json::Value) -> BoxFuture<'static, Result<Built<P>, PluginError>>,
                      dedicated_table: Option<&'static str>,   // the table of its own, e.g. "security.auth"
                      check: Option<fn(&PluginCheck) -> Result<Vec<String>, PluginError>>,   // config check, builds nothing
                      refused_in_production: bool }  // a fake or memory adapter: the registry refuses to build it
Built<P> { port: Arc<P>, lifecycle: Option<Arc<dyn Lifecycle>>, workers: Vec<Arc<dyn Worker>> }
PortKind: DATABASE, MAIL_TRANSPORT, TEMPLATES, HTTP_CLIENT, RATE_LIMITER, SCHEDULING_POLICY (single);
          AUTHENTICATOR (chain); EVENT_SINK, OUTBOX_HANDLER, PROVIDER, CONTENT_SCANNER (set)
PluginContext { clock, ids, keyring, sealer, hasher, http: Option<..>, database: Option<..>, mode: RunMode,
                failure_backoff: FailureBackoff }   // [security.auth]; the limiter is built with it (2.6)
```

`PluginDescriptor`, `PluginCheck` and `PluginSchema` are `#[non_exhaustive]`: they are built with `PluginDescriptor::new(..)`
and the `const` builders `with_dedicated_table`, `with_check` and `with_refused_in_production`, so a member added later does not break
a plugin crate (4.4). `register` refuses a table that another descriptor names, whatever the kind, and `plugin`,
`plugins` and the tables under them (`PluginError::DuplicateTable`, `InvalidTable`).

A registry introspection test asserts every selectable kind has at least two implementations (or one plus a
documented empty set) and that the default config resolves.

**F0.8 Wire types** (`davhaven-wire`): `Page<T>`, `Cursor`, `ProblemDetails`, `ProblemCode`, `EventView`,
`CalendarView`, `PrincipalView`, `GrantView`, `MembershipSet`, `AppPasswordCreated`, `ApiTokenCreated`,
`FeedTokenCreated`, `ClientConfigGeneric`, `BatchRequest`, `BatchResult`, `ChangesResponse`, `WebhookView`,
`DeliveryView`, `ExternalAccountView`, `AuditEventView`, `OutboxItemView`, `WebhookEnvelope`, MCP tool
input/output structs. `xtask contracts` exports `openapi.json`, `mcp-tools.json`, `events.schema.json`.

**F0.9 Configuration keys.** [`configuration.md`](configuration.md) is the generated reference of every key, type and
default (`cargo xtask config-docs`) and is the authority; this section only fixes the layout. Each crate owns the struct
of its table; `server` holds `[plugin.*]` as passthrough. The tables are `[server]` (mode, public base URL, trusted
proxies, listeners, HTTP limits, shutdown timings, connection cap), `[database]`, `[plugins]` (the adapter chosen for each
port), `[plugin.<kind>.<name>]` (adapter-specific settings), `[mail]`, `[templates]`, `[scheduling]`, `[sharing]`,
`[limits]` (2.15), `[security]` (key ring, authentication, egress policy, CORS, profile signing, MCP token lifetime),
`[retention]` (2.18), `[webhooks]`, `[outbox]`, `[feeds]`, `[mcp]`, `[providers]` (the providers' tables and the sync
engine's table `[providers.sync]`; a provider plugin cannot be called `sync`) and `[observability]`.

**F0.10 OpenAPI resources** (`/api/v1`; every path is registered whatever features are enabled; scope in brackets):

| Path | Methods |
| --- | --- |
| `/tenants`, `/tenants/{tenant}` | GET list; PUT, GET, PATCH, DELETE [system:tenants; GET also principals:read] |
| `/tenants/{tenant}/principals` | GET (`external_ref`, `kind` filters) [principals:read] |
| `/tenants/{tenant}/principals/{principal}` | PUT, GET, PATCH, DELETE [principals:write / read] |
| `…/principals/{group}/members`, `…/members/{member}` | PUT (full set), GET; PUT, DELETE [principals:write] |
| `…/principals/{principal}/app-passwords`, `…/{id}` | GET, POST; DELETE [credentials:write] |
| `…/principals/{principal}/feed-tokens`, `…/{id}`, `…/{id}/rotate` | GET, POST; DELETE; POST [credentials:write] |
| `…/principals/{principal}/bindings`, `…/bindings/{binding}/restore` | GET; POST [calendars:write] |
| `…/principals/{principal}/client-config/generic` | GET [principals:read] |
| `…/principals/{principal}/client-config/{apple-mobileconfig,davx5}` | POST [credentials:write] |
| `…/principals/{principal}/calendars`, `…/calendars/{calendar}` | GET; PUT, GET, PATCH, DELETE [calendars:read / write] |
| `…/calendars/{calendar}/grants`, `…/grants/{grantee}` | GET; PUT, DELETE [calendars:write] |
| `…/calendars/{calendar}/objects` | GET (range, external_key) [events:read] |
| `…/calendars/{calendar}/objects/batch` | POST [events:write] |
| `…/calendars/{calendar}/objects/by-key/{external_key}` | GET, PUT, DELETE [events:read / write] |
| `…/calendars/{calendar}/changes` | GET [events:read] |
| `/tenants/{tenant}/calendars` | GET search [calendars:read] |
| `/tenants/{tenant}/api-tokens`, `…/{id}` | GET, POST; DELETE [credentials:write] |
| `/tenants/{tenant}/webhooks`, `…/{id}`, `…/{id}/rotate-secret`, `…/{id}/ping`, `…/{id}/deliveries`, `…/deliveries/{delivery}/redeliver` | GET, POST; GET, PATCH, DELETE; POST; POST; GET; POST [webhooks:manage] |
| `/tenants/{tenant}/providers`, `/tenants/{tenant}/external-accounts`, `…/{id}` | GET; GET, POST; DELETE [providers:manage] |
| `/tenants/{tenant}/audit-events` | GET [audit:read] |
| `/tenants/{tenant}/outbox`, `…/{id}/retry` | GET (status filter); POST [outbox:manage] |
| `/tenants/{tenant}/itip/inbound` | POST [itip:inbound] |

Each operation carries `x-required-scope`; matrix cases are generated from it.

**F0.11 Test harness interfaces.** `TestApp::builder().store(Memory|Postgres).clock(ManualClock).ids(SeqIds)
.config(..).build()` with handles `dav(&Actor)`, `api(&Token)`, `mcp(&Token)`, `feed(token)`, `rsvp()`, `mails()`,
`events()`, `clock().advance(d)`, `run_workers_until_idle()`; `Transport` trait (in-process `oneshot` / reqwest
base URL); `FixtureWorld` (two tenants, owner, group member, sharees, other user, suspended user, service principals
(without grants, granted the group and managed calendars, granted the managed calendar with `read_write`),
personal/group/managed/shared/mirror calendars, one event of each kind, constant names); `Operation`/`Surface`/
`Expectation` enums and the expectations file format; scenario YAML schema and `run_scenario` signature;
`port_tests::<port>::run_all(factory)` entry points.

### 4.2 Acceptance criteria by area

What the tests of each area must show, in addition to the common requirements of 4.3.

| Area | Crates / modules | Acceptance criteria |
| --- | --- | --- |
| Storage | `store-postgres` (migrations, RLS), `store-memory`, `port-tests::store` | Store contract suite green on both adapters: foreign tenant → NotFound for every method, typed unique violations, write invariant (seq exactly once per mutation, linearizable visibility), rollback incl. outbox, SKIP LOCKED claims, cursor stability, infinity `last_end`; upgrade test harness |
| iCalendar | `ical`, `testdata/corpus`, `crates/fixtures/data/itip` golden files | Corpus round trips; leniency rules (Windows TZIDs, LF, missing VTIMEZONE, zero-length DTEND); limits enforced; RFC 4791 §9.9 vectors; metamorphic expansion props; iTIP diff golden set; never-panic proptest; fuzz targets |
| DAV core | `dav::{router, xml, props, methods, reports, sync, discovery, errors}` | OPTIONS/DAV header, PROPFIND/PROPPATCH (binding props), GET/PUT/DELETE/MOVE/COPY with preconditions, MKCALENDAR + extended MKCOL, calendar-query, multiget, sync-collection, free-busy-query, expand-property (proxy props empty), current-user-privilege-set, well-known, Prefer/Brief; precondition mapping table exhaustive |
| DAV collaboration | `dav::{sharing, notifications, scheduling, principals_search}` | CS:share / invite-reply / notifications fixtures, inbox/outbox, Schedule-Tag headers, principal-property-search and calendarserver-principal-search, bound collections |
| Application core | the `app` modules for calendars, objects, sharing, principals, provisioning, managed calendars, feeds, credentials, idempotency, audit and authz (F0.2) | All service methods implemented; authz facts in one query; batch semantics; idempotency; audit in the transaction; L3 tests incl. API↔DAV equivalence |
| Scheduling | `app::{scheduling, itip, rsvp, inbound, addresses, policy}` | The rules of 2.8; one `ItipProcessor` path; RSVP; inbound; default policy; scheduling matrix green |
| Edge, API, web, auth | `http`, `api`, `web`, `auth-local`, `crypto-local`, `ratelimit-memory`, `wire`, `openapi.json` | All F0.10 operations; idempotency layer; problem mapping exhaustive; credential formats; verification cache; backoff; RSVP page (WCAG, CSP); feeds; client config; OpenAPI client generation smoke (Java + TypeScript) |
| Mail, hooks, egress | `mime`, `mail-smtp`, `mail-memory`, `templates`, `hooks-webhook`, `http-egress`, `app::{outbox, imip}` | MIME structure snapshots; templates × locale × theme strict render; dispatcher (lease, backoff, dead, circuit breaker); Standard Webhooks with reference verifier; SSRF table (ranges, encodings, IPv6, redirects, rebinding) |
| MCP | `mcp` | All tools with schemas, annotations, snapshots; Origin check; scope rules; conformance test with an independent MCP client |
| Providers | `provider-google`, `provider-microsoft`, `provider-fake`, `app::{sync_engine, oauth}` | OAuth PKCE flow; pull import into a mirror calendar; recorded-HTTP tests; disabled provider → routes 409, no workers |
| Server, operations | `server`, `app::{retention, workers}`, `Dockerfile`, `deploy/`, `.github/workflows/release.yml`, `docs/operations/` | CLI subcommands; listeners; config validation; workers spawn/shutdown; healthcheck; image hardening; alert rules + dashboard; `docs/configuration.md` generated |
| Conformance | `fixtures`, `testkit`, `it`, `conformance`, `app-fake`, `testkit/matrix/expectations.toml` | Matrix and scheduling harness, flow runner, ported ccs-caldavtester/python-caldav scenarios, staging run against an ephemeral tenant, capture converter |

### 4.3 Common requirements

Every change meets these before it merges:

* CI is green, including `--all-features` and `--no-default-features`.
* No `AppError::Unsupported` is left in the modules the change completes (the `unsupported` job warns, and is an error
  on a release tag).
* Tests exist at the levels of 3.1 that apply, and matrix rows exist for the operations the change adds or alters.
* Rustdoc is complete, and user-facing behaviour is documented in `docs/` (`interop.md`, the generated configuration
  and problem references).
* No dependency is added outside `[workspace.dependencies]`.

### 4.4 Change control

Contracts (the F0 items, the port and service traits, the wire types, the generated documents) change additively:
`#[non_exhaustive]` enums, new trait methods with a default body returning `Unsupported`, new optional fields.
A change that is not additive says so in its pull request, updates this document and the ADR it touches, and is
acceptable only while the workspace is the only user of the interface (before 1.0); afterwards it needs a deprecation
path (`Deprecation`/`Sunset` on the API, a new tool name on MCP). A struct that adapters build and the application only
reads may become `#[non_exhaustive]` with constructors (`RemoteCalendar`, `RemoteChanges`): that breaks struct literals
and exhaustive patterns outside the crate, so the pull request calls it out instead of calling it additive.

Schema changes are new migration files in `crates/store-postgres/migrations/` (R16). The generated documents
(`docs/openapi.json`, `docs/contracts/**`, `docs/configuration.md`, `docs/permission-matrix.md`, `docs/problems.md`)
are regenerated with `cargo xtask`, never edited by hand; CI checks that they are current.

### 4.5 Release and CI/CD

* CI runs on GitHub-hosted runners, or on the runners named by `vars.CI_RUNS_ON` for this repository's own branches and
  main; fork and Dependabot PRs never run on self-hosted runners (R18); no `pull_request_target`; top-level
  `permissions: {}`; actions pinned by SHA; `persist-credentials: false`.
* `release.yml`, called by `ci.yml` on main (and started by `v*` tags, after a check that the checks and the tests of the tagged commit succeeded) after the checks and the tests of the same commit: build once,
  smoke-test that image, push `ghcr.io/${{ github.repository_owner }}/davhaven:main-<sha>` and
  version tags; outputs the digest. The release does not sign images or produce SBOMs or provenance attestations: delivery is
  build once, smoke test, push, report the immutable digest. Deployment is not part
  of this repository: an optional `repository_dispatch` with the digest notifies a deployment repository
  (`vars.DEPLOY_DISPATCH_REPO`), whose protected environments gate staging and production.
* Dependabot: cargo weekly (minor+patch grouped, majors separate, cooldown 7 days), GitHub Actions grouped (SHA
  pins), Docker digests of the Dockerfile; the images of the jobs (`container:`, `services:`, BuildKit) are pinned by digest too, which
  Dependabot does not read, so the weekly `image-pins.yml` fails when one points to a tag that moved and shows the patch in its summary
  (`scripts/image-pins.sh update` makes it; a person lands it as a pull request, the job opens none: it reads the repository and
  nothing more). GHCR retention workflow keeps release tags, the last 30 `main-*` images and every
  version younger than 30 days, whatever their tags; it needs nothing from the deployment repository. A run started by hand is
  a dry run unless the input says otherwise, and it refuses to delete every version of the package or more than 100 at once.
  It takes its runner from `vars.CI_RUNS_ON` like the other jobs and falls back to a hosted runner (R18): its token is the
  `GITHUB_TOKEN` of the job, scoped to the job and expiring with it, and the image job of `release.yml` holds `packages: write` on
  the same runners already. The consequence for a deployment is the one of every pinned digest: an image of a `main-*` build that
  is neither among the newest 30 nor younger than 30 days is gone from the registry, so a deployment that must be able to pull
  its image for longer runs a release (a `v*` tag) or redeploys within that window.

## 5. Design decisions

Decisions that depart from the obvious choice, each with the section that describes it. Longer rationales are ADRs in
[`adr/`](adr/README.md).

| Topic | Decision | Where |
| --- | --- | --- |
| Tenant isolation | Composite primary and foreign keys plus row-level security, with the application answering 404 for anything a caller may not see; RLS is a second line of defence, not a boundary against arbitrary SQL | 2.4, 2.6, ADR-0005 |
| Authorization | One pure decision function (`decide`) used by every protocol; protocol crates never decide; the test oracle is independent of it | 2.6, 3.2 |
| Consistency | The store enforces the write invariant (one `sync_seq` bump and one change row per mutation); sync tokens and CTag are the same string | 2.7, ADR-0003 |
| iCalendar handling | `calcard` wrapped entirely in `ical`; client bytes are stored verbatim and re-serialised only when the server changes an object | 2.2, 2.7, ADR-0001 |
| Credentials | Keyed hashes (HMAC with a rotating pepper) instead of a slow hash, a short-lived verification cache, and no hard lockout (exponential backoff per login and address) | 2.6, ADR-0012 |
| RSVP links | Derived from the key ring and the token id, so a retried mail carries the same link while the outbox keeps no credential | 2.6, ADR-0007 |
| Impersonation | No on-behalf-of delegation or per-request impersonation in 1.0; principal tokens act as their own principal | 2.6, 2.12 |
| Webhooks | Standard Webhooks signing instead of a custom header scheme | 2.11, ADR-0009 |
| Audit log | Append-only for the runtime role; the purge runs outside the server with owner rights | 2.4, 2.18, ADR-0005 |
| Alarms | Alarms are shared per event; acknowledge/snooze-only writes from read-only bindings return 204 without storing; a per-user overlay would change the ETag and change-log model and is in the backlog | ADR-0004, ROADMAP |
| Attachments | No managed attachments (RFC 8607) in 1.0; inline binary `ATTACH` up to 256 KiB, optionally scanned by a `ContentScanner` | 1.1, 2.15, ROADMAP |
| Group invitations | Group addresses are not expanded in 1.0 (`SCHEDULE-STATUS` 3.7) | 1.1, 2.8 |
| Plugins | The registry selects adapters only for ports a deployment chooses; clock, ids and key-handling ports are injected directly | 2.3, ADR-0002 |
| Rate limiting | In-process limiter for a single instance; a shared limiter is a backlog item | 1.1, 2.17 |
| SQL | sqlx runtime-checked queries instead of `query!` macros, so there is no offline query cache | 2.2 |
| OpenAPI | Generated from the code with `utoipa`, every route registered whatever features are enabled, so the document does not depend on the build | 2.2, 2.10, ADR-0011 |
| Test crates | Separate `fixtures`, `port-tests` and `testkit` crates instead of per-crate `testing` features (the `ports` fakes excepted), which avoids dev-dependency cycles | 2.1, 3.1 |
| Coverage | Measured on main and nightly with ratcheted per-crate floors; a diff gate on pull requests is not in place | 3.7 |
| CI runners | GitHub-hosted runners by default; self-hosted runners only for the repository's own branches and main | 4.5, R18 |
