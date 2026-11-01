# Operations runbook

This page is for the people who deploy and run Davhaven: what the process is made of, how to start, stop and upgrade
it, what to look at, and what to do when an alert fires. The related pages are
[`configuration.md`](../configuration.md) (every key, generated from the code), [`database.md`](database.md) (roles,
migrations, tenant isolation), [`keys.md`](keys.md) (the key ring and its rotation) and [`backup.md`](backup.md)
(backup, restore and what a restore needs afterwards). The design is described in [`PLAN.md`](../PLAN.md); the
rules behind it are R3, R6 and R8 of [`ENGINEERING_RULES.md`](../ENGINEERING_RULES.md).

Davhaven is deployed from a container image. This repository contains no deployment: the hosts, the secrets, the reverse
proxy and the deployment pipeline are yours.

## The process

One binary, `davhaven`, one process per instance. It serves up to three HTTP listeners, runs its background workers
and exits cleanly on `SIGTERM`.

| Listener | Default bind | Route groups | Who reaches it |
| --- | --- | --- | --- |
| `public` | `0.0.0.0:8080` | `wellknown`, `dav`, `web` | Calendar clients and browsers (RSVP pages, feeds), behind the reverse proxy |
| `internal` | `127.0.0.1:8081` | `api`, `mcp` | Integrations: the management API and MCP, on a private network |
| `ops` | `127.0.0.1:9090` | `ops` | Orchestrator and monitoring: `/healthz`, `/readyz`, `/metrics`. Never on the internet |

The `internal` and `ops` listeners bind the loopback interface until the configuration says otherwise
(`server.listeners.<name>.bind`), so a deployment has to name the addresses it wants to publish. A route group is served
by exactly one listener; merging everything onto one address is a list of all six groups
([Listeners](../configuration.md#listeners)). There is no TLS in the process: the reverse proxy terminates it and
sets `X-Forwarded-For`, which the server believes only from the networks in `server.trusted_proxies`. Links in mails
and feeds come from `server.public_base_url`, never from the `Host` header.

Background workers (all safe to run on several instances; the only per-instance state is the in-memory rate limiter, which counts
the requests of its own instance):

| Worker | Does | Interval |
| --- | --- | --- |
| `outbox` | Delivers mail, webhooks, invitations and domain events; retries with backoff; dead-letters | `outbox.poll_interval` (2 s) |
| `retention` | Removes expired data and publishes the audit gauges (see [Retention](#retention)) | 5 minutes |
| `profile_signing` | With `[security.profile_signing]`: keeps the signer of Apple profiles current with its files and publishes the end of its certificate ([`keys.md`](keys.md#the-certificate-that-signs-apple-profiles)) | 1 minute |
| `auth_last_used` | Writes the `last_used_at` of credentials in batches | `security.auth.last_used_flush` (15 minutes) |
| `provider_sync` | With calendar providers on: pulls the connected provider accounts that are due ([Calendar providers](#calendar-providers)) | `providers.sync.poll_interval` (1 minute) |

## Configuration

One TOML file (`--config <path>` or `DAVHAVEN_CONFIG`) and `DAVHAVEN_*` environment variables, the variables winning.
`__` separates nested keys: `DAVHAVEN_DATABASE__MIGRATION_URL_FILE` is `database.migration_url_file`. Every secret has a
`*_file` variant, and the container is usually configured by the environment and secret files alone. **Unknown keys and
unknown `DAVHAVEN_*` variables fail the start**, naming the key. The reference of every key is
[`configuration.md`](../configuration.md).

```sh
davhaven --config /etc/davhaven/davhaven.toml config check
```

`config check` (with `--explicit`, only the settings the file and environment give) validates every table, parses the table of every selected adapter, reads every secret file (a missing or
too short key file fails here, not at the first request) and prints what is configured with secrets redacted. It needs no
database. Run it in the deployment pipeline before the new version replaces the old one.

`server.mode` is `production` unless set to `dev`. Production requires signing keys, refuses the plugins that drop or fake
work (the in-memory store and mail transport, the `echo` renderer, the `noop` limiter, the recording HTTP client and the `eicar`
test scanner; each says so in its descriptor, one flag that `config check` and the plugin registry both read), refuses the DAV capture
(unless `observability.dav_capture.allow_in_production` says a staging instance captures on purpose), refuses a database
role that row-level security does not bind ([`database.md`](database.md)) and refuses two unencrypted transports: a
database URL (the runtime URL and the owner URL, which `davhaven migrate` and `admin purge-audit` open as well) to a
host other than this one without `sslmode=require`, `verify-ca` or `verify-full`, unless `database.allow_insecure_transport`
accepts the risk, and `plugin.smtp.tls = "none"` to a relay on another host, unless `plugin.smtp.allow_insecure_transport`
accepts it for a capture server on a private network (a login is refused over it whatever that says;
[`mail.md`](../mail.md#transports)). `config check` applies both rules as the start does, and warns when an opt-in is in
effect or no longer has an effect. Development mode generates a key ring for the process when none is
configured, which means **credentials created by one process cannot be verified by another** (the commands that hash
secrets, `admin bootstrap` and `admin rotate-keys`, refuse to run without `security.keys` for that reason).

## First deployment

1. **Database.** Create the roles and the database as in [`database.md`](database.md#provisioning): an owner role that
   migrates, a runtime role that is `NOBYPASSRLS` and owns nothing.
2. **Keys.** Generate a signing key and keep it where the secrets live ([`keys.md`](keys.md)): the key file is mounted into
   the container and named in `security.keys`.
3. **Configuration.** Write the file or the environment; at least `server.public_base_url`, `database.url_file`,
   `database.migration_url_file`, the key, `plugin.smtp` and the listener binds. Run `config check`.
4. **Migrate.** `davhaven migrate` as a one-off job with the owner credentials. Set `database.migrate_on_start = false`
   so that the serving process never holds the owner credentials.
5. **First tenant.** `davhaven admin bootstrap --tenant acme --display-name "Acme" --login-domain example.com
   --token-file /run/secrets/acme-admin` creates the tenant and a tenant API token with the scopes a tenant administrator
   needs, and writes the token (once, mode 0600) to the file. Everything else happens through the management API with that
   token. Running the command again changes nothing (an existing tenant is left as it is; a valid token with the same
   label is not created twice).
6. **Serve.** `davhaven serve`. Wait for `/readyz` on the ops listener to answer 200.
7. **Front end.** Point the reverse proxy at the `public` listener and publish
   `/.well-known/caldav` (it answers 301 to `/dav/`; DNS `_caldavs._tcp` SRV and TXT records for client discovery are a
   deployment task). Keep `internal` and `ops` off the internet.
8. **Scheduled jobs.** The server never purges the audit log. Schedule `davhaven admin purge-audit` and alert on it
   ([Retention](#retention)).

## Running the container

```sh
docker run --rm \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --env DAVHAVEN_CONFIG=/etc/davhaven/davhaven.toml \
  --volume /etc/davhaven:/etc/davhaven:ro --volume /run/secrets/davhaven:/run/secrets:ro \
  --publish 8080:8080 \
  ghcr.io/<owner>/davhaven@sha256:<digest> serve
```

* The binary is `/usr/local/bin/davhaven`, the user is `65532:65532`, the root filesystem can be read-only (the server
  writes only where the configuration names a directory, for example `observability.dav_capture.dir`).
* The image is distroless: no shell, no `curl`. `HEALTHCHECK` runs `davhaven healthcheck`, which asks `/readyz` of the ops
  listener and exits 0 (ready) or 1. Put `DAVHAVEN_CONFIG` (and the other `DAVHAVEN_*` settings) into the **environment** of
  the container, not only into the arguments of `serve`, so that the health check reads the same configuration; or pass
  `--address host:port` to the health check explicitly.
* Pin the image by digest. `release.yml` builds one image per commit of `main` (`main-<sha>`) and per version tag (`v1.2.3`
  becomes the image tag `1.2.3`), and reports the digest.
* Memory is bounded by the connection pool and the largest calendar objects in flight (`limits.ical.max_resource_size`, 1 MiB
  per object); 256 MiB is a sensible start for a small deployment, and the orchestrator's own container metrics tell you when
  it is not enough.

### Readiness, liveness, shutdown

* `GET /healthz` answers 200 `ok` while the process runs. It checks nothing else, so an orchestrator restarts the process only
  when it is wedged and not when the database is away.
* `GET /readyz` answers 200 when the instance should receive traffic and 503 otherwise, with a JSON body that names every
  component: `database` (reachable, schema at least the required version, role posture), the adapters that report health, and
  `worker:<name>` (a worker is unhealthy when it has not **completed** a pass for twice its interval, or one pass has run for
  more than five minutes; a pass that is still running is judged by the five minutes). A component can be `degraded` (for
  example a database role that is not bound by row-level security, with the reason) and the instance is still ready. Each
  component is asked for at most two seconds, concurrently, and the probe (`davhaven healthcheck`, the image's
  `HEALTHCHECK`) waits five: a component that hangs is named in the 503 body (`did not answer in time`) before the probe gives
  up. The ops endpoints serve at most 16 requests at a time and none takes longer than ten seconds; the surplus gets 503.
* `SIGTERM` (and `SIGINT`) start the shutdown: `/readyz` answers 503 `draining` at once. The listeners go on accepting for
  `server.shutdown_delay` (zero by default; set it to the time your load balancer needs to notice the 503), then stop accepting
  and give the requests in flight `server.shutdown_grace` (20 s) to finish while the workers finish the pass they are in. What
  is still running at the end of the grace period, connections included, is cut off. Then the shutdown hooks share five
  seconds: the outbox dispatcher hands back the leases it still holds (so its records are due at once on the next start and no
  attempt is lost, the unfinished attempt is not counted), the database closes its pool; the `ops` listener stops last, and the
  traces are flushed within four. The exit status is 0. **The process is gone at most `server.shutdown_delay +
  server.shutdown_grace + 10 s` after the signal** (30 s with the defaults; the server logs the figure when it starts): give
  the orchestrator a stop timeout longer than that.
* Connections: a client that does not finish its request head within `server.http.header_read_timeout` (10 s) is disconnected,
  and so is a connection that has had no request in flight for that long, whatever protocol it speaks and whether it ever sent
  a request (a client that connects and sends nothing, or a part of the HTTP/2 preface, holds no socket). HTTP/2 connections are
  pinged at the same interval. `server.max_connections` (4096) caps the open connections of each listener; further clients wait
  in the accept queue of the operating system.

## Upgrades and rollbacks

Migrations are forward-only and expand/contract ([`database.md`](database.md#migrations)): every released binary runs on the
schema of the next release. A fresh install has nothing to upgrade from: [First deployment](#first-deployment) starts with
`davhaven migrate`.

1. Run `davhaven migrate` of the **new** image as the owner. The old instances keep serving: the new schema is a superset they
   ignore.
2. Replace the instances one at a time. A new instance is ready once the schema is at least the version it requires.
3. To roll back, deploy the previous image again. Nothing needs undoing: the schema of the newer release is a superset of what
   the older one uses.

A restore from backup is different: see [`backup.md`](backup.md) (`admin bump-sync-epoch --all`).

If `davhaven migrate` fails with `lock timeout`, something holds a conflicting lock on a table the migration changes (a long
transaction, a manual `VACUUM`, a `LOCK TABLE`; `pg_stat_activity` and `pg_locks` show who). The migrating connection gives up after
10 seconds instead of making the application's statements queue behind it. Nothing of the migration was applied (each one is a
transaction) and the running instances were not disturbed: end that statement or choose a quieter moment, and run `davhaven migrate`
again ([`database.md`](database.md#migrations)).

Every `davhaven migrate` run, also one with nothing pending, ends with the role model step that sets what the runtime role may hold
([`database.md`](database.md#what-the-runtime-role-may-do)). It fails, instead of reporting success, when the role of
`database.migration_url` does not own the tables.

## Commands

All commands accept `--config <path>` (or `DAVHAVEN_CONFIG`) and exit 0 on success, 1 when the command failed (the reason is
on standard error, never a secret), 2 for a wrong command line. Each loads only what it needs, so a job holds only the secrets
of its task.

| Command | Needs | Does |
| --- | --- | --- |
| `serve` | everything | Runs the server |
| `migrate` | `[database]` (owner URL) | Applies pending migrations; says from which version to which; then puts the role model of the database back (what the runtime role may hold, `database.md`), which a restored database needs even when no migration is pending |
| `healthcheck [--address host:port] [--timeout 5s]` | the ops listener's address | Exit 0 when `/readyz` answers 200 |
| `config check [--explicit]` | the whole configuration, no database | Validates and prints the redacted settings (`--explicit`: only what the file and the environment set, without defaults) |
| `config reference` | nothing | Prints the configuration reference (what `docs/configuration.md` contains) |
| `admin bootstrap --tenant <slug> (--token-file <path> \| --print-token) [--display-name] [--login-domain] [--locale] [--timezone] [--theme] [--sender-domain] [--sender-display-name] [--auto-create-personal-calendar[=BOOL]] [--apple-identifier-prefix] [--organization-name] [--mcp-enabled[=BOOL]] [--label] [--scope ...] [--expires-in]` | whole configuration, keys | Creates a tenant with its settings and its administration token; idempotent |
| `admin system-token create (--token-file <path> or --print-token) [--label] [--expires-in]`, `list`, `revoke <id>` | whole configuration, keys (`create`) | Makes the system token that `/api/v1/tenants` needs (scope `system:tenants`; the management API cannot mint one), lists the system tokens, revokes one; `create` is idempotent by label |
| `admin principal-token create --tenant <slug> --principal <name> --label <label> --scope <scope> ... (--token-file <path> \| --print-token) [--expires-in]`, `list --tenant <slug> [--principal <name>]`, `revoke --tenant <slug> <id>` | whole configuration, keys (`create`) | Mints, lists and revokes the principal tokens with which an assistant or an integration acts as one principal on the API and on MCP; `create` goes through the credential service with the same rules as the management API (a tenant that switched MCP on and an expiry for `mcp:*`), is idempotent by (principal, label): while a valid token with that label exists a run creates nothing, so a replacement needs a new label (see "Giving an assistant access"); audited as the system actor |
| `admin bump-sync-epoch (--all or --tenant <slug>)` | `[database]` and the store plugin; **no key file** | Invalidates every sync token (after a restore) |
| `admin purge-audit` | `[database]` (owner URL) | Removes audit events older than `retention.audit_days` |
| `admin rotate-keys` | whole configuration, keys | Seals the stored secrets again under the active key and says how many it resealed and how many were current already; exits 1 if any could not be resealed ([`keys.md`](keys.md)) |

`admin bootstrap`, `admin system-token create` and `admin principal-token create` print nothing but the secret on standard output with `--print-token`
(`token="$(davhaven admin bootstrap ... --print-token)"`); everything else they say goes to standard error. A second run of
`admin bootstrap` compares the tenant only with the flags it was given (a run with just `--tenant` reports no differences) and
reports a token of the same label that lacks scopes, or that expires although no expiry was asked for (or the reverse): the
secret of an existing token cannot be shown again, so revoke it or choose another label. Two runs at the same time create the
tenant once (the second one finds it), and can both mint a token: the label is a convenience, not a unique key.

### The settings of a first tenant

`admin bootstrap` can set the settings that a first deployment needs, so that no system token and no `PATCH` is required:
`--locale de-DE`, `--timezone Europe/Berlin`, `--theme <name>` (without it the tenant follows `templates.default_theme`),
`--sender-domain <domain>` and `--sender-display-name <name>` (mail cannot be sent for a tenant without a sender domain),
`--auto-create-personal-calendar=false`, `--apple-identifier-prefix com.example`, `--organization-name <name>` and
`--mcp-enabled`. They apply to a tenant that is **created**; for a tenant that exists the run reports the settings that
differ from the flags it was given (`settings.locale`, ...) and changes nothing, like the display name and the login
domain. A settings flag that does not validate fails the run with the field named, and nothing is created.

### Giving an assistant access

An assistant (or any integration that acts on its own) is a **service principal** with the calendars it may use and a
principal token. With the administration token of the tenant, which `admin bootstrap --mcp-enabled` made:

1. `PUT /api/v1/tenants/acme/principals/assistant` with `{"kind": "service", "display_name": "Assistant"}`;
2. `PUT /api/v1/tenants/acme/principals/{owner}/calendars/{calendar}/grants/assistant` with `{"access": "read_write"}` (or `read`)
   for each calendar it may use;
3. the token, either through the API (`POST /api/v1/tenants/acme/api-tokens`, `{"kind": "principal", "principal": "assistant",
   "label": "assistant-mcp", "scopes": ["mcp:read", "mcp:write"], "expires_at": ...}`: the administration token holds
   `credentials:write`, which is enough for a service principal) or from the host:
   `davhaven admin principal-token create --tenant acme --principal assistant --label assistant-mcp --scope mcp:read --scope mcp:write
   --expires-in 90d --token-file /run/secrets/assistant-mcp`.

Put the token into the connector configuration of the assistant (`Authorization: Bearer ...` against `/mcp` on the
`internal` listener). What the token may do is what the principal may do (its own calendars and the ones it was granted); see
[`../api.md`](../api.md) for the impersonation rules.

**Replacing the token.** It expires after at most `security.max_mcp_token_days` (90), so replace it before that day, without a
gap, in this order:

1. mint the next token **with a new label** (`--label assistant-mcp-2027-02`). With the label of the token that is still valid,
   `admin principal-token create` finds that token, creates nothing and says so, because a run is idempotent by (principal,
   label); a label per rotation, named after the month, avoids the clash. Minting through the API has no such check;
2. put the new secret into the connector configuration and check that the assistant works;
3. revoke the old token (`admin principal-token revoke --tenant acme <id>` or `DELETE /api/v1/tenants/acme/api-tokens/{id}`).

`admin principal-token list --tenant acme` shows the ids, the state and the expiry of the tokens, never a secret. The label is a
convenience for a person, not a unique key: two runs at the same moment can both mint a token (as for `admin bootstrap`), and
the list shows both.

## Calendar providers

Google and Microsoft are in the image and off until you switch them on. For a provider:

1. Register an OAuth client at the provider (a web application) and put **`{server.public_base_url}/oauth/{provider}/callback`** in
   its redirect URIs, for example `https://cal.example.org/oauth/google/callback`. The scope is read access to calendars only
   (`calendar.readonly` at Google; `Calendars.Read`, `User.Read` and `offline_access` at Microsoft). Microsoft: an app registered as
   single-tenant needs `directory` in its table set to the id or domain of that directory.
2. Put the client secret in a file the container can read, and write the table (the keys are in
   [`../configuration.md`](../configuration.md)):

   ```toml
   [plugins]
   providers = ["google"]

   [providers.google]
   enabled = true
   client_id = "…apps.googleusercontent.com"
   client_secret_file = "/run/secrets/google-client-secret"
   redirect_uri = "https://cal.example.org/oauth/google/callback"
   ```

   `davhaven config check` reads the secret file and refuses a `redirect_uri` that is not the callback this server serves.
3. Outbound calls to the provider go through the egress policy like every webhook: `accounts.google.com`, `oauth2.googleapis.com` and
   `www.googleapis.com` (Google), `login.microsoftonline.com` and `graph.microsoft.com` (Microsoft) must be reachable from the
   instance, and the policy's response cap for provider calls (`provider_api_max_response_bytes`) must fit a page of events.
4. Connect an account for a user with the administration token (`providers:manage`): `POST /api/v1/tenants/acme/external-accounts`
   with `{"provider": "google", "principal": "anna"}` answers `{"authorization_url": …}`; give that URL to the person, who consents at the
   provider and lands on a page that says the calendar is connected. The URL works once and for ten minutes, and it is a bearer
   capability: whoever opens it first and consents connects *their* account to that person's mirror, so hand it to that person only and never
   post it in a shared channel or log it. Their mirror calendar
   appears in their calendar app after the next pull (at most `[providers.sync] interval`, 15 minutes by default).

**What to look at.** `GET …/external-accounts` lists every account with `status` (`active`, `error` or `disabled`) and `last_error`, which
starts with the reason:

* `auth_revoked`: the provider says that the **refresh token** is no longer valid (RFC 6749 `invalid_grant`: the person removed the
  access, or it was revoked or expired), or the account has none. The account is **disabled** and nothing is pulled until the person
  connects it again. Only this switches an account off. (A Google app whose consent screen is in the *testing* state lets refresh tokens
  expire after seven days: publish the app, or every person connects again every week.)
* `internal` with `a provider refuses the OAuth client of the deployment` in the log (`invalid_client`, `unauthorized_client`,
  `invalid_request`, `invalid_scope`): the **client secret** (or the client id) is wrong, was rotated or has expired (Microsoft client
  secrets expire after at most 24 months). It is the deployment's fault, so **no account is switched off**: every account is `error`,
  tried again after the wait, and works by itself once you have fixed the secret file and restarted. Nobody has to connect again.
* `provider_rejected` (the provider refuses a fresh token or the calendar), `provider_unavailable` (no connection, `5xx`, throttling),
  `too_large` (more than 10 000 events in the window the import reads: narrow `history_days` and `future_days` in the provider's table),
  `mirror_missing` (the mirror calendar is gone: the API does not delete one, so a purge or a statement of an operator did; the provider
  is not asked and the person's tokens are not used meanwhile; **connect the account again** to get a new mirror, or disconnect it) and
  `internal` (the stored tokens cannot be opened, the store failed): **error**, retried with a wait that grows from a third of the
  interval to `backoff_max`.
* `principal_deleted`: the person was deleted. The account is switched off at its next claim and its access is given back; no
  `external_account.sync_failed` event is emitted for it, the deletion is audited.

The accounts of a **suspended** person are left alone and pulled again when the person is active. `davhaven_provider_sync_total{provider,outcome}`
counts the pulls; the log says `a provider calendar was pulled` with the counts of events, and never an address or a token.

**Reconnecting** an account (the way back from `disabled` and from `mirror_missing`) is the same flow for the same person and account: the
account stays, the tokens are replaced, the mirror stays or, when it is gone, a new one is made. A pull that is running while the person
connects again is dropped instead of undoing the new connection. **Disconnecting** is `DELETE …/external-accounts/{id}`: the mirror
calendar is deleted (and purged after `retention.deleted_calendar_days`; the API refuses to delete a mirror on its own) and the provider
is asked to revoke the tokens (unless another account of the tenant holds the same grant), which does not hold the deletion up when it fails.

**Switching a provider off** (`enabled = false` or removing it from `plugins.providers`) stops the pulls of its accounts at once and
keeps the accounts and their mirrors as they are; the API answers 409 `feature-not-enabled` to a new flow. Switching it on again resumes.

**Rotating the OAuth client secret** at the provider is a change of the secret file and a restart; the stored tokens of the accounts
stay valid (they belong to the consent of the people, not to the secret), and nobody connects again. Until the new secret is in place,
the accounts of the provider are `error` with `internal`, never `disabled`. **Rotating the keys of the server** reseals the tokens
(`davhaven admin rotate-keys`, [`keys.md`](keys.md)).

## Observability

**Logs** go to standard error, one JSON object per line (`observability.log_format = "text"` for development), filtered by
`observability.log_filter` (`info`; `RUST_LOG` overrides it for a debugging session). Every request is one line with
`request_id`, `surface`, `method`, `route` (the route template, never the raw path), `status` and `latency_ms`, plus the
`trace_id` when the client sent a `traceparent` and the `tenant_id` and `principal_id` once the request was authenticated.
Tokens in URLs (feeds, RSVP links) are redacted before anything is logged; logs carry ids, not bodies, iCalendar data or
addresses. The `X-Request-Id` of a response is the key to the log line and to the problem document the client saw.

**Metrics** are served by the ops listener at `/metrics` in the Prometheus format (histogram buckets from 1 ms to 1 minute).

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `davhaven_http_requests_total` | counter | `surface`, `method`, `route`, `status` | Requests handled |
| `davhaven_http_request_duration_seconds` | histogram | `surface`, `method`, `route` | Request latency |
| `davhaven_port_calls_total` | counter | `port`, `adapter`, `op`, `outcome` | Calls to every adapter |
| `davhaven_port_call_duration_seconds` | histogram | `port`, `adapter`, `op` | Adapter latency |
| `davhaven_auth_failures_total` | counter | `mechanism`, `reason` | Refused credentials |
| `davhaven_budget_refusals_total` | counter | `class` (`mcp_read`, `mcp_write`) | Tool calls of MCP tokens refused for being over their budget (the audit log holds one `rate_limit.tripped` record per token, budget and minute) |
| `davhaven_outbox_pending` / `_in_flight` | gauge | | Messages waiting / being handled |
| `davhaven_outbox_oldest_pending_age_seconds` | gauge | | Age of the longest-waiting due message |
| `davhaven_outbox_handled_total` | counter | `kind`, `outcome` | Handler outcomes (`done`, `retry`, `deferred`, `dead`) |
| `davhaven_outbox_dead_total` | counter | `kind` | Messages given up |
| `davhaven_outbox_handle_duration_seconds` | histogram | `kind` | Time a handler takes for one message |
| `davhaven_outbox_settle_lost_total` | counter | | Outcomes dropped because another dispatcher settled first |
| `davhaven_mail_sent_total` / `_failed_total` / `_dropped_total` / `_held_total` | counter | `method` or `reason` | Mail outcomes |
| `davhaven_mail_reply_service_form_total` | counter | | iTIP replies sent in the service form (`From` is the tenant's address, `Reply-To` the attendee) because the attendee's address is not in the sender domain; some receivers may not apply them ([`interop.md`](../interop.md)) |
| `davhaven_mail_circuit_open` | gauge | | 1 while the mail circuit breaker is open |
| `davhaven_worker_heartbeat_age_seconds` | gauge | `worker` | Seconds since a worker last **completed** a pass (a pass that panicked is no progress; a pass in progress does not refresh it) |
| `davhaven_worker_passes_total` | counter | `worker`, `outcome` | Worker passes (`ok`, `failed`, `panicked`); `failed` means that records or steps of the pass failed (a webhook receiver that is down fails its outbox records), `panicked` is a bug |
| `davhaven_retention_removed_total` / `_failed_total` | counter | `step` | Cleanup work (the step `audit_oldest_event` is the lookup behind the two audit gauges below) |
| `davhaven_audit_oldest_event_timestamp_seconds` | gauge | | When the oldest audit event of all tenants occurred, in unix seconds. Looked up every 15 minutes by the cleanup worker with one indexed query; **absent** while the audit log is empty (it reads `NaN`, which no comparison matches, when the log is emptied while the server runs). See [Retention](#retention) for the alert |
| `davhaven_audit_retention_seconds` | gauge | | The configured `retention.audit_days` in seconds |
| `davhaven_profile_signing_certificate_expiry_timestamp_seconds` | gauge | | The end of the validity (`notAfter`) of the first certificate of `[security.profile_signing]` as the server uses it now, in unix seconds. Follows a renewal within a minute; **absent** while profile signing is off ([`keys.md`](keys.md#the-certificate-that-signs-apple-profiles)) |
| `davhaven_provider_sync_total` | counter | `provider`, `outcome` | Pulls of provider accounts (`pulled`, `failed`, `skipped`: not due, held by another worker, switched off) |

No metric carries a tenant label (`observability.metrics.tenant_label` is reserved, and `config check` refuses `true`). The database
connection pool is not exported yet; watch the `database` port metrics and the connection count on the database side.

**Traces** are exported over plain OTLP/gRPC when `observability.otlp.endpoint` is set to the collector's gRPC port
(`http://otel-collector:4317`). Every request is a server span named after the method and the route template, whose parent
is the span of the caller when it sent a W3C `traceparent` (the trace continues the caller's and its sampling decision wins);
the `port_call` spans of the adapters are its children, and the `trace_id` of the log line is the trace's.
`observability.otlp.sample_ratio` applies to traces that start here. Run the collector on the local network; TLS to a remote
backend is the collector's job.

**Dashboard and alerts** are shipped in [`deploy/`](../../deploy): `deploy/grafana/davhaven-dashboard.json` (import it,
choose the data source and the job) and `deploy/prometheus/davhaven-rules.yml` (the alerts below). A test keeps both in step
with the metric names the code registers.

## Alerts

Every alert of `deploy/prometheus/davhaven-rules.yml` links here. The first question for any of them is which instance and
what `/readyz` says: `davhaven healthcheck`, or `curl http://<ops>/readyz`, names the component that is not ready.

### DavhavenDown

The ops listener has not answered for five minutes. The process is gone, wedged or unreachable. Look at the orchestrator
(restarts, out-of-memory kills), then at the log of the last start: configuration and key errors are reported at startup,
naming the key (`config check` reproduces them). A start that dies on a port that is taken names the listener and address.

### DavhavenWorkerStalled

A worker has made no progress for 15 minutes; `/readyz` already reports the instance as not ready. `worker:outbox` stalled
means mail and webhooks are not leaving; `worker:retention` means cleanup stopped. A hung pass usually waits on the database:
look for long statements and locks (`pg_stat_activity`), connection exhaustion
(`database.max_connections`, `database.acquire_timeout`) and a database that is failing over. Restarting the instance
releases its outbox leases; the pass in flight is not lost, it is repeated.

### DavhavenWorkerPanicking

A pass of a worker panicked in the last 15 minutes, for half an hour. A panic is a bug: the worker goes on with its next pass,
but the one that panicked did nothing. The log line names the worker; keep it and the `RUST_BACKTRACE` of the instance and
report it. Passes that merely report failed records are no alert of their own: a webhook receiver that is down fails its
outbox records and is seen in [DavhavenOutboxBacklog](#davhavenoutboxbacklog) and
[DavhavenOutboxDeadLetters](#davhavenoutboxdeadletters), and a retention step that fails is
[DavhavenRetentionFailing](#davhavenretentionfailing).

### DavhavenServerErrors

More than 5 % of the requests of a surface end in a 5xx status. 503 with `Retry-After` is load shedding or a database that is
away (look at `davhaven_port_calls_total{port="database"}` and at `/readyz`); 500 is a bug, and the problem document and the
log line share the `request_id`. The `internal` and `public` listeners shed load above `server.http.concurrency_limit` and
time out requests after `server.http.request_timeout`.

### DavhavenSlowRequests

The 95th percentile of a surface is above two seconds. Compare the adapter latencies on the dashboard: a slow database
(statement timeout is `database.statement_timeout`, lock waits `database.lock_timeout`), a saturated pool, or one tenant with a
very large calendar (the log line has the route and the tenant; the limits of `[limits]` bound what one request may ask for).

### DavhavenAuthFailures

A sustained rate of refused credentials. Check `mechanism` and `reason`: a revoked app password in a client retry loop is
`revoked` on `dav` (the client shows up in the log by its request ids); guessing shows `unknown_credential` or `bad_secret`
from many addresses. The server answers every failure the same way and backs off per login and per address
(`security.auth.backoff_*`, 429 with `Retry-After`); there is no lockout. Revoke the credential or block the address at the
proxy.

### DavhavenOutboxBacklog

The oldest due message has waited 15 minutes (critical at an hour). Messages are not being delivered as fast as they are
produced. In order: is the outbox worker healthy in `/readyz`; is the mail circuit breaker open ([DavhavenMailCircuitOpen](#davhavenmailcircuitopen));
is a webhook receiver slow (the dispatcher handles `outbox.concurrency` records at a time under one deadline, 80 % of
`outbox.lease`); is the relay rate-limited (`mail.rate_limit_per_minute`, held mail shows in `davhaven_mail_held_total`). A deliberate
backlog (a tenant imported thousands of events with notifications) drains by itself.

### DavhavenOutboxDeadLetters

A message ran out of attempts (`outbox.max_attempts`) or its retry window (webhooks, 24 hours) and is `dead`. List them with
`GET /api/v1/tenants/{tenant}/outbox?status=dead` (scope `outbox:manage`), read `last_error`, fix the cause (a receiver URL that
changed, an address the relay refuses) and `POST .../outbox/{id}/retry`. A dead mail is announced to the tenant as the
`mail.delivery_failed` event. Dead records are removed after `retention.outbox_dead_days` (30).

### DavhavenMailCircuitOpen

The relay failed `mail.max_consecutive_failures` sends in a row; mail waits in the outbox and is sent again when the breaker
closes (it probes after a cool-down). Check the relay (`plugin.smtp.host`, `port`, `tls`, credentials), the network path and
the sender domain's SPF/DKIM/DMARC records. Nothing is lost while the breaker is open; mail that waits a week fails like any
relay error.

### DavhavenMailFailures

Sends fail for the reason in the label (the relay refuses a recipient, a timeout, a rejected message). One recipient that the
relay refuses is dead-lettered after its attempts; a relay that is down opens the breaker.

### DavhavenPortFailures

More than 10 % of the calls to one adapter fail with `unavailable`, `timeout` or `internal`. For `database/postgres`:
connections, restarts, `statement_timeout`. For `mail_transport/smtp`: the relay. For `http_client/egress`: webhook receivers and
provider APIs (the egress policy refuses private addresses by design; a refused call is `rejected`, not a failure of the
adapter).

### DavhavenRetentionFailing

A cleanup step failed in the last six hours. The log line names the step and the store error. The most common cause is a
database that rejects the statement (permissions after a role change, a lock). A deleted tenant or calendar purge that fails
is retried with the next pass. Audit retention that does not run is not a failure: see [Retention](#retention).

### DavhavenProviderSyncFailing

More than half of the pulls of the accounts of one provider failed for 30 minutes. Ask the API: `GET /api/v1/tenants/{tenant}/external-accounts`
shows `status` and `last_error` of every account, and the `external_account.sync_failed` events (webhooks) say when each one began.
If **many accounts** of one provider fail with `provider_unavailable`, the provider is down or throttles this deployment: the pulls are
retried with a growing wait, and nothing is lost. If they fail with `internal` all at once and the log says `a provider refuses the OAuth
client of the deployment`, the client secret was rotated or expired, or the client was disabled: fix the secret file and restart; the
accounts are on again by themselves at their next pull and **nobody connects again** (see [Calendar providers](#calendar-providers)).
`too_large` is one calendar that has more events than the import reads, and `mirror_missing` one account whose mirror is gone (connect
it again). A single account that fails with `auth_revoked` is the person's doing (they removed the access) and no reason to act; a burst
of `auth_revoked` means that the provider ended the grants (a Google consent screen in the testing state, a withdrawn app), and the
people connect again.

### DavhavenAuditPurgeNotRunning

The oldest audit event of all tenants is more than 35 days older than `retention.audit_days`: the job that purges the audit log did not
run (or does not remove anything). The server never deletes audit events (the runtime role cannot), so the purge is a job of the
deployment, `davhaven admin purge-audit` with the owner credentials or with a role of its own
([`database.md`](database.md#audit-log-retention)). Run it by hand and look at its output (it prints how many records it removed),
then at the scheduler: a job that is disabled, a schedule that never fires, a `database.migration_url` that points at a role that
may not execute the purge function (the command fails and says so). The expression is
`time() - davhaven_audit_oldest_event_timestamp_seconds > davhaven_audit_retention_seconds + 35 * 86400`; the 35 days are the slack of a
monthly job, so a job that runs more often can use less ([Retention](#retention) says how the slack and the schedule relate). The gauge
is looked up every 15 minutes; it is absent while the audit log is empty.

### DavhavenProfileSigningCertificateExpiring

The certificate that signs Apple profiles (`[security.profile_signing]`) ends within 14 days, or has ended. ACME clients renew 30 days
before the end, so a certificate in use that is this close means that no renewal reached the server. Look, in this order, at the ACME
client (did it renew? is the new `fullchain.pem` on disk?), at the log of the server (`the profile signer keeps the certificate in use`
says why a new pair was refused: a key that does not belong to the certificate, a damaged file, a certificate that has ended), and at the
mount: a file that is bind-mounted into the container on its own, a Compose or Swarm secret and a Kubernetes volume with `subPath` keep
the file that was there at the start, and the server never sees the renewal until it restarts. Mount the directory instead
([`keys.md`](keys.md#the-certificate-that-signs-apple-profiles)). A hung mount shows as failed passes of the `profile_signing` worker.
The gauge is absent while signing is off.

## Retention

The `retention` worker removes expired data, one system transaction per step so that no transaction holds locks for long
(`[retention]` in [`configuration.md`](../configuration.md)):

| What | After |
| --- | --- |
| Outbox records, done / dead | `retention.outbox_done_days` (7) / `retention.outbox_dead_days` (30) |
| Webhook delivery records | `retention.webhook_delivery_days` (30) |
| Change log (`collection_changes`) | `retention.collection_changes_days` (90); raises `sync_min_seq`, older sync tokens answer `valid-sync-token` and the client resyncs |
| Audit events | `retention.audit_days` (365), see below |
| Scheduling inbox items | `retention.scheduling_inbox_days` (30) |
| Idempotency keys | their own expiry (24 hours, `retention.idempotency_hours`) |
| OAuth states | `retention.oauth_state_days` (1) |
| RSVP tokens | `retention.rsvp_token_days` (30) after they expired or were revoked |
| Deleted principals / deleted calendars | `retention.principal_purge_days` / `retention.deleted_calendar_days` (30), purged in the tenant's transaction (`principal.purged` is audited) |

The runtime role cannot delete audit events and may not execute the purge function (a role that can is reported as holding a
privilege it must not have, and production refuses to start with it): schedule `davhaven admin purge-audit` with the owner
credentials, or with a role of its own ([`database.md`](database.md#audit-log-retention)); the server never purges the audit log. A pass
handles bounded batches and reports that more is waiting when it stopped early; a large backlog is cleared over several passes.

**Watching the audit purge job.** The server does not run the job, but it can tell when the job does not run: the cleanup worker
publishes `davhaven_audit_oldest_event_timestamp_seconds` (when the oldest audit event of all tenants occurred) and
`davhaven_audit_retention_seconds` (`retention.audit_days` in seconds). The shipped alert `DavhavenAuditPurgeNotRunning`
([Alerts](#davhavenauditpurgenotrunning)) is this expression, with the `job` matcher of the other rules:

```
time() - davhaven_audit_oldest_event_timestamp_seconds > davhaven_audit_retention_seconds + 35 * 86400
```

**What the 35 days mean.** A run of the job removes the events older than the retention period, so right after a run the oldest event is
about as old as the period, and just before the next run of a job that runs every *P* days it is about *P* days older. The alert
fires when the oldest event is 35 days past the period, that is, when a run is missing for `35 - P` days longer than its schedule says:
for a **monthly** job (*P* = 30) that is **about 5 days after the run that did not happen**, so one missed run is enough; for a weekly
job it is 28 days, for a daily job 34. Set the slack to the interval of your job plus the days you can wait (`+ 3 * 86400` for a daily
job), in the shipped rule or in your own.

Both series carry the labels of the instance, so the two sides of the comparison match one to one. The oldest event is looked up every
15 minutes, so the gauge can be a quarter of an hour behind. The series is **absent** while the audit log is empty (it reads `NaN` if the
log is emptied while the server runs), so a log without events raises no alert. The exit status of the job stays worth an alert of its
own: it says that a run failed, the gauge also says that none happened.
When the alert fires, run `davhaven admin purge-audit` by hand and look at the scheduler of the job.

## Image retention

`.github/workflows/ghcr-retention.yml` (weekly, and by hand as a dry run) applies
[`scripts/ghcr-retention.sh`](../../scripts/ghcr-retention.sh) to the package: **every release tag stays, the newest 30
`main-<sha>` versions stay, every version younger than 30 days stays** whatever its tags (an image that was pushed a day ago is
never deleted, and neither is an untagged version that a multi-platform push leaves behind while it is young), and the rest goes.
The rules need nothing from outside this repository: no deployment repository has to tag what it ran, so none needs write access
to the package.

The consequence is the one that a pinned digest always has: an image of a `main-*` build that is neither among the newest 30 nor
younger than 30 days is gone from the registry. A deployment that must be able to pull its image for longer (a production that
runs one image for months and may be rescheduled) runs a release, a `v*` tag, which stays for ever, or redeploys within that
window. The script refuses to delete every version of the package or more than 100 versions in one run (`MAX_DELETIONS`); a
manual run with `dry_run` lists what the next weekly run would delete.

## The DAV capture

`observability.dav_capture` records the DAV exchanges of the tenants in `tenants` as one JSON file per request in `dir`
(mode 0600; credentials redacted, calendar data **not**), which is how real client traffic becomes fixtures of the client-flow
suite ([`testing.md`](../testing.md)). It is off by default, `config check` warns when it is on, and production mode refuses it
unless `observability.dav_capture.allow_in_production` is set (a staging instance that captures on purpose). Only exchanges that
were authenticated as a user of a listed tenant are written (the 401 of a client that has not logged in yet is not), a request
body is read only within the DAV limits (`limits.dav.max_request_body` or `limits.ical.max_resource_size`, whichever is larger) and
the request timeout, at most `server.http.concurrency_limit` exchanges are handled at a time, and a request or response outside
those bounds passes through unrecorded. Use it on a staging instance with tenants whose users agreed; the directory is created
with mode 0700; treat it like the database; remove it when done. The file format is described in the rustdoc of the `capture`
module of `davhaven-server`.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| The start fails with `unknown field` or `invalid configuration` | The message names the key. `davhaven config check` reproduces it without a database. Unknown `DAVHAVEN_*` variables fail the same way (`DAVHAVEN_CONFIG` is the one variable that is not a key) |
| `plugins.store selects `memory`, which is refused when server.mode is "production"` (or another plugin) | Production refuses the in-memory store and mail transport, the `echo` renderer, the `noop` limiter, the recording client and the `eicar` scanner. Select a real adapter or set `server.mode = "dev"` |
| `[plugin.memory] is ambiguous` | A name that is selected for several kinds (`memory` is a store, a mail transport and a rate limiter) needs the kind: `[plugin.mail_transport.memory]` ([`configuration.md`](../configuration.md#how-the-configuration-is-read)) |
| The start fails naming the database role | Production refuses a runtime role that row-level security does not bind or that holds too many privileges ([`database.md`](database.md)); `database.allow_unbound_role` accepts the risk explicitly |
| The start or `config check` fails naming `sslmode=verify-full` or `tls = "none"` | Production refuses an unencrypted database URL and an unencrypted mail relay on another host. Put `sslmode=verify-full` into the database URLs and use `starttls` or `implicit`; `database.allow_insecure_transport` and `plugin.smtp.allow_insecure_transport` accept the risk explicitly, and a login is never accepted over `tls = "none"` |
| `/readyz` is 503 with `database ... schema` | The schema is older than the binary requires: run `davhaven migrate` with the owner role |
| `401` for a credential that was just created | In development mode each process makes up its own key ring: configure `security.keys` so that `bootstrap`, `serve` and the other commands share it. In production: the key id of the credential must still be in `security.keys` |
| `431` from clients | The request head exceeded `server.http.max_header_bytes` (16 KiB); a proxy that forwards huge cookies is the usual reason |
| Clients disconnect on slow links | `server.http.header_read_timeout` (10 s) closes a connection whose headers do not arrive in time |
| Mail is held, nothing sent | Staging rules (`mail.redirect_all_to`, `mail.allowed_recipient_domains`), the rate limit or an open breaker; `davhaven_mail_held_total` and `_dropped_total` say which |
| `davhaven healthcheck` fails in the container | It reads the configuration of its own environment: set `DAVHAVEN_CONFIG` in the container's environment, or pass `--address` |
