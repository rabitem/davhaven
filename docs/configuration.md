# Configuration reference

This page is generated from the code by `cargo xtask config-docs`; do not edit it. CI fails when it is out of date. It is
generated from a build with **every cargo feature** of `davhaven-server` (`--all-features`), so that optional adapters are
documented; the container image is built with the default features, and what needs another one says so where it is
described. `davhaven config reference` inside the image prints the reference of the image's own build.

## How the configuration is read

Davhaven reads one TOML file and the environment, in this order of increasing precedence: the defaults of this
page, the file named by `--config <path>` (or the environment variable `DAVHAVEN_CONFIG`), and the environment
variables with the prefix `DAVHAVEN_`. A named file must exist. Without a file the environment alone configures the
server, which is how the container image is usually configured.

* **Environment variables** use `__` (two underscores) as the separator of nested keys, and single underscores stay
  in key names: `DAVHAVEN_SERVER__SHUTDOWN_GRACE=30s` sets `server.shutdown_grace`, and
  `DAVHAVEN_DATABASE__MIGRATION_URL_FILE=/run/secrets/migration-url` sets `database.migration_url_file`. Lists are
  written as `DAVHAVEN_PLUGINS__EVENT_SINKS=["log"]`. `DAVHAVEN_CONFIG` is the one variable that is not a key.
* **Unknown keys fail the start**, in the file and in the environment, and the error names the key. So does a
  `[plugin...]` table for an adapter this build does not contain, and a table for an adapter that is not
  selected under `[plugins]` is reported as a warning by `davhaven config check`.
* **An adapter is configured by its kind and its name.** The table of the adapter `smtp` of the kind `mail_transport` is
  `[plugin.mail_transport.smtp]`, and `[plugin.smtp]` means the same when no other selected adapter is called `smtp`.
  Names repeat across kinds (`memory` is a store, a mail transport and a rate limiter; `noop` is an authenticator, an
  outbox handler and a rate limiter), so a name that is selected for several kinds needs the kind in the table:
  `[plugin.mail_transport.memory]` and `[plugin.rate_limiter.memory]` are two tables of two adapters, while
  `[plugin.memory]` with keys in it is refused as ambiguous. Environment variables follow the same path:
  `DAVHAVEN_PLUGIN__MAIL_TRANSPORT__MEMORY__MAX_MESSAGES=100`. A few adapters are configured in tables of their own
  (`[database]`, `[security.auth]`, `[security.egress]`, `[webhooks]`, `[templates]`, `[providers.<name>]`); the
  [Plugins](#plugins) section says where each adapter's table is. A key may be set in only one of an adapter's places.
* **Secrets are never inline-only.** Every secret has a `*_file` variant that names a file with the secret
  (`database.url_file`, `plugin.smtp.password_file`, `security.keys[].secret_file`, ...). One trailing line break of
  the file is ignored. `davhaven config check` reads every such file, so a missing or unreadable secret is found
  before the first request. Inline values (`database.url`) exist for development; the output of `config check`
  redacts them.
* **Durations** are written as text: `500ms`, `30s`, `5m`, `1h`, `7d`. **Sizes** are bytes. The iCalendar duration
  of `feeds.refresh_interval` is the one exception (`PT15M`).
* **Tenant settings** (theme, sender, locale, scheduling policy, ...) are data, set through the management API, and are
  not part of this file.

`server.mode` is `production` unless you say `dev`. Production refuses the adapters that drop or fake work (the
in-memory store and mail transport, the `echo` renderer, the `noop` rate limiter, the recording HTTP client and the
`eicar` test scanner) and requires signing keys; the in-process rate limiter (`memory`) is the limiter of a single
instance and stays allowed. Development generates a key ring for the process when none is configured: credentials,
cursors, CSRF tokens and sealed data then do not survive a restart.

## The key ring

`security.keys` lists the keys of the key ring:

```toml
[[security.keys]]
id = "2027-01"
secret_file = "/run/secrets/davhaven-key-2027-01"

[[security.keys]]
id = "2026-07"
secret_file = "/run/secrets/davhaven-key-2026-07"

[security]
active_key_id = "2027-01"
```

* `id` is 1 to 32 characters of `a-z`, `0-9`, `-` and `_`. It is stored next to hashes, signatures and sealed data, so
  data stays verifiable after a rotation. Never reuse an id for another secret.
* The secret file contains **one secret of at least 32 characters, as printed by the tool that made it**: a base64 or
  hex encoding of 32 or more random bytes, for example `openssl rand -base64 48` or `openssl rand -hex 32`. The file
  content (one trailing line break removed) is the key material as it is: the server does not decode it, it derives
  the subkeys of every purpose (credential pepper, RSVP tokens, CSRF, cursors, cache keys, sealing) from it with
  HKDF-SHA256. A file of fewer than 32 characters is refused with the key id in the message.
* `active_key_id` names the key that signs, hashes and seals new data; without it the first key is active. The other
  keys only verify and open. See [`operations/keys.md`](operations/keys.md) for rotation.

## Listeners

`server.listeners.<name>` configures the three listeners: `public` (`wellknown`, `dav`, `web`), `internal` (`api`,
`mcp`) and `ops` (`ops`: `/healthz`, `/readyz`, `/metrics`). Each has `enabled`, `bind` and `routes`; a route group is
served by exactly one listener, and merging everything onto one listener is a list of all six groups. The default
binds are `0.0.0.0:8080` for `public` and the loopback addresses `127.0.0.1:8081` and `127.0.0.1:9090` for the other two;
a deployment that exposes them says so. `davhaven config check` warns when a listener that serves the `ops` group
(`/metrics`, `/readyz`, which need no credentials) is bound to an address that is not loopback.

`server.http.header_read_timeout` and `server.http.max_header_bytes` apply to every connection. A client that does not
finish its request head in time is disconnected, and so is a connection that has no request in flight for that long,
whatever protocol it speaks and whether it ever sent a request (a client that connects and sends nothing, or only a part
of the HTTP/2 preface, does not hold its socket). HTTP/2 connections are pinged at the same interval and closed when the
peer does not answer. `server.max_connections` caps the open connections of each listener (`server.http.concurrency_limit`
counts requests, not sockets); further clients wait in the accept queue of the operating system. An oversized request head
answers 431 in the form of the surface the path belongs to; values of `max_header_bytes` below 8192 are enforced on the
parsed request, because the HTTP library cannot buffer less (and what the library refuses itself answers 431 without a
body).

## Shutdown

On `SIGTERM` or `SIGINT` the server answers `/readyz` with 503 `draining`, keeps accepting connections for
`server.shutdown_delay` (zero by default; set it to the time your load balancer needs to notice), then stops accepting and
gives the requests in flight and the workers `server.shutdown_grace` to finish. What is still running at the end of the
grace period, connections included, is cut off. The shutdown hooks of the workers and adapters (the outbox hands back its
leases, the database closes its pool) then share five seconds, and the traces are flushed within four. The process is gone at
most `server.shutdown_delay + server.shutdown_grace + 10s` after the signal; the server logs that figure when it starts, and
the container needs a stop timeout that is longer.

## Mail transport

`plugin.smtp.tls` selects how the connection to the relay is secured: `"starttls"` (the default, port 587; the upgrade
to TLS is mandatory), `"implicit"` (TLS from the first byte, port 465; `"tls"` is accepted as another spelling of it) and
`"none"` (no encryption: for a capture server such as Mailpit). Production refuses `"none"` for a relay on another host,
because invitations and RSVP links would cross the network in the clear: `localhost` and the loopback addresses are
this host, any other name is another host (names are not resolved). `plugin.smtp.allow_insecure_transport = true`
accepts it for a capture server on a private network, such as the mail catcher of a staging deployment, and it never
accepts a login: with `plugin.smtp.username` and `plugin.smtp.password_file` set, production refuses `"none"` to another
host whatever the opt-in says, because a capture server needs no login. In `dev` mode the choice is the operator's.
`config check` applies the same rules as the start, and warns when mail travels unencrypted because of the opt-in and
when the opt-in is set but has no effect. The password is read from `plugin.smtp.password_file`.
`plugin.smtp.total_timeout` has to stay below 60 % of `outbox.lease`; `config check` refuses a combination that does
not.

## Observability

Logs go to standard error, one JSON object per line (`observability.log_format = "text"` for development), filtered
by `observability.log_filter` or, for a debugging session, by the `RUST_LOG` environment variable. The ops listener
serves the Prometheus metrics at `/metrics`. When `observability.otlp.endpoint` is set to the OTLP/gRPC port of a
collector (`http://otel-collector:4317`, the OTLP default) the server exports its spans there, sampled with
`observability.otlp.sample_ratio`; the export is plain gRPC without TLS and the endpoint may not carry credentials, so run
the collector on the local network and let it carry the traffic onwards. `observability.dav_capture` records the DAV
exchanges of the listed tenants (credentials redacted) as JSON files in a directory (mode 0700), which is how real client
traffic becomes test fixtures. Only exchanges that were authenticated as a user of a listed tenant are written, bodies are
read within the DAV limits and the request timeout, and responses of unknown or large size pass through unrecorded. It is
off by default, `config check` warns when it is on, and production mode refuses it unless
`observability.dav_capture.allow_in_production` says that a staging instance captures on purpose.

`davhaven config check` prints the **effective** configuration: the defaults of this build with the file and the
environment laid over them and the secrets redacted (credentials in URLs, whatever the key is called, and values under keys
that are named like secrets). `--explicit` prints only what the file and the environment say.

## Tables

### `[server]`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `http.concurrency_limit` | integer | `1024` | The most requests handled at the same time per listener; further requests wait or are shed. |
| `http.header_read_timeout` | string | `"10s"` | How long a client may take to send the request headers; slower connections are closed. |
| `http.max_header_bytes` | integer | `16384` | The largest header block in bytes; larger requests get 431. |
| `http.request_timeout` | string | `"1m"` | How long one request may take in total; slower requests get 503. |
| `listeners.internal.bind` | string, optional | unset | The address to bind: `0.0.0.0:8080` for `public`, `127.0.0.1:8081` for `internal`, `127.0.0.1:9090` for `ops`. |
| `listeners.internal.enabled` | boolean | `true` | Whether the listener is started. A disabled listener's default route groups are not served at all. |
| `listeners.internal.routes` | list of one of `"wellknown"`, `"dav"`, `"web"`, `"api"`, `"mcp"`, `"ops"`, optional | - | The route groups to serve: `wellknown`, `dav`, `web` for `public`, `api`, `mcp` for `internal`, `ops` for `ops`. |
| `listeners.ops.bind` | string, optional | unset | The address to bind: `0.0.0.0:8080` for `public`, `127.0.0.1:8081` for `internal`, `127.0.0.1:9090` for `ops`. |
| `listeners.ops.enabled` | boolean | `true` | Whether the listener is started. A disabled listener's default route groups are not served at all. |
| `listeners.ops.routes` | list of one of `"wellknown"`, `"dav"`, `"web"`, `"api"`, `"mcp"`, `"ops"`, optional | - | The route groups to serve: `wellknown`, `dav`, `web` for `public`, `api`, `mcp` for `internal`, `ops` for `ops`. |
| `listeners.public.bind` | string, optional | unset | The address to bind: `0.0.0.0:8080` for `public`, `127.0.0.1:8081` for `internal`, `127.0.0.1:9090` for `ops`. |
| `listeners.public.enabled` | boolean | `true` | Whether the listener is started. A disabled listener's default route groups are not served at all. |
| `listeners.public.routes` | list of one of `"wellknown"`, `"dav"`, `"web"`, `"api"`, `"mcp"`, `"ops"`, optional | - | The route groups to serve: `wellknown`, `dav`, `web` for `public`, `api`, `mcp` for `internal`, `ops` for `ops`. |
| `max_connections` | integer | `4096` | The most connections one listener keeps open at the same time (`server.http.concurrency_limit` counts requests, not sockets). Further clients wait in the accept queue of the operating system until a connection closes, so a flood of idle connections cannot exhaust the file descriptors of the process. |
| `mode` | one of `"production"`, `"dev"` | `"production"` | `production` (the default, so a forgotten setting is the safe one) or `dev`. Production requires signing keys and refuses the plugins that drop or fake work: the memory store and mail transport, the echo renderer, the `noop` rate limiter, the recording HTTP client and the `eicar` scanner (each of these plugins says so in its descriptor, and `config check` and the plugin registry both read that one flag). The in-process rate limiter is the 1.0 limiter of a single instance (PLAN 1.1) and stays allowed. |
| `public_base_url` | string, optional | unset | The public base URL of this deployment (`https://calendar.example.org`): the origin that mails, feeds, client configuration and OAuth redirects use. Required; there is no default because it is deployment-specific. Links never come from the `Host` header. |
| `shutdown_delay` | string | `"0s"` | How long the server keeps accepting connections after it was asked to stop, while `/readyz` already answers 503 `draining`: the time a load balancer needs to notice and to stop sending new requests. Zero (the default) stops accepting at once. The delay comes before the grace period. |
| `shutdown_grace` | string | `"20s"` | How long shutdown waits for in-flight requests and workers before it stops them: what is still running at the end (connections included) is cut off. The process is gone at most `shutdown_delay + shutdown_grace + 10s` after the stop signal, so give the container a stop timeout that is longer. |
| `trusted_proxies` | list of string | `[]` | The reverse proxies whose `X-Forwarded-For` is trusted (CIDR ranges). The client address is the rightmost entry that is not a trusted proxy; without trusted proxies the header is ignored. |

### `[database]`

The table of the `postgres` plugin; see [Plugins](#plugins), kind `database`.

### `[plugins]`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `authenticators` | list of string | `["local"]` | The authenticator chain, in order. |
| `content_scanners` | list of string | `[]` | The content scanners applied to inline binary attachments. |
| `event_sinks` | list of string | `["log"]` | The event sinks every domain event is delivered to. |
| `http_client` | string | `"egress"` | The outbound HTTP client. |
| `mail_transport` | string | `"smtp"` | The mail transport: `smtp` or `memory`. |
| `outbox_handlers` | list of string | `["webhook"]` | The outbox handlers contributed by adapters. |
| `providers` | list of string | `[]` | The calendar providers that are compiled in and selected. |
| `rate_limiter` | string | `"memory"` | The rate limiter: `memory` (the in-process limiter of a single instance) or `noop`. |
| `scheduling_policy` | string | `"default"` | The scheduling policy. |
| `store` | string | `"postgres"` | The database: `postgres` or `memory` (development and tests only). |
| `templates` | string | `"minijinja"` | The template renderer. |

### `[plugin]`

`[plugin.<kind>.<name>]`: the table of the adapter called `<name>` of the kind `<kind>` (`[plugin.<name>]` when the name is selected for one kind only); its keys are listed per adapter under [Plugins](#plugins).

### `[mail]`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `allowed_recipient_domains` | list of string | `[]` | When not empty, only recipients in these domains receive mail; others are dropped and recorded. |
| `from_mode` | one of `"service"`, `"organizer"` | `"service"` | How the `From` header is formed. |
| `max_consecutive_failures` | integer | `5` | After this many failed sends in a row the circuit breaker opens and mail waits in the outbox. |
| `rate_limit_per_minute` | integer | `120` | The most mails the server sends per minute (all tenants together). |
| `redirect_all_to` | string, optional | unset | When set, every mail goes to this address instead of its recipients (staging). |

### `[templates]`

Defaults of the `minijinja` plugin; see [Plugins](#plugins), kind `templates`.

### `[scheduling]`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `external_per_event` | integer | `50` | The most external recipients of one event. |
| `external_per_organizer_per_hour` | integer | `100` | The most external recipients one organizer may invite per hour. |
| `external_per_tenant_per_day` | integer | `1000` | The most external recipients one tenant may invite per day. |
| `inbound_itip.enabled` | boolean | `false` | Whether the inbound endpoint accepts messages at all. Off by default. |
| `inbound_itip.require_dmarc_pass` | boolean | `true` | Whether the gateway must report a passing DMARC verdict; anything else is quarantined. |
| `max_sync_internal_attendees` | integer | `50` | Internal attendees up to this number receive the invitation in the organizer's transaction; above it delivery is queued (`internal_delivery`). |

### `[sharing]`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | boolean | `true` | Whether calendar sharing from client apps is available at all. |

### `[limits]`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `api.default_page_size` | integer | `50` | Page size when the client sends no `limit`. |
| `api.max_batch_body` | integer | `10485760` | Largest batch request body in bytes. |
| `api.max_batch_items` | integer | `1000` | Most items in one batch upsert. |
| `api.max_json_body` | integer | `1048576` | Largest JSON request body in bytes. |
| `api.max_page_size` | integer | `200` | Largest page size a client may ask for. |
| `api.max_scanned_objects` | integer | `5000` | Most objects one request of the event listings and of the event search reads from the store before it answers with the page it has and a cursor that continues behind them. |
| `dav.max_dead_properties` | integer | `50` | Most dead properties per binding. |
| `dav.max_dead_property_size` | integer | `4096` | Largest dead property, counting its namespace, its name and its value, in bytes. |
| `dav.max_multiget_hrefs` | integer | `1000` | Most hrefs in one `calendar-multiget`. |
| `dav.max_query_bytes` | integer | `67108864` | Most bytes of calendar data one `calendar-query` returns. |
| `dav.max_query_candidates` | integer | `10000` | Most candidates one `calendar-query` examines against its exact filter; more is `number-of-matches-within-limits`. A query without a filter that needs the text matches every candidate and is bound by `max_query_results` alone. |
| `dav.max_query_results` | integer | `10000` | Most objects one `calendar-query` returns. |
| `dav.max_request_body` | integer | `262144` | Largest PROPFIND, PROPPATCH or REPORT body in bytes. |
| `dav.max_response_bytes` | integer | `33554432` | Largest `multistatus` answer in bytes. An answer that grows beyond it is cut off: the response for the request URI says 507 `number-of-matches-within-limits` and the client asks for the rest in smaller steps. |
| `dav.max_search_terms` | integer | `8` | Most `property-search` elements or `search-token`s one principal search may have: every term is a condition the store evaluates on every principal of the tenant. |
| `dav.max_sharees_per_request` | integer | `100` | Most sharees (`CS:set` and `CS:remove` together) one `CS:share` request may name. Every sharee is a lookup of the application and a notification in the sharee's collection, so the number is bound on its own and not by the size of a multiget. |
| `dav.max_sync_members` | integer | `100000` | Most members one `sync-collection` listing holds (an initial listing that needs more is refused). |
| `dav.max_xml_attributes` | integer | `32` | Most attributes on one XML element. |
| `dav.max_xml_depth` | integer | `32` | Deepest XML element nesting. |
| `dav.max_xml_elements` | integer | `10000` | Most XML elements in one request body. |
| `dav.max_xml_namespaces` | integer | `64` | Most distinct XML namespaces declared in one request body. |
| `ical.max_alarms` | integer | `10` | Most `VALARM` components per component. |
| `ical.max_attendees_per_instance` | integer | `200` | Most attendees per instance (`C:max-attendees-per-instance`). |
| `ical.max_components` | integer | `1000` | Most components in one object. |
| `ical.max_inline_attach_bytes` | integer | `262144` | Largest inline binary `ATTACH` in bytes. |
| `ical.max_instances` | integer | `3000` | Most instances one expansion may produce (`C:max-instances`). |
| `ical.max_iterator_steps` | integer | `100000` | Most iterator steps one expansion may take. |
| `ical.max_nesting` | integer | `4` | Deepest component nesting. |
| `ical.max_observances` | integer | `200` | Most observances in one `VTIMEZONE`. |
| `ical.max_properties_per_component` | integer | `500` | Most properties in one component. |
| `ical.max_recurrence_dates` | integer | `1000` | Most `RDATE` plus `EXDATE` values per component. |
| `ical.max_resource_size` | integer | `1048576` | Largest accepted calendar object resource in bytes (`C:max-resource-size`). |
| `ical.max_time_range_years` | integer | `10` | Longest time-range or free-busy span in years (`C:valid-filter`). |
| `ical.max_value_length` | integer | `65536` | Longest unfolded property value in bytes. |
| `ical.max_year` | integer | `2100` | Latest accepted year (`C:max-date-time`). |
| `ical.min_year` | integer | `1900` | Earliest accepted year (`C:min-date-time`). |
| `ical.time_budget_ms` | integer | `2000` | Wall-clock budget for parsing and expansion in milliseconds. |

### `[security]`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `active_key_id` | string, optional | unset | The id of the key that signs and hashes new data; the first key when absent. |
| `auth` | any | unset | `[security.auth]`: the cache and backoff of the local authenticator (parsed by `davhaven-auth-local`). |
| `cors.allowed_origins` | list of string | `[]` | The origins (`https://admin.example.org`, `http://localhost:3000`) that may call the API from a browser. Empty by default: no browser origin is allowed. |
| `egress` | any | unset | `[security.egress]`: the outbound HTTP policy (parsed by `davhaven-http-egress`). |
| `keys` | list of table | - | The keys of the key ring: `[{id = "2027-01", secret_file = "/run/secrets/key-2027-01"}]`. |
| `max_mcp_token_days` | integer | `90` | The longest lifetime of a token with `mcp:*` scopes, in days. |
| `profile_signing.certificate_file` | string, optional | unset | A PEM file with the certificate of the signer first, followed by the certificates of its chain (without the root). It may be the same file as `private_key_file`: one combined PEM with the key and then the chain. The server reads it again within a minute of a change, so a renewed certificate needs no restart, provided the file is reached through a mounted directory (a single-file bind mount, a Compose or Swarm secret or a Kubernetes `subPath` pins the file: restart). |
| `profile_signing.private_key_file` | string, optional | unset | A PEM file with the private key of the certificate: PKCS#8 (`BEGIN PRIVATE KEY`) or PKCS#1 RSA, RSA or ECDSA P-256, not encrypted. The same file as `certificate_file` when one combined PEM holds both. Read again together with the certificate. |

### `[retention]`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `audit_days` | integer | `365` | Days to keep audit events. |
| `collection_changes_days` | integer | `90` | Days to keep the change log of calendars (older tokens answer `valid-sync-token`). |
| `deleted_calendar_days` | integer | `30` | Days between the deletion of a calendar and its purge. |
| `idempotency_hours` | integer | `24` | Hours to keep idempotency keys. |
| `oauth_state_days` | integer | `1` | Days to keep OAuth states. |
| `outbox_dead_days` | integer | `30` | Days to keep dead outbox messages for inspection. |
| `outbox_done_days` | integer | `7` | Days to keep processed outbox messages. |
| `principal_purge_days` | integer | `30` | Days between the deletion of a principal and its purge (`?purge=true` purges immediately). |
| `rsvp_token_days` | integer | `30` | Days to keep an RSVP token after it expired or was revoked, before the cleanup worker removes it. |
| `scheduling_inbox_days` | integer | `30` | Days to keep scheduling inbox items. |
| `webhook_delivery_days` | integer | `30` | Days to keep the delivery records of webhooks (the status of each attempt to deliver an event to a subscription). |

### `[webhooks]`

The table of the `webhook` outbox handler; see [Plugins](#plugins), kind `outbox_handler`.

### `[outbox]`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `backoff_base` | string | `"30s"` | The delay before the second attempt; it doubles with every further attempt. |
| `backoff_max` | string | `"1h"` | The longest delay between two attempts. |
| `batch_size` | integer | `25` | The most messages one dispatcher claims at a time. |
| `concurrency` | integer | `8` | How many handlers of one pass run at the same time. A claim lasts `lease` and every handler of the pass has to be done before 80 % of it has passed, so `concurrency` times the time a handler takes bounds what one pass can do; records that do not get a turn in time are put back without using an attempt. |
| `lease` | string | `"1m"` | How long a claim lasts before another dispatcher may take the message over. |
| `max_attempts` | integer | `12` | After this many attempts a message goes dead. |
| `max_webhooks_per_tenant` | integer | `50` | The most webhook subscriptions one tenant may have. Every event is expanded into one delivery per matching subscription, so the limit bounds the work one event costs the shared dispatcher. |
| `poll_interval` | string | `"2s"` | How long the dispatcher sleeps when a pass found nothing to do. |

### `[feeds]`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `max_bytes` | integer | `33554432` | The most bytes of calendar data one feed holds; a feed that needs more is cut (and logged). |
| `max_objects` | integer | `20000` | The most objects one feed holds; a feed that needs more is cut after them (and logged). |
| `refresh_interval` | string | `"PT15M"` | The refresh interval advertised to subscribers (`REFRESH-INTERVAL` and `X-PUBLISHED-TTL`), as an iCalendar duration. |
| `window_future_days` | integer | `365` | How many days after the start of the current UTC day a feed ends. |
| `window_past_days` | integer | `90` | How many days before the start of the current UTC day a feed starts. The window is anchored at the start of the UTC day, not at the instant of the request, so the entity tag of a feed can be known without rendering it: a feed changes at 00:00 UTC for the passing of time alone. |

### `[mcp]`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `allowed_origins` | list of string | `[]` | The origins an `Origin` header may carry; requests with another origin are refused. |
| `enabled` | boolean | `true` | Whether the `/mcp` endpoint is served at all. Tenants additionally switch MCP on in their settings (`mcp_enabled`, off by default). |
| `max_range_days` | integer | `92` | The longest time range (in days) `list_events`, `search_events`, `free_busy` and `find_free_slots` accept. |
| `max_results` | integer | `200` | The most results one tool call returns (the cap of every `limit`). It must not exceed `limits.api.max_page_size`, which caps every page of the application. |

### `[providers]`

`[providers.google]` and `[providers.microsoft]` are the tables of the providers (see [Providers](#providers)); `[providers.sync]` holds what is the same for every provider: how often and how the connected accounts are pulled.

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `google` | any | unset | `[providers.google]` (parsed by `davhaven-provider-google`). |
| `microsoft` | any | unset | `[providers.microsoft]` (parsed by `davhaven-provider-microsoft`). |
| `sync.backoff_max` | string | `"1h"` | The longest wait after failed pulls. The wait starts at a third of `interval` and doubles with every failure in a row. |
| `sync.batch_size` | integer | `8` | The most accounts one pass pulls; the rest wait for the next pass. |
| `sync.concurrency` | integer | `4` | How many accounts of one pass are pulled at the same time. |
| `sync.interval` | string | `"15m"` | How long an account waits between two pulls. |
| `sync.poll_interval` | string | `"1m"` | How long the sync worker sleeps when no account is due. A newly connected account is pulled at the next pass. |
| `sync.timeout` | string | `"1m 30s"` | The longest a single pull may take. One that takes longer is abandoned without advancing the cursor, and the account is tried again after the claim on it has run out. At most two and a half minutes. |

### `[observability]`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `dav_capture.allow_in_production` | boolean | `false` | Production mode refuses the capture, because it writes the calendar data of tenants to files. A staging instance that runs in production mode and captures on purpose sets this to `true`; the directory is then part of the data that must be protected like the database. |
| `dav_capture.dir` | string, optional | unset | The directory the captures are written to. |
| `dav_capture.enabled` | boolean | `false` | Whether the capture middleware is active. |
| `dav_capture.tenants` | list of string | `[]` | The tenants that are captured; capture needs an explicit allowlist. |
| `log_filter` | string | `"info"` | Which log lines are written: a `tracing` filter such as `info` or `info,davhaven_app=debug`. The `RUST_LOG` environment variable takes precedence. |
| `log_format` | one of `"json"`, `"text"` | `"json"` | The format of the log lines. |
| `metrics.tenant_label` | boolean | `false` | Reserved for metrics labelled with the tenant (off by default because of label cardinality; see `docs/ENGINEERING_RULES.md` R8). No metric carries the label yet, so `true` is **refused** (`docs/ROADMAP.md`) instead of accepted and ignored. |
| `otlp.endpoint` | string, optional | unset | The OTLP/gRPC endpoint of the collector, an `http` URL with the collector's gRPC port (`http://otel-collector:4317`); traces are not exported when absent. The export is plain gRPC: run the collector on the local network (a sidecar or the same host) and let it carry the traffic onwards with TLS. |
| `otlp.sample_ratio` | number | `0.1` | The fraction of traces that are sampled, between 0 and 1. |

## Providers

Calendar providers are cargo features of the server (`provider-google`, `provider-microsoft`), which the default build (the container image) has, and are disabled in the configuration by default. Select one with `plugins.providers` and switch it on with `enabled = true`. A provider that is enabled needs its client credentials, and its `redirect_uri` must be the callback of this server, `{server.public_base_url}/oauth/{provider}/callback`: `davhaven config check` compares the two. The OAuth client of a provider is asked for read access to calendars only.

### `[providers.google]`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `client_id` | string, optional | unset | The OAuth client id of the Google Cloud project. |
| `client_secret_file` | string, optional | unset | A file with the OAuth client secret. |
| `enabled` | boolean | `false` | Whether the provider is available. Off by default. |
| `future_days` | integer | `365` | How many days of the future the mirror covers: events that start later are not imported. A recurring series is imported whole whenever it overlaps the window. |
| `history_days` | integer | `90` | How many days of the past the mirror covers: events that ended earlier are not imported. |
| `redirect_uri` | string, optional | unset | The redirect URI registered with the OAuth client; it must be `{public base URL}/oauth/google/callback`. |

### `[providers.microsoft]`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `client_id` | string, optional | unset | The application (client) id of the Entra ID app registration. |
| `client_secret_file` | string, optional | unset | A file with the client secret of the app registration. |
| `directory` | string | `"common"` | The Entra ID directory people sign in to: `common` (work and school accounts of any organisation and personal Microsoft accounts, for an app registered as multi-tenant), `organizations`, `consumers`, or the id or a verified domain of one organisation (for an app registered as single-tenant). |
| `enabled` | boolean | `false` | Whether the provider is available. Off by default. |
| `future_days` | integer | `365` | How many days of the future the mirror covers: events that start later are not imported. A recurring series is imported as the occurrences inside the window. |
| `history_days` | integer | `90` | How many days of the past the mirror covers: events that ended earlier are not imported. |
| `redirect_uri` | string, optional | unset | The redirect URI registered with the app; it must be `{public base URL}/oauth/microsoft/callback`. |

## Plugins

The adapters of the ports a deployment chooses are selected by name in `[plugins]` and configured by one table each, written with the kind of the adapter (`[plugin.<kind>.<name>]`, see above). This reference describes a build with every cargo feature of `davhaven-server`, so that optional plugins are documented; the container image is built with the default features, and the plugins that need another feature are marked with it. A plugin that is not compiled in is not listed and cannot be selected. Kinds with *list* cardinality take several plugins (`authenticator` is an ordered chain: the first one that recognises the credential decides).

### `http_client`

Selected by `plugins.http_client` (single); default `"egress"`.

#### `egress`

Outbound HTTP over rustls with the egress policy: https only, private, loopback, link-local and metadata addresses denied after DNS resolution, no redirects, timeouts and size caps.

Configured by `[security.egress]` (or `[plugin.http_client.egress]`).

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `allow_cidrs` | list of string | `[]` | Address ranges that are allowed although they are private, loopback or link-local (for example `10.20.0.0/16`). The cloud metadata address stays denied. |
| `allow_hosts` | list of string | `[]` | Host names whose resolved addresses are allowed in the same way (exact, lowercase, no wildcards). |
| `allow_http` | boolean | `false` | Allows plain `http` URLs. Off by default; only for tests and closed networks. |
| `allowed_ports` | list of integer | `[]` | The ports a target may have (the port of the URL, or 443 and 80 when it names none). Empty allows every port; a deployment whose receivers all listen on 443 lists `[443]`, which keeps a tenant administrator from probing the other services of a public host. |
| `connect_timeout` | string | `"5s"` | The timeout of connecting. |
| `deny_cidrs` | list of string | `[]` | Further address ranges that are denied. |
| `max_concurrent_lookups` | integer | `16` | The most host name lookups that run at the same time. A lookup occupies a thread of the blocking pool until the resolver answers, however long that takes, so names that never answer must not be able to starve everything else that uses the pool. |
| `max_response_bytes` | integer | `65536` | The most response bytes of a webhook delivery the client reads. The status is what counts for a webhook, so a longer answer is cut at this size and the delivery is still judged by its status. |
| `oauth_max_response_bytes` | integer | `262144` | The most response bytes of an OAuth call (token exchange, refresh, revocation); a larger answer fails. |
| `provider_api_max_response_bytes` | integer | `8388608` | The most response bytes of a call to a provider's calendar API (a page of events); a larger answer fails. |
| `provider_api_total_timeout` | string | `"30s"` | The timeout of the whole request of a call to a provider's calendar API. |
| `total_timeout` | string | `"10s"` | The timeout of the whole request including the response body (webhooks and OAuth). |

#### `recording`

Sends nothing: records every request and answers with a fixed status. For tests and for copies of a deployment that must not call out. Not allowed in production.

Configured by `[plugin.http_client.recording]` (or `[plugin.recording]`).

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `max_requests` | integer | `1000` | How many requests the client remembers; when there are more the oldest are dropped, so a copy of a deployment that runs for weeks does not grow without limit. |
| `status` | integer | `200` | The status the client answers with when no answer is scripted. |

### `database`

Selected by `plugins.store` (single); default `"postgres"`.

#### `memory`

In-memory storage with real transactions, for development and tests (refused in production mode).

Configured by `[plugin.database.memory]`. The name `memory` is used by other kinds too (mail_transport, rate_limiter), so `[plugin.memory]` with keys in it is refused as ambiguous when more than one of them is selected: write the kind.

This table has no keys.

#### `postgres`

PostgreSQL storage with row-level tenant isolation, forward-only migrations and the outbox queue.

Configured by `[database]` (or `[plugin.database.postgres]`).

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `acquire_timeout` | string | `"5s"` | How long a request waits for a free connection before it fails as unavailable. |
| `allow_insecure_transport` | boolean | `false` | Production only: start although a connection URL reaches a remote host without requiring TLS (`sslmode` other than `require`, `verify-ca` or `verify-full`). Credential hashes, sealed secrets and calendar data cross this connection, so production refuses it unless this accepts the risk. The owner URL that `davhaven migrate` and `davhaven admin purge-audit` connect with is judged the same way. Local hosts (loopback, a socket) are never flagged; in `dev` mode the finding is only logged. |
| `allow_unbound_role` | boolean | `false` | Production only: start although the runtime role is not bound by row-level security (a superuser, a role with `BYPASSRLS` or the owner of the tables) or holds privileges that the role model of `docs/operations/database.md` withholds (`TRUNCATE`, writes to the audit log or the migration history, `EXECUTE` on the audit purge function). Tenant isolation and the append-only audit log then rest on the application alone, and this switch accepts every such finding at once, so it is the setting for a deployment that cannot have the two roles, not a way to change one thing about them. In `dev` mode the finding is only logged. |
| `idle_in_transaction_timeout` | string | `"30s"` | The `idle_in_transaction_session_timeout` of every connection: a transaction that sits idle between two statements for this long is terminated by the database (a request task that stalled would otherwise pin a pooled connection and its locks indefinitely). |
| `lock_timeout` | string | `"3s"` | The `lock_timeout` of every connection: how long a statement waits for a row lock (for example the lock of a busy calendar) before it fails as a timeout. Writers queue behind a hot calendar while they hold a pooled connection, so this bounds how long a queue can starve the pool. |
| `maintenance_timeout` | string | `"10m"` | The `statement_timeout` of the maintenance operations that legitimately run long (deleting a tenant, purging a principal, bumping the sync epoch of every collection after a restore). `0s` removes the limit. |
| `max_connections` | integer | `10` | The most connections the pool opens. |
| `migrate_on_start` | boolean | `true` | Whether `serve` applies pending migrations at startup (needs a working migration role). Production deployments set this to `false` and run `davhaven migrate` as a separate job with the owner credentials, so the serving process never holds them. |
| `migration_url` | string, optional | - | The connection URL of the owner role that runs migrations; defaults to `url`. |
| `migration_url_file` | string, optional | unset | A file that contains the migration URL. |
| `statement_timeout` | string | `"15s"` | The `statement_timeout` of every connection: no statement of a request runs longer. |
| `url` | string, optional | - | The connection URL of the runtime role (`postgres://user:password@host/db`). Secret; use `url_file` to keep it out of the configuration file. |
| `url_file` | string, optional | unset | A file that contains the connection URL of the runtime role. |

### `mail_transport`

Selected by `plugins.mail_transport` (single); default `"smtp"`.

#### `memory`

Delivers nothing: keeps every mail with its RFC 5322 bytes in memory. For development and tests; refused in production mode.

Configured by `[plugin.mail_transport.memory]`. The name `memory` is used by other kinds too (database, rate_limiter), so `[plugin.memory]` with keys in it is refused as ambiguous when more than one of them is selected: write the kind.

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `max_messages` | integer | `10000` | The most mails the transport keeps; the oldest are dropped first (the capture is bounded, like every queue of the server). |

#### `smtp`

Sends mail to an SMTP relay with lettre over rustls (STARTTLS or implicit TLS), one connection per mail, with an optional login.

Configured by `[plugin.mail_transport.smtp]` (or `[plugin.smtp]`).

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `allow_insecure_transport` | boolean | `false` | Production only: accepts `tls = "none"` to a relay on another host, for a capture server on a private network such as the mail catcher of a staging deployment. Invitations and RSVP links then travel unencrypted, so production refuses that combination unless this is set. It never accepts a login: with `username` and `password_file` set, production refuses `tls = "none"` to another host whatever this says. A relay on this host (`localhost` or a loopback address) is never flagged; in `dev` mode the finding is only logged. |
| `ehlo_name` | string, optional | unset | The name the server gives itself in `EHLO`. Relays judge it (some refuse or penalize a name that is not a fully qualified domain), so set it to a name of this deployment that resolves, for example the domain of the sender address. Without it the transport says `localhost`; the name of the machine is never used, because in a container it is a random identifier. |
| `host` | string | `"localhost"` | The relay's host name. |
| `password_file` | string, optional | unset | A file that contains the password. |
| `port` | integer | `587` | The relay's port. |
| `timeout` | string | `"8s"` | The timeout of connecting and of each SMTP command. |
| `tls` | one of `"starttls"`, `"implicit"`, `"none"` | `"starttls"` | How the connection is secured. |
| `total_timeout` | string | `"30s"` | The longest one mail may take from the first byte to the answer to the end of the data. It has to stay below 60 % of `outbox.lease` (the handler gives a send that share and counts a longer one as a failure of the relay); the default of 30 s fits the default lease of a minute. |
| `username` | string, optional | unset | The login name; set together with `password_file`. |

### `templates`

Selected by `plugins.templates` (single); default `"minijinja"`.

#### `echo`

Renders nothing: returns the model as JSON. For tests of consumers; refused in production mode.

Configured by `[plugin.templates.echo]` (or `[plugin.echo]`).

This table has no keys.

#### `minijinja`

Renders mail and page templates with MiniJinja under strict undefined behavior and auto-escaping; German and English default theme, themes are directories that bring only what they change.

Configured by `[templates]` (or `[plugin.templates.minijinja]`).

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `default_locale` | string | `"en"` | The locale used when neither the recipient nor the tenant has one (de and en ship with the server). |
| `default_theme` | string | `"default"` | The theme used when a tenant names none or names one that does not exist. |
| `fuel` | integer | `200000` | The most instructions one template render may take (`minijinja` fuel); a template that exceeds it fails. |
| `theme_dirs` | list of string | `[]` | Directories with themes (`{dir}/{theme}/{template}.{locale}.…`); a theme found here replaces the built-in theme of the same name. Later directories win. |

### `rate_limiter`

Selected by `plugins.rate_limiter` (single); default `"memory"`.

#### `memory`

Keyed token buckets and failure backoff in the memory of one process. Right for a single instance; several instances need a shared limiter.

Configured by `[plugin.rate_limiter.memory]`. The name `memory` is used by other kinds too (database, mail_transport), so `[plugin.memory]` with keys in it is refused as ambiguous when more than one of them is selected: write the kind.

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `buckets` | table | - | Allowances of named buckets. The tool calls of MCP tokens are charged per token to `mcp_read` (default 120 per minute) and `mcp_write` (default 30 per minute); an entry with these names tunes them. |
| `default.backoff` | table, optional | - | Makes this a backoff bucket. |
| `default.limit` | integer | - | The units allowed per window (rate bucket) or the failures that are free (backoff bucket). |
| `default.window` | string | - | The length of the window (rate bucket) or the quiet time after which failures are forgotten (backoff bucket). |
| `max_keys` | integer | `100000` | The most keys the limiter tracks; the least recently used are evicted first. |

#### `noop`

Allows every request. For tests and for deployments that limit in front of Davhaven; refused in production mode.

Configured by `[plugin.rate_limiter.noop]`. The name `noop` is used by other kinds too (authenticator, outbox_handler), so `[plugin.noop]` with keys in it is refused as ambiguous when more than one of them is selected: write the kind.

This table has no keys.

### `scheduling_policy`

Selected by `plugins.scheduling_policy` (single); default `"default"`.

#### `default`

Follows the scheduling settings of each tenant: invitations are added to calendars automatically when the tenant says so, resources accept or decline by free-busy, and mail to external addresses follows the tenant's external policy.

Configured by `[plugin.scheduling_policy.default]` (or `[plugin.default]`).

This table has no keys.

#### `manual`

Never adds invitations to calendars and never lets a resource answer on its own: people decide. Mail to external addresses follows the tenant's external policy.

Configured by `[plugin.scheduling_policy.manual]` (or `[plugin.manual]`).

This table has no keys.

### `authenticator`

Selected by `plugins.authenticators` (chain); default `["local"]`.

#### `local`

Verifies app passwords (DAV), API tokens (API, MCP), feed tokens and RSVP tokens against the store with keyed hashes, caches verifications and records their use. Configured by `[security.auth]`.

Configured by `[security.auth]` (or `[plugin.authenticator.local]`).

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `backoff_base` | string | `"1s"` | The block after the first failure beyond the free ones; it doubles with every further failure of the same key. |
| `backoff_free` | integer | `5` | How many failed authentications of one (login, client address) pair within `backoff_window` are free; the per-address bucket allows four times as many. |
| `backoff_max` | string | `"5m"` | The longest block (`Retry-After`) a failing client is asked to wait. |
| `backoff_window` | string | `"15m"` | The quiet time after which the failures of a key are forgotten. |
| `cache_max_entries` | integer | `10000` | The most verified credentials the cache holds; when it is full, expired entries and then the least recently used ones (down to about nine tenths of this number) are dropped. |
| `cache_ttl` | string | `"5m"` | How long a successful verification of a secret is remembered; the state of the credential (revoked, expired, suspended) is read on every use regardless. |
| `last_used_flush` | string | `"15m"` | The shortest interval between two writes of `last_used_at` of one credential. |

#### `noop`

Recognises no credential: every answer is not-applicable. For chains that are completed elsewhere and for tests.

Configured by `[plugin.authenticator.noop]`. The name `noop` is used by other kinds too (rate_limiter, outbox_handler), so `[plugin.noop]` with keys in it is refused as ambiguous when more than one of them is selected: write the kind.

This table has no keys.

### `event_sink`

Selected by `plugins.event_sinks` (set); default `["log"]`.

#### `log`

Writes every domain event to the structured log: ids and type, never the payload.

Configured by `[plugin.event_sink.log]` (or `[plugin.log]`).

This table has no keys.

### `outbox_handler`

Selected by `plugins.outbox_handlers` (set); default `["webhook"]`.

#### `noop`

Takes webhook deliveries and completes them without sending anything (they are marked dead, so the API shows that nothing was sent). For deployments that do not use webhooks.

Configured by `[plugin.outbox_handler.noop]`. The name `noop` is used by other kinds too (rate_limiter, authenticator), so `[plugin.noop]` with keys in it is refused as ambiguous when more than one of them is selected: write the kind.

This table has no keys.

#### `webhook`

Delivers domain events to webhook subscriptions as signed HTTPS requests (Standard Webhooks), retried with backoff until the retry window ends.

Configured by `[webhooks]` (or `[plugin.outbox_handler.webhook]`).

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `max_consecutive_failures` | integer | `20` | After this many failed deliveries in a row the subscription is disabled. |
| `retry_window` | string | `"1day"` | How long a delivery is retried before it goes dead. |

### `provider`

Selected by `plugins.providers` (set); default `[]`.

#### `fake`

A scriptable calendar provider with its own remote world: OAuth with PKCE, expiring tokens, calendars and events. For tests of the sync engine; production mode refuses it.

Part of builds with the cargo feature `provider-fake`; the default build (the container image) does not have it.

Configured by `[plugin.provider.fake]` (or `[plugin.fake]`).

This table has no keys.

#### `google`

Google Calendar: OAuth with PKCE and a pull-only import of the primary calendar into a mirror calendar. Off unless `enabled = true`; needs the OAuth client of a Google Cloud project.

Configured by `[providers.google]` (or `[plugin.provider.google]`).

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `client_id` | string, optional | unset | The OAuth client id of the Google Cloud project. |
| `client_secret_file` | string, optional | unset | A file with the OAuth client secret. |
| `enabled` | boolean | `false` | Whether the provider is available. Off by default. |
| `future_days` | integer | `365` | How many days of the future the mirror covers: events that start later are not imported. A recurring series is imported whole whenever it overlaps the window. |
| `history_days` | integer | `90` | How many days of the past the mirror covers: events that ended earlier are not imported. |
| `redirect_uri` | string, optional | unset | The redirect URI registered with the OAuth client; it must be `{public base URL}/oauth/google/callback`. |

#### `microsoft`

Microsoft 365 calendars: OAuth with PKCE and a pull-only import of the default calendar into a mirror calendar. Off unless `enabled = true`; needs the app registration of a Microsoft Entra directory.

Configured by `[providers.microsoft]` (or `[plugin.provider.microsoft]`).

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `client_id` | string, optional | unset | The application (client) id of the Entra ID app registration. |
| `client_secret_file` | string, optional | unset | A file with the client secret of the app registration. |
| `directory` | string | `"common"` | The Entra ID directory people sign in to: `common` (work and school accounts of any organisation and personal Microsoft accounts, for an app registered as multi-tenant), `organizations`, `consumers`, or the id or a verified domain of one organisation (for an app registered as single-tenant). |
| `enabled` | boolean | `false` | Whether the provider is available. Off by default. |
| `future_days` | integer | `365` | How many days of the future the mirror covers: events that start later are not imported. A recurring series is imported as the occurrences inside the window. |
| `history_days` | integer | `90` | How many days of the past the mirror covers: events that ended earlier are not imported. |
| `redirect_uri` | string, optional | unset | The redirect URI registered with the app; it must be `{public base URL}/oauth/microsoft/callback`. |

### `content_scanner`

Selected by `plugins.content_scanners` (set); default `[]`.

#### `eicar`

Reports the EICAR anti-virus test string as infected and everything else as clean. A fake for tests of the scanning path; it is never selected by default and production mode refuses it.

Configured by `[plugin.content_scanner.eicar]` (or `[plugin.eicar]`).

This table has no keys.

## Environment variables

Every key above has the variable `DAVHAVEN_` + its path in capitals with `.` written as `__`, for example `DAVHAVEN_OUTBOX__BATCH_SIZE`, `DAVHAVEN_SERVER__LISTENERS__OPS__BIND` and `DAVHAVEN_PLUGIN__MAIL_TRANSPORT__SMTP__HOST`. `DAVHAVEN_CONFIG` names the configuration file.
