# ADR-0013: Server assembly, the mapping of configuration to adapters, and operations

- Status: accepted
- Date: 2026-10-26
- Scope: PLAN 2.3 (plugin model), 2.16 (configuration), 2.17 (operations), 4.5 (release); R1, R2, R3, R8; crate `server`

## Context

The server crate is where every other crate meets. Writing it needed decisions that no single contract decides: where the
configuration of an adapter lives (some adapters have tables of their own, `[database]` and `[security.egress]`, besides
`[plugin.<name>]`, and adapter names repeat across kinds), what a worker has to do to be "alive", in which order a process stops and
how long that may take, which connections the listeners defend against before a request exists, how OTLP over gRPC fits the
workspace dependencies, and what the image and the retention of images have to guarantee.

## Decision

**Configuration to adapters.** An adapter is configured by its **kind and its name**, because names repeat across kinds (`memory` is
the store, the mail transport and the rate limiter; `noop` is an authenticator, an outbox handler and a rate limiter). The table of
the adapter `smtp` of the kind `mail_transport` is `[plugin.mail_transport.smtp]`; `[plugin.smtp]` means the same when no other
selected plugin is called `smtp`, and a name that is selected for several kinds makes the unqualified table ambiguous, which is an
error that names the qualified spellings. Next to these, the adapters that have a table of their own keep it
(`database` for `postgres`, `security.auth` for `local`, `security.egress` for `egress`, `webhooks` for `webhook`, `templates` for
`minijinja`, `providers.<name>` for the providers); **the descriptor of the adapter names that table** (`PluginDescriptor::dedicated_table`), so the
server keeps no list of adapters, and the table belongs to the kind of the descriptor: a plugin of another kind with the same name never
receives it, and a descriptor of another kind that names the table is refused (`config::DEDICATED_TABLES` binds each table to one kind;
the registry refuses a second owner of a table). A table that is set while the build contains no adapter that reads it (`[database]` in a
build without the PostgreSQL store) is a warning of `config check`, so that it is not ignored without a word. The server builds **one configuration tree per kind** for the registry, so an adapter
parses exactly its own table, whichever way it was written. A key set in two places of one plugin is an error, because the operator
would not know which wins. A plugin must not be named like a kind (`[plugin.mail_transport]` would be both a table of the kind and a
plugin called `mail_transport`); the registry refuses such a name. This solves the problem of the shared `[plugin.memory]` table (the memory store, the memory mail transport and the memory rate limiter share a name, and each refuses keys it does not know) on the server side, without a change of the adapters or of the registry contract.

`davhaven config check` (and `serve`, once, before it builds anything) validates every selected plugin's table, and **every plugin judges
its own** (`PluginDescriptor::check`, `PluginRegistry::check_table`): it parses the table into its `Deserialize` struct, validates it as
`build` would, reads the files it names and returns the warnings, so a typo, a missing file or a theme that does not exist fails with the
key's name in the pipeline and not at the first request. The one rule that connects two sections (the SMTP send timeout against the outbox
lease, ADR-0008) stays in the server, which sees both. (There is no rule between the idempotency lease and the request timeout: the API
layer leases every key for the request timeout of the server plus 30 seconds, ADR-0012, so there is no second value to keep in step.) A plugin that has **no check of its own** (one that another crate registers later) is checked against the JSON Schema its
descriptor publishes (`additionalProperties: false` makes a typo an error) and its `build` does the semantic checks that `serve` runs right
after; the server never refuses a table because it does not know the plugin. Warnings are reported once. A table for an adapter this build
does not contain is an error that lists the adapters it does contain; a table for an adapter that is not selected is a warning. The SMTP
transport accepts `"tls"` as another spelling of `"implicit"` through a serde alias of the adapter, so its schema, its validation and
the generated reference agree.

`config check` prints the **effective** configuration: the defaults of this build, read from the JSON Schema of every table, with the
file and the environment laid over them, the table of every selected plugin with its own defaults, secrets redacted (values under keys
named like secrets, and credentials inside any URL whatever the key is called). `--explicit` prints only what was set.

**Production refuses what drops or fakes work.** One flag per descriptor decides (`PluginDescriptor::with_refused_in_production`): the
memory store and mail transport, the `echo` renderer, the `noop` limiter, the recording HTTP client and the `eicar` scanner carry it. The
registry refuses to build a flagged plugin with `RunMode::Production`, and `config check` asks the registry
(`PluginRegistry::refused_in_production`) without building anything, so the two answer from the same flag and the server keeps no list of
adapters; a test probes every kind and fails when a plugin refuses production that is not flagged. The in-process rate limiter stays allowed (PLAN 1.1: the limiter of a single instance). Production also refuses the
DAV capture unless `observability.dav_capture.allow_in_production` says that a staging instance captures on purpose.

**No plugin lives in the server.** The scheduling policies (`default`, `manual`) are the application's (PLAN 2.8,
`davhaven_app::policy`) and the server only registers them next to the adapters. The test scanner `eicar`, which makes the
`content_scanner` kind selectable twice (R2), is the adapter crate `davhaven-scanner-eicar` (cargo feature `scanner-eicar`, on by
default); it is refused in production and runs the contract suite of its port like every adapter. The registry introspection test asserts the rule for every kind; the provider kind has Google and Microsoft in the default build (ADR-0016).

**Workers.** The server drives `Worker::tick` and not `run`, because it needs a heartbeat after every pass. A worker is unhealthy in
`/readyz` when it has not **completed** a pass for twice its interval, or one pass has run for more than five minutes; a pass that
panics is counted, does not take the loop down and does not refresh the heartbeat. What a custom `run` loop would do on the way out
belongs in the worker's `Lifecycle` hook, which the server runs after the workers have stopped (the outbox dispatcher hands back its
leases there, with the unfinished attempt not counted; a test drives the server's supervisor against a handler that never finishes and
checks it). The application registers its own workers in `davhaven_app::workers::build` from the same `AppCore` that built the
services, so a module that brings a worker adds a line there and nothing in the server, and the state the core holds is shared.

**Shutdown has a bound.** `SIGTERM` flips `/readyz` to 503 `draining` at once. The listeners keep accepting for `server.shutdown_delay`
(zero by default: the time a load balancer needs to notice), then stop accepting and give requests in flight and the workers
`server.shutdown_grace`; what is still running then, connections included, is cut off. The worker hooks and the adapter hooks (in reverse
order of construction) share one budget of five seconds, the traces are flushed within four and the runtime ends within one: the process
is gone at most `shutdown_delay + shutdown_grace + 10 s` after the signal, a figure the server logs at start and the runbook asks the
container's stop timeout to exceed. The `ops` listener stops last so that the draining is visible. The exit status is 0 even when a
worker had to be cut off; that is logged.

**Connection limits act before a request exists.** hyper's header read timer starts only after the protocol has been detected, and
detection waits for the first bytes with no timer; HTTP/2 has no such timer at all. So the listeners drive connections with hyper's
builder directly and add an **idle watchdog** per connection: a connection with no request in flight for `header_read_timeout` is closed,
whatever protocol it speaks and whether it ever sent a request; HTTP/2 connections are also pinged at that interval; and
`server.max_connections` caps the open connections of a listener (further clients wait in the accept queue of the operating system),
because `concurrency_limit` counts requests and not sockets. The head size limit (431) is enforced on the parsed request when it is
below hyper's 8 KiB minimum buffer, in the form of the surface the path belongs to. hyper's read buffer is capped at the header limit,
which also bounds how much of a body is read per call; that trade-off is accepted for the small requests of calendar traffic and
documented in the module. The ops endpoints have a small bound of their own (16 concurrent requests, ten seconds) instead of the edge
layers of the API.

**Commands load what they need.** A job holds the secrets of its task: `migrate` and `admin purge-audit` read the `[database]` table,
`admin bump-sync-epoch` builds the store with a key ring that exists only in the process (the store seals nothing, so no key file is
read), `healthcheck` reads the ops address, and `serve`, `config check` and the commands that hash or seal secrets read everything. The
latter refuse to run without `security.keys`: development mode makes up a key ring per process, and a token hashed under one process's
key could never be verified by another. The `Foundation` of the assembly takes the clock and the id generator as parameters, so tests of
the assembled server run on the manual clock and sequential ids.

**OTLP over gRPC and the R1 exception.** Traces go over OTLP/gRPC (the OTLP default, port 4317). The workspace entry of
`opentelemetry-otlp` selects the `grpc-tonic` transport once; no HTTP exporter is compiled in next to it as dead weight. The
exporter brings `tonic` and its dependencies into `Cargo.lock`. tonic is an HTTP client, and R1 lets only `http-egress` depend on one, so R1 records **one exception**: the
exporter of `server` talks to the collector the operator names in `observability.otlp.endpoint`, a destination no tenant controls, and
carries spans only, so the egress policy that protects against tenant-chosen URLs does not apply to it. `xtask arch-check` allows
exactly that crate and dependency and recognises the exporter's transports and `tonic` as HTTP clients everywhere else. The export is
plain gRPC to a collector on the local network; `https` endpoints and credentials in the URL are refused at validation. TLS to a remote
backend is on the roadmap. **Every request is a server span** named after the method and the route template, whose parent is the span the
caller named in a W3C `traceparent` (the W3C propagator is installed whether or not spans are exported); the `port_call` spans of the
adapters nest under it, so the trace continues the caller's and its sampling decision wins. A unit test exports spans to memory and checks
the trace id, the parent and the nesting.

**The configuration reference** is rendered by the server binary (`davhaven config reference`, with every cargo feature on, so optional
adapters are listed and marked with the feature they need, since the image has the default features) and written or checked by
`cargo xtask config-docs` through a subprocess: linking the server into `xtask` would make `arch-check` compile every adapter.

**Key rotation is an application use case.** `admin rotate-keys` calls `davhaven_app::maintenance::keys::reseal_all`; the binary only
says which key a sealed value names (the format is the sealer's) and prints the result. Every module that seals a column contributes a
`Resealer` (today the webhook secrets) and a test reads the sealed tables from `davhaven-ports` and fails for one that has neither a
resealer nor a guard, so a new sealed column cannot ship unnoticed. Provider accounts reseal their tokens
(ADR-0016); a guard that fails a rotation while a table holds values nobody can reseal yet is still part of the mechanism, with no user today. Counts are per sealed
value, a tenant is audited (`keys.rotated`) only when something changed, and a secret that cannot be resealed is reported and left alone.
Credential hashes are not rehashed, because their plaintext is unknown; a credential keeps its key id, and retiring a key invalidates the
credentials made under it (`docs/operations/keys.md`). The command needs no store contract change.

**System tokens** (`admin system-token create|list|revoke`, `davhaven_app::maintenance::system_tokens`): the management API cannot mint a
`system` token (it belongs to no tenant), and `/api/v1/tenants` needs one, so the operator mints it with the configuration and the
database of the server. Creation is idempotent by label like `admin bootstrap`; the audit log is per tenant and a system token has none,
so creation and revocation are logged with the target `davhaven::audit`.

**The DAV capture** (`observability.dav_capture`) is a middleware around the DAV route group, outside its edge layers, for the tenants of
an allowlist: one JSON file per exchange (mode 0600, in a directory of mode 0700), credentials redacted. Because it sits outside the edge,
it carries limits of its own and never makes a request more expensive than the edge would: it reads a request body only within the DAV
limits and the request timeout and at most `server.http.concurrency_limit` exchanges at a time; a request or a response outside those
bounds passes through unrecorded; and it records only exchanges that the edge authenticated as a user of the listed tenant (the identity
the edge leaves in its response), so the 401 of a client that has not logged in and the probes of another tenant's users are never
written. It is a debugging mode, not a production feature: production refuses it unless allowed on purpose, and `config check` warns when
it is on.

**The image** is distroless on the user 65532 with `HEALTHCHECK CMD davhaven healthcheck`, and the build fails without the build argument
`REVISION`, which becomes the mandatory `org.opencontainers.image.revision` label. The `image` job of CI runs the image the way a deployment
does (read-only root, no capabilities, production mode) against PostgreSQL with the two-role model of `docs/operations/database.md` (an
owner role migrates, the server connects as a `NOBYPASSRLS` runtime role): version, metadata, the production rules refused for their own
reasons, `migrate`, `admin bootstrap` for two tenants, readiness through the binary and `/readyz` with a healthy database, one scenario over
HTTP (a user is provisioned through the API, writes over DAV, reads through the API and the other way round, and the second tenant sees
nothing of the first: 404), `/metrics`, `admin purge-audit` and a `SIGTERM` that ends with exit status 0.

**Image retention.** The retention is self-contained: it needs no word from a deployment repository, which therefore needs no write
access to the package. `.github/workflows/ghcr-retention.yml` keeps **every release tag, the newest 30 `main-*` versions and every
version younger than 30 days**, whatever its tags (so an image that was pushed a day ago is never deleted, and neither is an untagged
version that a multi-platform push leaves behind while it is young), and deletes the rest; it refuses to delete every version or more than
100 at once. The consequence for a deployment is the one that a pinned digest always has: an image of a `main-*` build that is neither
among the newest 30 nor younger than 30 days is gone from the registry, so a deployment that must be able to pull its image for longer
runs a release (a `v*` tag) or redeploys within that window.

## Consequences

- A deployment is described by one file or one environment and checked before it runs; the generated reference and the committed file cannot
  drift (`cargo xtask config-docs --check`).
- `observability.metrics.tenant_label` and the database pool metrics of PLAN 2.17 are not delivered: the key is reserved and refused when set
  to `true`, the pool belongs to the adapter; both are in `docs/ROADMAP.md`.
- The server depends on a few more crates through the OTLP exporter; none brings a second TLS stack or a banned license, and the one
  exception to R1 is named, narrow and enforced by `arch-check`.
- The `eicar` scanner is an adapter crate of its own; the server hosts no plugin, and `xtask arch-check` no longer lets it dev-depend on
  `port-tests`.

## Alternatives considered

- **A second table of options per adapter in the server** (instead of mapping the plan's tables): the adapters would parse one structure
  whichever way it was written down, but the operator would learn two places for one thing.
- **Unique plugin names** (`memory-store`, `memory-mail`) instead of kind-qualified tables: would change the adapter crates and the
  registry contract for a problem the server can solve where it builds the configuration trees.
- **Linking the server into `xtask`** for the reference: simpler code, but `cargo xtask arch-check` would compile the whole workspace.
- **Re-hashing credentials on use** to make key retirement free: needs the store to replace a hash atomically, a contract change
  that this decision did not make; ADR-0015 adds it.
- **OTLP over HTTP/protobuf on port 4318**: no tonic, but the OTLP default and the collector's usual port are gRPC on 4317, which the
  deployments this server is built for use; keeping both transports would compile an HTTP client library that nothing uses.
- **Refusing the DAV capture in production without a way out**: a staging instance that runs in production mode and captures on purpose could
  not produce fixtures, so the way out is an explicit key.
