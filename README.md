# Davhaven

Davhaven is a multi-tenant CalDAV and scheduling server written in Rust. It serves standard calendar clients
(Apple Calendar on macOS and iOS, DAVx⁵, Thunderbird, Evolution, Outlook with CalDav Synchronizer), delivers
invitations to internal and external attendees, and offers a management REST API and a Model Context Protocol
(MCP) endpoint for integrations.

Davhaven is generic: nothing in it is specific to one organisation. A deployment supplies its tenants, branding,
templates and adapter choices through configuration and the management API.

> **Status:** pre-1.0. The first release is 0.1.0 ([`CHANGELOG.md`](CHANGELOG.md)); until 1.0, interfaces, configuration
> keys and the database schema can still change. What is deliberately not supported, and why, is listed in [`docs/ROADMAP.md`](docs/ROADMAP.md).
> Read the [operations runbook](docs/operations/runbook.md) before putting an instance in front of real users.

## Features

- **CalDAV** (RFC 4791, 4918, 6578): discovery, PROPFIND/PROPPATCH, calendar-query, multiget, sync-collection,
  extended MKCOL, free-busy, VEVENT/VTODO/VJOURNAL storage with client bytes kept verbatim.
- **Multi-tenancy** with isolation enforced by the database schema: composite keys and PostgreSQL row-level
  security, not only application code.
- **Calendar kinds**: personal, group, managed (written through the API, read-only for clients) and
  user-created calendars, plus mirror calendars for imported provider calendars.
- **Sharing** from client apps (CalendarServer sharing as used by Apple Calendar) and through the API.
- **Scheduling** (RFC 6638, server side): internal attendees receive invitations directly; external attendees
  receive iMIP mails from themeable templates (German and English) and answer through an RSVP page.
- **Credentials**: per-device app passwords, scoped API tokens, feed tokens and RSVP tokens, all revocable and
  stored as keyed hashes.
- **Subscription feeds** (iCalendar over HTTPS), full or busy-only.
- **Management API** (`/api/v1`, OpenAPI 3.1) for provisioning, managed calendars, webhooks and integrations.
- **MCP server** with principal-bound, scoped tokens for reading and writing calendars.
- **Plugins** for every integration: storage, authentication, mail, templates, outbound HTTP, providers,
  webhooks, content scanning, rate limiting and scheduling policy.
- **Operations**: structured JSON logs, Prometheus metrics, optional OTLP traces, health endpoints and graceful
  shutdown.

Out of scope for 1.0 and tracked in [`docs/ROADMAP.md`](docs/ROADMAP.md): CardDAV, an inbound SMTP server, a
web calendar UI, WebDAV locking, RFC 3744 ACL writes, managed attachments and per-user alarms.

## Architecture

Davhaven follows a hexagonal architecture; dependencies point inwards only.

```
  binary:     davhaven-server (config, registry wiring, listeners, workers, CLI)
  protocols:  dav   api   web   mcp        ── all via davhaven-http (edge layers)
  app:        davhaven-app (service traits, use cases, authorization, scheduling, outbox, sync engine)
  core:       davhaven-domain (pure)   davhaven-ical (pure)   davhaven-wire (DTOs)
  ports:      davhaven-ports (traits, plugin registry, port errors)
  adapters:   store-postgres store-memory mail-smtp mail-memory mime templates auth-local crypto-local
              http-egress hooks-webhook ratelimit-memory scanner-eicar provider-{google,microsoft,fake}
  tests:      fixtures port-tests app-fake testkit it conformance   xtask
```

- `domain` and `ical` are pure: no I/O, no async runtime.
- Every outbound dependency is a port (trait) in `davhaven-ports`; adapters are selected by name through the
  plugin registry and each port has a contract test suite that every adapter runs.
- Protocol crates only see the application services, never ports or adapters.
- The layering is enforced in CI by `cargo xtask arch-check`.

The full design, data model and contracts are in [`docs/PLAN.md`](docs/PLAN.md); architecture decisions are
recorded in [`docs/adr/`](docs/adr/README.md).

## Quick start

Requirements: Rust (the toolchain is pinned in `rust-toolchain.toml` and installed by rustup on first use). A real
deployment also needs PostgreSQL 15 or newer (CI tests against PostgreSQL 18; nightly also against 15 and the
latest release).

The fastest way to see Davhaven run is development mode, which uses in-memory adapters and needs no database.
Everything is lost when the process stops, and production mode refuses these adapters, so use it for trying
things out only.

```sh
cargo build --release -p davhaven-server

export DAVHAVEN_SERVER__MODE=dev
export DAVHAVEN_SERVER__PUBLIC_BASE_URL=http://localhost:8080
export DAVHAVEN_PLUGINS__STORE=memory
export DAVHAVEN_PLUGINS__MAIL_TRANSPORT=memory
export DAVHAVEN_PLUGINS__HTTP_CLIENT=recording

target/release/davhaven config check   # validates and prints the effective configuration, secrets redacted
target/release/davhaven serve
```

Three listeners start: `public` on `0.0.0.0:8080` (CalDAV, feeds, RSVP pages), `internal` on `127.0.0.1:8081`
(management API and MCP) and `ops` on `127.0.0.1:9090` (health and metrics). In another terminal:

```sh
curl -i http://127.0.0.1:9090/readyz   # 200 when the instance is ready
```

The first tenant and its administration token are created with `davhaven admin bootstrap` (see
`davhaven admin bootstrap --help`); the [runbook](docs/operations/runbook.md) walks through it.

The container image is built from the `Dockerfile`. The git revision is a mandatory build argument, so that every
image can be traced to its source:

```sh
docker build --build-arg REVISION="$(git rev-parse HEAD)" -t davhaven .
```

The image runs `davhaven serve` as a non-root user and contains no configuration: supply a file (`--config` or
`DAVHAVEN_CONFIG`) or `DAVHAVEN_*` variables, with secrets as files.

### Commands

| Command | Purpose |
| --- | --- |
| `davhaven serve` | Run the listeners and the background workers. |
| `davhaven migrate` | Apply the database migrations with the owner role (`database.migration_url`). |
| `davhaven config check` | Validate the configuration and the secret files it names, and print what is configured. |
| `davhaven config reference` | Print the configuration reference of this build as Markdown. |
| `davhaven healthcheck` | Container health probe: asks `/readyz` of the ops listener. |
| `davhaven admin ...` | One-off administration: `bootstrap` a tenant, manage `system-token`s and `principal-token`s, `bump-sync-epoch` after a restore, `purge-audit`, `rotate-keys`. |

Deploying and operating Davhaven is described in [`docs/operations/runbook.md`](docs/operations/runbook.md).

## Configuration

Configuration is layered TOML plus `DAVHAVEN_*` environment variables (`__` separates nested keys); every secret
also accepts a `*_file` variant. Unknown keys and unknown `DAVHAVEN_*` variables fail startup. The generated
reference of every key is [`docs/configuration.md`](docs/configuration.md).

## Documentation

| Document | Contents |
| --- | --- |
| [`docs/operations/runbook.md`](docs/operations/runbook.md) | Deploying, running and troubleshooting, with pages on the [database](docs/operations/database.md), [backup](docs/operations/backup.md) and [keys](docs/operations/keys.md). |
| [`docs/configuration.md`](docs/configuration.md) | Generated configuration reference. |
| [`docs/api.md`](docs/api.md), [`docs/openapi.json`](docs/openapi.json) | Management API guide and OpenAPI document. |
| [`docs/interop.md`](docs/interop.md) | CalDAV client behaviour and known client quirks. |
| [`docs/ical.md`](docs/ical.md), [`docs/mail.md`](docs/mail.md), [`docs/templates.md`](docs/templates.md) | iCalendar processing, outgoing mail (iMIP), templates and themes. |
| [`docs/webhooks.md`](docs/webhooks.md), [`docs/egress.md`](docs/egress.md) | Webhooks and domain events, outbound HTTP policy. |
| [`docs/permission-matrix.md`](docs/permission-matrix.md) | Generated permission matrix. |
| [`docs/PLAN.md`](docs/PLAN.md), [`docs/adr/`](docs/adr/README.md) | Design, data model, contracts and decision records. |
| [`docs/testing.md`](docs/testing.md) | The test harness. |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | What is not in 1.0, and why. |

## Development

You need the pinned toolchain and a few cargo tools:

```sh
cargo install --locked cargo-nextest cargo-deny cargo-hack cargo-machete
scripts/check.sh            # everything CI runs on a pull request
scripts/check.sh fmt clippy # selected steps
cargo xtask arch-check      # layering rules
```

Tests that need PostgreSQL read `DATABASE_URL`; [`CONTRIBUTING.md`](CONTRIBUTING.md) shows how to start a
throw-away server with Docker. Read [`CONTRIBUTING.md`](CONTRIBUTING.md) and
[`docs/ENGINEERING_RULES.md`](docs/ENGINEERING_RULES.md) before opening a pull request;
[`docs/AGENTS.md`](docs/AGENTS.md) is the short version.

## Security

Please report vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE))
- MIT license ([`LICENSE-MIT`](LICENSE-MIT))

at your option. Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
this project, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms
or conditions.
