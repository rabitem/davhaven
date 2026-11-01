# Engineering rules

These rules apply to every crate, every pull request and every contributor. CI enforces
the ones marked **(CI)**. A rule changes only through a pull request that edits this file and explains why.
Section numbers like "PLAN 2.6" refer to `docs/PLAN.md`.

## R1 Layering
Hexagonal architecture as in PLAN 2.1. `domain` and `ical` have no I/O and no async runtime. `ports` depends on
`domain` only and contains traits, port errors, the plugin registry, the system clock/id generator and (feature
`testing`) test doubles. `app` depends on ports, never on adapters. Protocol crates (`dav`, `api`, `web`, `mcp`)
depend on `app` and `http`, never on `ports` or adapters. Adapters depend on `ports` and `domain` (plus `mime`
for mail adapters), never on each other. Only `server`, `testkit` and test crates know concrete adapters.
`testkit` is used only by `it` and `conformance`. Dev-dependencies follow the same rules, and a crate never
dev-depends on a crate that depends on it. Only `http-egress` may depend on an HTTP client library. The one recorded
exception is the trace exporter of `server` (`opentelemetry-otlp`, gRPC transport): it talks to the collector that the
operator names in `observability.otlp.endpoint`, a destination no tenant controls, and carries spans only, so the egress
policy that protects against tenant-chosen URLs does not apply to it (ADR-0013); `xtask arch-check` allows exactly that
crate and dependency, and recognises the exporter's transports as HTTP clients everywhere else. The `server` hosts no
plugin of its own: every plugin is an adapter crate or the application's. The contract suites of the adapters run in their
crates; the suite of the application's scheduling policies runs in `crates/it` (`tests/scheduling/policy.rs`).
**(CI: `xtask arch-check`, normal and dev-dependencies)**

## R2 Every integration is a port
Every outbound dependency is a trait in `davhaven-ports`. Ports a deployment chooses (store, mail, templates,
HTTP egress, rate limiting, authenticators, event sinks, outbox handlers, providers, scanners, scheduling policy)
are selected by name through the plugin registry and have a production adapter plus a second selectable
implementation (memory, noop or fake). Pure ports (clock, ids, key ring, sealer, hasher, profile signer) are injected
directly and have a production implementation plus a test double. Every port has a contract suite in
`davhaven-port-tests` that every implementation runs. **(CI: registry introspection test, contract suites)**

## R3 Configuration over code
Behaviour toggles, adapter choices, limits, branding and templates come from configuration or tenant settings,
validated at startup into typed structs with `deny_unknown_fields` and actionable errors. Unknown `DAVHAVEN_*`
variables fail startup. Secrets accept `*_file`. Production mode refuses the plugins that drop or fake work (PLAN 2.3). Every option has a
default and is documented in the generated `docs/configuration.md`. No deployment-specific values in code.
**(CI: config-docs drift)**

## R4 Tenant isolation by construction
A tenant transaction is bound to one `TenantId` at `begin`; repository methods cannot reach another tenant.
Every tenant table has a composite key `(tenant_id, id)` and composite foreign keys; Postgres RLS is enabled and
the runtime role cannot bypass it. Invisible resources, including other tenants', answer 404. The permission
matrix covers cross-tenant access for every operation; the store contract suite checks every repository method
with a foreign tenant.

## R5 Errors
Typed errors per layer (`thiserror`): `StoreError`/`PortError` in ports, `IcalError`, `AppError` with
`ErrorKind` and `Precondition`. Each protocol crate maps them exactly once through an exhaustively
tested table (DAV status + precondition element, RFC 9457 problem, MCP result). Internal error text never reaches
a client. The only allowed stub is `AppError::unsupported()` / `PortError::unsupported()`; a release ships none that a
user can reach. `xtask unsupported` scans the code the server binary links, without test code; a stub that ships but
cannot be reached (the default of a service-trait method that every production implementation overrides) carries
`// unsupported-allowed: <reason>` on its line or directly above it. A capability an adapter permanently lacks is
`PortError::new(PortErrorKind::Unsupported, ..)`, not a stub.
**(CI: lint set R17; `unsupported` job warns on PRs and fails release tags)**

## R6 Security by default
* Server-generated secrets (≥ 128 bits, typed scannable formats, PLAN 2.6) are stored as HMAC-SHA256 with a
  keyed pepper and compared in constant time; argon2id is reserved for human-chosen secrets (none in 1.0).
  Plaintext is shown exactly once. The one exception is the RSVP link: a mail is composed again on every attempt, so its
  token is derived from the key ring and the id of its row, and only the keyed hash of its secret is stored (ADR-0007;
  PLAN 2.6).
* Credentials are bound to their surface (app passwords on DAV, API tokens on API/MCP, feed and RSVP tokens on
  their pages). No hard account lockout: per (login, IP) and per IP backoff.
* Secrets live in redacting types (`secrecy`), are zeroized, never logged; credential structs implement `Debug`
  by hand. Sealed data uses AEAD with associated data binding tenant, table, row and purpose.
* All outbound HTTP goes through `HttpClient` with the egress policy (https only, private/loopback/link-local/
  metadata ranges denied after DNS resolution, no redirects, timeouts, size caps).
* Request, header, XML, iCalendar and expansion limits from PLAN 2.15; parsers run with a time budget.
* `#![forbid(unsafe_code)]` in every crate. **(CI: cargo-deny advisories and bans, `unsafe_code` forbid)**

## R7 Contracts
The management API is versioned (`/api/v1`), additive only within a version, and documented by an OpenAPI
document generated from code and committed. MCP tool schemas, domain event schemas, the problem catalog and the
permission-matrix report are generated and committed too. Breaking changes need a new API version or a new tool
name. DAV behaviour follows the RFCs; deviations are documented in `docs/interop.md`.
**(CI: `xtask contracts`, `xtask matrix` and `xtask problems-docs` drift checks)**

## R8 Observability
Structured JSON `tracing` with request id, trace id, tenant id and principal id; never secrets, bodies,
iCalendar data or e-mail addresses. Tokens in URL paths are redacted before any logging; metric and span labels
use the route template, never the raw path. Every adapter method is wrapped in `ports::observe` (latency
histogram, outcome counter, span). Metric names follow PLAN 2.17 (`davhaven_` prefix). `/healthz`, `/readyz`,
`/metrics` are served on the ops listener.

## R9 Tests
Each change ships tests at the right level (PLAN 3.1): unit, property, port contract, app, protocol, matrices,
client flows; parsers get fuzz targets. Every bug fix has a regression test. Expected results for permissions
come from the hand-reviewed expectations file, never from the code under test.
Determinism: time and randomness only through `Clock` and `IdGenerator`; `Utc::now`, `Local::now`,
`SystemTime::now`, `Uuid::new_v4`, `Uuid::now_v7`, `rand::thread_rng` and `rand::random` are disallowed outside
the production clock/id implementations. Multistatus output is sorted; workers expose `tick()`; tests never sleep
(`start_paused` for timer logic). Fixture files are byte-exact (`.gitattributes`). proptest regressions are committed.
A test needing Postgres fails, never skips, when `CI=true` and no database is configured.
**(CI: tests on memory and Postgres, disallowed-methods, non-UTC job, nightly flake run; coverage floors on main)**

## R10 Documentation
Rustdoc on every public item. **(CI: `missing_docs` deny, rustdoc warnings are errors)** Every crate has a crate-level
overview. Architecture decisions are ADRs in `docs/adr/`. User-facing behaviour is documented in `docs/` (API,
problem catalog, configuration, interoperability, mail, templates, webhooks, operations, roadmap); a change that alters
behaviour updates the page that describes it in the same pull request. The generated pages (`docs/openapi.json`,
`docs/contracts/`, `docs/configuration.md`, `docs/permission-matrix.md`, `docs/problems.md`) change through their source
and `cargo xtask`, never by hand. **(CI: `contracts`, `matrix`, `config-docs` and `problems-docs` drift checks)**

## R11 Dependencies
Few, maintained, permissively licensed dependencies, declared once in `[workspace.dependencies]` with exact
versions; crates use `dep.workspace = true`. `Cargo.lock` is committed and changes with the manifest that caused it.
One TLS stack: rustls with the ring provider; `openssl-sys` is banned. Toolchain pinned in `rust-toolchain.toml`.
Dependabot keeps everything current (grouped, with cooldown); the container images that workflows pin by digest, which Dependabot
does not read, are compared with their registries every week (`image-pins.yml`). A dependency that no source of its crate uses is
removed (`cargo machete`). **(CI: cargo-deny licenses, bans, sources; `--locked`; `cargo machete`; one digest per image)**

## R12 Change process
Conventional Commits, small focused pull requests, green CI before merge, no attribution footers of tools.
Code reads like its surroundings. Changes to a published contract (the OpenAPI document, MCP tool schemas, domain
events, the problem catalog) are additive within a version (R7).

## R13 Generic by design
No organisation-specific names, URLs, hostnames, runner labels, branding or business rules in this repository.
Deployments provide them through configuration, themes, the management API and their own deployment repository.

## R14 Performance
Async throughout; CPU-heavy work (large iCalendar parsing, expansion, argon2) in `spawn_blocking` with a time
budget; one query to load authorization facts per request; indexed queries, no N+1; cursor pagination; bounded
queues, connection pools and timeouts on every outbound call; per-request verification cost independent of
argon2 (credential cache, HMAC).

## R15 Internationalisation and accessibility
Mail and web templates ship German and English; locale per tenant and recipient; templates render with strict
undefined behaviour and auto-escaping, and every template × locale × theme combination is tested. Web pages meet
WCAG 2.1 AA and work without JavaScript.

## R16 Schema compatibility
Migrations are forward-only and expand/contract, so that a rolling upgrade works: a released binary runs on the
schema of the next release. Drops and renames ship one release after the code stops using them. The runtime ignores
unknown newer migrations and checks a minimum schema version for readiness. Logic-relevant timestamps come from
`Clock`, not database defaults. **(CI: the upgrade test; the `schema-compat` job, which runs the previous release's
contract tests against a new schema, is not in place yet, see [`operations/database.md`](operations/database.md))**

## R17 Lint set
Workspace `[lints]`, inherited by every crate. **(CI: clippy `-D warnings`, all targets, all features and no
default features)**

* rustc: `unsafe_code = forbid`, `missing_docs = deny`, `rust_2018_idioms = deny`, `unreachable_pub = warn`,
  `unused_must_use = deny`.
* clippy deny: `all`, `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented`, `dbg_macro`,
  `print_stdout`, `print_stderr`, `await_holding_lock`, `disallowed_methods`, `disallowed_types`,
  `string_slice`, `indexing_slicing` (parsers use checked access).
* clippy warn: `pedantic` (allowed: `module_name_repetitions`, `must_use_candidate`), `clone_on_ref_ptr`,
  `large_futures`, `cast_possible_truncation`, `as_conversions`.
* `clippy.toml`: `allow-unwrap-in-tests`, `allow-expect-in-tests`, `allow-panic-in-tests`,
  `allow-indexing-slicing-in-tests`, the disallowed methods of R9, and `std::sync::Mutex` disallowed in async crates.
* Exceptions need `#[expect(lint, reason = "...")]` at the narrowest scope.

## R18 CI and supply chain
CI runs on GitHub-hosted runners by default. A deployment may move it to its own runners only through the
repository variable `CI_RUNS_ON` (a JSON array of runner labels, documented in `CONTRIBUTING.md`). Every job that
builds or tests, like each of the two weekly jobs (image retention and image pins), has the same `runs-on: ${{ fromJSON((github.event.pull_request.head.repo.fork ||
github.event.pull_request.user.login == 'dependabot[bot]' || github.actor == 'dependabot[bot]') &&
'["ubuntu-latest"]' || vars.CI_RUNS_ON || '["ubuntu-latest"]') }}`, so pull requests from forks and from Dependabot,
and a repository without the variable, use `ubuntu-latest`; fork and Dependabot pull requests never run on
self-hosted runners. Image retention takes its labels from the variable although it may delete packages: its token is
the `GITHUB_TOKEN` of the job, which is scoped to the job and to its `permissions` and expires with it, so no runner
keeps it, and the image job of the release holds `packages: write` on the same runners already. An organisation that has
no budget for hosted runners would otherwise never run it. Image pins read this repository and nothing more, and take their
labels from the variable for the same reason. Both run in a job container like the jobs that build, because a runner is not
expected to bring `gh` and `jq`. The one short job that holds a secret of another repository, the release dispatch, always
uses `ubuntu-latest`. No workflow names a runner label (R13). Runners chosen by the variable are trusted
infrastructure of the deployment and may share a host and a Docker daemon with other workloads: only the branches of
this repository, pushed by people who may write to it, and main run on them. Job
containers (pinned by digest, with CPU, memory and process limits) bound what a build uses and keep its files off the
host; they are not a security boundary. The one job that uses the Docker daemon of the runner, the image build of the
release, is not contained at all: it runs for main, version tags and a maintainer's manual run only, never for a pull
request, keeps its Docker configuration, builder, network and containers to itself and removes them by label. No
`pull_request_target` with checkout of PR code; workflows declare `permissions: {}` at the top and least privilege per
job; actions are pinned by commit SHA; `persist-credentials: false`. Release images are built once, smoke-tested and
only then pushed, only after the checks and the tests of the same commit succeeded, and addressed by immutable
digest; no release signing, SBOM or provenance attestations (delivery stays build, digest, deploy, health check);
deployment lives outside this repository.
**(CI: actionlint, zizmor)**
