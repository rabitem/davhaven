# ADR-0001: Technology decisions

- Status: accepted
- Date: 2026-10-24
- Scope: PLAN 2.2

## Context

Davhaven is a workspace of many crates that are developed in parallel. They need one set of libraries, one async
model and one TLS stack, decided up front, so that the crates fit together and the root manifest rarely changes (R11).

## Decision

| Topic | Decision |
| --- | --- |
| Language | Rust 1.99.1, edition 2024, pinned in `rust-toolchain.toml`; workspace resolver 3. |
| Async ports | `#[async_trait]` with `Send` futures for every dyn port and service trait; injected as `Arc<dyn Trait>`. Large reads use cursor pages, not streams. |
| Runtime | tokio; cancellation with `tokio_util::sync::CancellationToken`. |
| Time | `chrono` + `chrono-tz` (bundled tzdb, updated by Dependabot); the CLDR Windows zone table is embedded in `ical`. Time only through the `Clock` port (R9). |
| iCalendar | `calcard`, pinned exactly and wrapped entirely in `ical` (no calcard type in any public API). Fallback for expansion gaps: `rrule` (declared in the workspace, not yet used). |
| HTTP server | axum + tower + hyper; DAV routes use `axum::routing::any` and dispatch on `req.method()`. |
| XML | `quick_xml::NsReader` into typed request enums; hand-written escaping writer; no serde derive for DAV XML. |
| Database | PostgreSQL through sqlx with runtime-checked queries (`query_as` + `FromRow`); no `query!` macros and no `.sqlx` cache. Migrations embedded with `sqlx::migrate!`. |
| TLS | rustls with the ring provider everywhere; `openssl`, `openssl-sys`, `native-tls`, `aws-lc-rs` and `aws-lc-sys` are banned in `deny.toml`. |
| Outbound HTTP | reqwest (`rustls-no-provider`, platform certificate verifier) only in `davhaven-http-egress`; the server installs the ring provider as the process default at startup. |
| OpenAPI | utoipa + utoipa-axum `OpenApiRouter`; every route registered regardless of features. |
| MCP | rmcp pinned exactly (server, macros, streamable HTTP server transport); protocol revision `2025-06-18`. |
| Mail | lettre (`builder`; SMTP with `tokio1-rustls`, ring, platform verifier) for transport and MIME. |
| Templates | minijinja with strict undefined behaviour and auto-escaping (the `fuel` feature is enabled for render limits). |
| Config | figment (TOML + `DAVHAVEN_` env, `__` nesting), `deny_unknown_fields`, `secrecy::SecretString`, durations via `humantime-serde`, JSON Schema via `schemars` for the generated reference. |
| Crypto | RustCrypto: `chacha20poly1305` (XChaCha20-Poly1305), `hmac` + `sha2`, `hkdf`, `argon2` (reserved), `subtle`, `zeroize`; randomness from `getrandom` behind the `IdGenerator` port. |
| Observability | `tracing` + `tracing-subscriber` (JSON), `metrics` + `metrics-exporter-prometheus` (recorder only; `/metrics` is served by the ops listener), OpenTelemetry with the OTLP gRPC exporter (`grpc-tonic`) behind the server feature `otlp` (ADR-0013). |
| Tests | cargo-nextest, proptest, insta, wiremock; cargo-deny, cargo-hack and cargo-llvm-cov in CI. |
| CLI | clap (derive) for `davhaven` and `davhaven-conformance`. |

All versions are exact (`=x.y.z`) in `[workspace.dependencies]`; crates inherit them and may only add features.
Dependabot proposes updates weekly with a seven-day cooldown.

### calcard spike

`calcard` 0.3.14 was evaluated before this decision was made.

**License.** `Apache-2.0 OR MIT` (crate metadata and SPDX headers); allowed by `deny.toml`, so `cargo deny`
checks it on every pull request. With `default-features = false` (no JMAP/JSCalendar) it pulls in `chrono`,
`chrono-tz`, `ahash`, `hashify`, `mail-parser` and `mail-builder`, all permissively licensed.

**Parsing.** Five realistic samples were parsed with `ICalendar::parse`, serialized with `Display` and parsed
again:

| Sample | Components | Result |
| --- | --- | --- |
| Apple Calendar: weekly series with `VTIMEZONE` (Europe/Berlin), `EXDATE`, one `RECURRENCE-ID` override, attendees, `VALARM`, `X-APPLE-*`, a folded UTF-8 summary | VCALENDAR, VTIMEZONE (DAYLIGHT, STANDARD), VEVENT, VALARM, VEVENT | parsed; round trip is a fixed point; output folded at 75 octets |
| Thunderbird `VTODO` with `DUE`, `PERCENT-COMPLETE`, escaped text, `X-MOZ-*` | VCALENDAR, VTIMEZONE, VTODO | parsed; byte-identical serialization |
| Outlook / CalDav Synchronizer event with the Windows TZID `W. Europe Standard Time` (quoted parameter) | VCALENDAR, VTIMEZONE, VEVENT | parsed; the TZID resolves to `Europe/Berlin` through the calendar's `VTIMEZONE` |
| Lenient input: LF line endings, `TZID=Europe/Berlin` without `VTIMEZONE`, zero-length `DTEND` | VCALENDAR, VEVENT | parsed; the IANA TZID resolves without a `VTIMEZONE` |
| `VJOURNAL` with a date-valued `DTSTART` | VCALENDAR, VJOURNAL | parsed; byte-identical serialization |

**Findings for `ical`.**

1. Serialization re-folds and normalises lines, so stored client bytes must stay verbatim and only objects the
   server changes are re-serialized (PLAN 2.7).
2. `expand_dates` honoured `EXDATE` and time zones, but in the Apple sample the `RECURRENCE-ID` override was
   reported as an additional instance while the overridden master instance was still emitted. `ical::expand`
   must match overrides to instances itself (or use the `rrule` fallback) and cover this case with RFC 4791 §9.9
   vectors and metamorphic property tests.
3. A truncated document (missing `END:VEVENT`/`END:VCALENDAR`) parsed without an error. `ical::parse` must reject
   unterminated components explicitly (`C:valid-calendar-data`).
4. Windows zone names resolved only through a matching `VTIMEZONE`; `Tz::from_ms_cdo_zone_id` does not map
   display names. The embedded CLDR Windows table in `ical::tz` remains necessary.
5. Non-iCalendar input is rejected with an error.

With these constraints `calcard` stays the parser; the limits of PLAN 2.15 and the never-panic property test are
enforced in `ical`, not delegated to the library.

### Resolution in `ical`

The findings above are resolved in `ical` (details in [`../ical.md`](../ical.md)):

1. Stored bytes stay verbatim. What the server serializes itself parses back to the same object and serializes to
   the same bytes (property test and fuzz target).
2. Overrides are paired with their instance by instant, independent of the zone they are written in, so an
   overridden instance is emitted once, from the override (`crates/ical/tests/corpus.rs`). `calcard` supplies only
   the wall-clock times of a rule; `DTSTART`, `RDATE`, `EXDATE`, overrides, zones and the limits are handled in
   `ical`, which is why the `rrule` fallback was not needed.
3. A structural scan runs before the parser and rejects documents with unbalanced `BEGIN:`/`END:` lines, so
   truncated uploads fail with `valid-calendar-data`. It also enforces the size, component, property, value and
   nesting limits before anything is allocated for them; a panic inside `calcard` is contained and reported as
   invalid data.
4. The CLDR Windows zone table is embedded in `ical` and checked in a unit test (every target is a valid zone name;
   the table is sorted and without duplicates).
5. One further observation from the never-panic test: `calcard` keeps a recurrence rule it cannot read as raw text,
   which its writer escapes again on every serialization, so such rules are refused at parse time.

## Consequences

- Crates rarely need manifest changes; new dependencies are added to the workspace manifest in a pull request of their own.
- One TLS stack and one crypto provider keep the supply chain small; `cargo deny` enforces the bans.
- `calcard` types never leak out of `ical`, so a parser swap stays local to `ical`.
- reqwest without a bundled provider requires the ring provider to be installed once at process start; tests that
  build an `HttpClient` do the same.

## Alternatives considered

- `icalendar` crate instead of `calcard`: weaker parsing of real client data and no expansion.
- Native async traits without `async_trait`: not object safe for `Arc<dyn Trait>` without boxing boilerplate.
- `aws-lc-rs` as rustls provider (rustls default): needs a C toolchain and CMake in every build; ring suffices.
- sqlx compile-time checked queries: require a database or `.sqlx` cache in every build of every crate.
