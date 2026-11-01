# Rules digest for contributors

A one-page summary for human and automated contributors (including coding assistants). The binding text is
[`ENGINEERING_RULES.md`](ENGINEERING_RULES.md) (rules R1–R18) and [`PLAN.md`](PLAN.md); when this page and those
documents disagree, they win.

## Before writing code

- Read the relevant section of [`PLAN.md`](PLAN.md) and the rules. The plan is the contract; if you think it is
  wrong, raise it in an issue instead of inventing an alternative design in a pull request.
- Edit only the crates and modules your change is about. Contract changes (domain, ports, service traits, wire
  types, the root `Cargo.toml` and `Cargo.lock`) should be additive where possible and go in a pull request of their
  own.

## Architecture (R1, R2)

- `domain` and `ical`: pure, no I/O, no async runtime. `ports` depends only on `domain`.
- `app` depends on ports, never on adapters. Protocol crates (`dav`, `api`, `web`, `mcp`) depend on `app` and
  `http`, never on `ports` or adapters. Adapters never depend on each other (mail adapters may use `mime`).
- Only `http-egress` talks HTTP to the outside. Only `it` and `conformance` use `testkit`.
- `cargo xtask arch-check` enforces this, including dev-dependencies.

## Code (R5, R6, R9, R17)

- `#![forbid(unsafe_code)]` everywhere. No `unwrap`, `expect`, `panic!`, `todo!`, `unimplemented!`, `dbg!` or
  printing outside tests; parsers use checked indexing.
- Typed errors (`thiserror`); internal error text never reaches a client. The only stub is
  `AppError::unsupported()` / `PortError::unsupported()`.
- Time and randomness only through `Clock` and `IdGenerator`; `Utc::now`, `SystemTime::now`, `Uuid::new_v4` and
  friends are disallowed by clippy. No `std::sync::Mutex` in async code.
- Tenant isolation by construction: a transaction is bound to one tenant; invisible resources answer 404.
- Secrets in `secrecy` types, never logged; outbound HTTP only through the egress policy.
- Exceptions need `#[expect(lint, reason = "...")]` at the narrowest scope.

## Tests and docs (R9, R10)

- Tests at the right level (PLAN 3.1); every bug fix has a regression test; tests never sleep; fixture files are
  byte-exact.
- Rustdoc on every public item; behaviour visible to users is documented in `docs/`.

## Dependencies (R11)

- Every dependency is declared once in `[workspace.dependencies]` with an exact version and inherited with
  `workspace = true`. rustls with ring is the only TLS stack.

## Process (R12, R13, R18)

- Conventional Commits; small pull requests; green CI (`scripts/check.sh` runs the same steps locally;
  see [`CONTRIBUTING.md`](../CONTRIBUTING.md)).
- No attribution footers or trailers added by tools in commits or pull requests.
- Nothing organisation-specific in this repository (names, URLs, hostnames, branding).
- Generated documents (`configuration.md`, `permission-matrix.md`, `openapi.json`, `contracts/`) are regenerated with
  `cargo xtask`, never edited by hand.
- Workflows: `permissions: {}` at the top, actions pinned by SHA, `persist-credentials: false`.
