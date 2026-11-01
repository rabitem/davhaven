# ADR-0011: The API contract is built from components; additions of the HTTP edge

- Status: accepted
- Date: 2026-10-26
- Scope: PLAN 2.10 (management API); R5, R7; crates `http`, `api`, `web`, `wire`

## Context

`docs/openapi.json` is generated from the registered routes of `davhaven-api`. Implementing the HTTP edge turned up
problems with the first generated document and two missing pieces:

1. The first document was 474 KB. Every operation repeated its problem responses, its path and header parameters and, in
   every `Page_{Item}`, a full copy of the item schema.
2. The domain types that cannot derive `ToSchema` reach the document through a bridge from their `schemars` schemas.
   The bridge inlined every referenced type and read the result with the OpenAPI types, which drop `const`. The values
   of every enumeration with documented variants (alarm action, attendee role, participation status, event status,
   class, transparency, the scheduling settings, ...) were lost: a client saw a `oneOf` of anonymous strings.
3. A property that refers to a named string with a default (`locale`, `timezone`) made OpenAPI Generator write the
   default as code, so a generated Java client did not compile. A union told apart by a tag (the alarm trigger) became a
   plain `oneOf`, which generators cannot read reliably.
4. `AppError` could not say `feature-not-enabled`: it is a 409 on the API and a 403 on DAV, a refinement of
   `conflict` that neither the kind nor a precondition can express.
5. Repeated `POST`s had no replay layer, although the plan promises one.
6. The schema of `ProblemCode` listed the names of the Rust variants (`BadRequest`) where the server sends the catalog
   code (`bad-request`): the derive of the schema does not see the `serde` rename of a `macro_rules` expansion. No
   generated client could have matched a problem.

[ADR-0012](0012-authentication-failures-credential-format-and-fenced-idempotency.md) records the contract changes that
review of the edge added to these decisions (authentication failures, the credential format, fenced idempotency); this ADR
describes the document.

## Decision

**The document is built from components.** `davhaven_api::document` registers the problem responses
(`components/responses`: `BadRequest` ... `Unavailable`, with `WWW-Authenticate` and `Retry-After` where the status
carries them), the parameters that several operations declare identically (`components/parameters`: `TenantPath`,
`LimitQuery`, `IfMatchHeader`, ...), the shared schemas of the wire crate and the item of every page, and drops what
nothing reaches. Operations refer to them. An optional parameter is a plain type, a file is `type: string,
format: binary`. Tests keep the document honest: every reference resolves, no problem response is repeated inline, no
component is unreachable, enumerations keep their values, the document stays below a size budget. Each operation
lists the problems that follow from what it accepts (413, 415 and 422 only with a body, 412 only with a conditional
header), and each `POST` declares the form of `Idempotency-Key` that is true for it. The names of the parameter
components (`TenantPath`, `WebhookIdPath`, `EventIfMatchHeader`, ...) are declared in the code and pinned by a test, not
derived from how often a variant is used: they become type names in generated clients, so they are published
contract. The schema of `ProblemCode` is written from the catalog list by the macro that defines the codes, and a test compares
it with `ProblemCode::ALL`.

**The bridge preserves what the domain says.** `wire::schema::try_bridge` rewrites the `schemars` schema before the
OpenAPI types read it: `const` becomes a one-value `enum`; alternatives that are only string constants become one string
enumeration whose description lists the values; named objects and enumerations stay components; named primitives (ids,
tags, names) become plain `string` properties, because a reference with a sibling default breaks generators; `anyOf` of a
primitive and `null` becomes `type: [primitive, "null"]`; and an internally tagged union becomes a polymorphic type with
one component per alternative and a `discriminator`. `wire::schema::shared_components` lists the domain types that wire
types refer to by name. The enumerations are checked against `ALL` of the domain, so a variant added there cannot be
missing here.

**Generators are part of the contract.** `crates/api/clients` generates a Java client and two TypeScript clients
(OpenAPI Generator and Orval, the generator of the frontends) from the committed document, compiles and type-checks them
and has the generated Java model read and write an event and a problem exactly as the server writes them (`fixtures`, kept
equal to the output of the wire types by a Rust test), and read both with an enumeration value it does not know. The
workflow `openapi-clients` runs it when the document or the project changes, with the tools pinned by a lock file
(`npm ci --ignore-scripts`) and by the `pom.xml`. The smoke found the settings that matter, which `docs/api.md`
records: `useOneOfInterfaces` does not compile with the `native` library of OpenAPI Generator 7.26;
`enumUnknownDefaultCase` is required for the compatibility policy (a value a later version adds must not make a deployed
client throw) and makes both alternatives of the alarm trigger match unless the union is resolved by its discriminator,
so it is used together with `useOneOfDiscriminatorLookup`. The enumerations stay closed lists in the document (an open
`anyOf` would give generators a string where they can give a type); the policy is carried by the documented generator
settings and by the smoke that reads an unknown value.

**An error can say `feature-not-enabled`.** The row is a refinement of `conflict` that neither the kind nor a
precondition could express, so it is a new precondition: `Precondition::FeatureNotEnabled` (the enum is
`#[non_exhaustive]`) with the constructor
`AppError::feature_not_enabled()` (kind `Conflict`). `ProblemCode::from_precondition` maps it, so `EdgeProblem` and every
other surface render the same row through the mapping they already have, and DAV can answer 403 for the same error. An
explicit catalog row on `AppError` (`with_problem`) was tried and dropped: it let any error name any row, including one of
another class, and the class could not be enforced.

**Repeated `POST`s are replayed by a layer of the API.** The layer sits inside bearer authentication, fingerprints the
request, asks the `IdempotencyService` what the key means and runs the handler in a task of its own, so that the outcome
is recorded even when the client disconnects. Successful responses are stored (status, `Content-Type`, `Location`, `ETag`,
JSON body); responses marked `no-store` are remembered as used and never stored (a secret is shown once); every other
outcome releases the key. When the service fails the request is refused (503) rather than run unprotected. What is
stored is decided by the response, not by the absence of a mark: a handler marks a response replayable, and the default
is that nothing is kept, so a secret cannot reach the table by omission. The layer asks for the lease (the request
timeout plus a margin), bounds the handler by the request timeout and settles with the reservation the service gave it,
so that the fenced operations of the store (ADR-0006) can ignore the late outcome of an attempt that lost its key;
ADR-0012 records the service methods that carry this.

## Consequences

- `docs/openapi.json` is about 260 KB instead of 474 KB and describes enumerations completely. Component names are part of the
  published document: renaming `PartStat` or `TenantSettings` renames the type in generated clients, so such a rename is a
  breaking change of `v1` like any other.
- Wire types that refer to a shared domain type by name (`schema_with = crate::schema::part_stat`) are references that
  only an OpenAPI document registering `shared_components()` resolves. The API crate does; a test checks that every
  reference of its document resolves and that the shared components are never defined twice, differently.
- `wire::schema::bridge` no longer inlines referenced types (its result refers to components, and
  `bridged_components` returns them), and the helpers for enumerations (`string_enum`) are gone. Both were internal to the
  bridge; the OpenAPI document is the contract.
- `Precondition` gained a variant (it is `#[non_exhaustive]`, so a `match` already has a catch-all arm) and `AppError`
  a constructor; code that builds errors with the existing constructors is unaffected.
- A new workflow runs Maven and Node on the runner when the document changes. It needs the network and is not a required
  check.

## Alternatives considered

- **Leave the bridge inlining and add the enumeration values by hand to the affected schemas**: fixes the symptom for the
  types of today and breaks for the next documented enumeration.
- **`allOf` wrappers for references with defaults**: generators handle a default next to `allOf` no better, and the
  named primitives carry nothing a client uses.
- **Implement `ToSchema` for the domain types**: the domain crate has no OpenAPI dependency, and adding one would put a
  presentation concern into the core.
- **A problem hint as a new `ErrorKind`**: `feature-not-enabled` is a conflict for every caller that does not know the
  row, so a new kind would change the class of failure for them.
- **An explicit catalog row on every `AppError`** (`with_problem`): any error could name any row, and nothing enforces
  that it stays within its class. A precondition is the mechanism the catalog already has for a refinement.
- **Open enumerations in the document** (`anyOf` of the values and a string, or `x-extensible-enum`): generators render
  them as strings or ignore the extension, which costs every client its type for a problem that one generator setting
  solves.
- **Replaying by the handler instead of a layer**: every handler would repeat the fingerprint and the recording, and a
  handler that forgot would run twice.
