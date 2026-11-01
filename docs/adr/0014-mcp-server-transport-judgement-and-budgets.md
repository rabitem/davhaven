# ADR-0014: The MCP server: stateless JSON transport, judgement per call, and what the application does for it

- Status: proposed
- Date: 2026-10-26
- Scope: PLAN 2.5, 2.6, 2.12, 3.2; R1, R2, R6, R9, R14; crate `davhaven-mcp`

## Context

The MCP crate (PLAN 2.12) serves ten tools to AI assistants over streamable HTTP with the pinned `rmcp` crate. Four
facts shape it. The services return what a person may see and decide through `davhaven_domain::authz::decide`, so the
protocol layer must not decide anything itself (PLAN 2.6). Protocol crates never depend on `davhaven-ports` (R1), so
there is no `Clock` and no `RateLimiter` in reach. The permission matrix (`crates/testkit/matrix/expectations.toml`) is
the hand-reviewed oracle: tenant tokens on MCP are `hidden`, a denied operation is `forbidden` or `hidden`, never a
success. And the transport library has defaults made for local servers (sessions, a loopback-only `Host` list, SSE).

An implementation that kept the busy-only rule, the budgets and a wall clock in the protocol crate would break these
facts. This ADR records the decisions that keep them out.

## Decision

- **Transport.** `rmcp`'s `StreamableHttpService` in stateless mode with JSON responses and no session manager: every
  request stands alone, `Mcp-Session-Id` is neither issued nor read. The router (not the transport) answers non-`POST`
  methods with 405, and a body that is no JSON-RPC message with the JSON-RPC fault, because the transport answers `415`
  and a plain text; the body is parsed once as the message it should be. The transport's `Host` check (loopback names by
  default) is switched off and the transport sees a neutral `Host`: the header is chosen by the attacker, so the exact
  `Origin` check in front of authentication is the defense, as the specification asks.
- **One protocol revision.** `2025-06-18`, the plan's revision, and only that: `initialize` is answered with it
  whatever the client asks for, and the client decides whether to continue. `2024-11-05` is the HTTP+SSE transport,
  which this endpoint does not serve, and `2025-03-26` requires servers to receive JSON-RPC batches, which `2025-06-18`
  removed and this server refuses.
- **Judgement per call.** The HTTP layer authenticates (401) and checks the origin (403) and nothing else. The handler
  judges each `tools/call`: only a principal token acts as a person (any other token: `not-found`, with a detail for the
  operator), a tool needs its scope (`forbidden`), and `tools/list` offers only the tools that pass the same two checks.
  The scope of a tool is the one the domain table gives its operation (`Operation::scope_rule(Channel::Mcp)`), which the
  services enforce again; the catalog of `davhaven-wire` repeats it for clients, and a test ties the two together.
- **The application shows the assistant only what it may see.** What is private to others, the busy-only form of an
  event, is the application's rule, applied where the facts are loaded (`objects::sight`), for every view that reaches
  the MCP channel: reads, searches, the answers of writes and replies. It is the rule of the subscription feeds, shared
  in code (`authz::busy_only`): an event of class `PRIVATE` or `CONFIDENTIAL` in a calendar the reader does not own. A
  text search leaves such events out of the text match, so it cannot be used to read what they say, and an update of an
  event the assistant sees as busy time is refused, so `class: public` cannot unmask it. `writable` is
  `domain::authz::can_write_events`, the rule `decide` applies. The protocol crate only maps fields.
- **The person comes from `PrincipalService::current`,** read at most once per call and only when an answer says
  something about people (`organizer_is_me`, `my_partstat`, `is_me`) or `list_calendars` needs the name of the home. It
  reads no calendar and needs no scope, so a token that only writes can write. A service that does not implement it
  answers `not-implemented`; nothing is guessed in its place.
- **Budgets are the rate limiter's.** `AuthService::charge_budget` charges each call to the bucket of its token
  (`mcp_read`, `mcp_write`), so the allowance is the configuration of the limiter the deployment chose
  (`[plugin.rate_limiter.memory.buckets.mcp_read]`, 120 and 30 per minute by default) and follows a shared limiter when one exists.
  Refusals are counted (`davhaven_budget_refusals_total{class}`) and audited as `rate_limit.tripped`, one record per
  token, budget and minute when the token trips and one with the total when that minute ends. A limiter that does not
  answer lets the call through.
- **The present is the application's.** `search_events` is the one tool that defaults to "now": `AppServices::now()`
  reads the clock `app::build` was given, the same one the services use, so tests that inject a manual clock reach it.
  The protocol crate has no clock of its own.
- **The tenant switch is enforced** where authentication is decided: `tenant.settings.mcp_enabled` (off by default)
  refuses to mint tokens with `mcp:*` scopes (`feature-not-enabled`, as feeds) and the MCP channel does not authenticate
  for a tenant that has not switched it on (`not-found`: for that tenant the endpoint does not exist). `mcp.enabled`
  removes the endpoint for the whole deployment.
- **`create_event` creates once.** `ObjectService::create_event` returns the event a repeated `client_request_id`
  already made (`created: false`, nothing written, nobody told) and refuses a key that names an event with other content
  (`conflict`), so an assistant that reuses an id cannot rewrite an earlier event or one that an integration manages. The
  management API's `PUT …/by-key/{key}` stays an upsert.
- **`delete_event` says whether there was something to delete.** `ObjectService::delete_event_if_present` answers
  `false` for a whole event that is not there after the deletion was decided for the caller, so a denied deletion is a
  denial and never `deleted: false`; an instance or a condition on a missing event stays `not-found`.
- **Results.** Success: `structuredContent` and the same JSON as text. Failure: `isError: true`, a short text and, in
  `_meta["davhaven/problem"]`, the problem document (`errors[]` included) with the retry hint beside it. **A failed
  result has no `structuredContent`; this amends PLAN 2.12.** Every tool announces an `outputSchema` and the specification
  requires structured content to conform to it; a client that validates whenever the field is present would turn every
  failure into an exception of its own and the model would never see it. The alternative, a ProblemDetails alternative in
  every output schema, would put an `anyOf` at the root of schemas that clients expect to be objects.
- **The contract includes the vendor members.** `_meta["davhaven/required_scope"]` of a tool and
  `_meta["davhaven/tools_version"]` of the `initialize` result come from `wire::mcp::tools_document()`, so
  `docs/contracts/mcp-tools.json` and `xtask contracts --check` cover them.

## Consequences

- The tools work against the real application (`crates/it/tests/mcp` runs every tool over the real services, with the
  `rmcp` client as an independent client over a socket).
- Additive changes to shared crates: `AppServices.clock` and `AppServices::now`,
  `AuthService::charge_budget`, `ObjectService::create_event` and `delete_event_if_present` (all with defaults),
  `PrincipalServiceImpl::current`, `RateKey::MCP_READ/MCP_WRITE`, `domain::can_write_events`, the defaults of the two
  buckets in `ratelimit-memory`, `testkit` re-exporting `davhaven_mcp`.
- The budgets of a deployment with several instances are per instance until a shared limiter exists (backlog).
- No CORS: browsers cannot call the endpoint, whatever `mcp.allowed_origins` says (`docs/ROADMAP.md`).
- The log filter of the server never lets `rmcp` log below `info`: the library logs requests and results (titles,
  attendee addresses) at `debug` and `trace` (R8).

## Alternatives considered

- **Sessions (`LocalSessionManager`).** State to lose on restart and to hijack, an SSE stream per client, nothing a tool
  server of request-response tools needs.
- **403 for tenant and system tokens at the edge.** Clearer for an operator, but it contradicts the oracle of the matrix
  and makes MCP answer differently from `decide`.
- **The viewer projection in the protocol crate** (`current` plus the home listing on every call, the
  busy-only rule in `render`). Three surfaces then follow three rules, every call costs two extra transactions, and a
  write-only token fails on the listing's scope.
- **A fingerprint-checked `get` then `put` in the tool** for the idempotent creation. A race between two creations with
  the same key could still merge; the application decides in the transaction of the write.
- **Budgets in the crate** (token buckets in memory). They bypass the limiter the deployment chose, cannot be shared
  between instances, and trips are neither audited nor counted.
- **Per-call claims about structured content** (`anyOf` with the problem schema). See Results.
- **`rmcp`'s `#[tool]` macros.** The schemas, names and annotations are the committed contract of `davhaven-wire`; the
  handler builds the `Tool` descriptions from it, so a drift cannot happen between the contract and the server.
