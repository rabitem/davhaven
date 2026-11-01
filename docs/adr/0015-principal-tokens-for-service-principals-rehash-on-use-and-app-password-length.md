# ADR-0015: Principal tokens for service principals, re-hash on use, and the secret length of app passwords

- Status: proposed
- Date: 2026-10-27
- Scope: PLAN 2.6, 2.9, 2.10, 2.12; R6, R9, R16; an assistant that reads and writes the team calendars of a tenant

## Context

A deployment needs to let an AI assistant act on the calendars of a tenant through MCP. Four facts of the first design
made that impossible, and a fifth was found on the way.

1. **No way to mint the token.** PLAN 2.12 issues `mcp:*` scopes through `POST …/api-tokens` and PLAN 2.6 says a token
   mints tokens with a subset of its own scopes. A tenant token cannot hold `mcp:*` (`Scope::allowed_for`), so no token
   could ever mint one: the tests used the internal channel, which a deployment has no command for.
2. **No grants for the principal.** Grants were refused for service principals (`422 /grantee`), although a service
   principal is exactly the principal that holds principal tokens for the API and MCP.
3. **App passwords had 100 secret bits.** An app password of seven base32 groups has 140 bits, of which the 40 of the prefix
   are stored and listed in clear; R6 asks for at least 128 secret bits.
4. **A key rotation was a one-way door.** A credential hashed under a retired pepper key is unverifiable once the key
   leaves `security.keys`, and nothing moved a credential to the active key, so a key could be retired only by
   reissuing every credential.
5. **Provisioning could not tell a hidden principal from a conflict**: a deleted, unpurged principal keeps
   its name, `external_ref` and addresses reserved, and a client got a generic 409 for each.

## Decision

- **Principal tokens for service principals.** The rule "a token mints tokens whose scopes are a subset of its own"
  stays, with **one exception**: the `mcp:*` scopes, which a tenant token cannot hold. A tenant token with
  `credentials:write` may put them on a **principal token for a service principal**, **provided it holds the API scope
  that reaches the same data**: `events:read` for `mcp:read`, `events:write` for `mcp:write` and for
  `mcp:schedule_external` (the API sends invitations by mail when a write asks for it). The condition is the reach of
  MCP: DAV caps managed calendars at read and MCP does not, so `mcp:write` reaches what `events:write` reaches there,
  and a token that cannot write events itself must not be able to hand out that power. Every other scope of the token
  (`calendars:*`, `events:*`) still has to be one the minter holds, so the exception is as narrow as the need. It adds
  only the reach of MCP to what `credentials:write` already is: the power to act as any principal of the tenant that
  can act (it mints app passwords, which log in over DAV, and principal tokens). It does not extend to users or
  resources: their tokens carry only the scopes the minter holds, and MCP scopes reach a user only from the operator.
  What the token does, it does *as* the principal, through the same decisions as DAV; there is still no on-behalf-of
  and no per-request choice of the principal. The check is in the
  credential service, after the principal is read (the kind of the principal decides), and the rules of MCP tokens
  (a tenant that switched MCP on, an expiry within `security.max_mcp_token_days`, never outliving the minter) are
  unchanged.
- **`davhaven admin principal-token create | list | revoke`.** The operator mints, lists and revokes principal tokens
  from the host, through the credential service on the internal channel, like `admin bootstrap` does for tenant tokens:
  the same validation, the same `token.created` and `token.revoked` audit records (actor `system`), idempotent by
  (principal, label), the secret to a file with mode 0600 or to standard output once. The internal channel is the
  operator, so the subset rule does not apply to it: it is the one path by which MCP scopes reach a user.
- **API grants to service principals.** `PUT …/grants/{grantee}` accepts users, groups and service principals (never
  the owner or a resource). Client sharing (`CS:share`) stays with users and groups, and principal search does not find
  service principals, so they appear in no sharing UI: `CS:invite` does not list them, a `set` for one answers
  `invalid-sharee` and a `remove` `need-privileges`, on every kind of calendar, so a client never lists or undoes the
  grant of an integration.
- **Nine groups.** An app password is nine groups of four base32 characters: 180 bits, of which the 40 of the prefix are
  stored and shown and the 140 of the rest are the secret, above the 128 of R6. The prefix keeps its size because it is
  the unique key of the credential table.
- **Re-hash on use.** A credential that is used moves to the active pepper key: after a **fresh** verification (never
  after a cached one) of a credential whose hash names another key, the authenticator hashes the secret again and the
  store swaps the hash with a compare-and-set on the old key id (`CredentialRepo::rehash`, an additive method, ADR-0006).
  Failures are logged, never fail the request. It runs in a tenant transaction because system scope may not overwrite a
  credential hash (ADR-0005 item 3), so **system tokens are not moved** (they are recreated with `admin system-token`).
  A key can be removed when no live credential names it; `docs/operations/keys.md` has the query and the waiting rule.
- **Reserved values.** A create or replace whose `external_ref` or address belongs to a deleted principal answers
  `409 external-ref-reserved` / `address-reserved` (new catalog rows and preconditions); the name answers 412 to
  `If-None-Match: *` like every name that exists, and `409 name-reserved` to a write without it, so that a declarative
  client can tell the two apart. The check runs before the write, in the transaction, so it does not
  depend on the unique constraint of a database that aborts a transaction on a violation; a collision with a live
  principal stays the plain 409.
- **Smaller changes of the same round.** The tenant theme is optional (`None` follows `templates.default_theme`; an empty
  `RenderRequest.theme` asks the renderer for its default) and `admin bootstrap` takes the settings a first deployment
  needs as flags, including `--mcp-enabled`, so that no system token and no `PATCH` is needed.

## Consequences

- An assistant is provisioned with three calls and no operator: a service principal, grants, a token. Where there is no
  tenant token with `credentials:write` yet, the operator mints the token from the host.
- `credentials:write` stays what it was (the power to act as the tenant's principals); the documentation now says so in
  one place (`docs/api.md`, `docs/interop.md`) and the exception is bounded by kind (principal tokens of service
  principals only), by tenant switch and by expiry.
- A rotation no longer needs a coordinated reissue: used credentials follow the active key, and the operator reads from
  the database when the old key is no longer needed. Credentials that nobody uses still depend on it, which is the
  point: retiring the key ends them.
- A rolling change of `security.active_key_id` has instances that disagree on the active key for a while, and a used
  credential can then move between the two keys more than once (each move is a compare-and-set that succeeds). That is
  harmless and ends with the rollout; `docs/operations/keys.md` says to keep the mixed state short.
- Three contract additions are visible to other crates: `CredentialRepo::rehash`, and the three problem rows
  (`name-reserved`, `external-ref-reserved`, `address-reserved`).
- **Tests.** The fixture world has two service principals that are granted calendars (`assistant`, `importer`), with rows in
  the permission matrix for the API and MCP, and the staging runner issues the MCP tokens of the service principals through
  the management API as this ADR describes and those of users through the command of the operator
  (`--principal-token-command`, `docs/testing.md`). Tests in `crates/it` and `crates/server` pin the behaviour.
- **Not done here.** `docs/problems.md`, the problem catalog with the new `409` rows, does not exist yet (tracked in
  [`../ROADMAP.md`](../ROADMAP.md)). The rows are documented in the OpenAPI document (`putPrincipal`), `docs/api.md` and
  `docs/interop.md`, and defined in `wire::ProblemCode`.

## Alternatives considered

- **`mcp:*` on tenant tokens.** Rejected: a tenant token acts as nobody and administers; giving it assistant scopes
  would mix two roles in one credential and break the permission matrix's rule that tenant tokens on MCP are hidden.
- **The exception for every principal, or for every scope of a service principal.** Rejected: the first would let a
  provisioning token hand MCP access to the people of the tenant, the second would let it hand out `events:*` and
  `calendars:*` it does not hold (which reach managed calendars that DAV caps at read). Service principals are the
  machine identities the administrator provisions for exactly this, and MCP is the one thing a tenant token cannot hold.
- **The exception without the condition on the API scope.** Rejected (found in review): `credentials:write`
  alone would then mint `mcp:write` for the service principal that owns a managed calendar, and `mcp:schedule_external`,
  for a token that could neither write that calendar nor send mail itself, which is the same escalation as the second
  alternative with the MCP scopes in place of `events:*`.
- **Re-hashing only away from keys marked as retired** (a `retired` flag on `[[security.keys]]`). Not now: it would stop the
  back and forth of a rolling change, but a flag that every deployment has to keep in step with `active_key_id` is more
  configuration than the transient it removes; the rollout is documented instead.
- **On-behalf-of delegation.** Rejected for 1.0 because of the impersonation risk; a token acts as its principal only.
- **Re-hashing by an admin command.** Impossible: the plaintext of a credential is unknown once it was shown.
- **Verify-only retired keys without moving credentials.** Kept as the behaviour for credentials nobody uses, but not as
  the whole answer: it makes every retired key permanent as long as one credential names it.
- **A longer prefix instead of more groups.** Rejected: it stores and lists more of the credential in clear; the secret
  part has to grow.
