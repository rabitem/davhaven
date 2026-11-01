# ADR-0016: Calendar providers: the OAuth flow, mirror calendars and the pull sync engine

- Status: accepted
- Date: 2026-10-28
- Scope: PLAN 1.1 (providers), 2.4 (`external_accounts`, `oauth_states`), 2.10 (OAuth), 2.11 (`external_account.sync_failed`);
  R1, R2, R6, R8; crates `provider-google`, `provider-microsoft`, `provider-fake`, `app`
  (`oauth`, `sync_engine`, `maintenance::keys`), `server`, `testkit`

## Context

A person can connect an account at Google or Microsoft; Davhaven pulls its calendar into a read-only **mirror calendar**
of that person. 1.0 is pull only. The plan fixes the tables, the ports (`OAuthProvider`, `RemoteCalendarApi`), the routes and the
rule that all HTTP goes through the egress policy, and leaves open how the pieces fit: who finds the tenant of an OAuth
callback that carries no credential, what exactly is stored, how several instances share the pulling, what a failing
provider does to an account, and how the mirror is written when every principal surface treats it as read-only.

## Decision

**The flow.** `POST …/external-accounts` stores a single-use state (ten minutes) with the sealed PKCE verifier and answers the
consent URL; `GET /oauth/{provider}/callback` ends it. The state is `{tenant}.{secret}`: the tenant id (32 hex digits, not a
secret) and 256 random bits. The callback has no session, so the tenant must be readable from the state to open the right
transaction; the secret part is what makes it unguessable, and the store keeps only `HMAC(pepper, state)`. The state is
**consumed first, in a transaction of its own**, before the code is exchanged: nothing that fails afterwards can leave it
usable. Every refusal at the provider (a refused consent, a rejected code, an account without calendars, a verifier that
cannot be opened) ends on the `oauth_result` page with `success: false` and says nothing about why; an unknown, expired or used
state, or the state of another provider, answers 404 and reveals nothing. The redirect URI is always
`{server.public_base_url}/oauth/{name}/callback`; `davhaven config check` compares it with `providers.<name>.redirect_uri` of
a provider that is on.

**The tokens** are one JSON document sealed with `SealAad::external_account_tokens(tenant, account)`
(`external_accounts.sealed_tokens`), the verifier with `SealAad::oauth_verifier(tenant, state row)`. Key rotation reseals the
tokens (`maintenance::keys::ExternalAccountTokens`); the verifier lives ten minutes and is listed as short lived. Views never
carry tokens, and neither do logs, events or metrics.

**The mirror** is a calendar of kind `mirror` owned by the principal, with the owner's binding, created in the same transaction as
the account. The engine writes it through the batch use case of the object service on the internal channel, which `decide`
allows everything: so the mirror gets the same write path as every calendar (the change log, the sync token, one
`calendar.objects_changed` event per batch, no-op writes by content hash) without a second write path, and stays
read-only for DAV, the API and MCP. An event's external key is `r:` and 128 bits of the SHA-256 of the provider's id (provider ids are
long and have characters external keys do not allow); everything of a mirror has the prefix, which is the scope of a snapshot.
A pull that is a **snapshot** (the adapters of 1.0 list the calendar again every time) deletes what the mirror holds and the
list does not name; a **delta** applies the changes and the deletions. Large pulls are stored in chunks of at most
`limits.api.max_batch_items` entries and 8 MiB; an entry that cannot be stored is left out (counted and logged) and does not
fail the pull.

**Several instances.** The sync worker lists the accounts of the providers that are on and claims one with an **optimistic update
of its `sync_state`** that writes a lease (`timeout` plus a minute): a second worker loses the race or finds the lease unexpired.
No transaction is held across a call to the provider. The cursor moves only after the changes were applied, a provider that
rotates refresh tokens has its new token stored before anything else, and a pull that dies is simply due again when its lease ends.

**Failures** are classified into six reasons (`auth_revoked`, `provider_rejected`, `provider_unavailable`, `too_large`,
`mirror_missing`, `internal`). Only a refresh token that the provider calls invalid (`auth_revoked`: RFC 6749 `invalid_grant`) switches
an account off (`disabled`: nothing is pulled until the person connects the account again, which keeps the account and replaces its
tokens); the others set `error`, and the account is tried again after a wait that starts at a third of the interval and doubles up to
`backoff_max`. A provider that refuses the **client** of the deployment (`invalid_client`, `unauthorized_client`, `invalid_request`,
`invalid_scope`: an expired, rotated or wrong client secret) is a fault of the deployment and of no account, so it is `internal` and
switches nothing off: the adapters map only `invalid_grant` to `Rejected`, every other refusal of the token endpoint to `Invalid`.
`external_account.sync_failed` is emitted once when an account that worked fails, and once more when it is switched off;
`last_error` is a sentence of this catalogue, never the text of the provider's answer. A principal who was deleted ends its accounts
with a seventh text, `principal_deleted`, which is no failure of a pull and emits no `sync_failed` (the deletion is audited). The
lease is the **fencing token** of a pull: what a pull renewed or found is stored only while the account still holds the lease the pull
wrote, so a reconnection (which clears it) is never undone by the pull of the grant it replaced.

**Deployment.** Both provider adapters are default features of the server, so a deployment enables one by configuration
(`[providers.<name>] enabled = true` and its client credentials) without a build of its own; both are off by default, a provider that is
off answers 409 `feature-not-enabled`, and the sync worker is built only when a provider is on. The management API lists the providers of
the project whether or not the build has them. `[providers.sync]` holds the settings every provider shares.

## Consequences

- A callback costs one transaction for the state, two HTTP calls to the provider and one transaction for the account; nothing waits
  on the provider with a transaction open.
- The tenant id is visible in the consent URL. It is an identifier the person's own administrator knows. The URL as a whole is,
  however, a short-lived **bearer capability**: it lives for ten minutes and works once, and whoever opens it first and consents
  attaches the provider account they consent with to the named principal's mirror, because the callback has no session to bind it
  to. The API answers it with `Cache-Control: no-store`; the administrator hands it to that person only, and it is never logged or
  forwarded (`docs/operations/runbook.md`).
- A rotation of the pepper key while a person is at the consent screen makes that state unfindable: the person starts again
  (`docs/operations/keys.md`).
- The mirror is written by the same code that API writes use. A change to the batch semantics is a change to the sync engine too, which the
  `providers` suite of `davhaven-it` runs on the memory store and on PostgreSQL.
- The snapshot mode is O(events) per pull. It is bounded by the window of the import (`history_days`, `future_days`) and by the
  response size cap of the egress policy.

## Rejected alternatives

- **A table or lookup that finds a state by its hash across tenants.** It needs a system-scope repository method and a second index
  on a table that is otherwise tenant-bound; the tenant in the state needs neither.
- **Writing the mirror directly through the store.** It would duplicate the validation, the change log and the events of the batch path.
- **One long transaction for a pull.** It would hold a connection and the calendar lock across the provider's latency.
- **A lease in a separate table.** The account row is the one thing the claim is about, and its version is the compare-and-swap.
- **Switching an account off on the first rejected call.** A `403` or `404` of one calendar is often temporary or the account's
  doing; only a refused refresh token is proof that the access is gone.
