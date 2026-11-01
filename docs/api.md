# Management API

The management API is how a deployment provisions tenants, principals and memberships, mints credentials, manages
calendars, grants and managed events, subscribes to webhooks and looks at the outbox and the audit log. It is served
on the `internal` listener under `/api/v1` and described by [`openapi.json`](openapi.json), an OpenAPI 3.1 document
that is generated from the code (`cargo xtask contracts`) and checked in CI, so it cannot drift from what the server
does. This page describes the conventions the document cannot express in one place. Where this page and the
document differ, the document is right: please report the difference.

| Need | Where |
| --- | --- |
| Every operation, its parameters, bodies and responses | [`openapi.json`](openapi.json) |
| The scopes of an operation | the `x-required-scope` extension of the operation (any one of the scopes suffices) |
| The domain operations behind a route | the `x-davhaven-operation` extension |
| The problem codes | the `code` of a problem document; the `ProblemCode` enumeration in [`openapi.json`](openapi.json) lists them |
| Webhook payloads and signing | [`webhooks.md`](webhooks.md) and [`contracts/events.schema.json`](contracts/events.schema.json) |

## Authentication and scopes

Every request carries an API token in `Authorization: Bearer dvh_pat_{prefix}_{secret}`. Tokens are never accepted in
a URL or a cookie, and the API never reads cookies at all, so a browser cannot be made to act with ambient
credentials. Tokens are minted by the API (`POST /tenants/{tenant}/api-tokens`), shown exactly once, and stored only
as a keyed hash.

| Kind | May | Notes |
| --- | --- | --- |
| `system` | `system:tenants` only; never reads calendar data | belongs to no tenant |
| `tenant` | acts as the administrator of its tenant within its scopes | `events:*` reaches managed and group calendars, never personal or user calendars |
| `principal` | acts as its principal through the same decision function as DAV | `mcp:*` scopes need a principal token with an expiry (at most 90 days by default) |

A token can only mint tokens with a subset of its own scopes, with one exception for service principals (next section). The scopes are `system:tenants`, `principals:read`,
`principals:write`, `credentials:write`, `calendars:read`, `calendars:write`, `events:read`, `events:write`,
`webhooks:manage`, `providers:manage`, `outbox:manage`, `audit:read`, `itip:inbound`, `mcp:read`, `mcp:write` and
`mcp:schedule_external`. The tenant in the path must be the tenant of the token (system tokens name any tenant). A
valid token of one tenant that names another tenant in the path is not refused as a credential: the other tenant is a
resource it cannot see, so the answer is 404 `not-found` like for every resource of another tenant (a client cannot
tell a tenant that does not exist from one it may not see), and the request does not count as a failed
authentication.

What a refusal looks like is deliberately uniform:

| Situation | Answer |
| --- | --- |
| No credential, an unknown, revoked or expired token, a suspended or deleted tenant or principal, a malformed token | 401 with `WWW-Authenticate: Bearer realm="davhaven"`; the body never says which |
| The token is valid but lacks the scope, or the principal may not do this | 403 `forbidden` |
| The resource does not exist or is invisible to the caller, including other tenants' resources | 404 `not-found` |
| Too many failed attempts from one login and address, or one address | 429 with `Retry-After` |

There is no hard lockout. Failed authentications back off exponentially per login and client address and per client
address, so guessing becomes impractical while a legitimate client is never locked out of its own account: after a
few failures a block begins, every failure after the block ended lengthens the next one (up to
`security.auth.backoff_max`), failures of a blocked key do not extend its block, and a long quiet time forgets
them. The rate limiter owns this (the `auth_failure_login` and `auth_failure_ip` failure buckets of the `RateLimiter` port,
ADR-0012); an IPv6 client is counted by its /64 prefix, because one host controls a whole /64. A credential that is
valid but may not be used for the request (another tenant's, a surface it does not belong to) is not a failed
attempt.

## Calendars that everybody must have: required grants and the bindings of a home

A person who deletes a shared calendar in a calendar app (a group calendar, a managed catalogue, a calendar somebody shared)
only hides it in their own home. The calendar and the grant stay, and nothing in a calendar app brings it back. Two things
keep that from becoming a support case:

* **`required` on a grant.** `PUT …/calendars/{calendar}/grants/{grantee}` takes `{"access": "read", "required": true}`. A
  calendar that an accepted grant marks required cannot be deleted by the people the grant reaches (the grantee, or the members
  of a grantee group): the calendar app's `DELETE` is answered `403` with `DAV:need-privileges` naming `DAV:unbind` (on the home,
  the parent of the collection, as RFC 4918 has it), and the calendar stays. Bindings that were hidden before the flag come
  back with it, and so do those of people who join the group later. A grant without the flag is optional (the default).
  **`PUT` replaces the grant, so a body without `required` makes it optional again: a client that reconciles grants (the
  provisioning code of a deployment) must send `required` on every `PUT`, or it switches the flag off at its next run.** Only a
  tenant token sets or clears the flag, and only a tenant token removes a grant that has it: a principal's token that asks for
  `"required": true` is refused with `403` (`/required`), and a grant it puts keeps the flag it has. A calendar app cannot
  change or remove a grant that has it either. A group that owns its calendar may be granted that calendar, which is how the
  calendar is made required for its members: the grant carries no access of its own (the members have the group's default
  access already), so its access is `read` (`422` for another level), and only a tenant token puts it. Taking the grant away
  makes the calendar optional again and leaves the group's own binding alone.
* **The bindings of a home.** `GET /tenants/{tenant}/principals/{principal}/bindings` (`calendars:read`) lists what the
  principal's calendar apps can list, hidden ones included (`?hidden=true` lists only those), with `required` for each. A
  calendar a principal can no longer reach (a removed group member, a revoked grant) is not in the home and not listed. A
  binding exists from the principal's first listing of the home on, so the list holds the bindings created so far: a member who
  has not synced since they joined a group has none yet. `POST …/bindings/{binding}/restore` (`calendars:write`, `{binding}` is
  the `slug` of the listing) shows a hidden binding again, answers `200` for one that is visible already and `404` for one
  whose calendar the principal can no longer reach. A binding is no resource of its own: there is no `GET` of one and no
  `ETag`. Every restoration is in the audit log (`binding.restored`).

```sh
curl -X PUT $API/tenants/acme/principals/team/calendars/team/grants/team -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" -d '{"access": "read", "required": true}'
curl "$API/tenants/acme/principals/mia/bindings?hidden=true" -H "Authorization: Bearer $ADMIN"
curl -X POST $API/tenants/acme/principals/mia/bindings/team-calendar/restore -H "Authorization: Bearer $ADMIN"
```

## Tokens for service principals (assistants and integrations)

An assistant or an integration acts as a **service principal** (`kind: "service"`): a machine identity without a password and
without a personal calendar, that principal search does not find. Give it the calendars it may use with grants (service
principals are grantees like users and groups, on calendars of every kind) and a principal token:

```sh
curl -X PUT  $API/tenants/acme/principals/assistant -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
     -d '{"kind": "service", "display_name": "Assistant"}'
curl -X PUT  $API/tenants/acme/principals/anna/calendars/team/grants/assistant -H "Authorization: Bearer $ADMIN" \
     -H "Content-Type: application/json" -d '{"access": "read_write"}'
curl -X POST $API/tenants/acme/api-tokens -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
     -d '{"kind": "principal", "principal": "assistant", "label": "assistant-mcp", "scopes": ["mcp:read", "mcp:write"],
          "expires_at": "2027-01-31T00:00:00Z"}'
```

The answer carries the token once (`secret`, `Cache-Control: no-store`). What this means:

* **Who may mint it.** A tenant token with `credentials:write`. A token mints only scopes it holds, with one exception:
  the `mcp:*` scopes, which a tenant token cannot hold, may be put on the token of a **service principal**, provided the
  minting token holds the API scope that reaches the same data: `events:read` for `mcp:read`, `events:write` for
  `mcp:write` and `mcp:schedule_external`. (MCP does not cap managed calendars at read as DAV does, and
  `mcp:schedule_external` sends invitations by mail, so a token that cannot write events itself cannot hand out the
  power to.) The administration token of `admin bootstrap` (every scope a tenant token may hold, `credentials:write` and
  the `events:*` scopes among them) mints the MCP token of an assistant; a token that holds `credentials:write` and
  `events:read` mints `mcp:read` only. For a user or a resource the rule stays that a token mints only scopes it holds, so
  MCP scopes for a user come from the operator (`davhaven admin principal-token`). A token never acts for a group.
* **Impersonation.** `credentials:write` is the power to act as any principal of the tenant that can act: it mints app
  passwords (DAV) and principal tokens (API, MCP) for them. A principal token acts **as** its principal, through the same
  decisions as DAV: the calendars the principal owns or is granted, nothing else. There is no on-behalf-of and no
  per-request choice of the principal. Give `credentials:write` to provisioning, not to an integration that only needs
  calendars; every minting is audited (`token.created`, with the token that minted it).
* **Rules of MCP tokens.** The tenant must have switched MCP on (`settings.mcp_enabled`; `409 feature-not-enabled`
  otherwise), the token needs an expiry within `security.max_mcp_token_days` (90), and it never outlives the token that
  minted it. Revoking it (`DELETE …/api-tokens/{id}`) ends it at once.

## Requests and responses

* Paths use the immutable natural keys: the tenant slug, the principal name, the calendar slug, the external key
  (`[A-Za-z0-9._:~-]{1,200}`). Every body and view also carries the `id`, and `dav_url` where there is a DAV
  resource. A path segment that cannot be a key (an upper-case slug, a malformed UUID) is a 404.
* JSON is snake_case. Timestamps are RFC 3339 in UTC. Request bodies must be sent as `application/json` (`PATCH`:
  `application/merge-patch+json`), otherwise 415. A body that is not JSON is 400, a body that is JSON but does not
  fit is 422 with `errors`. Bodies are limited to 1 MiB, batch upserts to 10 MiB (413).
* `X-Request-Id` is accepted when it is a UUID and generated otherwise; it is echoed on every response and appears
  in every problem document and log line.
* `Cache-Control: no-store` is set on every response that carries a secret (app passwords, API tokens, feed tokens
  and URLs, webhook secrets, authorization URLs) or a client profile.
* Unknown query parameters are ignored. Request bodies of writes refuse members they do not know (422), so a typo
  is not silently dropped; events are the exception, because their members are flattened from the event model, so an
  event ignores a member it does not know.

### Concurrency: `ETag`, `If-Match`, `If-None-Match`

Mutable resources (tenants, principals, calendars, grants, webhooks) return an `ETag` derived from their `version`
(`"v7"`). `PUT` creates or replaces (201 with `Location`, or 200); `If-None-Match: *` makes it create-only and an
`If-Match` makes it replace-only that version. `PATCH` takes a JSON Merge Patch (RFC 7396). A stale `If-Match` is 412.
Deleting tenants, principals and calendars requires `If-Match` and answers 428 without it, so a client deletes the
version it has seen. Events are the exception: their `ETag` is the content tag that DAV serves (`getetag`), and
`If-Match` on an event takes that tag.

### Deleted principals keep their values reserved

A principal that was deleted without `purge=true` is hidden (it is not listed and not found by `external_ref`) but keeps its
name, its `external_ref` and its addresses until it is purged (`retention.principal_purge_days`, or `DELETE …?purge=true`).
A client that provisions principals can tell this from a conflict with a live principal:

| Request | Answer |
| --- | --- |
| `PUT …/principals/{name}` with `If-None-Match: *`, the name belongs to a deleted principal | `412 precondition-failed`, as for every name that exists, with no hint about the hidden principal |
| `PUT …/principals/{name}` **without** `If-None-Match: *`, the name belongs to a deleted principal | `409 name-reserved` |
| a `PUT` whose `external_ref` belongs to a deleted principal | `409 external-ref-reserved` |
| a `PUT` with an address (`email` or `addresses`) of a deleted principal | `409 address-reserved` |
| the same collisions with a **live** principal | `409 conflict` |

Purge the hidden principal (`DELETE` with `purge=true`) or wait, then repeat the request.

### Writing events: value, absent, `null`

An event is written as JSON (`PUT …/objects/by-key/{key}`, the `event` of a batch item) and merged into the stored
event like a JSON Merge Patch (RFC 7396), for the members of the event:

| In the body | What happens to the stored event |
| --- | --- |
| a field with a value | it replaces the stored value |
| a field that is absent | it keeps its stored value |
| a field that is `null` | it is removed (`"location": null` clears the location) |

`null` removes `summary`, `description`, `location`, `end`, `duration`, `status`, `transparency`, `class`,
`recurrence`, `organizer`, `attendees`, `categories`, `url` and `alarms`; an empty text or list removes them too.
`uid` and `start` cannot be removed: `null` for one of them is 422, and the problem names the member by its pointer
(`/start`, and `/items/3/event/start` in a batch, so a client sees which item it is about) with the code
`not-nullable`. `recurrence_id` (which instance a write is about) and `sequence` (which the server manages) are no
fields that a write could remove: for them `null` is the same as leaving them out. Unknown properties, alarms and
`X-` properties of the stored event survive a write that does not mention them. A write that leaves the content of the
event unchanged changes nothing (no new `ETag`, no event), so an integration may send every member of every event on
every run, with `null` for the empty ones, to repair what drifted; it leaves `uid` and `start` out or gives them a
value. The MCP tools `create_event` and `update_event` follow the same rules.

RFC 7396 holds for the members of the event, and no deeper:

* A member whose value is an object or a list **replaces** the stored one as a whole: `recurrence` (the rule and the
  extra dates and the exclusions together), `organizer` (with its name and `SENT-BY`), `start`, `end`, `alarms`,
  `categories`. A client that adds an exclusion with `{"recurrence": {"exdates": […]}}` loses the rule: it sends the
  whole recurrence.
* Attendees are matched by address. An attendee that the write lists keeps the parameters it does not state (an absent
  parameter, and a `null` one, keep the stored value); one that is not listed is removed; `null` or `[]` removes all.
  The answers (`partstat`) of the attendees are theirs and stay as stored.
* An event that has attendees names its organizer: `"organizer": null` is 422 while attendees remain (send
  `"attendees": null` in the same write). In a series with overrides every component names the same organizer, so the
  organizer of the master cannot be removed alone either (`same-organizer-in-all-components`).

### The busy text of a tenant, per language

The summary of the busy blocks of the busy-mode feeds of a tenant is set in the tenant settings, in two members that
are both optional and both leave the `feed_busy` template of the theme in charge where they name nothing:

* `settings.busy_text` is one text for every language (one to 100 characters, surrounding white space removed; control characters,
  line and paragraph separators and invisible or bidirectional formatting characters are refused: 422 at `/settings/busy_text`).
* `settings.busy_text_by_locale` is a map from a language tag (`de`, `en-GB`, written in any spelling of the tag and stored in its
  canonical case) to a text under the same rules, at most 20 languages (422 at `/settings/busy_text_by_locale`; the message names the
  language of the text that was refused). It wins where it has the language of the feed's owner (the principal's locale, else the
  tenant's): the tag is looked up as it is and then without its last subtag, so `de-AT` finds `de` and `zh-Hant-TW` tries `zh-Hant`,
  then `zh`; where the map has none, `busy_text` answers.

A merge patch changes one language and keeps the others, and `null` removes it, like any member of the settings:

```json
{"settings": {"busy_text_by_locale": {"de": "Nicht verfügbar", "en": null}}}
```

The tag of a patch is read like the tag of a body, so any spelling of a stored tag names it: with `de-DE` stored, `{"de_DE": null}`
removes it and `{"DE-de": "Neu"}` changes it. One tag written twice in different spellings in one body or one patch (`de-DE` and
`de_de`) is refused with 422 at `/settings/busy_text_by_locale` and the code `duplicate-tag`, and nothing changes; so is a tag
that is none, which a patch names at the same member whatever its value is (`null` included) and a body answers as a body that
does not fit the shape. `"busy_text_by_locale": null` removes every language.

### Pagination

Listings are cursor pages: `?limit` (1 to 200, default 50; `0` is a 400, a limit above what the deployment allows
is lowered to that maximum, `limits.api.max_page_size`) and `?cursor`, answered as `{items, next_cursor}` with
`Link: <…>; rel="next"` while more pages follow, ordered by id. The reference of `Link` is relative to the URL the
client called (the API is served on the `internal` listener, whose public name the server does not know), so it
resolves correctly behind any proxy; the other query parameters of the request are carried over. A cursor is opaque
and signed by the server: text that cannot be a cursor is 400, a cursor that was not issued for this listing is 422.

## Idempotency

A client that does not know whether a `POST` arrived repeats it with the same `Idempotency-Key` (1 to 255 visible
ASCII characters). The key is scoped to the tenant, the token and the key itself and lasts 24 hours. The header is
optional on every `POST` (required on the batch upsert, where it is the only protection against writing a batch twice)
and ignored on `PUT`, `PATCH` and `DELETE`, which are idempotent by definition. The document declares it on every
`POST`, in the form that is true for the operation:

* **Replayed** (`IdempotencyKeyHeader`): the operations whose answer holds no secret (the batch upsert is required,
  `IdempotencyKeyRequiredHeader`; redelivering a webhook delivery, retrying an outbox item, the inbound iTIP
  endpoint). A repeat is answered with the first response again.
* **Never replayed** (`IdempotencyKeySecretHeader`): the nine operations whose answer carries a secret, a feed URL
  or a client profile (app passwords, API tokens, feed tokens, webhook secrets, external accounts, the DAVx5 and
  Apple profiles). A repeat is 409 `secret-not-replayable`.

Only a response that its handler has marked replayable is stored. The default is that nothing is, so a response that
carries a secret can never end up in the idempotency table by omission.

| What the server finds | Answer |
| --- | --- |
| A new key | the request runs; the outcome is recorded |
| The same request completed | the first response again (same status, `ETag`, `Location` and document) with `Idempotent-Replayed: true` |
| The same request is still running | 409 `idempotency-in-progress`; retry shortly |
| Another request (method, path, query, content type or body differ) | 422 `idempotency-key-reuse` |
| The first response was not kept: it carried a secret, or it could not be stored (too large, not JSON) | 409 `secret-not-replayable` with the `status` and the `location` of the first answer in the problem, so a client whose first attempt was lost can find what it created (a token or a webhook) and read or revoke it; a secret is shown once and never stored |
| The first attempt failed (an error status, a timeout, a crash) | the key is free again and the request runs afresh |

A request that is too large for its route (1 MiB, 10 MiB for the batch upsert) is 413 before a key is reserved. The
request runs to completion even if the client disconnects, so a retry after a dropped connection finds the recorded
result, but never longer than the request timeout (`server.http.request_timeout`): a key is claimed for that time plus
a margin, and the work stops when it is up, so a retry that takes the key over after the lease cannot run the request
a second time while the first one still works. A late outcome of an attempt that lost its claim is ignored by the
store (ADR-0006, ADR-0012). If the idempotency bookkeeping itself is unavailable the request is refused with 503
(`unavailable`, with `Retry-After`) instead of running unprotected.

## Batch upsert

`POST …/calendars/{calendar}/objects/batch` writes up to 1000 entries (items and deletes together) in one
transaction, all or nothing, and requires an `Idempotency-Key`:

```json
{"mode": "merge", "items": [{"external_key": "shift-42", "event": {"summary": "Early shift", "start": {…}}}],
 "deletes": ["shift-17"]}
```

`mode` is `merge` (the default: only the listed items and `deletes` are touched) or `replace`: objects whose
external key starts with `replace_scope_prefix` (required with `replace`, so one integration cannot wipe the
objects of another) and that are not listed are deleted. `allow_empty` permits a replace without items, which would
delete the whole scope, and `max_deletes` fails a batch that would delete more. Each item has exactly one of
`event` (JSON, merged into the stored component as described under "Writing events") or `ical` (text). The UID is the UUIDv5 of the calendar and the
external key unless the event brings one, so the same batch twice changes nothing. A failing entry rejects the whole
batch with 422 and one `errors` entry per failed item (`/items/3`). The batch emits one `calendar.objects_changed`
event and never sends scheduling messages.

## Providers and external accounts

`GET …/providers` lists the calendar providers (`{name, enabled}`; Google and Microsoft are listed whether or not the build or the
configuration has them). `POST …/external-accounts` with `{provider, principal}` starts connecting an account for a user and answers
`{authorization_url}` (`Cache-Control: no-store`): the person opens it, consents at the provider and lands on the callback of this
server, after which the account is in `GET …/external-accounts` with its `status` (`active`, `error`, `disabled`), a `last_error` that
names the reason and its `mirror_calendar_id`. The mirror is a calendar of kind `mirror` of that user: it is read-only on every
surface. `DELETE …/external-accounts/{id}` disconnects (the mirror calendar is deleted, the provider is asked to revoke the tokens). All
four need the scope `providers:manage`; a provider that is off answers 409 `feature-not-enabled`, an unknown provider or principal 404,
a principal that is not a user 422 (`/principal`). Views never carry tokens. The flow, the failures and the operations are in
[`interop.md`](interop.md) and [`operations/runbook.md`](operations/runbook.md#calendar-providers).

## Errors

Failures are RFC 9457 documents (`application/problem+json`):

```json
{"type": "urn:davhaven:problem:validation-failed", "title": "Validation failed", "status": 422,
 "code": "validation-failed", "detail": "The request body does not match the expected shape.",
 "request_id": "018f3c1e-7b2a-7c3d-9e4f-0123456789ab",
 "errors": [{"pointer": "/display_name", "code": "required", "message": "must not be empty"}]}
```

`code` is stable and the thing to branch on, and its value is the kebab-case catalog code (`validation-failed`),
which is what the `ProblemCode` enumeration of the document lists; `detail` and `errors[].message` are for people and
may change. Internal error text never reaches a client. A disabled feature (a provider that is switched off, feeds a
tenant disabled) answers 409 `feature-not-enabled`; the routes always exist so that the document does not depend on
the build. 429 and 503 carry `Retry-After`.

The document lists the problems an operation can answer, not the problems any operation might: 413, 415 and 422 only
where there is a body (422 also on a `POST`, for the `Idempotency-Key` that was used for another request), 412 only
where `If-Match` or `If-None-Match` is declared, 409 on the writes.

## Browsers

The API is meant for servers. A browser application is allowed only from the origins in
`security.cors.allowed_origins` (empty by default): preflights are answered for those, credentials are never
allowed, and an unsafe request with another `Origin` is 403.

## Compatibility and clients

`v1` only grows: new operations, new optional request members, new members of responses and new values of
enumerations (a new row of the problem catalog among them: `ProblemCode` says so itself). Clients must ignore
response members they do not know and must tolerate enumeration values they do not know. The enumerations of the
document are closed lists of what this version sends, so a generator has to be told to read the others instead of
failing: see the generator settings below. A breaking change needs a new API version. Deprecations are announced with
the `Deprecation` and `Sunset` headers and in the document.

The document is written for generators. Problems, parameters and the shared objects (enumerations such as
`CalendarKind` and `PartStat`, `TenantSettings`, `EventTime`, `Recurrence`) are components, operations carry stable
`operationId`s (`verbNoun`), files are `type: string, format: binary`, optional parameters are plain types, and the one
union, the trigger of an alarm, names its tag (`type`) as the discriminator. `crates/api/clients/smoke.sh` generates a
Java client (OpenAPI Generator) and two TypeScript clients (OpenAPI Generator `typescript-fetch` and Orval) from the
committed document, compiles the Java one, type-checks the TypeScript ones and has the generated Java model read and
write an event and a problem document (`crates/api/clients/fixtures`: exactly what the server sends, checked by Rust
tests), and read both with an enumeration value that this version does not know; CI runs it whenever the document or
the project changes, with the tools pinned by `package-lock.json` and `pom.xml`.

**Generator settings a Java client needs.** Set `enumUnknownDefaultCase=true` together with
`useOneOfDiscriminatorLookup=true` (the smoke's `pom.xml` is the reference). The first makes a value the client does
not know read as `UNKNOWN_DEFAULT_OPEN_API` instead of throwing from `fromValue`, so a new `CalendarKind`,
`PartStat` or problem code does not break a deployed client. The second is what makes the first usable: the
`native` client tells the alternatives of a union (the trigger of an alarm) apart by trying each of them, and with the
fallback on, every alternative accepts every tag, so reading any alarm fails with "2 classes match" unless the union is
resolved by its discriminator. The TypeScript generators type enumerations as unions of literals and do not check them
when reading, so an unknown value arrives as it was sent. One more thing the smoke taught: the generated model writes
the `rdates` and `exdates` of a recurrence as empty lists where the server omits them, which means the same.

**Keep `openApiNullable` on** (it is the generator's default, and the smoke's `pom.xml` sets it): a nullable member is
then a `JsonNullable`, which tells an explicit `null` (remove the field) from an absent member (keep it). Without it a
Java client cannot send the `null` that removes a field. `crates/api/clients/fixtures/event-write.json` is the proof:
the generated model keeps its `location: null` and leaves `description` out. The TypeScript models type a nullable
member as `T | null` and every member as optional, so `null` removes and `undefined` leaves the field alone
(`crates/api/clients/src/smoke/nullable.ts`).
