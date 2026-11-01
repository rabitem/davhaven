# ADR-0006: Store contract amendments

- Status: accepted
- Date: 2026-10-25
- Scope: PLAN 2.4, 2.7, 2.18, 4.4; R12

## Context

PLAN 4.4 says that once the contract crates (`domain`, `ports`, service traits, wire types, the root manifest and
`Cargo.lock`) are frozen they change additively, in a small pull request that merges first. The PostgreSQL storage
adapter met the contract while it implemented it and changed it, partly in ways that alter the meaning of existing items,
not only add to them. This ADR is the record that the code written against the contract in parallel (the application, the
DAV and API layers, the mail and webhook handlers, the server and the test harness) needs: every semantic delta in one
place, who it affects, and where the plan text differs from the code. As much as possible was made additive (new methods
with default bodies that answer `StoreError::Unsupported`).

## Decision

### Changes of meaning (not additive)

These are the meanings the code and the contract suite implement; the "before" column is the text of the original contract.

| Item | Before (original contract) | Now | Affects |
| --- | --- | --- | --- |
| `ObjectIndex::may_overlap`, `TimeRange::may_overlap`, the SQL of `ObjectRepo::query` | half-open range, `last_end > start` | **closed at both ends** (`first_start <= end`, `last_end >= start`), one definition `interval_may_overlap` (ADR-0003 item 4) | `davhaven-ical` (anchors of the index), DAV and application (exact filter) |
| `CalendarRepo::soft_delete` | marked the calendar deleted | also **deletes every binding** of the calendar (owner's and sharees') and logs a `delete` in each affected home; the application must not list or delete bindings afterwards (it would get `NotFound`) | DAV, application |
| `OutboxQueue::complete`, `fail` | no state guard | only an **in-flight** record can be settled; otherwise `StoreError::LeaseLost` (`NotFound` for a missing one). Fenced variants `complete_claimed` / `fail_claimed` also check the claim | mail and webhook handlers, workers |
| `IdempotencyRepo::claim` | an in-flight key answered "in progress" until it expired | an in-flight key is **taken over after its lease** (default ten minutes); `claim_with_lease` is now a required method, `claim` is provided; leased variants fence `complete` and `release` | HTTP edge |
| `InboxRepo::create`, `delete` | always logged | **quarantined** items never move the inbox's token and are not logged | scheduling inbox |
| `WebhookRepo::update` | unspecified | does not write `failure_count` (the dispatcher owns it: `record_success`, `record_failure`; re-enabling resets it); keeps event types this release does not know | webhook handler |
| `WebhookRepo::create_delivery` | unspecified for a repeated event | returns the **existing** record for a repeated `(subscription, event)` | webhook handler |
| `CalendarRepo::lock` | no read-only rule | refuses (`Internal`) in a read-only transaction (PostgreSQL refuses row locks there) | application |
| `RsvpRepo::record_use` | unspecified | stamps `last_used_at` and also bumps `version` and `updated_at` | RSVP page |
| `ChangeRepo::since` | `PreconditionFailed` for an unusable token | **`InvalidSyncToken`** (`PreconditionFailed` keeps its single meaning, a stale version) | DAV, application, HTTP edge |
| `ObjectRepo::delete` with `Expected::Etag` on a missing object | `NotFound` | **`PreconditionFailed`** (RFC 7232: `If-Match` is false when nothing exists); `Any` and `Absent` stay `NotFound` | DAV, application |
| `RetentionRepo::purge_audit` without the privilege | `Internal` error | removes nothing and returns `0`; `purge_audit_checked` answers `AuditPurge::NotPermitted`; readiness reports it | workers |
| `StoreError`, `TxMode` | exhaustive | `#[non_exhaustive]`; `StoreError` gained `InvalidSyncToken`, `LeaseLost`, `Unsupported`, `InvalidData`; `TxMode` gained `Snapshot`. A `match` outside `davhaven-ports` needs a catch-all arm | every matcher |
| Transactions | no rule | **one transaction per task**: never hold two at once (pool starvation); the in-memory adapter fails fast instead of hanging | everyone who opens transactions |
| Reading a collection with its sync token | unspecified | read `ChangeRepo::state` before listing members, or use `TxMode::Snapshot` (ADR-0003 item 10) | DAV, application, HTTP edge |

### Additive (new methods with default bodies, new types)

`ObjectRepo::list_index`, `query_index` (heads without the iCalendar text, `ObjectHead`), `uri_for_uid`,
`uri_for_scheduling_uid`; `OutboxQueue::complete_claimed`, `fail_claimed`, `release_claimed` (`OutboxClaim`,
`OutboxRecord::claim`); `IdempotencyRepo::claim_leased`, `complete_leased`, `release_leased` (`LeasedClaim`);
`RetentionRepo::purge_audit_checked` (`AuditPurge`), `purge_deliveries` (default `Unsupported`); `TxMode::Snapshot`;
`davhaven_ports::store::{micros, lease_end}`; `davhaven_domain::index::interval_may_overlap`; in `ports::testing`:
`FaultyDatabase` (fails commits and begins on demand, so the application's retry can be tested). The storage adapter
exports `migrate::purge_audit` (audit retention as the owner), which `davhaven admin purge-audit` of the server crate
calls. Also: `CredentialRepo::rehash` (`Rehash`; default `Unsupported`): the compare-and-set swap of the keyed hash of a
credential under another pepper key, which the authenticator makes when a credential that was hashed under a retired key
is used (`docs/operations/keys.md`). It runs in a tenant transaction: system scope may not overwrite a credential hash
(ADR-0005 item 3), so system tokens are not moved.

### Where the plan text differs from the code

* **2.4 Data model**: the audit log is INSERT/SELECT for the runtime role, and rows leave it through
  `davhaven_purge_audit`, which the runtime role may not call (ADR-0005 item 4); the
  system policies list (ADR-0005 item 3); `idempotency_keys.lease_until`, `calendar_objects.live`,
  `principal_addresses.is_primary`, `principals_sync` per-collection `min_seq` and `epoch`; the two deviations from the
  composite-key rule (`api_tokens` primary key, `feed_tokens.calendar_ids`).
* **2.7 Consistency contract**: the lock is `FOR NO KEY UPDATE` (ADR-0003 item 9); the query pre-filter is closed at both
  ends (item 4); the read order for a listing with its token and `TxMode::Snapshot` (item 10).
* **2.18 Lifecycle**: the audit retention of 365 days runs as the owner (`davhaven admin purge-audit`, scheduled), never
  from the server; the worker treats `AuditPurge::NotPermitted` as a skip, not as a failure.
* **The port definitions** (PLAN 4.1): the new `StoreError` variants and the additive methods above.

### What each user of the contract does

* **`davhaven-ical`**: index `DUE`-only and `COMPLETED`-only to-dos at that instant for both `first_start` and `last_end`, and a
  date-valued start without end with `last_end = DTSTART + P1D` (the `ObjectIndex` documentation says so).
* **DAV and the application**: map `InvalidSyncToken` to `DAV:valid-sync-token` (API 410), call `state` before listing for a full
  sync, use `list_index` for ETag-only listings, take `CalendarRepo::lock` before creating a binding, grant or property
  on a calendar that may be deleted, and name a `C:no-uid-conflict` or `C:unique-scheduling-object-resource` href with
  `uri_for_uid` / `uri_for_scheduling_uid` after locking.
* **The HTTP edge**: use `claim_leased` with the request timeout plus a margin, `complete_leased`, and `release_leased` on cancel.
* **Mail and webhook handlers, workers**: settle outbox records with the `*_claimed` methods; treat `LeaseLost` as "someone else decided".
* **The server**: `davhaven admin purge-audit` calls `migrate::purge_audit` and is scheduled in the production recipe; the
  retention worker calls `purge_audit_checked` and treats `NotPermitted` as a skip.

## Consequences

- The contract text and the code agree, and anyone who codes against the ports can find every semantic delta in one place.
- Changes that are not additive are documented as such; later changes to the ports go in a separate small pull request
  that merges first (PLAN 4.4), as planned.
- `#[non_exhaustive]` on `StoreError` and `TxMode` makes the next additions non-breaking.

## Alternatives considered

- **Reverting the semantic changes to the original text**: rejected; each one fixes a defect found while implementing the
  store (a lost update, a hang, a leak across a lease), and the original text would have to be wrong again.
