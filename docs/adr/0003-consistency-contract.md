# ADR-0003: Consistency contract

- Status: accepted
- Date: 2026-10-24
- Scope: PLAN 2.7

## Context

CalDAV clients cache aggressively and synchronise with ETags, CTags and sync tokens. The same calendar objects
are written through DAV, the management API, MCP, the scheduling engine and the provider sync engine. Unless all
writers follow one contract, clients miss changes, see phantom updates or loop on conflicts. The contract must
hold on both store adapters (PostgreSQL and memory).

## Decision

1. **ETag.** Strong: `"` + base64url(SHA-256(stored bytes))[0..22] + `"`, identical in GET, PROPFIND, REPORT and
   the API. The store keeps client bytes verbatim; the server re-serializes only objects it changes. A PUT
   returns `ETag` only when the stored bytes equal the request body (RFC 4791 §5.3.4).

2. **Write invariant, enforced by the store.** `ObjectRepo::put/delete/move` run in the caller's transaction:
   `UPDATE calendars SET sync_seq = sync_seq + 1 ... RETURNING sync_seq` (serialising writers per calendar), write
   the change row at that sequence number and return the sequence number and ETag. `CalendarRepo::touch` does the
   same for collection property, sharing and binding changes. Home, inbox and notification collections use the
   same mechanism.

3. **Sync token and CTag.** `urn:davhaven:sync:{collection_id}:{epoch}:{seq}`; `getctag` is the same string.
   Foreign, garbled, wrong-epoch, future or pruned (`seq < sync_min_seq`) tokens answer 403
   `DAV:valid-sync-token` (API: 410 `sync-token-expired`). Sync level 1 only; truncation answers 507 for the
   request URI plus a usable token; deletions are reported as 404 responses. `admin bump-sync-epoch` runs after
   a restore.

4. **Query semantics.** `ObjectRepo::query` returns a superset of matches from the index (UTC `first_start`,
   `last_end` or infinity, floating times padded by ±14 h); `app` filters exactly with `ical`. The pre-filter is
   **closed at both ends**: `first_start <= range end AND last_end >= range start`, where an absent bound is open and a
   component without a start is undated (`first_start` and `last_end` are `None`) and matches every range. RFC 4791
   §9.9 ranges are half-open, but rows of its table match when the range *end* touches the anchor of the component:
   a `VTODO` with only `DUE` matches `start < DUE AND end >= DUE`, one with only `COMPLETED` matches
   `start <= COMPLETED AND end >= COMPLETED`, and zero-length components (`DURATION:PT0S`, `DTEND == DTSTART`) and
   components without `DTEND` match `start <= DTSTART < end`. A candidate the pre-filter drops never reaches the exact
   filter and is lost for good, so the pre-filter keeps both touching ends and the exact filter removes the extras.
   There is one definition, `davhaven_domain::index::interval_may_overlap`: `ObjectIndex::may_overlap` and
   `TimeRange::may_overlap` delegate to it, the in-memory store evaluates it, the SQL of the PostgreSQL store mirrors
   it, and the contract suite compares both stores with it and with a model of every table row. The indexer
   (`davhaven-ical`) anchors each component accordingly: `DUE`-only and `COMPLETED`-only to-dos at that instant, a
   date-valued start without end at `DTSTART + P1D`, an instant at `DTSTART`.

5. **No-op writes.** API and sync-engine upserts whose content hash (ignoring DTSTAMP, LAST-MODIFIED, SEQUENCE,
   PRODID) equals the stored one change nothing: no new ETag, no sequence bump.

6. **Conditional precedence** on PUT and DELETE: `If-Schedule-Tag-Match`, then `If-Match`, then
   `If-None-Match: *`.

7. **Schedule-Tag** changes on organizer-initiated changes and on attendee changes to their own copy, and stays
   unchanged on server merges (REPLY PARTSTAT, SCHEDULE-STATUS). On a schedule-tag match the attendee's change is
   merged instead of answering 412.

8. **UIDs** are unique per calendar (`C:no-uid-conflict` with href); scheduling objects are unique per owner
   (`C:unique-scheduling-object-resource` with href). MOVE within one owner is a relocation: no iTIP, schedule
   tag kept, changes logged in both calendars.

9. **Isolation.** READ COMMITTED with an explicit `FOR NO KEY UPDATE` row lock on calendar rows in ascending id
   order, and a bounded application retry (3 attempts) on `StoreError::SerializationFailure`. (PLAN 2.7 says
   `FOR UPDATE`; the lock mode is the one deliberate deviation, see
   [ADR-0006](0006-store-contract-amendments.md).) The lock is `NO KEY UPDATE` rather than `UPDATE`: the foreign key
   check of an insert that references the calendar (a sharee's binding, a grant, a property) takes only `KEY SHARE`,
   which does not conflict, so such inserts do not queue behind a busy writer, while the writers themselves still
   serialise (their `UPDATE calendars SET sync_seq` takes the same lock). The flip side is documented on the ports: a
   write that must not outlive a concurrent `soft_delete` of the calendar takes `CalendarRepo::lock` first. A lock wait
   that expires (`lock_timeout`) is a `StoreError::Timeout`, which `is_retryable()` and which the application may retry
   like a serialization failure before it answers 503 with `Retry-After`. Transactions are never nested within a task
   (one transaction per task), on any adapter.

10. **Reading a collection together with its sync token.** Because every statement of a READ COMMITTED transaction sees
    a fresh snapshot, a listing and a token read in one transaction are not one snapshot. A full or initial sync (and
    any answer that reports members with a token) reads `ChangeRepo::state` **first** and lists the members
    afterwards: a write that commits in between is then in the listing and after the token, and the client sees it
    again on its next sync (a harmless repeat); the other order loses it. A caller that wants the whole read to be one
    snapshot opens the transaction with `TxMode::Snapshot` (`REPEATABLE READ`, read-only). The incremental path
    (`ChangeRepo::since`) bounds its rows by the position it returns and is safe either way. A sync token the store
    cannot resume (another epoch, below the minimum sequence, from the future) is `StoreError::InvalidSyncToken`, never
    the `PreconditionFailed` of a stale `If-Match`.

## Consequences

- Every surface produces the same ETags and change log entries because they share one app use case.
- The store contract suite (`davhaven-port-tests`) tests the invariant on both adapters: exactly one sequence bump per mutation,
  linearizable visibility, rollback including the outbox.
- Clients never see a changed ETag for a semantically unchanged managed object, which keeps polling clients
  quiet.
- The per-calendar row lock serialises writers to one calendar; writes to different calendars stay parallel.

## Alternatives considered

- **Weak ETags or ETags from `version`**: rejected; RFC 4791 clients compare bytes, and `version` changes on
  metadata-only updates.
- **Change log derived from timestamps**: rejected; clock skew and same-millisecond writes lose changes.
- **SERIALIZABLE isolation everywhere**: rejected; higher abort rates under scheduling fan-out for no gain over
  explicit, ordered row locks.
