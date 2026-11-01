# ADR-0004: Shared alarms; per-user alarm overlay deferred

- Status: accepted
- Date: 2026-10-24
- Scope: PLAN 5, backlog in [`../ROADMAP.md`](../ROADMAP.md)

## Context

`VALARM` components live inside the stored calendar object. On shared, group and managed calendars several
principals see the same object, but alarms are personal: one user's reminder, acknowledgement or snooze should
not change what others see. Apple Calendar and other clients write `ACKNOWLEDGED`, `X-MOZ-SNOOZE-TIME`,
`X-APPLE-DEFAULT-ALARM` and similar properties back to the server, also from read-only bindings.

Two options were considered:

- **A. Per-user alarm overlay**: alarms stored per principal and merged into the object on read, as CalendarServer
  does.
- **B. Shared alarms**: alarms are part of the shared object; personal alarm-only writes from principals without
  write access are accepted without being stored.

An overlay changes the ETag and change-log model of ADR-0003: the ETag would depend on the reader, the sync
token would have to cover per-user changes, and the store would need a merge step on every read and query.

## Decision

Option B for 1.0:

1. Alarms are stored as part of the calendar object and are the same for everyone who can read it.
2. A PUT from a principal with only read access whose only differences from the stored object are alarm
   acknowledgement or snooze changes (`VALARM` properties such as `ACKNOWLEDGED`, `X-MOZ-LASTACK`,
   `X-MOZ-SNOOZE-TIME`) answers **204 No Content** without storing anything and without an `ETag`, so the client
   does not report an error. Any other change from a read-only binding answers 403 as usual.
3. Principals with write access change alarms like any other property; the change is visible to all readers.
4. Default alarms remain per-binding properties (PLAN 2.6) and are therefore personal.

The per-user overlay is in the backlog ([`../ROADMAP.md`](../ROADMAP.md)).

## Consequences

- ETags, sync tokens and the change log stay reader-independent (ADR-0003).
- Users of shared calendars may see reminders set by the organizer or other writers; acknowledging or snoozing on
  a read-only calendar does not fail but is not synchronised to the user's other devices.
- The overlay can be added later without breaking stored data: the stored object stays the canonical source and
  the overlay only adds per-user alarm data on read.

## Alternatives considered

- **Overlay in 1.0 (option A)**: rejected for 1.0; it changes the ETag and change-log model and is more than the first release needs.
- **Strip alarms from shared objects**: rejected; it destroys alarms that owners set deliberately.
- **Reject alarm-only writes with 403**: rejected; clients show errors and retry for every reminder.
