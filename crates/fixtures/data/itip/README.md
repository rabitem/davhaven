# iTIP golden set

Every directory is one scheduling scenario of the organizer's calendar:

| File | Content |
| --- | --- |
| `old.ics` | the stored organizer copy (absent when the object is created) |
| `new.ics` | the version the client sends |
| `reply.ics` | optional: a `REPLY` that reached the organizer's copy after the client read it; it is applied to `old.ics` first and `new.ics` is compared with the result |
| `addresses.txt` | optional: addresses mapped to `mailto` addresses before a message is built (`from => to`, one per line) |
| `diff.txt` | the classification of every instance, added and removed attendees, cancelled instances |
| `organizer.ics` | the organizer copy to store: `SEQUENCE` raised where needed, answers and delivery states as the server holds them |
| `after-reply.ics`, `reply.txt` | with a `reply.ics`: the copy after the reply and what the application learns from it (attendee, answer, instances, comment) |
| `request-<name>.ics` | the `REQUEST` for an attendee |
| `cancel-<name>.ics` | the `CANCEL` of the whole object for an attendee |
| `cancel-instance-<n>-<name>.ics` | the `CANCEL` of one instance for an attendee |

`<name>` is the local part of the attendee's mailbox. The organizer never receives a message, and neither does an
attendee that the server does not schedule (`SCHEDULE-AGENT` other than `SERVER`). Messages are built at 2027-02-02
09:00 UTC, after every `DTSTAMP` of the stored copies.

## Rules the files encode

* A significant change (`DTSTART`, `DTEND`/`DURATION`, `RRULE`/`RDATE`/`EXDATE`, `LOCATION`, `SUMMARY`, `STATUS`)
  of an instance sends a `REQUEST` with the whole object to every attendee, resets their `PARTSTAT` to
  `NEEDS-ACTION` on that instance and raises its `SEQUENCE` above the stored one when the client did not.
* A new object sends a `REQUEST` to every attendee.
* **The answers of the attendees belong to the server.** Whatever `PARTSTAT` and `SCHEDULE-STATUS` the client
  writes, the stored copy keeps the answer and the delivery state the stored copy had; an attendee that is new on
  an instance (a new object, a new override, an added attendee) starts as `NEEDS-ACTION` without a status. Only a
  `REPLY` changes an answer (`reply-then-stale-edit`: Bob declined after the client read the copy, the stale
  version cannot take that back). Attendees with another `SCHEDULE-AGENT` than `SERVER` keep what their client
  wrote (`schedule-agent-client`).
* A new override that moves, shortens or renames its instance is a significant change of that instance (it is
  compared with the instance as the series produced it); one that only adds details is just new. Several overrides
  are classified one by one (`two-overrides`), and an override with `RANGE=THISANDFUTURE` is stored as sent
  (`this-and-future-override`).
* An insignificant edit (description, alarms, an attendee's own answer, other properties) sends nothing.
* A new attendee gets a `REQUEST` even when nothing else changed; the others hear nothing.
* A removed attendee gets a `CANCEL` of the whole object, built from the stored copy.
* An added `EXDATE` and a removed override give every attendee a `CANCEL` of that instance, built from the stored
  copy (`STATUS:CANCELLED`, `RECURRENCE-ID`). An override cancelled with `STATUS` is a significant change of its
  instance.
* `STATUS:CANCELLED` on the series gives every attendee a `CANCEL` of the whole object and no `REQUEST`.
* Every message is stamped with the moment it is built (`DTSTAMP`), never with the stamp of the stored copy, so that
  it sorts after the messages it follows.
* A `REQUEST` or `CANCEL` shows the recipient's `ATTENDEE` line only.
* Principal URLs and `urn:uuid` addresses are `mailto` addresses on the wire (`principal-addresses`): the stored
  copy keeps what the client wrote.
* Nothing private leaves the server: no `SCHEDULE-*` parameters, no alarms, no `X-APPLE-*` or `X-MOZ-*`
  properties, no inline attachments; every message carries a `VTIMEZONE` for each `TZID` it uses.

## Updating

The files are produced by `crates/ical/tests/itip_golden.rs`, which compares them byte for byte:

```
UPDATE_GOLDEN=1 cargo test -p davhaven-ical --test itip_golden
```

rewrites them. Review the resulting diff like any other change: it is the contract the scheduling matrix of the
application and the calendar API are tested against. The test also holds hand-written expectations (the
classification, the recipients, the `SEQUENCE` and the answers of every organizer copy) that do not change with the
files: a regression that the regenerated files would hide fails there.

The inputs are synthetic: they follow what the clients of PLAN G1 send, with the same event and the same three
people throughout so that two scenarios differ only in the edit. Line endings are `CRLF`; `.gitattributes`
keeps them byte-exact.
