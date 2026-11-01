# iCalendar processing

How Davhaven reads, checks, expands and schedules iCalendar data. The code is the crate `davhaven-ical`
(`crates/ical`); the rules it enforces come from [`PLAN.md`](PLAN.md) sections 2.7, 2.8 and 2.15. This page
describes the behaviour clients and operators can rely on; the places where Davhaven deviates from an RFC or
chooses between readings are listed in [`interop.md`](interop.md).

## What is stored

A calendar object resource is stored exactly as the client sent it. The server serializes an object again
only when it changes it itself (a merged API edit, an iTIP update, `SCHEDULE-STATUS`); the output is folded at
75 octets and parses back to the same object, and serializing that again gives the same bytes. Everything the
server produces passes the gate every stored object passes: it is written out, parsed and validated again with the
configured limits, so a result can always be stored and read back.

Everything the server generates carries `PRODID:-//Davhaven//iCalendar//EN`.

## What clients may send

The parser accepts what the clients of PLAN G1 produce, not only what RFC 5545 allows:

| Leniency | Behaviour |
| --- | --- |
| Line endings | `CRLF`, bare `LF` and bare `CR` are all lines; a leading byte order mark and trailing blank lines are ignored |
| Folding | folded lines are unfolded |
| Unknown properties and parameters | kept verbatim (`X-*`, vendor and unknown IANA names) |
| Windows time zone names | `TZID=W. Europe Standard Time` resolves to `Europe/Berlin` through an embedded CLDR table; a `VTIMEZONE` is not needed |
| IANA `TZID` without `VTIMEZONE` | resolves through the time zone database |
| `VTIMEZONE` with a custom `TZID` | its observances are evaluated; `X-LIC-LOCATION` and `X-MICROSOFT-CDO-TZID` name the zone when the `TZID` itself is unknown |
| Unknown `TZID` and no usable `VTIMEZONE` | the value is read as floating time |
| Zero-length events | `DTEND` equal to `DTSTART` (or `DURATION:PT0S`) is an instant, not an error; see below |
| `RRULE:FREQ=HOURLY` | accepted with a `COUNT` or an `UNTIL`; an endless hourly rule needs more steps than the budget allows (see "Index") |
| `EXRULE` | kept, ignored when expanding (RFC 5545 obsoleted it) |

What is refused, with the CalDAV precondition a client sees when it stores the object:

| Input | Response |
| --- | --- |
| Not iCalendar, not UTF-8, or not one `VCALENDAR` | `valid-calendar-data` |
| A truncated document (an unterminated `BEGIN:` block, a missing `END:VCALENDAR`) | `valid-calendar-data`; storing it would lose data |
| A `METHOD` property, components of more than one type (`VEVENT` with `VTODO`), more than one UID, more than one master component, two components with the same `RECURRENCE-ID`, a component that is not `VEVENT`, `VTODO` or `VJOURNAL` | `valid-calendar-object-resource` (RFC 4791 section 5.3.2.1) |
| Differing `ORGANIZER`s in the components | `same-organizer-in-all-components` (RFC 6638) |
| An `RRULE` or `EXRULE` that cannot be read, a rule without `DTSTART`, or a rule RFC 5545 forbids (for example `BYMONTHDAY` on a `WEEKLY` rule) | `valid-calendar-data` |
| `DTEND` or `DUE` before `DTSTART`, a value that is not a date, a duplicate property that may appear once, a wrong `VERSION` | `valid-calendar-data` |
| `FREQ=SECONDLY` or `MINUTELY` | `valid-calendar-data` |
| Something the writer cannot reproduce: a parameter name with a backslash, a quote or a colon in it, a UTC offset of fewer than four digits, a date-time that something follows (`DTSTAMP:20270101T000000Z2`), a parameter value with a quote in it, a value whose escaped form is longer than `max_value_length` | `valid-calendar-data` (see below) |
| Any date outside 1900-2100 (VTIMEZONE observances are exempt) | `min-date-time` / `max-date-time` |
| A recurrence rule that needs more than `max_iterator_steps` steps to reach the year 2100 (every endless `HOURLY` rule, and endless rules that produce many instances a day) | `max-instances` |

### What survives the writer

The reader behind `parse` (the `calcard` crate) is more lenient than its writer: it reads a value that is nearly a
date-time as one, and it unescapes a parameter name like a value, while the writer writes a name as it is. Data
for which the two disagree came back from the writer as another calendar, or as text that no longer parsed.

There are two entry points, and the difference is the point. `parse` **reads**: it is how everything that is stored is
read (a `calendar-query`, a feed, a search, free-busy, the JSON view of an event, the scheduling paths), and it does not
decide what may be kept, so a read never fails because of how a client wrote a value. `parse::accept` is the **gate**
of what comes in: `validate::parse_and_validate` (a `PUT`, a batch item, the result of a merge), `itip::parse_message`
(an inbound or posted scheduling message) and `tz::calendar_timezone` (a `calendar-timezone`) go through it. It accepts
only what the writer reproduces: it writes the tree it read, reads that text again, within the same limits, and
requires the same tree (the corner cases the scan treats before that: a parameter name must be letters, digits, `-`
or `_`, and only the space and the tab are blank around a name, because the parser reads the other Unicode white space
as part of it). What is refused is refused as `valid-calendar-data`; what is accepted has the round trip
`parse(serialize(c)) == c`, the same content hash and a serialization that is a fixed point. The limits hold for the
written text because the server may store it and reads a stored object under them: escaping makes a value longer (a `,`
that a client sent without a backslash is two characters when written), so data whose written form is above
`max_value_length` or `max_resource_size` is refused when it comes in, not when the server first rewrites it. The gate
costs one more write and read of the document (tens of microseconds for a typical event in a release build), once per
write and not per read.

The stored bytes of an object are never touched by this: it only decides what is accepted. Everything stored is
read with `parse`, so it stays readable everywhere; an object that `parse::accept` would refuse cannot be rewritten by
the server (a JSON merge or a scheduling merge is refused as `valid-calendar-data`, like a client's write of the same
bytes). The fuzz target `parse_validate` and the robustness test
assert the property for everything `accept` lets in, and `tests/robustness.rs` sweeps every content line of the corpus
with the characters that matter and a value that grows when it is written.

### One error, three answers

The same [`IcalError`] is a different answer on a `PUT`, on a `REPORT` and on an iTIP message. `davhaven-ical`
therefore reports what is wrong, and the application chooses the situation with `ErrorContext` (and
`AppError::from_ical`, which `AppError::from` calls with `Store`):

| Situation | Entry points |
| --- | --- |
| `Store` | `parse_and_validate`, `validate`, `index`, `merge_event`, `merge_event_split`, `remove_instances_with_limits`, `diff`, `apply_organizer_changes`, `calendar_timezone` |
| `Query` | `matches`, `validate_filter`, `expand`, `busy_periods`, `busy_periods_for`, `project` (all with their `_in_zone` forms) and `TimeRange::validate` |
| `Scheduling` | `parse_message`, `build_message`, `apply_reply_with`, `set_schedule_status`, `reply_message`, `set_sent_by`, `read_request` |

| Error | Store | Query | Scheduling |
| --- | --- | --- | --- |
| invalid data | `valid-calendar-data` | `valid-filter` | `valid-scheduling-message` |
| calendar object resource rule | `valid-calendar-object-resource` | `valid-filter` | `valid-scheduling-message` |
| organizer mismatch | `same-organizer-in-all-components` | `valid-filter` | `valid-scheduling-message` |
| `ResourceSize` | `max-resource-size` | `max-resource-size` | `max-resource-size` |
| `Attendees` | `max-attendees-per-instance` | `max-attendees-per-instance` | `valid-scheduling-message` |
| `Instances`, `IteratorSteps` | `max-instances` | `valid-filter` | `valid-scheduling-message` |
| `MinDateTime`, `MaxDateTime` | `min-date-time`, `max-date-time` | `valid-filter` | `valid-scheduling-message` |
| `TimeRange` | `valid-filter` | `valid-filter` | `valid-scheduling-message` |
| `Nesting` | `valid-calendar-data` | `valid-filter` | `valid-scheduling-message` |
| every other limit | `valid-calendar-data` | `valid-calendar-data` | `valid-scheduling-message` |
| `TimeBudget` | none: 503 | none: 503 | none: 503 |
| unsupported | none: a server-side gap | none | none |

`min-date-time`, `max-date-time` and `max-instances` are preconditions of `PUT` in RFC 4791; a query that asks for
too much is a filter problem. Running out of time (`TimeBudget`) depends on the load of the machine and not on the
data, so it is never a statement about the data: the application answers 503 with `Retry-After` (PLAN 2.15).

## Limits

`IcalLimits` carries the values of PLAN 2.15. The deterministic bound of every computation is the step budget
(`max_iterator_steps`, counted per generated recurrence date) together with the structural limits below; the
wall-clock budget `time_budget_ms` is a second line of defence for the load of the machine. It is checked between
series, after every rule, every few hundred instances and by the parser after it has read the document (the
structural scan and the size limit run first and bound the input). A budget that runs out is the transient
`TimeBudget`, not invalid data, and a budget is shared by everything one call does: free-busy over many objects
spends one step budget and one time budget, not one per object.

| Limit | Default | Precondition when storing |
| --- | --- | --- |
| resource size | 1 MiB | `max-resource-size` |
| components, properties per component, unfolded value length | 1000, 500, 64 KiB | `valid-calendar-data` |
| nesting depth (the parser stops at 32 whatever is configured) | 4 | `valid-calendar-data` |
| attendees per instance, and distinct attendees of the object as a whole | 200 | `max-attendees-per-instance` |
| `VALARM`s per component, `RDATE` plus `EXDATE` values, observances per `VTIMEZONE` | 10, 1000, 200 | `valid-calendar-data` |
| observances and transitions an evaluated `VTIMEZONE` may produce together (only zones that something refers to are evaluated) | 1000, 20 000 | `valid-calendar-data` |
| inline binary `ATTACH` (decoded; exempt from the value length limit) | 256 KiB | `valid-calendar-data` |
| instances an expansion returns, iterator steps | 3000, 100 000 | `max-instances` |
| earliest, latest year | 1900, 2100 | `min-date-time`, `max-date-time` |
| time-range and free-busy span | 10 years | `valid-filter` |

`max_instances` caps what an expansion *returns* (`expand`, `limit-recurrence-set`). Deciding whether any instance
overlaps a time range (`matches`), computing busy time and indexing do not count instances: they stop at the first
instance that decides the question or fold over all of them, so one long series never fails a whole `REPORT`. Free
busy still caps its merged output (50 000 busy periods).

## Time and recurrence

* **Zones.** A wall-clock time in a zone maps to an instant by RFC 5545 section 3.3.5: a time that occurs twice
  (the clocks go back) is the first occurrence, a time that does not occur (the clocks go forward) uses the offset
  from before the jump. A recurring event keeps its wall-clock time across a change of offset.
* **Floating times and all-day dates** have no zone. RFC 4791 section 9.9 reads them in the calendar's
  `CALDAV:calendar-timezone`. `tz::calendar_timezone` validates that property's value (exactly one `VTIMEZONE`,
  nothing else) and returns the zone it stands for, and the `_in_zone` variants (`expand_in_zone`,
  `matches_in_zone`, `busy_periods_in_zone`, `project_in_zone`) read floating values and dates in that zone. The
  plain `expand`, `matches`, `busy_periods` and `project` read them as UTC; the application uses the `_in_zone`
  forms. Everything that is only an index (`index`) widens such values by 14 hours on both sides, so the index never
  excludes an object that a query in any zone would find.
* **Instances.** `DTSTART` is the first instance whether or not the rule produces it. `RDATE` (dates, date-times
  and periods) adds instances, `EXDATE` removes them (by instant for date-times, by day for dates). An override
  (`RECURRENCE-ID`) replaces exactly the instance it names, matched by instant (by date for all-day series), so an
  override written in another zone than the series still pairs with its instance; an override that names no
  instance stands on its own. `RANGE=THISANDFUTURE` on an override moves and reshapes the following instances when
  reading; the server never writes it (see "Editing this and following instances").
* **Zero-length events** are instants and are accepted. RFC 4791 section 9.9 treats three of them differently,
  and so does `time-range`: with a timed `DTEND` equal to `DTSTART` the range must contain the instant strictly (it
  starts before it and ends after it); with `DURATION:PT0S`, or with neither `DTEND` nor `DURATION`, a range that
  starts exactly at the instant finds it as well; none finds an instant at the end of the range. A date-valued
  `DTEND` equal to `DTSTART` is read as the one day the client means (a query for that day starts at midnight and
  has to find it).
* **Tasks** follow the table of RFC 4791 section 9.9 for `DTSTART`, `DUE`, `DURATION`, `COMPLETED` and `CREATED`.
* **Index.** `first_start` and `last_end` bound every instance. Both are widened by one second because RFC 4791
  section 9.9 compares inclusively in some rows (an event without an end matches a range that starts exactly at
  its start, a to-do with only a `DUE` matches a range that ends exactly at it) while the store's pre-filter
  compares strictly: the index is a superset at every boundary (a property test checks it against the exact
  evaluation). `last_end` is absent for a rule that never ends, so the pre-filter treats such an object as
  open-ended. Every rule, bounded or not, is evaluated up to the year 2100 within `max_iterator_steps` when the
  object is stored: a rule that needs more (every endless hourly rule) is refused with
  `max-instances`, so that no stored object can make a later read fail. The distinct attendees of an object are
  bounded by the same limit as one instance's.

## Scheduling (iTIP)

`itip::diff` compares the stored organizer copy with the new one, instance by instance (the master and every
override), and reports each change as `Created`, `Significant`, `Insignificant`, `Removed` or `Unchanged`, the
attendees that came or went (for the object, and per instance for an override that names other attendees than the
series) and the cancelled instances.

* A significant change is one of `DTSTART`, `DTEND`/`DURATION`/`DUE`, `RRULE`, `RDATE`, `EXDATE`, `LOCATION`,
  `SUMMARY`, `STATUS`. Equivalent encodings of the same time (another zone, `DTEND` against `DURATION`) are not
  changes; `SEQUENCE`, `DTSTAMP`, `LAST-MODIFIED`, `CREATED` and `PRODID` never are.
* A new override is compared with the instance the series produced for it, so moving one occurrence is a
  significant change of that occurrence.
* Added `EXDATE`s and removed overrides are reported as cancelled instances; removed attendees as removed
  attendees. The organizer's own `ATTENDEE` line is never a recipient.
* **The answers of the attendees are the server's.** `PARTSTAT` and `SCHEDULE-STATUS` of an attendee on the
  organizer's copy change in exactly two ways: `itip::apply_reply_with` writes the answer of a `REPLY`, delivery
  writes the status (`itip::set_schedule_status`). `itip::apply_organizer_changes` replaces whatever the
  organizer's client sent for them: an attendee that is on the same instance of the stored copy keeps both as
  stored, an attendee that is new on the instance (a new object, a new override, an added attendee) starts as
  `NEEDS-ACTION` without a status, and a significantly changed instance resets every attendee but the organizer to
  `NEEDS-ACTION` and raises its `SEQUENCE` above the stored one (unless the client already raised it). Nobody who
  can write the organizer's calendar can forge an acceptance, and a stale copy cannot overwrite a reply that
  arrived after the client read it. Attendees whose `SCHEDULE-AGENT` is not `SERVER` and the organizer's own line
  are left alone: their answers do not come from the server. `itip::organizer_change_violations` names an
  `ORGANIZER` or `UID` that changed.
* `itip::build_message` derives the `REQUEST`, `CANCEL` or `REPLY` for one recipient. Every component carries the
  `DTSTAMP` of the moment the message is built (`MessageSpec::dtstamp`, from the `Clock`), because recipients order
  messages with the same `SEQUENCE` by `DTSTAMP` (RFC 5546 section 2.1.5); `SEQUENCE` is the one of the copy the
  message is built from, which is at least that of every `REQUEST` sent before. A whole-object message leaves out
  the components that do not list the recipient, so an attendee who was removed from one instance still gets the
  rest and a `CANCEL` of that instance (`MessageScope::Instances`) is a message of its own. A `REQUEST` or `CANCEL`
  shows the recipient's `ATTENDEE` line only (`AttendeeVisibility::Own`, the default) or all of them
  (`AttendeeVisibility::All`). A `REPLY` carries `MessageSpec::comment` as `COMMENT`. Nothing private leaves the
  server: no `SCHEDULE-*` parameters, no alarms, no `X-APPLE-*` or `X-MOZ-*` properties, no inline attachments;
  every `TZID` of a message comes with a `VTIMEZONE`.
* `itip::rewrite_addresses` maps calendar user addresses (`ORGANIZER`, `ATTENDEE`, `SENT-BY`, with their
  parameters) before a message is built: principal URLs and `urn:uuid` addresses become `mailto` addresses (PLAN
  2.6). The application maps the copy first and builds the message from the mapped copy.
* `itip::parse_message` checks inbound messages like stored objects (dates, recurrence rules, counts, sizes, one
  UID, a known `METHOD`, only the components that method allows).
* `itip::apply_reply_with` folds a `REPLY` into the organizer copy. It takes the configured limits and the address
  the message came from: a reply whose `ATTENDEE` is somebody else is refused, so an attendee cannot answer for
  another. A reply may name at most `max_recurrence_dates` instances (looked up in one expansion, within the time
  range limit of each other), a reply to an instance without an override creates the override, a reply without
  `RECURRENCE-ID` answers the master and every override that still carries the attendee's earlier answer, and the
  result must still be an object the server stores. The `COMMENT` of the reply is returned in
  `ReplyApplication::comment` (it is not stored in the copy). `itip::apply_reply` is the same with the default
  limits and no expected attendee, for tests.
* `itip::attendee_change_violations` tells which parts of an attendee's copy changed beyond their own
  participation (their `ATTENDEE` parameters, alarms and `TRANSP`).
* The application never reads or writes iCalendar text itself; these constructions are here for it.
  `itip::reply_message` builds the `REPLY` of an answer that has no copy to derive it from (the RSVP page, the
  answer through the API, a decline that a deletion implies); `ItipMessage::object` is the calendar object a message
  describes (no `METHOD`); `itip::set_sent_by` names the party that acts for the organizer on every `ORGANIZER`;
  `itip::strip_alarms` removes the alarms of an object that came from outside; `itip::carry_over_attendee_data`
  keeps the alarms and the `TRANSP` of the copy a recipient had when the organizer's next version replaces it;
  `freebusy::read_request` reads the `VFREEBUSY` request of an outbox `POST` from a message that passed
  `parse_message`; `freebusy::busy_periods_for` is the busy time of one person (what they declined is free, and in
  the calendar of a group or a shared one only what they take part in counts).

The scenarios in `crates/fixtures/data/itip/` show the messages and the stored copy of every case; see the
`README.md` there.

### Editing this and following instances

`remove_instances_with_limits` removes one instance (`EXDATE` and the override go) or this and the following ones
(the rule ends with an `UNTIL` before the instance). `merge_event_split` edits this and the following instances
the way calendar clients commonly do it, because few of them evaluate `RANGE=THISANDFUTURE`: the original object
is shortened with an `UNTIL`, and the edited instance starts a new series with a UID of its own
(`SplitEdit::earlier` and `SplitEdit::continuation`; when the first instance is edited, nothing remains before it
and the whole object is edited). Both objects pass the gate of every stored
object. Whether and to whom the changes are sent is the caller's business: the new series is a new scheduling
object. `merge_event` with `EditScope::ThisAndFuture` and a recurrence id is not supported for that reason; the
server never writes `RANGE=THISANDFUTURE`.

## Merging JSON events

`merge_event` merges an `EventData` into a stored component as a JSON Merge Patch (RFC 7396) and keeps everything the
model does not know: a field with a value replaces the property, an absent field keeps it and a field that is `null`
(`EventData::removed`) removes it. `uid` and `start` cannot be removed (`null` for them is refused where the JSON is
read); `null` for `recurrence_id` and `sequence` is the same as leaving them out; the other fields can be removed
(`summary`, `description`, `location`, `end`, `duration`, `status`, `transparency`, `class`, `recurrence`, `organizer`,
`attendees`, `categories`, `url`, `alarms`), and an empty text or list removes them as well. The rule is that of
RFC 7396 for the members of the event and no deeper: an object or a list that is sent replaces the stored one as a
whole (`recurrence` takes the rule, the extra dates and the exclusions together, `organizer` its name and `SENT-BY`),
and only attendees are matched, by address. An organizer cannot be removed while the event has attendees (refused as
invalid data: remove them in the same write), and in a series with overrides the organizer of the master cannot be
removed alone (`same-organizer-in-all-components`). The
answers of the attendees are not the patch's to set (`partstat` is ignored for every attendee but the organizer's
own line), `EMAIL` alarms are refused (they would need a `SUMMARY` and an `ATTENDEE` the model does not carry), the
text of an alarm that has no text comes from the title of the event or from `MergeContext::default_alarm_text`
(localized by the caller), and the escaped length of text fields, the size of the object and the number of
properties are checked by the same gate as every stored object.

## Public items for the application

Besides the core functions (`parse`, `validate`, `index`, `expand`, `matches`, `busy_periods`, `project`, `diff`,
`merge_event` and the `itip` message builders), the crate exports these items, because the application needs them to
apply the same rules:

* `ErrorContext`, `IcalError::ObjectRule`, `IcalError::OrganizerMismatch`, `IcalError::precondition_in`,
  `IcalError::is_transient`, `IcalError::client_message`, `LimitKind::precondition_in`,
  `LimitKind::client_message`: the answer depends on the request (above);
* `expand::expand_in_zone`, `filter::matches_in_zone`, `freebusy::busy_periods_in_zone`,
  `projection::project_in_zone` and `tz::calendar_timezone`: floating times and dates in a calendar's zone;
* `itip::apply_organizer_changes` with `OrganizerUpdate`, `itip::organizer_change_violations`,
  `itip::attendee_change_violations`, `itip::apply_reply_with`, `itip::rewrite_addresses` and
  `itip::AttendeeVisibility`;
* `itip::reply_message` with `ReplySpec`, `ItipMessage::object`, `itip::set_sent_by`, `itip::strip_alarms`,
  `itip::carry_over_attendee_data`, `freebusy::read_request` with `FreeBusyRequest` and `freebusy::busy_periods_for`
  with `Participation`;
* `merge::merge_event_split` with `SplitEdit` and `merge::remove_instances_with_limits`;
* new fields: `MessageSpec::{dtstamp, attendees, comment}` (build one with `MessageSpec::new`),
  `ReplyApplication::comment`, `ItipDiff::instance_attendees` and `MergeContext::default_alarm_text`;
* `contained_panics`: how many panics of the parser library were contained (a metric for the application).

The transient `TimeBudget` has no precondition: `LimitKind::precondition` cannot say "none" for it, so use
`IcalError::precondition_in`. The plain zone-less functions read floating values as UTC; the application calls
the `_in_zone` forms.

## Tests

| What | Where |
| --- | --- |
| Corpus of client bodies: every file parses, round-trips, expands, matches and sums up as documented; rejected inputs fail with the expected precondition | `testdata/corpus`, `crates/ical/tests/corpus.rs` |
| RFC 4791 section 9.9 time-range vectors | `crates/ical/tests/rfc4791_time_range.rs` |
| `calendar-query` filters (RFC 4791 section 9.7): collations, `negate-condition`, `is-not-defined` at three levels, parameter filters, nested components, alarms, free-busy, `validate_filter` | `crates/ical/tests/filters.rs` |
| Read paths: long series, one budget per call, the index as a pre-filter that never misses, override pairing across zones and for all-day series | `crates/ical/tests/reads.rs` |
| Expansion against an independent oracle, metamorphic relations (windows add up, an `EXDATE` removes exactly one instance, an override replaces exactly one), fixed-point serialization, `time-range` against a brute-force evaluation of the RFC | `crates/ical/tests/properties.rs` |
| Never-panic over arbitrary bytes, mutated corpus files and random assemblies of iCalendar lines; a panic that the parser library throws and the crate contains counts as a failure; whatever is accepted survives the writer (the round trip, the same content hash, a fixed point), also with every content line of the corpus edited at its start, after its first `;` and at its end by the characters that mattered | `crates/ical/tests/robustness.rs` |
| iTIP golden set, with hand-written expectations for classification, `SEQUENCE`, answers and recipients next to it | `crates/ical/tests/itip_golden.rs`, `crates/fixtures/data/itip` |
| Fuzz targets | `crates/ical/fuzz` |

`PROPTEST_CASES=20000 cargo test -p davhaven-ical --release` runs the property tests as the nightly job does;
failing cases are written next to the test (`*.proptest-regressions`) and replayed first, so commit them. The
golden files are rewritten with `UPDATE_GOLDEN=1 cargo test -p davhaven-ical --test itip_golden`; review the diff
like any other change.

The corpus is synthetic: the bodies are reconstructions of what each client sends, written for this repository
(`testdata/corpus/README.md` says so per file). Real captures (see "The capture converter" in
[`testing.md`](testing.md)) are meant to replace them, and the client-flow grid keeps reporting the cells that rest on
synthetic bodies until then.

### Fuzzing

The fuzz package is outside the workspace (it needs a nightly toolchain and the libFuzzer runtime) and has its own
lock file. CI runs `cargo check` and `cargo deny` on it, Dependabot updates it, and the nightly workflow runs every
target for ten minutes, seeded with the corpus. From `crates/ical`:

```
cargo +nightly fuzz run parse_validate     # parse, validate, round trip, index
cargo +nightly fuzz run expand_filter      # expansion, filters, free-busy, projection over any time range
cargo +nightly fuzz run itip               # diff, organizer rules, messages, replies, inbound messages
cargo +nightly fuzz run zones              # time zone identifiers and VTIMEZONE rendering
cargo +nightly fuzz run everything         # every entry point, the body of the never-panic test
```

The corpus files of `testdata/corpus` are good seeds: `cargo +nightly fuzz run parse_validate ../../testdata/corpus`.
A crash input becomes a regression test next to the corpus files.
