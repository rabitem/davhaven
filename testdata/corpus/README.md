# iCalendar corpus

Calendar object resources and iTIP messages as the clients of PLAN G1 produce them. The `ical` crate parses,
validates, indexes, expands, serializes and hashes every file in this directory (`crates/ical/tests/corpus.rs`).

The files are compared byte for byte and must keep their line endings (`.gitattributes` marks `testdata/**` as `-text`,
so git never converts them). Every file uses `CRLF` except
`lenient-lf-line-endings.ics`, which is `LF` on purpose.

## Provenance

The bodies are **reconstructions**: they follow the structure, property order, parameter spelling and quirks that
each client is known to produce (documented formats and widely reported quirks), with example data and
invented identifiers. They are marked `synthetic` in the client flow grid (PLAN 3.4) until staging captures
replace them. When a capture is added, keep the source note next to the file name below.

| File | Imitates | What it exercises |
| --- | --- | --- |
| `apple-macos-weekly-override.ics` | Apple Calendar on macOS (CalDAV) | `VTIMEZONE` with `RRULE`, weekly series with `UNTIL` in UTC, `EXDATE`, a moved instance (`RECURRENCE-ID`), folded UTF-8 summary, `X-APPLE-*`, alarm with `X-WR-ALARMUID` |
| `apple-ios-allday-yearly.ics` | Calendar on iOS | all-day series, `RRULE:FREQ=YEARLY`, default alarm with the 1976 trigger date and `ATTACH;VALUE=URI` |
| `apple-ios-invite-accepted.ics` | Calendar on iOS, attendee copy | `ATTENDEE` with `SCHEDULE-STATUS`, `EMAIL`, `RSVP`, organizer with `EMAIL` |
| `thunderbird-todo.ics` | Thunderbird (Lightning) | `VTODO` with `DUE`, `PERCENT-COMPLETE`, `X-MOZ-*`, alarm with `VALUE=DURATION`, escaped text |
| `thunderbird-event-monthly.ics` | Thunderbird | monthly rule with two ordinal weekdays and `COUNT` |
| `davx5-event-utc.ics` | DAVx5 (ical4j) | UTC times, `WKST`, weekly rule with two weekdays, `EXDATE` in UTC |
| `evolution-event-registry-tzid.ics` | Evolution | `TZID` in the `/freeassociation.sourceforge.net/Tzfile/` form, `X-LIC-LOCATION`, `X-EVOLUTION-*` |
| `caldav-synchronizer-windows-tzid.ics` | CalDav Synchronizer for Outlook | Windows `TZID` (`W. Europe Standard Time`) with its own `VTIMEZONE`, `X-MICROSOFT-CDO-*` |
| `caldav-synchronizer-windows-tzid-no-vtimezone.ics` | CalDav Synchronizer for Outlook | Windows `TZID` (`Romance Standard Time`) without a `VTIMEZONE` |
| `outlook-customized-timezone.ics` | Outlook | `TZID:Customized Time Zone` (not an IANA or Windows name) with a `VTIMEZONE` that starts in 1601 |
| `lenient-lf-line-endings.ics` | scripts and tools | `LF` line endings |
| `lenient-zero-length-dtend.ics`, `lenient-zero-length-allday.ics` | assorted clients | `DTEND` equal to `DTSTART`, timed and all-day |
| `lenient-iana-tzid-without-vtimezone.ics` | assorted clients | IANA `TZID` without a `VTIMEZONE`, series across a daylight saving change |
| `journal-date.ics` | assorted clients | `VJOURNAL` with a date-valued `DTSTART` |
| `utf8-folded-description.ics` | assorted clients | multi-byte characters, folding inside a word, escaped separators |
| `imip/google-request.ics`, `imip/google-cancel.ics` | Google Calendar invitations | iTIP `REQUEST` and `CANCEL` with `X-NUM-GUESTS` |
| `imip/outlook-request-windows-tzid.ics`, `imip/outlook-reply-accepted.ics` | Exchange / Outlook | `REQUEST` and `REPLY` with a Windows `TZID`, `LANGUAGE` parameters, `X-MICROSOFT-*` |
| `imip/apple-reply-declined.ics` | Apple Mail / Calendar | minimal `REPLY` |
| `rejected/*.ics` | broken uploads | data that must be refused: truncated documents (a parser that accepts them loses data; see ADR-0001), a `METHOD` in an object, mixed component types, differing UIDs, two calendars in one body, a vCard, an unbounded `SECONDLY` rule, `DTEND` before `DTSTART`, a date beyond the limit |
