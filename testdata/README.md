# Test data

Byte-exact bodies that tests, client-flow scenarios and fuzz targets start from. `.gitattributes` marks everything here
`-text diff`: git never converts a line ending (the `CRLF` of iCalendar is significant). Each kind of body has one place
(PLAN 3.5), and nothing is copied into a crate:

| Directory | Holds | Read by |
| --- | --- | --- |
| [`corpus/`](corpus/README.md) | iCalendar bodies as the clients write them (`rejected/` for what must be refused, `imip/` for mail attachments) | `crates/ical/tests` (corpus, robustness), `davhaven-fixtures::corpus`, the `ical` fuzz targets (seed corpus), client-flow scenarios (`body_file: corpus/...`) |
| [`dav/`](dav/README.md) | The DAV request and answer documents of the clients (`PROPFIND`, `PROPPATCH`, `REPORT`, `MKCALENDAR`) and, in `sharing/`, the CalendarServer sharing, notification, scheduling and principal search documents | `crates/dav` (unit and protocol tests), `crates/it/tests/appcore/dav_collaboration.rs`, `davhaven-fixtures::dav`, the `dav` fuzz targets (seed corpus), client-flow scenarios (`body_file: dav/...`) |

The iTIP golden set (the organizer's copy, the client's version, the classification and every message that results) is not
here: it is the specification of `davhaven-ical` and lives in `crates/fixtures/data/itip/` (see `docs/ical.md`).

`cargo xtask arch-check` fails when the nightly fuzz job names a seed corpus that is not a directory of the repository, so
a directory that moves takes its references with it. A file that a client really sent replaces its reconstruction with
the source note next to the name in the README of its directory, and the client-flow grid then stops reporting the cell as
synthetic.
