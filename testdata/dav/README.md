# DAV request corpus

Request bodies as the clients of PLAN G1 send them to a CalDAV server. The protocol tests of the `dav` crate send every
file to the router and check what a client needs from the answer (`crates/dav/tests/protocol/clients.rs`); the fuzz
targets of the crate start from them.

The files are compared byte for byte (`.gitattributes` marks `testdata/**` as `-text`, so git never converts line
endings). XML libraries of the clients write the carriage returns of embedded iCalendar text as `&#13;`,
and the files do the same.

## Provenance

The bodies are **reconstructions**: they follow the structure, property order, prefix choices and quirks that each
client is known to produce (documented formats, the property lists of public traces and widely reported behavior),
with example data. They are marked `synthetic` in the client flow grid (PLAN 3.4) until captures from a deployed
instance (`observability.dav_capture`) replace them. When a capture is added, keep the source note next to the file
name below.

| File | Imitates | Sent to | What it exercises |
| --- | --- | --- | --- |
| `macos-propfind-entry.xml` | Apple Calendar on macOS, first request after login | `/dav/`, `Depth: 0` | `current-user-principal` discovery with the `A:` prefix for `DAV:` |
| `macos-propfind-principal.xml` | Apple Calendar | the principal, `Depth: 0` | the namespace declared on every property element, home, inbox, outbox and notification URLs, properties the server does not have (`dropbox-home-URL`, `resource-id`, `xmpp-server`) |
| `macos-propfind-home.xml` | Apple Calendar | the calendar home, `Depth: 1` | the 38-property listing with a namespace declaration on every element, Apple, CalendarServer and `me.com` properties, about half of them unknown to the server |
| `macos-propfind-members.xml` | Apple Calendar | a calendar, `Depth: 1` | listing the members with `getcontenttype`, `getetag` and `resourcetype` |
| `macos-mkcalendar.xml` | Calendar on iOS and macOS creating a calendar | a free calendar URL | `symbolic-color` attribute on `calendar-color`, `calendar-enabled` as a dead property, `calendar-timezone` with `&#13;` line breaks, `schedule-calendar-transp` |
| `macos-proppatch-color.xml` | Apple Calendar changing a calendar | a calendar | `set` and `remove` in one request, a dead property, `calendar-order` removal |
| `davx5-propfind-home-set.xml` | DAVx5 | the principal, `Depth: 0` | default namespace with prefix only for CalDAV, `group-membership` |
| `davx5-sync-collection.xml` | DAVx5 | a calendar | initial `sync-collection` with `getcontenttype` and `getetag`, the default namespace on the root |
| `davx5-multiget.xml` | DAVx5 | a calendar | `calendar-multiget` with the CalDAV namespace as default and an object that was deleted in the meantime |
| `thunderbird-calendar-query-events.xml` | Thunderbird (Lightning) | a calendar | `calendar-query` for `VEVENT` with a time range |
| `thunderbird-calendar-query-todos.xml` | Thunderbird | a calendar | `calendar-query` for open `VTODO`s: `is-not-defined`, negated `text-match` |
| `evolution-propfind-calendar.xml` | Evolution | a calendar, `Depth: 0` | a document that declares all namespaces on the root and writes `DAV:` as the default namespace |
| `ios-calendar-query-expand.xml` | Calendar on iOS | a calendar | `calendar-data` with `expand` and a time range |

## Sharing, notifications, scheduling and principal search (`sharing/`)

The requests and documents of the CalendarServer sharing flow, the scheduling collections of RFC 6638 and the principal
searches (PLAN 2.9). They are compared byte for byte by the unit tests of the modules `sharing`, `notifications`,
`scheduling` and `principals_search` of the `dav` crate (`crates/dav/src/*.rs`), sent to the router by
`crates/dav/tests/protocol/collaboration.rs` (over the fake application) and by
`crates/it/tests/appcore/dav_collaboration.rs` (over the real services). They follow the same provenance rules as the
files above: reconstructions of what Apple Calendar and the other clients send, with example data (`synthetic` in the
client flow grid). The documents the server writes are compared with what writes them, so that a change in either is a
visible change of a file: `notification-*.xml` with the output of `davhaven-app` (a unit test of `app::sharing::xml`),
`invite-reply-response.xml` and `schedule-response-freebusy.xml` with the output of the DAV layer (the unit tests of
`sharing` and `scheduling`). The bodies the clients send use the prefixes they use (`CS:` with the namespace declared
on the root, `D:` declared on the element that needs it, `A:`/`B:`).

| File | Imitates / documents | Used for |
| --- | --- | --- |
| `share-set-read-write.xml`, `share-set-read.xml` | Apple Calendar sharing a calendar with one person, with and without a display name and summary | `POST` to a calendar collection; `CS:set` with one access level |
| `share-remove.xml` | Apple Calendar ending a share | `CS:remove` |
| `share-set-and-remove.xml` | one request that invites, invites an outside address and removes | per-item answers of a share request |
| `invite-reply-accepted.xml`, `invite-reply-declined.xml` | the sharee's client answering an invitation | `POST` to the calendar home; `CS:in-reply-to`, `CS:hosturl`, `CS:summary` |
| `invite-reply-response.xml` | what the server answers to an acceptance | `CS:shared-as` naming the new collection |
| `notification-invite.xml`, `notification-invite-reply.xml` | the notifications the application stores for a sharee and for an owner | the resources of the notification collection |
| `propfind-notifications.xml`, `sync-notifications.xml` | Apple Calendar listing and synchronizing the notification collection | `CS:notificationtype`, `getetag`, `getcontenttype` |
| `outbox-freebusy-request.ics` | Apple Calendar asking for the free time of two people (CRLF line ends are significant) | `POST` to the outbox |
| `schedule-response-freebusy.xml` | the `CALDAV:schedule-response` of the server | one `response` per recipient, `&#13;` in embedded iCalendar |
| `inbox-multiget.xml` | a client fetching an item of Anna's inbox, one of Ben's inbox, one of a calendar and a stranger | `calendar-multiget` of the scheduling inbox: only the first is an item of the inbox it is sent to |
| `principal-search-attendee.xml` | Apple Calendar looking up an attendee while the user types | `CS:calendarserver-principal-search` with `context="attendee"` |
| `principal-property-search-anyof.xml`, `principal-search-property-set.xml` | other clients searching people | `DAV:principal-property-search` with `anyof`, `DAV:principal-search-property-set` |
