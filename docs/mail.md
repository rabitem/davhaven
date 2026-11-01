# Mail (iMIP)

Davhaven sends scheduling mail to attendees outside the tenant and to external organizers (RFC 6047, iMIP).
Internal attendees are served inside the server (RFC 6638); mail is only the way out. This page describes the mail
itself, what an operator can configure and what happens when something goes wrong. The templates are described in
[`templates.md`](templates.md).

## The path of a mail

1. A scheduling change writes an `ImipJob` to the **outbox** in the transaction of the change: the object, the
   recipient, the iTIP method, the locale, the template name and, where a message must survive the deletion of its
   object (`CANCEL`) or carry exactly the version that triggered it, a snapshot of the iCalendar text. The outbox
   never holds rendered content.
2. After the commit the **dispatcher** claims the record and gives it to the `imip` handler (`app::imip`).
3. The handler loads the tenant and the object, builds the iTIP message and describes the event with the iCalendar
   layer, resolves organizer and attendee, mints the RSVP link of an invitation, renders the template and composes
   the mail.
4. The `mime` crate assembles the message, a **mail transport** (`smtp` or `memory`) sends it.

Every step is repeatable: the `Message-ID` (derived from the outbox id) and the RSVP link (derived from the key
ring, see below) of a record are the same on every attempt, and so is the iTIP text when the job carries a snapshot.
A job without a snapshot (an invitation, a reply of an attendee whose copy still exists) is built from the object as
it is when the mail is sent. Records are not ordered, so the handler checks what it is about to say against that
object first: an invitation for someone who is no longer an attendee, or one older than the object (its `SEQUENCE`
is lower), is **dropped**, because the cancellation or the newer invitation that made it obsolete is queued on its
own and says the right thing. A mail that is sent twice (the process stopped between the send and the bookkeeping)
therefore says the same twice, or something newer, never something older.

## The message

```text
multipart/mixed
├── multipart/alternative
│   ├── text/plain; charset=utf-8
│   ├── text/html; charset=utf-8
│   └── text/calendar; charset=UTF-8; method=REQUEST
└── application/ics; name="invite.ics"
```

* One message per external recipient; `To` is that attendee (for a reply: the organizer).
* The `text/calendar` part and `invite.ics` carry the same iTIP text. The `method` parameter equals the `METHOD`
  property (the assembler refuses a mail where they differ). Alarms, `X-APPLE-*`, `X-MOZ-*`, `SCHEDULE-*` parameters
  and binary attachments are removed; a `VTIMEZONE` is included for every `TZID`.
* Headers: `Content-Class: urn:content-classes:calendarmessage`, `Auto-Submitted: auto-generated`,
  `X-Auto-Response-Suppress: OOF, AutoReply`, an RFC 2047 encoded `Subject`, `Message-ID: <{outbox id}@{sender domain}>`
  and a `Date` from the server clock. Header values cannot contain line breaks: the types of the mail model reject
  them, and display names from calendar data are cleaned and shortened before they are used.
* The calendar part of an update carries the higher `SEQUENCE`. The mail says "updated" (the template model has
  `update: true`) when it is an invitation (`REQUEST`) whose event has a `SEQUENCE` above zero in the version the
  mail is built from; the first invitation of an event, which has a `SEQUENCE` of zero, says "invitation".

### Who the mail comes from

`mail.from_mode` decides:

| Mode | `From` | `Sender` | `Reply-To` |
| --- | --- | --- | --- |
| `service` (default) | `"{person} via {tenant}" <noreply@{sender domain}>` | — | the person |
| `organizer` | the person's own address | the tenant's sender address | — |

`{person}` is the organizer of an invitation or cancellation, and the attendee who answers for a reply. Names from
calendar data are cleaned, and the person and the tenant are shortened to 80 characters each, so the sender name
stays a name and the "via" always remains in the header; the address of the person is never part of the display name. The sender address of a tenant comes from `tenant.settings.sender` (`local_part`, `domain`, `display_name`); **without a sender
domain no mail is sent for the tenant** (the record dies with the text "the tenant has no sender domain" and can be
retried after the settings are fixed). The `organizer` mode is used only for people whose address is in the sender
domain of the tenant (or one of its subdomains); for everyone else the `service` form is used, because the relay
would not sign for a foreign domain. The default passes SPF, DKIM and DMARC for the sender domain, which is why it
is the default.

### The RSVP link

Every invitation carries a link `…/rsvp/dvh_rsvp_{prefix}_{secret}` to the RSVP page, the tracked way to answer.
Replies that clients send with their mail buttons reach the organizer's mailbox and change the participation status
only if a mail gateway forwards them to the inbound iTIP endpoint ([`interop.md`](interop.md)).

* Server side only a keyed hash of the **secret component** of the token is stored (`RsvpToken`). Prefix and secret
  are derived from the key ring (purpose `rsvp`), the tenant and the token id, so a retry reproduces the link
  without storing it; [ADR-0007](adr/0007-derived-rsvp-tokens.md) records why this deviates from "random, shown once"
  and what it costs.
* The newest live token of an attendee for the object is reused while it still matches its derivation (the key ring
  has not been rotated) and outlives the event. Otherwise a new token is minted, and the links of earlier mails keep
  working until their own expiry: a reschedule or a key rotation never silently kills a link the attendee already has.
  A link expires seven days after the last instance of the event ended, at most a year after it was minted.
* Removing the attendee, cancelling and deleting the event revoke the tokens (the scheduling code does that with the
  change).

### Replies of internal attendees to external organizers

The job of a `REPLY` names the copy of the answering attendee (`object`) and the external organizer (`recipient`).
The job names the answering attendee (`replying_attendee`) and may carry the attendee's comment; the `ATTENDEE` of
the reply is that address, never one derived from the stored object, so the answer of an attendee who deleted their
copy still reaches the organizer. The RSVP link is not part of a reply.

Mail clients and gateways of the organizer expect the sender of a `REPLY` to be the attendee (RFC 6047). The
`service` form puts the tenant's address in `From` and the attendee in `Reply-To`, because the relay does not sign
for the attendee's domain, so a receiver that checks the sender of replies against the attendee may not apply them.
`davhaven_mail_reply_service_form_total` counts these replies; [`interop.md`](interop.md) describes the limitation
and what an operator can do about it.

## Safety rails

All of these are configured in `[mail]` and apply to every tenant.

* **Rate limit** (`rate_limit_per_minute`, default 120): a token bucket shared by all tenants **of the process**,
  refilled continuously (a fraction of a token is kept, so a low limit does not round down to nothing). Behind it
  the `mail` bucket of the `RateLimiter` port applies, which is shared between instances when the deployment
  configures a shared limiter (and allows everything with the `noop` one); a limiter that cannot answer does not
  stop the mail. A mail that finds either bucket empty is **deferred** for the time the next token takes: it comes
  back then, and the hold neither counts as an attempt nor fails anything. A hold that has lasted more than a week
  ends and fails like a relay error, so a mail cannot wait for ever.
* **Circuit breaker** (`max_consecutive_failures`, default 5): after that many failed sends in a row (the relay is
  unreachable, times out, or answers a temporary error) the breaker opens and mail waits in the outbox, deferred
  without using up attempts, instead of hammering a relay that is down. After a cooldown (it starts at
  `outbox.backoff_base`, doubles each time the relay fails again, and stops at `outbox.backoff_max`) one mail is let
  through as a probe while the others wait a few seconds; success closes the breaker. An answer of the relay, even
  the refusal of a recipient, shows that the relay works. The breaker is local to the process. The gauge
  `davhaven_mail_circuit_open` shows the state, `davhaven_mail_held_total{reason}` counts the mails held back.
* **Staging safety:** `allowed_recipient_domains` limits mail to the listed domains and their subdomains (others are
  dropped and counted in `davhaven_mail_dropped_total{reason="recipient_domain"}`), `redirect_all_to` sends every
  mail to one address instead (the original recipient is in the header `X-Davhaven-Redirected-From`). A test
  deployment that is cloned from production should set both before the first start.

## Failure behavior

| What happened | Result |
| --- | --- |
| the relay accepted the mail | done |
| the object was deleted before the mail was sent (invitation, reply without snapshot), the tenant is gone, the recipient is no longer an attendee, the invitation is older than the object, the recipient is outside `allowed_recipient_domains` | done (dropped, counted) |
| rate limit or open breaker | deferred until a token or the probe is due (no attempt used) |
| relay unreachable, timeout, temporary refusal, a refusal that is the relay's policy (`5.7.x`), template renderer or calendar layer unavailable | retried with backoff (`outbox.max_attempts`, default 12) |
| the relay refuses the mail or a recipient (`5.1.x`, `5.2.x`, `5.3.4`, `5.4.x`, `5.6.x`, a bare `550`-`553`) | dead at once |
| invalid calendar data, no organizer or start in the event, a template that cannot render, no sender domain, no e-mail recipient | dead at once |

A record that is dead (or out of attempts) raises the event `mail.delivery_failed` for the tenant (reason `rejected`
or `exhausted`), which webhook subscribers and the event sinks see (an integration can tell the organizer). Dead records
are listed by `GET /api/v1/tenants/{tenant}/outbox?status=dead` and retried with `POST …/outbox/{id}/retry` after the
cause is fixed. The error text of a record never contains addresses or relay output: relay failures are reduced to
"the mail relay refused the message" and "the mail relay is not available".

## Transports

```toml
[plugins]
mail_transport = "smtp"          # or "memory"

[plugin.smtp]
host = "smtp.example.org"
port = 587
tls = "starttls"                 # "starttls" (the upgrade is mandatory), "implicit" (port 465) or "none"
username = "davhaven"
password_file = "/run/secrets/smtp_password"
ehlo_name = "example.org"        # what the server calls itself in EHLO; default "localhost"
timeout = "8s"                   # connecting and every SMTP command
total_timeout = "30s"            # the whole mail, from the first byte to the answer to the end of the data
```

* `ehlo_name` is judged by relays (some refuse or penalize a name that is not a fully qualified domain). Set it to a
  name of the deployment that resolves, for example the sender domain. The name of the machine is never used: in a
  container it is a random identifier.
* `tls = "none"` is for a capture server such as Mailpit. In production mode a relay on another host is refused with
  it, because invitations and RSVP links would cross the network in the clear; `localhost` and the loopback addresses
  are this host, any other name is another host (names are not resolved). `plugin.smtp.allow_insecure_transport = true`
  accepts it for a capture server on a private network, such as the mail catcher of a staging deployment, and never
  accepts a login: with `username` and `password_file` set, production refuses `tls = "none"` to another host whatever
  the opt-in says, because a capture server needs none. In `dev` mode the choice is the operator's. `config check`
  applies the same rules as the start, warns when the opt-in is in effect (mail travels unencrypted) and when it is
  set but has no effect.
* A mail has a budget. Connecting and each command expected (`EHLO`, `MAIL`, one `RCPT` per recipient, `DATA`, the
  end of the data) take at most `timeout` each, and the whole conversation at most `total_timeout`; a relay that is
  slow but never fails is cut off and counted as a timeout (and by the circuit breaker). The outbox cancels a handler
  after 80 % of `outbox.lease` and the handler gives the send 60 % of it, so **`total_timeout` has to stay below
  60 % of the lease** (30 s of the default minute). `davhaven config check` and the start refuse a configuration where
  it does not.
* How a failure is classified decides what the outbox does:

| The relay or the network | Result |
| --- | --- |
| connection refused or reset, TLS failure, `4xx`, authentication refused (`530`, `534`, `535`, `538`), no `STARTTLS` or `AUTH` where the configuration requires it | retried, counts for the breaker |
| no answer in time | retried, counts for the breaker |
| `5xx` that says the mail or a recipient is the problem (`5.1.x` address, `5.2.x` mailbox, `5.3.4` too big, `5.4.x` routing, `5.6.x` content, a bare `550`-`553`) | dead at once |
| any other `5xx` (`5.7.x` policy such as "relay access denied" or "sender not allowed", `5.5.x`, a refusal at the greeting) | retried: an operator fixes the relay, and the mail is not dead-lettered one by one |
| the mail cannot be encoded | dead at once |

  The text of an error never contains the reply of the relay (it can quote the recipient); only the code is kept.

* `smtp` opens a fresh connection per mail (mail volume is low and a stale pooled connection is a worse failure than
  the handshake). The relay's queue id is logged with the outbox id. Credentials come from a file, never from the
  configuration text.
* `memory` keeps the structured mail and the assembled bytes of the last `max_messages` mails for tests; it is
  refused in production mode.

## Metrics

| Metric | Meaning |
| --- | --- |
| `davhaven_mail_sent_total{method}` | mails the transport accepted |
| `davhaven_mail_failed_total{reason}` | mails that failed (`rejected`, `unavailable`, `rate_limited`, `breaker_open`, `template`, `calendar`, `no_sender`, …) |
| `davhaven_mail_dropped_total{reason}` | mails dropped on purpose |
| `davhaven_mail_held_total{reason}` | mails the rate limit or the breaker held back (deferred, not failures) |
| `davhaven_mail_reply_service_form_total` | replies sent in the service form because the attendee's address is not in the sender domain |
| `davhaven_mail_circuit_open` | 1 while the breaker is open or half open |
| `davhaven_port_calls_total{port="mail_transport",…}` | every transport call, with outcome and latency |

Logs mention the outbox id, the tenant id, the method and the reason; they never contain an address.
