# Webhooks and domain events

Davhaven tells other systems what happens in a tenant with **domain events**. An event is written to the outbox in
the transaction of the change that causes it; after the commit the dispatcher hands it to the configured event sinks
and turns it into one **webhook delivery** per matching subscription. Deliveries follow the
[Standard Webhooks](https://www.standardwebhooks.com) specification, so existing libraries verify them.

This page describes what a receiver sees and how an operator runs it. The event catalog and the payload schemas are
generated from the code (`docs/contracts/events.schema.json`); the management API is described by `docs/openapi.json`.

## Events

| Type | When |
| --- | --- |
| `principal.created`, `principal.updated`, `principal.deleted` | a principal changed |
| `membership.changed` | the members of a group changed |
| `calendar.created`, `calendar.updated`, `calendar.deleted` | a calendar changed |
| `calendar.objects_changed` | objects of a calendar were created, changed or deleted |
| `grant.created`, `grant.updated`, `grant.deleted` | the grants of a calendar changed |
| `share.invited`, `share.accepted`, `share.declined` | a calendar share invitation was sent or answered |
| `scheduling.reply_received`, `scheduling.reply_rejected` | an attendee's reply was applied or refused |
| `rsvp.answered` | an attendee answered through an RSVP link |
| `mail.delivery_failed` | a scheduling mail could not be delivered (permanently) |
| `external_account.sync_failed` | syncing an external account failed |
| `webhook.disabled` | a subscription was switched off after repeated failures (or because the receiver answered 410) |
| `webhook.ping` | the test event of `POST …/webhooks/{id}/ping`; it goes to that subscription only, whatever its filter says, and **cannot be subscribed to** (a subscription that lists it is refused) |

Payloads are thin: ids, natural keys and ETags, never the content of an event and never an e-mail address.
Consumers fetch what they need through the API. The shape of `data` is fixed per type and only grows.

## Subscriptions

`POST /api/v1/tenants/{tenant}/webhooks` (scope `webhooks:manage`) creates a subscription:

```json
{
  "url": "https://hooks.example.org/davhaven",
  "description": "Billing sync",
  "events": ["calendar.objects_changed", "rsvp.answered"],
  "include_details": false,
  "active": true
}
```

* The URL must be `https` and pass the egress policy ([`egress.md`](egress.md)) **now and on every delivery**: an
  address in a private range, loopback, link-local or metadata range is refused at registration, and a host name
  that starts to resolve to one later fails the delivery. Whatever the reason, the refusal reads the same ("The URL
  is not allowed as a webhook target."), so registering URLs is no way to probe the private DNS of the deployment.
* The response carries the signing secret `whsec_{base64}` **once**. Only a sealed copy is stored.
* A tenant may have `outbox.max_webhooks_per_tenant` (default 50) subscriptions: every event is expanded into one
  delivery per matching subscription, and the cap bounds that work. A further registration is refused with a conflict.
* `GET`, `PATCH` (JSON Merge Patch with `If-Match`), `DELETE`, `GET …/deliveries` and
  `POST …/deliveries/{delivery}/redeliver` complete the management API. A subscription that is switched on again
  starts with a failure count of zero.
* The audit log records `webhook.created`, `webhook.updated` (the names of the settings that changed, and the host
  of the URL when it changed: never its path or query), `webhook.deleted`, `webhook.secret_rotated`,
  `webhook.pinged`, `webhook.redelivered` and `webhook.disabled`. A ping and a redelivery make the server call a
  host of the tenant's choosing, which is why they leave a trace.

### Rotating the secret

`POST …/webhooks/{id}/rotate-secret` returns a new secret once. The previous secret keeps signing **alongside** the
new one until `webhooks.retry_window` has passed, so deliveries that are being retried are still accepted by a
receiver that has not switched yet. Receivers rotate in this order: add the new secret, wait for the first delivery
that verifies with it, drop the old one.

Only one previous secret is kept: **rotating twice** retires the original secret at once (the secret before the
first rotation is gone, the one before the second still signs). That is how a leaked secret is revoked quickly: rotate
twice.

## The request

```http
POST /davhaven HTTP/1.1
content-type: application/json
user-agent: Davhaven-Webhooks/0.1.0
webhook-id: 01900000-0000-7000-8000-000000000e01
webhook-timestamp: 1798761600
webhook-signature: v1,rkwp5YuvdrMkcu0ZhuMsXoTg44mHAr1Q0+FFgFpXsjY= v1,xZe4u4IBgdY9pubFkzRPneiShUtf/C3XAkjUNY3B+EA=

{"id":"01900000-0000-7000-8000-000000000e01","type":"calendar.created","version":1,"tenant":"…",
 "occurred_at":"2027-01-01T12:00:00Z","actor":{…},"data":{"calendar":"…","owner":"…","kind":"group"}}
```

* `webhook-id` is the id of the event. It is the same for every attempt, every redelivery and every subscription
  of the event: **deduplicate on it**. Delivery is at-least-once and unordered.
* `webhook-timestamp` is the time of the attempt in seconds since the epoch; every attempt is signed afresh.
* `webhook-signature` has one signature `v1,{base64}` per valid secret, separated by spaces: the HMAC-SHA256 of
  `{webhook-id}.{webhook-timestamp}.{raw body}` under the secret `whsec_…` (the base64 part, decoded, is the key).
  Verify the raw bytes of the body, not a re-serialization.

### Verifying

The reference implementation is `davhaven_hooks_webhook::signing::Verifier`; any Standard Webhooks library does
the same:

1. reject a timestamp that is not a number of seconds, more than five minutes old or more than five minutes in the
   future (replay protection);
2. compute the HMAC for every secret you know, compare it in constant time with every `v1` signature of the
   header, and ignore signatures of other versions;
3. answer a `2xx` status after the event is stored (or queued) on your side.

The signature of the specification's example (`whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw`, id
`msg_p5jXN8AQM9LWM0D4loKWxJek`, timestamp `1614265330`, body `{"test": 2432232314}`) is
`v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=`; the tests of the crate check it.

## Details

A subscription with `include_details: true` receives `data.details` for events that are about calendar objects
(`calendar.objects_changed`, `scheduling.reply_received`, `rsvp.answered`, `mail.delivery_failed`). The application
reads the details once, when it fans the event out, and writes them into the delivery; the webhook adapter loads no
calendar data:

```json
"details": { "objects": [ {
  "object": "018f…", "summary": "Planning", "restricted": false,
  "start": "2027-02-01T09:00:00Z", "end": "2027-02-01T10:30:00Z", "recurring": false
} ] }
```

`start` is the start of the first instance, `end` the end of the last one (`null` for an open series). Objects of the
classes `PRIVATE` and `CONFIDENTIAL` come with `"restricted": true` and **no summary**. Objects that no longer exist
are left out. Subscriptions without the flag never see any of this.

Details are given for objects of **managed and group calendars only**. A webhook subscription belongs to the tenant,
and a tenant credential never reaches the personal calendars of principals, so an event about an object of a
personal, user or mirror calendar is delivered with ids only, as if the subscription had not asked. Switching
`include_details` on therefore does not widen what the webhook can learn about people's own calendars. Because the
details are read when the event is fanned out, they show the object as it was then, not as it is when a retry or a
redelivery is sent.

## Delivery, retries and failure

| Answer of the receiver | Delivery | What happens next |
| --- | --- | --- |
| `2xx` | `delivered` | the failure counter of the subscription is reset |
| `410 Gone` | `dead` | the subscription is switched off at once (`disabled_reason: endpoint_gone`) |
| any other status (`3xx` included: redirects are not followed), timeout, connection error | `failed` | retried with exponential backoff |
| refused by the egress policy | `dead` | counts as a failure; no retry |
| the subscription is switched off | `dead` ("the subscription is disabled") | not sent, counts for nothing |

* Retries follow the outbox backoff (`outbox.backoff_base` = 30 s, doubling up to `outbox.backoff_max` = 1 h) and
  end when the outbox record is older than `webhooks.retry_window` (24 h, counted from the creation of the record,
  however often it has been attempted): the delivery is then `dead`. An operator sends deliveries again with
  `POST …/redeliver` (the event is sent afresh, with a new retry window). It works for `dead` and `delivered`
  deliveries of an active subscription; a delivery that is still being attempted answers a conflict, and so does one
  whose event has left the outbox (finished records are purged after `retention.outbox_done_days`, 7 days by default,
  dead ones after `retention.outbox_dead_days`). `POST …/outbox/{id}/retry` refuses webhook deliveries for the same
  reason: it would give one attempt to a record that is older than its window.
* **What counts against a subscription** is a *delivery that ended dead because the receiver did not accept it*:
  its retry window ran out, or the egress policy refused its URL. One event counts once, however many attempts it
  took, and an attempt that fails but is retried counts for nothing. A receiver that is down for an hour therefore
  does not lose its subscription because twenty events were waiting for it, and a single event cannot use up the
  limit alone. A delivered event resets the counter, and so does switching the subscription on again.
* A subscription for which `webhooks.max_consecutive_failures` deliveries (20) ended dead in a row is **switched
  off**: `active` becomes `false`, `disabled_reason` is `max_consecutive_failures`, the audit log gets
  `webhook.disabled` and the event `webhook.disabled` is published (to the other subscriptions and the sinks). A
  `410 Gone` switches it off at once (`endpoint_gone`). Deliveries of a switched-off subscription that are still in
  the outbox end as `dead` without being sent and without counting; the outbox record is done, because nothing
  failed that an operator has to look at. Nothing is sent until the subscription is activated again; redeliver
  what was missed.
* The answer of the receiver is read for its status only: a body larger than `max_response_bytes` is cut at that size
  and the delivery is judged by its status ([`egress.md`](egress.md)).
* `GET …/deliveries` shows status, attempts, the last HTTP status and a short error text for every delivery. The
  text never contains the URL, the payload or a secret.

Deleting a subscription deletes its deliveries; records still in the outbox end without sending.

## Configuration

```toml
[plugins]
outbox_handlers = ["webhook"]     # "noop" completes webhook deliveries without sending anything
event_sinks = ["log"]             # one structured log line per event: ids and type, never the payload

[webhooks]
max_consecutive_failures = 20
retry_window = "24h"
```

The outbox settings (`[outbox]`: batch size, lease, attempts, backoff) apply to webhook deliveries like to every
other record kind; the webhook handler bounds its retries by time (`retry_window`) and ignores `outbox.max_attempts`.
`outbox.concurrency` (default 8) is the number of records a dispatcher handles at the same time, and
`outbox.poll_interval` (default 2 s) how often it looks for due ones.

## Operations

* Metrics: `davhaven_outbox_pending`, `davhaven_outbox_oldest_pending_age_seconds`, `davhaven_outbox_dead_total`,
  `davhaven_outbox_handled_total{kind,outcome}`, `davhaven_outbox_handle_duration_seconds{kind}`, and the port
  metrics of the `outbox_handler` and `http_client` ports.
* Logs carry ids only: outbox id, tenant, webhook and event ids. Secrets, URLs and bodies are never logged.
* `GET /api/v1/tenants/{tenant}/outbox?status=dead` lists dead records of every kind; `POST …/outbox/{id}/retry`
  makes one due again (not for webhook deliveries, see above) and is audited (`outbox.retried`).
* `davhaven_outbox_settle_lost_total` counts outcomes that could not be stored because another dispatcher had taken
  the record over after its lease ran out; it should stay at zero in normal operation.
* Secrets are sealed with the secret sealer, bound to the tenant, the subscription row and the purpose
  (`SealAad::webhook_secret`). Losing the sealing key makes the stored secrets unreadable: deliveries then end as
  `dead` with the text "the signing secret cannot be opened", and rotating the secret repairs the subscription.
