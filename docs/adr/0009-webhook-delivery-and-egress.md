# ADR-0009: Webhook delivery, details and the egress boundary

- Status: accepted
- Date: 2026-10-25
- Scope: PLAN 2.6 (tenant credentials), 2.11 (domain events and webhooks); R3, R6; crates `hooks-webhook`, `http-egress`, `app`

## Context

Webhooks are the one place where a tenant administrator makes the server call an address of their choosing, and the one
place where a tenant-wide credential reads data that belongs to people. The first version settled four
questions by accident, and review asked for decisions:

1. what counts as a failure of a subscription, so that a flaky receiver is switched off and a slow one is not;
2. who reads the calendar data behind `include_details`, and whose calendars it may come from;
3. what the egress adapter does with an answer larger than its cap, and what `validate_url` means for an adapter that does
   not implement it;
4. what the audit log records of an operation that causes a request to a host of the tenant's choosing.

## Decision

**Failures are dead deliveries.** The counter of a subscription counts deliveries that **ended dead because the receiver
did not accept them**: the retry window (24 hours from the creation of the outbox record) ran out, or the egress policy now
refuses the URL. Each event counts once however many attempts it took, a retried failure counts for nothing, a delivery
resets the counter, `410 Gone` disables at once (`endpoint_gone`), and `webhooks.max_consecutive_failures` (20) dead
deliveries in a row disable the subscription (`max_consecutive_failures`, audit `webhook.disabled`, event
`webhook.disabled`). Deliveries of a disabled subscription are **skipped**: the row is `dead` with the text "the
subscription is disabled", the outbox record is done, nothing counts. The store owns the counter (`record_success`,
`record_failure`, ADR-0006): a patch from a stale copy cannot erase it.

**Details are the application's, and only for tenant-owned calendars.** The application reads the details of an event when
it fans the event out and writes them into the delivery (`WebhookDelivery::details`, an optional field). The webhook adapter
reads no calendar data and parses no iCalendar. Details are given for objects of **managed and group** calendars only: a
webhook subscription belongs to the tenant, a tenant credential never reaches the personal, user or mirror calendars of
principals (PLAN 2.6), and `include_details` must not widen that. Objects of the classes `PRIVATE` and `CONFIDENTIAL` come
without a summary (`restricted`). A summary that cannot be read is left out; the event goes out without details rather than
not at all. The details show the object as it was when the event was fanned out.

**The egress adapter cuts, and fails closed.** `HttpClient::validate_url` defaults to `Unsupported`, which the application
treats as an error, so no URL is accepted unchecked by a client that cannot check it. The answer of a webhook receiver is
read for its status only: the body is **cut** at the cap of its purpose (`HttpPurpose::Webhook`) and the delivery is
judged by the status; for OAuth and provider API calls an oversized answer fails the request. The caps and timeouts are per
purpose. A host name is resolved once per connection and the connection goes to that answer; lookups run in a bounded
number. The refusal a tenant administrator sees at registration is one sentence for every reason, so registration cannot be
used to probe the private DNS of the deployment. `docs/egress.md` has the rest.

**Audit.** Creating, changing (the names of the changed settings, and the host when the URL changed, never path or query),
deleting and rotating a subscription, **a test event** (`webhook.pinged`), **a repeated delivery** (`webhook.redelivered`)
and an operator's retry of an outbox record (`outbox.retried`) are audited in the transaction of the operation. A tenant
may have `outbox.max_webhooks_per_tenant` (50) subscriptions, which bounds the work of expanding one event.

**The test event.** `webhook.ping` goes to the pinged subscription only, whatever its filter says, and cannot be
subscribed to. A redelivery starts a new outbox record, with a retry window of its own, for the stored event; it refuses a
delivery that is still being attempted and one whose event has been purged from the outbox, and `outbox retry` refuses
webhook deliveries (one attempt for a record past its window would be pointless).

## Consequences

- Contract changes (additive): `EventType::WebhookPing` and the reasons of `WebhookPayload`, `WebhookDelivery::details`,
  `AuditEvent::{WebhookPinged, WebhookRedelivered, OutboxRetried}` and the fields `fields`/`host` of `WebhookAudit`,
  `SealAad::webhook_secret`, `HttpClient::validate_url` (default `Unsupported`) and `HttpPurpose`, `OutboxConfig::max_webhooks_per_tenant`.
  The schema `docs/contracts/events.schema.json` is regenerated.
- A receiver that is down for a day loses its subscription once twenty events have outlived the retry window, not after
  the first twenty failed attempts; an operator who wants to resend what was missed uses `redeliver`.
- A tenant that wants the summary of a personal calendar in a webhook cannot have it. That is intended: the integration
  that needs it uses the API with a credential of the principal.
- The permission matrix (`docs/permission-matrix.md`) has no rows for the webhook operations; the nine operations are
  covered by a test that runs every operation for every actor kind and every tenant (`crates/it`).

## Alternatives considered

- **Counting every failed attempt**: one event retried with backoff reaches twenty attempts in an afternoon; a receiver
  that is down for an hour is switched off by the events waiting for it.
- **Reading the details in the webhook handler**: every handler that loads calendar data is a place where the
  managed-or-group rule can be forgotten, and the adapter would have to parse iCalendar.
- **Failing a delivery whose answer is too large**: a receiver that echoes the request or answers with a page is
  not failing; only the status decides.
