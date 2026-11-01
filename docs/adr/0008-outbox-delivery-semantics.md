# ADR-0008: Outbox delivery semantics

- Status: accepted
- Date: 2026-10-25
- Scope: PLAN 2.11 (events), 2.14 (mail), 2.17 (operations); R12; ADR-0006 (claim-fenced settlement)

## Context

The outbox is at-least-once: a record is claimed with a lease, handled, and settled. Three things turned out to need an
explicit decision while the dispatcher, the mail handler and the webhook handler were written, and review found the
first two wrong in the first version:

1. what happens when a handler runs longer than its lease, or the lease runs out while the outcome is being stored;
2. what a handler does when it did not try at all (the mail rate limit, an open circuit breaker): an attempt must not be
   consumed, or a long hold dead-letters mail that was never sent;
3. which side of the dead-letter announcement ("this mail will never arrive") may be repeated.

## Decision

**Claims and settlement.** The dispatcher settles every record with the claim it was handed out under
(`complete_claimed`, `fail_claimed`, `defer_claimed`, ADR-0006) and releases its leases on shutdown with
`release_claimed`. `LeaseLost` and `NotFound` mean that someone else decided or the record is gone: the outcome is dropped
and counted (`davhaven_outbox_settle_lost_total`), and it never keeps the rest of the batch from being stored.

**One deadline per batch.** The handlers of a batch run concurrently (at most `outbox.concurrency`, default 8) under one
deadline, 80 % of `outbox.lease` from the moment of the claim, so a claim never expires under a handler that is still
working. A record whose turn comes with less than a quarter of the lease left is **deferred** and not started (a handler
cut off in the middle of its work would repeat it, a mail half sent). A handler that panics or hangs is an ordinary
retryable failure. The dispatcher looks for work every `outbox.poll_interval` (default 2 s).

**Deferral.** `HandlerError::Defer { after, reason }` and `OutboxQueue::defer_claimed` put a claimed record back, due
after the given time, with `attempts` given back and `last_error` set to a static reason. A hold does not use up
`outbox.max_attempts`. The mail handler defers for the rate limit (the process-local bucket, then the `mail` bucket of
the `RateLimiter` port, which a deployment can share between instances) and for an open circuit breaker; a hold that has
lasted a week ends and fails like a relay error, so mail does not wait for ever. The default of `defer_claimed` counts the
claim like a failure (safe, but a long hold could dead-letter), so stores override it; the store contract suite checks it.

**Attempts.** `OutboxHandler::limits_attempts` says whether the dispatcher dead-letters a record that was claimed
`outbox.max_attempts` times. The webhook handler answers `false` and bounds its retries by time instead (a retry window of
24 hours from the creation of the record), which fits a receiver that is down for an afternoon.

**Announcing a dead mail.** A dead `imip` record is announced first (`mail.delivery_failed` for the tenant), and only when
that worked is it settled dead; otherwise it is rescheduled as a transient failure, so a tenant is never left without the
event for a record nobody will look at again. The announcement's outbox id is **derived from the id of the dead record**,
so a pass that crashed after announcing and handled the record again enqueues nothing a second time.

**Fan-out.** An event becomes one delivery per matching subscription, with a delivery id derived from the event and the
subscription. A repeated fan-out (a crash before the event record was settled) finds the delivery and enqueues nothing.
The store's `create_delivery` returns the existing row for a repeated pair (ADR-0006).

**Tests.** The unit tests of `app` use an inert fixture and need no database. What needs transactions is tested in
`crates/it/tests/outbox` against the real in-memory store (`davhaven-store-memory` through `testkit`), including the
settlement races (a lease that ran out, a record that was purged), the outage cases (a store that fails to settle, to
begin, or for one tenant) and the cross-tenant checks. There is no database double in `davhaven-ports`: a double that
reimplements the store hides exactly the behavior these tests are about.

## Consequences

- Contract changes (additive): `HandlerError::Defer` (and `HandlerError` is `#[non_exhaustive]`), `OutboxQueue::defer_claimed`
  with a default, `OutboxHandler::limits_attempts`, `OutboxConfig::{concurrency, poll_interval, max_webhooks_per_tenant}`.
  Both stores override `defer_claimed`.
- The dispatcher never settles with a bare key: the unfenced `complete`/`fail`/`release_leases` stay in the port for
  operators and tests.
- A mail that is held for a long time shows as `pending` with its `last_error` set to the reason, and not as a retry
  count that climbs; the metrics `davhaven_mail_held_total{reason}` and the gauge `davhaven_mail_circuit_open` say why.
- A deployment with several instances gets the shared mail limit through the `RateLimiter` port; the breaker is local to
  an instance, which is what a connection problem of that instance looks like.
- `plugin.smtp.total_timeout` has to stay below 60 % of `outbox.lease`; `davhaven config check` refuses a combination that
  does not (`docs/mail.md`).

## Alternatives considered

- **Settling with bare keys and ignoring `PreconditionFailed`**: a dispatcher whose lease ran out could settle a record
  that another dispatcher holds, sending a message twice and recording the wrong outcome.
- **Rate limit by failing the attempt**: simple, and wrong: twelve minutes of limit would dead-letter an invitation.
- **A separate "held" status**: a schema change for every adapter for something `pending` with a due time and a reason
  already expresses.
