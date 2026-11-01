# ADR-0007: RSVP link tokens are derived from the key ring

- Status: accepted
- Date: 2026-10-25
- Scope: PLAN 2.6 (credentials), 2.13 (RSVP), 2.14 (mail); R6 (credentials are random and shown once)

## Context

Every invitation mail carries a link to the RSVP page, and the link contains a token in the format of every other
credential (`dvh_rsvp_{prefix}_{secret}`, PLAN 2.6). R6 says a credential is drawn at random, shown
once and stored only as a keyed hash.

A mail is not shown once. The outbox keeps references and no rendered content, because rendered content holds
addresses and, here, a bearer credential; the mail is composed again on every attempt of the record, and an update mail
for the same invitation has to carry the link of the invitation (an attendee who answers from the first mail and from
the update must reach the same row). A random token that is shown once cannot be put into a mail that is composed again
without either storing it (in the outbox payload, or sealed in the row), or minting a new one on every attempt.

## Decision

The prefix and the secret of an RSVP token are **derived**, not drawn: both are a keyed function of the tenant and the
token id (HMAC with the key ring's `rsvp` purpose over `davhaven/rsvp-token/v1/{prefix|secret}/{tenant}/{id}`). The
prefix is 12 characters of lowercase base32 of the first 8 bytes of the SHA-256 of the prefix MAC, the secret is the 43
characters of unpadded base64url of the SHA-256 of the secret MAC. The token row stores what every credential row
stores, the keyed hash of the **secret component** (`CredentialHasher::hash(RsvpToken, secret)`), found by prefix; the
authenticator of the web surface hashes the secret component of the presented token the same way, so a link minted by
the mail composer authenticates there without a special case. A retry recomputes the link from the row's id.

Rules around it:

* The newest live token of an attendee for an object is **reused** while it still matches its derivation (the key ring
  has not been rotated since) and outlives the event. Otherwise a **new** token is minted and the earlier ones are left
  alone: links in mails that were sent before keep working until their own expiry, whatever a key rotation or a
  reschedule does. A prefix collision (a chance of about 2^-60) is retried with a fresh id, three times.
* A link expires seven days after the last instance of the event ended and at most a year after it was minted. The bound
  does not move with the clock, so an event without an end keeps one token for the whole year.
* Removing the attendee, cancelling and deleting the event revoke the tokens.

## Consequences

- A retried or repeated mail carries the same link without any stored plaintext, and the outbox stays free of
  credentials.
- This **deviates from R6** ("random, shown once"). The `rsvp` key of the ring is as sensitive as the pepper: whoever has
  the key and the ids of the token rows (the ids are ordinary UUIDs in the database and in backups) can recompute every
  link that was ever mailed. The key therefore lives where the pepper lives, is covered by the same rotation procedure and
  is never logged. The hash in the row still protects a database leak on its own: without the key a row reveals nothing
  that opens a link.
- Rotating the key ring does not kill outstanding links (their rows keep the hash that was valid), but the next
  invitation or update of an attendee mints a token under the new key.
- The authenticator of the web surface must hash the secret component of a presented token, not the whole string, and must treat a token that is expired or
  revoked like an unknown one (one page, one status).
- R6 and PLAN 2.6 carry a footnote that names this exception.

## Alternatives considered

- **A random token, sealed in the row and unsealed when a mail is composed**: the plaintext would be recoverable from
  every backup that has the sealing key, which is the same exposure as the derivation with more moving parts (a sealing
  key, an AAD, a column) and a token that exists in the clear in memory for longer.
- **A random token carried in the outbox payload**: puts a bearer credential into a table that operators read and retain
  for weeks (`outbox:manage`, `retention.outbox_*_days`).
- **A new random token on every attempt**: an invitation mailed twice (a retry after a lost acknowledgement) would
  carry two links, and every attempt would leave a live row behind. Revoking the earlier ones on each attempt would kill
  the link in the mail the attendee has already received.
- **A signed, stateless link without a row**: cannot be revoked and cannot record its use.
