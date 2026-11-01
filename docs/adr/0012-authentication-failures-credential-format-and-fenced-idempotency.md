# ADR-0012: Authentication failures, the credential format and fenced idempotency

- Status: accepted
- Date: 2026-10-26
- Scope: PLAN 2.6 (authentication), 2.10 (idempotency); R4, R6, R12, R14; crates `auth-local`, `crypto-local`,
  `ratelimit-memory`, `api`, additions to `domain`, `ports`, `app` and `http`

## Context

Review of the HTTP edge found that three promises of the plan were met by the adapters instead of by the contracts they
implement, so that nothing but the code of those adapters kept them:

1. **Failure backoff** (R6, PLAN 2.6: failed authentications back off exponentially per (login, address) and per address,
   no lockout) existed as an option of the in-memory limiter. The `RateLimiter` port did not say it, no other limiter
   was held to it, nothing read the settings of `[security.auth]`, and the schedule stopped growing at the length of its
   window, so the configured maximum was never reached.
2. **The credential format** (markers, lengths, alphabets, the split of a credential into prefix and secret) was written
   out in four places: the authenticator, the RSVP derivation of the application, the fixtures and the contract suite.
3. **Fenced idempotency** (ADR-0006: a claim has a lease, and only the holder settles it): `IdempotencyService::complete`
   identified an attempt by its key alone, so the layer could not use the fenced operations of the store, and a handler
   that outlived its lease could settle or release the key of the attempt that replaced it.

It also found a conflict with R4 (a valid credential of one tenant that names another tenant in the path was refused as an
unknown credential, 401, and counted as a failed login, where the plan and the oracle say 404), a verified-credential
cache that saved no database work and depended on a counter nobody owned for revocation, and several smaller
contradictions between documentation and code.

## Decision

All changes to the contract crates are additive. What each implementation has to do is listed under Consequences.

**Failure backoff is a property of the `RateLimiter` port.** `RateKey::AUTH_LOGIN_IP` and `RateKey::AUTH_IP` name the two
failure buckets (the one spelling), `FailureBackoff` is the policy (`free`, `window`, `base`, `max`, with defaults that
are on without any configuration) and `davhaven_ports::bucket_address` is the address a bucket is keyed by (an IPv6 address
stands for its /64, an IPv4-mapped one for the IPv4 address it maps). A failure bucket works as the module documentation of
`rate_limit` says: `check(key, 0)` asks without consuming, `check(key, 1)` records a failure; the first `free` failures are
free, every further one blocks the key for `base`, `2 × base`, … up to `max`; a blocked key is denied with the time left and
failures that arrive meanwhile do not lengthen the block; failures are forgotten after `window` without a new one, counted
from the end of the last block (so a block as long as the window does not wipe out its own cause, and `max` is reachable).
`davhaven_port_tests::rate_limit::run_backoff` is the contract suite; the `noop` limiter fails it by design. The policy
reaches the limiter through `PluginContext::failure_backoff` (`with_failure_backoff`): `[security.auth]` is the one place a
deployment writes the four numbers (`AuthConfig::failure_backoff()`), the server puts them into the context before it builds
the limiter, and an entry for either bucket under the limiter's own `buckets` overrides them. The memory limiter keeps its
table bounded without letting a flood of fresh keys lift the block of a key that is being punished (blocked keys are evicted
last, and making room frees a tenth at once).

**Authentication does not decide visibility (R4).** The authenticator judges the credential: shape, surface, the secret, the
state of the row, and, for an app password, the login (`name@login_domain`, or a bare name that means "this name in the
tenant of the path"). The tenant named by the path is not a condition: a valid credential is authenticated, and the
application answers 404 for the path of another tenant, without counting a failed authentication. `AuthService::authenticate`
documents this, `FakeAuth` and the tests of the edge and of DAV follow it, and the contract suite
(`tokens_ignore_the_tenant_of_the_path`) holds every authenticator to it. A client with a valid token can therefore no longer
earn itself a 429 by asking for another tenant.

**One credential format, owned by the domain.** `davhaven_domain::credential_format` (`AppPasswordText`, `TokenText`) defines
the markers, the lengths, the alphabets, parsing, generation and the split into prefix and secret. The authenticator, the RSVP
derivation of the application (`TokenText::from_random`, `from_parts`), the fixtures and the contract suite use it, and a test
in each consumer fails when the format drifts. The credential service, which mints credentials, uses the same module.

**The credential lookup answers everything at once.** `LookedUpCredential` gained `owner` (`CredentialOwner`: the slug and
login domain of the tenant and the name of the principal), so the authenticator needs one system query per request, whether
the credential is new to the process or was verified a minute ago. The cache saves the hash verification only: an entry is
valid for the stored hash it was verified against and the credential generation it saw; the row, the statuses and the
generation are read on every use. A revocation of one credential therefore applies at once, whoever does or does not bump
`credential_generation`, and a credential whose tenant or principal cannot be found is refused instead of being assumed
active. The cache and the debounce of `last_used_at` are bounded and cut back by a tenth at once.

**Idempotency has reservations.** `IdempotencyService` gained `reserve` and `settle` next to `begin` and `complete`, with
`Reservation` (the proof of a claim: the end of its lease), `Reserved`, `Settlement` and `ResponseNote` (the status and
`Location` of an answer that was not kept, free of secrets). The provided methods call `begin` and `complete`, so a service
that implements only the first pair keeps compiling and works unfenced. The API layer calls `reserve` and `settle`, asks for
a lease of the request timeout plus a margin of 30 seconds (`Edge::request_timeout`; nothing else sets the lease, and there is no separate lease setting), and bounds the
handler it detaches by the request timeout, so the work cannot outlive its claim. The detached task holds the concurrency permit of the edge (`HeldPermit`), so
detached work stays counted against the limit after the edge has answered. A service that backs `reserve` and `settle` with
`claim_leased`, `complete_leased` and `release_leased` gets the fence of ADR-0006: a settlement that presents a lease that
was taken over is ignored. The layer stores only responses that their handler marked replayable (`Reply::replayable`), never
one marked `no-store`, and records "used, not replayable" for a success it cannot store; the client still gets the original
response, and a repeat gets 409 `secret-not-replayable` with the status and `Location` of the first answer.

**`feature-not-enabled` is a precondition.** `Precondition::FeatureNotEnabled` and `AppError::feature_not_enabled()`
(ADR-0011).

**Smaller additions.** `EdgeProblem::with_location` (a problem that carries a `Location`), and the re-exports `testkit` needs
for the integration tests of the edge (`davhaven-port-tests`, `davhaven-auth-local`, `davhaven-crypto-local`,
`davhaven-ratelimit-memory`, `davhaven-http`).

## Consequences

- **`AuthServiceImpl`**: answer `not_found()` when the credential is valid and the path names another tenant, without
  recording a failure; take the failure buckets, their keys and the address from `RateKey` and `bucket_address`; implement
  `IdempotencyService::reserve` and `settle` with the fenced store operations and the lease it is given (a service that
  implements only the unfenced `begin` and `complete` keeps working, unfenced). Builders of `LookedUpCredential` (the store adapters only) fill `owner`.
- **The server** (wiring): pass `AuthConfig::failure_backoff()` into `PluginContext::with_failure_backoff` before the rate limiter
  is built, and construct the limiter from the context; refuse the `noop` limiter in production (the port documents why).
- The `Authenticator` contract is two suites, because two things are promised: what every authenticator promises (`run`,
  `noop` included) and what an authenticator of the credential store promises (`run_store_backed`). Both run from
  `crates/it/tests/auth_local.rs`.
- Credentials are hashed under the pepper of the key ring and carry its id; retiring a key makes the credentials hashed
  under it unverifiable. A credential that is used is hashed again under the active key
  (`CredentialRepo::rehash`, ADR-0006, ADR-0015), so a key can be retired when no live credential names it
  (`docs/operations/keys.md`). An app password has 180 bits, of which the 40 of its prefix are stored and listed in clear:
  its secret has 140 bits, above the 128 that R6 asks for (ADR-0015).

## Known limits

- The `Authenticator` store-backed suite runs on the memory store. The database half of the lookup (`begin_system`,
  `find_by_prefix` with the owner and the statuses) is covered by the credential cases of the store contract suite on
  PostgreSQL as the runtime role; running the authenticator over PostgreSQL needs a test rig in `crates/it`, which the
  harness does not offer yet and the architecture check does not allow an adapter's tests to build.

## Alternatives considered

- **Keep the backoff an option of the memory limiter**: it stays unspecified for every other limiter, and the next
  implementation would not have to provide it. As a port property it has a suite and a place in the plugin context.
- **Make the authenticator reject the credential of another tenant** (the first implementation): it answers 401 where the
  plan says 404, and it feeds the backoff with requests that are not failures.
- **Bump `credential_generation` on every revocation and cache by it**: revocation then depends on every writer of the store
  remembering to bump; reading the row on every use costs one query that a cache miss costs too.
- **Replace `complete` with `settle` in the service trait**: it would break every implementation of `begin` and `complete`;
  the provided methods let both pairs coexist.
- **Store every successful response unless the handler says otherwise**: a handler that forgets `no_store` writes a secret
  into the table for 24 hours. Storing only what is marked is the fail-closed form.
