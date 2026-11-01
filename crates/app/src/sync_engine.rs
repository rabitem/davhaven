//! Pull synchronisation of external provider calendars into mirror calendars (PLAN 1.1, 4.2).
//!
//! A connected account (`crate::oauth`) has a **mirror calendar**: a calendar of kind `mirror`, owned by the principal who
//! connected the account, read-only for every principal surface (DAV, API, MCP and the sharing rules all treat it as
//! read-only) and written by nobody but this engine. The engine pulls the provider's calendar into it. 1.0 is **pull only**:
//! nothing is sent to the provider except OAuth calls and read requests, and changes a person makes to a mirror in a client
//! are refused by the server before they could be lost.
//!
//! # A pass
//!
//! [`ProviderSyncWorker`] is the worker the server supervises. It exists only when at least one provider is switched on
//! (`workers::build`), so a deployment without providers runs nothing. Every `[providers.sync] poll_interval` a pass lists the
//! accounts of the providers that are on, picks the ones that are due (oldest first, at most `batch_size`) and pulls them,
//! `concurrency` at a time, each under `timeout`; it starts no account after [`PASS_BUDGET`], so that a pass ends before `/readyz`
//! calls the worker stalled ([`STALL_LIMIT`]: the budget, the longest `timeout` that the configuration allows and
//! [`STALL_MARGIN`] fit into it). The accounts of a **suspended** principal are not listed: they stay as they are and are due
//! the moment the principal is active again, and listed they would be the oldest accounts for as long as they are suspended and
//! take the places of every other account in every pass. A pass says that more work is ready (so that the supervisor starts the
//! next pass at once instead of sleeping) only when it left accounts behind **and** got somewhere (pulled an account, or stored a
//! failure): a pass of accounts that could not even be claimed, because the store fails, is followed by the sleep.
//!
//! Finding the due accounts reads the accounts of every active tenant, one transaction per tenant, a page of 200 at a time. That
//! is a few small queries a minute for a deployment of a few tenants with hundreds of accounts, and it grows with the **number of
//! tenants**, accounts or not: a deployment with very many tenants needs one query across tenants for the due accounts (the due
//! time as a column of its own, a schema change for the storage owner; on the backlog in `docs/ROADMAP.md`).
//!
//! # An account
//!
//! [`SyncEngine::sync_account`] pulls one account in four steps, and holds **no transaction across a call to the provider**:
//!
//! 1. **Claim.** In one transaction the account is checked (not disabled, its provider on, its principal active, its time
//!    come, and whether its mirror calendar is there) and a **lease** is written into its `sync_state` with an optimistic update.
//!    A second worker, on this instance or on another, loses that race (`PreconditionFailed`) or finds the lease unexpired, and
//!    leaves the account alone: pulls of one account never overlap, and the engine needs nothing the store does not have (the
//!    outbox does the same with its claims). A pull that dies keeps its account for `timeout` and a minute, then the account is
//!    due again.
//! 2. **Pull.** An account whose mirror is gone is not pulled (`mirror_missing`: the provider is not asked and the tokens of the
//!    person are not used). Otherwise the sealed tokens are opened, an access token that is about to expire is renewed (and
//!    stored at once, because a provider that rotates refresh tokens has invalidated the old one), and `changes_since` is asked
//!    with the cursor of the last pull. An access token the provider refuses is renewed once and the call repeated; a cursor it
//!    no longer accepts starts a full pull; a calendar that is too large (`Unsupported`) is neither. What came back is written
//!    into the mirror through the batch use case of the object service (one transaction per chunk of up to
//!    `limits.api.max_batch_items` events, so the calendar's sync token, change log and `calendar.objects_changed` events are
//!    those of any other write).
//! 3. **Settle.** The result is stored: after a success the cursor, the time of the pull and the next due time; after a failure
//!    the counter of failures, a wait that doubles from a third of the interval up to `backoff_max`, the status and `last_error`.
//!    The cursor moves **only** after the changes were applied. The lease is the **fencing token** of the pull: tokens that were
//!    renewed and the result are stored only while the account still holds the lease this pull wrote. A reconnection clears it
//!    (the person connected the account again, with a new grant), and the claim of another worker replaces it; either says that
//!    the pull works from a state that is not the account's any more, and its result is dropped instead of undoing the
//!    reconnection (a pull with the old, revoked grant would otherwise switch the new connection off).
//! 4. **Tell.** A pull that fails for the first time (or that switches the account off) emits `external_account.sync_failed`
//!    with the reason, once, so that a person is told when their calendar stops updating and is not told again every pull.
//!
//! # Failures
//!
//! | Reason | Cause | Status | Next |
//! | --- | --- | --- | --- |
//! | `auth_revoked` | the provider says that the refresh token is no longer valid (`invalid_grant`), or there is none | `disabled` | none: connect the account again |
//! | `provider_rejected` | the provider refuses a fresh token or the calendar (`403`, `404`) | `error` | after the backoff |
//! | `provider_unavailable` | no connection, `5xx`, throttling, a timeout of the pull | `error` | after the backoff |
//! | `too_large` | the calendar has more events in the pulled window than the adapter imports | `error` | after the backoff; narrow `history_days` and `future_days` |
//! | `mirror_missing` | the mirror calendar was deleted (the API refuses to; a purge or an operator did) | `error` | after the backoff; connect the account again to get a new mirror |
//! | `internal` | the sealed tokens cannot be opened, the store failed, **the provider refuses the OAuth client of the deployment** (`invalid_client`: a wrong, rotated or expired client secret) | `error` | after the backoff; the accounts recover by themselves once the client is fixed |
//!
//! Only a refused **refresh token** switches an account off; a refused **client** is the operator's to fix and switches nothing
//! off (every account would fail alike, and every person would have to connect again for the fault of a secret). A success sets
//! the status back to `active`. Events that cannot be stored (an event the calendar rejects, two events that share one UID) are
//! left out, counted and logged, and do not fail the pull.
//!
//! A seventh text, `principal_deleted`, is no failure of a pull: the claim of an account whose principal was deleted switches it
//! off (`disabled`, `last_error` starting with `principal_deleted`), asks the provider to forget the access and emits **no**
//! `external_account.sync_failed` (the deletion of the principal is audited, and that is what tells).
//!
//! # What is never logged
//!
//! Ids, counts and reasons only: no address of the account, no token, no event text, no text of the provider's answers.

mod account;
mod apply;
mod state;
mod worker;

pub use account::{SyncEngine, SyncOutcome};
pub use apply::Applied;
pub(crate) use state::SyncState;
pub use worker::{PASS_BUDGET, ProviderSyncWorker, STALL_LIMIT, STALL_MARGIN, SYNC_TOTAL};
