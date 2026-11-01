//! Test doubles shared by the integration tests of the API and the unit tests of its idempotency layer (the unit
//! tests include this file with `#[path]`).
//!
//! The fake application of `davhaven-app-fake` answers `unsupported` for idempotency; [`MemoryIdempotency`] is a
//! small in-memory implementation of the service with the semantics of PLAN 2.10 and of ADR-0006: a claim has a
//! lease, an in-flight key is taken over once its lease has run out, and a settlement that presents the reservation
//! of a claim that was taken over is ignored (the fence of the real store). Time is the clock of tokio, so tests
//! that pause it can let a lease run out.
//!
//! It stands in for the service, which scopes keys by (tenant, token, key); what the layer is responsible for is
//! handing the service the authenticated context, and the double records the contexts it receives so that tests
//! can check that.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use chrono::DateTime;
use davhaven_app::error::{AppError, AppResult};
use davhaven_app::services::{
    IdempotencyKey, IdempotencyOutcome, IdempotencyService, IdempotencyState, Reservation, Reserved, ResponseNote,
    Settlement, StoredResponse,
};
use davhaven_domain::{RequestContext, TenantId, TokenId};
use tokio::sync::Mutex;
use tokio::time::Instant;

/// How long `begin` (the unfenced pair) holds a key, as the store's default does.
const DEFAULT_LEASE: Duration = Duration::from_secs(600);

/// What the store remembers of a key.
#[derive(Debug, Clone)]
enum Record {
    InFlight {
        fingerprint: String,
        claim: u64,
        until: Instant,
    },
    Done {
        fingerprint: String,
        response: StoredResponse,
    },
    Used {
        fingerprint: String,
        note: Option<ResponseNote>,
    },
}

type Scope = (TenantId, Option<TokenId>, String);

/// The result of claiming a key.
enum Claimed {
    Fresh(u64),
    Existing(Record),
}

/// An in-memory [`IdempotencyService`], scoped by tenant, token and key.
#[derive(Debug, Default)]
pub(crate) struct MemoryIdempotency {
    records: Mutex<HashMap<Scope, Record>>,
    next_claim: AtomicU64,
    /// The contexts the service was called with, in order.
    seen: Mutex<Vec<RequestContext>>,
    /// The leases `reserve` was asked for.
    pub(crate) leases: Mutex<Vec<Duration>>,
    /// How many times `begin` was called.
    pub(crate) begins: AtomicUsize,
    /// How many times `complete` was called.
    pub(crate) completes: AtomicUsize,
    /// How many times `reserve` was called.
    pub(crate) reserves: AtomicUsize,
    /// How many times `settle` was called.
    pub(crate) settles: AtomicUsize,
    /// How many settlements were ignored because their claim had been taken over.
    pub(crate) stale: AtomicUsize,
    /// Makes `begin` and `reserve` fail with an unavailable service.
    pub(crate) fail_begin: AtomicBool,
    /// Makes `complete` and `settle` fail with an unavailable service.
    pub(crate) fail_complete: AtomicBool,
}

fn scope(ctx: &RequestContext, key: &IdempotencyKey) -> Scope {
    (ctx.tenant, ctx.actor.token(), key.key.clone())
}

fn state_of(existing: &Record, fingerprint: &str) -> IdempotencyState {
    let (stored_fingerprint, state) = match existing {
        Record::InFlight { fingerprint, .. } => (fingerprint, IdempotencyState::InProgress),
        Record::Done { fingerprint, response } => (fingerprint, IdempotencyState::Replay(response.clone())),
        Record::Used { fingerprint, .. } => (fingerprint, IdempotencyState::NotReplayable),
    };
    if stored_fingerprint == fingerprint {
        state
    } else {
        IdempotencyState::KeyReuse
    }
}

impl MemoryIdempotency {
    /// The number of keys the store remembers.
    pub(crate) async fn len(&self) -> usize {
        self.records.lock().await.len()
    }

    /// Whether the store remembers no key.
    pub(crate) async fn is_empty(&self) -> bool {
        self.records.lock().await.is_empty()
    }

    /// The contexts the service was called with.
    pub(crate) async fn contexts(&self) -> Vec<RequestContext> {
        self.seen.lock().await.clone()
    }

    /// Whether the key `key` of the default scope (tenant 1, token 1) holds a stored response.
    pub(crate) async fn has_stored_response(&self, key: &str) -> bool {
        self.records
            .lock()
            .await
            .iter()
            .any(|((_, _, candidate), record)| candidate == key && matches!(record, Record::Done { .. }))
    }

    /// Claims the key for `lease`: fresh, or what is there (an in-flight key whose lease has run out is taken over).
    async fn claim(&self, ctx: &RequestContext, key: &IdempotencyKey, fingerprint: &str, lease: Duration) -> Claimed {
        self.seen.lock().await.push(ctx.clone());
        let mut records = self.records.lock().await;
        let scope = scope(ctx, key);
        if let Some(existing) = records.get(&scope).cloned() {
            let expired = matches!(&existing, Record::InFlight { until, .. } if *until <= Instant::now());
            if !expired {
                return Claimed::Existing(existing);
            }
        }
        let claim = self.next_claim.fetch_add(1, Ordering::SeqCst) + 1;
        records.insert(
            scope,
            Record::InFlight {
                fingerprint: fingerprint.to_owned(),
                claim,
                until: Instant::now() + lease,
            },
        );
        Claimed::Fresh(claim)
    }

    /// Applies a settlement to the key when `claim` still holds it (`None`: whoever holds it).
    async fn apply(&self, ctx: &RequestContext, key: &IdempotencyKey, claim: Option<u64>, settlement: Settlement) {
        self.seen.lock().await.push(ctx.clone());
        let mut records = self.records.lock().await;
        let scope = scope(ctx, key);
        let Some(Record::InFlight {
            fingerprint,
            claim: held,
            ..
        }) = records.get(&scope).cloned()
        else {
            self.stale.fetch_add(usize::from(claim.is_some()), Ordering::SeqCst);
            return;
        };
        if claim.is_some_and(|presented| presented != held) {
            self.stale.fetch_add(1, Ordering::SeqCst);
            return;
        }
        match settlement {
            Settlement::Response(response) => {
                records.insert(scope, Record::Done { fingerprint, response });
            }
            Settlement::Secret(note) | Settlement::Unstorable(note) => {
                records.insert(
                    scope,
                    Record::Used {
                        fingerprint,
                        note: Some(note),
                    },
                );
            }
            Settlement::Abandon => {
                records.remove(&scope);
            }
        }
    }
}

/// The proof of a claim: its number as an instant, which the double reads back.
fn proof(claim: u64) -> Reservation {
    Reservation::leased(DateTime::from_timestamp(i64::try_from(claim).unwrap_or(0), 0).unwrap_or_default())
}

fn claim_of(reservation: &Reservation) -> Option<u64> {
    reservation
        .lease_until()
        .and_then(|time| u64::try_from(time.timestamp()).ok())
}

#[async_trait]
impl IdempotencyService for MemoryIdempotency {
    async fn begin(
        &self,
        ctx: &RequestContext,
        key: IdempotencyKey,
        fingerprint: String,
    ) -> AppResult<IdempotencyState> {
        self.begins.fetch_add(1, Ordering::SeqCst);
        if self.fail_begin.load(Ordering::SeqCst) {
            return Err(AppError::unavailable());
        }
        Ok(match self.claim(ctx, &key, &fingerprint, DEFAULT_LEASE).await {
            Claimed::Fresh(_) => IdempotencyState::Fresh,
            Claimed::Existing(existing) => state_of(&existing, &fingerprint),
        })
    }

    async fn complete(&self, ctx: &RequestContext, key: &IdempotencyKey, outcome: IdempotencyOutcome) -> AppResult<()> {
        self.completes.fetch_add(1, Ordering::SeqCst);
        if self.fail_complete.load(Ordering::SeqCst) {
            return Err(AppError::unavailable());
        }
        let settlement = match outcome {
            IdempotencyOutcome::Response(response) => Settlement::Response(response),
            IdempotencyOutcome::SecretResponse => Settlement::Secret(ResponseNote {
                status: 0,
                location: None,
            }),
            IdempotencyOutcome::Abandon => Settlement::Abandon,
        };
        self.apply(ctx, key, None, settlement).await;
        Ok(())
    }

    async fn reserve(
        &self,
        ctx: &RequestContext,
        key: IdempotencyKey,
        fingerprint: String,
        lease: Duration,
    ) -> AppResult<Reserved> {
        self.reserves.fetch_add(1, Ordering::SeqCst);
        self.leases.lock().await.push(lease);
        if self.fail_begin.load(Ordering::SeqCst) {
            return Err(AppError::unavailable());
        }
        Ok(match self.claim(ctx, &key, &fingerprint, lease).await {
            Claimed::Fresh(claim) => Reserved::Fresh(proof(claim)),
            Claimed::Existing(existing) => match state_of(&existing, &fingerprint) {
                IdempotencyState::Replay(stored) => Reserved::Replay(stored),
                IdempotencyState::InProgress | IdempotencyState::Fresh => Reserved::InProgress,
                IdempotencyState::KeyReuse => Reserved::KeyReuse,
                IdempotencyState::NotReplayable => Reserved::NotReplayable(match existing {
                    Record::Used { note, .. } => note,
                    _ => None,
                }),
            },
        })
    }

    async fn settle(
        &self,
        ctx: &RequestContext,
        key: &IdempotencyKey,
        reservation: &Reservation,
        settlement: Settlement,
    ) -> AppResult<()> {
        self.settles.fetch_add(1, Ordering::SeqCst);
        if self.fail_complete.load(Ordering::SeqCst) {
            return Err(AppError::unavailable());
        }
        self.apply(ctx, key, claim_of(reservation), settlement).await;
        Ok(())
    }
}
