//! Idempotency keys for management API requests (PLAN 2.10).
//!
//! A key is scoped to (tenant, token, key) and lasts 24 hours. `begin` and `reserve` claim the key in a transaction
//! of their own, so a concurrent request with the same key sees it at once; the request then runs; `complete` and
//! `settle` record how it ended in another transaction.
//!
//! * the same request again returns the stored response (`Replay`);
//! * another request with the key (another method, route or fingerprint) is `KeyReuse` (422). The fingerprint
//!   covers the concrete path, so the same key and body sent to two calendars are two requests;
//! * a request that is still running is `InProgress` (409), until its lease runs out: a process that died between
//!   the claim and its settlement never releases the key, so after the lease (the request timeout of the server
//!   plus a margin, which the API layer asks for; 90 seconds for the callers that do not ask for one) the next request
//!   takes it over;
//! * a request settles its key **fenced by its lease** (`reserve` and `settle`, ADR-0006 and ADR-0012): the
//!   reservation carries the end of the lease the claim took, and a request that outlived its lease cannot overwrite
//!   the response of the retry that took the key over, nor release the claim of a request that is running. The
//!   unfenced `begin` and `complete` remain for callers that do not carry a reservation;
//! * a response that was not kept (it contained a secret, or could not be stored) leaves a note with its status and
//!   its `Location`: a replay is `NotReplayable` (409) and carries the note.
//!
//! The response is stored as `{"headers": [[name, value], ...], "body": ...}` next to its status; a note as
//! `{"location": ...}` next to the status of the first answer.

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use davhaven_domain::{RequestContext, TokenId};
use davhaven_ports::{IdempotencyClaim, IdempotencyRecord, IdempotencyStatus, LeasedClaim, StoreError, TxMode};
use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult, SafeMessage};
use crate::services::{
    IdempotencyKey, IdempotencyOutcome, IdempotencyService, IdempotencyState, Reservation, Reserved, ResponseNote,
    Settlement, StoredResponse,
};
use crate::wiring::AppCore;

/// How long a key stays valid after it was claimed.
const KEY_LIFETIME_HOURS: i64 = 24;

/// The longest `Idempotency-Key` accepted, in characters.
const MAX_KEY_CHARS: usize = 255;

/// How long a claim of the unfenced [`begin`](IdempotencyService::begin) holds its key before a retry may take it over: the
/// default request timeout of the server (60 s) plus the margin that the API layer adds (30 s). A caller that knows its
/// own time limit asks for a lease with `reserve`; the API layer does, and leases every key for the request timeout of
/// the server it is mounted in plus that margin (ADR-0012), so no setting has to be kept in step with the timeout.
const UNFENCED_LEASE: Duration = Duration::from_secs(90);

/// The stored form of a replayable response.
#[derive(Debug, Serialize, Deserialize)]
struct StoredForm {
    headers: Vec<(String, String)>,
    body: serde_json::Value,
}

/// The stored form of a response that was not kept: what is known of it, free of secrets.
#[derive(Debug, Serialize, Deserialize)]
struct NoteForm {
    location: Option<String>,
}

/// The [`IdempotencyService`] of the application.
#[derive(Debug, Clone)]
pub struct IdempotencyServiceImpl {
    core: AppCore,
}

impl IdempotencyServiceImpl {
    /// Creates the service on the shared application core.
    pub fn new(core: AppCore) -> Self {
        Self { core }
    }

    /// The shared application core: ports, configuration and limits.
    pub fn core(&self) -> &AppCore {
        &self.core
    }
}

/// The token a key is scoped to: idempotency belongs to API tokens.
fn token_of(ctx: &RequestContext) -> AppResult<TokenId> {
    ctx.actor.token().ok_or_else(|| {
        AppError::invalid(SafeMessage::from_static(
            "Idempotency keys are only available to requests with an API token.",
        ))
    })
}

fn check_key(key: &IdempotencyKey) -> AppResult<()> {
    let text = key.key.as_str();
    if text.is_empty() || text.chars().count() > MAX_KEY_CHARS || text.chars().any(char::is_control) {
        return Err(AppError::invalid(SafeMessage::from_static(
            "The Idempotency-Key must be 1 to 255 printable characters.",
        ))
        .with_field_error(
            "/idempotency_key",
            "invalid",
            SafeMessage::from_static("The Idempotency-Key must be 1 to 255 printable characters."),
        ));
    }
    Ok(())
}

/// What an existing record says about a new request with the same key.
enum Found {
    Replay(StoredResponse),
    InProgress,
    KeyReuse,
    NotReplayable(Option<ResponseNote>),
}

fn found(record: &IdempotencyRecord, key: &IdempotencyKey, fingerprint: &str) -> Found {
    if record.method != key.method || record.path != key.route || record.fingerprint != fingerprint {
        return Found::KeyReuse;
    }
    if record.status == IdempotencyStatus::InFlight {
        return Found::InProgress;
    }
    let stored = record.response_status.zip(record.response.as_ref());
    if let Some((status, value)) = stored
        && let Ok(form) = serde_json::from_value::<StoredForm>(value.clone())
    {
        return Found::Replay(StoredResponse {
            status,
            headers: form.headers,
            body: form.body,
        });
    }
    // A response that was not kept: the status of the first answer (0 when the caller did not say) and its location.
    let note = record
        .response_status
        .filter(|status| *status != 0)
        .map(|status| ResponseNote {
            status,
            location: record
                .response
                .as_ref()
                .and_then(|value| serde_json::from_value::<NoteForm>(value.clone()).ok())
                .and_then(|form| form.location),
        });
    Found::NotReplayable(note)
}

/// A claim: what the key says and, for a fresh key, the end of the lease it took when the store fences claims.
struct Claimed {
    found: Option<Found>,
    lease_until: Option<DateTime<Utc>>,
}

impl IdempotencyServiceImpl {
    /// The record a request claims its key with.
    fn record_of(&self, token: TokenId, key: &IdempotencyKey, fingerprint: &str) -> IdempotencyRecord {
        IdempotencyRecord {
            token_id: token,
            key: key.key.clone(),
            method: key.method.clone(),
            path: key.route.clone(),
            fingerprint: fingerprint.to_owned(),
            status: IdempotencyStatus::InFlight,
            response_status: None,
            response: None,
            expires_at: self.core.deps().clock.now() + ChronoDuration::hours(KEY_LIFETIME_HOURS),
        }
    }

    /// Claims the key for `lease`; `found` is `None` for a fresh claim.
    async fn claim(
        &self,
        ctx: &RequestContext,
        key: &IdempotencyKey,
        fingerprint: &str,
        lease: Duration,
    ) -> AppResult<Claimed> {
        let token = token_of(ctx)?;
        check_key(key)?;
        let record = self.record_of(token, key, fingerprint);
        // The claim is a transaction of its own: concurrent requests must see it before this one finishes.
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadWrite).await?;
        let claim = match tx.idempotency().claim_leased(record.clone(), lease).await {
            Ok(LeasedClaim::Claimed { lease_until }) => (IdempotencyClaim::Claimed, Some(lease_until)),
            Ok(LeasedClaim::Existing(existing)) => (IdempotencyClaim::Existing(existing), None),
            // A store that cannot fence claims still protects the key by lease, without the proof.
            Err(StoreError::Unsupported) => (tx.idempotency().claim_with_lease(record, lease).await?, None),
            Err(error) => return Err(error.into()),
        };
        tx.commit().await?;
        Ok(match claim {
            (IdempotencyClaim::Claimed, lease_until) => Claimed {
                found: None,
                lease_until,
            },
            (IdempotencyClaim::Existing(existing), _) => Claimed {
                found: Some(found(&existing, key, fingerprint)),
                lease_until: None,
            },
        })
    }

    /// Records how a request ended, fenced by its reservation when it carries a lease.
    async fn finish(
        &self,
        ctx: &RequestContext,
        key: &IdempotencyKey,
        lease_until: Option<DateTime<Utc>>,
        ending: Ending,
    ) -> AppResult<()> {
        let token = token_of(ctx)?;
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadWrite).await?;
        let settled = match ending {
            Ending::Kept { status, form } => match lease_until {
                Some(until) => {
                    tx.idempotency()
                        .complete_leased(token, &key.key, until, status, form)
                        .await
                }
                None => tx.idempotency().complete(token, &key.key, status, form).await,
            },
            Ending::Release => match lease_until {
                Some(until) => tx.idempotency().release_leased(token, &key.key, until).await,
                None => tx.idempotency().release(token, &key.key).await,
            },
        };
        match settled {
            Ok(()) => {}
            // The key was taken over after the lease ran out: the request that replaced this one owns it now, and
            // what this one would write is the loser's problem, not an error of the client.
            Err(StoreError::LeaseLost) => {
                tracing::debug!(
                    target: "davhaven::idempotency",
                    "a request settled an idempotency key after another request took it over"
                );
            }
            Err(error) => return Err(error.into()),
        }
        tx.commit().await?;
        Ok(())
    }
}

/// What a settlement writes.
enum Ending {
    /// Complete the key with a status and, for a response that is kept or noted, its stored form.
    Kept {
        status: u16,
        form: Option<serde_json::Value>,
    },
    /// Release the key.
    Release,
}

/// The ending of a response that is stored for replay.
fn kept(response: StoredResponse) -> AppResult<Ending> {
    let form = serde_json::to_value(StoredForm {
        headers: response.headers,
        body: response.body,
    })
    .map_err(AppError::internal)?;
    Ok(Ending::Kept {
        status: response.status,
        form: Some(form),
    })
}

/// The ending of a response that is not kept: the note says what is known of it.
fn noted(note: ResponseNote) -> AppResult<Ending> {
    let form = serde_json::to_value(NoteForm {
        location: note.location,
    })
    .map_err(AppError::internal)?;
    Ok(Ending::Kept {
        status: note.status,
        form: Some(form),
    })
}

#[async_trait]
impl IdempotencyService for IdempotencyServiceImpl {
    async fn begin(
        &self,
        ctx: &RequestContext,
        key: IdempotencyKey,
        fingerprint: String,
    ) -> AppResult<IdempotencyState> {
        let claimed = self.claim(ctx, &key, &fingerprint, UNFENCED_LEASE).await?;
        Ok(match claimed.found {
            None => IdempotencyState::Fresh,
            Some(Found::Replay(stored)) => IdempotencyState::Replay(stored),
            Some(Found::InProgress) => IdempotencyState::InProgress,
            Some(Found::KeyReuse) => IdempotencyState::KeyReuse,
            Some(Found::NotReplayable(_)) => IdempotencyState::NotReplayable,
        })
    }

    async fn complete(&self, ctx: &RequestContext, key: &IdempotencyKey, outcome: IdempotencyOutcome) -> AppResult<()> {
        let ending = match outcome {
            IdempotencyOutcome::Response(response) => kept(response)?,
            // The key is used, but the response is not kept: nothing of it can be replayed.
            IdempotencyOutcome::SecretResponse => Ending::Kept { status: 0, form: None },
            IdempotencyOutcome::Abandon => Ending::Release,
        };
        self.finish(ctx, key, None, ending).await
    }

    async fn reserve(
        &self,
        ctx: &RequestContext,
        key: IdempotencyKey,
        fingerprint: String,
        lease: Duration,
    ) -> AppResult<Reserved> {
        let claimed = self.claim(ctx, &key, &fingerprint, lease).await?;
        Ok(match claimed.found {
            None => Reserved::Fresh(
                claimed
                    .lease_until
                    .map_or_else(Reservation::unfenced, Reservation::leased),
            ),
            Some(Found::Replay(stored)) => Reserved::Replay(stored),
            Some(Found::InProgress) => Reserved::InProgress,
            Some(Found::KeyReuse) => Reserved::KeyReuse,
            Some(Found::NotReplayable(note)) => Reserved::NotReplayable(note),
        })
    }

    async fn settle(
        &self,
        ctx: &RequestContext,
        key: &IdempotencyKey,
        reservation: &Reservation,
        settlement: Settlement,
    ) -> AppResult<()> {
        let ending = match settlement {
            Settlement::Response(response) => kept(response)?,
            Settlement::Secret(note) | Settlement::Unstorable(note) => noted(note)?,
            Settlement::Abandon => Ending::Release,
        };
        self.finish(ctx, key, reservation.lease_until(), ending).await
    }
}
