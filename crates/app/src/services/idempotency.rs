//! Idempotency keys for management API requests (PLAN 2.10).
//!
//! The key's scope is (tenant, token, key) and lasts 24 hours. The same request with the same key returns the
//! stored response with `Idempotent-Replayed: true`; another request with the key is `idempotency-key-reuse`
//! (422); a request that is still running is `idempotency-in-progress` (409). Responses that contain secrets, and
//! responses the server cannot keep, are not stored: a replay answers `secret-not-replayable` (409).
//!
//! # What identifies "the same request"
//!
//! The fingerprint the caller passes decides. It must cover everything that makes a request another request: the
//! method, the **concrete** path (the route template names the operation but not the resource: the same key and
//! body sent to two calendars are two requests), the query, the content type and the body. The service additionally
//! compares the method and the route template.
//!
//! # Two ways to talk to the service
//!
//! [`IdempotencyService::begin`] and [`complete`](IdempotencyService::complete) identify a request by its key
//! alone. That cannot say *which attempt* settles a key: when an attempt outlives its claim (a slow handler, a
//! stalled store), a retry takes the key over after the lease, and the late settlement of the first attempt would
//! settle or release the second attempt's claim. [`reserve`](IdempotencyService::reserve) and
//! [`settle`](IdempotencyService::settle) fix that: `reserve` returns a [`Reservation`], the proof of the claim
//! (the end of its lease), and `settle` presents it, so a service that backs them with the fenced operations of the
//! store (`claim_leased`, `complete_leased`, `release_leased`, ADR-0006) can ignore a settlement that is not
//! the holder's. They also carry what a client needs after a response that was not stored: its status and its
//! `Location` ([`ResponseNote`]), both free of secrets.
//!
//! The two pairs are additive: the provided `reserve` and `settle` call `begin` and `complete`, so a service that
//! implements only the first pair keeps working (unfenced). The API layer calls `reserve` and `settle`, passes
//! the lease it needs (the request timeout of the server plus a margin) and bounds its own work by it.

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::RequestContext;

use crate::error::AppResult;

/// The client's key and the request it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotencyKey {
    /// The `Idempotency-Key` header value.
    pub key: String,
    /// The HTTP method of the request.
    pub method: String,
    /// The route template of the request (`/tenants/{tenant}/principals`), never the raw path. It names the
    /// operation, not the resource: what tells two resources apart belongs to the fingerprint.
    pub route: String,
}

/// A response kept for replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredResponse {
    /// The HTTP status.
    pub status: u16,
    /// The response headers worth replaying (`Content-Type`, `Location`, `ETag`), name and value.
    pub headers: Vec<(String, String)>,
    /// The JSON body.
    pub body: serde_json::Value,
}

/// What `begin` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdempotencyState {
    /// First use of the key: the request proceeds and calls `complete` afterwards.
    Fresh,
    /// The same request already completed: answer with the stored response and `Idempotent-Replayed: true`.
    Replay(StoredResponse),
    /// The same request is still being processed (409 `idempotency-in-progress`).
    InProgress,
    /// The key was used with a different request (422 `idempotency-key-reuse`).
    KeyReuse,
    /// The original response contained a secret, or could not be stored, and is not kept (409
    /// `secret-not-replayable`).
    NotReplayable,
}

/// How a request that began with a key ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdempotencyOutcome {
    /// Store the response for replay.
    Response(StoredResponse),
    /// The response contains a secret, or cannot be stored: remember that the key was used but store nothing.
    SecretResponse,
    /// The request ended without a response that can be replayed: an error answer, a timeout, a panic. Release the
    /// key so that a retry starts fresh and can succeed.
    Abandon,
}

/// The proof that a request holds its key, returned by [`IdempotencyService::reserve`] and presented to
/// [`IdempotencyService::settle`].
///
/// A service backed by the fenced operations of the store puts the end of the lease it took into it
/// ([`Reservation::leased`]) and settles only while that lease is still the key's; a service that does not fence
/// returns [`Reservation::unfenced`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reservation {
    lease_until: Option<DateTime<Utc>>,
}

impl Reservation {
    /// The reservation of a service that does not fence: it proves nothing.
    pub const fn unfenced() -> Self {
        Self { lease_until: None }
    }

    /// The reservation of a claim that holds the key until `lease_until`.
    pub const fn leased(lease_until: DateTime<Utc>) -> Self {
        Self {
            lease_until: Some(lease_until),
        }
    }

    /// The end of the lease the claim took, if the service fences.
    pub const fn lease_until(&self) -> Option<DateTime<Utc>> {
        self.lease_until
    }
}

/// What is known of a response that is not replayed, free of secrets: the status of the first answer and where the
/// resource it created can be found. The API layer sends them with the `secret-not-replayable` problem, so a client
/// whose first attempt was lost can find the credential or webhook that attempt created and revoke or read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseNote {
    /// The HTTP status of the first answer.
    pub status: u16,
    /// Its `Location` header, when it had one.
    pub location: Option<String>,
}

/// What [`IdempotencyService::reserve`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reserved {
    /// First use of the key: the request proceeds and calls `settle` with the reservation afterwards.
    Fresh(Reservation),
    /// The same request already completed: answer with the stored response and `Idempotent-Replayed: true`.
    Replay(StoredResponse),
    /// The same request is still being processed (409 `idempotency-in-progress`).
    InProgress,
    /// The key was used with a different request (422 `idempotency-key-reuse`).
    KeyReuse,
    /// The original response is not kept (409 `secret-not-replayable`); the note says what is known of it.
    NotReplayable(Option<ResponseNote>),
}

/// How a request that holds a [`Reservation`] ended, as [`IdempotencyService::settle`] takes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Settlement {
    /// Store the response for replay.
    Response(StoredResponse),
    /// The response contains a secret: remember that the key was used, with the note, and store no body.
    Secret(ResponseNote),
    /// The response is a success that cannot be stored (it is not a JSON document the server keeps, or it is too
    /// large): remember that the key was used, with the note, and store no body.
    Unstorable(ResponseNote),
    /// The request ended without a response that can be replayed (an error answer, a timeout, a panic): release the
    /// key so that a retry starts fresh.
    Abandon,
}

/// Idempotency bookkeeping.
#[async_trait]
pub trait IdempotencyService: Send + Sync {
    /// Looks the key up and, for a fresh key, reserves it for the request with the given fingerprint (a hash of
    /// method, route and body).
    ///
    /// # Errors
    ///
    /// Only infrastructure failures; every key state is an [`IdempotencyState`].
    async fn begin(
        &self,
        ctx: &RequestContext,
        key: IdempotencyKey,
        fingerprint: String,
    ) -> AppResult<IdempotencyState>;

    /// Records how a request that began with `key` ended.
    ///
    /// # Errors
    ///
    /// Only infrastructure failures.
    async fn complete(&self, ctx: &RequestContext, key: &IdempotencyKey, outcome: IdempotencyOutcome) -> AppResult<()>;

    /// [`begin`](Self::begin) for a caller that needs the proof of its claim: a fresh key is claimed for `lease`
    /// (counted by the service's clock) and the [`Reservation`] says until when. A service backed by the fenced
    /// operations of the store passes `lease` to `claim_leased`. Additive method: the provided implementation calls
    /// [`begin`](Self::begin), ignores `lease` (the service's own lease applies) and returns an unfenced
    /// reservation.
    ///
    /// # Errors
    ///
    /// Only infrastructure failures; every key state is a [`Reserved`].
    async fn reserve(
        &self,
        ctx: &RequestContext,
        key: IdempotencyKey,
        fingerprint: String,
        lease: Duration,
    ) -> AppResult<Reserved> {
        let _ = lease;
        Ok(match self.begin(ctx, key, fingerprint).await? {
            IdempotencyState::Fresh => Reserved::Fresh(Reservation::unfenced()),
            IdempotencyState::Replay(stored) => Reserved::Replay(stored),
            IdempotencyState::InProgress => Reserved::InProgress,
            IdempotencyState::KeyReuse => Reserved::KeyReuse,
            IdempotencyState::NotReplayable => Reserved::NotReplayable(None),
        })
    }

    /// [`complete`](Self::complete) that presents the [`Reservation`] and keeps the non-secret facts of a response
    /// that is not stored. A fenced service settles only while the reservation is still the key's claim: a claim
    /// that was taken over after its lease is left alone (and a settlement of a stale claim is not an error).
    /// Additive method: the provided implementation calls [`complete`](Self::complete): a stored response
    /// stays one, a secret or unstorable response is `SecretResponse`, an abandoned request releases the key; the
    /// note is dropped.
    ///
    /// # Errors
    ///
    /// Only infrastructure failures.
    async fn settle(
        &self,
        ctx: &RequestContext,
        key: &IdempotencyKey,
        reservation: &Reservation,
        settlement: Settlement,
    ) -> AppResult<()> {
        let _ = reservation;
        let outcome = match settlement {
            Settlement::Response(response) => IdempotencyOutcome::Response(response),
            Settlement::Secret(_) | Settlement::Unstorable(_) => IdempotencyOutcome::SecretResponse,
            Settlement::Abandon => IdempotencyOutcome::Abandon,
        };
        self.complete(ctx, key, outcome).await
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;
    use davhaven_domain::{Actor, Channel, RequestId, ScopeSet, TenantId, TokenId};
    use tokio::sync::Mutex;
    use uuid::Uuid;

    use super::*;

    /// A service of the first pair only, recording what it was asked.
    #[derive(Default)]
    struct Basic {
        state: Mutex<Option<IdempotencyState>>,
        completed: Mutex<Vec<IdempotencyOutcome>>,
    }

    #[async_trait]
    impl IdempotencyService for Basic {
        async fn begin(&self, _: &RequestContext, _: IdempotencyKey, _: String) -> AppResult<IdempotencyState> {
            Ok(self.state.lock().await.take().unwrap_or(IdempotencyState::Fresh))
        }

        async fn complete(&self, _: &RequestContext, _: &IdempotencyKey, outcome: IdempotencyOutcome) -> AppResult<()> {
            self.completed.lock().await.push(outcome);
            Ok(())
        }
    }

    fn context() -> RequestContext {
        RequestContext {
            tenant: TenantId::from_uuid(Uuid::from_u128(1)),
            actor: Actor::TenantToken(TokenId::from_uuid(Uuid::from_u128(2))),
            scopes: ScopeSet::empty(),
            channel: Channel::Api,
            credential: None,
            request_id: RequestId::from_uuid(Uuid::nil()),
            locale: None,
            client_ip: None,
        }
    }

    fn key() -> IdempotencyKey {
        IdempotencyKey {
            key: "k".to_owned(),
            method: "POST".to_owned(),
            route: "/things".to_owned(),
        }
    }

    fn stored() -> StoredResponse {
        StoredResponse {
            status: 200,
            headers: Vec::new(),
            body: serde_json::json!({"ok": true}),
        }
    }

    #[test]
    fn a_reservation_remembers_its_lease_or_none() {
        let until = Utc.with_ymd_and_hms(2027, 1, 1, 0, 1, 30).unwrap();
        assert_eq!(Reservation::unfenced().lease_until(), None);
        assert_eq!(Reservation::leased(until).lease_until(), Some(until));
        assert_ne!(Reservation::unfenced(), Reservation::leased(until));
    }

    #[tokio::test]
    async fn the_provided_reserve_maps_every_state_of_begin() {
        let service = Basic::default();
        let cases = [
            (IdempotencyState::Fresh, Reserved::Fresh(Reservation::unfenced())),
            (IdempotencyState::Replay(stored()), Reserved::Replay(stored())),
            (IdempotencyState::InProgress, Reserved::InProgress),
            (IdempotencyState::KeyReuse, Reserved::KeyReuse),
            (IdempotencyState::NotReplayable, Reserved::NotReplayable(None)),
        ];
        for (state, expected) in cases {
            *service.state.lock().await = Some(state);
            let reserved = service
                .reserve(&context(), key(), "f".to_owned(), Duration::from_secs(90))
                .await
                .unwrap();
            assert_eq!(reserved, expected);
        }
    }

    #[tokio::test]
    async fn the_provided_settle_maps_every_settlement_to_complete() {
        let service = Basic::default();
        let note = ResponseNote {
            status: 201,
            location: Some("/api/v1/things/1".to_owned()),
        };
        for settlement in [
            Settlement::Response(stored()),
            Settlement::Secret(note.clone()),
            Settlement::Unstorable(note),
            Settlement::Abandon,
        ] {
            service
                .settle(&context(), &key(), &Reservation::unfenced(), settlement)
                .await
                .unwrap();
        }
        assert_eq!(
            *service.completed.lock().await,
            vec![
                IdempotencyOutcome::Response(stored()),
                IdempotencyOutcome::SecretResponse,
                IdempotencyOutcome::SecretResponse,
                IdempotencyOutcome::Abandon,
            ]
        );
    }
}
