//! Cases of idempotency keys and the audit log.

use std::time::Duration;

use davhaven_domain::audit::{PrincipalAudit, TokenRevocationAudit};
use davhaven_domain::{AuditActor, AuditActorKind, AuditEvent, TokenId};
use davhaven_ports::{
    AuditFilter, IdempotencyClaim, IdempotencyRecord, IdempotencyStatus, LeasedClaim, NewAudit, PageReq,
};

use super::Outcome;
use super::world::{Db, StoreChecks, begin, far_future, id, long_ago, seed, uuid};
use crate::suite::Checks;

/// A request that claims a key.
fn request(token: TokenId, key: &str, fingerprint: &str) -> IdempotencyRecord {
    IdempotencyRecord {
        token_id: token,
        key: key.to_owned(),
        method: "POST".to_owned(),
        path: "/api/v1/tenants/acme/principals".to_owned(),
        fingerprint: fingerprint.to_owned(),
        status: IdempotencyStatus::Done,
        response_status: Some(500),
        response: Some(serde_json::json!({"ignored": true})),
        expires_at: far_future(),
    }
}

/// Claiming, completing and releasing idempotency keys.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn idempotency_keys(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let token: TokenId = id(0x710);
    let mut tx = begin(db, world.a).await?;
    checks.equal(
        &tx.idempotency().claim(request(token, "key-1", "abc")).await?,
        &IdempotencyClaim::Claimed,
        "a free key is claimed",
    );
    let existing = tx.idempotency().claim(request(token, "key-1", "different")).await?;
    let IdempotencyClaim::Existing(record) = existing else {
        checks.fail("claiming a claimed key returns the existing record");
        return Ok(());
    };
    checks.equal(&record.fingerprint.as_str(), &"abc", "the record of the first request");
    checks.equal(
        &record.status,
        &IdempotencyStatus::InFlight,
        "claimed keys are in flight, whatever the request said",
    );
    checks.equal(
        &(record.response_status, record.response),
        &(None, None),
        "without a response",
    );
    checks.equal(&record.expires_at, &far_future(), "and the expiry of the claim");
    checks.equal(
        &tx.idempotency().claim(request(id(0x711), "key-1", "abc")).await?,
        &IdempotencyClaim::Claimed,
        "keys are scoped to the token",
    );
    checks.equal(
        &tx.idempotency().claim(request(token, "key-2", "abc")).await?,
        &IdempotencyClaim::Claimed,
        "and to the key",
    );
    tx.commit().await?;

    let mut tx = begin(db, world.a).await?;
    checks.that(
        matches!(
            tx.idempotency().claim(request(token, "key-1", "abc")).await?,
            IdempotencyClaim::Existing(_)
        ),
        "a claim is visible to the next transaction",
    );
    tx.idempotency()
        .complete(token, "key-1", 201, Some(serde_json::json!({"id": "x"})))
        .await?;
    let IdempotencyClaim::Existing(done) = tx.idempotency().claim(request(token, "key-1", "abc")).await? else {
        checks.fail("a completed key is still claimed");
        return Ok(());
    };
    checks.equal(&done.status, &IdempotencyStatus::Done, "a completed key is done");
    checks.equal(&done.response_status, &Some(201), "with the response status");
    checks.equal(
        &done.response,
        &Some(serde_json::json!({"id": "x"})),
        "and the response",
    );
    tx.idempotency().complete(token, "key-2", 200, None).await?;
    let IdempotencyClaim::Existing(secret) = tx.idempotency().claim(request(token, "key-2", "abc")).await? else {
        checks.fail("a completed key is still claimed");
        return Ok(());
    };
    checks.equal(
        &(secret.status, secret.response),
        &(IdempotencyStatus::Done, None),
        "a response may be withheld",
    );
    checks.not_found(
        tx.idempotency().complete(token, "missing", 200, None).await,
        "completing an unknown key",
    );

    tx.idempotency().release(token, "key-1").await?;
    checks.that(
        matches!(
            tx.idempotency().claim(request(token, "key-1", "abc")).await?,
            IdempotencyClaim::Existing(_)
        ),
        "releasing a completed key does nothing",
    );
    tx.idempotency().claim(request(token, "key-3", "abc")).await?;
    tx.idempotency().release(token, "key-3").await?;
    checks.equal(
        &tx.idempotency().claim(request(token, "key-3", "abc")).await?,
        &IdempotencyClaim::Claimed,
        "a released in-flight key can be claimed again",
    );
    tx.idempotency().release(token, "never-claimed").await?;

    let mut stale = request(token, "key-old", "first");
    stale.expires_at = long_ago();
    checks.equal(
        &tx.idempotency().claim(stale).await?,
        &IdempotencyClaim::Claimed,
        "claiming a key that expires long ago",
    );
    checks.equal(
        &tx.idempotency().claim(request(token, "key-old", "second")).await?,
        &IdempotencyClaim::Claimed,
        "an expired key is replaced",
    );
    let IdempotencyClaim::Existing(replaced) = tx.idempotency().claim(request(token, "key-old", "third")).await? else {
        checks.fail("the replacement holds the key");
        return Ok(());
    };
    checks.equal(&replaced.fingerprint.as_str(), &"second", "by the new request");
    tx.commit().await?;

    let mut other = begin(db, world.b).await?;
    checks.equal(
        &other.idempotency().claim(request(token, "key-1", "abc")).await?,
        &IdempotencyClaim::Claimed,
        "keys are scoped to the tenant",
    );
    Ok(())
}

/// Appending to and listing the audit log.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn audit_log(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let actor = AuditActor {
        kind: AuditActorKind::Principal,
        principal_id: Some(world.mia),
        token_id: None,
        label: Some("laptop".to_owned()),
        ip_hash: Some("hash".to_owned()),
    };
    let events = [
        (1, AuditActor::system(), AuditEvent::TenantCreated),
        (
            2,
            actor.clone(),
            AuditEvent::PrincipalCreated(PrincipalAudit {
                principal: world.olivia,
            }),
        ),
        (
            3,
            actor.clone(),
            AuditEvent::TokenRevoked(TokenRevocationAudit { token: id(0x710) }),
        ),
    ];
    for (n, actor, event) in events {
        tx.audit()
            .append(NewAudit {
                id: uuid(n),
                actor,
                event,
            })
            .await?;
    }
    checks.internal(
        tx.audit()
            .append(NewAudit {
                id: uuid(1),
                actor: AuditActor::system(),
                event: AuditEvent::TenantCreated,
            })
            .await,
        "appending a record with an id that exists",
    );
    let all = tx.audit().list(&AuditFilter::default(), PageReq::default()).await?;
    checks.equal(
        &all.items.iter().map(|row| row.action.as_str()).collect::<Vec<_>>(),
        &vec!["tenant.created", "principal.created", "token.revoked"],
        "records come in id order with their action names",
    );
    let created = all.items.get(1);
    checks.equal(&created.map(|row| row.tenant_id), &Some(world.a), "the tenant");
    checks.equal(
        &created.and_then(|row| row.target.clone()),
        &Some(format!("principal:{}", world.olivia)),
        "the target is kind and id",
    );
    checks.equal(
        &created.map(|row| row.details.clone()),
        &Some(serde_json::json!({"principal": world.olivia.to_string()})),
        "the details are what remains of the event",
    );
    checks.equal(
        &created.map(|row| row.actor.clone()),
        &Some(actor.clone()),
        "the actor round-trips",
    );
    checks.equal(
        &all.items.first().and_then(|row| row.target.clone()),
        &None,
        "an event without a target",
    );
    checks.that(
        all.items
            .iter()
            .all(|row| row.at >= long_ago() && row.at < far_future()),
        "stamped by the clock",
    );

    let by_action = tx
        .audit()
        .list(
            &AuditFilter {
                action: Some("token.revoked".to_owned()),
                ..AuditFilter::default()
            },
            PageReq::default(),
        )
        .await?;
    checks.equal(&by_action.items.len(), &1, "the action filter");
    let by_principal = tx
        .audit()
        .list(
            &AuditFilter {
                principal: Some(world.mia),
                ..AuditFilter::default()
            },
            PageReq::default(),
        )
        .await?;
    checks.equal(&by_principal.items.len(), &2, "the principal filter matches the actor");
    let by_target = tx
        .audit()
        .list(
            &AuditFilter {
                target: Some(format!("principal:{}", world.olivia)),
                ..AuditFilter::default()
            },
            PageReq::default(),
        )
        .await?;
    checks.equal(&by_target.items.len(), &1, "the target filter");
    let since = |at| AuditFilter {
        since: Some(at),
        ..AuditFilter::default()
    };
    let until = |at| AuditFilter {
        until: Some(at),
        ..AuditFilter::default()
    };
    checks.equal(
        &tx.audit()
            .list(&since(long_ago()), PageReq::default())
            .await?
            .items
            .len(),
        &3,
        "since long ago",
    );
    checks.equal(
        &tx.audit()
            .list(&since(far_future()), PageReq::default())
            .await?
            .items
            .len(),
        &0,
        "since the far future",
    );
    checks.equal(
        &tx.audit()
            .list(&until(far_future()), PageReq::default())
            .await?
            .items
            .len(),
        &3,
        "until the far future",
    );
    checks.equal(
        &tx.audit()
            .list(&until(long_ago()), PageReq::default())
            .await?
            .items
            .len(),
        &0,
        "until long ago",
    );
    let first = tx.audit().list(&AuditFilter::default(), PageReq::first(2)).await?;
    checks.equal(&first.items.len(), &2, "a page of two");
    if let Some(cursor) = first.next {
        let rest = tx
            .audit()
            .list(&AuditFilter::default(), PageReq::first(2).after(cursor))
            .await?;
        checks.equal(&rest.items.len(), &1, "the rest");
        checks.equal(&rest.next, &None, "is the last page");
    } else {
        checks.fail("a page of two out of three records names a cursor");
    }
    tx.commit().await?;

    let mut other = begin(db, world.b).await?;
    checks.equal(
        &other
            .audit()
            .list(&AuditFilter::default(), PageReq::default())
            .await?
            .items
            .len(),
        &0,
        "another tenant sees none of it",
    );
    Ok(())
}

/// The in-flight state of a key is a lease: a claim takes over a key whose claimant did not finish within its
/// lease (the process died), and respects a key whose lease is running or that is done.
pub(super) async fn idempotency_leases(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let token: TokenId = id(0x720);
    let mut tx = begin(db, world.a).await?;

    // The suite never sleeps: a lease of zero is over as soon as the claim returns.
    checks.equal(
        &tx.idempotency()
            .claim_with_lease(request(token, "dead", "first"), Duration::ZERO)
            .await?,
        &IdempotencyClaim::Claimed,
        "a key claimed with a lease that is over at once",
    );
    checks.equal(
        &tx.idempotency().claim(request(token, "dead", "second")).await?,
        &IdempotencyClaim::Claimed,
        "an in-flight key whose lease ran out is taken over, so the client's retry is never locked out",
    );
    let IdempotencyClaim::Existing(adopted) = tx.idempotency().claim(request(token, "dead", "third")).await? else {
        checks.fail("the new claimant holds the key");
        return Ok(());
    };
    checks.equal(
        &adopted.fingerprint.as_str(),
        &"second",
        "the record is the new claimant's",
    );
    checks.equal(
        &adopted.status,
        &IdempotencyStatus::InFlight,
        "still in flight, under the default lease of minutes",
    );

    checks.equal(
        &tx.idempotency()
            .claim_with_lease(request(token, "fresh", "a"), Duration::from_secs(3600))
            .await?,
        &IdempotencyClaim::Claimed,
        "a key claimed with a long lease",
    );
    let IdempotencyClaim::Existing(fresh) = tx
        .idempotency()
        .claim_with_lease(request(token, "fresh", "b"), Duration::ZERO)
        .await?
    else {
        checks.fail("a key with a running lease is not taken over");
        return Ok(());
    };
    checks.equal(
        &(fresh.fingerprint.as_str(), fresh.status),
        &("a", IdempotencyStatus::InFlight),
        "a second claim sees the first claimant's in-flight record, whatever lease the second asks for",
    );

    tx.idempotency()
        .claim_with_lease(request(token, "done", "a"), Duration::ZERO)
        .await?;
    tx.idempotency()
        .complete(token, "done", 201, Some(serde_json::json!({"id": "x"})))
        .await?;
    let IdempotencyClaim::Existing(done) = tx
        .idempotency()
        .claim_with_lease(request(token, "done", "b"), Duration::ZERO)
        .await?
    else {
        checks.fail("a completed key is never taken over");
        return Ok(());
    };
    checks.equal(
        &(done.status, done.response_status),
        &(IdempotencyStatus::Done, Some(201)),
        "completing a key ends its lease: it answers until it expires",
    );
    tx.commit().await?;

    let mut tx = begin(db, world.a).await?;
    checks.that(
        matches!(
            tx.idempotency().claim(request(token, "fresh", "c")).await?,
            IdempotencyClaim::Existing(_)
        ),
        "a running lease is visible to the next transaction",
    );
    Ok(())
}

/// A request that took over an abandoned key is not overwritten by the slow first request: completing and releasing
/// are fenced by the lease of the claim, so only the current claimant settles the key.
pub(super) async fn idempotency_fenced_settling(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let token: TokenId = id(0x730);
    let mut tx = begin(db, world.a).await?;

    // Request A claims with a lease that is over at once (it is slow, or its process died); the client's retry B
    // takes the key over.
    let LeasedClaim::Claimed { lease_until: a } = tx
        .idempotency()
        .claim_leased(request(token, "slow", "a"), Duration::ZERO)
        .await?
    else {
        checks.fail("a free key is claimed");
        return Ok(());
    };
    let LeasedClaim::Claimed { lease_until: b } = tx
        .idempotency()
        .claim_leased(request(token, "slow", "b"), Duration::from_secs(600))
        .await?
    else {
        checks.fail("a key whose lease ran out is taken over");
        return Ok(());
    };
    checks.differ(&a, &b, "every claim has its own lease");

    // A finishes late: refused, and B's in-flight record is untouched.
    checks.lease_lost(
        tx.idempotency()
            .complete_leased(token, "slow", a, 200, Some(serde_json::json!({"from": "a"})))
            .await,
        "A's late completion of a key that B took over",
    );
    tx.idempotency().release_leased(token, "slow", a).await?;
    let LeasedClaim::Existing(current) = tx
        .idempotency()
        .claim_leased(request(token, "slow", "c"), Duration::from_secs(600))
        .await?
    else {
        checks.fail("A's release removed B's key");
        return Ok(());
    };
    checks.equal(
        &(current.fingerprint.as_str(), current.status, current.response_status),
        &("b", IdempotencyStatus::InFlight, None),
        "the key is still B's, in flight, without A's response",
    );

    // B completes with its lease; the response is B's.
    tx.idempotency()
        .complete_leased(token, "slow", b, 201, Some(serde_json::json!({"from": "b"})))
        .await?;
    let LeasedClaim::Existing(done) = tx
        .idempotency()
        .claim_leased(request(token, "slow", "d"), Duration::ZERO)
        .await?
    else {
        checks.fail("a completed key answers");
        return Ok(());
    };
    checks.equal(
        &(done.status, done.response_status, done.response),
        &(
            IdempotencyStatus::Done,
            Some(201),
            Some(serde_json::json!({"from": "b"})),
        ),
        "the stored response is the current claimant's, whoever finished last",
    );
    checks.lease_lost(
        tx.idempotency().complete_leased(token, "slow", b, 500, None).await,
        "completing a key that is done already",
    );
    checks.not_found(
        tx.idempotency().complete_leased(token, "missing", b, 200, None).await,
        "completing a key that does not exist",
    );

    // Releasing with the right lease removes an in-flight key, so the client can retry at once.
    let LeasedClaim::Claimed { lease_until: held } = tx
        .idempotency()
        .claim_leased(request(token, "cancelled", "a"), Duration::from_secs(600))
        .await?
    else {
        checks.fail("a free key is claimed");
        return Ok(());
    };
    tx.idempotency().release_leased(token, "cancelled", held).await?;
    checks.that(
        matches!(
            tx.idempotency()
                .claim_leased(request(token, "cancelled", "b"), Duration::from_secs(600))
                .await?,
            LeasedClaim::Claimed { .. }
        ),
        "a key released by its claimant is free again",
    );
    tx.commit().await?;
    Ok(())
}
