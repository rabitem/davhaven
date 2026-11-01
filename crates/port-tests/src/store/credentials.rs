//! Cases of credentials: app passwords, API tokens, feed tokens, RSVP tokens and the lookup by prefix.

use davhaven_domain::{
    CalendarUserAddress, CredentialKind, CredentialRef, PartStat, PrincipalStatus, Scope, ScopeSet, TenantStatus,
    TokenKind,
};
use davhaven_ports::store::ApiTokenFilter;
use davhaven_ports::{CredentialRecord, CredentialUse, Expected, PageReq, Rehash, StoredHash, UniqueKey};

use super::Outcome;
use super::world::{
    Db, StoreChecks, api_token, app_password, at, begin, far_future, feed_token, id, key, rsvp_token, scheduling, seed,
    system, version,
};
use crate::suite::Checks;

/// App passwords and API tokens: creation, revocation, listing, uniqueness.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn app_passwords_and_api_tokens(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let created = tx
        .credentials()
        .create_app_password(app_password(0x701, world.mia, "abcd-efgh"))
        .await?;
    checks.equal(&created.version, &1, "a new app password has version 1");
    checks.equal(&created.tenant_id, &world.a, "bound to the tenant of the transaction");
    checks.equal(&created.hash, &vec![1, 2, 3], "the keyed hash is stored as given");
    checks.equal(&created.last_used_at, &None, "never used");
    checks.equal(&tx.credentials().get_app_password(created.id).await?, &created, "get");
    checks.equal(
        &tx.credentials().list_app_passwords(world.mia).await?,
        &vec![created.clone()],
        "the app passwords of a principal",
    );
    checks.equal(
        &tx.credentials().list_app_passwords(world.olivia).await?,
        &Vec::new(),
        "none for another principal",
    );
    checks.unique(
        tx.credentials()
            .create_app_password(app_password(0x702, world.olivia, "abcd-efgh"))
            .await,
        UniqueKey::CredentialPrefix,
        "a duplicate prefix",
    );
    checks.not_found(
        tx.credentials()
            .create_app_password(app_password(0x703, id(0x999), "zzzz-zzzz"))
            .await,
        "an app password of an unknown principal",
    );
    checks.not_found(
        tx.credentials().get_app_password(id(0x999)).await,
        "an unknown app password",
    );
    tx.credentials().revoke_app_password(created.id).await?;
    let revoked = tx.credentials().get_app_password(created.id).await?;
    checks.that(revoked.revoked_at.is_some(), "a revoked app password stays, stamped");
    checks.equal(&revoked.version, &2, "revoking bumps the version");
    tx.credentials().revoke_app_password(created.id).await?;
    let again = tx.credentials().get_app_password(created.id).await?;
    checks.equal(
        &again.revoked_at,
        &revoked.revoked_at,
        "revoking again keeps the first revocation time",
    );
    checks.equal(&again.version, &2, "and the version");
    checks.not_found(
        tx.credentials().revoke_app_password(id(0x999)).await,
        "revoking an unknown app password",
    );

    let mut tenant_token = api_token(0x710, TokenKind::Tenant, None, "tenanttoken1");
    tenant_token.scopes = ScopeSet::of(&[Scope::EventsRead, Scope::EventsWrite]);
    tenant_token.expires_at = Some(far_future());
    let tenant_token = tx.credentials().create_api_token(tenant_token).await?;
    checks.equal(
        &tenant_token.tenant_id,
        &Some(world.a),
        "a tenant token belongs to the tenant",
    );
    checks.equal(
        &tenant_token.scopes,
        &ScopeSet::of(&[Scope::EventsRead, Scope::EventsWrite]),
        "the scopes round-trip",
    );
    checks.equal(&tenant_token.expires_at, &Some(far_future()), "the expiry");
    checks.equal(
        &tenant_token.allowed_origins,
        &vec!["https://example.org".to_owned()],
        "the allowed origins",
    );
    let principal_token = tx
        .credentials()
        .create_api_token(api_token(0x711, TokenKind::Principal, Some(world.mia), "principaltok1"))
        .await?;
    checks.equal(
        &principal_token.principal_id,
        &Some(world.mia),
        "a principal token acts as its principal",
    );
    checks.equal(
        &tx.credentials().get_api_token(tenant_token.id).await?,
        &tenant_token,
        "get",
    );
    checks.internal(
        tx.credentials()
            .create_api_token(api_token(0x712, TokenKind::System, None, "systemtoken1"))
            .await,
        "a system token through a tenant transaction",
    );
    checks.unique(
        tx.credentials()
            .create_api_token(api_token(0x713, TokenKind::Tenant, None, "tenanttoken1"))
            .await,
        UniqueKey::CredentialPrefix,
        "a duplicate token prefix",
    );
    checks.not_found(
        tx.credentials()
            .create_api_token(api_token(0x714, TokenKind::Principal, Some(id(0x999)), "ghosttoken01"))
            .await,
        "a token of an unknown principal",
    );
    let by_principal = tx
        .credentials()
        .list_api_tokens(
            &ApiTokenFilter {
                principal: Some(world.mia),
                ..ApiTokenFilter::default()
            },
            PageReq::default(),
        )
        .await?;
    checks.equal(
        &by_principal.items,
        &vec![principal_token.clone()],
        "the principal filter",
    );
    let by_kind = tx
        .credentials()
        .list_api_tokens(
            &ApiTokenFilter {
                kind: Some(TokenKind::Tenant),
                ..ApiTokenFilter::default()
            },
            PageReq::default(),
        )
        .await?;
    checks.equal(&by_kind.items, &vec![tenant_token.clone()], "the kind filter");
    tx.credentials().revoke_api_token(tenant_token.id).await?;
    let live = tx
        .credentials()
        .list_api_tokens(&ApiTokenFilter::default(), PageReq::default())
        .await?;
    checks.equal(&live.items.len(), &1, "revoked tokens are excluded by default");
    let everything = tx
        .credentials()
        .list_api_tokens(
            &ApiTokenFilter {
                include_revoked: true,
                ..ApiTokenFilter::default()
            },
            PageReq::first(1),
        )
        .await?;
    checks.equal(&everything.items.len(), &1, "a page of one");
    checks.that(everything.next.is_some(), "with a cursor");
    let first_revocation = tx.credentials().get_api_token(tenant_token.id).await?.revoked_at;
    tx.credentials().revoke_api_token(tenant_token.id).await?;
    checks.equal(
        &tx.credentials().get_api_token(tenant_token.id).await?.revoked_at,
        &first_revocation,
        "revoking a token again keeps the first revocation time",
    );
    checks.not_found(tx.credentials().get_api_token(id(0x999)).await, "an unknown token");
    checks.not_found(
        tx.credentials().revoke_api_token(id(0x999)).await,
        "revoking an unknown token",
    );
    tx.commit().await?;
    Ok(())
}

/// Feed tokens, revoking everything of a principal, and recording uses.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn feed_tokens_and_usage(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let feed = tx
        .credentials()
        .create_feed_token(feed_token(
            0x721,
            world.mia,
            vec![world.personal, world.shared],
            "feedtoken001",
        ))
        .await?;
    checks.equal(
        &feed.calendar_ids,
        &vec![world.personal, world.shared],
        "the calendars of the feed",
    );
    checks.equal(&feed.tenant_id, &world.a, "bound to the tenant of the transaction");
    checks.equal(&tx.credentials().get_feed_token(feed.id).await?, &feed, "get");
    checks.equal(
        &tx.credentials().list_feed_tokens(world.mia).await?,
        &vec![feed.clone()],
        "list",
    );
    checks.not_found(
        tx.credentials()
            .create_feed_token(feed_token(
                0x722,
                world.mia,
                vec![world.personal, id(0x999)],
                "feedtoken002",
            ))
            .await,
        "a feed of an unknown calendar",
    );
    checks.not_found(
        tx.credentials()
            .create_feed_token(feed_token(0x723, id(0x999), vec![world.personal], "feedtoken003"))
            .await,
        "a feed of an unknown principal",
    );
    checks.unique(
        tx.credentials()
            .create_feed_token(feed_token(0x724, world.mia, vec![world.personal], "feedtoken001"))
            .await,
        UniqueKey::CredentialPrefix,
        "a duplicate feed prefix",
    );
    checks.not_found(
        tx.credentials().get_feed_token(id(0x999)).await,
        "an unknown feed token",
    );

    let password = tx
        .credentials()
        .create_app_password(app_password(0x701, world.mia, "abcd-efgh"))
        .await?;
    let token = tx
        .credentials()
        .create_api_token(api_token(0x711, TokenKind::Principal, Some(world.mia), "principaltok1"))
        .await?;
    let tenant_wide = tx
        .credentials()
        .create_api_token(api_token(0x710, TokenKind::Tenant, None, "tenanttoken1"))
        .await?;
    checks.equal(
        &tx.credentials().revoke_all_for_principal(world.mia).await?,
        &3,
        "an app password, a principal token and a feed token are revoked",
    );
    checks.equal(
        &tx.credentials().revoke_all_for_principal(world.mia).await?,
        &0,
        "and only newly revoked ones count",
    );
    checks.that(
        tx.credentials().get_feed_token(feed.id).await?.revoked_at.is_some(),
        "the feed token is revoked",
    );
    checks.that(
        tx.credentials()
            .get_app_password(password.id)
            .await?
            .revoked_at
            .is_some(),
        "the app password is revoked",
    );
    checks.that(
        tx.credentials().get_api_token(token.id).await?.revoked_at.is_some(),
        "the principal token is revoked",
    );
    checks.that(
        tx.credentials()
            .get_api_token(tenant_wide.id)
            .await?
            .revoked_at
            .is_none(),
        "a tenant token is not a token of the principal",
    );

    let fresh = tx
        .credentials()
        .create_app_password(app_password(0x702, world.olivia, "ijkl-mnop"))
        .await?;
    let used = |kind: CredentialKind, id: uuid::Uuid, hour: u32| CredentialUse { kind, id, at: at(hour) };
    let changed = tx
        .credentials()
        .touch_last_used(&[
            used(CredentialKind::AppPassword, fresh.id.as_uuid(), 10),
            used(CredentialKind::AppPassword, fresh.id.as_uuid(), 12),
            used(CredentialKind::AppPassword, fresh.id.as_uuid(), 11),
            used(CredentialKind::ApiToken, tenant_wide.id.as_uuid(), 9),
            used(CredentialKind::FeedToken, feed.id.as_uuid(), 9),
            used(CredentialKind::AppPassword, super::world::uuid(0x999), 9),
        ])
        .await?;
    checks.equal(
        &changed,
        &2,
        "one change per credential that has a last use: feed tokens and unknown ids are ignored",
    );
    let after = tx.credentials().get_app_password(fresh.id).await?;
    checks.equal(&after.last_used_at, &Some(at(12)), "the latest use of a batch wins");
    checks.equal(
        &after.version,
        &fresh.version,
        "recording a use does not change the version",
    );
    checks.equal(&after.updated_at, &fresh.updated_at, "or the update time");
    checks.equal(
        &tx.credentials()
            .touch_last_used(&[used(CredentialKind::AppPassword, fresh.id.as_uuid(), 8)])
            .await?,
        &0,
        "an older use changes nothing",
    );
    checks.equal(
        &tx.credentials().get_app_password(fresh.id).await?.last_used_at,
        &Some(at(12)),
        "and the stored value is kept",
    );
    checks.equal(
        &tx.credentials()
            .touch_last_used(&[used(CredentialKind::AppPassword, fresh.id.as_uuid(), 13)])
            .await?,
        &1,
        "a newer use is recorded",
    );
    checks.equal(&tx.credentials().touch_last_used(&[]).await?, &0, "an empty batch");
    tx.commit().await?;
    Ok(())
}

/// Moving a credential to another pepper key (re-hash on use): the swap is compare-and-set on the key id, touches
/// nothing but the hash and its key id, and never reaches a credential of another tenant.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn credential_rehash(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let password = tx
        .credentials()
        .create_app_password(app_password(0x7a1, world.mia, "rhsh-aaaa"))
        .await?;
    let mut tenant_token = api_token(0x7a2, TokenKind::Tenant, None, "rehashtoken1");
    tenant_token.scopes = ScopeSet::of(&[Scope::EventsRead]);
    let tenant_token = tx.credentials().create_api_token(tenant_token).await?;
    let feed = tx
        .credentials()
        .create_feed_token(feed_token(0x7a3, world.mia, vec![world.personal], "rehashfeed01"))
        .await?;
    let object = tx
        .objects()
        .put(
            world.personal,
            scheduling(
                version(0x4E1, "rehash.ics", "rehash")?,
                "mailto:olivia@example.org",
                &[("mailto:x@example.org", None)],
            )?,
            Expected::Absent,
        )
        .await?
        .object_id;
    let rsvp = tx
        .rsvp()
        .create(rsvp_token(0x7a4, object, "mailto:x@example.org", "rehash-rsvp1")?)
        .await?;

    let swap = |kind: CredentialKind, id: uuid::Uuid, from: &str, to: &str, hash: u8| Rehash {
        credential: CredentialRef { kind, id },
        from_kid: from.to_owned(),
        to: StoredHash::new(kind, to, vec![hash; 4]),
    };
    checks.equal(
        &tx.credentials()
            .rehash(&swap(
                CredentialKind::AppPassword,
                password.id.as_uuid(),
                "k1",
                "k2",
                0x11,
            ))
            .await?,
        &true,
        "an app password under the named key is re-hashed",
    );
    let after = tx.credentials().get_app_password(password.id).await?;
    checks.equal(&after.hash, &vec![0x11; 4], "the new hash is stored");
    checks.equal(&after.pepper_kid, &"k2".to_owned(), "with the id of its key");
    checks.equal(
        &(
            after.version,
            after.updated_at,
            after.last_used_at,
            after.revoked_at,
            after.prefix.clone(),
        ),
        &(
            password.version,
            password.updated_at,
            password.last_used_at,
            password.revoked_at,
            password.prefix.clone(),
        ),
        "nothing else of the credential changes: not the version, the update time or the prefix",
    );
    checks.equal(
        &tx.credentials()
            .rehash(&swap(
                CredentialKind::AppPassword,
                password.id.as_uuid(),
                "k1",
                "k3",
                0x22,
            ))
            .await?,
        &false,
        "a hash that no longer names the key it was read under is left alone (another request was first)",
    );
    checks.equal(
        &tx.credentials().get_app_password(password.id).await?.hash,
        &vec![0x11; 4],
        "and keeps the first re-hash",
    );
    checks.equal(
        &tx.credentials()
            .rehash(&swap(
                CredentialKind::AppPassword,
                password.id.as_uuid(),
                "k2",
                "k3",
                0x33,
            ))
            .await?,
        &true,
        "a credential can move again, to a newer key",
    );

    checks.equal(
        &tx.credentials()
            .rehash(&swap(
                CredentialKind::ApiToken,
                tenant_token.id.as_uuid(),
                "k1",
                "k2",
                0x44,
            ))
            .await?,
        &true,
        "an API token is re-hashed",
    );
    let token_after = tx.credentials().get_api_token(tenant_token.id).await?;
    checks.equal(
        &(
            token_after.hash,
            token_after.pepper_kid,
            token_after.scopes,
            token_after.version,
        ),
        &(
            vec![0x44; 4],
            "k2".to_owned(),
            tenant_token.scopes,
            tenant_token.version,
        ),
        "with its scopes and version as they were",
    );
    checks.equal(
        &tx.credentials()
            .rehash(&swap(CredentialKind::FeedToken, feed.id.as_uuid(), "k1", "k2", 0x55))
            .await?,
        &true,
        "a feed token is re-hashed",
    );
    checks.equal(
        &tx.credentials().get_feed_token(feed.id).await?.hash,
        &vec![0x55; 4],
        "the feed token has the new hash",
    );
    checks.equal(
        &tx.credentials()
            .rehash(&swap(CredentialKind::RsvpToken, rsvp.id.as_uuid(), "k1", "k2", 0x66))
            .await?,
        &true,
        "an RSVP token is re-hashed",
    );
    checks.equal(
        &tx.rsvp().get(rsvp.id).await?.hash,
        &vec![0x66; 4],
        "the RSVP token has the new hash",
    );

    checks.equal(
        &tx.credentials()
            .rehash(&swap(
                CredentialKind::AppPassword,
                super::world::uuid(0x999),
                "k1",
                "k2",
                0x77,
            ))
            .await?,
        &false,
        "an unknown credential is not an error",
    );
    checks.equal(
        &tx.credentials()
            .rehash(&swap(CredentialKind::ApiToken, password.id.as_uuid(), "k3", "k4", 0x88))
            .await?,
        &false,
        "an id of another kind of credential is unknown to this one",
    );

    tx.credentials().revoke_app_password(password.id).await?;
    checks.equal(
        &tx.credentials()
            .rehash(&swap(
                CredentialKind::AppPassword,
                password.id.as_uuid(),
                "k3",
                "k4",
                0x99,
            ))
            .await?,
        &true,
        "a revoked credential keeps its record under the active key like any other",
    );
    checks.that(
        tx.credentials()
            .get_app_password(password.id)
            .await?
            .revoked_at
            .is_some(),
        "and stays revoked",
    );
    tx.commit().await?;

    // The lookup before the tenant is known shows the new key id: this is what the authenticator reads next.
    let mut system = system(db).await?;
    let found = system
        .credential_lookup()
        .find_by_prefix(CredentialKind::AppPassword, "rhsh-aaaa")
        .await?;
    let found_kid = found.as_ref().map(|looked| match &looked.record {
        CredentialRecord::AppPassword(password) => password.pepper_kid.clone(),
        _ => String::new(),
    });
    checks.equal(
        &found_kid,
        &Some("k4".to_owned()),
        "the lookup by prefix sees the new key id",
    );
    drop(system);

    // Another tenant's credentials cannot be re-hashed.
    let mut other = begin(db, world.b).await?;
    checks.equal(
        &other
            .credentials()
            .rehash(&swap(
                CredentialKind::AppPassword,
                password.id.as_uuid(),
                "k4",
                "k5",
                0xaa,
            ))
            .await?,
        &false,
        "a transaction of another tenant re-hashes nothing",
    );
    drop(other);
    let mut tx = begin(db, world.a).await?;
    checks.equal(
        &tx.credentials().get_app_password(password.id).await?.pepper_kid,
        &"k4".to_owned(),
        "and the credential is as it was",
    );
    Ok(())
}

/// Looking credentials up by prefix, before the tenant is known, with the facts authentication needs.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn credential_lookup(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    tx.credentials()
        .create_app_password(app_password(0x701, world.mia, "mia-pass-1"))
        .await?;
    tx.credentials()
        .create_api_token(api_token(0x710, TokenKind::Tenant, None, "tenanttoken1"))
        .await?;
    tx.credentials()
        .create_api_token(api_token(0x711, TokenKind::Principal, Some(world.mia), "principaltok1"))
        .await?;
    tx.credentials()
        .create_feed_token(feed_token(0x721, world.mia, vec![world.personal], "feedtoken001"))
        .await?;
    let meeting = scheduling(
        version(0x4C1, "m.ics", "meeting")?,
        "mailto:olivia@example.org",
        &[("mailto:x@example.org", None)],
    )?;
    let written = tx.objects().put(world.personal, meeting, Expected::Absent).await?;
    tx.rsvp()
        .create(rsvp_token(
            0x731,
            written.object_id,
            "mailto:x@example.org",
            "rsvptoken001",
        )?)
        .await?;
    tx.principals().bump_credential_generation(world.mia).await?;
    tx.commit().await?;

    let mut sys = system(db).await?;
    let mut system_token = api_token(0x7F0, TokenKind::System, None, "systemtoken1");
    system_token.scopes = ScopeSet::of(&[Scope::SystemTenants]);
    let system_token = sys.credential_lookup().create_system_token(system_token).await?;
    checks.equal(&system_token.tenant_id, &None, "a system token belongs to no tenant");
    checks.equal(&system_token.kind, &TokenKind::System, "of kind system");
    checks.internal(
        sys.credential_lookup()
            .create_system_token(api_token(0x7F1, TokenKind::Tenant, None, "tenanttoken9"))
            .await,
        "a tenant token through the system repository",
    );
    checks.unique(
        sys.credential_lookup()
            .create_system_token(api_token(0x7F2, TokenKind::System, None, "tenanttoken1"))
            .await,
        UniqueKey::CredentialPrefix,
        "a system token with the prefix of a tenant token",
    );

    let found = sys
        .credential_lookup()
        .find_by_prefix(CredentialKind::AppPassword, "mia-pass-1")
        .await?;
    let found = found.ok_or_else(|| davhaven_ports::StoreError::internal("the app password was not found"))?;
    checks.equal(
        &found.record.kind(),
        &CredentialKind::AppPassword,
        "the kind of the record",
    );
    checks.equal(&found.record.tenant_id(), &Some(world.a), "its tenant");
    checks.equal(&found.record.principal_id(), &Some(world.mia), "its principal");
    checks.equal(&found.tenant_status, &Some(TenantStatus::Active), "the tenant status");
    checks.equal(
        &found.principal_status,
        &Some(PrincipalStatus::Active),
        "the principal status",
    );
    checks.equal(
        &found.credential_generation,
        &Some(1),
        "the credential generation of the principal",
    );
    checks.equal(
        &found.owner.as_ref().map(|owner| {
            (
                owner.tenant_slug.as_str(),
                owner.login_domain.as_ref().map(davhaven_domain::DomainName::as_str),
                owner
                    .principal_name
                    .as_ref()
                    .map(davhaven_domain::PrincipalName::as_str),
            )
        }),
        &Some(("acme", Some("acme.example"), Some("mia"))),
        "the names of its tenant and principal, so that a login can be compared in the same query",
    );

    let tenant_token = sys
        .credential_lookup()
        .find_by_prefix(CredentialKind::ApiToken, "tenanttoken1")
        .await?;
    checks.equal(
        &tenant_token.map(|found| (found.tenant_status, found.principal_status, found.credential_generation)),
        &Some((Some(TenantStatus::Active), None, None)),
        "a tenant token has no principal facts",
    );
    let tenant_token = sys
        .credential_lookup()
        .find_by_prefix(CredentialKind::ApiToken, "tenanttoken1")
        .await?;
    checks.equal(
        &tenant_token.and_then(|found| {
            found
                .owner
                .map(|owner| (owner.tenant_slug.as_str().to_owned(), owner.principal_name))
        }),
        &Some(("acme".to_owned(), None)),
        "a tenant token knows its tenant by name and has no principal name",
    );
    let principal_token = sys
        .credential_lookup()
        .find_by_prefix(CredentialKind::ApiToken, "principaltok1")
        .await?;
    checks.equal(
        &principal_token.map(|found| (found.principal_status, found.credential_generation)),
        &Some((Some(PrincipalStatus::Active), Some(1))),
        "a principal token has them",
    );
    let system_found = sys
        .credential_lookup()
        .find_by_prefix(CredentialKind::ApiToken, "systemtoken1")
        .await?;
    checks.equal(
        &system_found.map(|found| {
            (
                found.tenant_status,
                found.principal_status,
                found.record.tenant_id(),
                found.owner,
            )
        }),
        &Some((None, None, None, None)),
        "a system token has no tenant and no principal",
    );
    let feed = sys
        .credential_lookup()
        .find_by_prefix(CredentialKind::FeedToken, "feedtoken001")
        .await?;
    checks.equal(
        &feed.map(|found| matches!(found.record, CredentialRecord::FeedToken(_)) && found.principal_status.is_some()),
        &Some(true),
        "a feed token",
    );
    let rsvp = sys
        .credential_lookup()
        .find_by_prefix(CredentialKind::RsvpToken, "rsvptoken001")
        .await?;
    checks.equal(
        &rsvp.map(|found| (found.tenant_status, found.principal_status)),
        &Some((Some(TenantStatus::Active), None)),
        "an RSVP token has a tenant but no principal",
    );
    checks.equal(
        &sys.credential_lookup()
            .find_by_prefix(CredentialKind::AppPassword, "unknown")
            .await?
            .is_none(),
        &true,
        "an unknown prefix",
    );
    checks.equal(
        &sys.credential_lookup()
            .find_by_prefix(CredentialKind::ApiToken, "mia-pass-1")
            .await?
            .is_none(),
        &true,
        "a prefix of another kind of credential",
    );

    let listed = sys.credential_lookup().list_system_tokens().await?;
    checks.equal(
        &listed.iter().map(|token| token.id).collect::<Vec<_>>(),
        &vec![system_token.id],
        "the system tokens",
    );
    sys.credential_lookup().revoke_system_token(system_token.id).await?;
    let first = sys.credential_lookup().list_system_tokens().await?;
    sys.credential_lookup().revoke_system_token(system_token.id).await?;
    let second = sys.credential_lookup().list_system_tokens().await?;
    checks.that(
        first.first().is_some_and(|token| token.revoked_at.is_some()),
        "a revoked system token stays",
    );
    checks.equal(
        &second.first().map(|token| token.revoked_at),
        &first.first().map(|token| token.revoked_at),
        "revoking again keeps the first revocation time",
    );
    checks.not_found(
        sys.credential_lookup().revoke_system_token(id(0x999)).await,
        "revoking an unknown system token",
    );

    // Suspending the tenant and the principal shows in the lookup.
    let acme = sys.tenants().get(world.a).await?;
    let mut suspended = acme.clone();
    suspended.status = TenantStatus::Suspended;
    sys.tenants().update(suspended, acme.version).await?;
    let after = sys
        .credential_lookup()
        .find_by_prefix(CredentialKind::AppPassword, "mia-pass-1")
        .await?;
    checks.equal(
        &after.map(|found| found.tenant_status),
        &Some(Some(TenantStatus::Suspended)),
        "a suspended tenant",
    );
    sys.commit().await?;

    let mut tenant_tx = begin(db, world.a).await?;
    checks.not_found(
        tenant_tx.credentials().get_api_token(system_token.id).await,
        "a tenant cannot read a system token",
    );
    let visible = tenant_tx
        .credentials()
        .list_api_tokens(&ApiTokenFilter::default(), PageReq::default())
        .await?;
    checks.equal(
        &visible.items.len(),
        &2,
        "and its token list holds the tenant's own tokens only",
    );
    Ok(())
}

/// RSVP tokens.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn rsvp_tokens(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let meeting = |n: u128, uri: &str, uid: &str| {
        scheduling(
            version(n, uri, uid)?,
            "mailto:olivia@example.org",
            &[("mailto:x@example.org", None), ("mailto:y@example.org", None)],
        )
    };
    let first = tx
        .objects()
        .put(world.personal, meeting(0x4D1, "1.ics", "m1")?, Expected::Absent)
        .await?
        .object_id;
    let second = tx
        .objects()
        .put(world.personal, meeting(0x4D2, "2.ics", "m2")?, Expected::Absent)
        .await?
        .object_id;
    let x = key(CalendarUserAddress::parse("mailto:x@example.org"))?;
    let y = key(CalendarUserAddress::parse("mailto:y@example.org"))?;
    let tx1 = tx
        .rsvp()
        .create(rsvp_token(0x731, first, "mailto:x@example.org", "rsvp-x-1")?)
        .await?;
    let ty1 = tx
        .rsvp()
        .create(rsvp_token(0x732, first, "mailto:y@example.org", "rsvp-y-1")?)
        .await?;
    let tx2 = tx
        .rsvp()
        .create(rsvp_token(0x733, second, "mailto:x@example.org", "rsvp-x-2")?)
        .await?;
    checks.equal(&tx1.version, &1, "a new token has version 1");
    checks.equal(&tx1.tenant_id, &world.a, "bound to the tenant of the transaction");
    checks.equal(&tx.rsvp().get(tx1.id).await?, &tx1, "get");
    checks.equal(
        &tx.rsvp().for_object(first).await?,
        &vec![tx1.clone(), ty1.clone()],
        "the tokens of an invitation in id order",
    );
    checks.equal(
        &tx.rsvp().find_live(first, &x).await?,
        &Some(tx1.clone()),
        "the live token of an attendee",
    );
    checks.unique(
        tx.rsvp()
            .create(rsvp_token(0x734, first, "mailto:x@example.org", "rsvp-x-1")?)
            .await,
        UniqueKey::CredentialPrefix,
        "a duplicate prefix",
    );
    checks.not_found(
        tx.rsvp()
            .create(rsvp_token(0x735, id(0x999), "mailto:x@example.org", "rsvp-zz")?)
            .await,
        "a token for an unknown object",
    );
    checks.not_found(tx.rsvp().get(id(0x999)).await, "an unknown token");

    tx.rsvp().record_use(tx1.id, Some(PartStat::Accepted)).await?;
    tx.rsvp().record_use(tx1.id, None).await?;
    let used = tx.rsvp().get(tx1.id).await?;
    checks.that(used.last_used_at.is_some(), "a use is recorded");
    checks.equal(
        &used.last_response,
        &Some(PartStat::Accepted),
        "a use without an answer keeps the last answer",
    );
    checks.not_found(tx.rsvp().record_use(id(0x999), None).await, "a use of an unknown token");

    tx.rsvp().revoke(tx1.id).await?;
    let revoked = tx.rsvp().get(tx1.id).await?;
    checks.that(revoked.revoked_at.is_some(), "revoking stamps the token");
    tx.rsvp().revoke(tx1.id).await?;
    checks.equal(
        &tx.rsvp().get(tx1.id).await?.revoked_at,
        &revoked.revoked_at,
        "the first revocation time is kept",
    );
    checks.equal(
        &tx.rsvp().find_live(first, &x).await?,
        &None,
        "a revoked token is not live",
    );
    checks.not_found(tx.rsvp().revoke(id(0x999)).await, "revoking an unknown token");

    checks.equal(
        &tx.rsvp().revoke_for_attendee(first, &y).await?,
        &1,
        "revoking the tokens of one attendee",
    );
    checks.equal(
        &tx.rsvp().revoke_for_attendee(first, &y).await?,
        &0,
        "only newly revoked tokens count",
    );
    checks.equal(
        &tx.rsvp().revoke_for_object(first).await?,
        &0,
        "everything of the invitation is revoked already",
    );
    checks.equal(
        &tx.rsvp().revoke_for_address(&x).await?,
        &1,
        "revoking by address reaches the other invitation",
    );
    checks.that(tx.rsvp().get(tx2.id).await?.revoked_at.is_some(), "and revokes it");
    let third = tx
        .rsvp()
        .create(rsvp_token(0x736, second, "mailto:y@example.org", "rsvp-y-2")?)
        .await?;
    checks.equal(
        &tx.rsvp().revoke_for_object(second).await?,
        &1,
        "revoking everything of an invitation",
    );
    checks.that(
        tx.rsvp().get(third.id).await?.revoked_at.is_some(),
        "revokes its tokens",
    );
    tx.commit().await?;
    Ok(())
}
