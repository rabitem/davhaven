//! Credentials and authentication: server-generated secrets shown once and stored as keyed hashes, scopes that
//! can only shrink, feed tokens, client configuration and the authenticator chain with its failure backoff.

use std::net::IpAddr;

use davhaven_testkit::davhaven_app::error::AppError;
use davhaven_testkit::davhaven_app::services::{
    AuthRequest, ClientConfigKind, ClientConfigResponse, PageRequest, PresentedCredential, SecretString,
};
use davhaven_testkit::davhaven_domain::{
    Actor, CalendarKind, Channel, CredentialKind, CredentialRef, ErrorKind, FeedMode, RequestContext, RequestId, Scope,
    ScopeSet, TenantId, TokenId, TokenKind,
};
use davhaven_testkit::davhaven_ports::{AuthOutcome, Authenticated, PortError, RejectReason};
use davhaven_testkit::davhaven_wire::{ApiTokenCreate, AppPasswordCreate, ClientConfigRequest, FeedTokenCreate};
use chrono::Duration;
use uuid::Uuid;

use super::support::{Fixture, Org, Person, World, fixture};

fn is_app_password(text: &str) -> bool {
    let groups: Vec<&str> = text.split('-').collect();
    groups.len() == 9
        && groups.iter().all(|group| {
            group.len() == 4
                && group
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
        })
}

fn is_token(text: &str, kind: &str) -> bool {
    let rest = text.strip_prefix(&format!("dvh_{kind}_"));
    let Some((prefix, secret)) = rest.and_then(|rest| rest.split_once('_')) else {
        return false;
    };
    let url_safe = |text: &str| {
        text.bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    };
    prefix.len() == 12 && secret.len() == 43 && url_safe(prefix) && url_safe(secret)
}

fn is_ics(url: &str) -> bool {
    std::path::Path::new(url)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("ics"))
}

fn secret(text: &str) -> SecretString {
    SecretString::from(text.to_owned())
}

async fn generation(world: &World, org: &Org, who: &Person) -> i32 {
    world
        .read(org)
        .await
        .principals()
        .get(who.id)
        .await
        .unwrap()
        .credential_generation
}

fn creator(world: &World, org: &Org, scopes: &[Scope]) -> RequestContext {
    world.tenant_token(org, ScopeSet::of(scopes))
}

#[tokio::test]
async fn an_app_password_is_generated_shown_once_and_stored_only_as_a_keyed_hash() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let admin = world.admin(&acme);
    let created = world
        .services
        .credentials
        .create_app_password(
            &admin,
            &anna.name,
            AppPasswordCreate {
                label: "  iPhone ".to_owned(),
            },
        )
        .await
        .unwrap();
    assert!(
        is_app_password(&created.password),
        "nine groups of four base32 characters: {}",
        created.password
    );
    assert_eq!(created.label, "iPhone");
    assert_eq!(
        created.prefix,
        created.password.split('-').take(2).collect::<Vec<_>>().join("-"),
        "found by the first two groups"
    );
    assert!(!format!("{created:?}").contains(&created.password));

    // The store holds a keyed hash of the secret, found by prefix, never the secret.
    let row = world
        .read(&acme)
        .await
        .credentials()
        .get_app_password(created.id)
        .await
        .unwrap();
    let expected = world
        .core
        .deps()
        .hasher
        .hash(CredentialKind::AppPassword, &secret(&created.password));
    assert_eq!(row.hash, expected.hash);
    assert_eq!(row.pepper_kid, expected.pepper_kid);
    assert_eq!(row.prefix, created.prefix);
    assert_eq!(row.principal_id, anna.id);
    assert!(row.revoked_at.is_none() && row.last_used_at.is_none());

    // The listing never shows the secret, and secrets are different every time.
    let listed = world
        .services
        .credentials
        .list_app_passwords(&admin, &anna.name, PageRequest::first())
        .await
        .unwrap();
    assert_eq!(listed.items.len(), 1);
    assert_eq!(listed.items[0].id, created.id);
    assert!(!format!("{listed:?}").contains(&created.password));
    let second = world
        .services
        .credentials
        .create_app_password(
            &admin,
            &anna.name,
            AppPasswordCreate {
                label: "Laptop".to_owned(),
            },
        )
        .await
        .unwrap();
    assert_ne!(second.password, created.password);
    assert_ne!(second.prefix, created.prefix);

    // The audit log records the creation by id and kind, without the secret.
    let audit = world.audit(&acme).await;
    let rows: Vec<_> = audit.iter().filter(|row| row.action == "credential.created").collect();
    assert_eq!(rows.len(), 2);
    let text = format!("{rows:?}");
    assert!(
        !text.contains(&created.password) && !text.contains(&second.password),
        "{text}"
    );
    assert!(text.contains(&created.id.to_string()), "{text}");
}

#[tokio::test]
async fn app_passwords_have_rules_about_labels_owners_and_who_may_create_them() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    let team = world.group(&acme, "team", &[&anna]).await;
    let admin = world.admin(&acme);
    let create = |ctx: &RequestContext, who: &Person, label: &str| {
        let world = &world;
        let ctx = ctx.clone();
        let who = who.clone();
        let label = label.to_owned();
        async move {
            world
                .services
                .credentials
                .create_app_password(&ctx, &who.name, AppPasswordCreate { label })
                .await
        }
    };
    for bad in ["", "   ", "line\nbreak"] {
        let error = create(&admin, &anna, bad).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Invalid, "{bad:?}");
        assert_eq!(error.field_errors().first().map(|field| field.pointer), Some("/label"));
    }
    assert_eq!(
        create(&admin, &anna, &"x".repeat(101)).await.unwrap_err().kind(),
        ErrorKind::Invalid
    );
    assert_eq!(
        create(&admin, &team, "group").await.unwrap_err().kind(),
        ErrorKind::Invalid,
        "groups do not log in"
    );
    let ghost = Person {
        id: anna.id,
        name: davhaven_testkit::davhaven_domain::PrincipalName::parse("ghost").unwrap(),
    };
    assert_eq!(
        create(&admin, &ghost, "x").await.unwrap_err().kind(),
        ErrorKind::NotFound
    );

    // credentials:write on a tenant token; principals mint nothing for themselves in 1.0.
    let reader = creator(&world, &acme, &[Scope::PrincipalsRead]);
    assert_eq!(
        create(&reader, &anna, "x").await.unwrap_err().kind(),
        ErrorKind::Forbidden
    );
    let own = world.api(&acme, &anna, &[Scope::CalendarsRead, Scope::EventsWrite]);
    assert_eq!(create(&own, &anna, "x").await.unwrap_err().kind(), ErrorKind::Forbidden);
    assert_eq!(
        create(&world.dav(&acme, &anna), &anna, "x").await.unwrap_err().kind(),
        ErrorKind::Forbidden
    );
    let _ = ben;
}

#[tokio::test]
async fn revoking_an_app_password_ends_cached_verifications_and_is_audited_once() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    let admin = world.admin(&acme);
    let created = world
        .services
        .credentials
        .create_app_password(
            &admin,
            &anna.name,
            AppPasswordCreate {
                label: "phone".to_owned(),
            },
        )
        .await
        .unwrap();
    let before = generation(&world, &acme, &anna).await;

    world
        .services
        .credentials
        .revoke_app_password(&admin, &anna.name, created.id)
        .await
        .unwrap();
    let row = world
        .read(&acme)
        .await
        .credentials()
        .get_app_password(created.id)
        .await
        .unwrap();
    assert_eq!(row.revoked_at, Some(world.now()), "revoked at the time of the request");
    assert!(
        generation(&world, &acme, &anna).await > before,
        "a new generation invalidates cached verifications"
    );
    let listed = world
        .services
        .credentials
        .list_app_passwords(&admin, &anna.name, PageRequest::first())
        .await
        .unwrap();
    assert!(
        listed.items[0].revoked_at.is_some(),
        "revoked passwords stay in the list"
    );

    // Revoking again changes nothing, not even the audit log.
    let after = generation(&world, &acme, &anna).await;
    let audits = world.audit_actions(&acme).await;
    world
        .services
        .credentials
        .revoke_app_password(&admin, &anna.name, created.id)
        .await
        .unwrap();
    assert_eq!(generation(&world, &acme, &anna).await, after);
    assert_eq!(world.audit_actions(&acme).await, audits);
    assert_eq!(
        audits.iter().filter(|action| *action == "credential.revoked").count(),
        1
    );

    // Another principal's password and unknown ids do not exist.
    let other = world
        .services
        .credentials
        .create_app_password(
            &admin,
            &ben.name,
            AppPasswordCreate {
                label: "ben".to_owned(),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        world
            .services
            .credentials
            .revoke_app_password(&admin, &anna.name, other.id)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        world
            .services
            .credentials
            .revoke_app_password(
                &admin,
                &anna.name,
                davhaven_testkit::davhaven_domain::CredentialId::from_uuid(Uuid::from_u128(5))
            )
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    assert!(
        world
            .read(&acme)
            .await
            .credentials()
            .get_app_password(other.id)
            .await
            .unwrap()
            .revoked_at
            .is_none()
    );
}

#[tokio::test]
async fn an_api_token_has_the_documented_format_and_is_stored_as_a_hash() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let admin = world.stored_admin(&acme).await;
    let created = world
        .services
        .credentials
        .create_api_token(
            &admin,
            ApiTokenCreate {
                kind: TokenKind::Tenant,
                principal: None,
                label: "provisioning".to_owned(),
                scopes: ScopeSet::of(&[Scope::PrincipalsRead, Scope::PrincipalsWrite]),
                expires_at: None,
                allowed_origins: Vec::new(),
            },
        )
        .await
        .unwrap();
    assert!(is_token(&created.secret, "pat"), "{}", created.secret);
    assert!(created.secret.contains(&created.token.prefix));
    assert_eq!(created.token.kind, TokenKind::Tenant);
    assert_eq!(created.token.principal, None);
    assert_eq!(
        created.token.created_by,
        admin.actor.token(),
        "the token that minted it"
    );
    assert!(!format!("{created:?}").contains(&created.secret));
    let row = world
        .read(&acme)
        .await
        .credentials()
        .get_api_token(created.token.id)
        .await
        .unwrap();
    let secret_part = created.secret.rsplit('_').next().unwrap();
    assert_eq!(
        row.hash,
        world
            .core
            .deps()
            .hasher
            .hash(CredentialKind::ApiToken, &secret(secret_part))
            .hash,
        "the hash covers the secret part"
    );
    assert_eq!(row.tenant_id, Some(acme.id));

    // The listing shows no secrets and includes revoked tokens; the audit log names scopes, not secrets.
    world
        .services
        .credentials
        .create_api_token(
            &admin,
            ApiTokenCreate {
                kind: TokenKind::Principal,
                principal: Some(anna.name.clone()),
                label: "integration".to_owned(),
                scopes: ScopeSet::of(&[Scope::EventsRead]),
                expires_at: None,
                allowed_origins: vec![
                    "https://app.example.org".to_owned(),
                    "https://APP.example.org:443/".to_owned(),
                ],
            },
        )
        .await
        .unwrap();
    let listed = world
        .services
        .credentials
        .list_api_tokens(&admin, PageRequest::first())
        .await
        .unwrap();
    assert_eq!(
        listed.items.len(),
        3,
        "the token that minted them, and the two it minted"
    );
    assert_eq!(listed.items[2].principal, Some(anna.name.clone()));
    assert_eq!(
        listed.items[2].allowed_origins,
        vec!["https://app.example.org".to_owned()],
        "normalized and deduplicated"
    );
    assert!(!format!("{listed:?}").contains(secret_part));
    let audit = world.audit(&acme).await;
    let created_rows: Vec<_> = audit.iter().filter(|row| row.action == "token.created").collect();
    assert_eq!(created_rows.len(), 2);
    assert!(!format!("{created_rows:?}").contains(secret_part));
}

#[tokio::test]
async fn a_token_mints_only_tokens_with_scopes_of_its_own_and_for_its_kind() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let team = world.group(&acme, "team", &[&anna]).await;
    let minter = world
        .stored_token(
            &acme,
            ScopeSet::of(&[Scope::CredentialsWrite, Scope::PrincipalsRead, Scope::EventsRead]),
        )
        .await;
    let create = |kind, principal: Option<&Person>, scopes: &[Scope]| {
        let world = &world;
        let minter = minter.clone();
        let request = ApiTokenCreate {
            kind,
            principal: principal.map(|who| who.name.clone()),
            label: "x".to_owned(),
            scopes: ScopeSet::of(scopes),
            expires_at: None,
            allowed_origins: Vec::new(),
        };
        async move { world.services.credentials.create_api_token(&minter, request).await }
    };

    // A subset, including all of its own, is fine; anything beyond is forbidden.
    assert!(create(TokenKind::Tenant, None, &[Scope::PrincipalsRead]).await.is_ok());
    assert!(
        create(
            TokenKind::Tenant,
            None,
            &[Scope::PrincipalsRead, Scope::EventsRead, Scope::CredentialsWrite]
        )
        .await
        .is_ok()
    );
    let error = create(
        TokenKind::Tenant,
        None,
        &[Scope::PrincipalsRead, Scope::PrincipalsWrite],
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Forbidden);
    assert!(
        error.public_message().as_str().contains("scopes"),
        "{}",
        error.public_message()
    );

    // The rules of the kinds.
    let cases: Vec<(&str, Result<_, AppError>, &str, &str)> = vec![
        (
            "system",
            create(TokenKind::System, None, &[Scope::PrincipalsRead]).await,
            "/kind",
            "not-allowed",
        ),
        (
            "no scopes",
            create(TokenKind::Tenant, None, &[]).await,
            "/scopes",
            "empty",
        ),
        (
            "mcp on a tenant token",
            create(TokenKind::Tenant, None, &[Scope::EventsRead, Scope::McpRead]).await,
            "/scopes",
            "not-allowed",
        ),
        (
            "principal token without principal",
            create(TokenKind::Principal, None, &[Scope::EventsRead]).await,
            "/principal",
            "required",
        ),
        (
            "tenant token with principal",
            create(TokenKind::Tenant, Some(&anna), &[Scope::PrincipalsRead]).await,
            "/principal",
            "not-allowed",
        ),
        (
            "principal token for a group",
            create(TokenKind::Principal, Some(&team), &[Scope::EventsRead]).await,
            "/principal",
            "not-allowed",
        ),
    ];
    for (name, result, pointer, code) in cases {
        let error = result.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Invalid, "{name}");
        let field = error
            .field_errors()
            .first()
            .unwrap_or_else(|| panic!("{name}: {error:?}"));
        assert_eq!((field.pointer, field.code), (pointer, code), "{name}");
    }
    let ghost = Person {
        id: anna.id,
        name: davhaven_testkit::davhaven_domain::PrincipalName::parse("ghost").unwrap(),
    };
    assert_eq!(
        create(TokenKind::Principal, Some(&ghost), &[Scope::EventsRead])
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    // Without credentials:write nothing is minted or listed.
    let reader = creator(&world, &acme, &[Scope::PrincipalsRead]);
    assert_eq!(
        world
            .services
            .credentials
            .list_api_tokens(&reader, PageRequest::first())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Forbidden
    );
    assert_eq!(
        world
            .services
            .credentials
            .create_api_token(
                &world.dav(&acme, &anna),
                ApiTokenCreate {
                    kind: TokenKind::Tenant,
                    principal: None,
                    label: "x".to_owned(),
                    scopes: ScopeSet::of(&[Scope::PrincipalsRead]),
                    expires_at: None,
                    allowed_origins: Vec::new(),
                },
            )
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Forbidden
    );
}

#[tokio::test]
async fn mcp_tokens_need_an_expiry_within_the_configured_lifetime() {
    // MCP is opt-in per tenant: tokens with `mcp:*` scopes are only minted for a tenant that switched it on.
    let world = World::new();
    let acme = world.org_with("acme", |settings| settings.mcp_enabled = true).await;
    let anna = world.user(&acme, "anna").await;
    let admin = world.admin(&acme);
    // Tenant tokens cannot carry MCP scopes, so the minting token here is the server itself.
    let internal = RequestContext::internal(acme.id, RequestId::from_uuid(Uuid::from_u128(1)));
    let _ = admin;
    let now = world.now();
    let request = |scopes: &[Scope], expires_at| ApiTokenCreate {
        kind: TokenKind::Principal,
        principal: Some(anna.name.clone()),
        label: "integration".to_owned(),
        scopes: ScopeSet::of(scopes),
        expires_at,
        allowed_origins: Vec::new(),
    };
    let attempt = |scopes: &'static [Scope], expires_at| {
        let world = &world;
        let internal = internal.clone();
        let body = request(scopes, expires_at);
        async move { world.services.credentials.create_api_token(&internal, body).await }
    };
    let code = |error: &AppError| error.field_errors().first().map(|field| (field.pointer, field.code));

    assert_eq!(
        code(&attempt(&[Scope::McpRead], None).await.unwrap_err()),
        Some(("/expires_at", "required"))
    );
    assert_eq!(
        code(
            &attempt(&[Scope::McpRead], Some(now - Duration::days(1)))
                .await
                .unwrap_err()
        ),
        Some(("/expires_at", "in-the-past"))
    );
    assert_eq!(
        code(
            &attempt(&[Scope::McpWrite], Some(now + Duration::days(91)))
                .await
                .unwrap_err()
        ),
        Some(("/expires_at", "too-far")),
        "the default lifetime limit is 90 days"
    );
    let ok = attempt(&[Scope::McpRead, Scope::EventsRead], Some(now + Duration::days(90)))
        .await
        .unwrap();
    assert_eq!(ok.token.expires_at, Some(now + Duration::days(90)));
    // Tokens without MCP scopes may live forever, but never in the past.
    assert!(attempt(&[Scope::EventsRead], None).await.is_ok());
    assert_eq!(
        code(
            &attempt(&[Scope::EventsRead], Some(now - Duration::seconds(1)))
                .await
                .unwrap_err()
        ),
        Some(("/expires_at", "in-the-past"))
    );
    // The deployment decides how long MCP tokens may live.
    let strict = World::with(|deps| deps.config.max_mcp_token_days = 7);
    let org = strict.org_with("acme", |settings| settings.mcp_enabled = true).await;
    let owner = strict.user(&org, "anna").await;
    let internal = RequestContext::internal(org.id, RequestId::from_uuid(Uuid::from_u128(2)));
    let body = ApiTokenCreate {
        kind: TokenKind::Principal,
        principal: Some(owner.name.clone()),
        label: "integration".to_owned(),
        scopes: ScopeSet::of(&[Scope::McpRead]),
        expires_at: Some(strict.now() + Duration::days(8)),
        allowed_origins: Vec::new(),
    };
    assert_eq!(
        code(
            &strict
                .services
                .credentials
                .create_api_token(&internal, body)
                .await
                .unwrap_err()
        ),
        Some(("/expires_at", "too-far"))
    );
}

#[tokio::test]
async fn mcp_tokens_are_only_minted_for_a_tenant_that_switched_mcp_on() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let internal = RequestContext::internal(acme.id, RequestId::from_uuid(Uuid::from_u128(1)));
    let request = |scopes: &[Scope]| ApiTokenCreate {
        kind: TokenKind::Principal,
        principal: Some(anna.name.clone()),
        label: "assistant".to_owned(),
        scopes: ScopeSet::of(scopes),
        expires_at: Some(world.now() + Duration::days(30)),
        allowed_origins: Vec::new(),
    };
    for scopes in [
        &[Scope::McpRead][..],
        &[Scope::McpWrite],
        &[Scope::EventsRead, Scope::McpScheduleExternal],
    ] {
        let error = world
            .services
            .credentials
            .create_api_token(&internal, request(scopes))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Conflict, "{scopes:?}");
        assert_eq!(
            davhaven_testkit::davhaven_wire::ProblemCode::from_error(error.kind(), error.precondition()).code(),
            "feature-not-enabled",
            "{scopes:?}"
        );
    }
    // Tokens without MCP scopes are not the switch's business.
    let events = ApiTokenCreate {
        expires_at: None,
        ..request(&[Scope::EventsRead])
    };
    assert!(
        world
            .services
            .credentials
            .create_api_token(&internal, events)
            .await
            .is_ok()
    );
    // Once the tenant switches it on, the same request works.
    let on = world.org_with("acme", |settings| settings.mcp_enabled = true).await;
    assert_eq!(on.id, acme.id, "the same tenant, now with MCP");
    assert!(
        world
            .services
            .credentials
            .create_api_token(&internal, request(&[Scope::McpRead]))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn allowed_origins_are_validated_and_normalized() {
    let Fixture { world, acme, .. } = fixture().await;
    let admin = world.stored_admin(&acme).await;
    let create = |origins: Vec<String>| {
        let world = &world;
        let admin = admin.clone();
        async move {
            world
                .services
                .credentials
                .create_api_token(
                    &admin,
                    ApiTokenCreate {
                        kind: TokenKind::Tenant,
                        principal: None,
                        label: "x".to_owned(),
                        scopes: ScopeSet::of(&[Scope::PrincipalsRead]),
                        expires_at: None,
                        allowed_origins: origins,
                    },
                )
                .await
        }
    };
    for bad in [
        "not a url",
        "ftp://example.org",
        "https://example.org/path",
        "https://example.org/?q=1",
        "https://user@example.org",
        "https://example.org#frag",
    ] {
        let error = create(vec![bad.to_owned()]).await.unwrap_err();
        assert_eq!(
            error.field_errors().first().map(|field| field.code),
            Some("invalid-origin"),
            "{bad}"
        );
    }
    let many: Vec<String> = (0..21).map(|index| format!("https://app{index}.example.org")).collect();
    assert_eq!(
        create(many)
            .await
            .unwrap_err()
            .field_errors()
            .first()
            .map(|field| field.code),
        Some("too-many")
    );
    let created = create(vec![
        "http://localhost:8080".to_owned(),
        "https://B.example.org:443".to_owned(),
    ])
    .await
    .unwrap();
    assert_eq!(
        created.token.allowed_origins,
        vec!["http://localhost:8080".to_owned(), "https://b.example.org".to_owned()]
    );
}

#[tokio::test]
async fn revoking_a_token_bumps_the_generation_of_its_principal_and_is_audited_once() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let admin = world.stored_admin(&acme).await;
    let principal_token = world
        .services
        .credentials
        .create_api_token(
            &admin,
            ApiTokenCreate {
                kind: TokenKind::Principal,
                principal: Some(anna.name.clone()),
                label: "integration".to_owned(),
                scopes: ScopeSet::of(&[Scope::EventsRead]),
                expires_at: None,
                allowed_origins: Vec::new(),
            },
        )
        .await
        .unwrap();
    let tenant_token = world
        .services
        .credentials
        .create_api_token(
            &admin,
            ApiTokenCreate {
                kind: TokenKind::Tenant,
                principal: None,
                label: "ops".to_owned(),
                scopes: ScopeSet::of(&[Scope::PrincipalsRead]),
                expires_at: None,
                allowed_origins: Vec::new(),
            },
        )
        .await
        .unwrap();
    let before = generation(&world, &acme, &anna).await;
    world
        .services
        .credentials
        .revoke_api_token(&admin, principal_token.token.id)
        .await
        .unwrap();
    assert!(generation(&world, &acme, &anna).await > before);
    world
        .services
        .credentials
        .revoke_api_token(&admin, tenant_token.token.id)
        .await
        .unwrap();
    let revoked: Vec<_> = world
        .services
        .credentials
        .list_api_tokens(&admin, PageRequest::first())
        .await
        .unwrap()
        .items
        .into_iter()
        .map(|token| token.revoked_at.is_some())
        .collect();
    assert_eq!(
        revoked,
        vec![false, true, true],
        "the minting token itself is not revoked"
    );

    let audits = world.audit_actions(&acme).await;
    world
        .services
        .credentials
        .revoke_api_token(&admin, principal_token.token.id)
        .await
        .unwrap();
    assert_eq!(
        world.audit_actions(&acme).await,
        audits,
        "revoking again records nothing"
    );
    assert_eq!(audits.iter().filter(|action| *action == "token.revoked").count(), 2);
    assert_eq!(
        world
            .services
            .credentials
            .revoke_api_token(&admin, TokenId::from_uuid(Uuid::from_u128(9)))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
}

#[tokio::test]
async fn tokens_of_one_tenant_are_not_visible_in_another() {
    let Fixture { world, acme, .. } = fixture().await;
    let other = world.org("other").await;
    let created = world
        .services
        .credentials
        .create_api_token(
            &world.stored_admin(&acme).await,
            ApiTokenCreate {
                kind: TokenKind::Tenant,
                principal: None,
                label: "ops".to_owned(),
                scopes: ScopeSet::of(&[Scope::PrincipalsRead]),
                expires_at: None,
                allowed_origins: Vec::new(),
            },
        )
        .await
        .unwrap();
    let admin_other = world.admin(&other);
    assert!(
        world
            .services
            .credentials
            .list_api_tokens(&admin_other, PageRequest::first())
            .await
            .unwrap()
            .items
            .is_empty()
    );
    assert_eq!(
        world
            .services
            .credentials
            .revoke_api_token(&admin_other, created.token.id)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    let still = world
        .read(&acme)
        .await
        .credentials()
        .get_api_token(created.token.id)
        .await
        .unwrap();
    assert!(still.revoked_at.is_none());
}

#[tokio::test]
async fn feed_tokens_are_minted_for_readable_calendars_listed_rotated_and_revoked() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    world.calendar(&acme, &anna, "work", CalendarKind::User).await;
    let admin = world.admin(&acme);
    let personal = world
        .services
        .calendars
        .get(&admin, &world.key(&anna, "personal"))
        .await
        .unwrap()
        .id;
    let work = world
        .services
        .calendars
        .get(&admin, &world.key(&anna, "work"))
        .await
        .unwrap()
        .id;
    let bens = world
        .services
        .calendars
        .get(&admin, &world.key(&ben, "personal"))
        .await
        .unwrap()
        .id;
    let create = |who: &Person, mode, ids: Vec<_>| {
        let world = &world;
        let admin = admin.clone();
        let who = who.clone();
        async move {
            world
                .services
                .credentials
                .create_feed_token(
                    &admin,
                    &who.name,
                    FeedTokenCreate {
                        mode,
                        calendar_ids: ids,
                    },
                )
                .await
        }
    };

    let created = create(&anna, FeedMode::Busy, vec![personal, work]).await.unwrap();
    assert_eq!(created.token.mode, FeedMode::Busy);
    assert_eq!(created.token.calendar_ids, vec![personal, work]);
    let url = created.feed_url.as_str();
    assert!(
        url.starts_with("https://cal.example.org/feeds/") && is_ics(url),
        "{url}"
    );
    let token_text = url
        .trim_start_matches("https://cal.example.org/feeds/")
        .trim_end_matches(".ics");
    assert!(is_token(token_text, "feed"), "{token_text}");
    assert!(token_text.contains(&created.token.prefix));
    assert!(!format!("{created:?}").contains(token_text));
    let row = world
        .read(&acme)
        .await
        .credentials()
        .get_feed_token(created.token.id)
        .await
        .unwrap();
    assert_eq!(
        row.hash,
        world
            .core
            .deps()
            .hasher
            .hash(
                CredentialKind::FeedToken,
                &secret(token_text.rsplit('_').next().unwrap())
            )
            .hash
    );

    // Calendars the principal cannot read, none and too many are refused.
    for (name, ids) in [
        ("someone else's", vec![bens]),
        ("none", vec![]),
        ("too many", vec![personal; 51]),
    ] {
        let error = create(&anna, FeedMode::Full, ids).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Invalid, "{name}");
        assert_eq!(
            error.field_errors().first().map(|field| field.pointer),
            Some("/calendar_ids"),
            "{name}"
        );
    }

    // Rotation replaces the secret and keeps what the feed shows; the old one is revoked.
    let rotated = world
        .services
        .credentials
        .rotate_feed_token(&admin, &anna.name, created.token.id)
        .await
        .unwrap();
    assert_ne!(rotated.feed_url, created.feed_url);
    assert_ne!(rotated.token.id, created.token.id);
    assert_eq!(rotated.token.mode, FeedMode::Busy);
    assert_eq!(rotated.token.calendar_ids, vec![personal, work]);
    let listed = world
        .services
        .credentials
        .list_feed_tokens(&admin, &anna.name, PageRequest::first())
        .await
        .unwrap();
    assert_eq!(listed.items.len(), 2);
    assert!(listed.items[0].revoked_at.is_some() && listed.items[1].revoked_at.is_none());
    assert_eq!(
        world
            .services
            .credentials
            .rotate_feed_token(&admin, &anna.name, created.token.id)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound,
        "a revoked token cannot be rotated"
    );
    // Other principals' tokens are not theirs to manage.
    assert_eq!(
        world
            .services
            .credentials
            .revoke_feed_token(&admin, &ben.name, rotated.token.id)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        world
            .services
            .credentials
            .rotate_feed_token(&admin, &ben.name, rotated.token.id)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    world
        .services
        .credentials
        .revoke_feed_token(&admin, &anna.name, rotated.token.id)
        .await
        .unwrap();
    let audits = world.audit_actions(&acme).await;
    assert_eq!(
        audits.iter().filter(|action| *action == "credential.created").count(),
        2
    );
    assert_eq!(
        audits.iter().filter(|action| *action == "credential.revoked").count(),
        2,
        "the rotation and the revocation"
    );
}

#[tokio::test]
async fn feeds_can_be_switched_off_per_tenant() {
    let world = World::new();
    let acme = world.org_with("acme", |settings| settings.feeds_enabled = false).await;
    let anna = world.user(&acme, "anna").await;
    let admin = world.admin(&acme);
    let personal = world
        .services
        .calendars
        .get(&admin, &world.key(&anna, "personal"))
        .await
        .unwrap()
        .id;
    let error = world
        .services
        .credentials
        .create_feed_token(
            &admin,
            &anna.name,
            FeedTokenCreate {
                mode: FeedMode::Full,
                calendar_ids: vec![personal],
            },
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);
}

#[tokio::test]
async fn client_configuration_is_generic_without_a_secret_and_profiles_mint_an_app_password() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let admin = world.admin(&acme);
    let audits = world.audit_actions(&acme).await;

    // The generic values have no secret and no side effect.
    let generic = world
        .services
        .credentials
        .client_config(&admin, &anna.name, ClientConfigKind::Generic)
        .await
        .unwrap();
    let ClientConfigResponse::Generic(generic) = generic else {
        panic!("{generic:?}")
    };
    assert_eq!(generic.tenant, acme.slug);
    assert_eq!(generic.username, "anna@acme.example");
    assert_eq!(
        generic
            .login_domain
            .as_ref()
            .map(davhaven_testkit::davhaven_domain::DomainName::as_str),
        Some("acme.example")
    );
    assert_eq!(
        generic.well_known_url.as_str(),
        "https://cal.example.org/.well-known/caldav"
    );
    assert_eq!(generic.server_url.as_str(), "https://cal.example.org/dav/");
    assert_eq!(
        generic.principal_url.as_str(),
        "https://cal.example.org/dav/principals/acme/anna/"
    );
    assert_eq!(
        generic.calendar_home_url.as_str(),
        "https://cal.example.org/dav/calendars/acme/anna/"
    );
    assert_eq!(world.audit_actions(&acme).await, audits);
    assert!(
        world
            .services
            .credentials
            .list_app_passwords(&admin, &anna.name, PageRequest::first())
            .await
            .unwrap()
            .items
            .is_empty()
    );

    // DAVx5: a login URI with a fresh app password.
    let davx5 = world
        .services
        .credentials
        .client_config(
            &admin,
            &anna.name,
            ClientConfigKind::Davx5(ClientConfigRequest {
                app_password_label: "DAVx5 on the tablet".to_owned(),
                include_feed: false,
            }),
        )
        .await
        .unwrap();
    let ClientConfigResponse::Davx5(davx5) = davx5 else {
        panic!("{davx5:?}")
    };
    assert!(
        davx5.login_uri.starts_with("davx5://anna%40acme.example:"),
        "{}",
        davx5.login_uri
    );
    assert!(
        davx5.login_uri.ends_with("@cal.example.org/dav/"),
        "{}",
        davx5.login_uri
    );
    let listed = world
        .services
        .credentials
        .list_app_passwords(&admin, &anna.name, PageRequest::first())
        .await
        .unwrap();
    assert_eq!(listed.items.len(), 1);
    assert_eq!(listed.items[0].label, "DAVx5 on the tablet");
    assert_eq!(listed.items[0].id, davx5.app_password_id);
    let password = davx5
        .login_uri
        .split(':')
        .nth(2)
        .unwrap()
        .split('@')
        .next()
        .unwrap()
        .to_owned();
    assert!(is_app_password(&password), "{password}");
    assert!(!format!("{davx5:?}").contains(&password));

    // The Apple profile carries the login, a stable identifier and, when asked, the subscription feed.
    let request = |label: &str, include_feed| ClientConfigRequest {
        app_password_label: label.to_owned(),
        include_feed,
    };
    let apple = |request| {
        let world = &world;
        let admin = admin.clone();
        let name = anna.name.clone();
        async move {
            world
                .services
                .credentials
                .client_config(&admin, &name, ClientConfigKind::AppleMobileconfig(request))
                .await
        }
    };
    let ClientConfigResponse::Mobileconfig(profile) = apple(request("iPhone", true)).await.unwrap() else {
        panic!()
    };
    let text = String::from_utf8(profile.body.clone()).unwrap();
    assert!(profile.filename.ends_with(".mobileconfig"), "{}", profile.filename);
    assert!(text.contains(&format!("org.example.cal.caldav.{}", anna.id)), "{text}");
    assert!(
        text.contains("anna@acme.example") && text.contains("com.apple.subscribedcalendar.account"),
        "{text}"
    );
    assert!(
        !format!("{profile:?}").contains("anna@acme"),
        "the profile is not printed"
    );
    let ClientConfigResponse::Mobileconfig(again) = apple(request("iPad", false)).await.unwrap() else {
        panic!()
    };
    let again = String::from_utf8(again.body).unwrap();
    assert!(
        again.contains(&format!("org.example.cal.caldav.{}", anna.id)),
        "reinstalling replaces the profile: the identifier is stable"
    );
    assert!(!again.contains("subscribedcalendar"));
    let labels: Vec<String> = world
        .services
        .credentials
        .list_app_passwords(&admin, &anna.name, PageRequest::first())
        .await
        .unwrap()
        .items
        .into_iter()
        .map(|item| item.label)
        .collect();
    assert_eq!(
        labels,
        vec!["DAVx5 on the tablet", "iPhone", "iPad"],
        "every profile has its own password"
    );

    // The tenant can brand the identifier; blank labels are refused; scopes decide who may ask.
    let branded = world
        .org_with("brand", |settings| {
            settings.client_config.apple_identifier_prefix = Some("com.brand".to_owned());
            settings.client_config.organization_name = Some("Brand & Co".to_owned());
        })
        .await;
    let bob = world.user(&branded, "bob").await;
    let ClientConfigResponse::Mobileconfig(branded_profile) = world
        .services
        .credentials
        .client_config(
            &world.admin(&branded),
            &bob.name,
            ClientConfigKind::AppleMobileconfig(request("Mac", false)),
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    let branded_text = String::from_utf8(branded_profile.body).unwrap();
    assert!(branded_text.contains(&format!("com.brand.caldav.{}", bob.id)) && branded_text.contains("Brand &amp; Co"));
    assert_eq!(
        apple(request("  ", false)).await.unwrap_err().kind(),
        ErrorKind::Invalid
    );
    let reader = creator(&world, &acme, &[Scope::PrincipalsRead]);
    assert!(
        world
            .services
            .credentials
            .client_config(&reader, &anna.name, ClientConfigKind::Generic)
            .await
            .is_ok()
    );
    assert_eq!(
        world
            .services
            .credentials
            .client_config(&reader, &anna.name, ClientConfigKind::Davx5(request("x", false)))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Forbidden,
        "minting a password needs credentials:write"
    );
}

// ---------------------------------------------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------------------------------------------

fn ip(last: u8) -> Option<IpAddr> {
    format!("192.0.2.{last}").parse().ok()
}

fn basic(login: &str, password: &str) -> PresentedCredential {
    PresentedCredential::Basic {
        username: login.to_owned(),
        password: SecretString::from(password.to_owned()),
    }
}

fn request(
    channel: Channel,
    credential: PresentedCredential,
    hint: Option<&Org>,
    client_ip: Option<IpAddr>,
) -> AuthRequest {
    AuthRequest {
        channel,
        tenant_hint: hint.map(|org| org.slug.clone()),
        credential,
        client_ip,
        request_id: RequestId::from_uuid(Uuid::from_u128(0xabc)),
    }
}

fn accepted(org: &Org, who: &Person) -> Authenticated {
    Authenticated {
        tenant: Some(org.id),
        actor: Actor::Principal(who.id),
        scopes: ScopeSet::empty(),
        credential: CredentialRef::app_password(davhaven_testkit::davhaven_domain::CredentialId::from_uuid(
            Uuid::from_u128(77),
        )),
        label: Some("phone".to_owned()),
    }
}

#[tokio::test]
async fn an_accepted_credential_becomes_the_context_of_the_request() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    world.auth.accept("abcd-efgh", accepted(&acme, &anna));
    let context = world
        .services
        .auth
        .authenticate(request(
            Channel::Dav,
            basic("anna@acme.example", "abcd-efgh"),
            None,
            ip(7),
        ))
        .await
        .unwrap();
    assert_eq!(context.tenant, acme.id);
    assert_eq!(context.actor, Actor::Principal(anna.id));
    assert_eq!(context.channel, Channel::Dav);
    assert!(context.scopes.is_empty());
    assert_eq!(
        context.credential.map(|credential| credential.kind),
        Some(CredentialKind::AppPassword)
    );
    assert_eq!(context.client_ip, ip(7));
    assert_eq!(context.request_id, RequestId::from_uuid(Uuid::from_u128(0xabc)));

    // The chain saw the surface and the tenant hint.
    world
        .services
        .auth
        .authenticate(request(Channel::Dav, basic("anna", "abcd-efgh"), Some(&acme), None))
        .await
        .unwrap();
    let hints = world.auth.hints();
    assert_eq!(hints.last().map(|hint| hint.channel), Some(Channel::Dav));
    assert_eq!(
        hints.last().and_then(|hint| hint.tenant_hint.clone()),
        Some(acme.slug.clone())
    );
}

#[tokio::test]
async fn a_valid_credential_for_the_path_of_another_tenant_is_not_found_and_no_failure() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let other = world.org("other").await;
    world.auth.accept("abcd-efgh", accepted(&acme, &anna));
    // Authentication does not decide visibility: whatever is in the other tenant is invisible to the caller.
    // Asking for it never earns a backoff, however often it is done.
    for _ in 0..10 {
        let error = world
            .services
            .auth
            .authenticate(request(
                Channel::Dav,
                basic("anna@acme.example", "abcd-efgh"),
                Some(&other),
                ip(7),
            ))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotFound);
    }
    assert!(world.limiter.buckets().is_empty(), "no failure was recorded");
    let ok = world
        .services
        .auth
        .authenticate(request(
            Channel::Dav,
            basic("anna@acme.example", "abcd-efgh"),
            Some(&acme),
            ip(7),
        ))
        .await;
    assert!(ok.is_ok());
}

#[tokio::test]
async fn system_tokens_get_the_tenant_of_the_hint_or_none() {
    let Fixture { world, acme, .. } = fixture().await;
    world.auth.accept(
        "system-secret",
        Authenticated {
            tenant: None,
            actor: Actor::SystemToken(TokenId::from_uuid(Uuid::from_u128(5))),
            scopes: ScopeSet::of(&[Scope::SystemTenants]),
            credential: CredentialRef::api_token(TokenId::from_uuid(Uuid::from_u128(5))),
            label: None,
        },
    );
    let bearer = || PresentedCredential::Bearer(SecretString::from("system-secret".to_owned()));
    let unbound = world
        .services
        .auth
        .authenticate(request(Channel::Api, bearer(), None, None))
        .await
        .unwrap();
    assert_eq!(
        unbound.tenant,
        TenantId::from_uuid(Uuid::nil()),
        "a system context belongs to no tenant"
    );
    assert!(matches!(unbound.actor, Actor::SystemToken(_)));
    assert!(unbound.scopes.contains(Scope::SystemTenants));
    let hinted = world
        .services
        .auth
        .authenticate(request(Channel::Api, bearer(), Some(&acme), None))
        .await
        .unwrap();
    assert_eq!(hinted.tenant, acme.id);
    let unknown = Org {
        id: acme.id,
        slug: davhaven_testkit::davhaven_domain::TenantSlug::parse("ghost").unwrap(),
    };
    let nowhere = world
        .services
        .auth
        .authenticate(request(Channel::Api, bearer(), Some(&unknown), None))
        .await
        .unwrap();
    assert_eq!(nowhere.tenant, TenantId::from_uuid(Uuid::nil()));
}

#[tokio::test]
async fn refusals_are_all_the_same_unauthenticated_and_infrastructure_failures_are_unavailable() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    world.auth.accept("good", accepted(&acme, &anna));
    // An authenticator that accepts without naming a tenant (and is no system token) cannot be used.
    world.auth.accept(
        "no-tenant",
        Authenticated {
            tenant: None,
            ..accepted(&acme, &anna)
        },
    );
    for reason in RejectReason::ALL {
        world.auth.answer(reason.as_str(), AuthOutcome::Rejected(reason));
    }
    world.auth.answer("not-mine", AuthOutcome::NotApplicable);
    let attempts = ["unknown", "not-mine", "no-tenant"]
        .into_iter()
        .map(str::to_owned)
        .chain(RejectReason::ALL.map(|reason| reason.as_str().to_owned()));
    for (index, secret) in attempts.enumerate() {
        let error = world
            .services
            .auth
            .authenticate(request(
                Channel::Dav,
                basic("anna@acme.example", &secret),
                None,
                ip(u8::try_from(100 + index).unwrap()),
            ))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Unauthenticated, "{secret}");
        assert_eq!(
            error.public_message().as_str(),
            "Authentication is required.",
            "{secret}"
        );
    }
    world
        .auth
        .fail_with(PortError::unavailable("the credential store is down"));
    let error = world
        .services
        .auth
        .authenticate(request(Channel::Dav, basic("anna@acme.example", "good"), None, ip(9)))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Unavailable);
    assert!(!error.to_string().contains("credential store"));
}

#[tokio::test]
async fn repeated_failures_back_off_per_login_and_address_and_per_address_without_locking_accounts_out() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    world.auth.accept("good", accepted(&acme, &anna));
    let try_login = |login: &str, password: &str, last: u8| {
        let world = &world;
        let request = request(Channel::Dav, basic(login, password), None, ip(last));
        async move { world.services.auth.authenticate(request).await }
    };

    for _ in 0..3 {
        assert_eq!(
            try_login("anna@acme.example", "wrong", 1).await.unwrap_err().kind(),
            ErrorKind::Unauthenticated
        );
    }
    // The bucket of (login, address) is full: even the right password waits, with a Retry-After.
    let blocked = try_login("anna@acme.example", "good", 1).await.unwrap_err();
    assert_eq!(blocked.kind(), ErrorKind::RateLimited);
    assert_eq!(blocked.retry_after(), Some(std::time::Duration::from_secs(30)));
    // Another address has its own buckets: the real user gets in, so nobody can lock an account out.
    assert!(try_login("anna@acme.example", "good", 2).await.is_ok());
    // The same address with another login is slowed down too: its per-address bucket is full as well.
    assert_eq!(
        try_login("ben@acme.example", "wrong", 1).await.unwrap_err().kind(),
        ErrorKind::RateLimited
    );
    // Time passes.
    world.limiter.reset();
    assert!(try_login("anna@acme.example", "good", 1).await.is_ok());

    // The buckets are keyed hashes: neither the login nor the address is ever handed to the limiter.
    for _ in 0..2 {
        let _ = try_login("ben@acme.example", "wrong", 5).await;
    }
    assert_eq!(world.limiter.buckets(), vec!["auth_failure_ip", "auth_failure_login"]);
    assert_eq!(world.limiter.count("auth_failure_login", "ben"), 0);
    assert_eq!(world.limiter.count("auth_failure_ip", "192.0.2.5"), 0);
}

#[tokio::test]
async fn a_limiter_that_is_down_does_not_lock_everybody_out() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    world.auth.accept("good", accepted(&acme, &anna));
    world.limiter.break_down();
    assert!(
        world
            .services
            .auth
            .authenticate(request(Channel::Dav, basic("anna@acme.example", "good"), None, ip(1)))
            .await
            .is_ok()
    );
    assert_eq!(
        world
            .services
            .auth
            .authenticate(request(Channel::Dav, basic("anna@acme.example", "bad"), None, ip(1)))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Unauthenticated
    );
}

#[tokio::test]
async fn a_tenant_without_feeds_answers_feature_not_enabled_and_a_failing_profile_stores_nothing() {
    let world = World::new();
    let acme = world.org_with("acme", |settings| settings.feeds_enabled = false).await;
    let anna = world.user(&acme, "anna").await;
    let admin = world.admin(&acme);
    let personal = world
        .services
        .calendars
        .get(&admin, &world.key(&anna, "personal"))
        .await
        .unwrap()
        .id;
    let error = world
        .services
        .credentials
        .create_feed_token(
            &admin,
            &anna.name,
            FeedTokenCreate {
                mode: FeedMode::Full,
                calendar_ids: vec![personal],
            },
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);
    assert_eq!(
        davhaven_testkit::davhaven_wire::ProblemCode::from_error(error.kind(), error.precondition()),
        davhaven_testkit::davhaven_wire::ProblemCode::FeatureNotEnabled,
        "409 feature-not-enabled, not a plain conflict"
    );

    // A profile that asks for a feed the tenant does not have fails before an app password is stored.
    let audits = world.audit_actions(&acme).await;
    let error = world
        .services
        .credentials
        .client_config(
            &admin,
            &anna.name,
            ClientConfigKind::AppleMobileconfig(ClientConfigRequest {
                app_password_label: "Phone".to_owned(),
                include_feed: true,
            }),
        )
        .await
        .unwrap_err();
    assert_eq!(
        davhaven_testkit::davhaven_wire::ProblemCode::from_error(error.kind(), error.precondition()),
        davhaven_testkit::davhaven_wire::ProblemCode::FeatureNotEnabled
    );
    assert!(
        world
            .services
            .credentials
            .list_app_passwords(&admin, &anna.name, PageRequest::first())
            .await
            .unwrap()
            .items
            .is_empty(),
        "no password whose secret nobody saw"
    );
    assert_eq!(world.audit_actions(&acme).await, audits);

    // Without a feed the profile works.
    assert!(
        world
            .services
            .credentials
            .client_config(
                &admin,
                &anna.name,
                ClientConfigKind::AppleMobileconfig(ClientConfigRequest {
                    app_password_label: "Phone".to_owned(),
                    include_feed: false,
                }),
            )
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn a_minted_token_never_outlives_the_token_that_minted_it() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let id = world.token_id();
    let now = world.now();
    let hashed = world.core.deps().hasher.hash(CredentialKind::ApiToken, &secret("seed"));
    let mut tx = world
        .db
        .store()
        .begin(acme.id, davhaven_testkit::davhaven_ports::TxMode::ReadWrite)
        .await
        .unwrap();
    tx.credentials()
        .create_api_token(davhaven_testkit::davhaven_domain::ApiToken {
            id,
            tenant_id: Some(acme.id),
            kind: TokenKind::Tenant,
            principal_id: None,
            label: "short lived".to_owned(),
            scopes: ScopeSet::of(&[Scope::CredentialsWrite, Scope::EventsRead]),
            prefix: "abcdefghijkl".to_owned(),
            hash: hashed.hash,
            pepper_kid: hashed.pepper_kid,
            expires_at: Some(now + Duration::days(2)),
            created_by: None,
            allowed_origins: Vec::new(),
            last_used_at: None,
            revoked_at: None,
            created_at: now,
            updated_at: now,
            version: 1,
        })
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let minter = RequestContext {
        actor: Actor::TenantToken(id),
        ..world.tenant_token(&acme, ScopeSet::of(&[Scope::CredentialsWrite, Scope::EventsRead]))
    };
    let mint = |expires_at| ApiTokenCreate {
        kind: TokenKind::Principal,
        principal: Some(anna.name.clone()),
        label: "integration".to_owned(),
        scopes: ScopeSet::of(&[Scope::EventsRead]),
        expires_at,
        allowed_origins: Vec::new(),
    };

    // Asked to live longer, or forever, the token lives as long as its minter.
    for requested in [Some(now + Duration::days(30)), None] {
        let created = world
            .services
            .credentials
            .create_api_token(&minter, mint(requested))
            .await
            .unwrap();
        assert_eq!(created.token.expires_at, Some(now + Duration::days(2)), "{requested:?}");
    }
    // A shorter life is kept.
    let created = world
        .services
        .credentials
        .create_api_token(&minter, mint(Some(now + Duration::days(1))))
        .await
        .unwrap();
    assert_eq!(created.token.expires_at, Some(now + Duration::days(1)));
}

#[tokio::test]
async fn credentials_that_do_not_fit_their_surface_or_belong_to_a_suspended_tenant_are_refused() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    // An app password an authenticator accepted on the API: app passwords are for DAV.
    world.auth.accept("abcd-efgh", accepted(&acme, &anna));
    let error = world
        .services
        .auth
        .authenticate(request(Channel::Api, basic("anna", "abcd-efgh"), None, None))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Unauthenticated);
    // A bearer token presented where the authenticator found an app password: the mechanism does not match.
    world.auth.accept("dvh_pat_x", accepted(&acme, &anna));
    let error = world
        .services
        .auth
        .authenticate(request(
            Channel::Api,
            PresentedCredential::Bearer(secret("dvh_pat_x")),
            None,
            None,
        ))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Unauthenticated);

    // On DAV it works; suspending the tenant ends it at once, on the same instance and without the clock moving.
    let dav = || request(Channel::Dav, basic("anna", "abcd-efgh"), None, None);
    assert!(world.services.auth.authenticate(dav()).await.is_ok());
    let suspended = davhaven_testkit::davhaven_app::services::TenantSpec {
        slug: acme.slug.clone(),
        body: davhaven_testkit::davhaven_wire::TenantWrite {
            display_name: "acme organisation".to_owned(),
            login_domain: None,
            status: Some(davhaven_testkit::davhaven_domain::TenantStatus::Suspended),
            settings: None,
        },
    };
    world
        .services
        .tenants
        .upsert(
            &world.system(),
            suspended,
            davhaven_testkit::davhaven_app::services::Conditions::none(),
        )
        .await
        .unwrap();
    for hint in [None, Some(&acme)] {
        let error = world
            .services
            .auth
            .authenticate(request(Channel::Dav, basic("anna", "abcd-efgh"), hint, None))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Unauthenticated, "hint {hint:?}");
    }
}

#[tokio::test]
async fn the_status_of_a_tenant_is_read_once_in_a_while_and_not_once_per_request() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    world.auth.accept("abcd-efgh", accepted(&acme, &anna));
    let dav = || request(Channel::Dav, basic("anna", "abcd-efgh"), Some(&acme), None);
    // The first request reads the tenant; the next ones, within seconds, do not begin a transaction at all.
    world.services.auth.authenticate(dav()).await.unwrap();
    let begins = world.faults.begins();
    world.services.auth.authenticate(dav()).await.unwrap();
    assert_eq!(
        world.faults.begins(),
        begins,
        "the tenant is remembered: no transaction for it"
    );
    // After the memory has expired the store is asked once more.
    world.clock.advance(Duration::seconds(30));
    world.services.auth.authenticate(dav()).await.unwrap();
    assert_eq!(world.faults.begins(), begins + 1);
}

#[tokio::test]
async fn profiles_are_signed_when_the_deployment_has_a_certificate_and_are_plain_otherwise() {
    use davhaven_testkit::davhaven_crypto_local::profile::CmsProfileSigner;
    use davhaven_testkit::davhaven_crypto_local::testing::{KeyKind, identity};

    let request = ClientConfigRequest {
        app_password_label: "iPhone".to_owned(),
        include_feed: false,
    };
    let profile = |world: &World, acme: &Org, anna: &Person| {
        let (admin, name) = (world.admin(acme), anna.name.clone());
        let request = request.clone();
        let services = world.services.clone();
        async move {
            match services
                .credentials
                .client_config(&admin, &name, ClientConfigKind::AppleMobileconfig(request))
                .await
                .unwrap()
            {
                ClientConfigResponse::Mobileconfig(profile) => profile.body,
                other => panic!("{other:?}"),
            }
        }
    };

    // Without a certificate the profile is the property list itself.
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let plain = profile(&world, &acme, &anna).await;
    assert!(plain.starts_with(b"<?xml"), "unsigned profiles stay what they were");

    // With one the same profile is wrapped in a CMS signature (a DER SEQUENCE) and still carries the login and the
    // identifier of the profile, so that a device that ignores the signature reads the same document.
    let identity = identity(KeyKind::EcdsaP256, "Davhaven test").unwrap();
    let certificate =
        CmsProfileSigner::from_pem(&identity.certificate_pem, &SecretString::from(identity.private_key_pem)).unwrap();
    let world = World::with(move |deps| deps.profile_signer = Some(std::sync::Arc::new(certificate)));
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let wrapped = profile(&world, &acme, &anna).await;
    assert_eq!(wrapped.first(), Some(&0x30), "a DER document");
    assert!(!wrapped.starts_with(b"<?xml"));
    let text = String::from_utf8_lossy(&wrapped);
    assert!(
        text.contains("<key>PayloadType</key>") && text.contains("anna@acme.example"),
        "the profile travels inside the signature"
    );
    assert!(
        text.contains(&format!("org.example.cal.caldav.{}", anna.id)),
        "the identifier of the profile is the same"
    );
    // Signing costs nothing else: the password is minted once, as for an unsigned profile.
    let passwords = world
        .services
        .credentials
        .list_app_passwords(&world.admin(&acme), &anna.name, PageRequest::first())
        .await
        .unwrap()
        .items;
    assert_eq!(passwords.len(), 1);
}

/// A signer that cannot sign.
#[derive(Debug)]
struct BrokenSigner;

impl davhaven_testkit::davhaven_ports::ProfileSigner for BrokenSigner {
    fn sign(&self, _profile: &[u8], _signed_at: chrono::DateTime<chrono::Utc>) -> Result<Vec<u8>, PortError> {
        Err(PortError::internal("the key is gone"))
    }
}

#[tokio::test]
async fn a_profile_that_cannot_be_signed_leaves_no_app_password_whose_secret_nobody_saw() {
    let world = World::with(|deps| deps.profile_signer = Some(std::sync::Arc::new(BrokenSigner)));
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let admin = world.admin(&acme);
    let request = ClientConfigRequest {
        app_password_label: "iPhone".to_owned(),
        include_feed: false,
    };
    let error = world
        .services
        .credentials
        .client_config(&admin, &anna.name, ClientConfigKind::AppleMobileconfig(request))
        .await
        .unwrap_err();
    assert_ne!(error.kind(), ErrorKind::NotFound, "{error:?}");
    // The document is made before the transaction commits: nothing was stored.
    let passwords = world
        .services
        .credentials
        .list_app_passwords(&admin, &anna.name, PageRequest::first())
        .await
        .unwrap()
        .items;
    assert!(passwords.is_empty(), "{passwords:?}");
}
