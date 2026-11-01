//! Tenant provisioning: create-or-replace, conditions, merge patches, the tokens that may administer tenants,
//! deletion and paged listings.

use davhaven_testkit::davhaven_app::services::{Conditions, MergePatch, PageRequest, PrincipalSpec, TenantSpec};
use davhaven_testkit::davhaven_domain::{
    DomainName, ErrorKind, ExternalPolicy, PrincipalKind, PrincipalName, RequestContext, Scope, ScopeSet, TenantSettings,
    TenantSlug, TenantStatus,
};
use davhaven_testkit::davhaven_wire::{Cursor, TenantWrite};
use serde_json::json;

use super::support::{Org, World, principal_body};

fn spec(slug: &str, login_domain: &str) -> TenantSpec {
    TenantSpec {
        slug: TenantSlug::parse(slug).unwrap(),
        body: TenantWrite {
            display_name: format!("{slug} organisation"),
            login_domain: Some(DomainName::parse(login_domain).unwrap()),
            status: None,
            settings: None,
        },
    }
}

#[tokio::test]
async fn a_tenant_is_created_once_and_the_same_body_changes_nothing() {
    let world = World::new();
    let system = world.system();
    let first = world
        .services
        .tenants
        .upsert(&system, spec("acme", "acme.example"), Conditions::none())
        .await
        .unwrap();
    assert!(first.created);
    assert_eq!(first.value.version, 1);
    assert_eq!(first.value.settings, TenantSettings::default());
    assert_eq!(first.value.status, TenantStatus::Active);

    world.clock.advance(chrono::Duration::minutes(5));
    let again = world
        .services
        .tenants
        .upsert(&system, spec("acme", "acme.example"), Conditions::none())
        .await
        .unwrap();
    assert!(!again.created);
    assert_eq!(again.value, first.value, "no new version, no new timestamp");

    let org = Org {
        id: first.value.id,
        slug: first.value.slug.clone(),
    };
    assert_eq!(world.audit_actions(&org).await, vec!["tenant.created"]);
}

#[tokio::test]
async fn changes_bump_the_version_and_setting_changes_are_audited_by_name() {
    let world = World::new();
    let system = world.system();
    let created = world
        .services
        .tenants
        .upsert(&system, spec("acme", "acme.example"), Conditions::none())
        .await
        .unwrap()
        .value;
    let org = Org {
        id: created.id,
        slug: created.slug.clone(),
    };

    let mut renamed = spec("acme", "acme.example");
    renamed.body.display_name = "Acme Incorporated".to_owned();
    let renamed = world
        .services
        .tenants
        .upsert(&system, renamed, Conditions::none())
        .await
        .unwrap();
    assert!(!renamed.created);
    assert_eq!(renamed.value.version, 2);
    assert_eq!(renamed.value.display_name, "Acme Incorporated");
    assert_eq!(
        world.audit_actions(&org).await,
        vec!["tenant.created", "tenant.settings_changed"],
        "a rename is audited too: the record names the field, not the value"
    );
    let rename = world.audit(&org).await.pop().unwrap();
    assert_eq!(rename.details.to_string(), r#"{"fields":["display_name"]}"#);

    let mut settings = TenantSettings::default();
    settings.scheduling.external = ExternalPolicy::Deny;
    settings.theme = Some("dark".to_owned());
    let mut changed = spec("acme", "acme.example");
    changed.body.settings = Some(settings);
    let changed = world
        .services
        .tenants
        .upsert(&system, changed, Conditions::none())
        .await
        .unwrap();
    assert_eq!(changed.value.version, 3);
    let audit = world.audit(&org).await;
    let last = audit.last().unwrap();
    assert_eq!(last.action, "tenant.settings_changed");
    let details = last.details.to_string();
    assert!(
        details.contains("scheduling.external") && details.contains("theme"),
        "{details}"
    );
    assert!(
        !details.contains("deny") && !details.contains("dark"),
        "the audit names the settings, not their values: {details}"
    );
}

#[tokio::test]
async fn invalid_settings_are_a_field_error_and_change_nothing() {
    let world = World::new();
    let system = world.system();
    let mut settings = TenantSettings::default();
    settings.theme = Some("Not Valid!".to_owned());
    let mut body = spec("acme", "acme.example");
    body.body.settings = Some(settings);
    let error = world
        .services
        .tenants
        .upsert(&system, body, Conditions::none())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Invalid);
    assert_eq!(
        error.field_errors().first().map(|field| field.pointer),
        Some("/settings/theme")
    );
    let missing = world
        .services
        .tenants
        .get(&system, &TenantSlug::parse("acme").unwrap())
        .await
        .unwrap_err();
    assert_eq!(missing.kind(), ErrorKind::NotFound, "nothing was created");

    let blank = TenantSpec {
        slug: TenantSlug::parse("acme").unwrap(),
        body: TenantWrite {
            display_name: "   ".to_owned(),
            login_domain: None,
            status: None,
            settings: None,
        },
    };
    let error = world
        .services
        .tenants
        .upsert(&system, blank, Conditions::none())
        .await
        .unwrap_err();
    assert_eq!(
        error.field_errors().first().map(|field| field.pointer),
        Some("/display_name")
    );
}

#[tokio::test]
async fn the_text_of_busy_blocks_is_a_tenant_setting_that_merge_patches_set_and_remove() {
    let world = World::new();
    let system = world.system();
    let slug = TenantSlug::parse("acme").unwrap();
    let created = world
        .services
        .tenants
        .upsert(&system, spec("acme", "acme.example"), Conditions::none())
        .await
        .unwrap();
    let org = Org {
        id: created.value.id,
        slug: created.value.slug.clone(),
    };
    assert_eq!(
        created.value.settings.busy_text, None,
        "unset: the theme's text applies"
    );

    let named = MergePatch::new(json!({"settings": {"busy_text": "  In a meeting "}})).unwrap();
    let named = world
        .services
        .tenants
        .patch(&system, &slug, named, Conditions::none())
        .await
        .unwrap();
    assert_eq!(named.settings.busy_text.as_deref(), Some("In a meeting"), "trimmed");
    assert_eq!(named.version, 2);
    assert!(
        world.audit(&org).await.last().is_some_and(|record| {
            let details = record.details.to_string();
            details.contains("busy_text") && !details.contains("In a meeting")
        }),
        "the audit names the setting and not its value"
    );

    // Not blank, not longer than 100 characters, no control characters: a field error that changes nothing.
    for bad in [
        json!(""),
        json!("   "),
        json!("x".repeat(101)),
        json!("Busy\r\nBcc: x"),
        json!("Busy\u{202E}live"),
    ] {
        let patch = MergePatch::new(json!({"settings": {"busy_text": bad}})).unwrap();
        let error = world
            .services
            .tenants
            .patch(&system, &slug, patch, Conditions::none())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Invalid, "{bad}");
        assert_eq!(
            error.field_errors().first().map(|field| field.pointer),
            Some("/settings/busy_text")
        );
    }
    let kept = world.services.tenants.get(&system, &slug).await.unwrap();
    assert_eq!(
        (kept.settings.busy_text.as_deref(), kept.version),
        (Some("In a meeting"), 2)
    );

    let removed = MergePatch::new(json!({"settings": {"busy_text": null}})).unwrap();
    let removed = world
        .services
        .tenants
        .patch(&system, &slug, removed, Conditions::none())
        .await
        .unwrap();
    assert_eq!((removed.settings.busy_text, removed.version), (None, 3));
}

#[tokio::test]
async fn the_texts_of_busy_blocks_per_language_are_merge_patched_one_language_at_a_time() {
    let world = World::new();
    let system = world.system();
    let slug = TenantSlug::parse("acme").unwrap();
    let created = world
        .services
        .tenants
        .upsert(&system, spec("acme", "acme.example"), Conditions::none())
        .await
        .unwrap();
    let org = Org {
        id: created.value.id,
        slug: created.value.slug.clone(),
    };
    assert!(
        created.value.settings.busy_text_by_locale.is_empty(),
        "unset: the single text or the theme's text applies"
    );
    let patch = |body: serde_json::Value| MergePatch::new(json!({"settings": body})).unwrap();
    let texts = |tenant: &davhaven_testkit::davhaven_wire::TenantView| -> Vec<(String, String)> {
        tenant
            .settings
            .busy_text_by_locale
            .iter()
            .map(|(tag, text)| (tag.to_string(), text.clone()))
            .collect()
    };

    // A language is set with its tag, written in any spelling of it, and its text is trimmed.
    let named = world
        .services
        .tenants
        .patch(
            &system,
            &slug,
            patch(json!({"busy_text": "In a meeting", "busy_text_by_locale": {"de_de": "  Nicht verfügbar ", "en": "Out"}})),
            Conditions::none(),
        )
        .await
        .unwrap();
    assert_eq!(
        texts(&named),
        [("de-DE".to_owned(), "Nicht verfügbar".to_owned()), ("en".to_owned(), "Out".to_owned())]
    );
    assert_eq!(named.settings.busy_text.as_deref(), Some("In a meeting"), "the single text stays valid beside it");
    assert!(
        world.audit(&org).await.last().is_some_and(|record| {
            let details = record.details.to_string();
            details.contains("busy_text_by_locale.de-DE")
                && details.contains("busy_text_by_locale.en")
                && !details.contains("Nicht verfügbar")
                && !details.contains("Out")
        }),
        "the audit names the languages that changed and not their texts"
    );

    // A merge patch changes the languages it names and keeps the others (RFC 7396); `null` removes one.
    let merged = world
        .services
        .tenants
        .patch(
            &system,
            &slug,
            patch(json!({"busy_text_by_locale": {"en": "Away", "de-DE": null}})),
            Conditions::none(),
        )
        .await
        .unwrap();
    assert_eq!(texts(&merged), [("en".to_owned(), "Away".to_owned())]);
    assert_eq!(merged.settings.busy_text.as_deref(), Some("In a meeting"), "the single text is untouched");
    assert_eq!(merged.version, 3);

    // The tag of a patch is read like the tag of a body, and the stored tags are canonical: a merge patch is merged by its
    // keys, so a spelling that is not the canonical one must not name another member than the stored tag (it used to be ignored
    // without an error: a removal that removed nothing and a change that left the old text).
    let added = world
        .services
        .tenants
        .patch(&system, &slug, patch(json!({"busy_text_by_locale": {"de_at": "Servus"}})), Conditions::none())
        .await
        .unwrap();
    assert_eq!(
        texts(&added),
        [("de-AT".to_owned(), "Servus".to_owned()), ("en".to_owned(), "Away".to_owned())],
        "the tag is stored in its canonical case"
    );
    let removed = world
        .services
        .tenants
        .patch(&system, &slug, patch(json!({"busy_text_by_locale": {"DE_at": null}})), Conditions::none())
        .await
        .unwrap();
    assert_eq!(texts(&removed), [("en".to_owned(), "Away".to_owned())], "`DE_at` removes the stored `de-AT`");
    let changed = world
        .services
        .tenants
        .patch(&system, &slug, patch(json!({"busy_text_by_locale": {"EN": "Out again"}})), Conditions::none())
        .await
        .unwrap();
    assert_eq!(
        texts(&changed),
        [("en".to_owned(), "Out again".to_owned())],
        "`EN` changes the stored `en` and adds no second one"
    );
    assert_eq!((added.version, removed.version, changed.version), (4, 5, 6));

    // One tag in two spellings in one patch, and a tag that is none whatever its value is (`null` included), are refused at the
    // member and change nothing.
    for (bad, code) in [
        (json!({"busy_text_by_locale": {"de_DE": "a", "de-DE": "b"}}), "duplicate-tag"),
        (json!({"busy_text_by_locale": {"EN": null, "en": "again"}}), "duplicate-tag"),
        (json!({"busy_text_by_locale": {"!!": null}}), "invalid"),
        (json!({"busy_text_by_locale": {"not a tag": "Busy"}}), "invalid"),
    ] {
        let error = world
            .services
            .tenants
            .patch(&system, &slug, patch(bad.clone()), Conditions::none())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Invalid, "{bad}");
        assert_eq!(
            error.field_errors().first().map(|field| (field.pointer, field.code)),
            Some(("/settings/busy_text_by_locale", code)),
            "{bad}"
        );
    }
    let merged = world.services.tenants.get(&system, &slug).await.unwrap();
    assert_eq!((texts(&merged), merged.version), (texts(&changed), 6), "a refusal changes nothing");

    // A text that breaks a rule, and a value that is no text, are field errors that change nothing.
    for bad in [
        json!({"busy_text_by_locale": {"de": ""}}),
        json!({"busy_text_by_locale": {"de": "   "}}),
        json!({"busy_text_by_locale": {"de": "x".repeat(101)}}),
        json!({"busy_text_by_locale": {"de": "Busy\r\nBcc: x"}}),
        json!({"busy_text_by_locale": {"de": "Busy\u{202E}live"}}),
        json!({"busy_text_by_locale": {"not a tag": "Busy"}}),
        json!({"busy_text_by_locale": {"de": 1}}),
    ] {
        let error = world
            .services
            .tenants
            .patch(&system, &slug, patch(bad.clone()), Conditions::none())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Invalid, "{bad}");
    }
    // A text names its language and the pointer is the map.
    let error = world
        .services
        .tenants
        .patch(
            &system,
            &slug,
            patch(json!({"busy_text_by_locale": {"de": "x".repeat(101)}})),
            Conditions::none(),
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.field_errors().first().map(|field| field.pointer),
        Some("/settings/busy_text_by_locale")
    );
    // More languages than the limit are refused as a whole.
    let many: serde_json::Map<String, serde_json::Value> = (0..=davhaven_testkit::davhaven_domain::settings::MAX_BUSY_TEXT_LOCALES)
        .map(|index| (format!("de-A{}", char::from(b'A' + u8::try_from(index).unwrap())), json!("Busy")))
        .collect();
    let error = world
        .services
        .tenants
        .patch(
            &system,
            &slug,
            patch(json!({"busy_text_by_locale": many})),
            Conditions::none(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Invalid);
    let kept = world.services.tenants.get(&system, &slug).await.unwrap();
    assert_eq!((texts(&kept), kept.version), (texts(&merged), 6), "a refusal changes nothing");

    // `null` for the whole map removes every language, as it removes the single text.
    let cleared = world
        .services
        .tenants
        .patch(&system, &slug, patch(json!({"busy_text_by_locale": null})), Conditions::none())
        .await
        .unwrap();
    assert!(cleared.settings.busy_text_by_locale.is_empty());
    assert_eq!(cleared.version, 7);
}

#[tokio::test]
async fn conditions_guard_tenant_writes() {
    let world = World::new();
    let system = world.system();
    let created = world
        .services
        .tenants
        .upsert(&system, spec("acme", "acme.example"), Conditions::create_only())
        .await
        .unwrap();
    assert!(created.created);

    for conditions in [Conditions::create_only(), Conditions::if_match(99)] {
        let error = world
            .services
            .tenants
            .upsert(&system, spec("acme", "acme.example"), conditions)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::PreconditionFailed, "{conditions:?}");
    }
    let error = world
        .services
        .tenants
        .upsert(&system, spec("ghost", "ghost.example"), Conditions::if_match(1))
        .await
        .unwrap_err();
    assert_eq!(
        error.kind(),
        ErrorKind::PreconditionFailed,
        "If-Match on a tenant that does not exist is a failed precondition"
    );
    let matched = world
        .services
        .tenants
        .upsert(&system, spec("acme", "acme.example"), Conditions::if_match(1))
        .await
        .unwrap();
    assert!(!matched.created);
}

#[tokio::test]
async fn a_login_domain_belongs_to_one_tenant() {
    let world = World::new();
    let system = world.system();
    world
        .services
        .tenants
        .upsert(&system, spec("acme", "shared.example"), Conditions::none())
        .await
        .unwrap();
    let error = world
        .services
        .tenants
        .upsert(&system, spec("other", "Shared.Example"), Conditions::none())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);
}

#[tokio::test]
async fn merge_patches_change_single_members_and_follow_the_conditions() {
    let world = World::new();
    let system = world.system();
    let slug = TenantSlug::parse("acme").unwrap();
    world
        .services
        .tenants
        .upsert(&system, spec("acme", "acme.example"), Conditions::none())
        .await
        .unwrap();

    let patch = MergePatch::new(json!({"display_name": "Patched", "settings": {"theme": "dark"}})).unwrap();
    let patched = world
        .services
        .tenants
        .patch(&system, &slug, patch, Conditions::if_match(1))
        .await
        .unwrap();
    assert_eq!(patched.display_name, "Patched");
    assert_eq!(patched.settings.theme.as_deref(), Some("dark"));
    assert_eq!(
        patched.settings.locale,
        TenantSettings::default().locale,
        "other settings stay"
    );
    assert_eq!(
        patched.login_domain.as_ref().map(DomainName::as_str),
        Some("acme.example")
    );
    assert_eq!(patched.version, 2);

    // A theme of the tenant is optional: `null` removes it, and the tenant follows `templates.default_theme` again.
    let follow = MergePatch::new(json!({"settings": {"theme": null}})).unwrap();
    let followed = world
        .services
        .tenants
        .patch(&system, &slug, follow, Conditions::none())
        .await
        .unwrap();
    assert_eq!(followed.settings.theme, None);
    assert_eq!(followed.version, 3);
    let named_again = MergePatch::new(json!({"settings": {"theme": "dark"}})).unwrap();
    let again = world
        .services
        .tenants
        .patch(&system, &slug, named_again, Conditions::none())
        .await
        .unwrap();
    assert_eq!((again.settings.theme.as_deref(), again.version), (Some("dark"), 4));

    let removal = MergePatch::new(json!({"login_domain": null})).unwrap();
    let cleared = world
        .services
        .tenants
        .patch(&system, &slug, removal, Conditions::none())
        .await
        .unwrap();
    assert!(cleared.login_domain.is_none());
    assert_eq!(cleared.version, 5);

    let stale = MergePatch::new(json!({"display_name": "Late"})).unwrap();
    let error = world
        .services
        .tenants
        .patch(&system, &slug, stale, Conditions::if_match(1))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::PreconditionFailed);

    let broken = MergePatch::new(json!({"display_name": 5})).unwrap();
    let error = world
        .services
        .tenants
        .patch(&system, &slug, broken, Conditions::none())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Invalid);

    let unknown = MergePatch::new(json!({"display_name": "x"})).unwrap();
    let error = world
        .services
        .tenants
        .patch(
            &system,
            &TenantSlug::parse("ghost").unwrap(),
            unknown,
            Conditions::none(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotFound);
}

#[tokio::test]
async fn only_the_right_tokens_administer_tenants() {
    let world = World::new();
    let acme = world.org("acme").await;
    let other = world.org("other").await;
    let slug = acme.slug.clone();

    // A tenant token with every scope still cannot list or write tenants: that is for system tokens.
    let admin = world.admin(&acme);
    assert_eq!(
        world
            .services
            .tenants
            .list(&admin, PageRequest::first())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Forbidden
    );
    assert_eq!(
        world
            .services
            .tenants
            .upsert(&admin, spec("acme", "acme.example"), Conditions::none())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Forbidden
    );
    // DAV sessions and unscoped tokens administer nothing.
    let anna = world.user(&acme, "anna").await;
    let dav = world.dav(&acme, &anna);
    assert_eq!(
        world.services.tenants.get(&dav, &slug).await.unwrap_err().kind(),
        ErrorKind::Forbidden
    );
    let unscoped = world.tenant_token(&acme, ScopeSet::empty());
    assert_eq!(
        world.services.tenants.get(&unscoped, &slug).await.unwrap_err().kind(),
        ErrorKind::Forbidden
    );

    // `principals:read` may read the token's own tenant and nothing else.
    let reader = world.tenant_token(&acme, ScopeSet::of(&[Scope::PrincipalsRead]));
    assert_eq!(world.services.tenants.get(&reader, &slug).await.unwrap().slug, slug);
    assert_eq!(
        world
            .services
            .tenants
            .get(&reader, &other.slug)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound,
        "another tenant is as good as unknown"
    );

    // A system token reads any tenant; an unknown slug is not found.
    let system = world.system();
    assert_eq!(
        world.services.tenants.get(&system, &other.slug).await.unwrap().id,
        other.id
    );
    assert_eq!(
        world
            .services
            .tenants
            .get(&system, &TenantSlug::parse("ghost").unwrap())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
}

#[tokio::test]
async fn a_tenant_is_deleted_with_if_match_and_takes_its_data_along() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let system = world.system();
    let current = world.services.tenants.get(&system, &acme.slug).await.unwrap();

    let error = world
        .services
        .tenants
        .delete(&system, &acme.slug, Conditions::none())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::PreconditionRequired);
    let error = world
        .services
        .tenants
        .delete(&system, &acme.slug, Conditions::if_match(current.version + 1))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::PreconditionFailed);
    let admin = world.admin(&acme);
    assert_eq!(
        world
            .services
            .tenants
            .delete(&admin, &acme.slug, Conditions::if_match(current.version))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Forbidden
    );

    world
        .services
        .tenants
        .delete(&system, &acme.slug, Conditions::if_match(current.version))
        .await
        .unwrap();
    assert_eq!(
        world
            .services
            .tenants
            .get(&system, &acme.slug)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        world
            .services
            .principals
            .get(&admin, &anna.name)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound,
        "the principals went with the tenant"
    );
    // The slug can be provisioned again, as a new tenant.
    let again = world.org("acme").await;
    assert_ne!(again.id, acme.id);
}

#[tokio::test]
async fn tenant_lists_are_paged_by_id_with_signed_cursors() {
    let world = World::new();
    let system = world.system();
    let a = world.org("alpha").await;
    let b = world.org("bravo").await;
    let c = world.org("charlie").await;

    let first = world
        .services
        .tenants
        .list(&system, PageRequest::with_limit(2))
        .await
        .unwrap();
    assert_eq!(
        first.items.iter().map(|tenant| tenant.id).collect::<Vec<_>>(),
        vec![a.id, b.id]
    );
    let cursor = first.next_cursor.clone().expect("a third tenant follows");
    let second = world
        .services
        .tenants
        .list(&system, PageRequest::with_limit(2).after(cursor.clone()))
        .await
        .unwrap();
    assert_eq!(
        second.items.iter().map(|tenant| tenant.id).collect::<Vec<_>>(),
        vec![c.id]
    );
    assert!(second.next_cursor.is_none());

    for forged in [
        Cursor::parse("garbage").unwrap(),
        Cursor::parse(&format!("{}x", cursor.as_str())).unwrap(),
    ] {
        let error = world
            .services
            .tenants
            .list(&system, PageRequest::with_limit(2).after(forged))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Invalid);
    }
}

#[tokio::test]
async fn a_put_that_leaves_the_status_out_keeps_it_and_a_suspension_is_audited() {
    let world = World::new();
    let system = world.system();
    let created = world
        .services
        .tenants
        .upsert(&system, spec("acme", "acme.example"), Conditions::none())
        .await
        .unwrap()
        .value;
    let org = Org {
        id: created.id,
        slug: created.slug.clone(),
    };

    let mut suspend = spec("acme", "acme.example");
    suspend.body.status = Some(TenantStatus::Suspended);
    let suspended = world
        .services
        .tenants
        .upsert(&system, suspend, Conditions::none())
        .await
        .unwrap()
        .value;
    assert_eq!(suspended.status, TenantStatus::Suspended);
    let audit = world.audit(&org).await.pop().unwrap();
    assert_eq!(audit.action, "tenant.settings_changed");
    assert_eq!(
        audit.details.to_string(),
        r#"{"fields":["status"]}"#,
        "a suspension leaves a record"
    );

    // A reconciler that sends the body it always sends, without a status, does not reactivate the tenant.
    let rewritten = world
        .services
        .tenants
        .upsert(&system, spec("acme", "acme.example"), Conditions::none())
        .await
        .unwrap();
    assert!(!rewritten.created);
    assert_eq!(rewritten.value.status, TenantStatus::Suspended);
    assert_eq!(rewritten.value.version, suspended.version, "nothing changed");

    let mut resume = spec("acme", "acme.example");
    resume.body.status = Some(TenantStatus::Active);
    assert_eq!(
        world
            .services
            .tenants
            .upsert(&system, resume, Conditions::none())
            .await
            .unwrap()
            .value
            .status,
        TenantStatus::Active
    );
}

#[tokio::test]
async fn the_audit_record_of_a_tenant_commits_with_the_tenant_in_one_transaction() {
    // `tenant.created` and `tenant.settings_changed` are appended in the system transaction of the change (backlog
    // item 14), not in a second one after it: one commit per change, and a lost commit loses both or neither.
    let world = World::new();
    let system = world.system();

    let commits = world.faults.commits();
    let created = world
        .services
        .tenants
        .upsert(&system, spec("acme", "acme.example"), Conditions::none())
        .await
        .unwrap()
        .value;
    assert_eq!(
        world.faults.commits() - commits,
        1,
        "one transaction holds the tenant and its record"
    );
    let org = Org {
        id: created.id,
        slug: created.slug.clone(),
    };
    assert_eq!(world.audit_actions(&org).await, vec!["tenant.created"]);

    let mut renamed = spec("acme", "acme.example");
    renamed.body.display_name = "Acme Incorporated".to_owned();
    let commits = world.faults.commits();
    world
        .services
        .tenants
        .upsert(&system, renamed.clone(), Conditions::none())
        .await
        .unwrap();
    assert_eq!(world.faults.commits() - commits, 1, "and so does a change");
    assert_eq!(
        world.audit_actions(&org).await,
        vec!["tenant.created", "tenant.settings_changed"]
    );

    // A change that writes nothing records nothing and does not even open a second transaction for it.
    let commits = world.faults.commits();
    world
        .services
        .tenants
        .upsert(&system, renamed, Conditions::none())
        .await
        .unwrap();
    assert_eq!(world.faults.commits() - commits, 1);
    assert_eq!(world.audit_actions(&org).await.len(), 2);

    // Lost commits take the record with the tenant: nothing exists, and nothing is half there.
    world.faults.fail_next_commits(3);
    let lost = world
        .services
        .tenants
        .upsert(&system, spec("globex", "globex.example"), Conditions::none())
        .await
        .unwrap_err();
    assert_eq!(lost.kind(), ErrorKind::Unavailable);
    let listed = world
        .services
        .tenants
        .list(&system, PageRequest::first())
        .await
        .unwrap();
    assert_eq!(
        listed.items.len(),
        1,
        "the tenant that could not be committed does not exist"
    );

    // A commit that is lost once and then wins leaves exactly one record, not one per attempt.
    world.faults.fail_next_commits(1);
    let globex = world
        .services
        .tenants
        .upsert(&system, spec("globex", "globex.example"), Conditions::none())
        .await
        .unwrap()
        .value;
    let globex = Org {
        id: globex.id,
        slug: globex.slug,
    };
    assert_eq!(world.audit_actions(&globex).await, vec!["tenant.created"]);
}

#[tokio::test]
async fn the_address_hash_of_a_tenant_record_is_keyed_on_the_tenant_whose_log_holds_it() {
    // A system token has no tenant of its own, so a hash keyed on the tenant of the request would be one and the same in
    // the log of every tenant that the operator creates from one address. The record belongs to the log of the tenant it
    // is about, and so does the key of the hash: the same address has another hash in every tenant (interop.md).
    let world = World::new();
    let from_one_address = RequestContext {
        client_ip: Some("203.0.113.7".parse().unwrap()),
        ..world.system()
    };
    let mut orgs = Vec::new();
    for (slug, domain) in [("acme", "acme.example"), ("globex", "globex.example")] {
        let created = world
            .services
            .tenants
            .upsert(&from_one_address, spec(slug, domain), Conditions::none())
            .await
            .unwrap()
            .value;
        orgs.push(Org {
            id: created.id,
            slug: created.slug,
        });
    }
    let hash_in = |org: &Org| {
        let world = &world;
        let org = org.clone();
        async move {
            let rows = world.audit(&org).await;
            assert_eq!(rows.len(), 1, "{rows:?}");
            rows.into_iter().next().and_then(|row| row.actor.ip_hash)
        }
    };
    let (acme, globex) = (hash_in(&orgs[0]).await, hash_in(&orgs[1]).await);
    assert!(acme.is_some() && globex.is_some(), "the address is recorded as a hash");
    assert_ne!(acme, globex, "the same address has another hash in every tenant's log");

    // The hash is the one that every other record of that log carries for the address: a request of the tenant itself.
    let from_the_same_address = RequestContext {
        client_ip: Some("203.0.113.7".parse().unwrap()),
        ..world.admin(&orgs[0])
    };
    world
        .services
        .principals
        .upsert(
            &from_the_same_address,
            PrincipalSpec {
                name: PrincipalName::parse("anna").unwrap(),
                body: principal_body(&orgs[0], "anna", PrincipalKind::User),
            },
            Conditions::none(),
        )
        .await
        .unwrap();
    let rows = world.audit(&orgs[0]).await;
    let hash_of = |action: &str| {
        rows.iter()
            .find(|row| row.action == action)
            .and_then(|row| row.actor.ip_hash.clone())
    };
    assert!(hash_of("principal.created").is_some(), "{rows:?}");
    assert_eq!(
        hash_of("tenant.created"),
        hash_of("principal.created"),
        "the record of the tenant's creation and a later record of the same address agree"
    );
}
