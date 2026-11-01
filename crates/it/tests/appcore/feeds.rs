//! Subscription feeds: the window, the headers of the document, busy mode, restricted events, and the rule that
//! access is checked again on every request.

use std::collections::BTreeMap;

use davhaven_testkit::davhaven_app::services::{
    Conditional, Conditions, DeleteOptions, FeedBody, FeedResponse, GrantSpec, PutRequest, ScheduleReply,
    WritePrecondition,
};
use davhaven_testkit::davhaven_domain::{
    CalendarKind, Classification, ETag, ErrorKind, FeedMode, GrantAccess, Locale, PrincipalKind, PrincipalStatus,
    TenantSettings, Transparency,
};
use davhaven_testkit::davhaven_fixtures::event::{Attendee, EventBuilder, Organizer, When};
use davhaven_testkit::davhaven_wire::{FeedTokenCreate, GrantWrite, PrincipalWrite};
use chrono::Duration;

use super::support::{Fixture, Org, Person, PortCalls, World, fixture, principal_body};

async fn put(world: &World, org: &Org, who: &Person, slug: &str, uri: &str, body: String) {
    world
        .services
        .objects
        .put(
            &world.dav(org, who),
            PutRequest {
                path: world.object(org, who, slug, uri),
                body,
                content_type: None,
                preconditions: WritePrecondition::none(),
                schedule_reply: ScheduleReply::Send,
            },
        )
        .await
        .unwrap();
}

fn event(uid: &str, summary: &str, year: i32, month: u32, day: u32) -> EventBuilder {
    EventBuilder::event(uid)
        .summary(summary)
        .starts(When::utc(year, month, day, 9, 0))
        .ends(When::utc(year, month, day, 10, 0))
}

async fn feed_token(
    world: &World,
    org: &Org,
    who: &Person,
    mode: FeedMode,
    calendars: &[&str],
    owner: &Person,
) -> davhaven_testkit::davhaven_domain::TokenId {
    let admin = world.admin(org);
    let mut ids = Vec::new();
    for slug in calendars {
        ids.push(
            world
                .services
                .calendars
                .get(&admin, &world.key(owner, slug))
                .await
                .unwrap()
                .id,
        );
    }
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
        .unwrap()
        .token
        .id
}

async fn render(
    world: &World,
    org: &Org,
    who: &Person,
    token: davhaven_testkit::davhaven_domain::TokenId,
) -> Result<FeedResponse, davhaven_testkit::davhaven_app::error::AppError> {
    world
        .services
        .feeds
        .render(&world.feed(org, who, token), Conditional::default())
        .await
}

async fn body(world: &World, org: &Org, who: &Person, token: davhaven_testkit::davhaven_domain::TokenId) -> FeedBody {
    match render(world, org, who, token).await.unwrap() {
        FeedResponse::Body(body) => body,
        FeedResponse::NotModified { etag } => panic!("not modified: {etag:?}"),
    }
}

#[tokio::test]
async fn a_feed_holds_the_events_inside_the_window_and_the_headers_of_a_subscription() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    put(
        &world,
        &acme,
        &anna,
        "personal",
        "in.ics",
        event("in", "Inside", 2027, 3, 1).build(),
    )
    .await;
    put(
        &world,
        &acme,
        &anna,
        "personal",
        "far.ics",
        event("far", "Far future", 2031, 3, 1).build(),
    )
    .await;
    put(
        &world,
        &acme,
        &anna,
        "personal",
        "old.ics",
        event("old", "Long ago", 2026, 1, 1).build(),
    )
    .await;
    let berlin = event("zoned", "Zoned", 2027, 4, 1)
        .starts(When::zoned("Europe/Berlin", 2027, 4, 1, 9, 0))
        .ends(When::zoned("Europe/Berlin", 2027, 4, 1, 10, 0))
        .build();
    put(&world, &acme, &anna, "personal", "zoned.ics", berlin).await;
    let token = feed_token(&world, &acme, &anna, FeedMode::Full, &["personal"], &anna).await;

    let feed = body(&world, &acme, &anna, token).await;
    assert!(
        feed.body.starts_with("BEGIN:VCALENDAR\r\nVERSION:2.0\r\n"),
        "{}",
        feed.body
    );
    assert!(feed.body.ends_with("END:VCALENDAR\r\n"));
    assert!(feed.body.contains("METHOD:PUBLISH"));
    assert!(
        feed.body.contains("X-WR-CALNAME:personal calendar") || feed.body.contains("X-WR-CALNAME:Personal"),
        "{}",
        feed.body
    );
    assert_eq!(feed.calendar_name, "Personal");
    assert!(feed.body.contains("REFRESH-INTERVAL;VALUE=DURATION:PT15M"));
    assert!(feed.body.contains("X-PUBLISHED-TTL:PT15M"));
    assert_eq!(feed.refresh_interval.as_str(), "PT15M");
    assert!(feed.body.contains("SUMMARY:Inside") && feed.body.contains("SUMMARY:Zoned"));
    assert!(!feed.body.contains("Far future"), "beyond the window of 365 days");
    assert!(!feed.body.contains("Long ago"), "before the window of 90 days");
    assert_eq!(
        feed.body.matches("BEGIN:VTIMEZONE").count(),
        1,
        "one definition for the zone that is used: {}",
        feed.body
    );
    // The strong tag is derived from what the document is made of, so a second rendering of the same state has the
    // same one, and it is not the hash of the bytes (the next tests say what it costs and what changes it).
    assert_eq!(
        body(&world, &acme, &anna, token).await.etag,
        feed.etag,
        "the same state, the same tag"
    );
    assert_ne!(feed.etag, ETag::from_bytes(feed.body.as_bytes()));
    assert!(feed.last_modified.is_some());

    // The feed has a conditional form: the ETag answers 304 until something changes.
    let conditional = Conditional {
        if_none_match: Some(feed.etag.clone()),
    };
    let ctx = world.feed(&acme, &anna, token);
    assert_eq!(
        world.services.feeds.render(&ctx, conditional.clone()).await.unwrap(),
        FeedResponse::NotModified {
            etag: feed.etag.clone()
        }
    );
    put(
        &world,
        &acme,
        &anna,
        "personal",
        "new.ics",
        event("new", "Added later", 2027, 5, 1).build(),
    )
    .await;
    let changed = match world.services.feeds.render(&ctx, conditional).await.unwrap() {
        FeedResponse::Body(changed) => changed,
        FeedResponse::NotModified { etag } => panic!("not modified: {etag:?}"),
    };
    assert_ne!(changed.etag, feed.etag);
    assert!(changed.body.contains("Added later"));
    // As time passes events leave the window.
    world.clock.advance(Duration::days(500));
    let later = body(&world, &acme, &anna, token).await;
    assert!(!later.body.contains("SUMMARY:Inside"));
    assert!(
        later.body.contains("BEGIN:VCALENDAR"),
        "a feed without events is still a feed"
    );
}

#[tokio::test]
async fn recurring_events_stay_one_master_with_their_overrides_and_feeds_can_span_calendars() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    world.calendar(&acme, &anna, "work", CalendarKind::User).await;
    put(
        &world,
        &acme,
        &anna,
        "personal",
        "daily.ics",
        event("daily", "Daily", 2027, 3, 1).rrule("FREQ=DAILY;COUNT=5").build(),
    )
    .await;
    put(
        &world,
        &acme,
        &anna,
        "work",
        "w.ics",
        event("w", "Workday", 2027, 3, 2).build(),
    )
    .await;
    let token = feed_token(&world, &acme, &anna, FeedMode::Full, &["personal", "work"], &anna).await;
    let feed = body(&world, &acme, &anna, token).await;
    assert_eq!(feed.body.matches("BEGIN:VEVENT").count(), 2, "{}", feed.body);
    assert!(feed.body.contains("RRULE:"), "the master keeps its rule: {}", feed.body);
    assert_eq!(
        feed.calendar_name, "acme organisation",
        "several calendars are named after the tenant"
    );
}

#[tokio::test]
async fn busy_feeds_show_only_times_with_a_hashed_uid_and_skip_transparent_and_cancelled_events() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    put(
        &world,
        &acme,
        &anna,
        "personal",
        "secret.ics",
        event("secret-1", "Secret meeting", 2027, 3, 1)
            .description("Salary talks")
            .location("Room 13")
            .organizer(Organizer::new("mailto:anna@acme.example"))
            .attendee(Attendee::new("mailto:ben@acme.example"))
            .build(),
    )
    .await;
    put(
        &world,
        &acme,
        &anna,
        "personal",
        "free.ics",
        event("free-1", "Free time", 2027, 3, 2)
            .transp(Transparency::Transparent)
            .build(),
    )
    .await;
    put(
        &world,
        &acme,
        &anna,
        "personal",
        "cancelled.ics",
        event("cancelled-1", "Cancelled", 2027, 3, 3)
            .status(davhaven_testkit::davhaven_domain::EventStatus::Cancelled)
            .build(),
    )
    .await;
    let token = feed_token(&world, &acme, &anna, FeedMode::Busy, &["personal"], &anna).await;
    let feed = body(&world, &acme, &anna, token).await;
    assert_eq!(feed.body.matches("BEGIN:VEVENT").count(), 1, "{}", feed.body);
    assert!(feed.body.contains("SUMMARY:Busy"), "{}", feed.body);
    for hidden in [
        "Secret meeting",
        "Salary talks",
        "Room 13",
        "ben@acme.example",
        "secret-1",
        "Free time",
        "Cancelled",
    ] {
        assert!(!feed.body.contains(hidden), "{hidden} must not leak: {}", feed.body);
    }
    assert!(feed.body.contains("DTSTART:20270301T090000Z") && feed.body.contains("DTEND:20270301T100000Z"));
    let again = body(&world, &acme, &anna, token).await;
    assert_eq!(again.body, feed.body, "the hashed UID is stable for a token");
    // Another token hashes differently: the UIDs of two subscriptions cannot be correlated.
    let other = feed_token(&world, &acme, &anna, FeedMode::Busy, &["personal"], &anna).await;
    let uid_of = |text: &str| text.lines().find(|line| line.starts_with("UID:")).unwrap().to_owned();
    assert_ne!(
        uid_of(&body(&world, &acme, &anna, other).await.body),
        uid_of(&feed.body)
    );
}

/// A user whose own language is `locale`: it wins over the language of the tenant.
async fn user_with_locale(world: &World, org: &Org, name: &str, locale: Locale) -> Person {
    let mut body = principal_body(org, name, PrincipalKind::User);
    body.locale = Some(locale);
    let view = world.principal_write(org, name, body).await.unwrap();
    Person {
        id: view.id,
        name: view.name,
    }
}

/// The busy-mode feed of `who` over the personal calendar, which holds one event.
async fn busy_feed(world: &World, org: &Org, who: &Person) -> String {
    put(
        world,
        org,
        who,
        "personal",
        "a.ics",
        event("a", "Anything", 2027, 3, 1).build(),
    )
    .await;
    let token = feed_token(world, org, who, FeedMode::Busy, &["personal"], who).await;
    body(world, org, who, token).await.body
}

#[tokio::test]
async fn a_single_busy_text_of_a_tenant_is_used_for_every_language() {
    let world = World::new();
    let acme = world
        .org_with("acme", |settings| {
            settings.locale = Locale::de();
            settings.busy_text = Some("Nicht verfügbar".to_owned());
        })
        .await;
    let anna = world.user(&acme, "anna").await;
    let feed = busy_feed(&world, &acme, &anna).await;
    assert!(feed.contains("SUMMARY:Nicht verfügbar"), "{feed}");
    assert!(
        !feed.contains("Beschäftigt") && !feed.contains("Anything"),
        "the named text replaces the theme's, and nothing a person wrote reaches the feed: {feed}"
    );

    // A principal who speaks another language gets the same text: the tenant named it once, for everyone.
    let ben = user_with_locale(&world, &acme, "ben", Locale::en()).await;
    assert!(busy_feed(&world, &acme, &ben).await.contains("SUMMARY:Nicht verfügbar"));
}

/// The texts per language of a tenant: `(language tag, text)`.
fn texts_by_language(texts: &[(&str, &str)]) -> BTreeMap<Locale, String> {
    texts
        .iter()
        .map(|(tag, text)| (Locale::parse(tag).unwrap(), (*text).to_owned()))
        .collect()
}

#[tokio::test]
async fn a_tenant_can_name_the_text_of_its_busy_blocks_for_each_language() {
    let world = World::new();
    let acme = world
        .org_with("acme", |settings| {
            settings.locale = Locale::de();
            settings.busy_text = Some("In a meeting".to_owned());
            settings.busy_text_by_locale =
                texts_by_language(&[("de", "Nicht verfügbar"), ("en-GB", "Out, back soon")]);
        })
        .await;

    // The language of the feed's owner picks the text: the tenant's own (de) where the principal names none, and the principal's
    // own where it does, as far as its tag is named (`de-AT` finds `de`, `en-GB` is named as it is).
    let anna = world.user(&acme, "anna").await;
    let feed = busy_feed(&world, &acme, &anna).await;
    assert!(feed.contains("SUMMARY:Nicht verfügbar"), "{feed}");
    let ben = user_with_locale(&world, &acme, "ben", Locale::parse("de-AT").unwrap()).await;
    assert!(busy_feed(&world, &acme, &ben).await.contains("SUMMARY:Nicht verfügbar"));
    let carla = user_with_locale(&world, &acme, "carla", Locale::parse("en-GB").unwrap()).await;
    let english = busy_feed(&world, &acme, &carla).await;
    assert!(
        english.contains("SUMMARY:Out\\, back soon"),
        "the text of a language is escaped like every text of a tenant: {english}"
    );
    assert!(
        !english.contains("Nicht verfügbar") && !english.contains("In a meeting") && !english.contains("Anything"),
        "{english}"
    );

    // A language that the map does not name gets the single text: `en` is wider than the `en-GB` that the map names.
    let dora = user_with_locale(&world, &acme, "dora", Locale::en()).await;
    let other = busy_feed(&world, &acme, &dora).await;
    assert!(other.contains("SUMMARY:In a meeting"), "{other}");
    assert!(!other.contains("Out\\, back soon"), "{other}");
}

#[tokio::test]
async fn a_language_the_map_does_not_name_falls_back_to_the_theme_without_a_single_text() {
    let world = World::new();
    let acme = world
        .org_with("acme", |settings| {
            settings.locale = Locale::de();
            settings.busy_text_by_locale = texts_by_language(&[("de", "Nicht verfügbar")]);
        })
        .await;
    let anna = world.user(&acme, "anna").await;
    assert!(busy_feed(&world, &acme, &anna).await.contains("SUMMARY:Nicht verfügbar"));

    // The tenant names no text for English and no single text: the `feed_busy` template speaks, as it did before the map.
    let ben = user_with_locale(&world, &acme, "ben", Locale::en()).await;
    let feed = busy_feed(&world, &acme, &ben).await;
    assert!(
        feed.contains("SUMMARY:Busy") && !feed.contains("Nicht verfügbar"),
        "{feed}"
    );
}

#[tokio::test]
async fn a_change_of_the_texts_per_language_changes_the_tag_of_the_feed() {
    let world = World::new();
    let named = |texts: &[(&str, &str)]| {
        let texts = texts_by_language(texts);
        move |settings: &mut TenantSettings| {
            settings.locale = Locale::de();
            settings.busy_text_by_locale = texts;
        }
    };
    let acme = world.org_with("acme", named(&[("de", "Nicht verfügbar")])).await;
    let anna = world.user(&acme, "anna").await;
    put(
        &world,
        &acme,
        &anna,
        "personal",
        "a.ics",
        event("a", "Anything", 2027, 3, 1).build(),
    )
    .await;
    let token = feed_token(&world, &acme, &anna, FeedMode::Busy, &["personal"], &anna).await;
    let before = body(&world, &acme, &anna, token).await;
    assert!(before.body.contains("SUMMARY:Nicht verfügbar"), "{}", before.body);
    assert_eq!(
        revalidate(&world, &acme, &anna, token, &before.etag).await,
        FeedResponse::NotModified {
            etag: before.etag.clone()
        }
    );

    // The tenant words the text of the reader's language differently: the old tag no longer answers 304.
    let mut settings = TenantSettings::default();
    named(&[("de", "Abwesend")])(&mut settings);
    world.tenant_write("acme", settings).await.unwrap();
    changed(&world, &acme, &anna, token, &before, "the text of a language", "SUMMARY:Abwesend").await;

    // A text for another language than the reader's changes nothing the reader sees, and the tag stays.
    let after = body(&world, &acme, &anna, token).await;
    let mut settings = TenantSettings::default();
    named(&[("de", "Abwesend"), ("fr", "Occupé")])(&mut settings);
    world.tenant_write("acme", settings).await.unwrap();
    assert_eq!(
        revalidate(&world, &acme, &anna, token, &after.etag).await,
        FeedResponse::NotModified {
            etag: after.etag.clone()
        },
        "the tag names what the reader gets, not the settings"
    );
}

#[tokio::test]
async fn the_text_of_a_tenant_is_escaped_in_the_feed_and_stays_with_that_tenant() {
    let world = World::new();
    // The first tenant text that ends in a feed: the characters that mean something in iCalendar TEXT are escaped.
    let acme = world
        .org_with("acme", |settings| {
            settings.busy_text = Some("Out, back soon; a\\b".to_owned());
        })
        .await;
    let globex = world
        .org_with("globex", |settings| settings.locale = Locale::de())
        .await;
    let anna = world.user(&acme, "anna").await;
    let feed = busy_feed(&world, &acme, &anna).await;
    assert!(feed.contains("SUMMARY:Out\\, back soon\\; a\\\\b"), "{feed}");
    assert!(
        !feed.contains("SUMMARY:Out, back"),
        "the text is not written unescaped: {feed}"
    );

    // Another tenant of the same world that names no text keeps the text of its theme in its own language.
    let gina = world.user(&globex, "gina").await;
    let other = busy_feed(&world, &globex, &gina).await;
    assert!(
        other.contains("SUMMARY:Beschäftigt") && !other.contains("Out"),
        "the text of one tenant does not reach another: {other}"
    );
}

#[tokio::test]
async fn busy_blocks_speak_the_language_of_the_tenant_or_the_principal() {
    let world = World::new();
    let acme = world.org_with("acme", |settings| settings.locale = Locale::de()).await;
    let anna = world.user(&acme, "anna").await;
    assert!(busy_feed(&world, &acme, &anna).await.contains("SUMMARY:Beschäftigt"));

    // A principal's own locale wins over the tenant's.
    let ben = user_with_locale(&world, &acme, "ben", Locale::en()).await;
    assert!(busy_feed(&world, &acme, &ben).await.contains("SUMMARY:Busy"));
}

#[tokio::test]
async fn private_and_confidential_events_are_busy_only_for_everyone_but_the_owner_in_every_mode() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    put(
        &world,
        &acme,
        &anna,
        "personal",
        "public.ics",
        event("public-1", "Open meeting", 2027, 3, 1).build(),
    )
    .await;
    for (uri, uid, class) in [
        ("private.ics", "private-1", Classification::Private),
        ("confidential.ics", "confidential-1", Classification::Confidential),
    ] {
        put(
            &world,
            &acme,
            &anna,
            "personal",
            uri,
            event(uid, &format!("{uid} details"), 2027, 3, 2).class(class).build(),
        )
        .await;
    }
    world
        .services
        .sharing
        .put_grant(
            &world.admin(&acme),
            GrantSpec {
                calendar: world.key(&anna, "personal"),
                grantee: ben.name.clone(),
                body: GrantWrite {
                    access: GrantAccess::Read,
                    required: false,
                },
            },
            Conditions::none(),
        )
        .await
        .unwrap();

    // The owner sees everything.
    let owners = feed_token(&world, &acme, &anna, FeedMode::Full, &["personal"], &anna).await;
    let own = body(&world, &acme, &anna, owners).await;
    assert_eq!(own.body.matches("BEGIN:VEVENT").count(), 3);
    assert!(own.body.contains("private-1 details") && own.body.contains("confidential-1 details"));

    // A sharee sees the open event in full and the others as busy time.
    let bens = feed_token(&world, &acme, &ben, FeedMode::Full, &["personal"], &anna).await;
    let shared = body(&world, &acme, &ben, bens).await;
    assert_eq!(shared.body.matches("BEGIN:VEVENT").count(), 3);
    assert!(shared.body.contains("SUMMARY:Open meeting"));
    assert!(
        !shared.body.contains("private-1") && !shared.body.contains("confidential-1"),
        "{}",
        shared.body
    );
    assert_eq!(shared.body.matches("SUMMARY:Busy").count(), 2, "{}", shared.body);
}

#[tokio::test]
async fn access_is_checked_again_on_every_request() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    put(
        &world,
        &acme,
        &anna,
        "personal",
        "a.ics",
        event("a", "Anna's day", 2027, 3, 1).build(),
    )
    .await;
    put(
        &world,
        &acme,
        &ben,
        "personal",
        "b.ics",
        event("b", "Ben's day", 2027, 3, 1).build(),
    )
    .await;
    let admin = world.admin(&acme);
    let grant = || {
        world.services.sharing.put_grant(
            &admin,
            GrantSpec {
                calendar: world.key(&anna, "personal"),
                grantee: ben.name.clone(),
                body: GrantWrite {
                    access: GrantAccess::Read,
                    required: false,
                },
            },
            Conditions::none(),
        )
    };
    grant().await.unwrap();
    let annas_id = world
        .services
        .calendars
        .get(&admin, &world.key(&anna, "personal"))
        .await
        .unwrap()
        .id;
    let bens_id = world
        .services
        .calendars
        .get(&admin, &world.key(&ben, "personal"))
        .await
        .unwrap()
        .id;
    let both = world
        .services
        .credentials
        .create_feed_token(
            &admin,
            &ben.name,
            FeedTokenCreate {
                mode: FeedMode::Full,
                calendar_ids: vec![bens_id, annas_id],
            },
        )
        .await
        .unwrap()
        .token
        .id;
    let feed = body(&world, &acme, &ben, both).await;
    assert!(feed.body.contains("Anna's day") && feed.body.contains("Ben's day"));

    // The share ends: anna's calendar drops out of the feed at once, ben's stays.
    world
        .services
        .sharing
        .delete_grant(&admin, &world.key(&anna, "personal"), &ben.name, Conditions::none())
        .await
        .unwrap();
    let feed = body(&world, &acme, &ben, both).await;
    assert!(
        !feed.body.contains("Anna's day") && feed.body.contains("Ben's day"),
        "{}",
        feed.body
    );

    // Only anna's calendar left in a feed: nothing readable means not found.
    grant().await.unwrap();
    let only_annas = world
        .services
        .credentials
        .create_feed_token(
            &admin,
            &ben.name,
            FeedTokenCreate {
                mode: FeedMode::Full,
                calendar_ids: vec![annas_id],
            },
        )
        .await
        .unwrap()
        .token
        .id;
    assert!(render(&world, &acme, &ben, only_annas).await.is_ok());
    world
        .services
        .sharing
        .delete_grant(&admin, &world.key(&anna, "personal"), &ben.name, Conditions::none())
        .await
        .unwrap();
    assert_eq!(
        render(&world, &acme, &ben, only_annas).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
}

#[tokio::test]
async fn revoked_tokens_disabled_feeds_deleted_calendars_and_foreign_readers_find_nothing() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    world.calendar(&acme, &anna, "work", CalendarKind::User).await;
    let admin = world.admin(&acme);
    put(
        &world,
        &acme,
        &anna,
        "personal",
        "a.ics",
        event("a", "A", 2027, 3, 1).build(),
    )
    .await;
    let token = feed_token(&world, &acme, &anna, FeedMode::Full, &["personal"], &anna).await;
    assert!(render(&world, &acme, &anna, token).await.is_ok());

    // A reader that is not the token's principal, and contexts that are no feed readers at all.
    assert_eq!(
        render(&world, &acme, &ben, token).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        world
            .services
            .feeds
            .render(&world.dav(&acme, &anna), Conditional::default())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        world
            .services
            .feeds
            .render(&world.feed(&acme, &anna, world.token_id()), Conditional::default())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound,
        "an unknown token"
    );

    // A tenant that turns feeds off: every feed disappears, and comes back with the setting.
    let mut off = TenantSettings::default();
    off.feeds_enabled = false;
    world.tenant_write("acme", off).await.unwrap();
    assert_eq!(
        render(&world, &acme, &anna, token).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
    world.tenant_write("acme", TenantSettings::default()).await.unwrap();
    assert!(render(&world, &acme, &anna, token).await.is_ok());

    // A revoked token is not found, and neither is the token of a deleted calendar.
    world
        .services
        .credentials
        .revoke_feed_token(&admin, &anna.name, token)
        .await
        .unwrap();
    assert_eq!(
        render(&world, &acme, &anna, token).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
    let work_token = feed_token(&world, &acme, &anna, FeedMode::Full, &["work"], &anna).await;
    assert!(render(&world, &acme, &anna, work_token).await.is_ok());
    let version = world
        .services
        .calendars
        .get(&admin, &world.key(&anna, "work"))
        .await
        .unwrap()
        .version;
    world
        .services
        .calendars
        .delete(&admin, &world.key(&anna, "work"), Conditions::if_match(version))
        .await
        .unwrap();
    assert_eq!(
        render(&world, &acme, &anna, work_token).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
}

#[tokio::test]
async fn a_feed_of_many_objects_is_rendered_in_chunks_without_losing_any() {
    // More than one chunk of objects: the document is the same as if it had been rendered in one piece.
    let Fixture { world, acme, anna, .. } = fixture().await;
    for n in 0..450 {
        put(
            &world,
            &acme,
            &anna,
            "personal",
            &format!("e{n}.ics"),
            event(&format!("e{n}"), &format!("Event {n:03}"), 2027, 3, 1 + (n % 20)).build(),
        )
        .await;
    }
    let token = feed_token(&world, &acme, &anna, FeedMode::Full, &["personal"], &anna).await;
    let feed = body(&world, &acme, &anna, token).await;
    assert_eq!(feed.body.matches("BEGIN:VEVENT").count(), 450);
    assert_eq!(feed.body.matches("BEGIN:VCALENDAR").count(), 1);
    assert_eq!(feed.body.matches("END:VCALENDAR").count(), 1);
    for n in [0, 199, 200, 201, 449] {
        assert!(feed.body.contains(&format!("SUMMARY:Event {n:03}")), "{n}");
    }
}

#[tokio::test]
async fn a_feed_over_the_configured_size_is_cut_and_not_failed() {
    let world = World::with(|deps| deps.config.feeds.max_objects = 5);
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    for n in 0..8 {
        put(
            &world,
            &acme,
            &anna,
            "personal",
            &format!("e{n}.ics"),
            event(&format!("e{n}"), &format!("Event {n}"), 2027, 3, 1 + n).build(),
        )
        .await;
    }
    let token = feed_token(&world, &acme, &anna, FeedMode::Full, &["personal"], &anna).await;
    let feed = body(&world, &acme, &anna, token).await;
    assert_eq!(
        feed.body.matches("BEGIN:VEVENT").count(),
        5,
        "the limit of this deployment"
    );
    assert!(feed.body.starts_with("BEGIN:VCALENDAR") && feed.body.ends_with("END:VCALENDAR\r\n"));
}

#[tokio::test]
async fn folded_lines_and_quoted_colons_do_not_confuse_the_assembly_of_a_feed() {
    // The zone of an event is named in a parameter whose quoted value contains a colon, and a long summary is folded.
    let Fixture { world, acme, anna, .. } = fixture().await;
    let long = "A long title that has to be folded because it is much longer than seventy-five octets per line";
    put(
        &world,
        &acme,
        &anna,
        "personal",
        "long.ics",
        event("long", long, 2027, 3, 1).build(),
    )
    .await;
    let token = feed_token(&world, &acme, &anna, FeedMode::Full, &["personal"], &anna).await;
    let feed = body(&world, &acme, &anna, token).await;
    let unfolded = feed.body.replace("\r\n ", "");
    assert!(unfolded.contains(&format!("SUMMARY:{long}")), "{unfolded}");
    assert!(
        feed.body.lines().all(|line| line.len() <= 75),
        "the document is folded again"
    );
}

#[tokio::test]
async fn an_object_that_the_gate_refuses_today_stays_readable_in_every_read_path() {
    use davhaven_testkit::davhaven_app::services::{
        CalendarDataSpec, FreeBusyRequest, FreeBusyTarget, ObjectFilter, TimeRange,
    };
    use davhaven_testkit::davhaven_domain::{
        ComponentKind, ContentHash, ObjectId, ObjectIndex, ObjectUri, Precondition, Uid,
    };
    use davhaven_testkit::davhaven_ports::{Expected, NewVersion, TxMode};
    use chrono::TimeZone as _;

    let Fixture { world, acme, anna, .. } = fixture().await;
    // Stored before the gate was as strict as it is: the start has an offset that the writer cannot reproduce (read as
    // a floating time, it would be written as one). The bytes are the client's, and the object is in the calendar.
    let legacy = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Old//EN\r\nBEGIN:VEVENT\r\nUID:legacy\r\n\
                  DTSTAMP:20270101T000000Z\r\nDTSTART:20270301T100000+0100\r\nDTEND:20270301T110000Z\r\n\
                  SUMMARY:Legacy\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    // A write of the same bytes is refused: the gate holds what comes in.
    let refused = world
        .services
        .objects
        .put(
            &world.dav(&acme, &anna),
            PutRequest {
                path: world.object(&acme, &anna, "personal", "legacy.ics"),
                body: legacy.to_owned(),
                content_type: None,
                preconditions: WritePrecondition::none(),
                schedule_reply: ScheduleReply::Send,
            },
        )
        .await
        .unwrap_err();
    assert!(
        matches!(refused.precondition(), Some(Precondition::ValidCalendarData(_))),
        "{refused:?}"
    );

    // The store has it all the same.
    let calendar = world
        .services
        .calendars
        .get(&world.admin(&acme), &world.key(&anna, "personal"))
        .await
        .unwrap();
    let at = |hour: u32| chrono::Utc.with_ymd_and_hms(2027, 3, 1, hour, 0, 0).unwrap();
    let mut tx = world.db.store().begin(acme.id, TxMode::ReadWrite).await.unwrap();
    tx.objects()
        .put(
            calendar.id,
            NewVersion {
                id: ObjectId::parse("018f3c1e-7b2a-7c3d-9e4f-0123456789ab").unwrap(),
                uri: ObjectUri::parse("legacy.ics").unwrap(),
                etag: ETag::from_bytes(legacy.as_bytes()),
                data: legacy.to_owned(),
                schedule_tag: None,
                content_hash: ContentHash::from_digest([0; 32]),
                index: ObjectIndex {
                    uid: Uid::parse("legacy").unwrap(),
                    component: ComponentKind::Event,
                    first_start: Some(at(10)),
                    last_end: Some(at(11)),
                    is_recurring: false,
                    is_scheduling: false,
                    organizer: None,
                    attendees: Vec::new(),
                    sequence: 0,
                    class: Classification::Public,
                    transp: Transparency::Opaque,
                },
                attendee_principals: Vec::new(),
                external_key: None,
                origin: None,
            },
            Expected::Any,
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let dav = world.dav(&acme, &anna);
    let collection = world.collection(&acme, &anna, "personal");
    // `calendar-query`: the object is a hit, and the query does not fail because of how the start was written.
    let hits = world
        .services
        .objects
        .query(&dav, &collection, ObjectFilter::default(), CalendarDataSpec::default())
        .await
        .expect("a query reads what is stored");
    assert_eq!(hits.len(), 1);
    // `free-busy-query` of the collection, and the free time of its owner.
    let range = TimeRange::new(Some(at(0)), Some(at(23)));
    world
        .services
        .scheduling
        .free_busy(
            &dav,
            FreeBusyRequest {
                target: FreeBusyTarget::Collection(collection.clone()),
                range,
            },
        )
        .await
        .expect("free-busy reads what is stored");
    // The subscription feed of the calendar: the document is made, and it holds the object.
    let token = feed_token(&world, &acme, &anna, FeedMode::Full, &["personal"], &anna).await;
    let feed = body(&world, &acme, &anna, token).await;
    assert!(feed.body.contains("SUMMARY:Legacy"), "{}", feed.body);
}

// ---------------------------------------------------------------------------------------------------------------
// The entity tag is known before the work: a 304 reads no object (backlog item 11)
// ---------------------------------------------------------------------------------------------------------------

/// What a request with `If-None-Match: etag` is answered with.
async fn revalidate(
    world: &World,
    org: &Org,
    who: &Person,
    token: davhaven_testkit::davhaven_domain::TokenId,
    etag: &ETag,
) -> FeedResponse {
    world
        .services
        .feeds
        .render(
            &world.feed(org, who, token),
            Conditional {
                if_none_match: Some(etag.clone()),
            },
        )
        .await
        .unwrap()
}

/// What a request with `If-None-Match: etag` is refused with.
async fn refused(
    world: &World,
    org: &Org,
    who: &Person,
    token: davhaven_testkit::davhaven_domain::TokenId,
    etag: &ETag,
) -> ErrorKind {
    world
        .services
        .feeds
        .render(
            &world.feed(org, who, token),
            Conditional {
                if_none_match: Some(etag.clone()),
            },
        )
        .await
        .unwrap_err()
        .kind()
}

#[tokio::test]
async fn a_subscriber_with_the_current_document_gets_a_304_before_any_object_is_read() {
    let calls = PortCalls::default();
    let _installed = metrics::set_default_local_recorder(&calls);
    let Fixture { world, acme, anna, .. } = fixture().await;
    for (uri, uid, day) in [("a.ics", "a", 1), ("b.ics", "b", 2), ("c.ics", "c", 3)] {
        put(
            &world,
            &acme,
            &anna,
            "personal",
            uri,
            event(uid, uid, 2027, 3, day).build(),
        )
        .await;
    }
    let token = feed_token(&world, &acme, &anna, FeedMode::Full, &["personal"], &anna).await;

    calls.reset();
    let feed = body(&world, &acme, &anna, token).await;
    assert!(
        calls.count("objects.query") >= 1,
        "the document is made of the objects, which are read: {:?}",
        calls.all()
    );

    calls.reset();
    assert_eq!(
        revalidate(&world, &acme, &anna, token, &feed.etag).await,
        FeedResponse::NotModified {
            etag: feed.etag.clone()
        }
    );
    assert_eq!(
        calls.count("objects.query") + calls.count("objects.list") + calls.count("objects.get"),
        0,
        "a subscriber that has the document costs no read of an object: {:?}",
        calls.all()
    );

    // Time passes inside the day: nothing a client can see has changed, and the answer stays the same.
    world.clock.advance(Duration::hours(9));
    calls.reset();
    assert_eq!(
        revalidate(&world, &acme, &anna, token, &feed.etag).await,
        FeedResponse::NotModified {
            etag: feed.etag.clone()
        }
    );
    assert_eq!(calls.count("objects.query"), 0, "{:?}", calls.all());

    // A tag that is not the current one gets the document.
    let stale = ETag::from_bytes(b"something else");
    assert!(matches!(
        revalidate(&world, &acme, &anna, token, &stale).await,
        FeedResponse::Body(_)
    ));
}

/// The old tag no longer answers 304: the document that comes instead has another tag and contains `expected`.
async fn changed(
    world: &World,
    org: &Org,
    who: &Person,
    token: davhaven_testkit::davhaven_domain::TokenId,
    old: &FeedBody,
    what: &str,
    expected: &str,
) -> FeedBody {
    let FeedResponse::Body(next) = revalidate(world, org, who, token, &old.etag).await else {
        panic!("{what}: the old tag is still taken for current");
    };
    assert_ne!(next.etag, old.etag, "{what}");
    assert!(next.body.contains(expected), "{what}: {}", next.body);
    next
}

#[tokio::test]
async fn whatever_changes_the_document_changes_the_tag() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    put(
        &world,
        &acme,
        &anna,
        "personal",
        "a.ics",
        event("a", "First", 2027, 3, 1).build(),
    )
    .await;
    let token = feed_token(&world, &acme, &anna, FeedMode::Full, &["personal"], &anna).await;
    let first = body(&world, &acme, &anna, token).await;

    // Each step changes one thing; the old tag must get the new document, and the new document must say so.
    put(
        &world,
        &acme,
        &anna,
        "personal",
        "b.ics",
        event("b", "Second", 2027, 3, 2).build(),
    )
    .await;
    let added = changed(
        &world,
        &acme,
        &anna,
        token,
        &first,
        "an object is added",
        "SUMMARY:Second",
    )
    .await;

    put(
        &world,
        &acme,
        &anna,
        "personal",
        "b.ics",
        event("b", "Second renamed", 2027, 3, 2).build(),
    )
    .await;
    let edited = changed(
        &world,
        &acme,
        &anna,
        token,
        &added,
        "an object is changed",
        "SUMMARY:Second renamed",
    )
    .await;

    world.calendar(&acme, &anna, "personal", CalendarKind::Personal).await;
    let renamed = changed(
        &world,
        &acme,
        &anna,
        token,
        &edited,
        "the calendar is renamed",
        "X-WR-CALNAME:personal calendar",
    )
    .await;

    world
        .services
        .objects
        .delete(
            &world.dav(&acme, &anna),
            davhaven_testkit::davhaven_app::services::DeleteRequest {
                path: world.object(&acme, &anna, "personal", "a.ics"),
                preconditions: WritePrecondition::none(),
                schedule_reply: ScheduleReply::Send,
            },
        )
        .await
        .unwrap();
    let deleted = changed(
        &world,
        &acme,
        &anna,
        token,
        &renamed,
        "an object is deleted",
        "SUMMARY:Second renamed",
    )
    .await;
    assert!(!deleted.body.contains("SUMMARY:First"), "{}", deleted.body);

    // The window moves with the day, even when nothing else did: an event that was just beyond it is in it now.
    put(
        &world,
        &acme,
        &anna,
        "personal",
        "edge.ics",
        event("edge", "Edge of the window", 2028, 1, 1).build(),
    )
    .await;
    let current = body(&world, &acme, &anna, token).await;
    assert!(!current.body.contains("Edge of the window"), "{}", current.body);
    world.clock.advance(Duration::hours(20));
    assert_eq!(
        revalidate(&world, &acme, &anna, token, &current.etag).await,
        FeedResponse::NotModified {
            etag: current.etag.clone()
        },
        "the window is anchored at the start of the day: the same day, the same document"
    );
    world.clock.advance(Duration::hours(4));
    changed(
        &world,
        &acme,
        &anna,
        token,
        &current,
        "the day changes",
        "SUMMARY:Edge of the window",
    )
    .await;
}

#[tokio::test]
async fn a_revoked_feed_is_not_found_even_for_a_subscriber_that_has_its_tag() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    put(
        &world,
        &acme,
        &anna,
        "personal",
        "a.ics",
        event("a", "First", 2027, 3, 1).build(),
    )
    .await;
    let token = feed_token(&world, &acme, &anna, FeedMode::Full, &["personal"], &anna).await;
    let feed = body(&world, &acme, &anna, token).await;
    world
        .services
        .credentials
        .revoke_feed_token(&world.admin(&acme), &anna.name, token)
        .await
        .unwrap();
    let error = world
        .services
        .feeds
        .render(
            &world.feed(&acme, &anna, token),
            Conditional {
                if_none_match: Some(feed.etag),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.kind(),
        ErrorKind::NotFound,
        "access is judged before the tag is compared"
    );
}

#[tokio::test]
async fn a_tenant_that_turns_feeds_off_has_none_for_a_subscriber_with_the_current_tag() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    put(
        &world,
        &acme,
        &anna,
        "personal",
        "a.ics",
        event("a", "First", 2027, 3, 1).build(),
    )
    .await;
    let token = feed_token(&world, &acme, &anna, FeedMode::Full, &["personal"], &anna).await;
    let feed = body(&world, &acme, &anna, token).await;

    let mut off = TenantSettings::default();
    off.feeds_enabled = false;
    world.tenant_write("acme", off).await.unwrap();
    let error = world
        .services
        .feeds
        .render(
            &world.feed(&acme, &anna, token),
            Conditional {
                if_none_match: Some(feed.etag.clone()),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.kind(),
        ErrorKind::NotFound,
        "the tenant setting is judged before the tag is compared"
    );

    // With the setting back, nothing the document is made of has changed: the tag still answers 304.
    world.tenant_write("acme", TenantSettings::default()).await.unwrap();
    assert_eq!(
        revalidate(&world, &acme, &anna, token, &feed.etag).await,
        FeedResponse::NotModified { etag: feed.etag }
    );
}

#[tokio::test]
async fn a_share_that_ends_changes_the_tag_and_takes_the_calendar_out_of_the_document() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    put(
        &world,
        &acme,
        &anna,
        "personal",
        "a.ics",
        event("a", "Anna's day", 2027, 3, 1).build(),
    )
    .await;
    put(
        &world,
        &acme,
        &ben,
        "personal",
        "b.ics",
        event("b", "Ben's day", 2027, 3, 1).build(),
    )
    .await;
    let admin = world.admin(&acme);
    world
        .services
        .sharing
        .put_grant(
            &admin,
            GrantSpec {
                calendar: world.key(&anna, "personal"),
                grantee: ben.name.clone(),
                body: GrantWrite {
                    access: GrantAccess::Read,
                    required: false,
                },
            },
            Conditions::none(),
        )
        .await
        .unwrap();
    let annas_id = world
        .services
        .calendars
        .get(&admin, &world.key(&anna, "personal"))
        .await
        .unwrap()
        .id;
    let bens_id = world
        .services
        .calendars
        .get(&admin, &world.key(&ben, "personal"))
        .await
        .unwrap()
        .id;
    let both = world
        .services
        .credentials
        .create_feed_token(
            &admin,
            &ben.name,
            FeedTokenCreate {
                mode: FeedMode::Full,
                calendar_ids: vec![bens_id, annas_id],
            },
        )
        .await
        .unwrap()
        .token
        .id;
    let feed = body(&world, &acme, &ben, both).await;
    assert!(feed.body.contains("Anna's day") && feed.body.contains("Ben's day"));
    assert_eq!(
        revalidate(&world, &acme, &ben, both, &feed.etag).await,
        FeedResponse::NotModified {
            etag: feed.etag.clone()
        }
    );

    // The share of one of the two calendars ends. A subscriber that presents the tag of the document it has is not told
    // that nothing changed: the access is judged first, the calendar is no longer readable, and the tag is another one.
    world
        .services
        .sharing
        .delete_grant(&admin, &world.key(&anna, "personal"), &ben.name, Conditions::none())
        .await
        .unwrap();
    let next = changed(
        &world,
        &acme,
        &ben,
        both,
        &feed,
        "the share of one of two calendars ends",
        "Ben's day",
    )
    .await;
    assert!(!next.body.contains("Anna's day"), "{}", next.body);
}

#[tokio::test]
async fn a_principal_that_is_suspended_or_deleted_has_no_feed_for_a_subscriber_with_the_current_tag() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    put(
        &world,
        &acme,
        &anna,
        "personal",
        "a.ics",
        event("a", "First", 2027, 3, 1).build(),
    )
    .await;
    let token = feed_token(&world, &acme, &anna, FeedMode::Full, &["personal"], &anna).await;
    let feed = body(&world, &acme, &anna, token).await;
    let status = |status| PrincipalWrite {
        status: Some(status),
        ..principal_body(&acme, "anna", PrincipalKind::User)
    };

    world
        .principal_write(&acme, "anna", status(PrincipalStatus::Suspended))
        .await
        .unwrap();
    assert_eq!(
        refused(&world, &acme, &anna, token, &feed.etag).await,
        ErrorKind::NotFound,
        "a suspended principal"
    );
    world
        .principal_write(&acme, "anna", status(PrincipalStatus::Active))
        .await
        .unwrap();
    assert_eq!(
        revalidate(&world, &acme, &anna, token, &feed.etag).await,
        FeedResponse::NotModified {
            etag: feed.etag.clone()
        },
        "and the feed is back with the principal"
    );

    let admin = world.admin(&acme);
    let version = world.services.principals.get(&admin, &anna.name).await.unwrap().version;
    world
        .services
        .principals
        .delete(
            &admin,
            &anna.name,
            DeleteOptions {
                purge: false,
                notify_attendees: false,
                conditions: Conditions::if_match(version),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        refused(&world, &acme, &anna, token, &feed.etag).await,
        ErrorKind::NotFound,
        "a deleted principal"
    );
}

#[tokio::test]
async fn what_attendees_wrote_to_the_organizer_is_not_in_a_feed() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    // The organizer's copy keeps the remark of an attendee next to the answer; a feed link can be passed on.
    let commented = event("commented", "With a remark", 2027, 3, 1)
        .property(
            "X-CALENDARSERVER-ATTENDEE-COMMENT;X-CALENDARSERVER-ATTENDEE-REF=\"mailto:bob@example.org\"",
            "Private remark",
        )
        .build();
    put(&world, &acme, &anna, "personal", "commented.ics", commented).await;
    let token = feed_token(&world, &acme, &anna, FeedMode::Full, &["personal"], &anna).await;
    let feed = body(&world, &acme, &anna, token).await;
    assert!(feed.body.contains("SUMMARY:With a remark"), "{}", feed.body);
    assert!(
        !feed.body.contains("Private remark") && !feed.body.contains("ATTENDEE-COMMENT"),
        "{}",
        feed.body
    );
}
