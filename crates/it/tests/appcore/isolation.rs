//! Tenant isolation through the services: whatever another tenant owns, no operation of this tenant can read it,
//! change it or even tell that it exists, and the attempts leave the other tenant exactly as it was.
//!
//! Two tenants, `alpha` and `bravo`, have principals with the same names. Alpha owns calendars, objects, shares and
//! credentials; bravo's contexts try to reach all of them by id, by natural key and through DAV paths that carry
//! alpha's slug. Every attempt must answer "not found" (or, where the request is about bravo's own data and merely
//! names something foreign, "invalid"), and alpha must not change.

use core::fmt::Debug;

use davhaven_testkit::davhaven_app::error::AppError;
use davhaven_testkit::davhaven_app::services::{
    AuditFilter, CalendarDataSpec, CalendarRef, Conditional, Conditions, CopyRequest, DeleteEventOptions,
    DeleteOptions, DeleteRequest, EventSearch, EventWrite, GrantSpec, InviteReply, MergePatch, MkCalendar, MoveRequest,
    NotificationView, ObjectFilter, ObjectSelector, PageRequest, PrincipalFilter, PrincipalSearch, PropPatch, PropertyChange,
    PutRequest, ScheduleReply, ShareRequest, ShareeSet, WritePrecondition,
};
use davhaven_testkit::davhaven_domain::{
    CalendarKind, CalendarSlug, CalendarUserAddress, ErrorKind, EventData, ExternalKey, FeedMode, GrantAccess,
    ObjectUri, PrincipalName, RequestContext, ResourcePath, Scope, ScopeSet, StoredObject, SyncToken, Uid,
};
use davhaven_testkit::davhaven_wire::mcp::ChangeScope;
use davhaven_testkit::davhaven_wire::{
    AppPasswordCreate, AppPasswordCreated, BatchItem, BatchRequest, CalendarView, EventView, FeedTokenCreate,
    FeedTokenCreated, GrantWrite,
};

use super::support::{Org, Person, World, ics};

#[track_caller]
fn hidden<T: Debug>(name: &str, result: Result<T, AppError>) {
    match result {
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        other => panic!("{name}: expected not found, got {other:?}"),
    }
}

fn name(text: &str) -> PrincipalName {
    PrincipalName::parse(text).unwrap()
}

fn event(key: &str) -> EventWrite {
    EventWrite {
        target: Some(ObjectSelector::Key(ExternalKey::parse(key).unwrap())),
        event: EventView::from_data(EventData {
            summary: Some("Intruder".to_owned()),
            start: Some(serde_json::from_value(serde_json::json!({"date": "2027-03-01"})).unwrap()),
            ..EventData::default()
        }),
        notify_attendees: false,
        if_match: None,
        scope: ChangeScope::All,
    }
}

/// What alpha looks like at a moment: the size of its logs and the positions of its calendars.
#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    audits: usize,
    events: usize,
    work: SyncToken,
    personal: SyncToken,
}

/// Alpha with its data, bravo with the contexts that try to get at it.
struct Duo {
    world: World,
    alpha: Org,
    bravo: Org,
    // Alpha.
    admin_a: RequestContext,
    alice: Person,
    anna_a: Person,
    ben_a: Person,
    work: CalendarView,
    personal: CalendarView,
    shared: CalendarView,
    object: StoredObject,
    notification: NotificationView,
    password: AppPasswordCreated,
    feed: FeedTokenCreated,
    // Bravo.
    admin_b: RequestContext,
    dav_b: RequestContext,
    api_b: RequestContext,
    mcp_b: RequestContext,
    anna_b: Person,
    ben_b: Person,
}

async fn duo() -> Duo {
    let world = World::new();
    let alpha = world.org("alpha").await;
    let bravo = world.org("bravo").await;
    // `alice-only` exists in alpha only; `anna`, `ben` and `team` exist in both tenants.
    let alice = world.user(&alpha, "alice-only").await;
    let anna_a = world.user(&alpha, "anna").await;
    let ben_a = world.user(&alpha, "ben").await;
    let team_a = world.group(&alpha, "team", &[&anna_a]).await;
    let anna_b = world.user(&bravo, "anna").await;
    let ben_b = world.user(&bravo, "ben").await;
    world.group(&bravo, "team", &[&anna_b]).await;

    let admin_a = world.stored_admin(&alpha).await;
    let work = world.calendar(&alpha, &anna_a, "work", CalendarKind::User).await;
    let personal = world
        .services
        .calendars
        .get(&admin_a, &world.key(&anna_a, "personal"))
        .await
        .unwrap();
    let shared = world.calendar(&alpha, &team_a, "shared", CalendarKind::Group).await;
    let scopes = [
        Scope::CalendarsRead,
        Scope::CalendarsWrite,
        Scope::EventsRead,
        Scope::EventsWrite,
    ];
    let api_a = world.api(&alpha, &anna_a, &scopes);
    world
        .services
        .objects
        .put(
            &world.dav(&alpha, &anna_a),
            PutRequest {
                path: world.object(&alpha, &anna_a, "personal", "x.ics"),
                body: ics("x-1", "Alpha's secret"),
                content_type: None,
                preconditions: WritePrecondition::none(),
                schedule_reply: ScheduleReply::Send,
            },
        )
        .await
        .unwrap();
    world
        .services
        .objects
        .put_event(&api_a, &world.key(&anna_a, "work"), event("k-1"))
        .await
        .unwrap();
    let object = world
        .read(&alpha)
        .await
        .objects()
        .get(personal.id, &ObjectUri::parse("x.ics").unwrap())
        .await
        .unwrap();
    world
        .services
        .sharing
        .share(
            &world.dav(&alpha, &anna_a),
            &world.collection(&alpha, &anna_a, "personal"),
            ShareRequest {
                set: vec![ShareeSet {
                    address: CalendarUserAddress::parse("mailto:ben@alpha.example").unwrap(),
                    common_name: None,
                    summary: None,
                    access: GrantAccess::Read,
                }],
                remove: Vec::new(),
            },
        )
        .await
        .unwrap();
    let notification = world
        .services
        .sharing
        .list_notifications(&world.dav(&alpha, &ben_a), &ben_a.name)
        .await
        .unwrap()
        .remove(0);
    world
        .services
        .sharing
        .put_grant(
            &admin_a,
            GrantSpec {
                calendar: world.key(&anna_a, "work"),
                grantee: ben_a.name.clone(),
                body: GrantWrite {
                    access: GrantAccess::Read,
                    required: false,
                },
            },
            Conditions::none(),
        )
        .await
        .unwrap();
    let password = world
        .services
        .credentials
        .create_app_password(
            &admin_a,
            &anna_a.name,
            AppPasswordCreate {
                label: "alpha phone".to_owned(),
            },
        )
        .await
        .unwrap();
    let feed = world
        .services
        .credentials
        .create_feed_token(
            &admin_a,
            &anna_a.name,
            FeedTokenCreate {
                mode: FeedMode::Full,
                calendar_ids: vec![personal.id],
            },
        )
        .await
        .unwrap();

    Duo {
        admin_b: world.stored_admin(&bravo).await,
        dav_b: world.dav(&bravo, &anna_b),
        api_b: world.api(&bravo, &anna_b, &scopes),
        mcp_b: world.mcp(&bravo, &anna_b, &[Scope::McpRead, Scope::McpWrite]),
        world,
        alpha,
        bravo,
        admin_a,
        alice,
        anna_a,
        ben_a,
        work,
        personal,
        shared,
        object,
        notification,
        password,
        feed,
        anna_b,
        ben_b,
    }
}

impl Duo {
    async fn token_of(&self, id: davhaven_testkit::davhaven_domain::CalendarId) -> SyncToken {
        self.world
            .services
            .calendars
            .get(&self.admin_a, &CalendarRef::Id(id))
            .await
            .unwrap()
            .sync_token
    }

    async fn snapshot(&self) -> Snapshot {
        Snapshot {
            audits: self.world.audit(&self.alpha).await.len(),
            events: self.world.events(&self.alpha).await.len(),
            work: self.token_of(self.work.id).await,
            personal: self.token_of(self.personal.id).await,
        }
    }

    /// Alpha is as it was: no change, no record, no event, no new position in any log, and its data is intact.
    async fn assert_untouched(&self, before: &Snapshot) {
        assert_eq!(&self.snapshot().await, before);
        let world = &self.world;
        let still = world
            .services
            .objects
            .get(
                &world.dav(&self.alpha, &self.anna_a),
                &world.object(&self.alpha, &self.anna_a, "personal", "x.ics"),
            )
            .await
            .unwrap();
        assert!(still.data.unwrap().contains("Alpha's secret"));
        let passwords = world
            .services
            .credentials
            .list_app_passwords(&self.admin_a, &self.anna_a.name, PageRequest::first())
            .await
            .unwrap();
        assert!(passwords.items.first().unwrap().revoked_at.is_none());
    }

    /// Alpha's collection `personal` with the slug of alpha, as bravo's `anna` would write it.
    fn alpha_collection(&self) -> ResourcePath {
        ResourcePath::Collection {
            tenant: self.alpha.slug.clone(),
            principal: self.anna_b.name.clone(),
            binding: CalendarSlug::parse("personal").unwrap(),
        }
    }

    fn alpha_object(&self) -> ResourcePath {
        ResourcePath::Object {
            tenant: self.alpha.slug.clone(),
            principal: self.anna_b.name.clone(),
            binding: CalendarSlug::parse("personal").unwrap(),
            object: self.object.uri.clone(),
        }
    }

    fn alpha_home(&self) -> ResourcePath {
        ResourcePath::Home {
            tenant: self.alpha.slug.clone(),
            principal: self.anna_b.name.clone(),
        }
    }
}

#[tokio::test]
async fn principals_of_another_tenant_do_not_exist_and_shared_names_are_the_own_principals() {
    let d = duo().await;
    let world = &d.world;
    let before = d.snapshot().await;
    let alice = d.alice.name.clone();

    hidden(
        "principals.get",
        world.services.principals.get(&d.admin_b, &alice).await,
    );
    hidden(
        "principals.members",
        world.services.principals.members(&d.admin_b, &alice).await,
    );
    let delete = DeleteOptions {
        conditions: Conditions::if_match(1),
        ..DeleteOptions::default()
    };
    hidden(
        "principals.delete",
        world.services.principals.delete(&d.admin_b, &alice, delete).await,
    );
    let patch = MergePatch::new(serde_json::json!({"display_name": "Hijacked"})).unwrap();
    hidden(
        "principals.patch",
        world
            .services
            .principals
            .patch(&d.admin_b, &alice, patch, Conditions::none())
            .await,
    );
    hidden(
        "calendars.list_owned",
        world
            .services
            .calendars
            .list_owned(&d.admin_b, &alice, PageRequest::first())
            .await,
    );
    hidden(
        "calendars.list_home",
        world.services.calendars.list_home(&d.dav_b, &alice).await,
    );
    hidden(
        "credentials.list_app_passwords",
        world
            .services
            .credentials
            .list_app_passwords(&d.admin_b, &alice, PageRequest::first())
            .await,
    );
    // A member that does not exist in this tenant is an invalid member, not a hint about another tenant.
    let unknown_member = world
        .services
        .principals
        .add_member(&d.admin_b, &name("team"), &alice)
        .await
        .unwrap_err();
    assert_eq!(unknown_member.kind(), ErrorKind::Invalid);
    assert_eq!(
        unknown_member.field_errors().first().map(|field| field.code),
        Some("unknown-member")
    );
    let replaced = world
        .services
        .principals
        .set_members(&d.admin_b, &name("team"), vec![alice.clone()])
        .await
        .unwrap_err();
    assert_eq!(replaced.kind(), ErrorKind::Invalid, "the same when the members are replaced");
    let listed = world
        .services
        .principals
        .list(&d.admin_b, PrincipalFilter::default(), PageRequest::first())
        .await
        .unwrap();
    assert!(
        !listed.items.is_empty() && listed.items.iter().all(|view| view.id != d.alice.id),
        "the list of a tenant holds its own principals only: {:?}",
        listed.items
    );

    // A name both tenants use is the principal of the tenant that asks.
    assert_eq!(
        world
            .services
            .principals
            .get(&d.admin_b, &name("anna"))
            .await
            .unwrap()
            .id,
        d.anna_b.id
    );
    assert_ne!(d.anna_b.id, d.anna_a.id);
    let search = PrincipalSearch::new("alice");
    assert!(
        world
            .services
            .principals
            .search(&d.dav_b, search)
            .await
            .unwrap()
            .is_empty()
    );
    d.assert_untouched(&before).await;
}

#[tokio::test]
async fn calendars_and_their_events_cannot_be_reached_by_id_or_by_key() {
    let d = duo().await;
    let world = &d.world;
    let before = d.snapshot().await;
    let k1 = ExternalKey::parse("k-1").unwrap();

    for (what, id) in [("work", d.work.id), ("personal", d.personal.id), ("group", d.shared.id)] {
        let calendar = CalendarRef::Id(id);
        hidden(
            &format!("calendars.get {what}"),
            world.services.calendars.get(&d.admin_b, &calendar).await,
        );
        hidden(
            &format!("calendars.delete {what}"),
            world
                .services
                .calendars
                .delete(&d.admin_b, &calendar, Conditions::if_match(1))
                .await,
        );
        let patch = MergePatch::new(serde_json::json!({"display_name": "Hijacked"})).unwrap();
        hidden(
            &format!("calendars.patch {what}"),
            world
                .services
                .calendars
                .patch(&d.admin_b, &calendar, patch, Conditions::none())
                .await,
        );
        hidden(
            &format!("objects.get_by_key {what}"),
            world.services.objects.get_by_key(&d.api_b, &calendar, &k1).await,
        );
        hidden(
            &format!("objects.put_event {what}"),
            world
                .services
                .objects
                .put_event(&d.api_b, &calendar, event("k-1"))
                .await,
        );
        hidden(
            &format!("objects.delete_by_key {what}"),
            world
                .services
                .objects
                .delete_by_key(&d.api_b, &calendar, &k1, DeleteEventOptions::default())
                .await,
        );
        hidden(
            &format!("objects.list {what}"),
            world
                .services
                .objects
                .list(&d.api_b, &calendar, ObjectFilter::default(), PageRequest::first())
                .await,
        );
        hidden(
            &format!("objects.changes {what}"),
            world.services.objects.changes(&d.api_b, &calendar, None, None).await,
        );
        let batch = BatchRequest {
            items: vec![BatchItem {
                external_key: ExternalKey::parse("k").unwrap(),
                event: None,
                ical: Some(ics("k", "K")),
            }],
            ..BatchRequest::default()
        };
        hidden(
            &format!("objects.batch {what}"),
            world.services.objects.batch(&d.admin_b, &calendar, batch).await,
        );
        let search = EventSearch {
            calendars: vec![calendar.clone()],
            ..EventSearch::default()
        };
        hidden(
            &format!("objects.search_events {what}"),
            world
                .services
                .objects
                .search_events(&d.mcp_b, search, PageRequest::first())
                .await,
        );
        hidden(
            &format!("sharing.list_grants {what}"),
            world
                .services
                .sharing
                .list_grants(&d.admin_b, &calendar, PageRequest::first())
                .await,
        );
        let grant = GrantSpec {
            calendar: calendar.clone(),
            grantee: d.ben_b.name.clone(),
            body: GrantWrite {
                access: GrantAccess::Admin,
                required: false,
            },
        };
        hidden(
            &format!("sharing.put_grant {what}"),
            world
                .services
                .sharing
                .put_grant(&d.admin_b, grant, Conditions::none())
                .await,
        );
        hidden(
            &format!("sharing.delete_grant {what}"),
            world
                .services
                .sharing
                .delete_grant(&d.admin_b, &calendar, &d.ben_b.name, Conditions::none())
                .await,
        );
    }
    // By the key of a principal that has no such calendar in bravo.
    hidden(
        "calendars.get by key",
        world
            .services
            .calendars
            .get(&d.admin_b, &world.key(&d.anna_b, "work"))
            .await,
    );
    hidden(
        "objects.get_by_key by key",
        world
            .services
            .objects
            .get_by_key(&d.api_b, &world.key(&d.anna_b, "work"), &k1)
            .await,
    );

    // The identity of an object of another tenant, asked for in a calendar of this tenant.
    let own = world.key(&d.anna_b, "personal");
    hidden(
        "objects.get_event by foreign id",
        world
            .services
            .objects
            .get_event(&d.api_b, &own, &ObjectSelector::Id(d.object.id), None)
            .await,
    );
    hidden(
        "objects.delete_event by foreign id",
        world
            .services
            .objects
            .delete_event(
                &d.api_b,
                &own,
                &ObjectSelector::Id(d.object.id),
                DeleteEventOptions::default(),
            )
            .await,
    );
    hidden(
        "objects.get_event by uid",
        world
            .services
            .objects
            .get_event(&d.api_b, &own, &ObjectSelector::Uid(Uid::parse("x-1").unwrap()), None)
            .await,
    );
    d.assert_untouched(&before).await;
}

#[tokio::test]
async fn dav_paths_with_the_slug_of_another_tenant_resolve_to_nothing() {
    let d = duo().await;
    let world = &d.world;
    let before = d.snapshot().await;
    let (collection, object, home) = (d.alpha_collection(), d.alpha_object(), d.alpha_home());
    let dav = &d.dav_b;

    hidden(
        "get_collection",
        world.services.calendars.get_collection(dav, &collection).await,
    );
    hidden(
        "get_collection of the home",
        world.services.calendars.get_collection(dav, &home).await,
    );
    let mkcalendar = MkCalendar {
        path: ResourcePath::Collection {
            tenant: d.alpha.slug.clone(),
            principal: d.anna_b.name.clone(),
            binding: CalendarSlug::parse("new").unwrap(),
        },
        display_name: None,
        description: None,
        color: None,
        sort_order: None,
        components: None,
        timezone_ics: None,
        schedule_transp: None,
        dead_properties: Vec::new(),
    };
    hidden("mkcalendar", world.services.calendars.mkcalendar(dav, mkcalendar).await);
    let patch = PropPatch {
        changes: vec![PropertyChange::DisplayName(Some("x".to_owned()))],
    };
    hidden(
        "proppatch",
        world.services.calendars.proppatch(dav, &collection, patch).await,
    );
    hidden(
        "delete_collection",
        world
            .services
            .calendars
            .delete_collection(dav, &collection, Conditions::none())
            .await,
    );
    hidden("get", world.services.objects.get(dav, &object).await);
    let put = PutRequest {
        path: object.clone(),
        body: ics("x-1", "Overwritten"),
        content_type: None,
        preconditions: WritePrecondition::none(),
        schedule_reply: ScheduleReply::Send,
    };
    hidden("put", world.services.objects.put(dav, put).await);
    let delete = DeleteRequest {
        path: object.clone(),
        preconditions: WritePrecondition::none(),
        schedule_reply: ScheduleReply::Send,
    };
    hidden("delete", world.services.objects.delete(dav, delete).await);
    let own = world.object(&d.bravo, &d.anna_b, "personal", "stolen.ics");
    let move_from = MoveRequest {
        from: object.clone(),
        to: own.clone(),
        overwrite: false,
        preconditions: WritePrecondition::none(),
    };
    hidden("move from", world.services.objects.move_to(dav, move_from).await);
    let copy_from = CopyRequest {
        from: object.clone(),
        to: own,
        overwrite: false,
    };
    hidden("copy from", world.services.objects.copy_to(dav, copy_from).await);
    hidden(
        "multiget",
        world
            .services
            .objects
            .multiget(dav, &collection, vec![object.clone()], CalendarDataSpec::default())
            .await,
    );
    hidden(
        "query",
        world
            .services
            .objects
            .query(dav, &collection, ObjectFilter::default(), CalendarDataSpec::default())
            .await,
    );
    hidden("sync", world.services.objects.sync(dav, &collection, None, None).await);
    hidden(
        "share",
        world
            .services
            .sharing
            .share(dav, &collection, ShareRequest::default())
            .await,
    );
    d.assert_untouched(&before).await;
}

#[tokio::test]
async fn invitations_and_notifications_of_another_tenant_cannot_be_answered_read_or_deleted() {
    let d = duo().await;
    let world = &d.world;
    let before = d.snapshot().await;
    let bens = world.dav(&d.bravo, &d.ben_b);
    let reply = |in_reply_to: &Uid| InviteReply {
        in_reply_to: in_reply_to.clone(),
        accepted: true,
        host_url: None,
        summary: None,
    };

    hidden(
        "reply_invite in alpha's home",
        world
            .services
            .sharing
            .reply_invite(&d.dav_b, &d.alpha_home(), reply(&d.notification.uid))
            .await,
    );
    hidden(
        "reply_invite to alpha's invitation",
        world
            .services
            .sharing
            .reply_invite(&bens, &world.home(&d.bravo, &d.ben_b), reply(&d.notification.uid))
            .await,
    );
    hidden(
        "get_notification",
        world
            .services
            .sharing
            .get_notification(&bens, &d.notification.path)
            .await,
    );
    hidden(
        "delete_notification",
        world
            .services
            .sharing
            .delete_notification(&bens, &d.notification.path)
            .await,
    );
    assert!(
        world
            .services
            .sharing
            .list_notifications(&bens, &d.ben_b.name)
            .await
            .unwrap()
            .is_empty()
    );
    d.assert_untouched(&before).await;
    // The invitation is still there for the one it was made for.
    let alphas = world.dav(&d.alpha, &d.ben_a);
    assert_eq!(
        world
            .services
            .sharing
            .list_notifications(&alphas, &d.ben_a.name)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn credentials_feeds_and_the_audit_log_of_another_tenant_are_out_of_reach() {
    let d = duo().await;
    let world = &d.world;
    let before = d.snapshot().await;
    let credentials = &world.services.credentials;

    // Ids of alpha's credentials belong to nobody in bravo, whoever carries the name.
    hidden(
        "revoke_app_password",
        credentials
            .revoke_app_password(&d.admin_b, &d.anna_b.name, d.password.id)
            .await,
    );
    hidden(
        "revoke_feed_token",
        credentials
            .revoke_feed_token(&d.admin_b, &d.anna_b.name, d.feed.token.id)
            .await,
    );
    hidden(
        "rotate_feed_token",
        credentials
            .rotate_feed_token(&d.admin_b, &d.anna_b.name, d.feed.token.id)
            .await,
    );
    hidden(
        "revoke_api_token",
        credentials
            .revoke_api_token(&d.admin_b, d.admin_a.actor.token().unwrap())
            .await,
    );
    let foreign_calendar = credentials
        .create_feed_token(
            &d.admin_b,
            &d.anna_b.name,
            FeedTokenCreate {
                mode: FeedMode::Full,
                calendar_ids: vec![d.personal.id],
            },
        )
        .await
        .unwrap_err();
    assert_eq!(
        foreign_calendar.kind(),
        ErrorKind::Invalid,
        "alpha's calendar is not one bravo's principal can read"
    );
    let feeds = credentials
        .list_feed_tokens(&d.admin_b, &d.anna_b.name, PageRequest::first())
        .await
        .unwrap();
    assert!(feeds.items.is_empty());
    let passwords = credentials
        .list_app_passwords(&d.admin_b, &d.anna_b.name, PageRequest::first())
        .await
        .unwrap();
    assert!(passwords.items.is_empty());
    hidden(
        "feeds.render",
        world
            .services
            .feeds
            .render(
                &world.feed(&d.bravo, &d.anna_b, d.feed.token.id),
                Conditional::default(),
            )
            .await,
    );

    // Bravo's audit log holds no record of alpha.
    let reader = world.tenant_token(&d.bravo, ScopeSet::of(&[Scope::AuditRead]));
    let theirs = world
        .services
        .audit
        .list(&reader, AuditFilter::default(), PageRequest::first())
        .await
        .unwrap();
    let alpha_rows: Vec<_> = world.audit(&d.alpha).await.into_iter().map(|row| row.id).collect();
    assert!(theirs.items.iter().all(|view| !alpha_rows.contains(&view.id)));
    d.assert_untouched(&before).await;
}
