//! Sharing: the CalendarServer flow (invitation, notification, reply, binding), API grants, how the two meet in one
//! grant, groups, leaving a share and the rules of who may share what.

use davhaven_testkit::davhaven_app::services::{
    CalendarRef, Conditions, GrantSpec, InviteReply, InviteReplyOutcome, NotificationView, PageRequest, ScheduleReply,
    ShareItemResult, ShareRequest, ShareeSet, SharingRole, WritePrecondition,
};
use davhaven_testkit::davhaven_domain::{
    Access, CalendarKind, CalendarUserAddress, ErrorKind, EventType, GrantAccess, GrantSource, GrantStatus,
    NotificationKind, Precondition, PrincipalKind, ResourcePath, Scope, ScopeSet,
};
use davhaven_testkit::davhaven_wire::GrantWrite;

use super::support::{Fixture, Org, Person, World, fixture, ics};

fn address(text: &str) -> CalendarUserAddress {
    CalendarUserAddress::parse(text).unwrap()
}

fn invite(text: &str, access: GrantAccess) -> ShareeSet {
    ShareeSet {
        address: address(text),
        common_name: None,
        summary: Some("Our calendar".to_owned()),
        access,
    }
}

fn request(set: Vec<ShareeSet>) -> ShareRequest {
    ShareRequest {
        set,
        remove: Vec::new(),
    }
}

async fn share(world: &World, org: &Org, owner: &Person, slug: &str, request: ShareRequest) -> Vec<ShareItemResult> {
    world
        .services
        .sharing
        .share(&world.dav(org, owner), &world.collection(org, owner, slug), request)
        .await
        .unwrap()
}

async fn notifications(world: &World, org: &Org, who: &Person) -> Vec<NotificationView> {
    world
        .services
        .sharing
        .list_notifications(&world.dav(org, who), &who.name)
        .await
        .unwrap()
}

async fn reply(
    world: &World,
    org: &Org,
    who: &Person,
    uid: &davhaven_testkit::davhaven_domain::Uid,
    accepted: bool,
) -> Result<InviteReplyOutcome, davhaven_testkit::davhaven_app::error::AppError> {
    world
        .services
        .sharing
        .reply_invite(
            &world.dav(org, who),
            &world.home(org, who),
            InviteReply {
                in_reply_to: uid.clone(),
                accepted,
                host_url: None,
                summary: None,
            },
        )
        .await
}

async fn ctag(world: &World, org: &Org, owner: &Person, slug: &str) -> String {
    world
        .services
        .calendars
        .get_collection(&world.dav(org, owner), &world.collection(org, owner, slug))
        .await
        .unwrap()
        .sync_token
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn an_invitation_is_a_pending_grant_and_a_notification_until_the_sharee_answers() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    let before = ctag(&world, &acme, &anna, "personal").await;
    let results = share(
        &world,
        &acme,
        &anna,
        "personal",
        request(vec![ShareeSet {
            common_name: Some("Ben B.".to_owned()),
            ..invite("mailto:ben@acme.example", GrantAccess::ReadWrite)
        }]),
    )
    .await;
    assert_eq!(results.len(), 1);
    assert!(results[0].error.is_none());
    assert_eq!(results[0].address, address("mailto:ben@acme.example"));
    assert_ne!(
        ctag(&world, &acme, &anna, "personal").await,
        before,
        "CS:invite is a property: the CTag moves"
    );

    // A pending grant, written by sharing, with an invitation to answer.
    let calendar = world
        .services
        .calendars
        .get(&world.admin(&acme), &world.key(&anna, "personal"))
        .await
        .unwrap();
    let grant = world
        .read(&acme)
        .await
        .grants()
        .find(calendar.id, ben.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(grant.status, GrantStatus::Pending);
    assert_eq!(grant.source, GrantSource::Share);
    assert_eq!(grant.access, GrantAccess::ReadWrite);
    let uid = grant
        .invite_uid
        .clone()
        .expect("every invitation has a UID the sharee answers with");
    let inbox = notifications(&world, &acme, &ben).await;
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].kind, NotificationKind::Invite);
    assert_eq!(inbox[0].uid, uid);
    assert!(
        inbox[0].body_xml.contains(uid.as_str()) && inbox[0].body_xml.contains("Our calendar"),
        "{}",
        inbox[0].body_xml
    );
    assert_eq!(
        inbox[0].etag,
        davhaven_testkit::davhaven_domain::ETag::from_bytes(inbox[0].body_xml.as_bytes()),
        "strong ETag of the notification body"
    );
    assert!(
        inbox[0]
            .path
            .format()
            .starts_with("/dav/calendars/acme/ben/notifications/")
    );

    // Nothing is shared yet: the calendar is not in ben's home and ben cannot read it.
    let bens = world.dav(&acme, &ben);
    let home = world.services.calendars.list_home(&bens, &ben.name).await.unwrap();
    assert!(home.iter().all(|view| view.owner.name != anna.name));
    let object = world.object(&acme, &anna, "personal", "x.ics");
    assert_eq!(
        world.services.objects.get(&bens, &object).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );

    // The owner's collection lists the invitation.
    let collection = world
        .services
        .calendars
        .get_collection(&world.dav(&acme, &anna), &world.collection(&acme, &anna, "personal"))
        .await
        .unwrap();
    assert_eq!(collection.invites.len(), 1);
    assert_eq!(collection.invites[0].status, GrantStatus::Pending);
    assert_eq!(collection.invites[0].access, GrantAccess::ReadWrite);
    assert_eq!(collection.invites[0].address, address("mailto:ben@acme.example"));
    assert_eq!(collection.invites[0].common_name.as_deref(), Some("Ben B."));

    // The trace of the invitation.
    assert!(world.audit_actions(&acme).await.contains(&"share.invited".to_owned()));
    assert_eq!(world.events_of(&acme, EventType::ShareInvited).await.len(), 1);

    // The notification collection has its own sync token.
    let sync = world
        .services
        .objects
        .sync(
            &bens,
            &ResourcePath::Notifications {
                tenant: acme.slug.clone(),
                principal: ben.name.clone(),
            },
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(sync.changes.len(), 1);
    assert_eq!(sync.changes[0].path, inbox[0].path);
}

#[tokio::test]
async fn accepting_binds_the_calendar_in_the_sharees_home_and_tells_the_owner() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    let object = world.object(&acme, &anna, "personal", "x.ics");
    world
        .services
        .objects
        .put(
            &world.dav(&acme, &anna),
            davhaven_testkit::davhaven_app::services::PutRequest {
                path: object.clone(),
                body: ics("x-1", "X"),
                content_type: None,
                preconditions: WritePrecondition::none(),
                schedule_reply: ScheduleReply::Send,
            },
        )
        .await
        .unwrap();
    share(
        &world,
        &acme,
        &anna,
        "personal",
        request(vec![invite("mailto:ben@acme.example", GrantAccess::Read)]),
    )
    .await;
    let uid = notifications(&world, &acme, &ben).await[0].uid.clone();
    let before = ctag(&world, &acme, &anna, "personal").await;

    let outcome = reply(&world, &acme, &ben, &uid, true).await.unwrap();
    let InviteReplyOutcome::Accepted { shared_as } = outcome else {
        panic!("{outcome:?}")
    };
    assert_eq!(
        shared_as.format(),
        "/dav/calendars/acme/ben/personal-2/",
        "bound under the calendar's slug, made unique because ben owns a `personal` calendar already"
    );
    let bens = world.dav(&acme, &ben);
    let view = world
        .services
        .calendars
        .list_home(&bens, &ben.name)
        .await
        .unwrap()
        .into_iter()
        .find(|view| view.owner.name == anna.name)
        .expect("the share is in the home");
    assert_eq!(view.path, shared_as);
    assert_eq!(view.sharing, SharingRole::Sharee);
    assert_eq!(view.access, Access::Read);
    assert_eq!(
        view.shared_url.as_ref().map(ResourcePath::format).as_deref(),
        Some("/dav/calendars/acme/anna/personal/")
    );
    assert_ne!(ctag(&world, &acme, &anna, "personal").await, before);

    // The owner's view shows the share, and the owner is told what the sharee answered.
    let owners = world
        .services
        .calendars
        .list_home(&world.dav(&acme, &anna), &anna.name)
        .await
        .unwrap();
    let own = owners.iter().find(|view| view.kind == CalendarKind::Personal).unwrap();
    assert_eq!(own.sharing, SharingRole::Owner);
    let told = notifications(&world, &acme, &anna).await;
    assert_eq!(told.len(), 1);
    assert_eq!(told[0].kind, NotificationKind::InviteReply);
    assert!(told[0].body_xml.contains("ben@acme.example"), "{}", told[0].body_xml);
    assert!(world.audit_actions(&acme).await.contains(&"share.accepted".to_owned()));
    assert_eq!(world.events_of(&acme, EventType::ShareAccepted).await.len(), 1);

    // The sharee reads, but with read access only.
    let mine = world.object(&acme, &ben, "personal-2", "x.ics");
    assert!(world.services.objects.get(&bens, &mine).await.is_ok());
    let error = world
        .services
        .objects
        .put(
            &bens,
            davhaven_testkit::davhaven_app::services::PutRequest {
                path: mine,
                body: ics("x-1", "Changed"),
                content_type: None,
                preconditions: WritePrecondition::none(),
                schedule_reply: ScheduleReply::Send,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Forbidden);

    // Answering again with the same answer repeats it: one binding, one notification for the owner.
    let again = reply(&world, &acme, &ben, &uid, true).await.unwrap();
    assert_eq!(
        again,
        InviteReplyOutcome::Accepted {
            shared_as: view.path.clone()
        }
    );
    assert_eq!(notifications(&world, &acme, &anna).await.len(), 1);
    let count = world
        .services
        .calendars
        .list_home(&bens, &ben.name)
        .await
        .unwrap()
        .into_iter()
        .filter(|view| view.owner.name == anna.name)
        .count();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn declining_binds_nothing_and_a_new_invitation_can_follow() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    share(
        &world,
        &acme,
        &anna,
        "personal",
        request(vec![invite("mailto:ben@acme.example", GrantAccess::Read)]),
    )
    .await;
    let uid = notifications(&world, &acme, &ben).await[0].uid.clone();
    assert_eq!(
        reply(&world, &acme, &ben, &uid, false).await.unwrap(),
        InviteReplyOutcome::Declined
    );
    assert_eq!(
        reply(&world, &acme, &ben, &uid, false).await.unwrap(),
        InviteReplyOutcome::Declined,
        "the same answer again is the same answer"
    );
    let home = world
        .services
        .calendars
        .list_home(&world.dav(&acme, &ben), &ben.name)
        .await
        .unwrap();
    assert!(home.iter().all(|view| view.owner.name != anna.name));
    let told = notifications(&world, &acme, &anna).await;
    assert_eq!(told.len(), 1);
    assert!(world.audit_actions(&acme).await.contains(&"share.declined".to_owned()));
    let collection = world
        .services
        .calendars
        .get_collection(&world.dav(&acme, &anna), &world.collection(&acme, &anna, "personal"))
        .await
        .unwrap();
    assert_eq!(collection.invites[0].status, GrantStatus::Declined);

    // The owner invites again: the same grant is pending once more and the invitation shows up again.
    share(
        &world,
        &acme,
        &anna,
        "personal",
        request(vec![invite("mailto:ben@acme.example", GrantAccess::ReadWrite)]),
    )
    .await;
    let collection = world
        .services
        .calendars
        .get_collection(&world.dav(&acme, &anna), &world.collection(&acme, &anna, "personal"))
        .await
        .unwrap();
    assert_eq!(collection.invites.len(), 1, "one grant per calendar and grantee");
    assert_eq!(collection.invites[0].status, GrantStatus::Pending);
    assert_eq!(collection.invites[0].access, GrantAccess::ReadWrite);
    let inbox = notifications(&world, &acme, &ben).await;
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].uid, uid, "the invitation keeps its UID");
    assert!(matches!(
        reply(&world, &acme, &ben, &uid, true).await.unwrap(),
        InviteReplyOutcome::Accepted { .. }
    ));
}

#[tokio::test]
async fn only_the_grantee_can_answer_an_invitation() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    let carla = world.user(&acme, "carla").await;
    share(
        &world,
        &acme,
        &anna,
        "personal",
        request(vec![invite("mailto:ben@acme.example", GrantAccess::Read)]),
    )
    .await;
    let uid = notifications(&world, &acme, &ben).await[0].uid.clone();

    // Someone else's reply, in their own home or in the sharee's, finds nothing.
    assert_eq!(
        reply(&world, &acme, &carla, &uid, true).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
    let in_bens_home = world
        .services
        .sharing
        .reply_invite(
            &world.dav(&acme, &carla),
            &world.home(&acme, &ben),
            InviteReply {
                in_reply_to: uid.clone(),
                accepted: true,
                host_url: None,
                summary: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(in_bens_home.kind(), ErrorKind::NotFound);
    let unknown = davhaven_testkit::davhaven_domain::Uid::parse("no-such-invitation").unwrap();
    assert_eq!(
        reply(&world, &acme, &ben, &unknown, true).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
    // Replies are for homes.
    let wrong_path = world
        .services
        .sharing
        .reply_invite(
            &world.dav(&acme, &ben),
            &world.collection(&acme, &ben, "personal"),
            InviteReply {
                in_reply_to: uid,
                accepted: true,
                host_url: None,
                summary: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(wrong_path.kind(), ErrorKind::NotFound);
}

#[tokio::test]
async fn auto_accept_binds_at_once_without_a_notification() {
    let world = World::new();
    let acme = world
        .org_with("acme", |settings| settings.sharing.auto_accept = true)
        .await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    share(
        &world,
        &acme,
        &anna,
        "personal",
        request(vec![invite("mailto:ben@acme.example", GrantAccess::ReadWrite)]),
    )
    .await;
    assert!(notifications(&world, &acme, &ben).await.is_empty());
    let home = world
        .services
        .calendars
        .list_home(&world.dav(&acme, &ben), &ben.name)
        .await
        .unwrap();
    let shared = home
        .iter()
        .find(|view| view.owner.name == anna.name)
        .expect("bound at once");
    assert_eq!(shared.access, Access::ReadWrite);
    assert_eq!(shared.sharing, SharingRole::Sharee);
    let calendar = world
        .services
        .calendars
        .get(&world.admin(&acme), &world.key(&anna, "personal"))
        .await
        .unwrap();
    let grant = world
        .read(&acme)
        .await
        .grants()
        .find(calendar.id, ben.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(grant.status, GrantStatus::Accepted);
}

#[tokio::test]
async fn sharees_must_be_active_users_or_groups_of_the_same_tenant_and_each_item_has_its_own_answer() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    let other = world.org("other").await;
    world.user(&other, "olga").await;
    let carla = world.user(&acme, "carla").await;
    let room = world.principal(&acme, "room-1", PrincipalKind::Resource).await;
    // Service principals are grantees of the management API (they hold tokens), not sharees of calendar clients.
    world.principal(&acme, "robot", PrincipalKind::Service).await;
    let team = world.group(&acme, "team", &[&carla]).await;
    // A deleted principal cannot be shared with.
    let doomed = world.user(&acme, "doomed").await;
    let admin = world.admin(&acme);
    let current = world.services.principals.get(&admin, &doomed.name).await.unwrap();
    world
        .services
        .principals
        .delete(
            &admin,
            &doomed.name,
            davhaven_testkit::davhaven_app::services::DeleteOptions {
                conditions: Conditions::if_match(current.version),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let results = share(
        &world,
        &acme,
        &anna,
        "personal",
        request(vec![
            invite("mailto:ben@acme.example", GrantAccess::Read),
            invite("mailto:olga@other.example", GrantAccess::Read),
            invite("mailto:nobody@elsewhere.example", GrantAccess::Read),
            invite("mailto:room-1@acme.example", GrantAccess::Read),
            invite("mailto:robot@acme.example", GrantAccess::Read),
            invite("mailto:anna@acme.example", GrantAccess::Read),
            invite("mailto:doomed@acme.example", GrantAccess::Read),
            invite(&format!("urn:uuid:{}", carla.id), GrantAccess::Read),
        ]),
    )
    .await;
    let outcome: Vec<(String, Option<ErrorKind>)> = results
        .iter()
        .map(|item| {
            (
                item.address.as_str().to_owned(),
                item.error
                    .as_ref()
                    .map(davhaven_testkit::davhaven_app::AppError::kind),
            )
        })
        .collect();
    assert_eq!(
        outcome,
        vec![
            ("mailto:ben@acme.example".to_owned(), None),
            ("mailto:olga@other.example".to_owned(), Some(ErrorKind::Forbidden)),
            ("mailto:nobody@elsewhere.example".to_owned(), Some(ErrorKind::Forbidden)),
            ("mailto:room-1@acme.example".to_owned(), Some(ErrorKind::Forbidden)),
            ("mailto:robot@acme.example".to_owned(), Some(ErrorKind::Forbidden)),
            ("mailto:anna@acme.example".to_owned(), Some(ErrorKind::Forbidden)),
            ("mailto:doomed@acme.example".to_owned(), Some(ErrorKind::Forbidden)),
            (format!("urn:uuid:{}", carla.id), None),
        ],
        "the valid sharees are invited whatever the others got"
    );
    assert!(
        matches!(
            results[1].error.as_ref().unwrap().precondition(),
            Some(Precondition::InvalidSharee(_))
        ),
        "external sharees are refused per item with DAV:invalid-sharee"
    );
    assert_eq!(notifications(&world, &acme, &ben).await.len(), 1);
    assert_eq!(notifications(&world, &acme, &carla).await.len(), 1);
    assert!(notifications(&world, &acme, &room).await.is_empty());

    // A group is not asked: its members have the access through the group at once.
    let results = share(
        &world,
        &acme,
        &anna,
        "personal",
        request(vec![invite(
            "urn:uuid:ffffffff-ffff-ffff-ffff-ffffffffffff",
            GrantAccess::Read,
        )]),
    )
    .await;
    assert_eq!(
        results[0]
            .error
            .as_ref()
            .map(davhaven_testkit::davhaven_app::AppError::kind),
        Some(ErrorKind::Forbidden)
    );
    let group_address = address(&format!("urn:uuid:{}", team.id));
    let results = share(
        &world,
        &acme,
        &anna,
        "personal",
        request(vec![ShareeSet {
            address: group_address,
            ..invite("mailto:x@y.example", GrantAccess::Read)
        }]),
    )
    .await;
    assert!(results[0].error.is_none());
    assert!(
        notifications(&world, &acme, &world.user(&acme, "dora").await)
            .await
            .is_empty()
    );
    let member_home = world
        .services
        .calendars
        .list_home(&world.dav(&acme, &carla), &carla.name)
        .await
        .unwrap();
    assert!(
        member_home.iter().any(|view| view.owner.name == anna.name),
        "a member of the group sees the calendar through the group"
    );
}

#[tokio::test]
async fn removing_a_sharee_takes_back_the_access_the_binding_and_the_invitation() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    let carla = world.user(&acme, "carla").await;
    share(
        &world,
        &acme,
        &anna,
        "personal",
        request(vec![
            invite("mailto:ben@acme.example", GrantAccess::Read),
            invite("mailto:carla@acme.example", GrantAccess::Read),
        ]),
    )
    .await;
    let uid = notifications(&world, &acme, &ben).await[0].uid.clone();
    reply(&world, &acme, &ben, &uid, true).await.unwrap();
    world
        .services
        .calendars
        .list_home(&world.dav(&acme, &ben), &ben.name)
        .await
        .unwrap();

    let results = share(
        &world,
        &acme,
        &anna,
        "personal",
        ShareRequest {
            set: Vec::new(),
            remove: vec![
                address("mailto:ben@acme.example"),
                address("mailto:carla@acme.example"),
                address("mailto:nobody@elsewhere.example"),
            ],
        },
    )
    .await;
    assert!(
        results.iter().all(|item| item.error.is_none()),
        "removing what is not there is not an error"
    );
    let home = world
        .services
        .calendars
        .list_home(&world.dav(&acme, &ben), &ben.name)
        .await
        .unwrap();
    assert!(
        home.iter().all(|view| view.owner.name != anna.name),
        "the binding is gone"
    );
    assert!(
        notifications(&world, &acme, &carla).await.is_empty(),
        "the pending invitation is withdrawn"
    );
    let collection = world
        .services
        .calendars
        .get_collection(&world.dav(&acme, &anna), &world.collection(&acme, &anna, "personal"))
        .await
        .unwrap();
    assert!(collection.invites.is_empty());
    assert!(world.audit_actions(&acme).await.contains(&"share.removed".to_owned()));
    assert_eq!(world.events_of(&acme, EventType::GrantDeleted).await.len(), 2);
    // The answer to a withdrawn invitation finds nothing.
    assert_eq!(
        reply(&world, &acme, &carla, &uid, true).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
}

#[tokio::test]
async fn a_sharee_who_deletes_the_collection_leaves_the_share_and_the_owner_is_told() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    share(
        &world,
        &acme,
        &anna,
        "personal",
        request(vec![invite("mailto:ben@acme.example", GrantAccess::Read)]),
    )
    .await;
    let uid = notifications(&world, &acme, &ben).await[0].uid.clone();
    let InviteReplyOutcome::Accepted { shared_as } = reply(&world, &acme, &ben, &uid, true).await.unwrap() else {
        panic!()
    };
    let bens = world.dav(&acme, &ben);
    world
        .services
        .calendars
        .delete_collection(&bens, &shared_as, Conditions::none())
        .await
        .unwrap();
    let home = world.services.calendars.list_home(&bens, &ben.name).await.unwrap();
    assert!(home.iter().all(|view| view.owner.name != anna.name));
    let calendar = world
        .services
        .calendars
        .get(&world.admin(&acme), &world.key(&anna, "personal"))
        .await
        .unwrap();
    let grant = world
        .read(&acme)
        .await
        .grants()
        .find(calendar.id, ben.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(grant.status, GrantStatus::Declined);
    let told = notifications(&world, &acme, &anna).await;
    assert!(
        told.iter()
            .any(|notification| notification.kind == NotificationKind::InviteReply),
        "{told:?}"
    );
    assert_eq!(world.events_of(&acme, EventType::ShareDeclined).await.len(), 1);
    // The calendar of the owner is untouched.
    assert!(
        world
            .services
            .calendars
            .get(&world.admin(&acme), &world.key(&anna, "personal"))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn only_owners_and_administrators_share_and_never_managed_calendars_or_when_sharing_is_off() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    let carla = world.user(&acme, "carla").await;
    let svc = world.principal(&acme, "svc", PrincipalKind::Service).await;
    world.calendar(&acme, &anna, "work", CalendarKind::User).await;
    let put = |grantee: &Person, access| {
        let world = &world;
        let acme = &acme;
        let anna = &anna;
        let grantee = grantee.clone();
        async move {
            world
                .services
                .sharing
                .put_grant(
                    &world.admin(acme),
                    GrantSpec {
                        calendar: world.key(anna, "work"),
                        grantee: grantee.name.clone(),
                        body: GrantWrite {
                            access,
                            required: false,
                        },
                    },
                    Conditions::none(),
                )
                .await
                .unwrap();
            world
                .services
                .calendars
                .list_home(&world.dav(acme, &grantee), &grantee.name)
                .await
                .unwrap();
        }
    };
    let try_share = |who: &Person| {
        let world = &world;
        let acme = &acme;
        let path = world.collection(acme, who, "work");
        let ctx = world.dav(acme, who);
        async move {
            world
                .services
                .sharing
                .share(
                    &ctx,
                    &path,
                    request(vec![invite("mailto:carla@acme.example", GrantAccess::Read)]),
                )
                .await
        }
    };

    // A read-write sharee may not share; an administrator may; a stranger finds nothing.
    put(&ben, GrantAccess::ReadWrite).await;
    let error = try_share(&ben).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Forbidden);
    assert!(
        matches!(error.precondition(), Some(Precondition::NeedPrivileges(missing)) if missing.iter().any(|(_, privilege)| *privilege == davhaven_testkit::davhaven_domain::Privilege::Share))
    );
    put(&ben, GrantAccess::Admin).await;
    assert!(try_share(&ben).await.is_ok());
    let stranger = world
        .services
        .sharing
        .share(
            &world.dav(&acme, &carla),
            &world.collection(&acme, &anna, "work"),
            request(vec![invite("mailto:ben@acme.example", GrantAccess::Read)]),
        )
        .await
        .unwrap_err();
    assert_eq!(stranger.kind(), ErrorKind::NotFound);

    // Managed calendars are not shared through DAV.
    world.calendar(&acme, &svc, "holidays", CalendarKind::Managed).await;
    let managed = world
        .services
        .sharing
        .share(
            &world.dav(&acme, &svc),
            &world.collection(&acme, &svc, "holidays"),
            request(vec![invite("mailto:ben@acme.example", GrantAccess::Read)]),
        )
        .await
        .unwrap_err();
    assert_eq!(managed.kind(), ErrorKind::Forbidden);
    assert_eq!(managed.precondition(), Some(&Precondition::SharingNotAllowed));

    // A tenant can switch sharing off ...
    let quiet = world
        .org_with("quiet", |settings| settings.sharing.enabled = false)
        .await;
    let qa = world.user(&quiet, "qa").await;
    world.user(&quiet, "qb").await;
    let off = world
        .services
        .sharing
        .share(
            &world.dav(&quiet, &qa),
            &world.collection(&quiet, &qa, "personal"),
            request(vec![invite("mailto:qb@quiet.example", GrantAccess::Read)]),
        )
        .await
        .unwrap_err();
    assert_eq!(off.precondition(), Some(&Precondition::SharingNotAllowed));
    // ... and so can the deployment.
    let closed = World::with(|deps| deps.config.sharing.enabled = false);
    let org = closed.org("acme").await;
    let owner = closed.user(&org, "anna").await;
    closed.user(&org, "ben").await;
    let off = closed
        .services
        .sharing
        .share(
            &closed.dav(&org, &owner),
            &closed.collection(&org, &owner, "personal"),
            request(vec![invite("mailto:ben@acme.example", GrantAccess::Read)]),
        )
        .await
        .unwrap_err();
    assert_eq!(off.precondition(), Some(&Precondition::SharingNotAllowed));
}

#[tokio::test]
async fn api_grants_are_accepted_at_once_and_one_grant_exists_per_calendar_and_grantee() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    world.calendar(&acme, &anna, "work", CalendarKind::User).await;
    let admin = world.admin(&acme);
    let spec = |access| GrantSpec {
        calendar: world.key(&anna, "work"),
        grantee: ben.name.clone(),
        body: GrantWrite {
            access,
            required: false,
        },
    };

    let created = world
        .services
        .sharing
        .put_grant(&admin, spec(GrantAccess::Read), Conditions::create_only())
        .await
        .unwrap();
    assert!(created.created);
    let grant = created.value;
    assert_eq!(
        (grant.status, grant.source, grant.access),
        (GrantStatus::Accepted, GrantSource::Api, GrantAccess::Read)
    );
    assert_eq!(grant.grantee, ben.name);
    assert_eq!(grant.calendar.as_str(), "work");
    assert_eq!(grant.version, 1);
    assert_eq!(world.events_of(&acme, EventType::GrantCreated).await.len(), 1);
    assert!(world.audit_actions(&acme).await.contains(&"grant.created".to_owned()));

    // The same grant again changes nothing.
    let again = world
        .services
        .sharing
        .put_grant(&admin, spec(GrantAccess::Read), Conditions::none())
        .await
        .unwrap();
    assert!(!again.created);
    assert_eq!(again.value, grant);
    assert_eq!(world.events_of(&acme, EventType::GrantCreated).await.len(), 1);
    assert!(world.events_of(&acme, EventType::GrantUpdated).await.is_empty());

    // A changed access is an update with a new version, guarded by If-Match.
    let stale = world
        .services
        .sharing
        .put_grant(&admin, spec(GrantAccess::ReadWrite), Conditions::if_match(7))
        .await
        .unwrap_err();
    assert_eq!(stale.kind(), ErrorKind::PreconditionFailed);
    let changed = world
        .services
        .sharing
        .put_grant(&admin, spec(GrantAccess::ReadWrite), Conditions::if_match(1))
        .await
        .unwrap();
    assert!(!changed.created);
    assert_eq!(changed.value.version, 2);
    assert_eq!(changed.value.access, GrantAccess::ReadWrite);
    assert_eq!(world.events_of(&acme, EventType::GrantUpdated).await.len(), 1);
    assert_eq!(
        world
            .services
            .sharing
            .put_grant(&admin, spec(GrantAccess::Read), Conditions::create_only())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::PreconditionFailed
    );

    // The grantee sees the calendar, listed by id with their name and the way it was made.
    let home = world
        .services
        .calendars
        .list_home(&world.dav(&acme, &ben), &ben.name)
        .await
        .unwrap();
    assert!(
        home.iter()
            .any(|view| view.calendar_id == grant.calendar_id && view.access == Access::ReadWrite)
    );
    let listed = world
        .services
        .sharing
        .list_grants(&admin, &world.key(&anna, "work"), PageRequest::first())
        .await
        .unwrap();
    assert_eq!(listed.items.len(), 1);
    assert_eq!(listed.items[0].id, grant.id);

    // Deleting needs the version when it is given, and removes the binding too.
    assert_eq!(
        world
            .services
            .sharing
            .delete_grant(&admin, &world.key(&anna, "work"), &ben.name, Conditions::if_match(1))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::PreconditionFailed
    );
    world
        .services
        .sharing
        .delete_grant(&admin, &world.key(&anna, "work"), &ben.name, Conditions::if_match(2))
        .await
        .unwrap();
    let home = world
        .services
        .calendars
        .list_home(&world.dav(&acme, &ben), &ben.name)
        .await
        .unwrap();
    assert!(home.iter().all(|view| view.calendar_id != grant.calendar_id));
    assert_eq!(
        world
            .services
            .sharing
            .delete_grant(&admin, &world.key(&anna, "work"), &ben.name, Conditions::none())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    assert_eq!(world.events_of(&acme, EventType::GrantDeleted).await.len(), 1);
}

#[tokio::test]
async fn grants_have_rules_about_who_gets_them_and_who_may_give_them() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    let other = world.org("other").await;
    let olga = world.user(&other, "olga").await;
    let room = world.principal(&acme, "room-1", PrincipalKind::Resource).await;
    let svc = world.principal(&acme, "svc", PrincipalKind::Service).await;
    world.calendar(&acme, &anna, "work", CalendarKind::User).await;
    let admin = world.admin(&acme);
    let put = |ctx: &davhaven_testkit::davhaven_domain::RequestContext, grantee: &Person, calendar: CalendarRef| {
        let world = &world;
        let ctx = ctx.clone();
        let grantee = grantee.clone();
        async move {
            world
                .services
                .sharing
                .put_grant(
                    &ctx,
                    GrantSpec {
                        calendar,
                        grantee: grantee.name.clone(),
                        body: GrantWrite {
                            access: GrantAccess::Read,
                            required: false,
                        },
                    },
                    Conditions::none(),
                )
                .await
        }
    };

    // Grantees: users, groups and service principals of the tenant, never the owner, resources or foreign principals.
    for (who, name) in [(&anna, "the owner"), (&room, "a resource")] {
        let error = put(&admin, who, world.key(&anna, "work")).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Invalid, "{name}");
        assert_eq!(
            error.field_errors().first().map(|field| field.pointer),
            Some("/grantee"),
            "{name}"
        );
    }
    // A service principal is a grantee like a user: it holds principal tokens for the API and MCP.
    let granted = put(&admin, &svc, world.key(&anna, "work")).await.unwrap();
    assert_eq!(granted.value.grantee, svc.name);
    assert_eq!(granted.value.access, GrantAccess::Read);
    assert_eq!(
        granted.value.status,
        davhaven_testkit::davhaven_domain::GrantStatus::Accepted
    );
    assert_eq!(
        put(&admin, &olga, world.key(&anna, "work")).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
    let ghost = Person {
        id: ben.id,
        name: davhaven_testkit::davhaven_domain::PrincipalName::parse("ghost").unwrap(),
    };
    assert_eq!(
        put(&admin, &ghost, world.key(&anna, "work")).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        put(&admin, &ben, world.key(&anna, "unknown")).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );

    // Scopes: calendars:write to change, nothing less.
    let reader = world.tenant_token(&acme, ScopeSet::of(&[Scope::CalendarsRead]));
    assert_eq!(
        put(&reader, &ben, world.key(&anna, "work")).await.unwrap_err().kind(),
        ErrorKind::Forbidden
    );
    assert_eq!(
        world
            .services
            .sharing
            .list_grants(&reader, &world.key(&anna, "work"), PageRequest::first())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Forbidden
    );
    // The owner's principal token manages grants of its own calendars; others have none to manage.
    let owner_token = world.api(&acme, &anna, &[Scope::CalendarsRead, Scope::CalendarsWrite]);
    assert!(put(&owner_token, &ben, world.key(&anna, "work")).await.is_ok());
    let bens_token = world.api(&acme, &ben, &[Scope::CalendarsRead, Scope::CalendarsWrite]);
    assert_eq!(
        put(&bens_token, &ben, world.key(&anna, "work"))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Forbidden,
        "a read-only sharee sees the calendar but may not change who else has access"
    );

    // Mirror and managed rules: managed calendars take API grants, but never DAV shares.
    world.calendar(&acme, &svc, "holidays", CalendarKind::Managed).await;
    assert!(put(&admin, &ben, world.key(&svc, "holidays")).await.is_ok());
}

/// A service principal is a grantee of the management API on every kind of calendar, and client sharing neither lists it
/// nor lets a client take its grant back (PLAN 2.9): one rule for personal, user, group and managed calendars.
#[tokio::test]
async fn an_api_grant_to_a_service_principal_is_no_invitation_and_not_the_clients_to_take_back() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    let robot = world.principal(&acme, "robot", PrincipalKind::Service).await;
    let team = world.group(&acme, "team", &[&anna]).await;
    world.calendar(&acme, &anna, "work", CalendarKind::User).await;
    world.calendar(&acme, &team, "shared", CalendarKind::Group).await;
    world.calendar(&acme, &ben, "courses", CalendarKind::Managed).await;
    let admin = world.admin(&acme);

    // The kinds of calendar an integration is given: a person's own, a group's (read and write) and a managed one (read).
    let calendars = [
        (&anna, "work", GrantAccess::ReadWrite),
        (&anna, "personal", GrantAccess::Read),
        (&team, "shared", GrantAccess::ReadWrite),
        (&ben, "courses", GrantAccess::Read),
    ];
    for (owner, slug, access) in calendars {
        let granted = world
            .services
            .sharing
            .put_grant(
                &admin,
                GrantSpec {
                    calendar: world.key(owner, slug),
                    grantee: robot.name.clone(),
                    body: GrantWrite {
                        access,
                        required: false,
                    },
                },
                Conditions::none(),
            )
            .await
            .unwrap_or_else(|error| panic!("{slug}: {error:?}"));
        assert_eq!(
            (granted.value.status, granted.value.access),
            (GrantStatus::Accepted, access),
            "{slug}: an API grant to a service principal is accepted at once"
        );
    }

    // A calendar client asking who the calendar is shared with does not hear of the integration ...
    for slug in ["work", "personal"] {
        let collection = world
            .services
            .calendars
            .get_collection(&world.dav(&acme, &anna), &world.collection(&acme, &anna, slug))
            .await
            .unwrap();
        assert!(collection.invites.is_empty(), "{slug}: {:?}", collection.invites);
    }

    // ... and cannot take its grant back by naming it, on a calendar of a person either: the removal answers with the
    // missing privilege, as it does for the API's grants on group and managed calendars, and the grant stays.
    for slug in ["work", "personal"] {
        let results = share(
            &world,
            &acme,
            &anna,
            slug,
            ShareRequest {
                set: Vec::new(),
                remove: vec![address("mailto:robot@acme.example")],
            },
        )
        .await;
        let refusal = results
            .iter()
            .find(|item| item.address == address("mailto:robot@acme.example"))
            .and_then(|item| item.error.as_ref())
            .unwrap_or_else(|| panic!("{slug}: the removal of the integration's grant was not refused: {results:?}"));
        assert_eq!(refusal.kind(), ErrorKind::Forbidden, "{slug}");
        assert!(
            matches!(refusal.precondition(), Some(Precondition::NeedPrivileges(_))),
            "{slug}: {refusal:?}"
        );
    }
    for (owner, slug, access) in calendars {
        let listed = world
            .services
            .sharing
            .list_grants(&admin, &world.key(owner, slug), PageRequest::first())
            .await
            .unwrap();
        let grant = listed
            .items
            .iter()
            .find(|grant| grant.grantee == robot.name)
            .unwrap_or_else(|| panic!("{slug}: the grant of the integration is gone"));
        assert_eq!((grant.access, grant.status), (access, GrantStatus::Accepted), "{slug}");
    }

    // The API takes it back, like any other grant.
    world
        .services
        .sharing
        .delete_grant(&admin, &world.key(&anna, "work"), &robot.name, Conditions::none())
        .await
        .unwrap();
    let listed = world
        .services
        .sharing
        .list_grants(&admin, &world.key(&anna, "work"), PageRequest::first())
        .await
        .unwrap();
    assert!(listed.items.iter().all(|grant| grant.grantee != robot.name));
}

#[tokio::test]
async fn the_last_write_wins_between_dav_sharing_and_the_api_and_the_grant_remembers_who_wrote() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    world.calendar(&acme, &anna, "work", CalendarKind::User).await;
    let admin = world.admin(&acme);
    let calendar_id = world
        .services
        .calendars
        .get(&admin, &world.key(&anna, "work"))
        .await
        .unwrap()
        .id;
    let find = || {
        let world = &world;
        let acme = &acme;
        let ben = &ben;
        async move {
            world
                .read(acme)
                .await
                .grants()
                .find(calendar_id, ben.id)
                .await
                .unwrap()
                .unwrap()
        }
    };

    // DAV first: pending, from sharing.
    share(
        &world,
        &acme,
        &anna,
        "work",
        request(vec![invite("mailto:ben@acme.example", GrantAccess::Read)]),
    )
    .await;
    let grant = find().await;
    assert_eq!(
        (grant.status, grant.source, grant.access),
        (GrantStatus::Pending, GrantSource::Share, GrantAccess::Read)
    );
    assert_eq!(notifications(&world, &acme, &ben).await.len(), 1);

    // The API answers for the sharee: accepted at once, no notification left, the API is the author.
    world
        .services
        .sharing
        .put_grant(
            &admin,
            GrantSpec {
                calendar: world.key(&anna, "work"),
                grantee: ben.name.clone(),
                body: GrantWrite {
                    access: GrantAccess::ReadWrite,
                    required: false,
                },
            },
            Conditions::none(),
        )
        .await
        .unwrap();
    let grant = find().await;
    assert_eq!(
        (grant.status, grant.source, grant.access),
        (GrantStatus::Accepted, GrantSource::Api, GrantAccess::ReadWrite)
    );
    assert!(notifications(&world, &acme, &ben).await.is_empty());

    // DAV again: the access changes, the grant stays accepted and is a sharing grant once more.
    share(
        &world,
        &acme,
        &anna,
        "work",
        request(vec![invite("mailto:ben@acme.example", GrantAccess::Read)]),
    )
    .await;
    let grant = find().await;
    assert_eq!(
        (grant.status, grant.source, grant.access),
        (GrantStatus::Accepted, GrantSource::Share, GrantAccess::Read)
    );
    assert_eq!(world.events_of(&acme, EventType::GrantUpdated).await.len(), 2);
}

#[tokio::test]
async fn clients_cannot_remove_grants_the_api_made_on_group_and_managed_calendars() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    let carla = world.user(&acme, "carla").await;
    let team = world.group(&acme, "team", &[&anna]).await;
    world.calendar(&acme, &team, "shared", CalendarKind::Group).await;
    let admin = world.admin(&acme);
    let grant = |who: &Person, access| GrantSpec {
        calendar: world.key(&team, "shared"),
        grantee: who.name.clone(),
        body: GrantWrite {
            access,
            required: false,
        },
    };
    // ben administers the group calendar and carla reads it, both by API grants.
    world
        .services
        .sharing
        .put_grant(&admin, grant(&ben, GrantAccess::Admin), Conditions::none())
        .await
        .unwrap();
    world
        .services
        .sharing
        .put_grant(&admin, grant(&carla, GrantAccess::Read), Conditions::none())
        .await
        .unwrap();
    let slug = world
        .services
        .calendars
        .list_home(&world.dav(&acme, &ben), &ben.name)
        .await
        .unwrap()
        .into_iter()
        .find(|view| view.kind == CalendarKind::Group)
        .map(|view| view.path)
        .unwrap();

    let results = world
        .services
        .sharing
        .share(
            &world.dav(&acme, &ben),
            &slug,
            ShareRequest {
                set: Vec::new(),
                remove: vec![address("mailto:carla@acme.example")],
            },
        )
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
    let error = results[0].error.as_ref().expect("the API's grant is protected");
    assert_eq!(error.kind(), ErrorKind::Forbidden);
    assert!(
        matches!(error.precondition(), Some(Precondition::NeedPrivileges(_))),
        "{:?}",
        error.precondition()
    );
    let calendar = world
        .services
        .calendars
        .get(&admin, &world.key(&team, "shared"))
        .await
        .unwrap();
    assert!(
        world
            .read(&acme)
            .await
            .grants()
            .find(calendar.id, carla.id)
            .await
            .unwrap()
            .is_some(),
        "untouched"
    );

    // The API removes it all the same.
    world
        .services
        .sharing
        .delete_grant(&admin, &world.key(&team, "shared"), &carla.name, Conditions::none())
        .await
        .unwrap();
}

#[tokio::test]
async fn deleting_a_principal_ends_the_shares_it_gave_and_the_ones_it_received() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    let carla = world.user(&acme, "carla").await;
    let admin = world.admin(&acme);
    let accept = |owner: &Person, grantee: &Person| {
        let world = &world;
        let acme = &acme;
        let owner = owner.clone();
        let grantee = grantee.clone();
        async move {
            share(
                world,
                acme,
                &owner,
                "personal",
                request(vec![invite(
                    &format!("mailto:{}@acme.example", grantee.name),
                    GrantAccess::Read,
                )]),
            )
            .await;
            let uid = notifications(world, acme, &grantee).await.last().unwrap().uid.clone();
            reply(world, acme, &grantee, &uid, true).await.unwrap();
            world
                .services
                .calendars
                .list_home(&world.dav(acme, &grantee), &grantee.name)
                .await
                .unwrap();
        }
    };
    accept(&anna, &ben).await; // ben has anna's calendar
    accept(&ben, &carla).await; // carla has ben's calendar
    accept(&carla, &anna).await; // anna has carla's calendar

    let current = world.services.principals.get(&admin, &ben.name).await.unwrap();
    world
        .services
        .principals
        .delete(
            &admin,
            &ben.name,
            davhaven_testkit::davhaven_app::services::DeleteOptions {
                conditions: Conditions::if_match(current.version),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // Ben's calendar disappears from carla's home at once; ben's access to anna's calendar is gone too.
    let carlas = world
        .services
        .calendars
        .list_home(&world.dav(&acme, &carla), &carla.name)
        .await
        .unwrap();
    assert!(
        carlas.iter().all(|view| view.owner.name != ben.name),
        "the received share of carla ended"
    );
    let annas_calendar = world
        .services
        .calendars
        .get(&admin, &world.key(&anna, "personal"))
        .await
        .unwrap();
    assert!(
        world
            .read(&acme)
            .await
            .grants()
            .find(annas_calendar.id, ben.id)
            .await
            .unwrap()
            .is_none()
    );
    let collection = world
        .services
        .calendars
        .get_collection(&world.dav(&acme, &anna), &world.collection(&acme, &anna, "personal"))
        .await
        .unwrap();
    assert!(collection.invites.is_empty(), "anna's calendar no longer lists ben");
    // The unrelated share stays.
    let annas = world
        .services
        .calendars
        .list_home(&world.dav(&acme, &anna), &anna.name)
        .await
        .unwrap();
    assert!(annas.iter().any(|view| view.owner.name == carla.name));
}

#[tokio::test]
async fn notifications_are_read_and_deleted_by_their_owner_only() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    share(
        &world,
        &acme,
        &anna,
        "personal",
        request(vec![invite("mailto:ben@acme.example", GrantAccess::Read)]),
    )
    .await;
    let inbox = notifications(&world, &acme, &ben).await;
    let path = inbox[0].path.clone();
    let bens = world.dav(&acme, &ben);
    let annas = world.dav(&acme, &anna);

    let read = world.services.sharing.get_notification(&bens, &path).await.unwrap();
    assert_eq!(read, inbox[0]);
    // Others see neither the collection nor the notification.
    assert_eq!(
        world
            .services
            .sharing
            .list_notifications(&annas, &ben.name)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        world
            .services
            .sharing
            .get_notification(&annas, &path)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        world
            .services
            .sharing
            .delete_notification(&annas, &path)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        world
            .services
            .sharing
            .get_notification(&bens, &world.object(&acme, &ben, "personal", "x.ics"))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound,
        "only notification resources are notifications"
    );

    // Clients delete a notification after showing it; the invitation itself stays answerable.
    world.services.sharing.delete_notification(&bens, &path).await.unwrap();
    assert!(notifications(&world, &acme, &ben).await.is_empty());
    assert_eq!(
        world
            .services
            .sharing
            .get_notification(&bens, &path)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    let sync = world
        .services
        .objects
        .sync(
            &bens,
            &ResourcePath::Notifications {
                tenant: acme.slug.clone(),
                principal: ben.name.clone(),
            },
            None,
            None,
        )
        .await
        .unwrap();
    assert!(sync.changes.is_empty());
    let grant_uid = inbox[0].uid.clone();
    assert!(
        matches!(
            reply(&world, &acme, &ben, &grant_uid, true).await.unwrap(),
            InviteReplyOutcome::Accepted { .. }
        ),
        "answering does not depend on the notification still being there"
    );
}

#[tokio::test]
async fn grants_to_a_group_reach_its_current_members_only() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    let carla = world.user(&acme, "carla").await;
    let team = world.group(&acme, "team", &[&ben]).await;
    world.calendar(&acme, &anna, "work", CalendarKind::User).await;
    let admin = world.admin(&acme);
    world
        .services
        .sharing
        .put_grant(
            &admin,
            GrantSpec {
                calendar: world.key(&anna, "work"),
                grantee: team.name.clone(),
                body: GrantWrite {
                    access: GrantAccess::Read,
                    required: false,
                },
            },
            Conditions::none(),
        )
        .await
        .unwrap();
    let sees = |who: Person| {
        let world = &world;
        let acme = &acme;
        async move {
            world
                .services
                .calendars
                .list_home(&world.dav(acme, &who), &who.name)
                .await
                .unwrap()
                .iter()
                .any(|view| view.owner.name.as_str() == "anna" && view.kind == CalendarKind::User)
        }
    };
    assert!(sees(ben.clone()).await, "a member sees it");
    assert!(!sees(carla.clone()).await, "a non-member does not");
    // Joining and leaving the group changes access without touching the grant.
    world
        .services
        .principals
        .add_member(&admin, &team.name, &carla.name)
        .await
        .unwrap();
    assert!(sees(carla.clone()).await);
    world
        .services
        .principals
        .remove_member(&admin, &team.name, &ben.name)
        .await
        .unwrap();
    assert!(!sees(ben.clone()).await, "a former member loses the access at once");
    assert_eq!(
        world
            .services
            .objects
            .get(&world.dav(&acme, &ben), &world.object(&acme, &anna, "work", "x.ics"))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
}

#[tokio::test]
async fn a_client_cannot_rewrite_the_grant_the_api_made_on_a_group_calendar() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    let carla = world.user(&acme, "carla").await;
    let team = world.group(&acme, "team", &[&anna]).await;
    world.calendar(&acme, &team, "shared", CalendarKind::Group).await;
    let admin = world.admin(&acme);
    let grant = |who: &Person, access| GrantSpec {
        calendar: world.key(&team, "shared"),
        grantee: who.name.clone(),
        body: GrantWrite {
            access,
            required: false,
        },
    };
    world
        .services
        .sharing
        .put_grant(&admin, grant(&ben, GrantAccess::Admin), Conditions::none())
        .await
        .unwrap();
    world
        .services
        .sharing
        .put_grant(&admin, grant(&carla, GrantAccess::Read), Conditions::none())
        .await
        .unwrap();
    let path = world
        .services
        .calendars
        .list_home(&world.dav(&acme, &ben), &ben.name)
        .await
        .unwrap()
        .into_iter()
        .find(|view| view.kind == CalendarKind::Group)
        .map(|view| view.path)
        .unwrap();
    let calendar = world
        .services
        .calendars
        .get(&admin, &world.key(&team, "shared"))
        .await
        .unwrap();
    let before = world.audit(&acme).await.len();

    // Setting would rewrite the grant's source to `share` and turn the integration's grant into a client's one.
    let results = world
        .services
        .sharing
        .share(
            &world.dav(&acme, &ben),
            &path,
            request(vec![invite("mailto:carla@acme.example", GrantAccess::ReadWrite)]),
        )
        .await
        .unwrap();
    let error = results[0].error.as_ref().expect("the API's grant is protected");
    assert_eq!(error.kind(), ErrorKind::Forbidden);
    let stored = world
        .read(&acme)
        .await
        .grants()
        .find(calendar.id, carla.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.access, GrantAccess::Read, "untouched");
    assert_eq!(stored.source, GrantSource::Api);
    assert_eq!(
        world.audit(&acme).await.len(),
        before,
        "nothing was recorded, nothing changed"
    );
}

#[tokio::test]
async fn principals_share_through_the_api_only_where_sharing_is_switched_on() {
    let world = World::new();
    let quiet = world
        .org_with("quiet", |settings| settings.sharing.enabled = false)
        .await;
    let qa = world.user(&quiet, "qa").await;
    let qb = world.user(&quiet, "qb").await;
    let spec = GrantSpec {
        calendar: world.key(&qa, "personal"),
        grantee: qb.name.clone(),
        body: GrantWrite {
            access: GrantAccess::Read,
            required: false,
        },
    };

    // The owner's own token follows the switch, like a DAV client does ...
    let error = world
        .services
        .sharing
        .put_grant(
            &world.api(&quiet, &qa, &[Scope::CalendarsRead, Scope::CalendarsWrite]),
            spec.clone(),
            Conditions::none(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);
    assert_eq!(error.precondition(), Some(&Precondition::FeatureNotEnabled));
    // ... and an administrator of the tenant, who manages access from outside, does not.
    assert!(
        world
            .services
            .sharing
            .put_grant(&world.admin(&quiet), spec, Conditions::none())
            .await
            .is_ok()
    );

    // The same for a deployment that switched sharing off.
    let closed = World::with(|deps| deps.config.sharing.enabled = false);
    let org = closed.org("acme").await;
    let owner = closed.user(&org, "anna").await;
    let other = closed.user(&org, "ben").await;
    let error = closed
        .services
        .sharing
        .put_grant(
            &closed.api(&org, &owner, &[Scope::CalendarsRead, Scope::CalendarsWrite]),
            GrantSpec {
                calendar: closed.key(&owner, "personal"),
                grantee: other.name.clone(),
                body: GrantWrite {
                    access: GrantAccess::Read,
                    required: false,
                },
            },
            Conditions::none(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.precondition(), Some(&Precondition::FeatureNotEnabled));
}

/// The personal collection of `owner` as the owner sees it.
async fn owners_view(
    world: &World,
    org: &Org,
    owner: &Person,
) -> davhaven_testkit::davhaven_app::services::CollectionView {
    world
        .services
        .calendars
        .get_collection(&world.dav(org, owner), &world.collection(org, owner, "personal"))
        .await
        .unwrap()
}

#[tokio::test]
async fn the_summaries_of_an_invitation_and_of_its_answer_are_cut_to_the_same_limit() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    let long = "s".repeat(1000);
    share(
        &world,
        &acme,
        &anna,
        "personal",
        request(vec![ShareeSet {
            summary: Some(long.clone()),
            ..invite("mailto:ben@acme.example", GrantAccess::Read)
        }]),
    )
    .await;
    let summary = owners_view(&world, &acme, &anna).await.invites[0]
        .summary
        .clone()
        .unwrap();
    assert!(summary.chars().count() <= 200, "{} characters", summary.chars().count());

    let uid = notifications(&world, &acme, &ben).await[0].uid.clone();
    let answered = world
        .services
        .sharing
        .reply_invite(
            &world.dav(&acme, &ben),
            &world.home(&acme, &ben),
            InviteReply {
                in_reply_to: uid,
                accepted: false,
                host_url: None,
                summary: Some(long),
            },
        )
        .await
        .unwrap();
    assert_eq!(answered, InviteReplyOutcome::Declined);
    let after = owners_view(&world, &acme, &anna).await;
    assert_eq!(after.invites[0].status, GrantStatus::Declined);
    assert!(after.invites[0].summary.as_ref().unwrap().chars().count() <= 200);
}
