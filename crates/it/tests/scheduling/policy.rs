//! The shipped scheduling policies: the contract of the port, the registry and what the choice of policy changes
//! for a deployment (PLAN 2.3, 2.8).

use std::sync::Arc;

use davhaven_testkit::davhaven_app::policy::{DefaultPolicy, ManualPolicy};
use davhaven_testkit::davhaven_port_tests::policy::run_all;

use super::support::{World, meeting, partstat_in};
use davhaven_testkit::davhaven_domain::PartStat;

#[tokio::test]
async fn the_default_policy_satisfies_the_contract_of_the_port() {
    run_all(|| Arc::new(DefaultPolicy)).await;
}

#[tokio::test]
async fn the_manual_policy_satisfies_the_contract_of_the_port() {
    run_all(|| Arc::new(ManualPolicy)).await;
}

#[tokio::test]
async fn a_tenant_can_ask_for_invitations_to_wait_in_the_inbox() {
    // `auto_add_invitations = false`: the invitation is delivered to the inbox, the calendar stays as it was.
    let world = World::new();
    let acme = world
        .org_with("acme", |settings| settings.scheduling.auto_add_invitations = false)
        .await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    world
        .put(
            &world.dav(&acme, &anna),
            &world.object(&acme, &anna, "m-1.ics"),
            &meeting("m-1", &anna, &[&ben.mailto()]).build(),
        )
        .await
        .unwrap();
    assert_eq!(world.inbox(&acme, &ben).await.len(), 1);
    assert!(
        world.copy_of(&acme, &ben, "m-1").await.is_none(),
        "nothing is added to Ben's calendar"
    );
    let text = world
        .text(&world.dav(&acme, &anna), &world.object(&acme, &anna, "m-1.ics"))
        .await;
    assert_eq!(partstat_in(&text, &ben.mailto()), Some(PartStat::NeedsAction));
}

#[tokio::test]
async fn the_manual_policy_never_adds_invitations_to_calendars() {
    // Whatever the tenant says, `manual` decides nothing for people.
    let world = World::with(|deps| deps.scheduling_policy = Arc::new(ManualPolicy));
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    world
        .put(
            &world.dav(&acme, &anna),
            &world.object(&acme, &anna, "m-1.ics"),
            &meeting("m-1", &anna, &[&ben.mailto()]).build(),
        )
        .await
        .unwrap();
    assert_eq!(world.inbox(&acme, &ben).await.len(), 1);
    assert!(world.copy_of(&acme, &ben, "m-1").await.is_none());
}
