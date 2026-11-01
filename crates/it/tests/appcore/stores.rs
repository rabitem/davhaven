//! The two copies of the suite run on the two stores: the world of each is built on the store its copy names, and the
//! port calls say which adapter really answered (a copy that silently ran on the other store would prove nothing).

use super::STORE;
use super::support::{PortCalls, World};
use crate::Store;

#[tokio::test]
async fn the_world_is_built_on_the_store_its_copy_names() {
    if STORE == Store::Postgres && !davhaven_testkit::postgres::require_database() {
        // Skipped on purpose (`DAVHAVEN_ALLOW_NO_DB=1` outside CI): the worlds of this copy run on the memory store.
        return;
    }
    let calls = PortCalls::default();
    let _installed = metrics::set_default_local_recorder(&calls);
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    world.calendar(&acme, &anna, "work", davhaven_testkit::davhaven_domain::CalendarKind::User).await;
    let expected = match STORE {
        Store::Memory => "memory",
        Store::Postgres => "postgres",
    };
    assert_eq!(
        calls.adapters(),
        vec![expected.to_owned()],
        "the application talked to the store of this copy and to no other: {:?}",
        calls.all()
    );
    assert!(
        world.db.store().health().await.is_ready(),
        "the store of the world is ready (on PostgreSQL: the runtime role is bound and the schema is current)"
    );
}
