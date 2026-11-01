//! Runs the store contract suite of `davhaven-port-tests` against the in-memory adapter, one test per case, so a
//! failure names its case and the runner can parallelise and retry. The cases come from the suite's own list: a
//! case added there has a test here without any edit.

use std::sync::Arc;

use davhaven_port_tests::ContractReport;
use davhaven_ports::Database;
use davhaven_ports::testing::{ManualClock, SeqIds};
use davhaven_store_memory::database::MemoryDatabase;

/// A fresh, empty store with a manual clock.
async fn fresh() -> Arc<dyn Database> {
    Arc::new(MemoryDatabase::new(
        Arc::new(ManualClock::default()),
        Arc::new(SeqIds::new()),
    ))
}

/// Runs one case of the suite on a fresh store.
async fn run(name: &'static str) -> Option<ContractReport> {
    davhaven_port_tests::store::run_case(name, fresh).await
}

davhaven_port_tests::store_contract_tests!(run);

/// A fresh store behind a wrapper that forwards the required methods of the repositories only, so that the default
/// bodies of their additive batch reads run instead of the overrides of this adapter.
async fn forwarding_required_methods_only() -> Arc<dyn Database> {
    davhaven_port_tests::store::required_methods_only(fresh().await)
}

/// The default bodies of the batch reads (what an adapter that does not override them gets) meet the same contract as
/// the overrides: the cases that compare each batch read with the single reads (the `get_many_by_uri` of notifications
/// and of the inbox are compared in `notifications_and_inbox`), and the one that asks them with a foreign tenant, run on
/// the memory store through the wrapper.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_default_bodies_of_the_batch_reads_meet_the_contract() {
    for name in [
        "principals_batch_reads",
        "calendars_batch_reads",
        "notifications_and_inbox",
        "foreign_tenant_reads",
    ] {
        let report = davhaven_port_tests::store::run_case(name, forwarding_required_methods_only).await;
        assert!(report.is_some(), "the suite has no case `{name}`");
        if let Some(report) = report {
            report.assert_ok();
        }
    }
}

/// A fresh, empty store and the manual clock it was built with, for the cases that move the clock.
async fn fresh_with_clock() -> (Arc<dyn Database>, ManualClock) {
    let clock = ManualClock::default();
    let database: Arc<dyn Database> = Arc::new(MemoryDatabase::new(Arc::new(clock.clone()), Arc::new(SeqIds::new())));
    (database, clock)
}

/// Runs one case that moves the clock on a fresh store.
async fn run_clocked(name: &'static str) -> Option<ContractReport> {
    davhaven_port_tests::store::run_clocked_case(name, fresh_with_clock).await
}

davhaven_port_tests::store_clocked_contract_tests!(run_clocked);

/// Two rules of the port that no case of the suite holds yet. The PostgreSQL adapter runs the same two tests
/// (`crates/store-postgres/tests/contract.rs`), so the adapters cannot drift apart on them.
mod beyond_the_suite {
    use std::sync::Arc;

    use davhaven_domain::{
        ApiToken, CalendarId, FeedMode, FeedToken, PrincipalId, ScopeSet, TenantId, TokenId, TokenKind,
    };
    use davhaven_port_tests::store::fixtures::seed;
    use davhaven_ports::{Database, StoreError, TxMode};

    /// The token id with the number `n`.
    fn token_id(n: u128) -> TokenId {
        TokenId::from_uuid(uuid::Uuid::from_u128(0x0190_0000_00ee_7000_8000_0000_0000_0000 | n))
    }

    /// A feed token of `principal` for `calendars`; the store sets the tenant, the stamps and the version.
    fn feed(n: u128, principal: PrincipalId, calendars: Vec<CalendarId>, prefix: &str) -> FeedToken {
        FeedToken {
            id: token_id(n),
            tenant_id: TenantId::from_uuid(uuid::Uuid::nil()),
            principal_id: principal,
            mode: FeedMode::Busy,
            calendar_ids: calendars,
            prefix: prefix.to_owned(),
            hash: vec![7, 8, 9],
            pepper_kid: "k1".to_owned(),
            revoked_at: None,
            created_at: chrono::DateTime::UNIX_EPOCH,
            updated_at: chrono::DateTime::UNIX_EPOCH,
            version: 99,
        }
    }

    /// A system token, minted by `created_by`.
    fn system_token(n: u128, prefix: &str, created_by: Option<TokenId>) -> ApiToken {
        ApiToken {
            id: token_id(n),
            tenant_id: None,
            kind: TokenKind::System,
            principal_id: None,
            label: "operator".to_owned(),
            scopes: ScopeSet::empty(),
            prefix: prefix.to_owned(),
            hash: vec![4, 5, 6],
            pepper_kid: "k1".to_owned(),
            expires_at: None,
            created_by,
            allowed_origins: Vec::new(),
            last_used_at: None,
            revoked_at: None,
            created_at: chrono::DateTime::UNIX_EPOCH,
            updated_at: chrono::DateTime::UNIX_EPOCH,
            version: 99,
        }
    }

    /// Purging a calendar takes it out of every feed token that names it (a feed token names its calendars without a key
    /// the store could cascade) and leaves the other feed tokens alone.
    async fn purging_a_calendar_drops_it_from_the_feeds(db: Arc<dyn Database>) -> Result<(), StoreError> {
        let world = seed(&db).await?;
        let mut tx = db.begin(world.a, TxMode::ReadWrite).await?;
        let naming = tx
            .credentials()
            .create_feed_token(feed(
                1,
                world.olivia,
                vec![world.personal, world.shared],
                "feedpurge001",
            ))
            .await?;
        let other = tx
            .credentials()
            .create_feed_token(feed(2, world.olivia, vec![world.shared], "feedpurge002"))
            .await?;
        let personal = tx.calendars().get(world.personal).await?;
        tx.calendars().soft_delete(world.personal, personal.version).await?;
        tx.calendars().purge(world.personal).await?;
        tx.commit().await?;

        let mut tx = db.begin(world.a, TxMode::ReadOnly).await?;
        let pruned = tx.credentials().get_feed_token(naming.id).await?;
        assert_eq!(
            pruned.calendar_ids,
            vec![world.shared],
            "the purged calendar left the feed"
        );
        assert_eq!(
            pruned.version,
            naming.version + 1,
            "the change is a new version of the token"
        );
        let untouched = tx.credentials().get_feed_token(other.id).await?;
        assert_eq!(
            (untouched.calendar_ids, untouched.version),
            (vec![world.shared], other.version),
            "a feed without the calendar is not changed"
        );
        Ok(())
    }

    /// A system token may name the token that minted it, which must exist: an unknown one is `NotFound`.
    async fn a_system_token_names_a_creator_that_exists(db: Arc<dyn Database>) -> Result<(), StoreError> {
        let mut system = db.begin_system().await?;
        let root = system
            .credential_lookup()
            .create_system_token(system_token(3, "systemroot01", None))
            .await?;
        let minted = system
            .credential_lookup()
            .create_system_token(system_token(4, "systemmint01", Some(root.id)))
            .await?;
        assert_eq!(minted.created_by, Some(root.id));
        system.commit().await?;

        let mut system = db.begin_system().await?;
        let orphan = system
            .credential_lookup()
            .create_system_token(system_token(5, "systemmint02", Some(token_id(0x999))))
            .await;
        assert_eq!(orphan.map(|token| token.id), Err(StoreError::NotFound));
        drop(system);
        let mut system = db.begin_system().await?;
        let listed: Vec<TokenId> = system
            .credential_lookup()
            .list_system_tokens()
            .await?
            .into_iter()
            .map(|token| token.id)
            .collect();
        assert_eq!(listed, vec![root.id, minted.id], "the refused token was not stored");
        Ok(())
    }

    #[tokio::test]
    async fn purging_a_calendar_drops_it_from_the_feed_tokens_that_name_it() {
        purging_a_calendar_drops_it_from_the_feeds(super::fresh().await)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_system_token_can_only_name_a_creator_that_exists() {
        a_system_token_names_a_creator_that_exists(super::fresh().await)
            .await
            .unwrap();
    }
}
