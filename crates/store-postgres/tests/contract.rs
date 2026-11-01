//! Runs the store contract suite of `davhaven-port-tests` against PostgreSQL: the migrated schema, the runtime
//! role without `BYPASSRLS`, row-level security and the real transactions. One test per case, so a failure names
//! its case and the runner can parallelise and retry. The cases come from the suite's own list: a case added there
//! has a test here without any edit.
//!
//! The databases have the opt-in grant that lets the runtime role purge the audit log (the retention cases need it);
//! `rls.rs` shows that without the grant the role cannot.

mod support;

use std::sync::Arc;

use davhaven_port_tests::ContractReport;
use davhaven_ports::Database;

/// A fresh database cloned from the migrated template.
async fn fresh(cluster: support::Cluster) -> Arc<dyn Database> {
    Arc::new(support::TestDatabase::create_with_audit_purge(&cluster).await)
}

/// Runs one case of the suite on a fresh database; `None` when the tests were told to skip PostgreSQL.
async fn run(name: &'static str) -> Option<ContractReport> {
    let cluster = support::cluster()?;
    davhaven_port_tests::store::run_case(name, || fresh(cluster)).await
}

davhaven_port_tests::store_contract_tests!(run);

/// A fresh database and the manual clock the store stamps with, for the cases that move the clock.
async fn fresh_with_clock(cluster: support::Cluster) -> (Arc<dyn Database>, davhaven_ports::testing::ManualClock) {
    let database = support::TestDatabase::create_with_audit_purge(&cluster).await;
    let clock = database.clock.clone();
    (Arc::new(database), clock)
}

/// Runs one case that moves the clock on a fresh database; `None` when the tests were told to skip PostgreSQL.
async fn run_clocked(name: &'static str) -> Option<ContractReport> {
    let cluster = support::cluster()?;
    davhaven_port_tests::store::run_clocked_case(name, || fresh_with_clock(cluster)).await
}

davhaven_port_tests::store_clocked_contract_tests!(run_clocked);

/// R4 says the explicit tenant predicates are the first line of defence and row-level security the second. The
/// cases above run as the bound runtime role, where the policies would hide a statement that forgot its tenant, so
/// the isolation cases run once more as the owner role, which the policies do not bind: only the predicates are left.
mod without_row_level_security {
    use std::sync::Arc;

    use davhaven_port_tests::ContractReport;
    use davhaven_ports::Database;

    use super::support;

    async fn owner(cluster: support::Cluster) -> Arc<dyn Database> {
        Arc::new(support::TestDatabase::create_as_owner(&cluster).await)
    }

    /// Runs one isolation case on a fresh database as the owner role.
    async fn run_as_owner(name: &'static str) -> Option<ContractReport> {
        let cluster = support::cluster()?;
        davhaven_port_tests::store::run_case(name, || owner(cluster)).await
    }

    davhaven_port_tests::store_isolation_tests!(run_as_owner);
}

/// Two rules of the port that no case of the suite holds yet. The in-memory adapter runs the same two tests
/// (`crates/store-memory/tests/contract.rs`), so the adapters cannot drift apart on them.
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
        let Some(cluster) = super::support::cluster() else {
            return;
        };
        purging_a_calendar_drops_it_from_the_feeds(super::fresh(cluster).await)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_system_token_can_only_name_a_creator_that_exists() {
        let Some(cluster) = super::support::cluster() else {
            return;
        };
        a_system_token_names_a_creator_that_exists(super::fresh(cluster).await)
            .await
            .unwrap();
    }
}
