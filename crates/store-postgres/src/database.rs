//! The `Database` implementation: pool, health and transaction start.
//!
//! [`PgDatabase`] owns the connection pool of the runtime role. A tenant transaction starts with `BEGIN` (or
//! `BEGIN READ ONLY`) followed by `set_config('davhaven.tenant_id', ..., true)`, which the row-level security
//! policies compare with `tenant_id`; a system transaction sets `davhaven.system` instead. Time and ids come from
//! the injected [`Clock`] and [`IdGenerator`], never from the database.
//!
//! Every connection carries three server-side limits (`statement_timeout`, `lock_timeout` and
//! `idle_in_transaction_session_timeout`), so a slow statement, a queue behind a hot calendar lock and a stalled
//! request task each end in [`StoreError::Timeout`] instead of pinning a pooled
//! connection.
//!
//! [`PgDatabase::posture`] checks what the connected role may do. Row-level security only protects the tenants when
//! the role is bound by it, so the check is part of readiness and, in production, of startup
//! ([`plugin`](crate::plugin)). Row-level security is a second line of defence against a missing or wrong tenant
//! predicate in this adapter's own SQL; it is not a boundary against code that can run SQL as the runtime role
//! (docs/adr/0005-database-role-model-and-system-scope.md, "Threat model").

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use davhaven_domain::TenantId;
use davhaven_ports::{
    Clock, Database, Health, IdGenerator, Lifecycle, PluginError, PortError, StoreError, SystemTx, Tx, TxMode, observe,
};
use secrecy::ExposeSecret;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, SqlSafeStr, Transaction};

use crate::config::{DatabaseConfig, PLUGIN};
use crate::error::map_sqlx;
use crate::migrate::{REQUIRED_SCHEMA_VERSION, applied_version_on, require_supported_server};
use crate::pool_metrics::PoolMetrics;
use crate::repos::LABEL;
use crate::tx::{PgSystemTx, PgTx};

/// What the connection's role may do, as far as tenant isolation and the role model of
/// `docs/operations/database.md` are concerned. `Posture::default()` is a clean posture: no finding of any kind.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Posture {
    /// The name of the connected role when row-level security does not bind it: a superuser, a role with
    /// `BYPASSRLS` (or a member of one, which can `SET ROLE` to it), or the owner of the tenant tables (or a
    /// member of the owner role, which can become it).
    pub unbound_role: Option<String>,
    /// Privileges the runtime role holds beyond the role model (`TRUNCATE`, `REFERENCES` or `TRIGGER` on a table,
    /// writes to the audit log or to the migration history, `CREATE` on the schema, `EXECUTE` on a `SECURITY DEFINER`
    /// function such as `davhaven_purge_audit`: a role that can call the purge can erase the audit trail of every
    /// tenant, and any function that runs with the owner's rights is a way past the runtime role's privileges). Only
    /// examined for a bound role: an unbound one holds everything.
    pub excess_privileges: Vec<String>,
    /// Why the security posture could not be determined (a failed query, tables or schema that are not where the
    /// adapter looks); empty when it could. Counts as a security finding: a posture nobody could check is not a
    /// safe one.
    pub unknown: Option<String>,
    /// Whether the database lowercases only ASCII text (its `LC_CTYPE` is not Unicode-aware). Case-insensitive
    /// search depends on it (the unique indexes on addresses and login domains do not: the domain types
    /// normalise those values to ASCII). A notice, not a security finding.
    pub ascii_only_case_folding: bool,
    /// Why the locale could not be checked (a failed query). A notice, not a security finding: it never keeps
    /// production from starting.
    pub locale_unknown: Option<String>,
}

/// The function that deletes audit records. The runtime role may not execute it (the audit log is append-only for a
/// compromised server), so retention runs as the owner, on a schedule (`davhaven admin purge-audit`); a runtime role
/// that can execute it is a security finding that says so.
const PURGE_FUNCTION: &str = "davhaven_purge_audit";

impl Posture {
    /// The findings that weaken tenant isolation or the append-only audit log. Production refuses to start with
    /// any of them unless `database.allow_unbound_role` is set.
    pub fn security_findings(&self) -> Vec<String> {
        let mut findings = Vec::new();
        if let Some(role) = &self.unbound_role {
            findings.push(format!(
                "the database role `{role}` is not bound by row-level security (superuser, BYPASSRLS, the owner of \
                 the tables, or a member of such a role): tenant isolation relies on the application alone"
            ));
        }
        if !self.excess_privileges.is_empty() {
            let mut finding = format!(
                "the database role holds privileges the runtime role must not have: {}",
                self.excess_privileges.join(", ")
            );
            if self
                .excess_privileges
                .iter()
                .any(|privilege| privilege.contains(PURGE_FUNCTION))
            {
                finding.push_str(
                    " (a role that can run the audit purge can erase the audit trail of every tenant: revoke it, and \
                     run the purge with the owner credentials, `davhaven admin purge-audit`)",
                );
            }
            findings.push(finding);
        }
        if let Some(reason) = &self.unknown {
            findings.push(format!("the role posture could not be checked: {reason}"));
        }
        findings
    }

    /// Every finding, security findings first, then the notices (the locale).
    pub fn findings(&self) -> Vec<String> {
        let mut findings = self.security_findings();
        if self.ascii_only_case_folding {
            findings.push(
                "the database does not lowercase non-ASCII text (its LC_CTYPE is not Unicode-aware, for example the \
                 C locale): case-insensitive search differs from the in-memory store; create the database with a \
                 UTF-8 locale or the ICU provider"
                    .to_owned(),
            );
        }
        if let Some(reason) = &self.locale_unknown {
            findings.push(format!("the database locale could not be checked: {reason}"));
        }
        findings
    }

    /// The text of the degraded health report, or `None` when there is nothing to report.
    pub fn reason(&self) -> Option<String> {
        let findings = self.findings();
        if findings.is_empty() {
            None
        } else {
            Some(format!("{}; see docs/operations/database.md", findings.join("; ")))
        }
    }
}

/// The SQL of the role check: the name of the connected role, the schema of the connection, whether the role is
/// (or is a member of) a superuser or `BYPASSRLS` role, whether the tenant tables are where this adapter looks
/// (schema `public`), and whether the role is a member of the owner of those tables. It reads the catalogs only, so it
/// answers for a role that has no privilege on the schema (such a role is not safe either, and must be reported).
const ROLE_POSTURE: &str = "\
    WITH RECURSIVE member_of(roleid) AS ( \
        SELECT oid FROM pg_roles WHERE rolname = current_user \
        UNION \
        SELECT m.roleid FROM pg_auth_members m JOIN member_of r ON m.member = r.roleid) \
    SELECT current_user::text, current_schema()::text, \
           EXISTS (SELECT 1 FROM member_of x JOIN pg_roles p ON p.oid = x.roleid \
                   WHERE p.rolsuper OR p.rolbypassrls), \
           EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
                   WHERE n.nspname = 'public' AND c.relname = 'principals'), \
           COALESCE((SELECT pg_has_role(current_user, c.relowner, 'MEMBER') FROM pg_class c \
                     JOIN pg_namespace n ON n.oid = c.relnamespace \
                     WHERE n.nspname = 'public' AND c.relname = 'principals'), false)";

/// The SQL of the privilege check: one text per privilege the runtime role holds beyond the role model. The functions
/// that run with the owner's rights (`SECURITY DEFINER`, today the audit purge only) are checked as a class: the role
/// model grants the runtime role the two row-level security helpers and nothing else, so a function of this kind that
/// the role can execute, a later migration's included, is a way past its privileges.
const EXCESS_PRIVILEGES: &str = "\
    SELECT format('%s on %s', p.priv, c.relname) FROM pg_class c \
    CROSS JOIN (VALUES ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')) AS p(priv) \
    WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p') \
      AND has_table_privilege(c.oid, p.priv) \
    UNION ALL \
    SELECT format('%s on audit_events', p.priv) FROM (VALUES ('UPDATE'), ('DELETE')) AS p(priv) \
    WHERE to_regclass('public.audit_events') IS NOT NULL AND has_table_privilege('public.audit_events', p.priv) \
    UNION ALL \
    SELECT format('%s on _sqlx_migrations', p.priv) FROM (VALUES ('INSERT'), ('UPDATE'), ('DELETE')) AS p(priv) \
    WHERE to_regclass('public._sqlx_migrations') IS NOT NULL \
      AND has_table_privilege('public._sqlx_migrations', p.priv) \
    UNION ALL \
    SELECT format('EXECUTE on %s', f.oid::regprocedure) FROM pg_proc f \
    WHERE f.pronamespace = 'public'::regnamespace AND f.prosecdef AND has_function_privilege(f.oid, 'EXECUTE') \
    UNION ALL \
    SELECT 'CREATE on schema public' WHERE has_schema_privilege('public', 'CREATE') \
    ORDER BY 1";

/// Whether `host` names this machine: empty (the default socket), a socket directory, `localhost` or a loopback
/// address. A name that merely starts like one (`127.example.net`) is a remote host.
pub fn is_local_host(host: &str) -> bool {
    let host = host.trim();
    if host.is_empty() || host.starts_with('/') || host.to_ascii_lowercase().starts_with("%2f") {
        return true;
    }
    let host = host.trim_matches(['[', ']']);
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|address| address.to_canonical().is_loopback())
}

/// The text of a warning when the connection URL sends data in the clear over a network, `None` for a local
/// database, an encrypted connection or an unreadable URL.
///
/// The driver's default `sslmode=prefer` falls back to plaintext, and credential hashes, sealed secrets and
/// calendar data cross this connection, so the plugin refuses such a URL in production
/// (`database.allow_insecure_transport` accepts the risk). Both spellings of the parameter (`sslmode` and
/// `ssl-mode`), `hostaddr` (the address that is really dialled) and a comma-separated `host` list are read.
pub fn transport_warning(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let mut hosts = parsed.host_str().map(str::to_owned);
    let mut hostaddr = None;
    let mut mode = None;
    for (key, value) in parsed.query_pairs() {
        match key.to_ascii_lowercase().replace('_', "-").as_str() {
            "sslmode" | "ssl-mode" => mode = Some(value.to_ascii_lowercase()),
            "host" => hosts = Some(value.into_owned()),
            "hostaddr" => hostaddr = Some(value.into_owned()),
            _ => {}
        }
    }
    let hosts = hostaddr.or(hosts)?;
    let remote: Vec<&str> = hosts.split(',').filter(|host| !is_local_host(host)).collect();
    if remote.is_empty() {
        return None;
    }
    match mode.as_deref().unwrap_or("prefer") {
        "require" | "verify-ca" | "verify-full" => None,
        other => Some(format!(
            "the database connection to `{}` uses sslmode `{other}`, which may send credentials and calendar \
             data unencrypted; use sslmode=verify-full in the connection URL for every database that is not on \
             this host",
            remote.join(", ")
        )),
    }
}

/// The PostgreSQL implementation of the `Database` port.
#[derive(Clone)]
pub struct PgDatabase {
    pool: PgPool,
    pub(crate) pool_metrics: Arc<PoolMetrics>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
    maintenance_timeout: Duration,
}

impl std::fmt::Debug for PgDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgDatabase")
            .field("pool_size", &self.pool.size())
            .finish_non_exhaustive()
    }
}

impl PgDatabase {
    /// Wraps an existing pool. The pool's role must be the runtime role: `NOBYPASSRLS`, not the owner of the
    /// tables (otherwise row-level security does not apply to it).
    pub fn from_pool(pool: PgPool, clock: Arc<dyn Clock>, ids: Arc<dyn IdGenerator>) -> Self {
        Self {
            pool_metrics: Arc::new(PoolMetrics::new(pool.clone())),
            pool,
            clock,
            ids,
            maintenance_timeout: DatabaseConfig::default().maintenance_timeout,
        }
    }

    /// Sets the `statement_timeout` of the maintenance operations (deleting a tenant, purging a principal or a
    /// calendar, bumping the sync epoch); zero removes the limit.
    #[must_use]
    pub fn with_maintenance_timeout(mut self, timeout: Duration) -> Self {
        self.maintenance_timeout = timeout;
        self
    }

    /// Connects the runtime role of `config` and opens the pool. The first connection is made eagerly, so an
    /// unreachable database fails startup instead of the first request.
    ///
    /// # Errors
    ///
    /// [`PluginError::InvalidConfig`] for a missing or malformed URL, [`PluginError::Build`] when the database
    /// cannot be reached.
    pub async fn connect(
        config: &DatabaseConfig,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
    ) -> Result<Self, PluginError> {
        config.validate()?;
        let url = config.runtime_url()?;
        let options: PgConnectOptions = url
            .expose_secret()
            .parse()
            .map_err(|_| PluginError::invalid_config(PLUGIN, "`url` is not a PostgreSQL connection URL"))?;
        let statement_ms = config.statement_timeout.as_millis().to_string();
        let lock_ms = config.lock_timeout.as_millis().to_string();
        let idle_ms = config.idle_in_transaction_timeout.as_millis().to_string();
        let options = options.application_name("davhaven").options([
            ("statement_timeout", statement_ms.as_str()),
            ("lock_timeout", lock_ms.as_str()),
            ("idle_in_transaction_session_timeout", idle_ms.as_str()),
        ]);
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .acquire_timeout(config.acquire_timeout)
            .connect_with(options)
            .await
            .map_err(|error| PluginError::build(PLUGIN, map_sqlx(error)))?;
        if let Err(error) = require_supported_server(&pool).await {
            pool.close().await;
            return Err(PluginError::build(PLUGIN, PortError::from(error)));
        }
        Ok(Self::from_pool(pool, clock, ids).with_maintenance_timeout(config.maintenance_timeout))
    }

    /// The connection pool (for the readiness probe and tests). Direct acquisitions are included in the sampled
    /// in-use gauge, but bypass the adapter's pending-acquisition gauge.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Checks that the schema is at least [`REQUIRED_SCHEMA_VERSION`] and what the connected role may do.
    async fn schema_health(&self) -> Health {
        // Release this connection before posture acquires one: a pool with a single connection must work too.
        let version = async {
            let mut conn = self.pool_metrics.acquire().await?;
            applied_version_on(&mut conn).await
        }
        .await;
        match version {
            Ok(Some(version)) if version >= REQUIRED_SCHEMA_VERSION => match self.posture().await.reason() {
                Some(reason) => Health::Degraded(reason),
                None => Health::Healthy,
            },
            Ok(Some(version)) => Health::Unhealthy(format!(
                "the database schema is at version {version}, this release needs at least {REQUIRED_SCHEMA_VERSION}; \
                 run `davhaven migrate` with the owner role (`database.migration_url`)"
            )),
            Ok(None) => Health::Unhealthy(
                "the database has not been migrated; run `davhaven migrate` with the owner role \
                 (`database.migration_url`), or set `database.migrate_on_start = true` with an owner URL"
                    .to_owned(),
            ),
            Err(_) => Health::Unhealthy("the database cannot be reached".to_owned()),
        }
    }

    /// Examines the connected role: whether row-level security binds it, whether it holds privileges the role
    /// model withholds and whether the database folds the case of non-ASCII text. A query that fails is part of the
    /// result ([`Posture::unknown`], [`Posture::locale_unknown`]), never a reason to report the role healthy. The
    /// tenant tables must be in schema `public`, which is where the migration puts them and where the checks look; a
    /// connection whose current schema is another one, or where the tables are not found, is reported as unknown.
    pub async fn posture(&self) -> Posture {
        let mut posture = Posture::default();
        let mut conn = match self.pool_metrics.acquire().await {
            Ok(conn) => conn,
            Err(error) => {
                posture.unknown = Some(format!("the role query failed ({error})"));
                posture.locale_unknown = Some(format!("the locale query failed ({error})"));
                return posture;
            }
        };
        let role = sqlx::query_as::<_, (String, Option<String>, bool, bool, bool)>(ROLE_POSTURE)
            .fetch_one(&mut *conn)
            .await;
        match role {
            Ok((name, schema, privileged, tables_found, owner_member)) => {
                if !tables_found {
                    posture.unknown = Some(
                        "the tenant tables were not found in schema `public` (Davhaven supports that schema only)"
                            .to_owned(),
                    );
                } else if schema.as_deref() != Some("public") {
                    posture.unknown = Some(format!(
                        "the connection's current schema is `{}`, but Davhaven uses schema `public` only; set the \
                         role's `search_path` to `public`",
                        schema.as_deref().unwrap_or("(none)")
                    ));
                }
                if privileged || owner_member {
                    posture.unbound_role = Some(name);
                } else if posture.unknown.is_none() {
                    match sqlx::query_scalar::<_, String>(EXCESS_PRIVILEGES)
                        .fetch_all(&mut *conn)
                        .await
                    {
                        Ok(excess) => posture.excess_privileges = excess,
                        Err(error) => {
                            posture.unknown = Some(format!("the privilege query failed ({})", map_sqlx(error)));
                        }
                    }
                }
            }
            Err(error) => posture.unknown = Some(format!("the role query failed ({})", map_sqlx(error))),
        }
        // `U&'\00C4...'` spells "ÄÖÜ" and "äöü" without non-ASCII source text.
        match sqlx::query_scalar::<_, bool>(r"SELECT lower(U&'\00C4\00D6\00DC') = U&'\00E4\00F6\00FC'")
            .fetch_one(&mut *conn)
            .await
        {
            Ok(folds) => posture.ascii_only_case_folding = !folds,
            Err(error) => posture.locale_unknown = Some(format!("the locale query failed ({})", map_sqlx(error))),
        }
        posture
    }
}

#[async_trait]
impl Database for PgDatabase {
    async fn begin(&self, tenant: TenantId, mode: TxMode) -> Result<Box<dyn Tx>, StoreError> {
        observe(LABEL, "begin", async {
            let statement = match mode {
                TxMode::ReadOnly => "BEGIN READ ONLY",
                // One snapshot for every statement, taken by the first one (the tenant binding below).
                TxMode::Snapshot => "BEGIN READ ONLY ISOLATION LEVEL REPEATABLE READ",
                TxMode::ReadWrite => "BEGIN",
                _ => return Err(StoreError::Unsupported),
            };
            let conn = self.pool_metrics.acquire().await?;
            // Like `PgPool::begin_with`, move the owned connection into a transaction that can outlive this call.
            let mut conn = Transaction::begin(conn, Some(statement.into_sql_str()))
                .await
                .map_err(map_sqlx)?;
            sqlx::query("SELECT set_config('davhaven.tenant_id', $1, true)")
                .bind(tenant.to_string())
                .execute(&mut *conn)
                .await
                .map_err(map_sqlx)?;
            let tx: Box<dyn Tx> = Box::new(PgTx::new(
                conn,
                tenant,
                Arc::clone(&self.clock),
                Arc::clone(&self.ids),
                self.maintenance_timeout,
            ));
            Ok(tx)
        })
        .await
    }

    async fn begin_system(&self) -> Result<Box<dyn SystemTx>, StoreError> {
        observe(LABEL, "begin_system", async {
            let conn = self.pool_metrics.acquire().await?;
            let mut conn = Transaction::begin(conn, None).await.map_err(map_sqlx)?;
            sqlx::query("SELECT set_config('davhaven.system', 'on', true)")
                .execute(&mut *conn)
                .await
                .map_err(map_sqlx)?;
            let tx: Box<dyn SystemTx> = Box::new(PgSystemTx::new(
                conn,
                Arc::clone(&self.clock),
                Arc::clone(&self.ids),
                self.maintenance_timeout,
            ));
            Ok(tx)
        })
        .await
    }

    async fn health(&self) -> Health {
        self.schema_health().await
    }
}

#[async_trait]
impl Lifecycle for PgDatabase {
    async fn health(&self) -> Health {
        self.schema_health().await
    }

    async fn shutdown(&self) {
        self.pool.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_default_posture_is_clean() {
        let posture = Posture::default();
        assert!(posture.security_findings().is_empty(), "{posture:?}");
        assert!(posture.findings().is_empty(), "{posture:?}");
        assert_eq!(posture.reason(), None);
    }

    #[test]
    fn every_finding_is_reported_and_security_findings_come_first() {
        let posture = Posture {
            unbound_role: Some("davhaven_owner".to_owned()),
            excess_privileges: vec!["TRUNCATE on principals".to_owned()],
            unknown: Some("the role query failed".to_owned()),
            ascii_only_case_folding: true,
            locale_unknown: Some("the locale query failed".to_owned()),
        };
        let security = posture.security_findings();
        assert_eq!(security.len(), 3);
        assert!(security[0].contains("davhaven_owner") && security[0].contains("row-level security"));
        assert!(security[1].contains("TRUNCATE on principals"));
        assert!(security[2].contains("could not be checked"));
        let all = posture.findings();
        assert_eq!(all.len(), 5);
        assert!(all[3].contains("LC_CTYPE"));
        assert!(all[4].contains("locale could not be checked"));
        assert!(posture.reason().unwrap().ends_with("see docs/operations/database.md"));
    }

    #[test]
    fn the_privilege_query_names_the_purge_function_that_the_hint_looks_for() {
        // The query lists a function as `EXECUTE on <regprocedure>`; the hint about the audit purge is chosen by the name.
        let posture = Posture {
            excess_privileges: vec![format!("EXECUTE on {PURGE_FUNCTION}(timestamp with time zone,integer)")],
            ..Posture::default()
        };
        let findings = posture.security_findings();
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(
            findings[0].contains("erase the audit trail") && findings[0].contains("davhaven admin purge-audit"),
            "{findings:?}"
        );
        let other = Posture {
            excess_privileges: vec!["EXECUTE on another_definer(integer)".to_owned()],
            ..Posture::default()
        };
        assert!(!other.security_findings()[0].contains("audit trail"));
        assert!(
            EXCESS_PRIVILEGES.contains("prosecdef"),
            "the query checks every function that runs with the owner's rights"
        );
    }

    #[test]
    fn notices_are_reported_but_are_not_security_findings() {
        for posture in [
            Posture {
                ascii_only_case_folding: true,
                ..Posture::default()
            },
            Posture {
                locale_unknown: Some("the locale query failed".to_owned()),
                ..Posture::default()
            },
        ] {
            assert_eq!(posture.security_findings().len(), 0, "{posture:?}");
            assert_eq!(posture.findings().len(), 1, "{posture:?}");
            assert!(posture.reason().is_some());
        }
    }

    #[test]
    fn local_hosts_are_told_from_look_alikes() {
        for host in [
            "",
            "localhost",
            "LOCALHOST",
            "127.0.0.1",
            "127.1.2.3",
            "::1",
            "[::1]",
            "::ffff:127.0.0.1",
            "/var/run/postgresql",
            "%2Fvar%2Frun%2Fpostgresql",
        ] {
            assert!(is_local_host(host), "{host:?} is this host");
        }
        for host in [
            "db.internal",
            "127.example.net",
            "localhost.example.net",
            "10.0.0.5",
            "192.168.1.1",
            "2001:db8::1",
            "[2001:db8::1]",
        ] {
            assert!(!is_local_host(host), "{host:?} is another host");
        }
    }

    #[test]
    fn unencrypted_connections_to_other_hosts_are_flagged() {
        for url in [
            "postgres://app:pw@db.internal/davhaven",
            "postgres://app:pw@db.internal/davhaven?sslmode=prefer",
            "postgres://app:pw@10.0.0.5/davhaven?sslmode=disable",
            "postgres://app:pw@db.internal/davhaven?sslmode=allow",
            "postgres://app:pw@db.internal/davhaven?ssl-mode=disable",
            "postgres://app:pw@db.internal/davhaven?SSLMODE=Prefer",
            "postgres://app:pw@127.example.net/davhaven",
            "postgres:///davhaven?host=db.internal&user=app",
            "postgres:///davhaven?host=localhost,db.internal&user=app",
            "postgres://app:pw@localhost/davhaven?hostaddr=10.0.0.5",
        ] {
            let warning = transport_warning(url).unwrap_or_default();
            assert!(warning.contains("verify-full"), "{url}: {warning}");
            assert!(!warning.contains("pw"), "the warning never repeats the password");
        }
    }

    #[test]
    fn encrypted_and_local_connections_are_not_flagged() {
        for url in [
            "postgres://app:pw@db.internal/davhaven?sslmode=verify-full",
            "postgres://app:pw@db.internal/davhaven?ssl-mode=verify-full",
            "postgres://app:pw@db.internal/davhaven?sslmode=require",
            "postgres://app:pw@db.internal/davhaven?sslmode=VERIFY-CA",
            "postgres://app:pw@localhost/davhaven",
            "postgres://app:pw@127.0.0.1:5432/davhaven",
            "postgres://app:pw@[::1]/davhaven",
            "postgres://app:pw@%2Fvar%2Frun%2Fpostgresql/davhaven",
            "postgres:///davhaven?host=/var/run/postgresql&user=app",
            "postgres://app:pw@db.internal/davhaven?hostaddr=127.0.0.1",
            "not a url",
        ] {
            assert_eq!(transport_warning(url), None, "{url}");
        }
    }
}
