# PostgreSQL: roles, migrations and tenant isolation

Davhaven keeps everything in one PostgreSQL database. This page is for the people who provision and run it: which
roles exist and what each may do, how the schema is migrated and upgraded without downtime, how tenant isolation is
enforced by the database itself, and what to know about backups, retention and the test setup. The data model is described in
[`PLAN.md`](../PLAN.md), the rules behind it in [`ENGINEERING_RULES.md`](../ENGINEERING_RULES.md) R4 and
R16, the decisions in [ADR-0005](../adr/0005-database-role-model-and-system-scope.md) (and
[ADR-0006](../adr/0006-store-contract-amendments.md) for the amendments to the storage contract), and the storage adapter is the crate
`davhaven-store-postgres` (the in-memory twin, `davhaven-store-memory`, is for tests and local development and
refuses to start in production).

The other operations pages are the [runbook](runbook.md), the [key ring](keys.md) and [backup and restore](backup.md).

## Requirements

* PostgreSQL 15 or newer (the schema uses `ON DELETE SET NULL (column)`). The adapter checks `server_version_num` before
  it migrates and when it connects, and refuses an older server with a message that names the minimum. The pull request
  pipeline runs the tests on one PostgreSQL version (the one of its service container, 18); the nightly run uses the latest
  release. No CI job runs against the oldest supported version (15) yet.
* No extensions. Identifiers, timestamps and sequence numbers come from the application (`IdGenerator`, `Clock`),
  never from `gen_random_uuid()` or `now()`, so a restored or replayed database behaves like the original.
* **A UTF-8 database with a Unicode-aware `LC_CTYPE`** (for example `en_US.UTF-8` or `C.UTF-8`, or the ICU provider:
  `CREATE DATABASE davhaven ... LOCALE_PROVIDER icu ICU_LOCALE 'und-x-icu'`). Display-name searches (`principals.search`,
  the text filter of the calendar list) lower-case with the database's `LC_CTYPE`; in the `C` locale `lower('Ä')` stays
  `Ä`, so a search for `müller` misses `Müller` and the results differ from the in-memory store. (The unique indexes on
  addresses and login domains do not depend on it: the domain types normalise those values to ASCII first.) The server
  checks this on connect and reports it in readiness (degraded, with the reason).
  Orderings that the API exposes use `COLLATE "C"`, but the plain indexes on text keys use the database default
  collation: after a restore on a host with another glibc version run `REINDEX DATABASE davhaven`.
* Any time zone: the adapter stores `timestamptz` (microsecond precision; it truncates the clock to microseconds so that
  the in-memory and the PostgreSQL adapter agree).
* Text and JSON values cannot contain the NUL character (U+0000); PostgreSQL rejects them (SQLSTATE 22021 and 22P05)
  and the adapter answers `StoreError::InvalidData`, which the application reports as an invalid value, not as a
  server error. The in-memory adapter refuses the same text in the free-text fields (names, descriptions, labels,
  summaries, properties, iCalendar and notification text), so tests on it see what production answers.
* **A connection in schema `public`.** The migration, the role checks and the audit purge function use the schema
  `public`; the connection's current schema must be `public` (the default for a role without a schema of its own name).
  A connection whose `search_path` points elsewhere is refused by `davhaven migrate` and reported as a finding by the
  readiness check.
* **TLS.** The connection carries credential hashes, sealed secrets and calendar data. For every database that is not
  on the same host put `sslmode=verify-full` (and, if needed, `sslrootcert=`) into `database.url` and
  `database.migration_url`. The default `sslmode=prefer` silently falls back to plaintext, so **production refuses to
  start** with a remote host that does not require encryption (`ssl-mode` is read as well as `sslmode`, `hostaddr`
  and a comma-separated `host` list included; only loopback addresses, `localhost` and sockets count as this host) unless
  `database.allow_insecure_transport = true` accepts the risk. In `dev` mode the finding is only logged.
  `config check` applies the same rule, and so do `davhaven migrate` and `davhaven admin purge-audit` to the owner
  URL they connect with (`database.migration_url`, else `database.url`), before they connect. Where the opt-in is in
  effect, or is set but no URL needs it, the check and the log say so.

## Role model

Two login roles, both without superuser rights:

| Role | Purpose | Owns | Row-level security | Can change the schema |
| --- | --- | --- | --- | --- |
| **owner** (for example `davhaven_owner`) | Runs the migrations (`davhaven migrate`); used by an operator for repairs and, if you choose so, for audit retention | the database, the schema `public`, every table, function and sequence | not bound (the owner of a table is exempt, which is also what lets `ON DELETE CASCADE` reach every tenant's rows) | yes |
| **runtime** (for example `davhaven_app`) | Everything the running server does | nothing | **bound**: `NOSUPERUSER NOBYPASSRLS`, not the owner of any table | no (no `CREATE` on the schema, no ownership) |

The server connects with the runtime role (`database.url`). The owner is used for migrations only
(`database.migration_url`).

**Production recipe.** Keep the owner credentials out of the serving process: set `database.migrate_on_start = false`
and run `davhaven migrate` as a separate job (an init container or a deployment step with its own secret holding
`migration_url`). A single URL that serves *and* migrates means the owner serves, and the owner is not bound by
row-level security.

**The server refuses that in production.** `server.mode = "production"` (the default) makes the database plugin
refuse to start when the connected role is a superuser, has `BYPASSRLS`, owns or can become the owner of the tenant
tables, is a member (directly or through other roles) of any such role, or holds privileges beyond the table below;
a posture the check cannot establish (a failed query, a current schema other than `public`) counts as a finding too.
The error names the role and points here. The explicit opt-out is
`database.allow_unbound_role = true` (tenant isolation then rests on the application alone). In `dev` mode the finding
is only logged. The same checks run on every `/readyz`, and a finding turns the database **degraded** (ready, with the
reason in the health report). A startup that finds `migration_url` set while `migrate_on_start` is on logs a warning,
because the serving process then holds the owner credentials.

### Provisioning

Run once, as a superuser of the cluster (the passwords come from your secret store):

```sql
CREATE ROLE davhaven_owner LOGIN PASSWORD '...' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE ROLE davhaven_app   LOGIN PASSWORD '...' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE DATABASE davhaven OWNER davhaven_owner;

\c davhaven
REVOKE ALL ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO davhaven_owner;
GRANT USAGE ON SCHEMA public TO davhaven_app;

-- Every table and sequence the owner creates (the migrations) is usable by the runtime role without a grant step.
ALTER DEFAULT PRIVILEGES FOR ROLE davhaven_owner IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO davhaven_app;
ALTER DEFAULT PRIVILEGES FOR ROLE davhaven_owner IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO davhaven_app;
```

Then `davhaven migrate` (as the owner) creates the schema. The default privileges are the whole grant mechanism:
a future migration that adds a table needs no `GRANT`. These statements are exactly the ones the test support runs
(a test compares them with this page), and the same statements without `IN SCHEMA public` work as well.

### What the runtime role may do

| Object | Privileges of the runtime role |
| --- | --- |
| Tenant tables | `SELECT`, `INSERT`, `UPDATE`, `DELETE`, filtered by row-level security (below). Never `TRUNCATE` (which bypasses row-level security), `REFERENCES` or `TRIGGER` |
| `audit_events` | `SELECT` and `INSERT` only, and only on the own tenant's rows (a system transaction reads the log of every tenant, see "System scope"). There is no `UPDATE`, `DELETE` or `TRUNCATE` privilege and no policy that would allow one |
| `_sqlx_migrations` (the migration history) | `SELECT` only; the readiness probe reads it. It cannot be written, so a compromised server cannot pretend a migration ran |
| Functions | `EXECUTE` on `davhaven_current_tenant()` and `davhaven_is_system()` (used by the policies), and on nothing else. **Never** on `davhaven_purge_audit(timestamptz, integer)` or on any other function that runs with the owner's rights (`SECURITY DEFINER`): a runtime role that can execute one is reported as holding a privilege it must not have (see below). A function that a later migration creates is not executable by the runtime role by default |
| Schema | `USAGE`; no `CREATE`, so no new objects; no `ALTER` of tables, policies or functions (it owns none) |

**Every run of `davhaven migrate` (and of `database.migrate_on_start`) ends with a step that enforces this**, whether or not a
migration was pending (`crates/store-postgres/src/role_model.sql`): it looks up the roles that hold default privileges of the
**owner of the tables** (`pg_default_acl`; a migration role that is a member of a `NOLOGIN` owner role acts for it, and the
default privileges are the owner's) and, for each of them, revokes `TRUNCATE`, `REFERENCES` and `TRIGGER` on every table
(a blanket `GRANT ALL` is cut back), revokes `UPDATE`, `DELETE` and `TRUNCATE` on `audit_events`, every write on
`_sqlx_migrations` and `EXECUTE` on the audit purge, takes away the default privilege on functions (so that a function a later
migration creates is not executable by the runtime role unless that migration grants it), and grants `EXECUTE` on the two
policy functions. The statements are idempotent and serialised by an advisory lock (replicas that start together apply them
one after the other); each looks its object up first, so an older schema is not an error. No role name is baked in. It matters
most after a **restore**: the tables of a restored database get the default privileges of the owner when they are created, which
include writes to the audit log and to the migration history, and the grants inside the dump only add to them
([backup and restore](backup.md)); the step puts the role model back, which is why "migrate" is not optional after a restore.

The step does nothing when the connected role does not own the tables (a runtime role that migrates with its own credentials may
not change privileges): `database.migrate_on_start` skips it quietly, and `davhaven migrate` **fails** with an explanation
instead of reporting a migration that did not do its job. The command says what it did (`role model: applied to 1 runtime
role`), and the log warns when the owner has granted no default privileges, so that no runtime role was found. A later
migration that adds a table which must not be fully writable adds the revocation to `role_model.sql` for that table; a later
migration that adds a function the runtime role calls adds the `GRANT`. If you provision without default privileges
(hand-written `GRANT` statements), or add a second runtime role after the first migration, the step does not cover that role:
grant by hand in the same shape: data access on all tenant tables, `SELECT, INSERT` on `audit_events`, `SELECT` on
`_sqlx_migrations`, `EXECUTE` on the two functions. The posture check (`has_table_privilege` on every table, the audit log, the
migration history, every function that runs with the owner's rights and the schema) reports every deviation as a privilege the
runtime role must not have, and production refuses to start with one unless `database.allow_unbound_role` accepts the risk (it
accepts every finding at once, the unbound role included: it is the setting of a deployment that cannot have the two roles).

### Audit log retention

The runtime role cannot delete audit records, and **cannot call the purge function either**.
`davhaven_purge_audit(cutoff, max_rows)` is a `SECURITY DEFINER` function owned by the owner role: it removes at most
`max_rows` records older than `cutoff` across all tenants and returns how many it removed. A role that may call it can
erase the audit trail of every tenant with one statement, so `PUBLIC` and the runtime role have no `EXECUTE` on it: the
initial migration revokes it from `PUBLIC`, and the role model step above revokes it from every runtime role after every
migration run and every restore (whatever way the role came by it: a default privilege on functions, a grant made
to let the server purge, a blanket `GRANT ... ON ALL FUNCTIONS`).
**A runtime role that holds it anyway is a finding**: the posture check lists `EXECUTE on davhaven_purge_audit(timestamp
with time zone,integer)` among the privileges the runtime role must not have, readiness is degraded with the reason, and
production refuses to start unless `database.allow_unbound_role = true` accepts that a compromised server could erase the audit
trail (together with every other security finding: there is no setting that accepts this one alone).

**The server never purges the audit log.** Retention (records live 365 days by default, `retention.audit_days`) is a job that runs outside
it, but the server **watches** it: the cleanup worker publishes when the oldest audit event of all tenants occurred
(`davhaven_audit_oldest_event_timestamp_seconds`) next to the configured retention (`davhaven_audit_retention_seconds`), and an
event that is much older than the retention period says that the job did not run. Schedule it, alert on its exit status, and
alert on the gauge too ([`runbook.md`](runbook.md#retention) has the expression): the exit status says that a run failed, the gauge
also says that none happened.

1. **With the owner credentials.** Schedule `davhaven admin purge-audit` (it runs with the `database.migration_url`
   credentials, removes what is older than the audit retention period in batches until a batch is not full, and prints how many
   records it removed; the storage adapter's `migrate::purge_audit` is what it calls), or run the statement yourself with the
   owner credentials, for example daily:

   ```sql
   SELECT davhaven_purge_audit(now() - interval '400 days', 50000);
   ```

   Repeat while the result equals the batch size.
2. **With a role of its own, so that the job does not hold the owner credentials** (which can drop the schema): a role that may
   execute the purge and nothing else.

   ```sql
   CREATE ROLE davhaven_retention LOGIN PASSWORD '...';
   GRANT USAGE ON SCHEMA public TO davhaven_retention;
   GRANT EXECUTE ON FUNCTION davhaven_purge_audit(timestamptz, integer) TO davhaven_retention;
   ```

   and `database.migration_url` (or `_file`) of the job's configuration names this role. The role model step leaves it alone
   because it holds no default privileges of the owner, which is how it tells the runtime roles from other roles; a test pins
   that. (A role that holds default privileges of the owner **is** a runtime role to it: give the retention role none.)

The retention worker of the server calls the purge function anyway, and finds that the runtime role may not: the retention port
answers `AuditPurge::NotPermitted` (the plain `purge_audit` removes nothing and returns `0`), and the worker skips the step. That
is **a state of the deployment, not an error**: no unhealthy heartbeat, no error every cycle, the other cleanups are unaffected,
and readiness has nothing to say. The audit table has no foreign key to `tenants`: the records about a deleted tenant outlive
it until retention removes them.

## Tenant isolation

Isolation is enforced twice. Row-level security is a **second line of defence against mistakes in the adapter's own
SQL** (a statement that forgets or mixes up its tenant predicate finds no rows or is refused); it is not a boundary
against code that can run SQL as the runtime role, because that role sets the tenant binding itself
([ADR-0005](../adr/0005-database-role-model-and-system-scope.md), "Threat model").

1. **Row-level security.** Every tenant table has RLS enabled and a policy
   `tenant_id = davhaven_current_tenant()` for reads and writes (`USING` and `WITH CHECK`). The function reads the
   transaction-local setting `davhaven.tenant_id`: it is `NULL` (so nothing matches) when the setting is absent or
   empty, and a malformed value is not a UUID, so the cast fails with `invalid_text_representation` (the statement
   fails closed). A tenant transaction starts with `BEGIN` and `set_config('davhaven.tenant_id', <tenant>, true)`
   (the `true` makes it `SET LOCAL`), so the setting dies with the transaction and a pooled connection never carries
   a tenant over. `tenants` is readable but not writable by tenant transactions; `audit_events` is append-only (see
   above). `SET row_security = off` does not help a bound role: queries fail with `insufficient_privilege` instead.
2. **Composite keys.** Every tenant table has the primary key `(tenant_id, id)` (or a natural key that starts with
   `tenant_id`) and every foreign key is `(tenant_id, x_id)`, so a row cannot reference a row of another tenant even
   when security is bypassed (the owner role, a bug in a migration, a restore). Rows without a parent tenant key on
   purpose (`audit_events`) and rows whose parent is polymorphic (`collection_changes.collection_id` is a calendar or
   a principal) are removed explicitly or through the tenant key.

Every query the adapter issues additionally names the tenant in its `WHERE` clause, so the indexes serve it and a
forgotten predicate would still be caught by the policies. The store contract suite calls every repository method
with a foreign tenant and expects `NotFound` or an empty result; the adapters' own tests fail when a repository
method exists without such a case. Because the suite runs as the bound runtime role, row-level security would hide a
forgotten predicate: the suite's isolation cases also run on a connection of the (unbound) owner role, where the
explicit predicates alone must hold.

### System scope

A few operations cross tenants by nature: creating and listing tenants, finding a credential by prefix before the
tenant is known, claiming outbox records, retention. They run in a *system transaction*, which sets
`davhaven.system = 'on'` instead of a tenant. Only the tables those operations touch carry a second policy, **one
policy per command** (`system_scope_select`, `_insert`, `_update`, `_delete`), and only for the commands they use:

| Tables | Commands in system scope |
| --- | --- |
| `tenants` | all |
| `principals`, `app_passwords`, `feed_tokens` | `SELECT` (credential lookup and the principals due for purging: system scope can read them, never overwrite a hash or a principal) |
| `api_tokens` | `SELECT` (lookup of every kind); `INSERT` and `UPDATE` only for system tokens (`tenant_id` NULL, kind `system`): it cannot mint or change a tenant's or principal's token |
| `calendars`, `principals_sync` | `SELECT`, `UPDATE` (sync epochs, minimum sequence numbers, the calendars due for purging); it cannot create or delete a calendar, which would cascade through every object |
| `collection_changes` | `SELECT`, `INSERT`, `DELETE` (retention logs the expiry of inbox items and prunes the log) |
| `scheduling_inbox`, `rsvp_tokens`, `oauth_states`, `idempotency_keys`, `webhook_deliveries` | `SELECT`, `DELETE` (lookup and retention); it cannot forge inbox items or RSVP links |
| `outbox` | `SELECT`, `UPDATE`, `DELETE` (claim, settle, retention); it cannot enqueue work |
| `audit_events` | `SELECT` (the oldest record of all tenants: one indexed lookup of the cleanup worker, which feeds the gauge that tells you when the purge job stops, [`runbook.md`](runbook.md#retention)) and `INSERT` of the two actions of tenant management, `tenant.created` and `tenant.settings_changed`, into the log of a tenant that exists, and nothing else: a tenant is created and changed in a system transaction, and its audit record commits in that transaction. System scope cannot change or delete an audit record, append any other action or write a record for a tenant that does not exist |

Calendar objects, grants, notifications and the rest are not reachable from system scope, and of the audit log it can read the records and
append the two events above and nothing else. Adding a
table or a command to this list is a security decision; a test pins the list with its commands and proves that every
other table-and-command pair is refused (an `UPDATE` or `DELETE` finds no row, an `INSERT` is refused by row-level
security).

The server's SQL is static (literal statements with bind parameters, or built from the filter's shape with every value
bound), so no request can make it set these settings. If you give someone `psql` access as the runtime role they can set
them and reach every tenant at once, which is why that role is for the server only.

## Migrations

* Files live in `crates/store-postgres/migrations/<YYYYMMDDHHMMSS>_<description>.sql`, are embedded in the binary and
  applied in version order by `davhaven migrate` (or at startup with `database.migrate_on_start = true`; see the
  production recipe above). Migrations are forward-only; there are no down migrations. Concurrent runs are serialised
  by an advisory lock, so starting three replicas with `migrate_on_start` applies each migration once.
* **A migration never queues the application behind it.** The connection that migrates has a `lock_timeout` of 10 seconds
  (`MIGRATION_LOCK_TIMEOUT`). A statement that needs a lock that something else holds (an `ALTER TABLE` on a
  table that a long transaction has read) would otherwise wait for it, and every statement that comes after it, the
  application's queries on that table included, would queue behind the waiting one until the first transaction ends. After 10
  seconds the migration fails with `lock timeout` and a hint, rolls back (each migration is one transaction, so nothing of it is
  applied) and leaves the schema as it was: end the long transaction (`pg_stat_activity` shows it) and **run `davhaven migrate`
  again**. The same limit holds for a second run, or an instance that starts with `migrate_on_start`, that waits for the advisory
  lock of the run that is applying migrations: if those take longer than 10 seconds it fails and is run again (the orchestrator
  restarts the instance).
* **Expand and contract** (R16): every released binary must run on the schema of the next release. A migration that adds
  is shipped with the release that needs it or earlier; a migration that drops or renames ships one release after the
  code stops using the old shape. The same applies to the vocabularies behind `CHECK` constraints (principal and
  calendar kinds, statuses): a new value needs the migration that allows it in one release and the code that writes it
  in the next, with the tolerant read first, because an old binary treats a value it does not know as corrupt data.
  The objects that `role_model.sql` names count as **used by the current binary**: the table `principals` (it finds the
  owner by it), `audit_events`, `_sqlx_migrations`, the functions `davhaven_current_tenant()`, `davhaven_is_system()` and
  `davhaven_purge_audit(timestamptz, integer)`, and the default privileges on functions. Every binary runs that file on every
  `migrate` and every start with `migrate_on_start`, so a release that stops using one of them ships a `role_model.sql` that no
  longer names it before a migration drops or renames it.
* Every migration run ends with the role model of the database (`role_model.sql`, see "What the runtime role may do").
* The runtime ignores migrations it does not know (a newer release already migrated the shared database while old
  instances still serve), and refuses to become ready on a schema older than the **required schema version** of its
  own release (`REQUIRED_SCHEMA_VERSION` in `migrate.rs`). Raise it only in the release that first needs the new
  migration, never in the release that merely ships it.
* An applied migration must never change: the checksum of every applied file is verified on each run, and a changed
  file stops the run. Because a fresh database migrates fine with an edited file, `tests/released_migrations.txt` lists
  the checksum of every migration of a release (a line is added when a release is cut), and a test fails when a listed
  migration was edited or removed. There is no release yet, so the list is empty and the initial migration
  (`20261101120000_initial_schema.sql`) may still change; from the first release on it is frozen. The `schema-compat` job of R16
  (the previous release's contract tests against the new schema) is not in place yet; the upgrade test below is what runs now.

### Rolling upgrade

1. Run `davhaven migrate` of the new release as the owner. The old instances keep serving: the new schema is a
   superset they ignore.
2. Replace the instances one by one. `/readyz` of a new instance is ready once the schema version is at least its
   required version, which it already is.
3. The contract step (a drop or rename) ships in a later release, after no running binary uses the old shape.

### Rules for a new migration

* Every new tenant table: `tenant_id` first, primary key `(tenant_id, id)`, composite foreign keys, `ENABLE ROW LEVEL
  SECURITY` and a `tenant_isolation` policy. Do not `FORCE` row-level security: the owner's cascading deletes rely
  on being exempt. A test fails for a table without both.
* No `DEFAULT now()`, `current_timestamp`, triggers or generated columns: logic-relevant time comes from the `Clock`
  (a test checks the catalog).
* Name unique constraints and add them to `UNIQUE_CONSTRAINTS` in `src/error.rs` with their `UniqueKey`; a test fails
  for a unique index without a key (a violation would otherwise surface as an internal error). An index that guards a
  statement the adapter checks first (`ON CONFLICT`) is listed in the test instead, with the reason.
* Text vocabularies that grow (event types, scopes, iCalendar tokens) get no `CHECK`, state machines do.
* Extend `tests/support/seed.sql` with rows for the new table (the isolation test fails while a table has none) and
  add the table to the system policy list only when a cross-tenant operation needs it, for the commands it needs.
* At the release that ships it, add the fixture of the new schema to `tests/upgrade/` and the migration's checksum to
  `tests/released_migrations.txt` (see below).

## Transactions, locking and errors

* Isolation level is the PostgreSQL default, `READ COMMITTED`. The consistency contract ([ADR-0003](../adr/0003-consistency-contract.md)) does not need more:
  every write to a calendar locks the calendar row (`SELECT ... FOR NO KEY UPDATE`; two calendars in ascending id
  order), checks its preconditions under the lock, advances `sync_seq` exactly once and writes the object and its
  change-log row at that number. The lock is `NO KEY UPDATE` and not `UPDATE` on purpose: inserts that reference the
  calendar (a sharee's binding, a grant, a property) only take a `KEY SHARE` lock for their foreign key check, which
  does not conflict, so they do not queue behind a busy writer. Writers of one calendar queue, writers of other
  calendars and all readers do not wait. Provisioning writes that replace a set (a group's members, a principal's
  addresses) lock the owning principal row the same way, so two reconcile runs of one group queue instead of
  inserting the same rows.
* **Lock the calendar first when it may be deleted.** `BindingRepo::create`, `GrantRepo::create` and
  `PropertyRepo::set` check the calendar with an unlocked read, and the lock of `soft_delete` (`NO KEY UPDATE`) does not
  conflict with the foreign key's `KEY SHARE` of the insert, so a binding written without the calendar lock can commit
  between that check and a concurrent soft delete and survive it. Callers take `CalendarRepo::lock` first (they `touch`
  the calendar after such a change anyway); a locking test shows the soft delete then removes the binding.
* **One transaction per task.** Every open transaction pins a pooled connection, so a task that holds one and waits for a
  second starves the pool as soon as as many requests do the same. Open the transaction late, close it early, never await
  another port while holding it. The in-memory adapter fails fast (`StoreError::Internal`, "nested transaction") instead
  of hanging.
* **Every transaction that succeeded commits**, reads included: read-only and snapshot transactions, the credential lookup
  of every authenticated request, a claim of the outbox that found nothing and a write that found nothing to change. Only
  a transaction that failed or was abandoned (an error answer, a cancelled request, a conflict that is retried, a batch
  upsert with an entry that failed) is dropped and rolled back. The rollback counter of the database
  (`pg_stat_database.xact_rollback`, which rules like `PostgresHighRollbackRate` of a postgres_exporter setup alert on)
  therefore counts failures, not traffic; an answer that refuses after reading (a 404, 403 or 412) may count as one
  (some paths commit their read before they check). `/readyz` runs its few statements outside a transaction and adds
  nothing to it. `crates/it/tests/transactions.rs` drives a representative happy path of each surface and the workers
  through a store wrapper that fails on a transaction that ends without a commit.
* **Reading members together with a sync token.** Read the sync state first and list the members afterwards (a write
  that commits in between is then in the listing *and* after the token, a harmless repeat), or open the transaction with
  `TxMode::Snapshot` (`REPEATABLE READ`, read-only) for one snapshot. The other order loses the write for good.
* Every repository call that writes runs in a savepoint, so a method that returns an error has changed nothing and
  the transaction stays usable (PostgreSQL would otherwise abort it). A dropped transaction rolls back, outbox
  messages and audit records included. Locks a failed write took are released with its savepoint; callers that need a
  lock for a follow-up read take it first with `CalendarRepo::lock`.
* The outbox queue is claimed with `FOR UPDATE SKIP LOCKED`: several dispatchers never get the same record and never
  wait for each other; a claim in a crashed transaction is undone with it. A record is settled (`complete`, `fail`)
  only while it is `in_flight` (`LeaseLost` otherwise), so a dispatcher whose lease expired cannot overwrite what the
  dispatcher that reclaimed the record already settled. A record that was *reclaimed* and is held by another dispatcher
  is in flight again, which the unfenced methods cannot tell apart: dispatchers settle with `complete_claimed`,
  `fail_claimed` and `release_claimed`, which also compare the attempt number and the lease end of their claim.
* An in-flight idempotency key carries a lease (ten minutes by default). The API layer claims with `claim_leased` and
  the request timeout plus a margin, so a process that dies mid-request locks the client's retry out for about a minute,
  not ten; `complete_leased` and `release_leased` compare the lease of the claim, so a slow first request cannot
  overwrite the response of the retry that took the key over (`LeaseLost`), and a request that is cancelled releases
  its key.
* **Time limits**, set on every connection when it opens: `database.statement_timeout` (15 s), `database.lock_timeout`
  (3 s; how long a writer waits for a calendar lock, which bounds how long a queue behind a hot calendar can hold
  pooled connections) and `database.idle_in_transaction_timeout` (30 s; a stalled request task cannot pin a connection
  and its locks). The maintenance operations that legitimately touch every row of a tenant or of the installation
  (deleting a tenant, **soft-deleting a calendar**, purging a principal or a calendar, bumping the sync epoch after a
  restore) run under `database.maintenance_timeout` (10 minutes, `0s` for no limit) instead. A lock wait that expires is
  a `StoreError::Timeout`, which the application may retry like a serialization failure before it answers 503 with
  `Retry-After`.
* **Large writes hold the calendar lock.** A transaction that writes many objects of one calendar (the API's batch
  upsert writes up to 1000 in one transaction, all-or-nothing) holds that calendar's row lock until it commits, and every
  other writer of the calendar (DAV `PUT` and `DELETE`) waits and answers `Timeout` after `lock_timeout`. Keep such
  transactions short: the API layer chunks very large batches into smaller transactions (one `calendar.objects_changed`
  event per chunk), or an operator raises `database.lock_timeout`. The soft delete of a very large calendar holds the lock
  for as long as the update of its objects takes, which is acceptable for a calendar that is being deleted.
* Error mapping: unique violations become typed `UniqueViolation`s, foreign key violations `NotFound`,
  `serialization_failure`/`deadlock_detected` `SerializationFailure` (the caller may retry), `query_canceled`
  (`statement_timeout`), `lock_not_available` (`lock_timeout`), idle-in-transaction timeouts and an exhausted pool
  (`database.acquire_timeout`, 5 s) `Timeout`, connection failures `Unavailable`. Everything unexpected is `Internal`
  and logged without row data.
* Connection settings: `database.max_connections` (default 10), `application_name = davhaven`. The three time limits
  are sent as startup parameters (`options`). State lives in transactions only (`SET LOCAL` semantics), so session
  pooling and statement-level state are not a concern; use a pooler that supports protocol-level prepared statements,
  because the driver prepares statements. PgBouncer rejects unknown startup parameters unless
  `ignore_startup_parameters = options,application_name` (or the limits are set per role with
  `ALTER ROLE davhaven_app SET statement_timeout = ...`, in which case the server's values are the same defaults).

## Change-log and retention facts worth knowing

* Sync tokens are `urn:davhaven:sync:{collection}:{epoch}:{seq}`. `collection_changes` keeps the log; the retention worker prunes rows
  older than the retention period (90 days by default) and raises the collection's minimum sequence, after which
  older tokens answer `valid-sync-token` and clients resync. Pruning, the inbox purge and the other cleanups work in
  batches of 5000 rows per call, so a backlog never holds long locks.
* Quarantined inbox items (rejected or suspicious inbound iTIP) are never shown to clients and therefore neither move
  the inbox's sync token nor appear in its change log.
* Webhook delivery records (one per event and subscription) are removed by retention after their cut-off, like the
  outbox. Creating a delivery for an event that already has one returns the existing record.
* Soft-deleting a calendar removes every binding of it (the owner's and the sharees', so the name can be reused at
  once) and logs the disappearance in each affected home; the calendar itself and its objects wait for the purge
  (30 days by default). The soft delete updates every object row of the calendar in the request's transaction (under
  `database.maintenance_timeout`, not the request's statement timeout: a test with a calendar of twenty thousand objects
  proves which limit applies), so for a calendar with a very large number of objects it takes as long as that update.
* Purging a principal (or a calendar) removes its calendars from the feed tokens of other principals (a grantee's
  feed token names calendars of other owners in an array without foreign keys), so no feed names a calendar that is gone.
* `principals.search` scans the tenant's principals (lower-casing the name, display name and addresses): its cost grows
  with the principals of the tenant. The application's minimum query length and rate limits are the guard; there is no
  trigram index.
* After restoring a backup run the `admin bump-sync-epoch` command: it gives every collection a new epoch, which
  invalidates every outstanding sync token, so clients that synced beyond the restored point do not miss changes. The
  procedure is in [`backup.md`](backup.md).

## Tests

`cargo nextest run -p davhaven-store-postgres` needs a PostgreSQL server on which `DATABASE_URL` is a superuser (CI
starts one; locally `docker run --rm -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:18 -c fsync=off` and
`DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres`). **Without it the tests fail**, in CI and
everywhere else, so a run that tested nothing never looks green; `DAVHAVEN_ALLOW_NO_DB=1` (outside CI) skips them
explicitly and says so. The tests create two roles named `davhaven_owner` and `davhaven_app` (password equal to the
name) and databases named `davhaven_t_*`, `davhaven_e_*` and `davhaven_tpl_*`: point `DATABASE_URL` at a throw-away
server, never at one that holds data you care about. Two guards back that up: the tests refuse a remote server unless the
run says it is disposable (`DAVHAVEN_TEST_DB_THROWAWAY=1`, `CI`, or a database named `davhaven_*`, the name shared build
hosts give to the one database of a workspace), and they refuse to take over an existing `davhaven_owner` that they
did not create and that owns a real database.

The tests create the two roles and reproduce the provisioning above, build the migrated schema once into a template
database (keyed by the checksums of the embedded migrations and the provisioning statements, built under a cluster-wide
lock so that parallel test binaries agree) and clone it for every test; clones are dropped when the test ends (a test
process that was killed leaves its databases behind). All store tests connect as the runtime role, so row-level
security applies to everything they do. The contract databases carry the opt-in grant for the audit purge, because
the retention cases run through the server's own role; the `rls` tests use databases without it.

Roles and the names of databases belong to the cluster, while the test runs of a shared host (one database each) share the two
test roles, want the same template and could drop each other's databases, and an advisory lock belongs to the database it is
taken in. Every lock of the provisioning (the template, the clones, the roles) is therefore taken in the maintenance database
`postgres`, where every run meets. A run never writes roles that are in order (every update of a role is an update of a catalog
row, and two processes that update the same row at the same time fail with `tuple concurrently updated`), and it tries again when
it still meets a run that writes them without knowing the lock. The names of the databases of a run carry a random text and no
process id, which repeats between the containers of a host. The harness of `davhaven-testkit` follows the same rules, and a
test there compares its copy of the statements and the lock keys with the support code of the store tests.

| Test binary | What it proves |
| --- | --- |
| `contract` | the store contract suite of `davhaven-port-tests` (one test per case, the same cases the memory adapter passes) against PostgreSQL |
| `rls` | RLS and a policy on every table, rows of every table visible only to their tenant, foreign writes refused, the system-scope policies with their commands, tenant context never outliving its transaction, composite keys, the append-only audit log and the purge function nobody but the owner may call, the runtime role's privileges (no `TRUNCATE`, what a blanket grant or a global default privilege leaves it) and what it cannot change, the provisioning printed on this page |
| `migrations` | idempotent and concurrent migration runs, the runtime role cannot migrate (and the error says to use `migration_url`), a changed migration is refused (by its checksum) and released ones never change, a newer schema is tolerated, readiness follows the schema version, the role posture (`BYPASSRLS` roles, members of the owner and of bypass roles, a schema that is not `public`, a runtime role that can execute the audit purge) and the audit retention state, the audit purge revoked from the runtime role however it came by it, the role model applied after every migration run (also when none is pending), the three time limits, the maintenance timeout of a large soft delete, production refusing an unbound role and an unencrypted remote connection, the plugin, event types of a newer release surviving an update, constraint names against `UniqueKey`s, no database clock |
| `locking` | per-calendar write locks (proven from a second connection, without waiting), bindings not queuing behind a writer, lock order of crossing moves (no deadlock), provisioning writes locking their group, `SKIP LOCKED` claims and their rollback, the order of a listing and its sync token with a writer in between (and `TxMode::Snapshot`), a binding created under the calendar lock not surviving the soft delete |
| `roles` | the setup of the test roles: the failure of two updates of one role (made deterministically, on a role of the run alone) is the one the setup recognises and tries again, roles that are in order are not written (their catalog rows keep their versions), the locks of the provisioning are taken in the maintenance database and end with their session, and the databases of a run are named with its random text |
| `upgrade` | the upgrade test described next, a made-up later migration applied over the fixture data, and the restore of a plain-format dump as the owner role followed by `migrate` and a production start ([backup.md](backup.md#this-procedure-is-tested)) |

### The upgrade test

`tests/upgrade/<version>.sql` holds the *standard dataset* (a tenant with principals, a group, calendars, objects,
a change log, credentials, an outbox message and an audit record, described in the file header) written with plain
`INSERT`s against the schema of the release whose newest migration is `<version>`. For every fixture the test applies
the migrations up to `<version>`, loads the fixture, applies all later migrations, reads every fact of the dataset back
through the repositories as the runtime role and then writes on top (sequence numbers and sync tokens continue where
the old data left off). A second test makes up one later migration (a nullable column) so the "apply what came later"
step is exercised before the first real one exists.

A migration PR therefore proves that the data of the previous release is still read correctly. When a release is cut,
add one file: the standard dataset in the schema of that release, and the release's migration checksums in
`tests/released_migrations.txt`. Once a release has shipped, its fixture is never edited. Today there is one fixture, for the
initial schema, so the made-up migration is what exercises the "apply all later migrations" step.
