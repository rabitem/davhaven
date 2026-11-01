# ADR-0005: Database role model, system scope and the audit purge

- Status: accepted
- Date: 2026-10-25
- Scope: PLAN 2.4 and 2.18, R4 and R16

## Context

PLAN 2.4 states the isolation design in one paragraph: every tenant table has one RLS policy that compares `tenant_id`
with `davhaven.tenant_id`, the runtime role is `NOBYPASSRLS` with DML only, migrations use a separate owner role, and
`audit_events` is INSERT/SELECT only for the runtime role. Implementing it in `davhaven-store-postgres` met four things the paragraph does
not settle: operations that cross tenants (tenant management, credential lookup before the tenant is known, the outbox
queue, retention), what "owner" means for row-level security, how audit records are ever deleted if the runtime role may
not delete them, and what happens when an operator runs a single role for everything. This ADR records the decisions;
[ADR-0006](0006-store-contract-amendments.md) lists where the plan text differs from what was built.

## Threat model

Row-level security here is a **second line of defence against mistakes in this adapter's own SQL**: a statement that
forgets its tenant predicate, or names the wrong one, finds no rows (or is refused) instead of reading or writing another
tenant's data. It is *not* a boundary against code that can run arbitrary SQL as the runtime role. The tenant binding
is a transaction-local setting (`davhaven.tenant_id`) that the runtime role sets itself at `begin`, so anything that
can execute statements as that role (an injected sub-select that calls `set_config`, a compromised server process, a
shell with the role's password) can name any tenant. What the design defends, and what it does not:

| Threat | Defended | By |
| --- | --- | --- |
| A bug in an adapter query that omits or mixes up the tenant predicate | yes | RLS policies, composite foreign keys, the contract suite's foreign-tenant cases (also run as the unbound owner) |
| A reference to a row of another tenant inserted through a bug | yes | composite foreign keys `(tenant_id, x_id)` |
| Operators who run migrations and serving with one owner role | yes, in production | the startup refusal (decision 2) |
| A compromised server process using **system scope** | partly | system policies admit only the commands the cross-tenant operations use (decision 3): it cannot overwrite a credential hash or a principal, mint or change tenant and principal tokens, create or delete calendars, forge outbox work, inbox items or RSVP links, truncate, rewrite the migration history, or change or delete the audit trail (it appends the two records of tenant management and reads the log) |
| A compromised server process using **tenant scope** for any tenant | no | it can do everything the application can do for that tenant, including credentials and principals of any tenant it names |
| Anyone with the runtime role's password | no | that role belongs to the server alone |

Hardening that would raise the bar (future work, not decided here): a per-tenant `SET LOCAL ROLE` so the binding is a
database privilege, or a `SECURITY DEFINER` binding function that verifies an HMAC of the tenant id issued by the
application.

## Decision

1. **Two login roles.** The *owner* owns the schema, runs migrations and is not bound by row-level security: a table
   owner is exempt unless the table is `FORCE`d, and `ON DELETE CASCADE` (deleting a tenant, purging a principal) runs
   with the owner's rights and relies on that exemption, so tables are never `FORCE`d. The *runtime* role owns
   nothing, is `NOSUPERUSER NOBYPASSRLS`, has data access through the owner's default privileges and nothing else:
   no `TRUNCATE` (it bypasses row-level security), no `REFERENCES`, no `TRIGGER`, no `CREATE`, no writes to the
   migration history, no `UPDATE`/`DELETE` on the audit log. The migration finds the runtime role through the
   owner's default privileges (`pg_default_acl`), so it bakes in no role name and undoes a blanket `GRANT ALL`.

2. **The server refuses an unbound role in production.** The plugin examines the connected role at startup and on
   every readiness probe (superuser, `BYPASSRLS`, owner of the tables, or a member of such a role, directly or
   through other roles, since it can `SET ROLE` to it; privileges beyond the role model; a posture query that fails,
   a connection whose current schema is not `public` and tables that are not where the check looks all count as
   findings). In `server.mode = "production"` any such finding fails startup with an error that names the role and the
   documentation, unless `database.allow_unbound_role = true` accepts the risk explicitly; in `dev` mode it is logged,
   and readiness reports the database degraded either way. The single-URL setup that migrates and serves with the
   owner is therefore not available by accident. The production recipe is `database.migrate_on_start = false` plus a
   separate `davhaven migrate` job with the owner credentials. The same rule covers the transport: production refuses
   a connection to a remote host without TLS (`sslmode` other than `require`, `verify-ca` or `verify-full`) unless
   `database.allow_insecure_transport = true`.

3. **System scope is a second policy on the tables the cross-tenant operations touch, one policy per command.** A
   *system transaction* sets `davhaven.system = 'on'` (transaction-local) instead of a tenant. The policies
   `system_scope*` admit it on 15 tables, **only for the commands `repos/system.rs` runs**:

   | Table | Commands in system scope |
   | --- | --- |
   | `tenants` | all (tenant management) |
   | `principals`, `app_passwords`, `feed_tokens` | `SELECT` (credential lookup, the principals due for purging) |
   | `api_tokens` | `SELECT` (lookup of every kind); `INSERT` and `UPDATE` only for system tokens (`tenant_id` NULL, kind `system`) |
   | `calendars`, `principals_sync` | `SELECT`, `UPDATE` (sync epochs, minimum sequence numbers, the calendars due for purging) |
   | `collection_changes` | `SELECT`, `INSERT`, `DELETE` (retention logs expired inbox items and prunes the log) |
   | `scheduling_inbox` | `SELECT`, `DELETE` (retention) |
   | `outbox` | `SELECT`, `UPDATE`, `DELETE` (claim, settle, retention); no `INSERT` |
   | `rsvp_tokens`, `oauth_states`, `idempotency_keys`, `webhook_deliveries` | `SELECT`, `DELETE` (lookup and retention) |
   | `audit_events` | `SELECT` (the oldest record, for the monitoring of the purge job); `INSERT` of the actions `tenant.created` and `tenant.settings_changed` only, for an existing tenant; no `UPDATE` or `DELETE` |

   Calendar objects, grants and notifications are unreachable from system scope, and of the audit log it reads the records and appends
   the two events of tenant management, nothing else. The list and the
   commands are pinned by a test, and the test proves that every other table-and-command pair is refused (an `UPDATE`
   or `DELETE` finds no row, an `INSERT` is refused by row-level security); changing them is a security decision.
   Anyone who can run arbitrary SQL as the runtime role can set the setting (see the threat model), which is why that
   role belongs to the server alone.

4. **The audit log is append-only, and the purge is not granted to the runtime role.** Retention must still delete
   old records (PLAN 2.18), so the migration provides `davhaven_purge_audit(cutoff, max_rows)` as `SECURITY DEFINER`
   (owner rights, `search_path = pg_catalog, pg_temp`, `PUBLIC` revoked). It is **not** granted to the runtime role:
   a role that can call it can erase every tenant's trail with one statement, whatever floor a function enforces
   (a floor based on `now()` is the caller's to move, a floor based on stored data is arbitrary). Retention runs as the
   owner on a schedule (`davhaven admin purge-audit`, which the server crate wires to `migrate::purge_audit` of the
   storage adapter, runs it with the `migration_url` credentials, or with the credentials of a role that holds this
   function and nothing else). The missing grant is a **state of the deployment, not an error**: the retention port
   reports it as `AuditPurge::NotPermitted` (the plain `purge_audit` removes nothing and returns `0`) and a retention
   worker skips the step without an unhealthy heartbeat.

5. **PostgreSQL 15 or newer and a Unicode-aware `LC_CTYPE` for searches.** The schema uses `ON DELETE SET NULL
   (column)`; the adapter checks `server_version_num` before migrating and when it connects, and names the minimum.
   Display-name searches (`principals.search`, the calendar list's text filter) lowercase with the database locale; the
   adapter checks that `lower` folds non-ASCII text and reports readiness degraded otherwise, because the in-memory
   adapter folds with Rust's Unicode tables. The unique indexes on addresses and login domains do not depend on the
   locale: the domain types normalise those values to ASCII before they reach the database.

6. **Schema details beyond the PLAN 2.4 table**, each there for a reason the plan did not anticipate (the schema is
   `crates/store-postgres/migrations/20261101120000_initial_schema.sql`):
   `calendar_objects.live` (false while the calendar is soft-deleted, so such objects neither occupy scheduling UIDs nor
   resolve by id); `principal_addresses.is_primary` (`primary` is reserved) with a partial unique index; per-collection
   `min_seq` and `epoch` in `principals_sync`; `collection_changes` without a foreign key on `collection_id` (a calendar
   or a principal; removed explicitly); `audit_events` without a tenant foreign key (the record of a deleted tenant
   outlives it until retention removes it); a unique `(tenant_id, principal_id, uri)` on `scheduling_inbox`;
   `idempotency_keys.lease_until` (an in-flight key whose claimant died is taken over after its lease);
   `webhook_deliveries` unique per `(tenant_id, subscription_id, event_id)` and an index for retention; extra unique
   keys that only serve as composite foreign-key targets; and checks that tie `api_tokens.kind` to `tenant_id` and
   `principal_id`. Two deviations from rule R4 and the "rules for a new migration" are deliberate and documented in the
   SQL: `api_tokens` has the single-column primary key `(id)` (a system token has no tenant, so `tenant_id` is nullable
   and cannot be part of a primary key; the unique `(tenant_id, id)` serves as the composite foreign-key target), and
   `feed_tokens.calendar_ids` is a `uuid[]` without foreign keys (a feed names several calendars; the purge of a
   calendar or of a principal removes the dangling ids explicitly, and a test pins it).

## Details of the decisions

**System scope appends two audit events, for a tenant that exists.** `audit_events` admits `INSERT` from system scope, and
only the actions `tenant.created` and `tenant.settings_changed`. A tenant is created and changed in a system transaction, and
its audit record has to commit and roll back with the change: written in a second transaction it could be lost on its own
(the change durable, the record not), because the table admits rows only inside a transaction of their tenant.
`SystemTenantRepo::append_audit` (a port method that defaults to `Unsupported`) writes it in the transaction of the change.
It takes `NewTenantAudit` with `TenantAudit::{Created, SettingsChanged}`, so the signature carries the two events and a store
never has to refuse anything else at runtime. The policy also requires the tenant row: the audit log has no foreign key to
`tenants` (see decision 6), so without the check a compromised server in system scope could append `tenant.created` to a
tenant that never existed. The hash of the client address in those two records is bound to the tenant of the log, as for every
other record; a system token has no tenant of its own, and the same operator address would otherwise have one hash in the log
of every tenant.

**The purge is revoked from the runtime role explicitly, and a runtime role that holds it is a finding.** The initial schema
revokes `EXECUTE` on `davhaven_purge_audit` from `PUBLIC`. A runtime role could still hold it through default privileges on
functions or a blanket `GRANT`, so the role model (`role_model.sql`, applied as described next) revokes it from every runtime
role on every migration run. The posture check lists `EXECUTE on davhaven_purge_audit(timestamptz, integer)` among the
privileges the runtime role must not have: a security finding, which degrades readiness and which production refuses at
startup unless `database.allow_unbound_role` accepts the risk. It also lists every other `SECURITY DEFINER` function in
`public` that the runtime role can execute. The server never purges the audit log and there is no setting for it. Retention is
a job outside the server (`davhaven admin purge-audit`, with the owner credentials or those of a role of its own), so the
default configuration with the role model is healthy and there is nothing to acknowledge. There is no narrower switch for
"let the server purge": a deployment that wants that accepts every finding with `allow_unbound_role`, which the option says in
its documentation. The retention worker still asks the store and skips the step on `AuditPurge::NotPermitted`.

**The role model is applied after every migration run, not only by the initial migration.** A database restored with
`pg_restore --no-owner --role=<owner>` gets its tables from the default privileges of the owner first, and the privileges of
the dump add to them, so without a corrective step the runtime role of a restored database would hold `UPDATE` and `DELETE` on
the audit log and writes to the migration history. `migrate::run_on` (`davhaven migrate`, `migrate_on_start`) therefore ends
with the revocations and grants of `role_model.sql` for every runtime role of the owner of the tables. The step is idempotent
and serialised by an advisory lock. It finds the runtime roles through the default privileges of the owner of
`public.principals` (not of the connected role, which can be a member of a `NOLOGIN` owner role, as on managed PostgreSQL),
reports how many roles it found (`MigrationReport::role_model`; `davhaven migrate` prints it, warns when it is none and fails
when the connected role does not own the tables at all), looks every object up before it touches it, revokes with `CASCADE`,
and takes the default privilege on functions away from the runtime roles: a function that a later migration creates is not
executable by them unless that migration grants it. A role that holds no default privileges of the owner is not a runtime role
to the step and keeps its grant, which is what makes a dedicated retention role a supported way to run the purge without the
owner credentials. The restore is tested (`tests/upgrade.rs`, `tests/restore/`).

**A signal for the audit purge.** Because the purge runs outside the server, nothing in the server would notice that the job
stopped. The cleanup worker therefore publishes two gauges for an alert (`davhaven_audit_oldest_event_timestamp_seconds` and
`davhaven_audit_retention_seconds`, see `docs/operations/runbook.md`), which needs `SELECT` on `audit_events` in system scope.
The oldest audit event of all tenants is one statement, `SELECT at FROM audit_events ORDER BY at LIMIT 1`, which the index
`audit_events_at_idx` that serves the purge can answer (the plan test turns sequential scans off, so it pins what the index
offers, not what the planner picks on every size of table). It crosses tenants, which only a system transaction does. The
policy `system_scope_select` (`davhaven_is_system()`) is one command like every other system policy; `UPDATE` and `DELETE`
stay refused and the insert stays limited to the two events of tenant management. One test pins the command in the list of
system policies, and a second proves that the statement is answered across tenants and by the index, and that a tenant
transaction and a transaction without a scope do not get the same answer.

- **Why a policy and not a function.** A `SECURITY DEFINER` function that returns the minimum would reveal less, but it would be
  a function the runtime role may execute with the owner's rights, which is what the posture check reports as a security
  finding (decision 2) and what the role model takes away from the runtime role on every run. A policy is the mechanism of
  every other cross-tenant operation, its reach is visible in the catalog, and a test pins it.
- **What it costs.** Nothing that the threat model did not already give away: a compromised server sets the tenant of a
  transaction itself and so reads the audit log of every tenant it names through tenant scope. System scope still cannot change
  or delete a record or append anything but the two events, so the log stays append-only for the server.
- **The policy is broader than the signal needs.** `system_scope_select` admits every row and every column of `audit_events`
  in system scope (actors, targets and details included), where the statement reads the time of one row. A policy cannot say
  "the oldest row" (a policy that selects it by a subquery on its own table is refused by PostgreSQL as infinitely recursive),
  and the only narrower mechanism is the `SECURITY DEFINER` function rejected above. It is accepted because the application's
  own system code never reads more (the list of system policies and their commands is pinned by a test, so a wider use is a
  reviewed change), and because a compromised server could read the same rows through tenant scope, naming each tenant.
- **The gauge of an emptied log.** The worker sets the oldest-event gauge only when there is an event. A log that is emptied
  while the server runs sets it to `NaN`, because a gauge cannot be taken back and its last value would go stale (see the
  rustdoc of `AUDIT_OLDEST_EVENT_TIMESTAMP_SECONDS`).

## Consequences

- Row-level security catches a query that forgets or mismatches the tenant predicate, and the composite keys keep
  references inside the tenant, so one adapter bug does not become a cross-tenant leak. It does not make the
  application untrusted: see the threat model for what a compromised server can and cannot do.
- In system scope a compromised server cannot overwrite a credential hash or a principal, mint or alter tenant or
  principal tokens, create or delete calendars, forge outbox work, inbox items or RSVP links, truncate a table, rewrite
  the migration history, or change or delete the audit trail (it appends the two records of tenant management and reads the log, as
  tenant scope lets it for any tenant it names; it appends no other). Through tenant scope it can do what the application can do for any tenant it names.
- Operators carry two jobs the zero-configuration setup hid: a migrate job with its own secret, and audit retention
  (a scheduled `davhaven admin purge-audit` with the owner credentials or those of a role of its own; the grant of the purge to the
  runtime role is a finding of the posture check, not a setup). The exit status of the job and the two gauges above are what
  to alert on.
- Adding a tenant table, a system policy or a privilege is reviewed against this ADR; the tests pin the policy list
  with its commands, the privilege matrix and the posture findings.

## Alternatives considered

- **A second runtime role with `BYPASSRLS` for system transactions**: rejected; it doubles the credentials the
  server holds and a bypass role reaches every table, while the second policy is scoped to 15 tables and their
  commands and a test pins it.
- **`FORCE ROW LEVEL SECURITY`**: rejected; the owner's cascading deletes and migrations would need their own
  policies, and the owner is not part of the serving process in the production recipe anyway.
- **Retention through a function the runtime role may call, with a minimum age**: rejected; a compromised server wipes
  everything older than the floor, and the floor protects nothing the operator cannot do better with a schedule.
- **Warn-only for an unbound role or an unencrypted remote connection in production**: rejected; the
  zero-configuration path is exactly that, and a warning in a log nobody reads is how the protection silently
  disappears.
- **Treating a missing audit-purge grant as an error of the retention worker**: rejected; it is a configuration state,
  and an error every tick hides real failures. It is a typed outcome and a readiness finding instead.
