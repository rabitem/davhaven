# Backup and restore

Davhaven keeps its state in one PostgreSQL database and its secrets in the key files of the deployment. This page says what to
back up, how to restore, and the three things a restored instance needs that a plain database restore does not give it (the role-model step of `davhaven migrate`, the
key files and a new sync epoch). Roles, migrations and the schema are in [`database.md`](database.md), the keys in [`keys.md`](keys.md),
the commands in the [runbook](runbook.md).

## What to back up

| What | Where it lives | How | Notes |
| --- | --- | --- | --- |
| The database | PostgreSQL | `pg_dump --format=custom` of the whole database, or a physical base backup with continuous WAL archiving | Everything: tenants, calendars, objects with their client bytes, credentials (as keyed hashes), the outbox, the audit log |
| The key files | The deployment's secret store | A copy in a second secret store | **Not** in the same backup as the database. A restore without the keys has no working credential and no openable webhook secret ([`keys.md`](keys.md)) |
| The configuration | Your deployment repository | Version control | Contains no secrets: they are files named by `*_file` keys |
| The image | GHCR | Nothing to do | Addressed by digest. Release tags are kept for ever; other builds are pruned by the retention workflow ([Image retention](runbook.md#image-retention)) |

Not worth backing up: logs and metrics (they are for operating, not for restoring), the in-memory rate limiter and the credential
cache (they refill), and anything inside the container (it is stateless).

The tool you choose decides the **recovery point objective**: a nightly `pg_dump` loses up to a day of changes; WAL archiving with
point-in-time recovery loses seconds. Calendar data changes continuously and clients cache it, so decide what a day of lost
changes means for your users before choosing the nightly dump.

## Restoring

Restore into a **new** database created with the production recipe of [`database.md`](database.md#provisioning) (the roles, the schema
ownership and the default privileges), not into a database that already holds data.

1. **Create the database and the roles** with the provisioning statements; the default privileges must exist *before* the restore
   so that the restored tables are usable by the runtime role without a grant step.
2. **Restore as the owner role**: `pg_restore --no-owner --role=davhaven_owner --dbname=davhaven backup.dump` (for a physical
   backup, recover and promote the cluster). `--role` makes the owner role the owner of every restored table. Restoring as a
   superuser without it makes the superuser the owner of every table, and the owner role of the deployment, which owns nothing,
   cannot migrate them: `davhaven migrate` fails, whether or not a migration is pending (with one, the owner cannot alter the
   tables; without one, the role model step finds that the role does not own the tables, and the command refuses to report a success
   that did not put the privileges right).
3. **Migrate**: `davhaven migrate` with the owner credentials. A backup taken by an earlier version is brought up to the schema of
   the binary you are about to run. **Run it even when the schema is current**: it ends with the role model step
   ([`database.md`](database.md#what-the-runtime-role-may-do)), and a restore needs that step. The restored tables were created
   with the default privileges of the owner (read and write on every table, which includes `UPDATE` and `DELETE` on the audit
   log and writes to the migration history), and the grants inside the dump only add to them, so the runtime role of a restored
   database holds privileges that the role model withholds until the step has run. A production server refuses to start on that
   ("the database role holds privileges the runtime role must not have: DELETE on audit_events, ..."), and the step is what takes
   them away again.
4. **Mount the keys** the backup's data was made with (every key that is still referenced, [`keys.md`](keys.md)), and run
   `davhaven config check`.
5. **Invalidate the sync tokens**: `davhaven admin bump-sync-epoch --all` (below). This step is not optional.
6. **Decide about the outbox** (below), then start the instance and watch `/readyz`.
7. After a restore onto a host with a different C library, run `REINDEX DATABASE davhaven` as the owner ([`database.md`](database.md)).

### Why the sync epoch has to change

A sync token is `urn:davhaven:sync:{collection}:{epoch}:{seq}`: the sequence number counts the changes of a calendar. After a
restore the calendar is back at the sequence of the backup, but clients hold tokens from after it. While the server is still
behind such a token it refuses it, and the client resyncs; but once new changes have advanced the sequence past the number in the
old token, that token is valid again and means something else: the numbers between the backup and the old token now belong to
different changes, and the client would skip them and never see them. A new epoch makes every outstanding token stale at once, so
every client does one full resync and sees exactly the restored calendar. `admin bump-sync-epoch --all` does that for every collection of every tenant
(`--tenant <slug>` for one tenant), in a system transaction, and prints how many collections it changed. Run it **before** the
instance serves requests; it needs only the database.

### What happens to the outbox

The outbox is part of the database, so a restore brings back its state as of the backup:

* **Messages that were pending at the backup and were sent afterwards** are pending again and will be sent again: invitation
  mails and webhooks can be delivered twice. Receivers of webhooks are told to deduplicate on the event id; people are not.
* **Messages created after the backup** are gone together with the changes that caused them.

If a duplicate mail is worse than a missing one, start the first instance with `plugins.mail_transport` pointing at a sink (or
`mail.redirect_all_to`) so that it drains the old messages harmlessly, then switch to the real settings. With the owner role you
can also mark the pending mail as dead before the first start, which keeps the records for inspection (and for the retry call of
the management API) and sends nothing:

```sql
UPDATE outbox SET status = 'dead', last_error = 'dropped after restore', updated_at = now()
 WHERE status IN ('pending', 'in_flight') AND kind = 'imip';
```

### What is not restored, and why it is fine

* **Credentials** are in the database as keyed hashes; they verify again as soon as the keys are mounted. Nothing needs re-issuing.
* **RSVP links** in mails already sent verify against their stored hashes. Links minted after the backup point do not exist
  any more; their invitations are gone with them.
* **Idempotency keys** (24 hours) and **OAuth states** (a day) are short-lived and harmless.
* **The audit log** is restored as of the backup; records written after it are lost with everything else.

### This procedure is tested

`crates/store-postgres/tests/upgrade.rs` replays a dump of a database the way the procedure above has it, but it is an
equivalent replay and not the tools themselves: the dump is a plain-format `pg_dump --no-owner --inserts` file
(`tests/restore/<schema version>.sql`, with the standard dataset in it), which the test runs through the SQL driver after `SET ROLE
<owner>`, and that is what `pg_restore --no-owner --role=<owner>` does for the owner of the restored objects. Only the psql
meta-commands of the dump and one setting that older servers do not know were removed from it. The test then checks the privileges the
restore leaves, runs `migrate` over it, starts the database plugin in production mode on it (the plugin that `serve` builds, not the
binary), reads the data back and writes on top of it; and it restores the same dump as the superuser, without the role, to show that
`migrate` then refuses. What it does not run is `pg_restore` on a custom-format archive, whose ordering of grants and default
privileges differs from a plain dump: the restore test below is where that gets exercised. A version that changes the schema adds a
dump of its own (see the header of the existing one); a dump is never edited otherwise.

## Test the restore

A backup that has never been restored is a hope. Once a quarter, and after every change of the backup method:

1. Restore the latest backup into a scratch database as above.
2. Start an instance against it **on staging**, with `mail.redirect_all_to` set (or the memory mail transport in `dev` mode) so that
   the restored outbox cannot mail real people, on a different `server.public_base_url`.
3. Check `/readyz`, log in as a test principal with an app password, read a calendar over DAV and list it through the API.
4. Note how long it took: that is your recovery time.

## Backups and the right to be forgotten

A principal is removed from the database after `retention.principal_purge_days` (30), and deleted calendars after
`retention.deleted_calendar_days`; backups keep what was in the database when they were taken. Your backup retention period is
therefore the real upper bound of how long deleted data survives, and an erasure request is answered with that period. Keep the
period as short as your recovery needs allow, and after restoring a backup **re-apply the erasure requests received since it was
taken** through the management API: a principal that was deleted after the backup point is active again in the restored data.
