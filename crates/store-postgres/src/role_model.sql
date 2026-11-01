-- The role model of docs/operations/database.md, applied to every runtime role of the owner of the tables.
--
-- `davhaven migrate` runs this after the migrations, every time, whether or not one was pending. The initial
-- migration applies the same revocations once; they are not part of the schema a dump carries. A database restored with
-- `pg_restore --no-owner --role=<owner>` gets its tables from the default privileges of the owner first (read and write
-- on every table, which includes UPDATE and DELETE on audit_events and writes to the migration history), and the dump's
-- own GRANT statements only add to that. Without this step the restored database would hold privileges that the
-- posture check refuses in production.
--
-- The runtime roles are found through the default privileges of the role that owns the tables (`pg_default_acl`), so no
-- role name is baked in. The owner is the owner of `public.principals`, which is not necessarily the role that runs
-- this: a migration role that is a member of a NOLOGIN owner role acts for it, and the default privileges belong to the
-- owner. A role that holds no default privileges of the owner is not a runtime role and is left alone: a dedicated role
-- that may run the audit purge (docs/operations/database.md) is one.
--
-- Every statement is idempotent: it takes away what must not be there, or grants what must be. The objects it names
-- are looked up first, so a database that lacks one of them (an older schema) is not an error. The number of runtime
-- roles it found is left in the transaction setting `davhaven.role_model_roles`, which the caller reads.
--
-- The objects named here count as used by the current binary (ENGINEERING_RULES R16, docs/operations/database.md,
-- "Schema compatibility"): a release that stops using one of them ships a version of this file that no longer names it
-- before a migration drops it.
DO $roles$
DECLARE
    owner_oid oid := (SELECT c.relowner FROM pg_class c WHERE c.oid = to_regclass('public.principals'));
    owner_name name;
    grantee name;
    touched integer := 0;
BEGIN
    IF owner_oid IS NOT NULL THEN
        owner_name := (SELECT r.rolname FROM pg_roles r WHERE r.oid = owner_oid);
        -- The purge is for the owner only (a role that can call it can erase the audit trail of every tenant). The
        -- initial migration took it from PUBLIC; a restore or a blanket GRANT may have given it back.
        IF to_regprocedure('public.davhaven_purge_audit(timestamptz, integer)') IS NOT NULL THEN
            REVOKE ALL ON FUNCTION public.davhaven_purge_audit(timestamptz, integer) FROM PUBLIC;
        END IF;
        FOR grantee IN
            SELECT DISTINCT r.rolname
            FROM pg_default_acl d
            CROSS JOIN LATERAL aclexplode(d.defaclacl) a
            JOIN pg_roles r ON r.oid = a.grantee
            WHERE d.defaclrole = owner_oid
              AND d.defaclobjtype = 'r'
              AND a.grantee <> owner_oid
        LOOP
            touched := touched + 1;
            -- TRUNCATE bypasses row-level security, and REFERENCES and TRIGGER have no use at runtime: the runtime role
            -- reads and writes rows, nothing more (a blanket GRANT ALL by an operator is undone here).
            EXECUTE format('REVOKE TRUNCATE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA public FROM %I', grantee);
            -- Append-only audit log.
            IF to_regclass('public.audit_events') IS NOT NULL THEN
                EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON public.audit_events FROM %I', grantee);
            END IF;
            -- The migration history belongs to the migration role; the runtime role may only read it (readiness).
            IF to_regclass('public._sqlx_migrations') IS NOT NULL THEN
                EXECUTE format('REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public._sqlx_migrations FROM %I', grantee);
            END IF;
            -- The row-level security helpers: the only functions the runtime role calls.
            IF to_regprocedure('public.davhaven_current_tenant()') IS NOT NULL THEN
                EXECUTE format('GRANT EXECUTE ON FUNCTION public.davhaven_current_tenant() TO %I', grantee);
            END IF;
            IF to_regprocedure('public.davhaven_is_system()') IS NOT NULL THEN
                EXECUTE format('GRANT EXECUTE ON FUNCTION public.davhaven_is_system() TO %I', grantee);
            END IF;
            IF to_regprocedure('public.davhaven_purge_audit(timestamptz, integer)') IS NOT NULL THEN
                EXECUTE format(
                    'REVOKE ALL ON FUNCTION public.davhaven_purge_audit(timestamptz, integer) FROM %I CASCADE', grantee);
            END IF;
            -- A function that a later migration creates is not executable by the runtime role unless that migration
            -- (and this file) grants it, whatever the owner's default privileges on functions say: a new function that
            -- runs with the owner's rights must not be a way past the privileges of the runtime role by default.
            EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I REVOKE EXECUTE ON FUNCTIONS FROM %I', owner_name, grantee);
            EXECUTE format(
                'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM %I',
                owner_name, grantee);
        END LOOP;
    END IF;
    PERFORM set_config('davhaven.role_model_roles', touched::text, true);
END
$roles$;
