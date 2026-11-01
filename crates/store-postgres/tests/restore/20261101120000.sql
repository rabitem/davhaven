-- Restore fixture: a plain-format `pg_dump` of the database of the release whose newest migration is 20261101120000,
-- with the standard dataset of tests/upgrade/20261101120000.sql in it.
--
-- tests/upgrade.rs restores it the way docs/operations/backup.md says (as the owner role, without the owner of the
-- dump: `--no-owner` at dump time, `SET ROLE` at restore time, which is what `pg_restore --no-owner --role=<owner>`
-- does), runs the migrations of the current release over it and starts the server on it in production mode.
--
-- Made with PostgreSQL 18 on a database provisioned like docs/operations/database.md says (the roles and the default
-- privileges), whose schema was made by `davhaven migrate`, whose `_sqlx_migrations` row carries the checksum of
-- that migration, and whose rows are the upgrade fixture:
--
--   pg_dump --format=plain --no-owner --inserts <database>
--
-- Edited after the dump, and only so: the psql meta-commands (a backslash `restrict` and `unrestrict` line, which newer
-- pg_dump versions write and which are not SQL) and `SET transaction_timeout` (only PostgreSQL 17 and newer know it)
-- were removed. A fixture is never edited otherwise; a release that changes the schema adds a file of its own.
--
--
-- PostgreSQL database dump
--


-- Dumped from database version 18.6 (Debian 18.6-1.pgdg13+2)
-- Dumped by pg_dump version 18.6 (Debian 18.6-1.pgdg13+2)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: public; Type: SCHEMA; Schema: -; Owner: -
--

-- *not* creating schema, since initdb creates it


--
-- Name: davhaven_current_tenant(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.davhaven_current_tenant() RETURNS uuid
    LANGUAGE sql STABLE PARALLEL SAFE
    AS $$ SELECT nullif(current_setting('davhaven.tenant_id', true), '')::uuid $$;


--
-- Name: davhaven_is_system(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.davhaven_is_system() RETURNS boolean
    LANGUAGE sql STABLE PARALLEL SAFE
    AS $$ SELECT coalesce(current_setting('davhaven.system', true), '') = 'on' $$;


--
-- Name: davhaven_purge_audit(timestamp with time zone, integer); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.davhaven_purge_audit(cutoff timestamp with time zone, max_rows integer) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE
    removed bigint;
BEGIN
    WITH doomed AS (
        SELECT tenant_id, id FROM public.audit_events WHERE at < cutoff ORDER BY at LIMIT greatest(max_rows, 1)
    ), gone AS (
        DELETE FROM public.audit_events a USING doomed d WHERE a.tenant_id = d.tenant_id AND a.id = d.id RETURNING 1
    )
    SELECT count(*) INTO removed FROM gone;
    RETURN removed;
END
$$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: _sqlx_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public._sqlx_migrations (
    version bigint NOT NULL,
    description text NOT NULL,
    installed_on timestamp with time zone DEFAULT now() NOT NULL,
    success boolean NOT NULL,
    checksum bytea NOT NULL,
    execution_time bigint NOT NULL
);


--
-- Name: api_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.api_tokens (
    tenant_id uuid,
    id uuid NOT NULL,
    kind text NOT NULL,
    principal_id uuid,
    label text NOT NULL,
    scopes text[] NOT NULL,
    prefix text NOT NULL,
    hash bytea NOT NULL,
    pepper_kid text NOT NULL,
    expires_at timestamp with time zone,
    created_by uuid,
    allowed_origins text[] NOT NULL,
    last_used_at timestamp with time zone,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    version bigint NOT NULL,
    CONSTRAINT api_tokens_kind_check CHECK ((kind = ANY (ARRAY['system'::text, 'tenant'::text, 'principal'::text]))),
    CONSTRAINT api_tokens_principal_check CHECK (((kind = 'principal'::text) = (principal_id IS NOT NULL))),
    CONSTRAINT api_tokens_system_check CHECK (((kind = 'system'::text) = (tenant_id IS NULL)))
);


--
-- Name: app_passwords; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.app_passwords (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    principal_id uuid NOT NULL,
    label text NOT NULL,
    prefix text NOT NULL,
    hash bytea NOT NULL,
    pepper_kid text NOT NULL,
    last_used_at timestamp with time zone,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    version bigint NOT NULL
);


--
-- Name: audit_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_events (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    actor jsonb NOT NULL,
    action text NOT NULL,
    target text,
    details jsonb NOT NULL,
    at timestamp with time zone NOT NULL
);


--
-- Name: calendar_bindings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.calendar_bindings (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    principal_id uuid NOT NULL,
    calendar_id uuid NOT NULL,
    slug text NOT NULL,
    display_name text,
    color text,
    sort_order integer,
    schedule_transp text,
    hidden boolean NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    version bigint NOT NULL
);


--
-- Name: calendar_grants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.calendar_grants (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    calendar_id uuid NOT NULL,
    grantee_id uuid NOT NULL,
    access text NOT NULL,
    status text NOT NULL,
    source text NOT NULL,
    invite_uid text,
    summary text,
    common_name text,
    required boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    version bigint NOT NULL,
    CONSTRAINT calendar_grants_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'accepted'::text, 'declined'::text])))
);


--
-- Name: calendar_objects; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.calendar_objects (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    calendar_id uuid NOT NULL,
    owner_id uuid NOT NULL,
    uri text NOT NULL,
    uid text NOT NULL,
    etag text NOT NULL,
    schedule_tag text,
    content_hash text NOT NULL,
    component text NOT NULL,
    data text NOT NULL,
    size bigint NOT NULL,
    first_start timestamp with time zone,
    last_end timestamp with time zone NOT NULL,
    is_recurring boolean NOT NULL,
    is_scheduling boolean NOT NULL,
    organizer_address text,
    sequence integer NOT NULL,
    class text NOT NULL,
    external_key text,
    origin text,
    live boolean NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    version bigint NOT NULL
);


--
-- Name: calendars; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.calendars (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    owner_id uuid NOT NULL,
    slug text NOT NULL,
    kind text NOT NULL,
    display_name text NOT NULL,
    description text,
    color text,
    sort_order integer NOT NULL,
    components text[] NOT NULL,
    timezone_ics text,
    sync_seq bigint NOT NULL,
    sync_min_seq bigint NOT NULL,
    sync_epoch uuid NOT NULL,
    deleted_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    version bigint NOT NULL,
    CONSTRAINT calendars_kind_check CHECK ((kind = ANY (ARRAY['personal'::text, 'group'::text, 'managed'::text, 'user'::text, 'mirror'::text])))
);


--
-- Name: collection_changes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.collection_changes (
    tenant_id uuid NOT NULL,
    collection_kind text NOT NULL,
    collection_id uuid NOT NULL,
    seq bigint NOT NULL,
    uri text NOT NULL,
    kind text NOT NULL,
    at timestamp with time zone NOT NULL,
    CONSTRAINT collection_changes_collection_kind_check CHECK ((collection_kind = ANY (ARRAY['calendar'::text, 'home'::text, 'inbox'::text, 'notifications'::text]))),
    CONSTRAINT collection_changes_kind_check CHECK ((kind = ANY (ARRAY['upsert'::text, 'delete'::text])))
);


--
-- Name: collection_properties; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.collection_properties (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    calendar_id uuid NOT NULL,
    binding_id uuid,
    ns text NOT NULL,
    name text NOT NULL,
    value_xml text NOT NULL
);


--
-- Name: external_accounts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.external_accounts (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    principal_id uuid NOT NULL,
    provider text NOT NULL,
    account_ref text NOT NULL,
    sealed_tokens bytea NOT NULL,
    mirror_calendar_id uuid,
    sync_state jsonb NOT NULL,
    status text NOT NULL,
    last_error text,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    version bigint NOT NULL
);


--
-- Name: feed_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.feed_tokens (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    principal_id uuid NOT NULL,
    mode text NOT NULL,
    calendar_ids uuid[] NOT NULL,
    prefix text NOT NULL,
    hash bytea NOT NULL,
    pepper_kid text NOT NULL,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    version bigint NOT NULL
);


--
-- Name: idempotency_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.idempotency_keys (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    token_id uuid NOT NULL,
    key text NOT NULL,
    method text NOT NULL,
    path text NOT NULL,
    fingerprint text NOT NULL,
    status text NOT NULL,
    response_status integer,
    response jsonb,
    lease_until timestamp with time zone,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT idempotency_keys_status_check CHECK ((status = ANY (ARRAY['in_flight'::text, 'done'::text])))
);


--
-- Name: memberships; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.memberships (
    tenant_id uuid NOT NULL,
    group_id uuid NOT NULL,
    member_id uuid NOT NULL
);


--
-- Name: notifications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.notifications (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    principal_id uuid NOT NULL,
    uri text NOT NULL,
    uid text NOT NULL,
    etag text NOT NULL,
    type text NOT NULL,
    body_xml text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    version bigint NOT NULL
);


--
-- Name: oauth_states; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_states (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    principal_id uuid NOT NULL,
    provider text NOT NULL,
    state_hash bytea NOT NULL,
    pkce_verifier_sealed bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL
);


--
-- Name: object_attendees; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.object_attendees (
    tenant_id uuid NOT NULL,
    object_id uuid NOT NULL,
    address text NOT NULL,
    principal_id uuid,
    partstat text NOT NULL
);


--
-- Name: outbox; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.outbox (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    kind text NOT NULL,
    payload jsonb NOT NULL,
    schema_version integer NOT NULL,
    status text NOT NULL,
    attempts integer NOT NULL,
    next_attempt_at timestamp with time zone NOT NULL,
    locked_until timestamp with time zone,
    last_error text,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT outbox_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'in_flight'::text, 'done'::text, 'dead'::text])))
);


--
-- Name: principal_addresses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.principal_addresses (
    tenant_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    address text NOT NULL,
    is_primary boolean NOT NULL
);


--
-- Name: principals; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.principals (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    kind text NOT NULL,
    name text NOT NULL,
    display_name text NOT NULL,
    email text,
    locale text,
    timezone text,
    external_ref text,
    status text NOT NULL,
    deleted_at timestamp with time zone,
    credential_generation integer NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    version bigint NOT NULL,
    CONSTRAINT principals_kind_check CHECK ((kind = ANY (ARRAY['user'::text, 'group'::text, 'resource'::text, 'service'::text]))),
    CONSTRAINT principals_status_check CHECK ((status = ANY (ARRAY['active'::text, 'suspended'::text, 'deleted'::text])))
);


--
-- Name: principals_sync; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.principals_sync (
    tenant_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    home_seq bigint NOT NULL,
    home_min_seq bigint NOT NULL,
    home_epoch uuid NOT NULL,
    inbox_seq bigint NOT NULL,
    inbox_min_seq bigint NOT NULL,
    inbox_epoch uuid NOT NULL,
    notifications_seq bigint NOT NULL,
    notifications_min_seq bigint NOT NULL,
    notifications_epoch uuid NOT NULL
);


--
-- Name: rsvp_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.rsvp_tokens (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    object_id uuid NOT NULL,
    attendee_address text NOT NULL,
    prefix text NOT NULL,
    hash bytea NOT NULL,
    pepper_kid text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    last_used_at timestamp with time zone,
    last_response text,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    version bigint NOT NULL
);


--
-- Name: scheduling_inbox; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scheduling_inbox (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    principal_id uuid NOT NULL,
    uri text NOT NULL,
    etag text NOT NULL,
    data text NOT NULL,
    quarantined boolean NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    version bigint NOT NULL
);


--
-- Name: tenants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenants (
    id uuid NOT NULL,
    slug text NOT NULL,
    display_name text NOT NULL,
    login_domain text,
    status text NOT NULL,
    settings jsonb NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    version bigint NOT NULL,
    CONSTRAINT tenants_status_check CHECK ((status = ANY (ARRAY['active'::text, 'suspended'::text])))
);


--
-- Name: webhook_deliveries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webhook_deliveries (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    event_id uuid NOT NULL,
    status text NOT NULL,
    attempts integer NOT NULL,
    response_status integer,
    last_error text,
    at timestamp with time zone NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    version bigint NOT NULL
);


--
-- Name: webhook_subscriptions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webhook_subscriptions (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    url text NOT NULL,
    description text,
    sealed_secret bytea NOT NULL,
    sealed_secret_previous bytea,
    secret_rotated_at timestamp with time zone,
    events text[] NOT NULL,
    include_details boolean NOT NULL,
    active boolean NOT NULL,
    failure_count integer NOT NULL,
    disabled_reason text,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    version bigint NOT NULL
);


--
-- Data for Name: _sqlx_migrations; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public._sqlx_migrations VALUES (20261101120000, 'initial schema', '2026-11-01 12:43:32.66871+00', true, '\xfcd3ccc4ecdc3ba1b8418e0845dba6e131f5ca5660866f1757aafe6c388add86bbe6d0022c8cc687ceb6bb788effd051', 41211798);


--
-- Data for Name: api_tokens; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.api_tokens VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000032', 'tenant', NULL, 'automation', '{calendars:read,principals:read}', 'at_fixture_acme', '\x0a0b0c', 'k1', NULL, NULL, '{https://admin.acme.example}', NULL, NULL, '2026-10-01 08:11:00+00', '2026-10-01 08:11:00+00', 1);
INSERT INTO public.api_tokens VALUES (NULL, '01900000-0000-7000-8000-000000000033', 'system', NULL, 'operator', '{system:tenants}', 'at_fixture_system', '\x0d0e0f', 'k1', NULL, NULL, '{}', NULL, NULL, '2026-10-01 07:00:00+00', '2026-10-01 07:00:00+00', 1);


--
-- Data for Name: app_passwords; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.app_passwords VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000031', '01900000-0000-7000-8000-000000000001', 'iPhone', 'ap_fixture_olivia', '\x0102030405', 'k1', '2026-10-03 07:00:00+00', NULL, '2026-10-01 08:10:00+00', '2026-10-03 07:00:00+00', 2);


--
-- Data for Name: audit_events; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.audit_events VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000051', '{"kind": "system", "label": null, "ip_hash": null, "token_id": null, "principal_id": null}', 'tenant.created', 'tenant:01900000-0000-7000-8000-00000000000a', '{}', '2026-10-01 08:00:00+00');


--
-- Data for Name: calendar_bindings; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.calendar_bindings VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000005', '01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-000000000003', 'personal', NULL, NULL, NULL, NULL, false, '2026-10-01 08:03:00+00', '2026-10-01 08:03:00+00', 1);


--
-- Data for Name: calendar_grants; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.calendar_grants VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000006', '01900000-0000-7000-8000-000000000003', '01900000-0000-7000-8000-000000000002', 'read_write', 'accepted', 'api', NULL, NULL, NULL, false, '2026-10-01 08:05:00+00', '2026-10-01 08:05:00+00', 1);


--
-- Data for Name: calendar_objects; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.calendar_objects VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000011', '01900000-0000-7000-8000-000000000003', '01900000-0000-7000-8000-000000000001', 'a.ics', 'uid-a', '"aaaaaaaaaaaaaaaaaaaaaa"', NULL, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'VEVENT', 'BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:uid-a
SUMMARY:A
END:VEVENT
END:VCALENDAR
', 84, '2027-03-01 10:00:00+00', '2027-03-01 11:00:00+00', false, false, NULL, 0, 'PUBLIC', 'ext-a', 'api', true, '2026-10-02 09:00:00+00', '2026-10-02 09:00:00+00', 1);
INSERT INTO public.calendar_objects VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000012', '01900000-0000-7000-8000-000000000003', '01900000-0000-7000-8000-000000000001', 'b.ics', 'uid-b', '"bbbbbbbbbbbbbbbbbbbbbb"', '"sched-b"', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'VEVENT', 'BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:uid-b
SUMMARY:B
RRULE:FREQ=WEEKLY
END:VEVENT
END:VCALENDAR
', 104, '2027-03-02 10:00:00+00', 'infinity', true, true, 'mailto:olivia@acme.example', 2, 'PRIVATE', NULL, NULL, true, '2026-10-02 09:30:00+00', '2026-10-02 09:45:00+00', 2);


--
-- Data for Name: calendars; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.calendars VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000003', '01900000-0000-7000-8000-000000000001', 'personal', 'personal', 'Olivia', 'Private appointments', '#336699', 0, '{VEVENT,VTODO}', NULL, 4, 0, '01900000-0000-7000-8000-0000000000e1', NULL, '2026-10-01 08:03:00+00', '2026-10-02 10:00:00+00', 5);
INSERT INTO public.calendars VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000004', '01900000-0000-7000-8000-000000000001', 'projects', 'user', 'Projects', NULL, NULL, 1, '{VEVENT}', NULL, 0, 0, '01900000-0000-7000-8000-0000000000e8', NULL, '2026-10-01 08:04:00+00', '2026-10-01 08:04:00+00', 1);


--
-- Data for Name: collection_changes; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.collection_changes VALUES ('01900000-0000-7000-8000-00000000000a', 'calendar', '01900000-0000-7000-8000-000000000003', 1, 'a.ics', 'upsert', '2026-10-02 09:00:00+00');
INSERT INTO public.collection_changes VALUES ('01900000-0000-7000-8000-00000000000a', 'calendar', '01900000-0000-7000-8000-000000000003', 2, 'b.ics', 'upsert', '2026-10-02 09:30:00+00');
INSERT INTO public.collection_changes VALUES ('01900000-0000-7000-8000-00000000000a', 'calendar', '01900000-0000-7000-8000-000000000003', 3, 'c.ics', 'upsert', '2026-10-02 09:40:00+00');
INSERT INTO public.collection_changes VALUES ('01900000-0000-7000-8000-00000000000a', 'calendar', '01900000-0000-7000-8000-000000000003', 4, 'c.ics', 'delete', '2026-10-02 10:00:00+00');
INSERT INTO public.collection_changes VALUES ('01900000-0000-7000-8000-00000000000a', 'home', '01900000-0000-7000-8000-000000000001', 1, 'personal', 'upsert', '2026-10-01 08:03:00+00');
INSERT INTO public.collection_changes VALUES ('01900000-0000-7000-8000-00000000000a', 'inbox', '01900000-0000-7000-8000-000000000001', 1, 'request.ics', 'upsert', '2026-10-02 11:00:00+00');
INSERT INTO public.collection_changes VALUES ('01900000-0000-7000-8000-00000000000a', 'notifications', '01900000-0000-7000-8000-000000000001', 1, 'invite.xml', 'upsert', '2026-10-02 12:00:00+00');


--
-- Data for Name: collection_properties; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.collection_properties VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000007', '01900000-0000-7000-8000-000000000003', NULL, 'urn:example', 'note', '<note xmlns="urn:example">hi</note>');


--
-- Data for Name: external_accounts; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: feed_tokens; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: idempotency_keys; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: memberships; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.memberships VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000002', '01900000-0000-7000-8000-000000000001');


--
-- Data for Name: notifications; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.notifications VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000021', '01900000-0000-7000-8000-000000000001', 'invite.xml', 'invite-1', '"cccccccccccccccccccccc"', 'invite', '<invite-notification xmlns="http://calendarserver.org/ns/"/>', '2026-10-02 12:00:00+00', '2026-10-02 12:00:00+00', 1);


--
-- Data for Name: oauth_states; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: object_attendees; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.object_attendees VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000012', 'mailto:olivia@acme.example', '01900000-0000-7000-8000-000000000001', 'ACCEPTED');
INSERT INTO public.object_attendees VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000012', 'mailto:guest@elsewhere.example', NULL, 'NEEDS-ACTION');


--
-- Data for Name: outbox; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.outbox VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000041', 'provider_push', '{}', 1, 'pending', 0, '2026-10-02 12:00:00+00', NULL, NULL, '2026-10-02 12:00:00+00', '2026-10-02 12:00:00+00');


--
-- Data for Name: principal_addresses; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.principal_addresses VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000001', 'mailto:olivia@acme.example', true);
INSERT INTO public.principal_addresses VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000001', 'mailto:o.ostermann@acme.example', false);


--
-- Data for Name: principals; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.principals VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000001', 'user', 'olivia', 'Olivia Ostermann', 'olivia@acme.example', 'de', 'Europe/Berlin', 'ldap:olivia', 'active', NULL, 2, '2026-10-01 08:01:00+00', '2026-10-02 09:00:00+00', 3);
INSERT INTO public.principals VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000002', 'group', 'team', 'The Team', NULL, NULL, NULL, NULL, 'active', NULL, 0, '2026-10-01 08:02:00+00', '2026-10-01 08:02:00+00', 1);


--
-- Data for Name: principals_sync; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.principals_sync VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000001', 1, 0, '01900000-0000-7000-8000-0000000000e2', 1, 0, '01900000-0000-7000-8000-0000000000e3', 1, 0, '01900000-0000-7000-8000-0000000000e4');
INSERT INTO public.principals_sync VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000002', 0, 0, '01900000-0000-7000-8000-0000000000e5', 0, 0, '01900000-0000-7000-8000-0000000000e6', 0, 0, '01900000-0000-7000-8000-0000000000e7');


--
-- Data for Name: rsvp_tokens; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: scheduling_inbox; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.scheduling_inbox VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000022', '01900000-0000-7000-8000-000000000001', 'request.ics', '"dddddddddddddddddddddd"', 'BEGIN:VCALENDAR
METHOD:REQUEST
END:VCALENDAR
', false, '2026-10-02 11:00:00+00', '2026-10-02 11:00:00+00', 1);


--
-- Data for Name: tenants; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.tenants VALUES ('01900000-0000-7000-8000-00000000000a', 'acme', 'Acme GmbH', 'acme.example', 'active', '{}', '2026-10-01 08:00:00+00', '2026-10-01 08:00:00+00', 1);


--
-- Data for Name: webhook_deliveries; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: webhook_subscriptions; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Name: _sqlx_migrations _sqlx_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public._sqlx_migrations
    ADD CONSTRAINT _sqlx_migrations_pkey PRIMARY KEY (version);


--
-- Name: api_tokens api_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_tokens
    ADD CONSTRAINT api_tokens_pkey PRIMARY KEY (id);


--
-- Name: api_tokens api_tokens_prefix_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_tokens
    ADD CONSTRAINT api_tokens_prefix_key UNIQUE (prefix);


--
-- Name: api_tokens api_tokens_tenant_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_tokens
    ADD CONSTRAINT api_tokens_tenant_id_key UNIQUE (tenant_id, id);


--
-- Name: app_passwords app_passwords_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.app_passwords
    ADD CONSTRAINT app_passwords_pkey PRIMARY KEY (tenant_id, id);


--
-- Name: app_passwords app_passwords_prefix_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.app_passwords
    ADD CONSTRAINT app_passwords_prefix_key UNIQUE (prefix);


--
-- Name: audit_events audit_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT audit_events_pkey PRIMARY KEY (tenant_id, id);


--
-- Name: calendar_bindings calendar_bindings_calendar_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_bindings
    ADD CONSTRAINT calendar_bindings_calendar_id_key UNIQUE (tenant_id, id, calendar_id);


--
-- Name: calendar_bindings calendar_bindings_calendar_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_bindings
    ADD CONSTRAINT calendar_bindings_calendar_key UNIQUE (tenant_id, principal_id, calendar_id);


--
-- Name: calendar_bindings calendar_bindings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_bindings
    ADD CONSTRAINT calendar_bindings_pkey PRIMARY KEY (tenant_id, id);


--
-- Name: calendar_bindings calendar_bindings_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_bindings
    ADD CONSTRAINT calendar_bindings_slug_key UNIQUE (tenant_id, principal_id, slug);


--
-- Name: calendar_grants calendar_grants_grantee_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_grants
    ADD CONSTRAINT calendar_grants_grantee_key UNIQUE (tenant_id, calendar_id, grantee_id);


--
-- Name: calendar_grants calendar_grants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_grants
    ADD CONSTRAINT calendar_grants_pkey PRIMARY KEY (tenant_id, id);


--
-- Name: calendar_objects calendar_objects_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_objects
    ADD CONSTRAINT calendar_objects_pkey PRIMARY KEY (tenant_id, id);


--
-- Name: calendar_objects calendar_objects_uid_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_objects
    ADD CONSTRAINT calendar_objects_uid_key UNIQUE (tenant_id, calendar_id, uid);


--
-- Name: calendar_objects calendar_objects_uri_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_objects
    ADD CONSTRAINT calendar_objects_uri_key UNIQUE (tenant_id, calendar_id, uri);


--
-- Name: calendars calendars_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendars
    ADD CONSTRAINT calendars_pkey PRIMARY KEY (tenant_id, id);


--
-- Name: collection_changes collection_changes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collection_changes
    ADD CONSTRAINT collection_changes_pkey PRIMARY KEY (tenant_id, collection_kind, collection_id, seq);


--
-- Name: collection_properties collection_properties_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collection_properties
    ADD CONSTRAINT collection_properties_pkey PRIMARY KEY (tenant_id, id);


--
-- Name: external_accounts external_accounts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.external_accounts
    ADD CONSTRAINT external_accounts_pkey PRIMARY KEY (tenant_id, id);


--
-- Name: feed_tokens feed_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feed_tokens
    ADD CONSTRAINT feed_tokens_pkey PRIMARY KEY (tenant_id, id);


--
-- Name: feed_tokens feed_tokens_prefix_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feed_tokens
    ADD CONSTRAINT feed_tokens_prefix_key UNIQUE (prefix);


--
-- Name: idempotency_keys idempotency_keys_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.idempotency_keys
    ADD CONSTRAINT idempotency_keys_key UNIQUE (tenant_id, token_id, key);


--
-- Name: idempotency_keys idempotency_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.idempotency_keys
    ADD CONSTRAINT idempotency_keys_pkey PRIMARY KEY (tenant_id, id);


--
-- Name: memberships memberships_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.memberships
    ADD CONSTRAINT memberships_pkey PRIMARY KEY (tenant_id, group_id, member_id);


--
-- Name: notifications notifications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_pkey PRIMARY KEY (tenant_id, id);


--
-- Name: notifications notifications_uri_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_uri_key UNIQUE (tenant_id, principal_id, uri);


--
-- Name: oauth_states oauth_states_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_states
    ADD CONSTRAINT oauth_states_hash_key UNIQUE (state_hash);


--
-- Name: oauth_states oauth_states_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_states
    ADD CONSTRAINT oauth_states_pkey PRIMARY KEY (tenant_id, id);


--
-- Name: object_attendees object_attendees_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.object_attendees
    ADD CONSTRAINT object_attendees_pkey PRIMARY KEY (tenant_id, object_id, address);


--
-- Name: outbox outbox_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.outbox
    ADD CONSTRAINT outbox_pkey PRIMARY KEY (tenant_id, id);


--
-- Name: principal_addresses principal_addresses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.principal_addresses
    ADD CONSTRAINT principal_addresses_pkey PRIMARY KEY (tenant_id, principal_id, address);


--
-- Name: principals principals_external_ref_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.principals
    ADD CONSTRAINT principals_external_ref_key UNIQUE (tenant_id, external_ref);


--
-- Name: principals principals_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.principals
    ADD CONSTRAINT principals_name_key UNIQUE (tenant_id, name);


--
-- Name: principals principals_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.principals
    ADD CONSTRAINT principals_pkey PRIMARY KEY (tenant_id, id);


--
-- Name: principals_sync principals_sync_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.principals_sync
    ADD CONSTRAINT principals_sync_pkey PRIMARY KEY (tenant_id, principal_id);


--
-- Name: rsvp_tokens rsvp_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rsvp_tokens
    ADD CONSTRAINT rsvp_tokens_pkey PRIMARY KEY (tenant_id, id);


--
-- Name: rsvp_tokens rsvp_tokens_prefix_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rsvp_tokens
    ADD CONSTRAINT rsvp_tokens_prefix_key UNIQUE (prefix);


--
-- Name: scheduling_inbox scheduling_inbox_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scheduling_inbox
    ADD CONSTRAINT scheduling_inbox_pkey PRIMARY KEY (tenant_id, id);


--
-- Name: scheduling_inbox scheduling_inbox_uri_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scheduling_inbox
    ADD CONSTRAINT scheduling_inbox_uri_key UNIQUE (tenant_id, principal_id, uri);


--
-- Name: tenants tenants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT tenants_pkey PRIMARY KEY (id);


--
-- Name: webhook_deliveries webhook_deliveries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_pkey PRIMARY KEY (tenant_id, id);


--
-- Name: webhook_subscriptions webhook_subscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_subscriptions
    ADD CONSTRAINT webhook_subscriptions_pkey PRIMARY KEY (tenant_id, id);


--
-- Name: api_tokens_principal_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX api_tokens_principal_idx ON public.api_tokens USING btree (tenant_id, principal_id) WHERE (principal_id IS NOT NULL);


--
-- Name: app_passwords_principal_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX app_passwords_principal_idx ON public.app_passwords USING btree (tenant_id, principal_id, id);


--
-- Name: audit_events_action_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_events_action_idx ON public.audit_events USING btree (tenant_id, action, id);


--
-- Name: audit_events_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_events_at_idx ON public.audit_events USING btree (at);


--
-- Name: calendar_bindings_calendar_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX calendar_bindings_calendar_idx ON public.calendar_bindings USING btree (tenant_id, calendar_id);


--
-- Name: calendar_grants_grantee_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX calendar_grants_grantee_idx ON public.calendar_grants USING btree (tenant_id, grantee_id);


--
-- Name: calendar_grants_invite_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX calendar_grants_invite_idx ON public.calendar_grants USING btree (tenant_id, invite_uid) WHERE (invite_uid IS NOT NULL);


--
-- Name: calendar_objects_external_key_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX calendar_objects_external_key_key ON public.calendar_objects USING btree (tenant_id, calendar_id, external_key) WHERE (external_key IS NOT NULL);


--
-- Name: calendar_objects_first_start_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX calendar_objects_first_start_idx ON public.calendar_objects USING btree (tenant_id, calendar_id, first_start);


--
-- Name: calendar_objects_last_end_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX calendar_objects_last_end_idx ON public.calendar_objects USING btree (tenant_id, calendar_id, last_end);


--
-- Name: calendar_objects_owner_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX calendar_objects_owner_idx ON public.calendar_objects USING btree (tenant_id, owner_id);


--
-- Name: calendar_objects_paging_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX calendar_objects_paging_idx ON public.calendar_objects USING btree (tenant_id, calendar_id, id);


--
-- Name: calendar_objects_scheduling_uid_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX calendar_objects_scheduling_uid_key ON public.calendar_objects USING btree (tenant_id, owner_id, uid) WHERE (is_scheduling AND live);


--
-- Name: calendars_deleted_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX calendars_deleted_idx ON public.calendars USING btree (deleted_at) WHERE (deleted_at IS NOT NULL);


--
-- Name: calendars_slug_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX calendars_slug_key ON public.calendars USING btree (tenant_id, owner_id, slug) WHERE (deleted_at IS NULL);


--
-- Name: collection_changes_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX collection_changes_at_idx ON public.collection_changes USING btree (at);


--
-- Name: collection_changes_uri_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX collection_changes_uri_idx ON public.collection_changes USING btree (tenant_id, collection_kind, collection_id, uri, seq);


--
-- Name: collection_properties_binding_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX collection_properties_binding_idx ON public.collection_properties USING btree (tenant_id, binding_id) WHERE (binding_id IS NOT NULL);


--
-- Name: collection_properties_binding_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX collection_properties_binding_key ON public.collection_properties USING btree (tenant_id, calendar_id, binding_id, ns, name) WHERE (binding_id IS NOT NULL);


--
-- Name: collection_properties_shared_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX collection_properties_shared_key ON public.collection_properties USING btree (tenant_id, calendar_id, ns, name) WHERE (binding_id IS NULL);


--
-- Name: external_accounts_principal_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX external_accounts_principal_idx ON public.external_accounts USING btree (tenant_id, principal_id, id);


--
-- Name: feed_tokens_principal_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX feed_tokens_principal_idx ON public.feed_tokens USING btree (tenant_id, principal_id, id);


--
-- Name: idempotency_keys_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idempotency_keys_expiry_idx ON public.idempotency_keys USING btree (expires_at);


--
-- Name: memberships_member_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX memberships_member_idx ON public.memberships USING btree (tenant_id, member_id);


--
-- Name: notifications_uid_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX notifications_uid_idx ON public.notifications USING btree (tenant_id, principal_id, uid);


--
-- Name: oauth_states_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oauth_states_expiry_idx ON public.oauth_states USING btree (expires_at);


--
-- Name: object_attendees_address_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX object_attendees_address_idx ON public.object_attendees USING btree (tenant_id, address);


--
-- Name: object_attendees_principal_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX object_attendees_principal_idx ON public.object_attendees USING btree (tenant_id, principal_id) WHERE (principal_id IS NOT NULL);


--
-- Name: outbox_due_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX outbox_due_idx ON public.outbox USING btree (status, next_attempt_at) WHERE (status = ANY (ARRAY['pending'::text, 'in_flight'::text]));


--
-- Name: outbox_settled_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX outbox_settled_idx ON public.outbox USING btree (status, updated_at) WHERE (status = ANY (ARRAY['done'::text, 'dead'::text]));


--
-- Name: outbox_tenant_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX outbox_tenant_status_idx ON public.outbox USING btree (tenant_id, status, id);


--
-- Name: principal_addresses_address_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX principal_addresses_address_key ON public.principal_addresses USING btree (tenant_id, lower(address));


--
-- Name: principal_addresses_primary_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX principal_addresses_primary_key ON public.principal_addresses USING btree (tenant_id, principal_id) WHERE is_primary;


--
-- Name: principals_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX principals_status_idx ON public.principals USING btree (status, deleted_at) WHERE (status = 'deleted'::text);


--
-- Name: rsvp_tokens_address_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX rsvp_tokens_address_idx ON public.rsvp_tokens USING btree (tenant_id, attendee_address);


--
-- Name: rsvp_tokens_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX rsvp_tokens_expiry_idx ON public.rsvp_tokens USING btree (expires_at);


--
-- Name: rsvp_tokens_object_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX rsvp_tokens_object_idx ON public.rsvp_tokens USING btree (tenant_id, object_id, id);


--
-- Name: rsvp_tokens_revoked_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX rsvp_tokens_revoked_idx ON public.rsvp_tokens USING btree (revoked_at) WHERE (revoked_at IS NOT NULL);


--
-- Name: scheduling_inbox_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX scheduling_inbox_created_idx ON public.scheduling_inbox USING btree (created_at);


--
-- Name: tenants_login_domain_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX tenants_login_domain_key ON public.tenants USING btree (lower(login_domain)) WHERE (login_domain IS NOT NULL);


--
-- Name: tenants_slug_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX tenants_slug_key ON public.tenants USING btree (slug);


--
-- Name: webhook_deliveries_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX webhook_deliveries_created_idx ON public.webhook_deliveries USING btree (created_at);


--
-- Name: webhook_deliveries_event_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX webhook_deliveries_event_key ON public.webhook_deliveries USING btree (tenant_id, subscription_id, event_id);


--
-- Name: webhook_deliveries_subscription_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX webhook_deliveries_subscription_idx ON public.webhook_deliveries USING btree (tenant_id, subscription_id, id);


--
-- Name: api_tokens api_tokens_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_tokens
    ADD CONSTRAINT api_tokens_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.api_tokens(id) ON DELETE SET NULL;


--
-- Name: api_tokens api_tokens_principal_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_tokens
    ADD CONSTRAINT api_tokens_principal_fkey FOREIGN KEY (tenant_id, principal_id) REFERENCES public.principals(tenant_id, id) ON DELETE CASCADE;


--
-- Name: api_tokens api_tokens_tenant_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_tokens
    ADD CONSTRAINT api_tokens_tenant_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: app_passwords app_passwords_principal_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.app_passwords
    ADD CONSTRAINT app_passwords_principal_fkey FOREIGN KEY (tenant_id, principal_id) REFERENCES public.principals(tenant_id, id) ON DELETE CASCADE;


--
-- Name: calendar_bindings calendar_bindings_calendar_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_bindings
    ADD CONSTRAINT calendar_bindings_calendar_fkey FOREIGN KEY (tenant_id, calendar_id) REFERENCES public.calendars(tenant_id, id) ON DELETE CASCADE;


--
-- Name: calendar_bindings calendar_bindings_principal_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_bindings
    ADD CONSTRAINT calendar_bindings_principal_fkey FOREIGN KEY (tenant_id, principal_id) REFERENCES public.principals(tenant_id, id) ON DELETE CASCADE;


--
-- Name: calendar_grants calendar_grants_calendar_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_grants
    ADD CONSTRAINT calendar_grants_calendar_fkey FOREIGN KEY (tenant_id, calendar_id) REFERENCES public.calendars(tenant_id, id) ON DELETE CASCADE;


--
-- Name: calendar_grants calendar_grants_grantee_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_grants
    ADD CONSTRAINT calendar_grants_grantee_fkey FOREIGN KEY (tenant_id, grantee_id) REFERENCES public.principals(tenant_id, id) ON DELETE CASCADE;


--
-- Name: calendar_objects calendar_objects_calendar_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_objects
    ADD CONSTRAINT calendar_objects_calendar_fkey FOREIGN KEY (tenant_id, calendar_id) REFERENCES public.calendars(tenant_id, id) ON DELETE CASCADE;


--
-- Name: calendar_objects calendar_objects_owner_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_objects
    ADD CONSTRAINT calendar_objects_owner_fkey FOREIGN KEY (tenant_id, owner_id) REFERENCES public.principals(tenant_id, id) ON DELETE CASCADE;


--
-- Name: calendars calendars_owner_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendars
    ADD CONSTRAINT calendars_owner_fkey FOREIGN KEY (tenant_id, owner_id) REFERENCES public.principals(tenant_id, id) ON DELETE CASCADE;


--
-- Name: collection_changes collection_changes_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collection_changes
    ADD CONSTRAINT collection_changes_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: collection_properties collection_properties_binding_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collection_properties
    ADD CONSTRAINT collection_properties_binding_fkey FOREIGN KEY (tenant_id, binding_id, calendar_id) REFERENCES public.calendar_bindings(tenant_id, id, calendar_id) ON DELETE CASCADE;


--
-- Name: collection_properties collection_properties_calendar_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collection_properties
    ADD CONSTRAINT collection_properties_calendar_fkey FOREIGN KEY (tenant_id, calendar_id) REFERENCES public.calendars(tenant_id, id) ON DELETE CASCADE;


--
-- Name: external_accounts external_accounts_calendar_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.external_accounts
    ADD CONSTRAINT external_accounts_calendar_fkey FOREIGN KEY (tenant_id, mirror_calendar_id) REFERENCES public.calendars(tenant_id, id) ON DELETE SET NULL (mirror_calendar_id);


--
-- Name: external_accounts external_accounts_principal_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.external_accounts
    ADD CONSTRAINT external_accounts_principal_fkey FOREIGN KEY (tenant_id, principal_id) REFERENCES public.principals(tenant_id, id) ON DELETE CASCADE;


--
-- Name: feed_tokens feed_tokens_principal_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feed_tokens
    ADD CONSTRAINT feed_tokens_principal_fkey FOREIGN KEY (tenant_id, principal_id) REFERENCES public.principals(tenant_id, id) ON DELETE CASCADE;


--
-- Name: idempotency_keys idempotency_keys_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.idempotency_keys
    ADD CONSTRAINT idempotency_keys_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: memberships memberships_group_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.memberships
    ADD CONSTRAINT memberships_group_fkey FOREIGN KEY (tenant_id, group_id) REFERENCES public.principals(tenant_id, id) ON DELETE CASCADE;


--
-- Name: memberships memberships_member_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.memberships
    ADD CONSTRAINT memberships_member_fkey FOREIGN KEY (tenant_id, member_id) REFERENCES public.principals(tenant_id, id) ON DELETE CASCADE;


--
-- Name: notifications notifications_principal_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_principal_fkey FOREIGN KEY (tenant_id, principal_id) REFERENCES public.principals(tenant_id, id) ON DELETE CASCADE;


--
-- Name: oauth_states oauth_states_principal_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_states
    ADD CONSTRAINT oauth_states_principal_fkey FOREIGN KEY (tenant_id, principal_id) REFERENCES public.principals(tenant_id, id) ON DELETE CASCADE;


--
-- Name: object_attendees object_attendees_object_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.object_attendees
    ADD CONSTRAINT object_attendees_object_fkey FOREIGN KEY (tenant_id, object_id) REFERENCES public.calendar_objects(tenant_id, id) ON DELETE CASCADE;


--
-- Name: object_attendees object_attendees_principal_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.object_attendees
    ADD CONSTRAINT object_attendees_principal_fkey FOREIGN KEY (tenant_id, principal_id) REFERENCES public.principals(tenant_id, id) ON DELETE SET NULL (principal_id);


--
-- Name: outbox outbox_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.outbox
    ADD CONSTRAINT outbox_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: principal_addresses principal_addresses_principal_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.principal_addresses
    ADD CONSTRAINT principal_addresses_principal_fkey FOREIGN KEY (tenant_id, principal_id) REFERENCES public.principals(tenant_id, id) ON DELETE CASCADE;


--
-- Name: principals_sync principals_sync_principal_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.principals_sync
    ADD CONSTRAINT principals_sync_principal_fkey FOREIGN KEY (tenant_id, principal_id) REFERENCES public.principals(tenant_id, id) ON DELETE CASCADE;


--
-- Name: principals principals_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.principals
    ADD CONSTRAINT principals_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: rsvp_tokens rsvp_tokens_object_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rsvp_tokens
    ADD CONSTRAINT rsvp_tokens_object_fkey FOREIGN KEY (tenant_id, object_id) REFERENCES public.calendar_objects(tenant_id, id) ON DELETE CASCADE;


--
-- Name: scheduling_inbox scheduling_inbox_principal_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scheduling_inbox
    ADD CONSTRAINT scheduling_inbox_principal_fkey FOREIGN KEY (tenant_id, principal_id) REFERENCES public.principals(tenant_id, id) ON DELETE CASCADE;


--
-- Name: webhook_deliveries webhook_deliveries_subscription_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_subscription_fkey FOREIGN KEY (tenant_id, subscription_id) REFERENCES public.webhook_subscriptions(tenant_id, id) ON DELETE CASCADE;


--
-- Name: webhook_subscriptions webhook_subscriptions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_subscriptions
    ADD CONSTRAINT webhook_subscriptions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: api_tokens; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.api_tokens ENABLE ROW LEVEL SECURITY;

--
-- Name: app_passwords; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.app_passwords ENABLE ROW LEVEL SECURITY;

--
-- Name: audit_events; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.audit_events ENABLE ROW LEVEL SECURITY;

--
-- Name: calendar_bindings; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.calendar_bindings ENABLE ROW LEVEL SECURITY;

--
-- Name: calendar_grants; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.calendar_grants ENABLE ROW LEVEL SECURITY;

--
-- Name: calendar_objects; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.calendar_objects ENABLE ROW LEVEL SECURITY;

--
-- Name: calendars; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.calendars ENABLE ROW LEVEL SECURITY;

--
-- Name: collection_changes; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.collection_changes ENABLE ROW LEVEL SECURITY;

--
-- Name: collection_properties; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.collection_properties ENABLE ROW LEVEL SECURITY;

--
-- Name: external_accounts; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.external_accounts ENABLE ROW LEVEL SECURITY;

--
-- Name: feed_tokens; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.feed_tokens ENABLE ROW LEVEL SECURITY;

--
-- Name: idempotency_keys; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.idempotency_keys ENABLE ROW LEVEL SECURITY;

--
-- Name: memberships; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.memberships ENABLE ROW LEVEL SECURITY;

--
-- Name: notifications; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.notifications ENABLE ROW LEVEL SECURITY;

--
-- Name: oauth_states; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.oauth_states ENABLE ROW LEVEL SECURITY;

--
-- Name: object_attendees; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.object_attendees ENABLE ROW LEVEL SECURITY;

--
-- Name: outbox; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.outbox ENABLE ROW LEVEL SECURITY;

--
-- Name: principal_addresses; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.principal_addresses ENABLE ROW LEVEL SECURITY;

--
-- Name: principals; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.principals ENABLE ROW LEVEL SECURITY;

--
-- Name: principals_sync; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.principals_sync ENABLE ROW LEVEL SECURITY;

--
-- Name: rsvp_tokens; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.rsvp_tokens ENABLE ROW LEVEL SECURITY;

--
-- Name: scheduling_inbox; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.scheduling_inbox ENABLE ROW LEVEL SECURITY;

--
-- Name: tenants system_scope; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY system_scope ON public.tenants USING (public.davhaven_is_system()) WITH CHECK (public.davhaven_is_system());


--
-- Name: collection_changes system_scope_delete; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY system_scope_delete ON public.collection_changes FOR DELETE USING (public.davhaven_is_system());


--
-- Name: idempotency_keys system_scope_delete; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY system_scope_delete ON public.idempotency_keys FOR DELETE USING (public.davhaven_is_system());


--
-- Name: oauth_states system_scope_delete; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY system_scope_delete ON public.oauth_states FOR DELETE USING (public.davhaven_is_system());


--
-- Name: outbox system_scope_delete; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY system_scope_delete ON public.outbox FOR DELETE USING (public.davhaven_is_system());


--
-- Name: rsvp_tokens system_scope_delete; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY system_scope_delete ON public.rsvp_tokens FOR DELETE USING (public.davhaven_is_system());


--
-- Name: scheduling_inbox system_scope_delete; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY system_scope_delete ON public.scheduling_inbox FOR DELETE USING (public.davhaven_is_system());


--
-- Name: webhook_deliveries system_scope_delete; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY system_scope_delete ON public.webhook_deliveries FOR DELETE USING (public.davhaven_is_system());


--
-- Name: api_tokens system_scope_insert; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY system_scope_insert ON public.api_tokens FOR INSERT WITH CHECK ((public.davhaven_is_system() AND (tenant_id IS NULL) AND (kind = 'system'::text)));


--
-- Name: audit_events system_scope_insert; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY system_scope_insert ON public.audit_events FOR INSERT WITH CHECK ((public.davhaven_is_system() AND (action = ANY (ARRAY['tenant.created'::text, 'tenant.settings_changed'::text])) AND (EXISTS ( SELECT 1
   FROM public.tenants t
  WHERE (t.id = audit_events.tenant_id)))));


--
-- Name: collection_changes system_scope_insert; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY system_scope_insert ON public.collection_changes FOR INSERT WITH CHECK (public.davhaven_is_system());


--
-- Name: api_tokens system_scope_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY system_scope_select ON public.api_tokens FOR SELECT USING (public.davhaven_is_system());


--
-- Name: app_passwords system_scope_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY system_scope_select ON public.app_passwords FOR SELECT USING (public.davhaven_is_system());


--
-- Name: audit_events system_scope_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY system_scope_select ON public.audit_events FOR SELECT USING (public.davhaven_is_system());


--
-- Name: calendars system_scope_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY system_scope_select ON public.calendars FOR SELECT USING (public.davhaven_is_system());


--
-- Name: collection_changes system_scope_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY system_scope_select ON public.collection_changes FOR SELECT USING (public.davhaven_is_system());


--
-- Name: feed_tokens system_scope_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY system_scope_select ON public.feed_tokens FOR SELECT USING (public.davhaven_is_system());


--
-- Name: idempotency_keys system_scope_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY system_scope_select ON public.idempotency_keys FOR SELECT USING (public.davhaven_is_system());


--
-- Name: oauth_states system_scope_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY system_scope_select ON public.oauth_states FOR SELECT USING (public.davhaven_is_system());


--
-- Name: outbox system_scope_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY system_scope_select ON public.outbox FOR SELECT USING (public.davhaven_is_system());


--
-- Name: principals system_scope_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY system_scope_select ON public.principals FOR SELECT USING (public.davhaven_is_system());


--
-- Name: principals_sync system_scope_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY system_scope_select ON public.principals_sync FOR SELECT USING (public.davhaven_is_system());


--
-- Name: rsvp_tokens system_scope_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY system_scope_select ON public.rsvp_tokens FOR SELECT USING (public.davhaven_is_system());


--
-- Name: scheduling_inbox system_scope_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY system_scope_select ON public.scheduling_inbox FOR SELECT USING (public.davhaven_is_system());


--
-- Name: webhook_deliveries system_scope_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY system_scope_select ON public.webhook_deliveries FOR SELECT USING (public.davhaven_is_system());


--
-- Name: api_tokens system_scope_update; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY system_scope_update ON public.api_tokens FOR UPDATE USING ((public.davhaven_is_system() AND (kind = 'system'::text))) WITH CHECK ((public.davhaven_is_system() AND (kind = 'system'::text)));


--
-- Name: calendars system_scope_update; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY system_scope_update ON public.calendars FOR UPDATE USING (public.davhaven_is_system()) WITH CHECK (public.davhaven_is_system());


--
-- Name: outbox system_scope_update; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY system_scope_update ON public.outbox FOR UPDATE USING (public.davhaven_is_system()) WITH CHECK (public.davhaven_is_system());


--
-- Name: principals_sync system_scope_update; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY system_scope_update ON public.principals_sync FOR UPDATE USING (public.davhaven_is_system()) WITH CHECK (public.davhaven_is_system());


--
-- Name: audit_events tenant_append; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_append ON public.audit_events FOR INSERT WITH CHECK ((tenant_id = public.davhaven_current_tenant()));


--
-- Name: api_tokens tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.api_tokens USING ((tenant_id = public.davhaven_current_tenant())) WITH CHECK ((tenant_id = public.davhaven_current_tenant()));


--
-- Name: app_passwords tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.app_passwords USING ((tenant_id = public.davhaven_current_tenant())) WITH CHECK ((tenant_id = public.davhaven_current_tenant()));


--
-- Name: calendar_bindings tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.calendar_bindings USING ((tenant_id = public.davhaven_current_tenant())) WITH CHECK ((tenant_id = public.davhaven_current_tenant()));


--
-- Name: calendar_grants tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.calendar_grants USING ((tenant_id = public.davhaven_current_tenant())) WITH CHECK ((tenant_id = public.davhaven_current_tenant()));


--
-- Name: calendar_objects tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.calendar_objects USING ((tenant_id = public.davhaven_current_tenant())) WITH CHECK ((tenant_id = public.davhaven_current_tenant()));


--
-- Name: calendars tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.calendars USING ((tenant_id = public.davhaven_current_tenant())) WITH CHECK ((tenant_id = public.davhaven_current_tenant()));


--
-- Name: collection_changes tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.collection_changes USING ((tenant_id = public.davhaven_current_tenant())) WITH CHECK ((tenant_id = public.davhaven_current_tenant()));


--
-- Name: collection_properties tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.collection_properties USING ((tenant_id = public.davhaven_current_tenant())) WITH CHECK ((tenant_id = public.davhaven_current_tenant()));


--
-- Name: external_accounts tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.external_accounts USING ((tenant_id = public.davhaven_current_tenant())) WITH CHECK ((tenant_id = public.davhaven_current_tenant()));


--
-- Name: feed_tokens tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.feed_tokens USING ((tenant_id = public.davhaven_current_tenant())) WITH CHECK ((tenant_id = public.davhaven_current_tenant()));


--
-- Name: idempotency_keys tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.idempotency_keys USING ((tenant_id = public.davhaven_current_tenant())) WITH CHECK ((tenant_id = public.davhaven_current_tenant()));


--
-- Name: memberships tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.memberships USING ((tenant_id = public.davhaven_current_tenant())) WITH CHECK ((tenant_id = public.davhaven_current_tenant()));


--
-- Name: notifications tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.notifications USING ((tenant_id = public.davhaven_current_tenant())) WITH CHECK ((tenant_id = public.davhaven_current_tenant()));


--
-- Name: oauth_states tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.oauth_states USING ((tenant_id = public.davhaven_current_tenant())) WITH CHECK ((tenant_id = public.davhaven_current_tenant()));


--
-- Name: object_attendees tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.object_attendees USING ((tenant_id = public.davhaven_current_tenant())) WITH CHECK ((tenant_id = public.davhaven_current_tenant()));


--
-- Name: outbox tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.outbox USING ((tenant_id = public.davhaven_current_tenant())) WITH CHECK ((tenant_id = public.davhaven_current_tenant()));


--
-- Name: principal_addresses tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.principal_addresses USING ((tenant_id = public.davhaven_current_tenant())) WITH CHECK ((tenant_id = public.davhaven_current_tenant()));


--
-- Name: principals tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.principals USING ((tenant_id = public.davhaven_current_tenant())) WITH CHECK ((tenant_id = public.davhaven_current_tenant()));


--
-- Name: principals_sync tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.principals_sync USING ((tenant_id = public.davhaven_current_tenant())) WITH CHECK ((tenant_id = public.davhaven_current_tenant()));


--
-- Name: rsvp_tokens tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.rsvp_tokens USING ((tenant_id = public.davhaven_current_tenant())) WITH CHECK ((tenant_id = public.davhaven_current_tenant()));


--
-- Name: scheduling_inbox tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.scheduling_inbox USING ((tenant_id = public.davhaven_current_tenant())) WITH CHECK ((tenant_id = public.davhaven_current_tenant()));


--
-- Name: tenants tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.tenants FOR SELECT USING ((id = public.davhaven_current_tenant()));


--
-- Name: webhook_deliveries tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.webhook_deliveries USING ((tenant_id = public.davhaven_current_tenant())) WITH CHECK ((tenant_id = public.davhaven_current_tenant()));


--
-- Name: webhook_subscriptions tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.webhook_subscriptions USING ((tenant_id = public.davhaven_current_tenant())) WITH CHECK ((tenant_id = public.davhaven_current_tenant()));


--
-- Name: audit_events tenant_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_read ON public.audit_events FOR SELECT USING ((tenant_id = public.davhaven_current_tenant()));


--
-- Name: tenants; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.tenants ENABLE ROW LEVEL SECURITY;

--
-- Name: webhook_deliveries; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.webhook_deliveries ENABLE ROW LEVEL SECURITY;

--
-- Name: webhook_subscriptions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.webhook_subscriptions ENABLE ROW LEVEL SECURITY;

--
-- Name: SCHEMA public; Type: ACL; Schema: -; Owner: -
--

REVOKE USAGE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO davhaven_app;


--
-- Name: FUNCTION davhaven_current_tenant(); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.davhaven_current_tenant() TO davhaven_app;


--
-- Name: FUNCTION davhaven_is_system(); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.davhaven_is_system() TO davhaven_app;


--
-- Name: FUNCTION davhaven_purge_audit(cutoff timestamp with time zone, max_rows integer); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.davhaven_purge_audit(cutoff timestamp with time zone, max_rows integer) FROM PUBLIC;


--
-- Name: TABLE _sqlx_migrations; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public._sqlx_migrations TO davhaven_app;


--
-- Name: TABLE api_tokens; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.api_tokens TO davhaven_app;


--
-- Name: TABLE app_passwords; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.app_passwords TO davhaven_app;


--
-- Name: TABLE audit_events; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT ON TABLE public.audit_events TO davhaven_app;


--
-- Name: TABLE calendar_bindings; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.calendar_bindings TO davhaven_app;


--
-- Name: TABLE calendar_grants; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.calendar_grants TO davhaven_app;


--
-- Name: TABLE calendar_objects; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.calendar_objects TO davhaven_app;


--
-- Name: TABLE calendars; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.calendars TO davhaven_app;


--
-- Name: TABLE collection_changes; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.collection_changes TO davhaven_app;


--
-- Name: TABLE collection_properties; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.collection_properties TO davhaven_app;


--
-- Name: TABLE external_accounts; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.external_accounts TO davhaven_app;


--
-- Name: TABLE feed_tokens; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.feed_tokens TO davhaven_app;


--
-- Name: TABLE idempotency_keys; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.idempotency_keys TO davhaven_app;


--
-- Name: TABLE memberships; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.memberships TO davhaven_app;


--
-- Name: TABLE notifications; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.notifications TO davhaven_app;


--
-- Name: TABLE oauth_states; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.oauth_states TO davhaven_app;


--
-- Name: TABLE object_attendees; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.object_attendees TO davhaven_app;


--
-- Name: TABLE outbox; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.outbox TO davhaven_app;


--
-- Name: TABLE principal_addresses; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.principal_addresses TO davhaven_app;


--
-- Name: TABLE principals; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.principals TO davhaven_app;


--
-- Name: TABLE principals_sync; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.principals_sync TO davhaven_app;


--
-- Name: TABLE rsvp_tokens; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.rsvp_tokens TO davhaven_app;


--
-- Name: TABLE scheduling_inbox; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.scheduling_inbox TO davhaven_app;


--
-- Name: TABLE tenants; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.tenants TO davhaven_app;


--
-- Name: TABLE webhook_deliveries; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.webhook_deliveries TO davhaven_app;


--
-- Name: TABLE webhook_subscriptions; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.webhook_subscriptions TO davhaven_app;


--
-- Name: DEFAULT PRIVILEGES FOR SEQUENCES; Type: DEFAULT ACL; Schema: public; Owner: -
--

ALTER DEFAULT PRIVILEGES FOR ROLE davhaven_owner IN SCHEMA public GRANT SELECT,USAGE ON SEQUENCES TO davhaven_app;


--
-- Name: DEFAULT PRIVILEGES FOR TABLES; Type: DEFAULT ACL; Schema: public; Owner: -
--

ALTER DEFAULT PRIVILEGES FOR ROLE davhaven_owner IN SCHEMA public GRANT SELECT,INSERT,DELETE,UPDATE ON TABLES TO davhaven_app;


--
-- PostgreSQL database dump complete
--


