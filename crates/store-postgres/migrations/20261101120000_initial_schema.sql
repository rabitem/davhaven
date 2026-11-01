-- Davhaven initial schema (PLAN 2.4, 2.7, ENGINEERING_RULES R4 and R16).
--
-- Runs as the owner role. The owner owns every object; the runtime role only gets what the owner grants it
-- through default privileges (docs/operations/database.md). Rules of this schema:
--
--   * Every tenant table has the primary key (tenant_id, id) (or a documented natural key that starts with
--     tenant_id) and composite foreign keys (tenant_id, x_id), so a cross-tenant reference cannot be inserted.
--   * Row-level security is enabled on every tenant table. The policies compare tenant_id with the
--     `davhaven.tenant_id` setting that a tenant transaction sets with SET LOCAL; the few cross-tenant
--     operations run in a system transaction that sets `davhaven.system` and are admitted by a second policy on
--     the tables they need. The owner is the table owner and is not subject to the policies (migrations,
--     cascading deletes).
--   * Timestamps that logic depends on are written by the application from its Clock, never by DEFAULT now().
--   * Text enumerations of state machines carry CHECK constraints; vocabularies that grow (event types, scopes,
--     iCalendar tokens) do not, so adding a value never needs a migration.
--   * Unique constraints have fixed names; the adapter maps them to UniqueKey (src/error.rs).

-- ---------------------------------------------------------------------------------------------------------------
-- Row-level security helpers
-- ---------------------------------------------------------------------------------------------------------------

-- The tenant a transaction is bound to; NULL (so no row matches) when the setting is absent or empty. A malformed
-- value is not a tenant id and makes the cast fail (invalid_text_representation), so the statement fails closed.
CREATE FUNCTION davhaven_current_tenant() RETURNS uuid
    LANGUAGE sql STABLE PARALLEL SAFE
    AS $$ SELECT nullif(current_setting('davhaven.tenant_id', true), '')::uuid $$;

-- Whether the transaction is a system transaction (cross-tenant operations of the server itself).
CREATE FUNCTION davhaven_is_system() RETURNS boolean
    LANGUAGE sql STABLE PARALLEL SAFE
    AS $$ SELECT coalesce(current_setting('davhaven.system', true), '') = 'on' $$;

-- ---------------------------------------------------------------------------------------------------------------
-- Tenants, principals, memberships
-- ---------------------------------------------------------------------------------------------------------------

CREATE TABLE tenants (
    id           uuid        PRIMARY KEY,
    slug         text        NOT NULL,
    display_name text        NOT NULL,
    login_domain text,
    status       text        NOT NULL CONSTRAINT tenants_status_check CHECK (status IN ('active', 'suspended')),
    settings     jsonb       NOT NULL,
    created_at   timestamptz NOT NULL,
    updated_at   timestamptz NOT NULL,
    version      bigint      NOT NULL
);
CREATE UNIQUE INDEX tenants_slug_key ON tenants (slug);
CREATE UNIQUE INDEX tenants_login_domain_key ON tenants (lower(login_domain)) WHERE login_domain IS NOT NULL;

CREATE TABLE principals (
    tenant_id             uuid        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    id                    uuid        NOT NULL,
    kind                  text        NOT NULL
        CONSTRAINT principals_kind_check CHECK (kind IN ('user', 'group', 'resource', 'service')),
    name                  text        NOT NULL,
    display_name          text        NOT NULL,
    email                 text,
    locale                text,
    timezone              text,
    external_ref          text,
    status                text        NOT NULL
        CONSTRAINT principals_status_check CHECK (status IN ('active', 'suspended', 'deleted')),
    deleted_at            timestamptz,
    credential_generation integer     NOT NULL,
    created_at            timestamptz NOT NULL,
    updated_at            timestamptz NOT NULL,
    version               bigint      NOT NULL,
    CONSTRAINT principals_pkey PRIMARY KEY (tenant_id, id),
    CONSTRAINT principals_name_key UNIQUE (tenant_id, name),
    CONSTRAINT principals_external_ref_key UNIQUE (tenant_id, external_ref)
);
CREATE INDEX principals_status_idx ON principals (status, deleted_at) WHERE status = 'deleted';

-- Calendar user addresses, normalized by the application. Unique per tenant, case-insensitively; the addresses of
-- deleted principals stay reserved until the principal is purged.
CREATE TABLE principal_addresses (
    tenant_id    uuid    NOT NULL,
    principal_id uuid    NOT NULL,
    address      text    NOT NULL,
    is_primary   boolean NOT NULL,
    CONSTRAINT principal_addresses_pkey PRIMARY KEY (tenant_id, principal_id, address),
    CONSTRAINT principal_addresses_principal_fkey FOREIGN KEY (tenant_id, principal_id)
        REFERENCES principals (tenant_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX principal_addresses_address_key ON principal_addresses (tenant_id, lower(address));
CREATE UNIQUE INDEX principal_addresses_primary_key ON principal_addresses (tenant_id, principal_id) WHERE is_primary;

CREATE TABLE memberships (
    tenant_id uuid NOT NULL,
    group_id  uuid NOT NULL,
    member_id uuid NOT NULL,
    CONSTRAINT memberships_pkey PRIMARY KEY (tenant_id, group_id, member_id),
    CONSTRAINT memberships_group_fkey FOREIGN KEY (tenant_id, group_id)
        REFERENCES principals (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT memberships_member_fkey FOREIGN KEY (tenant_id, member_id)
        REFERENCES principals (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX memberships_member_idx ON memberships (tenant_id, member_id);

-- The sync state of the collections that belong to a principal: its calendar home, its scheduling inbox and its
-- notification collection (calendars keep theirs on the calendar row). One row per principal, created with it.
CREATE TABLE principals_sync (
    tenant_id             uuid   NOT NULL,
    principal_id          uuid   NOT NULL,
    home_seq              bigint NOT NULL,
    home_min_seq          bigint NOT NULL,
    home_epoch            uuid   NOT NULL,
    inbox_seq             bigint NOT NULL,
    inbox_min_seq         bigint NOT NULL,
    inbox_epoch           uuid   NOT NULL,
    notifications_seq     bigint NOT NULL,
    notifications_min_seq bigint NOT NULL,
    notifications_epoch   uuid   NOT NULL,
    CONSTRAINT principals_sync_pkey PRIMARY KEY (tenant_id, principal_id),
    CONSTRAINT principals_sync_principal_fkey FOREIGN KEY (tenant_id, principal_id)
        REFERENCES principals (tenant_id, id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------------------------------------------
-- Calendars, bindings, properties, grants
-- ---------------------------------------------------------------------------------------------------------------

CREATE TABLE calendars (
    tenant_id    uuid        NOT NULL,
    id           uuid        NOT NULL,
    owner_id     uuid        NOT NULL,
    slug         text        NOT NULL,
    kind         text        NOT NULL
        CONSTRAINT calendars_kind_check CHECK (kind IN ('personal', 'group', 'managed', 'user', 'mirror')),
    display_name text        NOT NULL,
    description  text,
    color        text,
    sort_order   integer     NOT NULL,
    components   text[]      NOT NULL,
    timezone_ics text,
    sync_seq     bigint      NOT NULL,
    sync_min_seq bigint      NOT NULL,
    sync_epoch   uuid        NOT NULL,
    deleted_at   timestamptz,
    created_at   timestamptz NOT NULL,
    updated_at   timestamptz NOT NULL,
    version      bigint      NOT NULL,
    CONSTRAINT calendars_pkey PRIMARY KEY (tenant_id, id),
    CONSTRAINT calendars_owner_fkey FOREIGN KEY (tenant_id, owner_id)
        REFERENCES principals (tenant_id, id) ON DELETE CASCADE
);
-- The slug is free again once the calendar is soft-deleted.
CREATE UNIQUE INDEX calendars_slug_key ON calendars (tenant_id, owner_id, slug) WHERE deleted_at IS NULL;
CREATE INDEX calendars_deleted_idx ON calendars (deleted_at) WHERE deleted_at IS NOT NULL;

CREATE TABLE calendar_bindings (
    tenant_id      uuid        NOT NULL,
    id             uuid        NOT NULL,
    principal_id   uuid        NOT NULL,
    calendar_id    uuid        NOT NULL,
    slug           text        NOT NULL,
    display_name   text,
    color          text,
    sort_order     integer,
    schedule_transp text,
    hidden         boolean     NOT NULL,
    created_at     timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL,
    version        bigint      NOT NULL,
    CONSTRAINT calendar_bindings_pkey PRIMARY KEY (tenant_id, id),
    CONSTRAINT calendar_bindings_principal_fkey FOREIGN KEY (tenant_id, principal_id)
        REFERENCES principals (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT calendar_bindings_calendar_fkey FOREIGN KEY (tenant_id, calendar_id)
        REFERENCES calendars (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT calendar_bindings_slug_key UNIQUE (tenant_id, principal_id, slug),
    CONSTRAINT calendar_bindings_calendar_key UNIQUE (tenant_id, principal_id, calendar_id),
    -- Target of the composite key of collection_properties: a binding property names its own calendar.
    CONSTRAINT calendar_bindings_calendar_id_key UNIQUE (tenant_id, id, calendar_id)
);
CREATE INDEX calendar_bindings_calendar_idx ON calendar_bindings (tenant_id, calendar_id);

CREATE TABLE collection_properties (
    tenant_id   uuid NOT NULL,
    id          uuid NOT NULL,
    calendar_id uuid NOT NULL,
    binding_id  uuid,
    ns          text NOT NULL,
    name        text NOT NULL,
    value_xml   text NOT NULL,
    CONSTRAINT collection_properties_pkey PRIMARY KEY (tenant_id, id),
    CONSTRAINT collection_properties_calendar_fkey FOREIGN KEY (tenant_id, calendar_id)
        REFERENCES calendars (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT collection_properties_binding_fkey FOREIGN KEY (tenant_id, binding_id, calendar_id)
        REFERENCES calendar_bindings (tenant_id, id, calendar_id) ON DELETE CASCADE
);
-- Two partial indexes because NULL binding ids never collide in a plain unique constraint.
CREATE UNIQUE INDEX collection_properties_shared_key
    ON collection_properties (tenant_id, calendar_id, ns, name) WHERE binding_id IS NULL;
CREATE UNIQUE INDEX collection_properties_binding_key
    ON collection_properties (tenant_id, calendar_id, binding_id, ns, name) WHERE binding_id IS NOT NULL;
CREATE INDEX collection_properties_binding_idx ON collection_properties (tenant_id, binding_id)
    WHERE binding_id IS NOT NULL;

CREATE TABLE calendar_grants (
    tenant_id    uuid        NOT NULL,
    id           uuid        NOT NULL,
    calendar_id  uuid        NOT NULL,
    grantee_id   uuid        NOT NULL,
    access       text        NOT NULL,
    status       text        NOT NULL
        CONSTRAINT calendar_grants_status_check CHECK (status IN ('pending', 'accepted', 'declined')),
    source       text        NOT NULL,
    invite_uid   text,
    summary      text,
    common_name  text,
    -- Set only through the management API: the grantees cannot delete the calendar from a client (403
    -- DAV:need-privileges, DAV:unbind), and the API can restore a binding that was hidden. Client sharing never sets it.
    required     boolean     NOT NULL DEFAULT false,
    created_at   timestamptz NOT NULL,
    updated_at   timestamptz NOT NULL,
    version      bigint      NOT NULL,
    CONSTRAINT calendar_grants_pkey PRIMARY KEY (tenant_id, id),
    CONSTRAINT calendar_grants_calendar_fkey FOREIGN KEY (tenant_id, calendar_id)
        REFERENCES calendars (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT calendar_grants_grantee_fkey FOREIGN KEY (tenant_id, grantee_id)
        REFERENCES principals (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT calendar_grants_grantee_key UNIQUE (tenant_id, calendar_id, grantee_id)
);
CREATE INDEX calendar_grants_grantee_idx ON calendar_grants (tenant_id, grantee_id);
CREATE INDEX calendar_grants_invite_idx ON calendar_grants (tenant_id, invite_uid) WHERE invite_uid IS NOT NULL;

-- ---------------------------------------------------------------------------------------------------------------
-- Calendar objects
-- ---------------------------------------------------------------------------------------------------------------

CREATE TABLE calendar_objects (
    tenant_id         uuid        NOT NULL,
    id                uuid        NOT NULL,
    calendar_id       uuid        NOT NULL,
    -- The calendar's owner, denormalized for the per-owner uniqueness of scheduling objects.
    owner_id          uuid        NOT NULL,
    uri               text        NOT NULL,
    uid               text        NOT NULL,
    etag              text        NOT NULL,
    schedule_tag      text,
    content_hash      text        NOT NULL,
    component         text        NOT NULL,
    -- The client's iCalendar text, verbatim.
    data              text        NOT NULL,
    size              bigint      NOT NULL,
    first_start       timestamptz,
    -- 'infinity' for unbounded and undated objects, so range filters need no NULL branch.
    last_end          timestamptz NOT NULL,
    is_recurring      boolean     NOT NULL,
    is_scheduling     boolean     NOT NULL,
    organizer_address text,
    sequence          integer     NOT NULL,
    class             text        NOT NULL,
    external_key      text,
    origin            text,
    -- False while the calendar is soft-deleted: such objects neither occupy scheduling UIDs nor resolve by id.
    live              boolean     NOT NULL,
    created_at        timestamptz NOT NULL,
    updated_at        timestamptz NOT NULL,
    version           bigint      NOT NULL,
    CONSTRAINT calendar_objects_pkey PRIMARY KEY (tenant_id, id),
    CONSTRAINT calendar_objects_calendar_fkey FOREIGN KEY (tenant_id, calendar_id)
        REFERENCES calendars (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT calendar_objects_owner_fkey FOREIGN KEY (tenant_id, owner_id)
        REFERENCES principals (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT calendar_objects_uri_key UNIQUE (tenant_id, calendar_id, uri),
    CONSTRAINT calendar_objects_uid_key UNIQUE (tenant_id, calendar_id, uid)
);
CREATE UNIQUE INDEX calendar_objects_external_key_key
    ON calendar_objects (tenant_id, calendar_id, external_key) WHERE external_key IS NOT NULL;
-- C:unique-scheduling-object-resource: one scheduling object per owner and UID across the owner's calendars.
CREATE UNIQUE INDEX calendar_objects_scheduling_uid_key
    ON calendar_objects (tenant_id, owner_id, uid) WHERE is_scheduling AND live;
CREATE INDEX calendar_objects_paging_idx ON calendar_objects (tenant_id, calendar_id, id);
CREATE INDEX calendar_objects_first_start_idx ON calendar_objects (tenant_id, calendar_id, first_start);
CREATE INDEX calendar_objects_last_end_idx ON calendar_objects (tenant_id, calendar_id, last_end);
-- The owner foreign key cascades (purging a principal deletes its calendars' objects) and the scheduling-UID lookup
-- by owner needs a usable index: the unique one above is partial.
CREATE INDEX calendar_objects_owner_idx ON calendar_objects (tenant_id, owner_id);

CREATE TABLE object_attendees (
    tenant_id    uuid NOT NULL,
    object_id    uuid NOT NULL,
    address      text NOT NULL,
    -- The internal principal the address resolved to when the object was written; purging the principal clears it.
    principal_id uuid,
    partstat     text NOT NULL,
    CONSTRAINT object_attendees_pkey PRIMARY KEY (tenant_id, object_id, address),
    CONSTRAINT object_attendees_object_fkey FOREIGN KEY (tenant_id, object_id)
        REFERENCES calendar_objects (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT object_attendees_principal_fkey FOREIGN KEY (tenant_id, principal_id)
        REFERENCES principals (tenant_id, id) ON DELETE SET NULL (principal_id)
);
CREATE INDEX object_attendees_address_idx ON object_attendees (tenant_id, address);
CREATE INDEX object_attendees_principal_idx ON object_attendees (tenant_id, principal_id) WHERE principal_id IS NOT NULL;

-- ---------------------------------------------------------------------------------------------------------------
-- Change log (sync tokens)
-- ---------------------------------------------------------------------------------------------------------------

-- The collection is a calendar for kind 'calendar' and a principal otherwise, so there is no foreign key on
-- collection_id; deleting a calendar or principal removes its rows explicitly.
CREATE TABLE collection_changes (
    tenant_id       uuid        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    collection_kind text        NOT NULL
        CONSTRAINT collection_changes_collection_kind_check
            CHECK (collection_kind IN ('calendar', 'home', 'inbox', 'notifications')),
    collection_id   uuid        NOT NULL,
    seq             bigint      NOT NULL,
    uri             text        NOT NULL,
    kind            text        NOT NULL CONSTRAINT collection_changes_kind_check CHECK (kind IN ('upsert', 'delete')),
    at              timestamptz NOT NULL,
    CONSTRAINT collection_changes_pkey PRIMARY KEY (tenant_id, collection_kind, collection_id, seq)
);
CREATE INDEX collection_changes_uri_idx ON collection_changes (tenant_id, collection_kind, collection_id, uri, seq);
CREATE INDEX collection_changes_at_idx ON collection_changes (at);

-- ---------------------------------------------------------------------------------------------------------------
-- CalendarServer notifications and the scheduling inbox
-- ---------------------------------------------------------------------------------------------------------------

CREATE TABLE notifications (
    tenant_id    uuid        NOT NULL,
    id           uuid        NOT NULL,
    principal_id uuid        NOT NULL,
    uri          text        NOT NULL,
    uid          text        NOT NULL,
    etag         text        NOT NULL,
    type         text        NOT NULL,
    body_xml     text        NOT NULL,
    created_at   timestamptz NOT NULL,
    updated_at   timestamptz NOT NULL,
    version      bigint      NOT NULL,
    CONSTRAINT notifications_pkey PRIMARY KEY (tenant_id, id),
    CONSTRAINT notifications_principal_fkey FOREIGN KEY (tenant_id, principal_id)
        REFERENCES principals (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT notifications_uri_key UNIQUE (tenant_id, principal_id, uri)
);
CREATE INDEX notifications_uid_idx ON notifications (tenant_id, principal_id, uid);

CREATE TABLE scheduling_inbox (
    tenant_id    uuid        NOT NULL,
    id           uuid        NOT NULL,
    principal_id uuid        NOT NULL,
    uri          text        NOT NULL,
    etag         text        NOT NULL,
    data         text        NOT NULL,
    quarantined  boolean     NOT NULL,
    created_at   timestamptz NOT NULL,
    updated_at   timestamptz NOT NULL,
    version      bigint      NOT NULL,
    CONSTRAINT scheduling_inbox_pkey PRIMARY KEY (tenant_id, id),
    CONSTRAINT scheduling_inbox_principal_fkey FOREIGN KEY (tenant_id, principal_id)
        REFERENCES principals (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT scheduling_inbox_uri_key UNIQUE (tenant_id, principal_id, uri)
);
CREATE INDEX scheduling_inbox_created_idx ON scheduling_inbox (created_at);

-- ---------------------------------------------------------------------------------------------------------------
-- Outbox
-- ---------------------------------------------------------------------------------------------------------------

CREATE TABLE outbox (
    tenant_id       uuid        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    id              uuid        NOT NULL,
    kind            text        NOT NULL,
    payload         jsonb       NOT NULL,
    schema_version  integer     NOT NULL,
    status          text        NOT NULL
        CONSTRAINT outbox_status_check CHECK (status IN ('pending', 'in_flight', 'done', 'dead')),
    attempts        integer     NOT NULL,
    next_attempt_at timestamptz NOT NULL,
    locked_until    timestamptz,
    last_error      text,
    created_at      timestamptz NOT NULL,
    updated_at      timestamptz NOT NULL,
    CONSTRAINT outbox_pkey PRIMARY KEY (tenant_id, id)
);
CREATE INDEX outbox_due_idx ON outbox (status, next_attempt_at) WHERE status IN ('pending', 'in_flight');
CREATE INDEX outbox_tenant_status_idx ON outbox (tenant_id, status, id);
CREATE INDEX outbox_settled_idx ON outbox (status, updated_at) WHERE status IN ('done', 'dead');

-- ---------------------------------------------------------------------------------------------------------------
-- Credentials
-- ---------------------------------------------------------------------------------------------------------------

CREATE TABLE app_passwords (
    tenant_id    uuid        NOT NULL,
    id           uuid        NOT NULL,
    principal_id uuid        NOT NULL,
    label        text        NOT NULL,
    prefix       text        NOT NULL,
    hash         bytea       NOT NULL,
    pepper_kid   text        NOT NULL,
    last_used_at timestamptz,
    revoked_at   timestamptz,
    created_at   timestamptz NOT NULL,
    updated_at   timestamptz NOT NULL,
    version      bigint      NOT NULL,
    CONSTRAINT app_passwords_pkey PRIMARY KEY (tenant_id, id),
    CONSTRAINT app_passwords_principal_fkey FOREIGN KEY (tenant_id, principal_id)
        REFERENCES principals (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT app_passwords_prefix_key UNIQUE (prefix)
);
CREATE INDEX app_passwords_principal_idx ON app_passwords (tenant_id, principal_id, id);

-- tenant_id is NULL for system tokens only, so the primary key is the id alone; (tenant_id, id) stays unique for
-- the foreign keys of tenant tables. created_by names the token that minted this one and is a plain foreign key on
-- the token id: the application mints tokens inside one tenant (or from a system token), the schema does not
-- restrict which token may be named.
CREATE TABLE api_tokens (
    tenant_id       uuid,
    id              uuid        PRIMARY KEY,
    kind            text        NOT NULL
        CONSTRAINT api_tokens_kind_check CHECK (kind IN ('system', 'tenant', 'principal')),
    principal_id    uuid,
    label           text        NOT NULL,
    scopes          text[]      NOT NULL,
    prefix          text        NOT NULL,
    hash            bytea       NOT NULL,
    pepper_kid      text        NOT NULL,
    expires_at      timestamptz,
    created_by      uuid        REFERENCES api_tokens (id) ON DELETE SET NULL,
    allowed_origins text[]      NOT NULL,
    last_used_at    timestamptz,
    revoked_at      timestamptz,
    created_at      timestamptz NOT NULL,
    updated_at      timestamptz NOT NULL,
    version         bigint      NOT NULL,
    CONSTRAINT api_tokens_tenant_fkey FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT api_tokens_principal_fkey FOREIGN KEY (tenant_id, principal_id)
        REFERENCES principals (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT api_tokens_tenant_id_key UNIQUE (tenant_id, id),
    CONSTRAINT api_tokens_prefix_key UNIQUE (prefix),
    CONSTRAINT api_tokens_system_check CHECK ((kind = 'system') = (tenant_id IS NULL)),
    -- A principal token acts as its principal; tenant and system tokens act as no principal.
    CONSTRAINT api_tokens_principal_check CHECK ((kind = 'principal') = (principal_id IS NOT NULL))
);
CREATE INDEX api_tokens_principal_idx ON api_tokens (tenant_id, principal_id) WHERE principal_id IS NOT NULL;

CREATE TABLE feed_tokens (
    tenant_id    uuid        NOT NULL,
    id           uuid        NOT NULL,
    principal_id uuid        NOT NULL,
    mode         text        NOT NULL,
    calendar_ids uuid[]      NOT NULL,
    prefix       text        NOT NULL,
    hash         bytea       NOT NULL,
    pepper_kid   text        NOT NULL,
    revoked_at   timestamptz,
    created_at   timestamptz NOT NULL,
    updated_at   timestamptz NOT NULL,
    version      bigint      NOT NULL,
    CONSTRAINT feed_tokens_pkey PRIMARY KEY (tenant_id, id),
    CONSTRAINT feed_tokens_principal_fkey FOREIGN KEY (tenant_id, principal_id)
        REFERENCES principals (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT feed_tokens_prefix_key UNIQUE (prefix)
);
CREATE INDEX feed_tokens_principal_idx ON feed_tokens (tenant_id, principal_id, id);

CREATE TABLE rsvp_tokens (
    tenant_id        uuid        NOT NULL,
    id               uuid        NOT NULL,
    object_id        uuid        NOT NULL,
    attendee_address text        NOT NULL,
    prefix           text        NOT NULL,
    hash             bytea       NOT NULL,
    pepper_kid       text        NOT NULL,
    expires_at       timestamptz NOT NULL,
    revoked_at       timestamptz,
    last_used_at     timestamptz,
    last_response    text,
    created_at       timestamptz NOT NULL,
    updated_at       timestamptz NOT NULL,
    version          bigint      NOT NULL,
    CONSTRAINT rsvp_tokens_pkey PRIMARY KEY (tenant_id, id),
    CONSTRAINT rsvp_tokens_object_fkey FOREIGN KEY (tenant_id, object_id)
        REFERENCES calendar_objects (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT rsvp_tokens_prefix_key UNIQUE (prefix)
);
CREATE INDEX rsvp_tokens_object_idx ON rsvp_tokens (tenant_id, object_id, id);
CREATE INDEX rsvp_tokens_address_idx ON rsvp_tokens (tenant_id, attendee_address);
CREATE INDEX rsvp_tokens_expiry_idx ON rsvp_tokens (expires_at);
-- Retention removes expired tokens and, separately, revoked ones (two statements, each with its own index).
CREATE INDEX rsvp_tokens_revoked_idx ON rsvp_tokens (revoked_at) WHERE revoked_at IS NOT NULL;

-- ---------------------------------------------------------------------------------------------------------------
-- Providers, webhooks, OAuth
-- ---------------------------------------------------------------------------------------------------------------

CREATE TABLE external_accounts (
    tenant_id          uuid        NOT NULL,
    id                 uuid        NOT NULL,
    principal_id       uuid        NOT NULL,
    provider           text        NOT NULL,
    account_ref        text        NOT NULL,
    sealed_tokens      bytea       NOT NULL,
    mirror_calendar_id uuid,
    sync_state         jsonb       NOT NULL,
    status             text        NOT NULL,
    last_error         text,
    created_at         timestamptz NOT NULL,
    updated_at         timestamptz NOT NULL,
    version            bigint      NOT NULL,
    CONSTRAINT external_accounts_pkey PRIMARY KEY (tenant_id, id),
    CONSTRAINT external_accounts_principal_fkey FOREIGN KEY (tenant_id, principal_id)
        REFERENCES principals (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT external_accounts_calendar_fkey FOREIGN KEY (tenant_id, mirror_calendar_id)
        REFERENCES calendars (tenant_id, id) ON DELETE SET NULL (mirror_calendar_id)
);
CREATE INDEX external_accounts_principal_idx ON external_accounts (tenant_id, principal_id, id);

CREATE TABLE oauth_states (
    tenant_id            uuid        NOT NULL,
    id                   uuid        NOT NULL,
    principal_id         uuid        NOT NULL,
    provider             text        NOT NULL,
    state_hash           bytea       NOT NULL,
    pkce_verifier_sealed bytea       NOT NULL,
    expires_at           timestamptz NOT NULL,
    used_at              timestamptz,
    created_at           timestamptz NOT NULL,
    CONSTRAINT oauth_states_pkey PRIMARY KEY (tenant_id, id),
    CONSTRAINT oauth_states_principal_fkey FOREIGN KEY (tenant_id, principal_id)
        REFERENCES principals (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT oauth_states_hash_key UNIQUE (state_hash)
);
CREATE INDEX oauth_states_expiry_idx ON oauth_states (expires_at);

CREATE TABLE webhook_subscriptions (
    tenant_id              uuid        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    id                     uuid        NOT NULL,
    url                    text        NOT NULL,
    description            text,
    sealed_secret          bytea       NOT NULL,
    sealed_secret_previous bytea,
    secret_rotated_at      timestamptz,
    events                 text[]      NOT NULL,
    include_details       boolean     NOT NULL,
    active                 boolean     NOT NULL,
    failure_count          integer     NOT NULL,
    disabled_reason        text,
    created_at             timestamptz NOT NULL,
    updated_at             timestamptz NOT NULL,
    version                bigint      NOT NULL,
    CONSTRAINT webhook_subscriptions_pkey PRIMARY KEY (tenant_id, id)
);

CREATE TABLE webhook_deliveries (
    tenant_id       uuid        NOT NULL,
    id              uuid        NOT NULL,
    subscription_id uuid        NOT NULL,
    event_id        uuid        NOT NULL,
    status          text        NOT NULL,
    attempts        integer     NOT NULL,
    response_status integer,
    last_error      text,
    at              timestamptz NOT NULL,
    created_at      timestamptz NOT NULL,
    updated_at      timestamptz NOT NULL,
    version         bigint      NOT NULL,
    CONSTRAINT webhook_deliveries_pkey PRIMARY KEY (tenant_id, id),
    CONSTRAINT webhook_deliveries_subscription_fkey FOREIGN KEY (tenant_id, subscription_id)
        REFERENCES webhook_subscriptions (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX webhook_deliveries_subscription_idx ON webhook_deliveries (tenant_id, subscription_id, id);
-- One delivery per event and subscription: a repeated fan-out of the same event finds the record it made before.
CREATE UNIQUE INDEX webhook_deliveries_event_key ON webhook_deliveries (tenant_id, subscription_id, event_id);
-- Retention removes deliveries by age.
CREATE INDEX webhook_deliveries_created_idx ON webhook_deliveries (created_at);

-- ---------------------------------------------------------------------------------------------------------------
-- Idempotency keys and the audit log
-- ---------------------------------------------------------------------------------------------------------------

-- token_id has no foreign key: keys expire after a day and system tokens (no tenant) never use them.
-- lease_until is the end of the lease of an in-flight key: a claim takes over a key whose claimant did not finish
-- within the lease (the process died), so a client's retry is never locked out until expires_at. NULL once done.
CREATE TABLE idempotency_keys (
    tenant_id       uuid        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    id              uuid        NOT NULL,
    token_id        uuid        NOT NULL,
    key             text        NOT NULL,
    method          text        NOT NULL,
    path            text        NOT NULL,
    fingerprint     text        NOT NULL,
    status          text        NOT NULL
        CONSTRAINT idempotency_keys_status_check CHECK (status IN ('in_flight', 'done')),
    response_status integer,
    response        jsonb,
    lease_until     timestamptz,
    expires_at      timestamptz NOT NULL,
    created_at      timestamptz NOT NULL,
    updated_at      timestamptz NOT NULL,
    CONSTRAINT idempotency_keys_pkey PRIMARY KEY (tenant_id, id),
    CONSTRAINT idempotency_keys_key UNIQUE (tenant_id, token_id, key)
);
CREATE INDEX idempotency_keys_expiry_idx ON idempotency_keys (expires_at);

-- The audit log is append-only for the runtime role (INSERT and SELECT; see the end of this file) and has no
-- foreign key to the tenant, so the record of a tenant's deletion outlives the tenant until retention removes it.
CREATE TABLE audit_events (
    tenant_id uuid        NOT NULL,
    id        uuid        NOT NULL,
    actor     jsonb       NOT NULL,
    action    text        NOT NULL,
    target    text,
    details   jsonb       NOT NULL,
    at        timestamptz NOT NULL,
    CONSTRAINT audit_events_pkey PRIMARY KEY (tenant_id, id)
);
CREATE INDEX audit_events_at_idx ON audit_events (at);
CREATE INDEX audit_events_action_idx ON audit_events (tenant_id, action, id);

-- ---------------------------------------------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------------------------------------------

-- Tenant isolation: every row of a tenant table is visible and writable only inside a transaction bound to its
-- tenant. The runtime role is NOBYPASSRLS and is not the table owner, so these policies always apply to it.
ALTER TABLE principals ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON principals
    USING (tenant_id = davhaven_current_tenant()) WITH CHECK (tenant_id = davhaven_current_tenant());
ALTER TABLE principal_addresses ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON principal_addresses
    USING (tenant_id = davhaven_current_tenant()) WITH CHECK (tenant_id = davhaven_current_tenant());
ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON memberships
    USING (tenant_id = davhaven_current_tenant()) WITH CHECK (tenant_id = davhaven_current_tenant());
ALTER TABLE principals_sync ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON principals_sync
    USING (tenant_id = davhaven_current_tenant()) WITH CHECK (tenant_id = davhaven_current_tenant());
ALTER TABLE calendars ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON calendars
    USING (tenant_id = davhaven_current_tenant()) WITH CHECK (tenant_id = davhaven_current_tenant());
ALTER TABLE calendar_bindings ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON calendar_bindings
    USING (tenant_id = davhaven_current_tenant()) WITH CHECK (tenant_id = davhaven_current_tenant());
ALTER TABLE collection_properties ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON collection_properties
    USING (tenant_id = davhaven_current_tenant()) WITH CHECK (tenant_id = davhaven_current_tenant());
ALTER TABLE calendar_grants ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON calendar_grants
    USING (tenant_id = davhaven_current_tenant()) WITH CHECK (tenant_id = davhaven_current_tenant());
ALTER TABLE calendar_objects ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON calendar_objects
    USING (tenant_id = davhaven_current_tenant()) WITH CHECK (tenant_id = davhaven_current_tenant());
ALTER TABLE object_attendees ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON object_attendees
    USING (tenant_id = davhaven_current_tenant()) WITH CHECK (tenant_id = davhaven_current_tenant());
ALTER TABLE collection_changes ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON collection_changes
    USING (tenant_id = davhaven_current_tenant()) WITH CHECK (tenant_id = davhaven_current_tenant());
ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON notifications
    USING (tenant_id = davhaven_current_tenant()) WITH CHECK (tenant_id = davhaven_current_tenant());
ALTER TABLE scheduling_inbox ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON scheduling_inbox
    USING (tenant_id = davhaven_current_tenant()) WITH CHECK (tenant_id = davhaven_current_tenant());
ALTER TABLE outbox ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON outbox
    USING (tenant_id = davhaven_current_tenant()) WITH CHECK (tenant_id = davhaven_current_tenant());
ALTER TABLE app_passwords ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON app_passwords
    USING (tenant_id = davhaven_current_tenant()) WITH CHECK (tenant_id = davhaven_current_tenant());
-- System tokens (tenant_id NULL) never match, so tenant transactions cannot see them.
ALTER TABLE api_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON api_tokens
    USING (tenant_id = davhaven_current_tenant()) WITH CHECK (tenant_id = davhaven_current_tenant());
ALTER TABLE feed_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON feed_tokens
    USING (tenant_id = davhaven_current_tenant()) WITH CHECK (tenant_id = davhaven_current_tenant());
ALTER TABLE rsvp_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON rsvp_tokens
    USING (tenant_id = davhaven_current_tenant()) WITH CHECK (tenant_id = davhaven_current_tenant());
ALTER TABLE external_accounts ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON external_accounts
    USING (tenant_id = davhaven_current_tenant()) WITH CHECK (tenant_id = davhaven_current_tenant());
ALTER TABLE oauth_states ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON oauth_states
    USING (tenant_id = davhaven_current_tenant()) WITH CHECK (tenant_id = davhaven_current_tenant());
ALTER TABLE webhook_subscriptions ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON webhook_subscriptions
    USING (tenant_id = davhaven_current_tenant()) WITH CHECK (tenant_id = davhaven_current_tenant());
ALTER TABLE webhook_deliveries ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON webhook_deliveries
    USING (tenant_id = davhaven_current_tenant()) WITH CHECK (tenant_id = davhaven_current_tenant());
ALTER TABLE idempotency_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON idempotency_keys
    USING (tenant_id = davhaven_current_tenant()) WITH CHECK (tenant_id = davhaven_current_tenant());

-- The tenant row itself: a tenant transaction reads its own row and never writes it.
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenants FOR SELECT USING (id = davhaven_current_tenant());

-- The audit log: a tenant transaction appends and reads its own records. There is no UPDATE or DELETE policy, so
-- even a privilege granted by mistake cannot change a record.
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_read ON audit_events FOR SELECT USING (tenant_id = davhaven_current_tenant());
CREATE POLICY tenant_append ON audit_events FOR INSERT WITH CHECK (tenant_id = davhaven_current_tenant());

-- System scope: the cross-tenant operations of the server (tenant management, credential lookup before the tenant
-- is known, the outbox queue, retention). Only the tables those operations touch have a system policy, and each
-- policy admits one command, exactly the ones the operations of `repos/system.rs` run (a test pins the list and
-- proves that every other command is refused):
--   tenants                                  all commands (tenant management)
--   audit_events                             SELECT (the oldest record, for monitoring the audit purge); INSERT
--                                            only `tenant.created` and `tenant.settings_changed` of a tenant
--                                            that exists, so the record commits with the tenant change
--   principals, app_passwords, feed_tokens   SELECT (credential lookup; the principals due for purging)
--   api_tokens                               SELECT (lookup); INSERT and UPDATE only for system tokens
--   calendars, principals_sync               SELECT, UPDATE (sync epochs, minimum sequence numbers, due purges)
--   collection_changes                       SELECT, INSERT, DELETE (retention logs inbox expiry, prunes the log)
--   scheduling_inbox                         SELECT, DELETE (retention)
--   outbox                                   SELECT, UPDATE, DELETE (claim, settle, retention); no INSERT
--   rsvp_tokens, oauth_states,               SELECT, DELETE (lookup and retention)
--   idempotency_keys, webhook_deliveries
-- A system transaction therefore cannot create or delete a calendar (the cascade would remove its objects), forge
-- outbox work, inbox items or RSVP links, or change a tenant or principal token.
CREATE POLICY system_scope ON tenants USING (davhaven_is_system()) WITH CHECK (davhaven_is_system());

-- The audit log has no foreign key to the tenants on purpose (deleting a tenant keeps its log); the EXISTS check is
-- what keeps a record for a tenant that never existed, or under another tenant's name, out. The select policy lets the
-- cleanup worker read the first row of audit_events_at_idx across tenants (davhaven_audit_oldest_event_timestamp_seconds).
CREATE POLICY system_scope_select ON audit_events FOR SELECT USING (davhaven_is_system());
CREATE POLICY system_scope_insert ON audit_events FOR INSERT
    WITH CHECK (
        davhaven_is_system()
        AND action IN ('tenant.created', 'tenant.settings_changed')
        AND EXISTS (SELECT 1 FROM tenants t WHERE t.id = audit_events.tenant_id));

CREATE POLICY system_scope_select ON principals FOR SELECT USING (davhaven_is_system());
CREATE POLICY system_scope_select ON app_passwords FOR SELECT USING (davhaven_is_system());
CREATE POLICY system_scope_select ON feed_tokens FOR SELECT USING (davhaven_is_system());

CREATE POLICY system_scope_select ON api_tokens FOR SELECT USING (davhaven_is_system());
CREATE POLICY system_scope_insert ON api_tokens FOR INSERT
    WITH CHECK (davhaven_is_system() AND tenant_id IS NULL AND kind = 'system');
CREATE POLICY system_scope_update ON api_tokens FOR UPDATE
    USING (davhaven_is_system() AND kind = 'system') WITH CHECK (davhaven_is_system() AND kind = 'system');

CREATE POLICY system_scope_select ON calendars FOR SELECT USING (davhaven_is_system());
CREATE POLICY system_scope_update ON calendars FOR UPDATE
    USING (davhaven_is_system()) WITH CHECK (davhaven_is_system());
CREATE POLICY system_scope_select ON principals_sync FOR SELECT USING (davhaven_is_system());
CREATE POLICY system_scope_update ON principals_sync FOR UPDATE
    USING (davhaven_is_system()) WITH CHECK (davhaven_is_system());

CREATE POLICY system_scope_select ON collection_changes FOR SELECT USING (davhaven_is_system());
CREATE POLICY system_scope_insert ON collection_changes FOR INSERT WITH CHECK (davhaven_is_system());
CREATE POLICY system_scope_delete ON collection_changes FOR DELETE USING (davhaven_is_system());

CREATE POLICY system_scope_select ON scheduling_inbox FOR SELECT USING (davhaven_is_system());
CREATE POLICY system_scope_delete ON scheduling_inbox FOR DELETE USING (davhaven_is_system());

CREATE POLICY system_scope_select ON outbox FOR SELECT USING (davhaven_is_system());
CREATE POLICY system_scope_update ON outbox FOR UPDATE
    USING (davhaven_is_system()) WITH CHECK (davhaven_is_system());
CREATE POLICY system_scope_delete ON outbox FOR DELETE USING (davhaven_is_system());

CREATE POLICY system_scope_select ON rsvp_tokens FOR SELECT USING (davhaven_is_system());
CREATE POLICY system_scope_delete ON rsvp_tokens FOR DELETE USING (davhaven_is_system());
CREATE POLICY system_scope_select ON oauth_states FOR SELECT USING (davhaven_is_system());
CREATE POLICY system_scope_delete ON oauth_states FOR DELETE USING (davhaven_is_system());
CREATE POLICY system_scope_select ON idempotency_keys FOR SELECT USING (davhaven_is_system());
CREATE POLICY system_scope_delete ON idempotency_keys FOR DELETE USING (davhaven_is_system());
CREATE POLICY system_scope_select ON webhook_deliveries FOR SELECT USING (davhaven_is_system());
CREATE POLICY system_scope_delete ON webhook_deliveries FOR DELETE USING (davhaven_is_system());

-- ---------------------------------------------------------------------------------------------------------------
-- Audit retention and the role model
-- ---------------------------------------------------------------------------------------------------------------

-- The only path that deletes audit records (retention). The runtime role has no DELETE privilege on audit_events.
-- This function runs with the owner's rights, removes records older than the cut-off and takes at most `max_rows`
-- per call. It is NOT granted to the runtime role: a role that may call it can wipe the audit trail of every
-- tenant with one statement, which is exactly what the append-only log must prevent. Retention runs it as the
-- owner (a scheduled job with the migration credentials), or the operator opts in to run it from the server with
-- an explicit GRANT EXECUTE (docs/operations/database.md, "Audit log retention").
CREATE FUNCTION davhaven_purge_audit(cutoff timestamptz, max_rows integer) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
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
REVOKE ALL ON FUNCTION davhaven_purge_audit(timestamptz, integer) FROM PUBLIC;

-- Role model (docs/operations/database.md). The owner grants the runtime role data access through default
-- privileges (ALTER DEFAULT PRIVILEGES FOR ROLE owner ...), so every new table is usable without a grant step.
-- This block takes back what must not be writable and gives the runtime role the functions it calls. It finds
-- the runtime role(s) through the owner's default privileges and therefore needs no role name. When no default
-- privileges exist (a manual setup), it does nothing and the operator grants explicitly after migrating.
DO $roles$
DECLARE
    grantee name;
BEGIN
    FOR grantee IN
        SELECT DISTINCT r.rolname
        FROM pg_default_acl d
        CROSS JOIN LATERAL aclexplode(d.defaclacl) a
        JOIN pg_roles r ON r.oid = a.grantee
        WHERE d.defaclrole = (SELECT oid FROM pg_roles WHERE rolname = current_user)
          AND d.defaclobjtype = 'r'
          AND r.rolname <> current_user
    LOOP
        -- TRUNCATE bypasses row-level security, and REFERENCES and TRIGGER have no use at runtime: the runtime role
        -- reads and writes rows, nothing more (a blanket GRANT ALL by an operator is undone here).
        EXECUTE format('REVOKE TRUNCATE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA public FROM %I', grantee);
        -- Append-only audit log.
        EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM %I', grantee);
        -- The migration history belongs to the migration role; the runtime role may only read it (readiness).
        EXECUTE format('REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON _sqlx_migrations FROM %I', grantee);
        -- The row-level security helpers. davhaven_purge_audit is deliberately not granted (see above).
        EXECUTE format('GRANT EXECUTE ON FUNCTION davhaven_current_tenant() TO %I', grantee);
        EXECUTE format('GRANT EXECUTE ON FUNCTION davhaven_is_system() TO %I', grantee);
    END LOOP;
END
$roles$;
