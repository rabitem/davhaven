//! The column lists of the entity tables, as macros that expand to string literals so that queries stay
//! `&'static str` (`concat!`). Each macro takes a table alias prefix (`""` or `"p."`).
//!
//! The lists name every column the row structs read, in the order of the structs; a migration that adds a column
//! the code does not read needs no change here (R16).

macro_rules! tenant_columns {
    ($p:literal) => {
        concat!(
            $p,
            "id, ",
            $p,
            "slug, ",
            $p,
            "display_name, ",
            $p,
            "login_domain, ",
            $p,
            "status, ",
            $p,
            "settings, ",
            $p,
            "created_at, ",
            $p,
            "updated_at, ",
            $p,
            "version"
        )
    };
}

macro_rules! principal_columns {
    ($p:literal) => {
        concat!(
            $p,
            "tenant_id, ",
            $p,
            "id, ",
            $p,
            "kind, ",
            $p,
            "name, ",
            $p,
            "display_name, ",
            $p,
            "email, ",
            $p,
            "locale, ",
            $p,
            "timezone, ",
            $p,
            "external_ref, ",
            $p,
            "status, ",
            $p,
            "deleted_at, ",
            $p,
            "credential_generation, ",
            $p,
            "created_at, ",
            $p,
            "updated_at, ",
            $p,
            "version"
        )
    };
}

macro_rules! calendar_columns {
    ($p:literal) => {
        concat!(
            $p,
            "tenant_id, ",
            $p,
            "id, ",
            $p,
            "owner_id, ",
            $p,
            "slug, ",
            $p,
            "kind, ",
            $p,
            "display_name, ",
            $p,
            "description, ",
            $p,
            "color, ",
            $p,
            "sort_order, ",
            $p,
            "components, ",
            $p,
            "timezone_ics, ",
            $p,
            "sync_seq, ",
            $p,
            "sync_min_seq, ",
            $p,
            "sync_epoch, ",
            $p,
            "deleted_at, ",
            $p,
            "created_at, ",
            $p,
            "updated_at, ",
            $p,
            "version"
        )
    };
}

macro_rules! binding_columns {
    ($p:literal) => {
        concat!(
            $p,
            "tenant_id, ",
            $p,
            "id, ",
            $p,
            "principal_id, ",
            $p,
            "calendar_id, ",
            $p,
            "slug, ",
            $p,
            "display_name, ",
            $p,
            "color, ",
            $p,
            "sort_order, ",
            $p,
            "schedule_transp, ",
            $p,
            "hidden, ",
            $p,
            "created_at, ",
            $p,
            "updated_at, ",
            $p,
            "version"
        )
    };
}

macro_rules! grant_columns {
    ($p:literal) => {
        concat!(
            $p,
            "tenant_id, ",
            $p,
            "id, ",
            $p,
            "calendar_id, ",
            $p,
            "grantee_id, ",
            $p,
            "access, ",
            $p,
            "status, ",
            $p,
            "source, ",
            $p,
            "required, ",
            $p,
            "invite_uid, ",
            $p,
            "summary, ",
            $p,
            "common_name, ",
            $p,
            "created_at, ",
            $p,
            "updated_at, ",
            $p,
            "version"
        )
    };
}

/// The object columns; `last_end` is read as NULL for infinity (unbounded objects).
macro_rules! object_columns {
    ($p:literal) => {
        concat!(
            $p,
            "tenant_id, ",
            $p,
            "id, ",
            $p,
            "calendar_id, ",
            $p,
            "owner_id, ",
            $p,
            "uri, ",
            $p,
            "uid, ",
            $p,
            "etag, ",
            $p,
            "schedule_tag, ",
            $p,
            "content_hash, ",
            $p,
            "component, ",
            $p,
            "data, ",
            $p,
            "size, ",
            $p,
            "first_start, nullif(",
            $p,
            "last_end, 'infinity'::timestamptz) AS last_end, ",
            $p,
            "is_recurring, ",
            $p,
            "is_scheduling, ",
            $p,
            "organizer_address, ",
            $p,
            "sequence, ",
            $p,
            "class, ",
            $p,
            "external_key, ",
            $p,
            "origin, ",
            $p,
            "created_at, ",
            $p,
            "updated_at, ",
            $p,
            "version"
        )
    };
}

/// The object columns without the iCalendar text (`data` is read as an empty string): the listings that only
/// need names, ETags and index columns (`ObjectRepo::list_index`).
macro_rules! object_head_columns {
    ($p:literal) => {
        concat!(
            $p,
            "tenant_id, ",
            $p,
            "id, ",
            $p,
            "calendar_id, ",
            $p,
            "owner_id, ",
            $p,
            "uri, ",
            $p,
            "uid, ",
            $p,
            "etag, ",
            $p,
            "schedule_tag, ",
            $p,
            "content_hash, ",
            $p,
            "component, ",
            "''::text AS data, ",
            $p,
            "size, ",
            $p,
            "first_start, nullif(",
            $p,
            "last_end, 'infinity'::timestamptz) AS last_end, ",
            $p,
            "is_recurring, ",
            $p,
            "is_scheduling, ",
            $p,
            "organizer_address, ",
            $p,
            "sequence, ",
            $p,
            "class, ",
            $p,
            "external_key, ",
            $p,
            "origin, ",
            $p,
            "created_at, ",
            $p,
            "updated_at, ",
            $p,
            "version"
        )
    };
}

macro_rules! notification_columns {
    ($p:literal) => {
        concat!(
            $p,
            "tenant_id, ",
            $p,
            "id, ",
            $p,
            "principal_id, ",
            $p,
            "uri, ",
            $p,
            "uid, ",
            $p,
            "etag, ",
            $p,
            "type, ",
            $p,
            "body_xml, ",
            $p,
            "created_at, ",
            $p,
            "updated_at, ",
            $p,
            "version"
        )
    };
}

macro_rules! inbox_columns {
    ($p:literal) => {
        concat!(
            $p,
            "tenant_id, ",
            $p,
            "id, ",
            $p,
            "principal_id, ",
            $p,
            "uri, ",
            $p,
            "etag, ",
            $p,
            "data, ",
            $p,
            "quarantined, ",
            $p,
            "created_at, ",
            $p,
            "updated_at, ",
            $p,
            "version"
        )
    };
}

macro_rules! outbox_columns {
    ($p:literal) => {
        concat!(
            $p,
            "tenant_id, ",
            $p,
            "id, ",
            $p,
            "kind, ",
            $p,
            "payload, ",
            $p,
            "schema_version, ",
            $p,
            "status, ",
            $p,
            "attempts, ",
            $p,
            "next_attempt_at, ",
            $p,
            "locked_until, ",
            $p,
            "last_error, ",
            $p,
            "created_at, ",
            $p,
            "updated_at"
        )
    };
}

macro_rules! app_password_columns {
    ($p:literal) => {
        concat!(
            $p,
            "tenant_id, ",
            $p,
            "id, ",
            $p,
            "principal_id, ",
            $p,
            "label, ",
            $p,
            "prefix, ",
            $p,
            "hash, ",
            $p,
            "pepper_kid, ",
            $p,
            "last_used_at, ",
            $p,
            "revoked_at, ",
            $p,
            "created_at, ",
            $p,
            "updated_at, ",
            $p,
            "version"
        )
    };
}

macro_rules! api_token_columns {
    ($p:literal) => {
        concat!(
            $p,
            "tenant_id, ",
            $p,
            "id, ",
            $p,
            "kind, ",
            $p,
            "principal_id, ",
            $p,
            "label, ",
            $p,
            "scopes, ",
            $p,
            "prefix, ",
            $p,
            "hash, ",
            $p,
            "pepper_kid, ",
            $p,
            "expires_at, ",
            $p,
            "created_by, ",
            $p,
            "allowed_origins, ",
            $p,
            "last_used_at, ",
            $p,
            "revoked_at, ",
            $p,
            "created_at, ",
            $p,
            "updated_at, ",
            $p,
            "version"
        )
    };
}

macro_rules! feed_token_columns {
    ($p:literal) => {
        concat!(
            $p,
            "tenant_id, ",
            $p,
            "id, ",
            $p,
            "principal_id, ",
            $p,
            "mode, ",
            $p,
            "calendar_ids, ",
            $p,
            "prefix, ",
            $p,
            "hash, ",
            $p,
            "pepper_kid, ",
            $p,
            "revoked_at, ",
            $p,
            "created_at, ",
            $p,
            "updated_at, ",
            $p,
            "version"
        )
    };
}

macro_rules! rsvp_token_columns {
    ($p:literal) => {
        concat!(
            $p,
            "tenant_id, ",
            $p,
            "id, ",
            $p,
            "object_id, ",
            $p,
            "attendee_address, ",
            $p,
            "prefix, ",
            $p,
            "hash, ",
            $p,
            "pepper_kid, ",
            $p,
            "expires_at, ",
            $p,
            "revoked_at, ",
            $p,
            "last_used_at, ",
            $p,
            "last_response, ",
            $p,
            "created_at, ",
            $p,
            "updated_at, ",
            $p,
            "version"
        )
    };
}

macro_rules! webhook_columns {
    ($p:literal) => {
        concat!(
            $p,
            "tenant_id, ",
            $p,
            "id, ",
            $p,
            "url, ",
            $p,
            "description, ",
            $p,
            "sealed_secret, ",
            $p,
            "sealed_secret_previous, ",
            $p,
            "secret_rotated_at, ",
            $p,
            "events, ",
            $p,
            "include_details, ",
            $p,
            "active, ",
            $p,
            "failure_count, ",
            $p,
            "disabled_reason, ",
            $p,
            "created_at, ",
            $p,
            "updated_at, ",
            $p,
            "version"
        )
    };
}

macro_rules! delivery_columns {
    ($p:literal) => {
        concat!(
            $p,
            "tenant_id, ",
            $p,
            "id, ",
            $p,
            "subscription_id, ",
            $p,
            "event_id, ",
            $p,
            "status, ",
            $p,
            "attempts, ",
            $p,
            "response_status, ",
            $p,
            "last_error, ",
            $p,
            "at, ",
            $p,
            "created_at, ",
            $p,
            "updated_at, ",
            $p,
            "version"
        )
    };
}

macro_rules! external_account_columns {
    ($p:literal) => {
        concat!(
            $p,
            "tenant_id, ",
            $p,
            "id, ",
            $p,
            "principal_id, ",
            $p,
            "provider, ",
            $p,
            "account_ref, ",
            $p,
            "sealed_tokens, ",
            $p,
            "mirror_calendar_id, ",
            $p,
            "sync_state, ",
            $p,
            "status, ",
            $p,
            "last_error, ",
            $p,
            "created_at, ",
            $p,
            "updated_at, ",
            $p,
            "version"
        )
    };
}

macro_rules! oauth_state_columns {
    ($p:literal) => {
        concat!(
            $p,
            "tenant_id, ",
            $p,
            "id, ",
            $p,
            "principal_id, ",
            $p,
            "provider, ",
            $p,
            "state_hash, ",
            $p,
            "pkce_verifier_sealed, ",
            $p,
            "expires_at, ",
            $p,
            "used_at, ",
            $p,
            "created_at"
        )
    };
}

macro_rules! idempotency_columns {
    ($p:literal) => {
        concat!(
            $p,
            "token_id, ",
            $p,
            "key, ",
            $p,
            "method, ",
            $p,
            "path, ",
            $p,
            "fingerprint, ",
            $p,
            "status, ",
            $p,
            "response_status, ",
            $p,
            "response, ",
            $p,
            "expires_at"
        )
    };
}

macro_rules! audit_columns {
    ($p:literal) => {
        concat!(
            $p,
            "tenant_id, ",
            $p,
            "id, ",
            $p,
            "actor, ",
            $p,
            "action, ",
            $p,
            "target, ",
            $p,
            "details, ",
            $p,
            "at"
        )
    };
}
