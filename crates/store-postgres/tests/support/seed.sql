-- Rows for the isolation tests: every tenant table holds at least one row of each of the tenants `a` and `b`, and
-- `api_tokens` holds one system token. The ids are `<tenant letter>0000000-0000-7000-8000-0000000000NN`
-- (`sid('a', 1)`), where NN is the number named in the comments below.
--
-- Written for the CURRENT schema: a migration that adds a tenant table adds its rows here (the isolation test
-- fails while a table has none). The upgrade fixtures in tests/upgrade/ are never edited.

CREATE FUNCTION pg_temp.sid(prefix text, n integer) RETURNS uuid LANGUAGE sql IMMUTABLE AS
$$ SELECT (prefix || '0000000-0000-7000-8000-0000000000' || lpad(n::text, 2, '0'))::uuid $$;

DO $seed$
DECLARE
    p  text;
    ts timestamptz := '2026-10-01T12:00:00Z';
BEGIN
    FOREACH p IN ARRAY ARRAY['a', 'b'] LOOP
        -- 00 tenant
        INSERT INTO tenants (id, slug, display_name, login_domain, status, settings, created_at, updated_at, version)
        VALUES (pg_temp.sid(p, 0), 'tenant-' || p, 'Tenant ' || p, p || '.example', 'active', '{}', ts, ts, 1);

        -- 01 user, 02 group
        INSERT INTO principals (tenant_id, id, kind, name, display_name, email, locale, timezone, external_ref,
                                status, deleted_at, credential_generation, created_at, updated_at, version)
        VALUES (pg_temp.sid(p, 0), pg_temp.sid(p, 1), 'user', 'alice', 'Alice', 'alice@' || p || '.example', 'de',
                'Europe/Berlin', 'ext-alice', 'active', NULL, 0, ts, ts, 1),
               (pg_temp.sid(p, 0), pg_temp.sid(p, 2), 'group', 'staff', 'Staff', NULL, NULL, NULL, NULL,
                'active', NULL, 0, ts, ts, 1);
        INSERT INTO principal_addresses (tenant_id, principal_id, address, is_primary)
        VALUES (pg_temp.sid(p, 0), pg_temp.sid(p, 1), 'mailto:alice@' || p || '.example', true);
        INSERT INTO memberships (tenant_id, group_id, member_id)
        VALUES (pg_temp.sid(p, 0), pg_temp.sid(p, 2), pg_temp.sid(p, 1));
        INSERT INTO principals_sync (tenant_id, principal_id, home_seq, home_min_seq, home_epoch, inbox_seq,
                                     inbox_min_seq, inbox_epoch, notifications_seq, notifications_min_seq,
                                     notifications_epoch)
        VALUES (pg_temp.sid(p, 0), pg_temp.sid(p, 1), 0, 0, pg_temp.sid(p, 90), 0, 0, pg_temp.sid(p, 91), 0, 0,
                pg_temp.sid(p, 92)),
               (pg_temp.sid(p, 0), pg_temp.sid(p, 2), 0, 0, pg_temp.sid(p, 93), 0, 0, pg_temp.sid(p, 94), 0, 0,
                pg_temp.sid(p, 95));

        -- 03 and 21 calendars, 05 binding, 06 property, 07 grant
        INSERT INTO calendars (tenant_id, id, owner_id, slug, kind, display_name, description, color, sort_order,
                               components, timezone_ics, sync_seq, sync_min_seq, sync_epoch, deleted_at,
                               created_at, updated_at, version)
        VALUES (pg_temp.sid(p, 0), pg_temp.sid(p, 3), pg_temp.sid(p, 1), 'personal', 'personal', 'Personal', NULL,
                NULL, 0, ARRAY['VEVENT', 'VTODO'], NULL, 1, 0, pg_temp.sid(p, 96), NULL, ts, ts, 1),
               (pg_temp.sid(p, 0), pg_temp.sid(p, 21), pg_temp.sid(p, 1), 'projects', 'user', 'Projects', NULL,
                NULL, 1, ARRAY['VEVENT'], NULL, 0, 0, pg_temp.sid(p, 97), NULL, ts, ts, 1);
        INSERT INTO calendar_bindings (tenant_id, id, principal_id, calendar_id, slug, display_name, color,
                                       sort_order, schedule_transp, hidden, created_at, updated_at, version)
        VALUES (pg_temp.sid(p, 0), pg_temp.sid(p, 5), pg_temp.sid(p, 1), pg_temp.sid(p, 3), 'personal', NULL, NULL,
                NULL, NULL, false, ts, ts, 1);
        INSERT INTO collection_properties (tenant_id, id, calendar_id, binding_id, ns, name, value_xml)
        VALUES (pg_temp.sid(p, 0), pg_temp.sid(p, 6), pg_temp.sid(p, 3), NULL, 'DAV:', 'displayname', 'Personal');
        INSERT INTO calendar_grants (tenant_id, id, calendar_id, grantee_id, access, status, source, invite_uid,
                                     summary, common_name, created_at, updated_at, version)
        VALUES (pg_temp.sid(p, 0), pg_temp.sid(p, 7), pg_temp.sid(p, 3), pg_temp.sid(p, 2), 'read', 'accepted',
                'api', NULL, NULL, NULL, ts, ts, 1);

        -- 04 object (in calendar 03) with its attendee and its change-log row
        INSERT INTO calendar_objects (tenant_id, id, calendar_id, owner_id, uri, uid, etag, schedule_tag,
                                      content_hash, component, data, size, first_start, last_end, is_recurring,
                                      is_scheduling, organizer_address, sequence, class, external_key, origin,
                                      live, created_at, updated_at, version)
        VALUES (pg_temp.sid(p, 0), pg_temp.sid(p, 4), pg_temp.sid(p, 3), pg_temp.sid(p, 1), 'meeting.ics',
                'meeting-' || p, '"AAAAAAAAAAAAAAAAAAAAAA"', NULL, repeat('0', 64), 'VEVENT',
                E'BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:meeting-' || p
                    || E'\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n',
                100, '2027-03-01T10:00:00Z', '2027-03-01T11:00:00Z', false, false, NULL, 0, 'PUBLIC', NULL, NULL,
                true, ts, ts, 1);
        INSERT INTO object_attendees (tenant_id, object_id, address, principal_id, partstat)
        VALUES (pg_temp.sid(p, 0), pg_temp.sid(p, 4), 'mailto:alice@' || p || '.example', pg_temp.sid(p, 1),
                'NEEDS-ACTION');
        INSERT INTO collection_changes (tenant_id, collection_kind, collection_id, seq, uri, kind, at)
        VALUES (pg_temp.sid(p, 0), 'calendar', pg_temp.sid(p, 3), 1, 'meeting.ics', 'upsert', ts);

        -- 08 notification, 09 inbox item
        INSERT INTO notifications (tenant_id, id, principal_id, uri, uid, etag, type, body_xml, created_at,
                                   updated_at, version)
        VALUES (pg_temp.sid(p, 0), pg_temp.sid(p, 8), pg_temp.sid(p, 1), 'invite.xml', 'invite-' || p,
                '"AAAAAAAAAAAAAAAAAAAAAA"', 'invite', '<x/>', ts, ts, 1);
        INSERT INTO scheduling_inbox (tenant_id, id, principal_id, uri, etag, data, quarantined, created_at,
                                      updated_at, version)
        VALUES (pg_temp.sid(p, 0), pg_temp.sid(p, 9), pg_temp.sid(p, 1), 'request.ics', '"AAAAAAAAAAAAAAAAAAAAAA"',
                'BEGIN:VCALENDAR', false, ts, ts, 1);

        -- 10 outbox message
        INSERT INTO outbox (tenant_id, id, kind, payload, schema_version, status, attempts, next_attempt_at,
                            locked_until, last_error, created_at, updated_at)
        VALUES (pg_temp.sid(p, 0), pg_temp.sid(p, 10), 'provider_push', '{}', 1, 'pending', 0, ts, NULL, NULL, ts, ts);

        -- 11 app password, 12 tenant API token, 13 feed token, 14 RSVP token
        INSERT INTO app_passwords (tenant_id, id, principal_id, label, prefix, hash, pepper_kid, last_used_at,
                                   revoked_at, created_at, updated_at, version)
        VALUES (pg_temp.sid(p, 0), pg_temp.sid(p, 11), pg_temp.sid(p, 1), 'phone', 'ap-' || p, '\x00', 'k1', NULL,
                NULL, ts, ts, 1);
        INSERT INTO api_tokens (tenant_id, id, kind, principal_id, label, scopes, prefix, hash, pepper_kid,
                                expires_at, created_by, allowed_origins, last_used_at, revoked_at, created_at,
                                updated_at, version)
        VALUES (pg_temp.sid(p, 0), pg_temp.sid(p, 12), 'tenant', NULL, 'automation', ARRAY['calendars:read'],
                'at-' || p, '\x00', 'k1', NULL, NULL, ARRAY[]::text[], NULL, NULL, ts, ts, 1);
        INSERT INTO feed_tokens (tenant_id, id, principal_id, mode, calendar_ids, prefix, hash, pepper_kid,
                                 revoked_at, created_at, updated_at, version)
        VALUES (pg_temp.sid(p, 0), pg_temp.sid(p, 13), pg_temp.sid(p, 1), 'busy', ARRAY[pg_temp.sid(p, 3)],
                'ft-' || p, '\x00', 'k1', NULL, ts, ts, 1);
        INSERT INTO rsvp_tokens (tenant_id, id, object_id, attendee_address, prefix, hash, pepper_kid, expires_at,
                                 revoked_at, last_used_at, last_response, created_at, updated_at, version)
        VALUES (pg_temp.sid(p, 0), pg_temp.sid(p, 14), pg_temp.sid(p, 4), 'mailto:alice@' || p || '.example',
                'rt-' || p, '\x00', 'k1', '2027-01-01T00:00:00Z', NULL, NULL, NULL, ts, ts, 1);

        -- 15 external account, 16 OAuth state
        INSERT INTO external_accounts (tenant_id, id, principal_id, provider, account_ref, sealed_tokens,
                                       mirror_calendar_id, sync_state, status, last_error, created_at, updated_at,
                                       version)
        VALUES (pg_temp.sid(p, 0), pg_temp.sid(p, 15), pg_temp.sid(p, 1), 'google', 'alice@gmail.example', '\x00',
                pg_temp.sid(p, 21), '{}', 'active', NULL, ts, ts, 1);
        INSERT INTO oauth_states (tenant_id, id, principal_id, provider, state_hash, pkce_verifier_sealed,
                                  expires_at, used_at, created_at)
        VALUES (pg_temp.sid(p, 0), pg_temp.sid(p, 16), pg_temp.sid(p, 1), 'google', decode('01' || encode(convert_to(p, 'UTF8'), 'hex'), 'hex'),
                '\x00', '2027-01-01T00:00:00Z', NULL, ts);

        -- 17 webhook subscription, 18 delivery
        INSERT INTO webhook_subscriptions (tenant_id, id, url, description, sealed_secret, sealed_secret_previous,
                                           secret_rotated_at, events, include_details, active, failure_count,
                                           disabled_reason, created_at, updated_at, version)
        VALUES (pg_temp.sid(p, 0), pg_temp.sid(p, 17), 'https://hooks.example/' || p, NULL, '\x00', NULL, NULL,
                ARRAY['event.created'], false, true, 0, NULL, ts, ts, 1);
        INSERT INTO webhook_deliveries (tenant_id, id, subscription_id, event_id, status, attempts, response_status,
                                        last_error, at, created_at, updated_at, version)
        VALUES (pg_temp.sid(p, 0), pg_temp.sid(p, 18), pg_temp.sid(p, 17), pg_temp.sid(p, 98), 'pending', 0, NULL,
                NULL, ts, ts, ts, 1);

        -- 19 idempotency key, 20 audit event
        INSERT INTO idempotency_keys (tenant_id, id, token_id, key, method, path, fingerprint, status,
                                      response_status, response, expires_at, created_at, updated_at)
        VALUES (pg_temp.sid(p, 0), pg_temp.sid(p, 19), pg_temp.sid(p, 12), 'key-1', 'POST', '/api/v1/calendars',
                'f', 'in_flight', NULL, NULL, '2027-01-01T00:00:00Z', ts, ts);
        INSERT INTO audit_events (tenant_id, id, actor, action, target, details, at)
        VALUES (pg_temp.sid(p, 0), pg_temp.sid(p, 20), '{"kind": "system", "principal_id": null, "token_id": null, "label": null, "ip_hash": null}', 'tenant.created', NULL, '{}', ts);
    END LOOP;

    -- A system token: no tenant, never visible to a tenant transaction.
    INSERT INTO api_tokens (tenant_id, id, kind, principal_id, label, scopes, prefix, hash, pepper_kid, expires_at,
                            created_by, allowed_origins, last_used_at, revoked_at, created_at, updated_at, version)
    VALUES (NULL, pg_temp.sid('f', 1), 'system', NULL, 'operator', ARRAY['system:tenants'], 'at-system', '\x00', 'k1', NULL,
            NULL, ARRAY[]::text[], NULL, NULL, ts, ts, 1);
END
$seed$;
