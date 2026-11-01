-- Upgrade fixture: the standard dataset as the release whose newest migration is 20261101120000 stores it.
--
-- tests/upgrade.rs creates a database, applies the migrations up to the version in this file's name, runs this
-- script (as the owner role, with plain INSERTs against that schema), applies every later migration and then
-- reads the dataset back through the store adapter. The expectations are the same for every fixture, so a new
-- release adds ONE file here (the dataset in its schema) and a migration PR never edits an existing one.
--
-- The dataset: tenant `acme` (login domain acme.example) with the user `olivia` and the group `team` (olivia is a
-- member), olivia's calendars `personal` (sequence 4: a.ics, b.ics, c.ics created, c.ics deleted) and `projects`,
-- a binding, a grant to the group, a property, the notification collection, the scheduling inbox, an app password,
-- a tenant API token, a system API token, an outbox message and an audit record.
--
-- Ids are 01900000-0000-7000-8000-0000000000NN with NN as noted.

-- 0a tenant
INSERT INTO tenants (id, slug, display_name, login_domain, status, settings, created_at, updated_at, version)
VALUES ('01900000-0000-7000-8000-00000000000a', 'acme', 'Acme GmbH', 'acme.example', 'active', '{}',
        '2026-10-01T08:00:00Z', '2026-10-01T08:00:00Z', 1);

-- 01 olivia, 02 team
INSERT INTO principals (tenant_id, id, kind, name, display_name, email, locale, timezone, external_ref, status,
                        deleted_at, credential_generation, created_at, updated_at, version)
VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000001', 'user', 'olivia',
        'Olivia Ostermann', 'olivia@acme.example', 'de', 'Europe/Berlin', 'ldap:olivia', 'active', NULL, 2,
        '2026-10-01T08:01:00Z', '2026-10-02T09:00:00Z', 3),
       ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000002', 'group', 'team',
        'The Team', NULL, NULL, NULL, NULL, 'active', NULL, 0, '2026-10-01T08:02:00Z', '2026-10-01T08:02:00Z', 1);
INSERT INTO principal_addresses (tenant_id, principal_id, address, is_primary)
VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000001',
        'mailto:olivia@acme.example', true),
       ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000001',
        'mailto:o.ostermann@acme.example', false);
INSERT INTO memberships (tenant_id, group_id, member_id)
VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000002',
        '01900000-0000-7000-8000-000000000001');
INSERT INTO principals_sync (tenant_id, principal_id, home_seq, home_min_seq, home_epoch, inbox_seq, inbox_min_seq,
                             inbox_epoch, notifications_seq, notifications_min_seq, notifications_epoch)
VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000001', 1, 0,
        '01900000-0000-7000-8000-0000000000e2', 1, 0, '01900000-0000-7000-8000-0000000000e3', 1, 0,
        '01900000-0000-7000-8000-0000000000e4'),
       ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000002', 0, 0,
        '01900000-0000-7000-8000-0000000000e5', 0, 0, '01900000-0000-7000-8000-0000000000e6', 0, 0,
        '01900000-0000-7000-8000-0000000000e7');

-- 03 personal, 04 projects, 05 binding, 06 grant, 07 property
INSERT INTO calendars (tenant_id, id, owner_id, slug, kind, display_name, description, color, sort_order,
                       components, timezone_ics, sync_seq, sync_min_seq, sync_epoch, deleted_at, created_at,
                       updated_at, version)
VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000003',
        '01900000-0000-7000-8000-000000000001', 'personal', 'personal', 'Olivia', 'Private appointments',
        '#336699', 0, ARRAY['VEVENT', 'VTODO'], NULL, 4, 0, '01900000-0000-7000-8000-0000000000e1', NULL,
        '2026-10-01T08:03:00Z', '2026-10-02T10:00:00Z', 5),
       ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000004',
        '01900000-0000-7000-8000-000000000001', 'projects', 'user', 'Projects', NULL, NULL, 1, ARRAY['VEVENT'],
        NULL, 0, 0, '01900000-0000-7000-8000-0000000000e8', NULL, '2026-10-01T08:04:00Z', '2026-10-01T08:04:00Z', 1);
INSERT INTO calendar_bindings (tenant_id, id, principal_id, calendar_id, slug, display_name, color, sort_order,
                               schedule_transp, hidden, created_at, updated_at, version)
VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000005',
        '01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-000000000003', 'personal', NULL, NULL,
        NULL, NULL, false, '2026-10-01T08:03:00Z', '2026-10-01T08:03:00Z', 1);
INSERT INTO calendar_grants (tenant_id, id, calendar_id, grantee_id, access, status, source, invite_uid, summary,
                             common_name, created_at, updated_at, version)
VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000006',
        '01900000-0000-7000-8000-000000000003', '01900000-0000-7000-8000-000000000002', 'read_write', 'accepted',
        'api', NULL, NULL, NULL, '2026-10-01T08:05:00Z', '2026-10-01T08:05:00Z', 1);
INSERT INTO collection_properties (tenant_id, id, calendar_id, binding_id, ns, name, value_xml)
VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000007',
        '01900000-0000-7000-8000-000000000003', NULL, 'urn:example', 'note', '<note xmlns="urn:example">hi</note>');

-- 11 a.ics (change 1) and 12 b.ics (change 2); c.ics was created (change 3) and deleted (change 4)
INSERT INTO calendar_objects (tenant_id, id, calendar_id, owner_id, uri, uid, etag, schedule_tag, content_hash,
                              component, data, size, first_start, last_end, is_recurring, is_scheduling,
                              organizer_address, sequence, class, external_key, origin, live, created_at,
                              updated_at, version)
VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000011',
        '01900000-0000-7000-8000-000000000003', '01900000-0000-7000-8000-000000000001', 'a.ics', 'uid-a',
        '"aaaaaaaaaaaaaaaaaaaaaa"', NULL,
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'VEVENT',
        E'BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:uid-a\r\nSUMMARY:A\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n',
        84, '2027-03-01T10:00:00Z', '2027-03-01T11:00:00Z', false, false, NULL, 0, 'PUBLIC', 'ext-a', 'api', true,
        '2026-10-02T09:00:00Z', '2026-10-02T09:00:00Z', 1),
       ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000012',
        '01900000-0000-7000-8000-000000000003', '01900000-0000-7000-8000-000000000001', 'b.ics', 'uid-b',
        '"bbbbbbbbbbbbbbbbbbbbbb"', '"sched-b"',
        'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'VEVENT',
        E'BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:uid-b\r\nSUMMARY:B\r\nRRULE:FREQ=WEEKLY\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n',
        104, '2027-03-02T10:00:00Z', 'infinity', true, true, 'mailto:olivia@acme.example', 2, 'PRIVATE', NULL,
        NULL, true, '2026-10-02T09:30:00Z', '2026-10-02T09:45:00Z', 2);
INSERT INTO object_attendees (tenant_id, object_id, address, principal_id, partstat)
VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000012',
        'mailto:olivia@acme.example', '01900000-0000-7000-8000-000000000001', 'ACCEPTED'),
       ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000012',
        'mailto:guest@elsewhere.example', NULL, 'NEEDS-ACTION');
INSERT INTO collection_changes (tenant_id, collection_kind, collection_id, seq, uri, kind, at)
VALUES ('01900000-0000-7000-8000-00000000000a', 'calendar', '01900000-0000-7000-8000-000000000003', 1, 'a.ics',
        'upsert', '2026-10-02T09:00:00Z'),
       ('01900000-0000-7000-8000-00000000000a', 'calendar', '01900000-0000-7000-8000-000000000003', 2, 'b.ics',
        'upsert', '2026-10-02T09:30:00Z'),
       ('01900000-0000-7000-8000-00000000000a', 'calendar', '01900000-0000-7000-8000-000000000003', 3, 'c.ics',
        'upsert', '2026-10-02T09:40:00Z'),
       ('01900000-0000-7000-8000-00000000000a', 'calendar', '01900000-0000-7000-8000-000000000003', 4, 'c.ics',
        'delete', '2026-10-02T10:00:00Z'),
       ('01900000-0000-7000-8000-00000000000a', 'home', '01900000-0000-7000-8000-000000000001', 1, 'personal',
        'upsert', '2026-10-01T08:03:00Z'),
       ('01900000-0000-7000-8000-00000000000a', 'inbox', '01900000-0000-7000-8000-000000000001', 1, 'request.ics',
        'upsert', '2026-10-02T11:00:00Z'),
       ('01900000-0000-7000-8000-00000000000a', 'notifications', '01900000-0000-7000-8000-000000000001', 1,
        'invite.xml', 'upsert', '2026-10-02T12:00:00Z');

-- 21 notification, 22 inbox item
INSERT INTO notifications (tenant_id, id, principal_id, uri, uid, etag, type, body_xml, created_at, updated_at,
                           version)
VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000021',
        '01900000-0000-7000-8000-000000000001', 'invite.xml', 'invite-1', '"cccccccccccccccccccccc"', 'invite',
        '<invite-notification xmlns="http://calendarserver.org/ns/"/>', '2026-10-02T12:00:00Z',
        '2026-10-02T12:00:00Z', 1);
INSERT INTO scheduling_inbox (tenant_id, id, principal_id, uri, etag, data, quarantined, created_at, updated_at,
                              version)
VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000022',
        '01900000-0000-7000-8000-000000000001', 'request.ics', '"dddddddddddddddddddddd"',
        E'BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nEND:VCALENDAR\r\n', false, '2026-10-02T11:00:00Z',
        '2026-10-02T11:00:00Z', 1);

-- 31 app password, 32 tenant API token, 33 system API token
INSERT INTO app_passwords (tenant_id, id, principal_id, label, prefix, hash, pepper_kid, last_used_at, revoked_at,
                           created_at, updated_at, version)
VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000031',
        '01900000-0000-7000-8000-000000000001', 'iPhone', 'ap_fixture_olivia', '\x0102030405', 'k1',
        '2026-10-03T07:00:00Z', NULL, '2026-10-01T08:10:00Z', '2026-10-03T07:00:00Z', 2);
INSERT INTO api_tokens (tenant_id, id, kind, principal_id, label, scopes, prefix, hash, pepper_kid, expires_at,
                        created_by, allowed_origins, last_used_at, revoked_at, created_at, updated_at, version)
VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000032', 'tenant', NULL,
        'automation', ARRAY['calendars:read', 'principals:read'], 'at_fixture_acme', '\x0a0b0c', 'k1', NULL, NULL,
        ARRAY['https://admin.acme.example'], NULL, NULL, '2026-10-01T08:11:00Z', '2026-10-01T08:11:00Z', 1),
       (NULL, '01900000-0000-7000-8000-000000000033', 'system', NULL, 'operator', ARRAY['system:tenants'],
        'at_fixture_system', '\x0d0e0f', 'k1', NULL, NULL, ARRAY[]::text[], NULL, NULL, '2026-10-01T07:00:00Z',
        '2026-10-01T07:00:00Z', 1);

-- 41 outbox message, 51 audit record
INSERT INTO outbox (tenant_id, id, kind, payload, schema_version, status, attempts, next_attempt_at, locked_until,
                    last_error, created_at, updated_at)
VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000041', 'provider_push', '{}', 1,
        'pending', 0, '2026-10-02T12:00:00Z', NULL, NULL, '2026-10-02T12:00:00Z', '2026-10-02T12:00:00Z');
INSERT INTO audit_events (tenant_id, id, actor, action, target, details, at)
VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-000000000051', '{"kind": "system", "principal_id": null, "token_id": null, "label": null, "ip_hash": null}',
        'tenant.created', 'tenant:01900000-0000-7000-8000-00000000000a', '{}', '2026-10-01T08:00:00Z');
