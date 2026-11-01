-- The properties of several bindings at once (`PropertyRepo::list_many`).
--
-- $1 is the tenant; $2 and $3 are the calendar ids and the binding ids of the requested pairs, position by position.
-- A pair is valid when the binding belongs to the live calendar; the valid pairs decide what is read: the shared
-- properties of their calendars and the private properties of their bindings, grouped by calendar, the shared ones
-- first, then by namespace and name (the order of `PropertyRepo::list`).
--
-- Each of the two reads is driven from `wanted` and joins the partial unique index that serves it
-- (`collection_properties_shared_key` for `binding_id IS NULL`, `collection_properties_binding_key` for
-- `binding_id IS NOT NULL`), so it touches the rows of the listed calendars and nothing else. A single `WHERE ... OR ...`
-- over both kinds cannot do that: PostgreSQL runs a sub-select under an `OR` as a filter and the only index condition
-- left is the tenant, so every property row of the tenant would be read (`ENGINEERING_RULES` R14).
-- `tests/migrations.rs` pins the plan.
WITH wanted AS (
    SELECT DISTINCT r.calendar_id, r.binding_id
    FROM unnest($2::uuid[], $3::uuid[]) AS r(calendar_id, binding_id)
    JOIN calendar_bindings b ON b.tenant_id = $1 AND b.id = r.binding_id AND b.calendar_id = r.calendar_id
    JOIN calendars c ON c.tenant_id = $1 AND c.id = r.calendar_id AND c.deleted_at IS NULL)
SELECT u.calendar_id, u.binding_id, u.ns, u.name, u.value_xml
FROM (
    SELECT p.calendar_id, p.binding_id, p.ns, p.name, p.value_xml
    FROM (SELECT DISTINCT calendar_id FROM wanted) w
    JOIN collection_properties p ON p.tenant_id = $1 AND p.calendar_id = w.calendar_id AND p.binding_id IS NULL
    UNION ALL
    SELECT p.calendar_id, p.binding_id, p.ns, p.name, p.value_xml
    FROM wanted w
    JOIN collection_properties p ON p.tenant_id = $1 AND p.calendar_id = w.calendar_id
        AND p.binding_id IS NOT NULL AND p.binding_id = w.binding_id) u
ORDER BY u.calendar_id, u.binding_id NULLS FIRST, u.ns COLLATE "C", u.name COLLATE "C"
