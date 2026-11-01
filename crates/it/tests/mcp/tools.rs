//! Every tool against the real services, and the behaviour that belongs to the application: creation that is made once,
//! deletion of what is not there, tokens that carry one scope only, cursors that belong to their search.

use davhaven_testkit::davhaven_domain::{CalendarKind, GrantAccess, Scope};
use davhaven_testkit::davhaven_fixtures::{Attendee, EventBuilder, Organizer, When};
use serde_json::{Value, json};

use super::support::{Org, Person, World, data, march};

/// The tenant `acme` (MCP switched on) with the users anna, ben and cara, the calendar `work` of anna and a token of
/// anna with both MCP scopes.
struct Acme {
    world: World,
    org: Org,
    anna: Person,
    ben: Person,
    cara: Person,
    work: Value,
    token: String,
}

async fn acme() -> Acme {
    let world = World::new();
    let org = world.org("acme", true).await;
    let anna = world.user(&org, "anna").await;
    let ben = world.user(&org, "ben").await;
    let cara = world.user(&org, "cara").await;
    let work = world.calendar(&org, &anna, "work", CalendarKind::User).await;
    let token = world.token(&org, &anna, &[Scope::McpRead, Scope::McpWrite]).await;
    Acme {
        world,
        org,
        anna,
        ben,
        cara,
        work: json!(work.id),
        token,
    }
}

fn event_ids(listing: &Value) -> Vec<String> {
    listing["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["event_id"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn every_tool_works_against_the_real_application() {
    let Acme {
        world,
        org,
        anna,
        ben,
        work,
        token,
        ..
    } = acme().await;
    let assistant = world.mcp(&token);

    // list_calendars: the home of the person, with the access to each calendar.
    let calendars = assistant.ok("list_calendars", json!({})).await;
    let listed = calendars["calendars"].as_array().unwrap();
    let own = listed
        .iter()
        .find(|calendar| calendar["calendar_id"] == work)
        .unwrap_or_else(|| panic!("the calendar `work` is in the home: {calendars}"));
    assert_eq!(own["access"], "owner");
    assert_eq!(own["writable"], true);
    assert_eq!(own["untrusted_text"]["display_name"], "work");

    // create_event, get_event, list_events, search_events.
    let created = assistant
        .ok(
            "create_event",
            json!({"calendar_id": work, "client_request_id": "plan-1",
                   "event": {"summary": "Lunch with Ben", "location": "Canteen",
                             "start": {"date_time": "2027-03-02T09:00:00Z"},
                             "end": {"date_time": "2027-03-02T10:00:00Z"}}}),
        )
        .await;
    assert_eq!(created["created"], true);
    let event = &created["event"];
    assert_eq!(event["untrusted_text"]["summary"], "Lunch with Ben");
    assert_eq!(event["external_key"], "plan-1");
    let (event_id, etag) = (event["event_id"].clone(), event["etag"].clone());

    let one = assistant
        .ok("get_event", json!({"calendar_id": work, "event_id": event_id}))
        .await;
    assert_eq!(one["event"], *event);

    let mut listing_arguments = march();
    listing_arguments["calendar_id"] = work.clone();
    let listing = assistant.ok("list_events", listing_arguments).await;
    assert_eq!(listing["truncated"], false);
    assert_eq!(event_ids(&listing), vec![event_id.as_str().unwrap().to_owned()]);

    // The default range of a search starts now (the clock of the application: 2027-01-01) and is 92 days long.
    let found = assistant.ok("search_events", json!({"query": "lunch"})).await;
    assert_eq!(event_ids(&found), event_ids(&listing));
    let nothing = assistant.ok("search_events", json!({"query": "dinner"})).await;
    assert_eq!(nothing["events"], json!([]));

    // update_event: the changes are merged, the entity tag moves.
    let updated = assistant
        .ok(
            "update_event",
            json!({"calendar_id": work, "event_id": event_id, "if_match": etag,
                   "changes": {"location": "Garden"}}),
        )
        .await;
    assert_eq!(updated["event"]["untrusted_text"]["location"], "Garden");
    assert_eq!(updated["event"]["untrusted_text"]["summary"], "Lunch with Ben");
    assert_ne!(updated["event"]["etag"], etag);
    let stale = assistant
        .fails(
            "update_event",
            json!({"calendar_id": work, "event_id": event_id, "if_match": etag, "changes": {"location": "Lost"}}),
        )
        .await;
    assert_eq!(stale["code"], "precondition-failed");

    // free_busy and find_free_slots: when people are busy, never why.
    let busy = assistant
        .ok(
            "free_busy",
            json!({"addresses": ["anna@acme.example", "ben@acme.example", "nobody@acme.example"],
                   "start": "2027-03-02T00:00:00Z", "end": "2027-03-03T00:00:00Z"}),
        )
        .await;
    let entries = busy["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(
        entries[0],
        json!({"address": "anna@acme.example", "known": true,
               "busy": [{"start": "2027-03-02T09:00:00Z", "end": "2027-03-02T10:00:00Z", "kind": "busy"}]})
    );
    assert_eq!(entries[1]["known"], true);
    assert_eq!(entries[1]["busy"], json!([]));
    assert_eq!(entries[2]["known"], false, "an address of nobody in the tenant");
    assert!(
        !busy.to_string().contains("Lunch"),
        "what the events are is never shown: {busy}"
    );
    let slots = assistant
        .ok(
            "find_free_slots",
            json!({"addresses": ["anna@acme.example", "ben@acme.example"],
                   "start": "2027-03-02T08:00:00Z", "end": "2027-03-02T12:00:00Z", "duration_minutes": 60}),
        )
        .await;
    let free = slots["slots"].as_array().unwrap();
    assert!(!free.is_empty(), "{slots}");
    for slot in free {
        let (start, end) = (slot["start"].as_str().unwrap(), slot["end"].as_str().unwrap());
        assert!(
            end <= "2027-03-02T09:00:00Z" || start >= "2027-03-02T10:00:00Z",
            "a slot must not overlap anna's lunch: {slot}"
        );
    }

    // respond_to_invitation: ben invites anna in his calendar client; the invitation reaches her calendar.
    let invitation = EventBuilder::event("m-1")
        .summary("Planning")
        .starts(When::utc(2027, 3, 10, 9, 0))
        .ends(When::utc(2027, 3, 10, 10, 0))
        .organizer(Organizer::new(&ben.mailto))
        .attendee(Attendee::new(&anna.mailto))
        .build();
    world.put_ics(&org, &ben, &ben, "m-1.ics", &invitation).await;
    let invited = assistant
        .ok(
            "list_events",
            json!({"start": "2027-03-10T00:00:00Z", "end": "2027-03-11T00:00:00Z"}),
        )
        .await;
    let copy = invited["events"][0].clone();
    assert_eq!(copy["untrusted_text"]["summary"], "Planning");
    assert_eq!(copy["my_partstat"], "needs_action");
    assert_eq!(copy["organizer_is_me"], false);
    assert_eq!(copy["attendee_count"], 1);
    let answered = assistant
        .ok(
            "respond_to_invitation",
            json!({"calendar_id": copy["calendar_id"], "event_id": copy["event_id"],
                   "partstat": "accepted", "comment": "See you there"}),
        )
        .await;
    assert_eq!(answered["event"]["my_partstat"], "accepted");
    // The answer reached the organizer: Ben, with a token of his own, sees Anna's answer on his meeting.
    let ben_assistant = world.mcp(&world.token(&org, &ben, &[Scope::McpRead]).await);
    let meeting = ben_assistant
        .ok(
            "list_events",
            json!({"start": "2027-03-10T00:00:00Z", "end": "2027-03-11T00:00:00Z", "include_attendees": true}),
        )
        .await;
    let attendees = meeting["events"][0]["attendees"].as_array().unwrap();
    assert_eq!(attendees[0]["address"], anna.mailto.as_str());
    assert_eq!(attendees[0]["partstat"], "accepted");
    assert_eq!(meeting["events"][0]["organizer_is_me"], true);

    // delete_event: the event is gone, and saying so twice is no error.
    let deleted = assistant
        .ok("delete_event", json!({"calendar_id": work, "event_id": event_id}))
        .await;
    assert_eq!(deleted, json!({"deleted": true}));
    let again = assistant
        .ok("delete_event", json!({"calendar_id": work, "event_id": event_id}))
        .await;
    assert_eq!(again, json!({"deleted": false}));

    // Every write of the assistant is audited, with the tool and ids but never the content.
    let writes: Vec<_> = world
        .audit(&org)
        .await
        .into_iter()
        .filter(|row| row.action == "mcp.write")
        .collect();
    // The stale update was refused and the second delete found nothing: neither of them is a write.
    let tools: Vec<&str> = writes
        .iter()
        .map(|row| row.details["tool"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(
        tools,
        vec!["create_event", "update_event", "respond_to_invitation", "delete_event"],
        "{writes:?}"
    );
    assert!(writes.iter().all(|row| row.actor.principal_id == Some(anna.id)));
    let text = serde_json::to_string(&writes.iter().map(|row| &row.details).collect::<Vec<_>>()).unwrap();
    assert!(!text.contains("Lunch") && !text.contains("Garden"), "{text}");
}

#[tokio::test]
async fn a_token_with_only_the_write_scope_writes_and_is_refused_nothing_it_needs() {
    let Acme {
        world, org, anna, work, ..
    } = acme().await;
    let writer = world.mcp(&world.token(&org, &anna, &[Scope::McpWrite]).await);

    let created = writer
        .ok(
            "create_event",
            json!({"calendar_id": work, "client_request_id": "w-1",
                   "event": {"summary": "Lunch", "start": {"date_time": "2027-03-02T12:00:00Z"}, "duration": "PT1H"}}),
        )
        .await;
    assert_eq!(created["created"], true);
    let event_id = created["event"]["event_id"].clone();
    let updated = writer
        .ok(
            "update_event",
            json!({"calendar_id": work, "event_id": event_id, "changes": {"location": "Garden"}}),
        )
        .await;
    assert_eq!(updated["event"]["untrusted_text"]["location"], "Garden");
    assert_eq!(
        writer
            .ok("delete_event", json!({"calendar_id": work, "event_id": event_id}))
            .await,
        json!({"deleted": true})
    );
    // An event that is not there is gone, whatever the token carries: no read is needed to say so.
    assert_eq!(
        writer
            .ok("delete_event", json!({"calendar_id": work, "event_id": event_id}))
            .await,
        json!({"deleted": false})
    );
    // Reading is what the token does not do.
    for (tool, arguments) in [
        ("list_calendars", json!({})),
        ("get_event", json!({"calendar_id": work, "event_id": event_id})),
    ] {
        let problem = writer.fails(tool, arguments).await;
        assert_eq!(problem["code"], "forbidden", "{tool}");
        assert_eq!(problem["detail"], "This tool needs the scope mcp:read.");
    }
}

#[tokio::test]
async fn update_event_removes_a_field_that_is_sent_as_null_and_refuses_null_where_nothing_can_be_removed() {
    let Acme { world, work, token, .. } = acme().await;
    let assistant = world.mcp(&token);
    let created = assistant
        .ok(
            "create_event",
            json!({"calendar_id": work, "client_request_id": "n-1",
                   "event": {"summary": "Lunch", "location": "Canteen", "description": "Soup",
                             "start": {"date_time": "2027-03-02T12:00:00Z"}, "duration": "PT1H"}}),
        )
        .await;
    let event_id = created["event"]["event_id"].clone();
    assert_eq!(created["event"]["untrusted_text"]["location"], "Canteen");

    let cleared = assistant
        .ok(
            "update_event",
            json!({"calendar_id": work, "event_id": event_id, "changes": {"location": null}}),
        )
        .await;
    let text = &cleared["event"]["untrusted_text"];
    assert!(
        text.get("location").is_none_or(Value::is_null),
        "the location is gone: {text}"
    );
    assert_eq!(text["summary"], "Lunch");
    assert_eq!(text["description"], "Soup", "what the call does not name is kept");
    assert_ne!(cleared["event"]["etag"], created["event"]["etag"]);

    // The same call again changes nothing: the assistant may repeat it.
    let again = assistant
        .ok(
            "update_event",
            json!({"calendar_id": work, "event_id": event_id, "changes": {"location": null}}),
        )
        .await;
    assert_eq!(again["event"]["etag"], cleared["event"]["etag"]);

    // The start cannot be removed: the arguments do not fit the tool, and nothing is written.
    let refused = assistant
        .fails(
            "update_event",
            json!({"calendar_id": work, "event_id": event_id, "changes": {"start": null}}),
        )
        .await;
    assert_eq!(refused["code"], "validation-failed");
    assert!(
        refused.to_string().contains("`start` cannot be null"),
        "the problem names the field: {refused}"
    );
    let unchanged = assistant
        .ok("get_event", json!({"calendar_id": work, "event_id": event_id}))
        .await;
    assert_eq!(unchanged["event"]["etag"], cleared["event"]["etag"]);
}

#[tokio::test]
async fn a_repeated_client_request_id_finds_the_event_and_never_rewrites_it() {
    let Acme {
        world,
        org,
        anna,
        work,
        token,
        ..
    } = acme().await;
    let assistant = world.mcp(&token);
    let call = |summary: &str| {
        json!({"calendar_id": work, "client_request_id": "lunch-1",
               "event": {"summary": summary, "start": {"date_time": "2027-03-02T12:00:00Z"}, "duration": "PT1H"}})
    };
    let first = assistant.ok("create_event", call("Lunch")).await;
    assert_eq!(first["created"], true);
    let changes_before = world.outbox_count(&org, "domain_event").await;

    // The same call again: the event of the first one, nothing written, nobody told.
    let again = assistant.ok("create_event", call("Lunch")).await;
    assert_eq!(again["created"], false);
    assert_eq!(again["event"]["event_id"], first["event"]["event_id"]);
    assert_eq!(again["event"]["etag"], first["event"]["etag"], "nothing was written");
    assert_eq!(
        world.outbox_count(&org, "domain_event").await,
        changes_before,
        "no change, no event"
    );

    // The same id for another event is a conflict: the first event keeps what it says.
    let reused = assistant.fails("create_event", call("Dinner")).await;
    assert_eq!(reused["code"], "conflict");
    let kept = assistant
        .ok(
            "get_event",
            json!({"calendar_id": work, "event_id": first["event"]["event_id"]}),
        )
        .await;
    assert_eq!(kept["event"]["untrusted_text"]["summary"], "Lunch");
    let mut range = march();
    range["calendar_id"] = work.clone();
    assert_eq!(
        event_ids(&assistant.ok("list_events", range).await).len(),
        1,
        "never a second event"
    );

    // The key space is shared with the integrations of the management API: an assistant cannot take over what an
    // integration manages by choosing its key.
    world.event(&org, &anna, "work", "crm-17", data("From the CRM")).await;
    let takeover = assistant
        .fails(
            "create_event",
            json!({"calendar_id": work, "client_request_id": "crm-17",
                   "event": {"summary": "Mine now", "start": {"date_time": "2027-03-02T09:00:00Z"}}}),
        )
        .await;
    assert_eq!(takeover["code"], "conflict");
    let integration = world.event_id_of(&org, &anna, "work", "crm-17").await;
    let read = assistant
        .ok("get_event", json!({"calendar_id": work, "event_id": integration}))
        .await;
    assert_eq!(read["event"]["untrusted_text"]["summary"], "From the CRM");
}

#[tokio::test]
async fn deleting_what_is_not_there_is_only_a_success_where_deleting_is_allowed() {
    let Acme {
        world,
        org,
        anna,
        ben,
        cara,
        work,
        token,
    } = acme().await;
    let (event, _) = world.event(&org, &anna, "work", "standup", data("Standup")).await;
    let event_id = json!(event.id.unwrap());
    world.grant(&org, &anna, "work", &ben, GrantAccess::Read).await;
    let missing = json!("018f3c1e-7b2a-7c3d-9e4f-0000000000aa");
    let ben_assistant = world.mcp(&world.token(&org, &ben, &[Scope::McpRead, Scope::McpWrite]).await);
    let cara_assistant = world.mcp(&world.token(&org, &cara, &[Scope::McpRead, Scope::McpWrite]).await);
    let owner = world.mcp(&token);

    // A person who may only read cannot delete, and is told so: never `deleted: false` for what they may not touch.
    for id in [&event_id, &missing] {
        let denied = ben_assistant
            .fails("delete_event", json!({"calendar_id": work, "event_id": id}))
            .await;
        assert_eq!(denied["code"], "forbidden", "{id}");
    }
    // A stranger cannot see the calendar: the answer for something that does not exist, the same for both.
    let hidden = cara_assistant
        .fails("delete_event", json!({"calendar_id": work, "event_id": event_id}))
        .await;
    let nowhere = cara_assistant
        .fails(
            "delete_event",
            json!({"calendar_id": "018f3c1e-7b2a-7c3d-9e4f-0000000000bb", "event_id": event_id}),
        )
        .await;
    assert_eq!(
        (hidden["code"].as_str(), hidden["status"].as_u64()),
        (Some("not-found"), Some(404))
    );
    assert_eq!(
        hidden["detail"], nowhere["detail"],
        "an invisible calendar looks like none"
    );
    // Nothing happened to the event.
    let still = owner
        .ok("get_event", json!({"calendar_id": work, "event_id": event_id}))
        .await;
    assert_eq!(still["event"]["untrusted_text"]["summary"], "Standup");

    // The owner may delete: what is not there is gone, and only a whole event can be missing.
    assert_eq!(
        owner
            .ok("delete_event", json!({"calendar_id": work, "event_id": missing}))
            .await,
        json!({"deleted": false})
    );
    let older = serde_json::to_value(davhaven_testkit::davhaven_domain::ETag::from_bytes(b"an older version")).unwrap();
    let stale = owner
        .fails(
            "delete_event",
            json!({"calendar_id": work, "event_id": missing, "if_match": older}),
        )
        .await;
    assert_eq!(
        stale["code"], "not-found",
        "a condition on what is not there is no success"
    );
    let instance = owner
        .fails(
            "delete_event",
            json!({"calendar_id": work, "event_id": missing, "scope": "this",
                   "recurrence_id": {"date_time": "2027-03-09T09:00:00Z"}}),
        )
        .await;
    assert_eq!(
        instance["code"], "not-found",
        "an instance of what is not there is no success"
    );
    let unnamed = owner
        .fails(
            "delete_event",
            json!({"calendar_id": work, "event_id": event_id, "scope": "this_and_future"}),
        )
        .await;
    assert_eq!(unnamed["errors"][0]["pointer"], "/recurrence_id");
    assert_eq!(
        owner
            .ok("delete_event", json!({"calendar_id": work, "event_id": event_id}))
            .await,
        json!({"deleted": true})
    );
}

#[tokio::test]
async fn a_cursor_belongs_to_the_search_that_made_it() {
    let Acme {
        world,
        org,
        anna,
        work,
        token,
        ..
    } = acme().await;
    let personal = world.calendar(&org, &anna, "second", CalendarKind::User).await;
    world.event(&org, &anna, "work", "a", data("Alpha lunch")).await;
    let mut later = data("Beta lunch");
    later.start = Some(serde_json::from_value(json!({"date_time": "2027-03-03T09:00:00Z"})).unwrap());
    later.end = Some(serde_json::from_value(json!({"date_time": "2027-03-03T10:00:00Z"})).unwrap());
    world.event(&org, &anna, "work", "b", later).await;
    let assistant = world.mcp(&token);

    let arguments = |extra: Value| {
        let mut arguments = march();
        arguments["calendar_id"] = work.clone();
        arguments["limit"] = json!(1);
        for (name, value) in extra.as_object().unwrap() {
            arguments[name] = value.clone();
        }
        arguments
    };
    let first = assistant.ok("list_events", arguments(json!({}))).await;
    assert_eq!(first["truncated"], true);
    let cursor = first["next_cursor"].clone();

    // With the same arguments the cursor continues the listing.
    let second = assistant
        .ok("list_events", arguments(json!({"cursor": cursor.clone()})))
        .await;
    assert_eq!(second["events"].as_array().unwrap().len(), 1);
    assert_ne!(event_ids(&first), event_ids(&second));
    assert_eq!(second["truncated"], false);

    // With other arguments it is refused: it would skip or repeat results.
    for (what, extra) in [
        (
            "another end",
            json!({"cursor": cursor.clone(), "end": "2027-03-09T00:00:00Z"}),
        ),
        (
            "another start",
            json!({"cursor": cursor.clone(), "start": "2027-03-02T00:00:00Z"}),
        ),
        (
            "another calendar",
            json!({"cursor": cursor.clone(), "calendar_id": personal.id}),
        ),
    ] {
        let refused = assistant.fails("list_events", arguments(extra)).await;
        assert_eq!(refused["code"], "validation-failed", "{what}");
        assert_eq!(refused["errors"][0]["pointer"], "/cursor", "{what}");
    }
    // A cursor of a listing is no cursor of a search, and a made-up one is no cursor at all.
    let mut search = json!({"query": "lunch", "limit": 1, "cursor": cursor});
    search["calendar_id"] = work.clone();
    assert_eq!(
        assistant.fails("search_events", search).await["code"],
        "validation-failed"
    );
    let forged = assistant
        .fails("list_events", arguments(json!({"cursor": "c1.x.1.2.3"})))
        .await;
    assert_eq!(forged["code"], "validation-failed");
}

#[tokio::test]
async fn limits_follow_the_application_a_zero_is_one_and_a_long_query_is_refused() {
    let Acme {
        world,
        org,
        anna,
        work,
        token,
        ..
    } = acme().await;
    world.event(&org, &anna, "work", "a", data("Alpha")).await;
    world.event(&org, &anna, "work", "b", data("Beta")).await;
    let assistant = world.mcp(&token);
    let mut zero = march();
    zero["calendar_id"] = work;
    zero["limit"] = json!(0);
    let page = assistant.ok("list_events", zero).await;
    assert_eq!(
        page["events"].as_array().unwrap().len(),
        1,
        "a limit of zero is read as one"
    );
    assert_eq!(page["truncated"], true);
    let long = assistant
        .fails("search_events", json!({"query": "x".repeat(201)}))
        .await;
    assert_eq!(long["errors"][0]["pointer"], "/query");
    assert_eq!(long["errors"][0]["code"], "too-long");
    let short = assistant.fails("search_events", json!({"query": "x"})).await;
    assert_eq!(short["errors"][0]["code"], "too-short");
}

#[tokio::test]
async fn inviting_people_outside_the_tenant_needs_the_scope_and_the_flag() {
    let Acme {
        world, org, anna, work, ..
    } = acme().await;
    let plain = world.mcp(&world.token(&org, &anna, &[Scope::McpRead, Scope::McpWrite]).await);
    let external = world.mcp(
        &world
            .token(
                &org,
                &anna,
                &[Scope::McpRead, Scope::McpWrite, Scope::McpScheduleExternal],
            )
            .await,
    );
    let invite = |notify: bool, summary: &str| {
        json!({"calendar_id": work, "notify_attendees": notify,
               "event": {"summary": summary, "start": {"date_time": "2027-03-02T09:00:00Z"}, "duration": "PT1H",
                         "organizer": {"address": anna.mailto},
                         "attendees": [{"address": "mailto:guest@example.org"}]}})
    };
    // Without the flag the event is stored and nobody is told, whatever the token may do.
    plain.ok("create_event", invite(false, "Quiet")).await;
    external.ok("create_event", invite(false, "Also quiet")).await;
    assert_eq!(
        world.outbox_count(&org, "imip").await,
        0,
        "no mail without notify_attendees"
    );

    // With the flag, the token needs the scope that allows mail to people outside the tenant.
    let refused = plain.fails("create_event", invite(true, "Loud")).await;
    assert_eq!(refused["code"], "forbidden");
    assert_eq!(
        world.outbox_count(&org, "imip").await,
        0,
        "a refused call sends nothing"
    );
    external.ok("create_event", invite(true, "Loud")).await;
    assert_eq!(
        world.outbox_count(&org, "imip").await,
        1,
        "one mail to the guest, queued"
    );
}
