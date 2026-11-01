//! The samples of the client smoke (`clients/fixtures`) are what the server sends.
//!
//! `clients/smoke.sh` reads the files with the generated Java model and writes them back. That proves something
//! about the OpenAPI document only if the files are real documents, so these tests read the same files with the
//! wire types and write them back as the server would.

use davhaven_wire::{EventView, ProblemDetails};
use serde_json::Value;

const EVENT: &str = include_str!("../clients/fixtures/event.json");
const PROBLEM: &str = include_str!("../clients/fixtures/problem.json");
const EVENT_WRITE: &str = include_str!("../clients/fixtures/event-write.json");

#[test]
fn the_client_fixture_is_an_event_exactly_as_the_server_writes_it() {
    let written: Value = serde_json::from_str(EVENT).unwrap();
    let event: EventView = serde_json::from_value(written.clone()).unwrap();
    assert_eq!(serde_json::to_value(&event).unwrap(), written);
}

#[test]
fn the_client_fixture_is_a_problem_exactly_as_the_server_writes_it() {
    // The code is the kebab-case catalog code, not the name of the Rust variant: the document and the server must
    // agree on it, or a generated client cannot match any problem.
    let written: Value = serde_json::from_str(PROBLEM).unwrap();
    let problem: ProblemDetails = serde_json::from_value(written.clone()).unwrap();
    assert_eq!(serde_json::to_value(&problem).unwrap(), written);
    assert_eq!(written["code"], "validation-failed");
}

#[test]
fn the_client_write_fixture_says_null_for_a_removal_and_nothing_for_a_field_it_leaves_alone() {
    // A write of an event (RFC 7396): `location` is removed, `description` is not mentioned and keeps its value. A
    // generated client must be able to say both, and tell them apart: `JsonNullable` in Java, `null` and `undefined`
    // in TypeScript.
    let written: Value = serde_json::from_str(EVENT_WRITE).unwrap();
    assert_eq!(written["location"], Value::Null);
    assert!(written.get("description").is_none());
    let event: EventView = serde_json::from_value(written.clone()).unwrap();
    assert_eq!(
        event.data.removed,
        std::collections::BTreeSet::from([davhaven_domain::EventField::Location])
    );
    assert_eq!(event.data.description, None);
    assert_eq!(
        serde_json::to_value(&event).unwrap(),
        written,
        "the server reads what it is sent"
    );
}
