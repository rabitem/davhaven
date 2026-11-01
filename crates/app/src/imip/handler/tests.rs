//! The pure parts of the iMIP handler: the names that end up in headers. Composing and sending a mail, the staging
//! rules, the breaker and the failure classes run against the in-memory store in `davhaven-it` (`imip_mail`), and
//! the rendering through the real template renderer and the MIME assembler in `imip_templates`.

use super::*;

#[test]
fn the_service_name_is_the_person_via_the_tenant() {
    assert_eq!(
        service_name(Some("Anna Example"), "Example Organisation"),
        "Anna Example via Example Organisation"
    );
}

#[test]
fn without_a_name_the_service_name_is_the_tenant_and_never_an_address() {
    for none in [None, Some(""), Some("   "), Some("\r\n")] {
        assert_eq!(
            service_name(none, "Example Organisation"),
            "Example Organisation",
            "{none:?}"
        );
    }
}

#[test]
fn both_parts_of_the_service_name_are_shortened_before_they_are_joined() {
    let name = service_name(Some(&"D".repeat(300)), &"T".repeat(300));
    assert_eq!(name, format!("{} via {}", "D".repeat(80), "T".repeat(80)));
    assert!(header_text(&name).is_ok(), "the joined name fits a header");
}

#[test]
fn control_characters_in_a_name_become_spaces_and_cannot_end_the_header() {
    let name = service_name(Some("Anna\r\nBcc: victim@example.net"), "Example");
    assert_eq!(name, "Anna  Bcc: victim@example.net via Example");
    assert!(!name.chars().any(char::is_control));
}

#[test]
fn shortening_cuts_characters_not_bytes_and_leaves_no_trailing_space() {
    assert_eq!(shortened(&"ü".repeat(100), 80).chars().count(), 80);
    assert_eq!(shortened("  abc  def  ", 6), "abc  d");
    assert_eq!(shortened("abc   ", 4), "abc");
}

#[test]
fn header_text_is_cleaned_and_bounded() {
    assert_eq!(header_text("Hello\r\nWorld").unwrap().as_str(), "Hello  World");
    assert_eq!(
        header_text(&"x".repeat(500)).unwrap().as_str().chars().count(),
        MAX_HEADER_CHARS
    );
}

#[test]
fn the_budget_of_a_send_is_a_share_of_the_lease() {
    let outbox = OutboxConfig::default();
    assert_eq!(send_budget(&outbox), Duration::from_secs(36), "60 % of the minute");
    let dispatcher_budget = outbox.lease.mul_f64(0.8);
    assert!(
        send_budget(&outbox) < dispatcher_budget,
        "the send ends before the dispatcher cuts the handler off"
    );
}
