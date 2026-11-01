//! The pure parts of the dispatcher: the backoff, the text of an error, the id of an announcement. The dispatcher
//! itself (claim, lease, deadline, settling, announcing) runs against the in-memory store in `davhaven-it`.

use super::*;

#[test]
fn the_backoff_doubles_and_is_capped() {
    let config = OutboxConfig::default();
    let seconds: Vec<u64> = (1..=9)
        .map(|attempts| backoff_delay(&config, attempts).as_secs())
        .collect();
    assert_eq!(seconds, vec![30, 60, 120, 240, 480, 960, 1920, 3600, 3600]);
    assert_eq!(
        backoff_delay(&config, 0).as_secs(),
        30,
        "no attempt yet counts as the first"
    );
    assert_eq!(
        backoff_delay(&config, u32::MAX),
        config.backoff_max,
        "huge counts saturate"
    );
    let tight = OutboxConfig {
        backoff_base: Duration::from_secs(1),
        backoff_max: Duration::from_secs(5),
        ..OutboxConfig::default()
    };
    let capped: Vec<u64> = (1..=5)
        .map(|attempts| backoff_delay(&tight, attempts).as_secs())
        .collect();
    assert_eq!(capped, vec![1, 2, 4, 5, 5]);
}

#[test]
fn error_texts_are_one_line_and_bounded() {
    assert_eq!(clean("relay said:\r\n550 no"), "relay said:  550 no");
    assert_eq!(clean(&"x".repeat(1000)).chars().count(), MAX_ERROR_CHARS);
}

#[test]
fn the_announcement_id_is_a_time_ordered_function_of_the_dead_record() {
    let outbox = OutboxId::from_uuid(Uuid::from_u128(0x0190_1234_5678_7abc_8def_0123_4567_89ab));
    let id = announcement_id(outbox);
    assert_eq!(id, announcement_id(outbox), "the same record, the same id");
    assert_ne!(
        id,
        announcement_id(OutboxId::from_uuid(Uuid::from_u128(
            0x0190_1234_5678_7abc_8def_0123_4567_89ac
        )))
    );
    assert_eq!(id.get_version_num(), 7);
    assert_eq!(
        id.as_bytes().get(..6),
        outbox.as_uuid().as_bytes().get(..6),
        "the timestamp is the record's"
    );
    assert_ne!(id, outbox.as_uuid());
}

#[test]
fn a_time_after_the_end_of_time_saturates() {
    let now = DateTime::<Utc>::MAX_UTC - chrono::Duration::seconds(1);
    assert_eq!(after_now(now, Duration::from_secs(10)), DateTime::<Utc>::MAX_UTC);
    assert_eq!(
        after_now(DateTime::UNIX_EPOCH, Duration::from_secs(30)),
        DateTime::UNIX_EPOCH + chrono::Duration::seconds(30)
    );
}

#[test]
fn the_queue_gauges_never_overflow() {
    assert_eq!(gauge_value(5_u64), 5.0);
    assert_eq!(gauge_value(u64::MAX), f64::from(u32::MAX));
}
