use chrono::TimeZone;
use proptest::prelude::*;

use super::*;

// The example of the Standard Webhooks specification (and of its reference libraries).
const SPEC_SECRET: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
const SPEC_ID: &str = "msg_p5jXN8AQM9LWM0D4loKWxJek";
const SPEC_TIMESTAMP: i64 = 1_614_265_330;
const SPEC_BODY: &str = r#"{"test": 2432232314}"#;
const SPEC_SIGNATURE: &str = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";

// Computed independently with the HMAC of another implementation (Node.js `crypto`).
const CURRENT_SECRET: &str = "whsec_MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
const CURRENT_SIGNATURE: &str = "v1,rkwp5YuvdrMkcu0ZhuMsXoTg44mHAr1Q0+FFgFpXsjY=";
const PREVIOUS_SECRET: &str = "whsec_ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=";
const PREVIOUS_SIGNATURE: &str = "v1,xZe4u4IBgdY9pubFkzRPneiShUtf/C3XAkjUNY3B+EA=";

fn key(secret: &str) -> SigningKey {
    SigningKey::parse(secret).unwrap()
}

fn at(timestamp: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(timestamp, 0).unwrap()
}

#[test]
fn the_signature_of_the_specification_example() {
    assert_eq!(
        key(SPEC_SECRET).sign(SPEC_ID, SPEC_TIMESTAMP, SPEC_BODY.as_bytes()),
        SPEC_SIGNATURE
    );
}

#[test]
fn signatures_match_an_independent_implementation() {
    let body = br#"{"a":1}"#;
    assert_eq!(
        key(CURRENT_SECRET).sign("msg_1", 1_700_000_000, body),
        CURRENT_SIGNATURE
    );
    assert_eq!(
        key(PREVIOUS_SECRET).sign("msg_1", 1_700_000_000, body),
        PREVIOUS_SIGNATURE
    );
}

#[test]
fn the_reference_verifier_accepts_the_example() {
    let verifier = Verifier::new(vec![key(SPEC_SECRET)]);
    verifier
        .verify(
            SPEC_ID,
            &SPEC_TIMESTAMP.to_string(),
            SPEC_SIGNATURE,
            SPEC_BODY.as_bytes(),
            at(SPEC_TIMESTAMP + 5),
        )
        .unwrap();
}

#[test]
fn a_rotation_signs_with_both_secrets_and_either_one_verifies() {
    let keys = [key(CURRENT_SECRET), key(PREVIOUS_SECRET)];
    let header = signature_header(&keys, "msg_1", 1_700_000_000, br#"{"a":1}"#);
    assert_eq!(header, format!("{CURRENT_SIGNATURE} {PREVIOUS_SIGNATURE}"));

    for secret in [CURRENT_SECRET, PREVIOUS_SECRET] {
        Verifier::new(vec![key(secret)])
            .verify("msg_1", "1700000000", &header, br#"{"a":1}"#, at(1_700_000_000))
            .unwrap();
    }
    // A receiver that rotated too knows both.
    Verifier::new(vec![key(PREVIOUS_SECRET), key(CURRENT_SECRET)])
        .verify("msg_1", "1700000000", &header, br#"{"a":1}"#, at(1_700_000_000))
        .unwrap();
    assert_eq!(
        Verifier::new(vec![key(SPEC_SECRET)]).verify("msg_1", "1700000000", &header, br#"{"a":1}"#, at(1_700_000_000)),
        Err(VerifyError::NoValidSignature)
    );
}

#[test]
fn anything_that_changed_in_transit_fails() {
    let verifier = Verifier::new(vec![key(CURRENT_SECRET)]);
    let now = at(1_700_000_000);
    let ok = |id: &str, ts: &str, sig: &str, body: &[u8]| verifier.verify(id, ts, sig, body, now);
    assert_eq!(ok("msg_1", "1700000000", CURRENT_SIGNATURE, br#"{"a":1}"#), Ok(()));
    assert_eq!(
        ok("msg_1", "1700000000", CURRENT_SIGNATURE, br#"{"a":2}"#),
        Err(VerifyError::NoValidSignature),
        "the body"
    );
    assert_eq!(
        ok("msg_2", "1700000000", CURRENT_SIGNATURE, br#"{"a":1}"#),
        Err(VerifyError::NoValidSignature),
        "the id"
    );
    assert_eq!(
        ok("msg_1", "1700000001", CURRENT_SIGNATURE, br#"{"a":1}"#),
        Err(VerifyError::NoValidSignature),
        "the timestamp"
    );
    assert_eq!(
        ok("msg_1", "1700000000", PREVIOUS_SIGNATURE, br#"{"a":1}"#),
        Err(VerifyError::NoValidSignature),
        "another key"
    );
    // A prefix of the right tag is not the tag: the comparison covers all 32 bytes.
    assert_eq!(
        ok("msg_1", "1700000000", "v1,rkwp5Yuv", br#"{"a":1}"#),
        Err(VerifyError::NoValidSignature),
        "a truncated tag"
    );
    for junk in ["", "v1,", "v1", ",abc", "v1,!!!!", "v2,abc", "v1a,abc", "   "] {
        assert_eq!(
            ok("msg_1", "1700000000", junk, br#"{"a":1}"#),
            Err(VerifyError::NoValidSignature),
            "{junk:?}"
        );
    }
}

#[test]
fn signatures_of_other_versions_and_junk_entries_are_skipped() {
    let verifier = Verifier::new(vec![key(CURRENT_SECRET)]);
    let header = format!(
        "v1a,AAAA junk v2,{} {CURRENT_SIGNATURE} v1,!!",
        CURRENT_SIGNATURE.trim_start_matches("v1,")
    );
    verifier
        .verify("msg_1", "1700000000", &header, br#"{"a":1}"#, at(1_700_000_000))
        .unwrap();
}

#[test]
fn the_timestamp_must_be_within_five_minutes() {
    let key = key(SPEC_SECRET);
    let body = b"{}";
    let verifier = Verifier::new(vec![SigningKey::parse(SPEC_SECRET).unwrap()]);
    let sent = 1_700_000_000;
    let header = key.sign("msg_1", sent, body);
    let check = |now: i64| verifier.verify("msg_1", &sent.to_string(), &header, body, at(now));
    assert_eq!(check(sent), Ok(()));
    assert_eq!(check(sent + 300), Ok(()), "exactly at the tolerance");
    assert_eq!(check(sent + 301), Err(VerifyError::TooOld));
    assert_eq!(check(sent - 300), Ok(()));
    assert_eq!(check(sent - 301), Err(VerifyError::TooNew));

    let wide = Verifier::new(vec![SigningKey::parse(SPEC_SECRET).unwrap()]).with_tolerance(Duration::hours(1));
    assert!(
        wide.verify("msg_1", &sent.to_string(), &header, body, at(sent + 3000))
            .is_ok()
    );
}

#[test]
fn timestamps_are_plain_digits() {
    let verifier = Verifier::new(vec![key(SPEC_SECRET)]);
    for bad in [
        "",
        " 1700000000",
        "+1700000000",
        "-1700000000",
        "1.7e9",
        "0x10",
        "1700000000 ",
        "17000000000000",
    ] {
        assert_eq!(
            verifier.verify("msg_1", bad, "v1,AAAA", b"{}", at(1_700_000_000)),
            Err(VerifyError::BadTimestamp),
            "{bad:?}"
        );
    }
}

#[test]
fn the_timestamp_is_signed_as_the_sender_wrote_it() {
    // A sender may pad the number; the signature covers the text of the header.
    let key = key(SPEC_SECRET);
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&STANDARD.decode(SPEC_SECRET.trim_start_matches("whsec_")).unwrap()).unwrap();
    mac.update(b"msg_1.01700000000.{}");
    let header = format!("v1,{}", STANDARD.encode(mac.finalize().into_bytes()));
    let verifier = Verifier::new(vec![key]);
    verifier
        .verify("msg_1", "01700000000", &header, b"{}", at(1_700_000_000))
        .unwrap();
}

#[test]
fn secrets_are_parsed_strictly_but_padding_is_optional() {
    assert!(SigningKey::parse(CURRENT_SECRET).is_ok());
    assert!(
        SigningKey::parse(&CURRENT_SECRET.replace('=', "")).is_ok(),
        "padding is optional"
    );
    assert_eq!(
        SigningKey::parse("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw").unwrap_err(),
        SigningError::Prefix
    );
    assert_eq!(SigningKey::parse("whsec_!!!!").unwrap_err(), SigningError::Encoding);
    assert_eq!(
        SigningKey::parse("whsec_AAAA").unwrap_err(),
        SigningError::Length,
        "three bytes"
    );
    assert_eq!(
        SigningKey::parse("whsec_").unwrap_err(),
        SigningError::Length,
        "no bytes"
    );
    let long = format!("whsec_{}", STANDARD.encode([7_u8; 200]));
    assert_eq!(SigningKey::parse(&long).unwrap_err(), SigningError::Length);
    assert!(SigningKey::parse(&format!("whsec_{}", STANDARD.encode([7_u8; 16]))).is_ok());
    assert!(SigningKey::parse(&format!("whsec_{}", STANDARD.encode([7_u8; 128]))).is_ok());
}

#[test]
fn keys_do_not_print_their_bytes() {
    let shown = format!("{:?}", key(CURRENT_SECRET));
    assert!(!shown.contains("MDEyMzQ1"), "{shown}");
    assert!(!shown.contains("0123456789abcdef"), "{shown}");
    assert!(!format!("{:?}", Verifier::new(vec![key(CURRENT_SECRET)])).contains("MDEyMzQ1"));
}

proptest! {
    #[test]
    fn what_is_signed_verifies_and_nothing_else_does(
        id in "[a-zA-Z0-9_]{1,40}",
        sent in 1_000_000_000_i64..4_000_000_000,
        body in proptest::collection::vec(any::<u8>(), 0..256),
        flip in any::<prop::sample::Index>(),
    ) {
        let key = key(CURRENT_SECRET);
        let header = key.sign(&id, sent, &body);
        let verifier = Verifier::new(vec![SigningKey::parse(CURRENT_SECRET).unwrap()]);
        prop_assert_eq!(verifier.verify(&id, &sent.to_string(), &header, &body, at(sent)), Ok(()));
        if !body.is_empty() {
            let mut damaged = body.clone();
            let index = flip.index(damaged.len());
            if let Some(byte) = damaged.get_mut(index) {
                *byte ^= 0x01;
            }
            prop_assert_eq!(
                verifier.verify(&id, &sent.to_string(), &header, &damaged, at(sent)),
                Err(VerifyError::NoValidSignature)
            );
        }
        let other_id = format!("{id}x");
        prop_assert_eq!(
            verifier.verify(&other_id, &sent.to_string(), &header, &body, at(sent)),
            Err(VerifyError::NoValidSignature)
        );
    }
}
