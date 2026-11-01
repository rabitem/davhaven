//! The CSRF token of the RSVP form (PLAN 2.13): bound to the RSVP token, valid for one hour.
//!
//! The token is stateless. It names the key that signed it, the moment it expires and a MAC over those and the ids
//! of the tenant and the RSVP token, made with the key ring's `Csrf` purpose:
//!
//! ```text
//! v1.{kid}.{expires}.{mac}            kid and mac are base64url, expires is Unix seconds
//! mac = HMAC(Csrf, "davhaven/rsvp-csrf/v1/{tenant}/{token id}/{expires}")
//! ```
//!
//! A token made for one RSVP link is useless on another (the token id is part of what is signed), on another tenant,
//! after the hour, and after a key rotation that removed its key. The page that is served to a link holder carries a
//! fresh one on every `GET`; nothing is stored.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use davhaven_domain::{TenantId, TokenId};
use davhaven_ports::{KeyPurpose, KeyRing, Signature};

/// How long a form stays valid.
pub(crate) const LIFETIME: Duration = Duration::hours(1);

/// The version tag of the format.
const VERSION: &str = "v1";

/// The bytes the MAC covers.
fn signed(tenant: TenantId, token: TokenId, expires: i64) -> String {
    format!("davhaven/rsvp-csrf/{VERSION}/{tenant}/{token}/{expires}")
}

/// Issues the token for the form of the RSVP link `token` at `now`.
pub(crate) fn issue(keyring: &dyn KeyRing, tenant: TenantId, token: TokenId, now: DateTime<Utc>) -> String {
    let expires = (now + LIFETIME).timestamp();
    let signature = keyring.sign(KeyPurpose::Csrf, signed(tenant, token, expires).as_bytes());
    format!(
        "{VERSION}.{}.{expires}.{}",
        URL_SAFE_NO_PAD.encode(signature.kid.as_bytes()),
        URL_SAFE_NO_PAD.encode(&signature.mac)
    )
}

/// Whether `presented` is a token issued for the RSVP link `token` that has not expired at `now`.
pub(crate) fn verify(
    keyring: &dyn KeyRing,
    tenant: TenantId,
    token: TokenId,
    presented: &str,
    now: DateTime<Utc>,
) -> bool {
    let mut parts = presented.split('.');
    let (Some(version), Some(kid), Some(expires), Some(mac), None) =
        (parts.next(), parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    if version != VERSION {
        return false;
    }
    let Ok(expires) = expires.parse::<i64>() else {
        return false;
    };
    if expires < now.timestamp() {
        return false;
    }
    let (Ok(kid), Ok(mac)) = (URL_SAFE_NO_PAD.decode(kid), URL_SAFE_NO_PAD.decode(mac)) else {
        return false;
    };
    let Ok(kid) = String::from_utf8(kid) else {
        return false;
    };
    keyring.verify(
        KeyPurpose::Csrf,
        signed(tenant, token, expires).as_bytes(),
        &Signature::new(kid, mac),
    )
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use davhaven_ports::testing::FixedKeyRing;
    use uuid::Uuid;

    use super::*;

    fn tenant(n: u128) -> TenantId {
        TenantId::from_uuid(Uuid::from_u128(n))
    }

    fn token(n: u128) -> TokenId {
        TokenId::from_uuid(Uuid::from_u128(n))
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2027, 3, 1, 9, 0, 0).unwrap()
    }

    #[test]
    fn a_token_is_good_for_its_link_until_the_hour_is_over() {
        let ring = FixedKeyRing::default();
        let csrf = issue(&ring, tenant(1), token(2), now());
        assert!(verify(&ring, tenant(1), token(2), &csrf, now()));
        assert!(verify(&ring, tenant(1), token(2), &csrf, now() + Duration::minutes(59)));
        assert!(
            verify(&ring, tenant(1), token(2), &csrf, now() + Duration::hours(1)),
            "the last second of the hour still counts"
        );
        assert!(!verify(
            &ring,
            tenant(1),
            token(2),
            &csrf,
            now() + Duration::hours(1) + Duration::seconds(1)
        ));
    }

    #[test]
    fn a_token_belongs_to_one_link_of_one_tenant() {
        let ring = FixedKeyRing::default();
        let csrf = issue(&ring, tenant(1), token(2), now());
        assert!(!verify(&ring, tenant(1), token(3), &csrf, now()), "another RSVP link");
        assert!(!verify(&ring, tenant(9), token(2), &csrf, now()), "another tenant");
    }

    #[test]
    fn forged_and_malformed_tokens_are_refused() {
        let ring = FixedKeyRing::default();
        let csrf = issue(&ring, tenant(1), token(2), now());
        let mut pieces: Vec<&str> = csrf.split('.').collect();
        // A later expiry with the old MAC.
        let later = (now() + Duration::days(30)).timestamp().to_string();
        pieces[2] = &later;
        assert!(!verify(&ring, tenant(1), token(2), &pieces.join("."), now()));
        for bad in [
            "",
            "v1",
            "v1.a.b.c",
            "v2.a.1.c",
            "v1..1.",
            "v1.a.1.c.d",
            &csrf.replace("v1.", "v0."),
            &format!("{csrf}x"),
            "v1.!!!.9999999999.!!!",
        ] {
            assert!(!verify(&ring, tenant(1), token(2), bad, now()), "{bad}");
        }
    }
}
