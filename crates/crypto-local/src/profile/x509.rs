//! PEM blocks and the parts of an X.509 certificate that a CMS signature names.
//!
//! A `SignerInfo` identifies the certificate that verifies it by the issuer name and the serial number, exactly as they
//! are encoded in the certificate, and the signer checks that its private key belongs to the public key of the certificate.
//! So this reads the certificate as far as the `SubjectPublicKeyInfo`; it validates no chain and no dates (the device that
//! installs the profile does, and says so on its screen). It reads the end of the validity, so that the operator is warned
//! before the certificate runs out.

use core::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, TimeZone as _, Utc};
use zeroize::Zeroizing;

use super::der::{BIT_STRING, CONTEXT_0, GENERALIZED_TIME, INTEGER, OID, Reader, SEQUENCE, UTC_TIME};

/// A block of a PEM file: `-----BEGIN {label}-----`, base64, `-----END {label}-----`.
///
/// The decoded bytes can be a private key, so they are wiped when the block goes, and `Debug` shows the label and the length
/// only.
pub(crate) struct PemBlock {
    /// The label, for example `CERTIFICATE` or `PRIVATE KEY`.
    pub(crate) label: String,
    /// The decoded bytes.
    pub(crate) der: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for PemBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PemBlock")
            .field("label", &self.label)
            .field("len", &self.der.len())
            .finish_non_exhaustive()
    }
}

/// The blocks of a PEM text, in order. Text outside the blocks is ignored.
///
/// # Errors
///
/// A short reason when a block is not closed, does not match its end line or is not base64.
pub(crate) fn pem_blocks(text: &str) -> Result<Vec<PemBlock>, &'static str> {
    let mut blocks = Vec::new();
    // The base64 of a key is as good as the key: it is wiped like the bytes it decodes to.
    let mut open: Option<(&str, Zeroizing<String>)> = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(label) = line
            .strip_prefix("-----BEGIN ")
            .and_then(|rest| rest.strip_suffix("-----"))
        {
            if open.is_some() {
                return Err("a block begins inside another block");
            }
            open = Some((label, Zeroizing::new(String::new())));
        } else if let Some(label) = line
            .strip_prefix("-----END ")
            .and_then(|rest| rest.strip_suffix("-----"))
        {
            let Some((begun, body)) = open.take() else {
                return Err("a block ends that never began");
            };
            if begun != label {
                return Err("a block ends with another label than it began with");
            }
            let der = STANDARD.decode(body.as_bytes()).map_err(|_| "a block is not base64")?;
            blocks.push(PemBlock {
                label: label.to_owned(),
                der: Zeroizing::new(der),
            });
        } else if let Some((_, body)) = open.as_mut() {
            body.push_str(line);
        }
    }
    if open.is_some() {
        return Err("a block is not closed");
    }
    Ok(blocks)
}

/// What a signature names of a certificate.
#[derive(Debug, Clone)]
pub(crate) struct Certificate {
    /// The certificate as DER, as it goes into the signature.
    pub(crate) der: Vec<u8>,
    /// The issuer name, encoded (tag, length and content).
    pub(crate) issuer: Vec<u8>,
    /// The serial number, encoded (tag, length and content).
    pub(crate) serial: Vec<u8>,
    /// The key of the certificate: the content of the bit string of the `SubjectPublicKeyInfo` (for RSA the `RSAPublicKey`,
    /// for an elliptic curve the encoded point).
    pub(crate) public_key: Vec<u8>,
    /// The end of the validity of the certificate, when it is written in a form that can be read (`UTCTime` or
    /// `GeneralizedTime` in UTC).
    pub(crate) not_after: Option<DateTime<Utc>>,
}

/// The time in a `UTCTime` (`YYMMDDHHMMSSZ`, a year from 50 on is 19YY) or `GeneralizedTime` (`YYYYMMDDHHMMSSZ`) element.
fn time_of(tag: u8, content: &[u8]) -> Option<DateTime<Utc>> {
    let text = core::str::from_utf8(content).ok()?.strip_suffix('Z')?;
    let (year, rest) = match tag {
        UTC_TIME => {
            let (digits, rest) = text.split_at_checked(2)?;
            let short: i32 = digits.parse().ok()?;
            (if short >= 50 { 1900 + short } else { 2000 + short }, rest)
        }
        GENERALIZED_TIME => {
            let (digits, rest) = text.split_at_checked(4)?;
            (digits.parse().ok()?, rest)
        }
        _ => return None,
    };
    let part = |at: usize| -> Option<u32> { rest.get(at..at.checked_add(2)?)?.parse().ok() };
    if rest.len() != 10 {
        return None;
    }
    Utc.with_ymd_and_hms(year, part(0)?, part(2)?, part(4)?, part(6)?, part(8)?)
        .single()
}

/// Reads the certificate in `der`; `None` when it is not one.
pub(crate) fn parse_certificate(der: &[u8]) -> Option<Certificate> {
    let mut outer = Reader::new(der);
    let certificate = outer.next().filter(|element| element.tag == SEQUENCE)?;
    if !outer.is_empty() {
        return None;
    }
    let tbs = Reader::new(certificate.content)
        .next()
        .filter(|element| element.tag == SEQUENCE)?;
    let mut fields = Reader::new(tbs.content);
    let mut first = fields.next()?;
    if first.tag == CONTEXT_0 {
        // The version, which v1 certificates leave out.
        first = fields.next()?;
    }
    let serial = Some(first).filter(|element| element.tag == INTEGER)?;
    let _signature_algorithm = fields.next()?;
    let issuer = fields.next().filter(|element| element.tag == SEQUENCE)?;
    let validity = fields.next().filter(|element| element.tag == SEQUENCE)?;
    let mut times = Reader::new(validity.content);
    let _not_before = times.next()?;
    let not_after = times.next().and_then(|element| time_of(element.tag, element.content));
    let _subject = fields.next()?;
    let key_info = fields.next().filter(|element| element.tag == SEQUENCE)?;
    let mut key_fields = Reader::new(key_info.content);
    let algorithm = key_fields.next().filter(|element| element.tag == SEQUENCE)?;
    // The algorithm identifier must start with an object identifier, which a later check of the key relies on.
    Reader::new(algorithm.content)
        .next()
        .filter(|element| element.tag == OID)?;
    let bits = key_fields.next().filter(|element| element.tag == BIT_STRING)?;
    let (unused_bits, public_key) = bits.content.split_first()?;
    if *unused_bits != 0 {
        return None;
    }
    Some(Certificate {
        der: der.to_vec(),
        issuer: issuer.encoded.to_vec(),
        serial: serial.encoded.to_vec(),
        public_key: public_key.to_vec(),
        not_after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_are_read_in_order_and_text_between_them_is_ignored() {
        let text = "subject=CN=Example\n-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n\n\
                    -----BEGIN PRIVATE KEY-----\r\nBAUG\r\nBw==\r\n-----END PRIVATE KEY-----\r\n";
        let blocks = pem_blocks(text).unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].label, "CERTIFICATE");
        assert_eq!(blocks[0].der.as_slice(), [1, 2, 3]);
        assert_eq!(blocks[1].label, "PRIVATE KEY");
        assert_eq!(blocks[1].der.as_slice(), [4, 5, 6, 7]);
        assert!(pem_blocks("nothing here").unwrap().is_empty());
    }

    #[test]
    fn a_block_shows_its_label_and_length_and_never_its_bytes() {
        let blocks = pem_blocks("-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n").unwrap();
        let shown = format!("{:?}", blocks[0]);
        assert!(shown.contains("PRIVATE KEY") && shown.contains("len: 3"), "{shown}");
        assert!(!shown.contains("AQID") && !shown.contains("[1, 2, 3]"), "{shown}");
    }

    #[test]
    fn the_times_of_a_certificate_are_read_the_way_rfc_5280_writes_them() {
        let at = |year: i32, month: u32, day: u32, hour: u32, minute: u32, second: u32| {
            chrono::NaiveDate::from_ymd_opt(year, month, day)
                .and_then(|date| date.and_hms_opt(hour, minute, second))
                .map(|naive| naive.and_utc())
        };
        assert_eq!(time_of(UTC_TIME, b"260101000000Z"), at(2026, 1, 1, 0, 0, 0));
        assert_eq!(time_of(UTC_TIME, b"491231235959Z"), at(2049, 12, 31, 23, 59, 59));
        assert_eq!(
            time_of(UTC_TIME, b"500101000000Z"),
            at(1950, 1, 1, 0, 0, 0),
            "from 50 on it is 19YY"
        );
        assert_eq!(time_of(GENERALIZED_TIME, b"20510304050607Z"), at(2051, 3, 4, 5, 6, 7));
        for (tag, text) in [
            (UTC_TIME, &b"2601010000Z"[..]),
            (UTC_TIME, &b"260101000000"[..]),
            (UTC_TIME, &b"261301000000Z"[..]),
            (GENERALIZED_TIME, &b"2026-01-01Z"[..]),
            (INTEGER, &b"260101000000Z"[..]),
            (UTC_TIME, &[0xFF, 0xFE][..]),
        ] {
            assert_eq!(time_of(tag, text), None, "{text:?}");
        }
    }
    #[test]
    fn damaged_blocks_are_refused_with_a_reason() {
        for text in [
            "-----BEGIN CERTIFICATE-----\nAQID\n",
            "AQID\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nAQID\n-----END PRIVATE KEY-----\n",
            "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
            "-----BEGIN A-----\n-----BEGIN B-----\n-----END B-----\n-----END A-----\n",
        ] {
            assert!(pem_blocks(text).is_err(), "{text}");
        }
    }

    #[test]
    fn what_is_not_a_certificate_is_nothing() {
        for bytes in [
            &[][..],
            &[0x30, 0x00][..],
            &[1, 2, 3][..],
            &[0x30, 0x03, 0x30, 0x01, 0x00][..],
        ] {
            assert!(parse_certificate(bytes).is_none(), "{bytes:?}");
        }
    }
}
