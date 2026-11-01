//! Throwaway identities for the tests of whatever signs configuration profiles: a self-signed certificate and the private
//! key it belongs to, as PEM, for an RSA key and for an elliptic curve key.
//!
//! Available with the `testing` feature (and to the tests of this crate). **The RSA key below is public and worthless**: it
//! was generated for these tests and is committed with them, so every RSA identity has the same key (a renewed certificate
//! for it is a new certificate for the same key). The elliptic curve key is generated anew by every call. Nothing here is used
//! by the server.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, TimeZone as _, Utc};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _, RSA_PKCS1_SHA256, RsaKeyPair};

use crate::profile::cms::{OID_ECDSA_SHA256, OID_RSA_ENCRYPTION, OID_SHA256_WITH_RSA};
use crate::profile::der::{
    BIT_STRING, CONTEXT_0, OCTET_STRING, SEQUENCE, SET, UTC_TIME, UTF8_STRING, concat, null, oid, small_integer, tlv,
};

/// The kind of key of a test identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// RSA, 2048 bits.
    Rsa,
    /// ECDSA over P-256.
    EcdsaP256,
}

/// A certificate and the key that belongs to it.
#[derive(Debug, Clone)]
pub struct Identity {
    /// The kind of key.
    pub kind: KeyKind,
    /// The certificate as PEM.
    pub certificate_pem: String,
    /// The private key as PEM: PKCS#8 for an elliptic curve key, PKCS#1 (`BEGIN RSA PRIVATE KEY`) for the RSA key.
    pub private_key_pem: String,
}

/// An RSA key of 2048 bits as a PKCS#1 `RSAPrivateKey`, base64. It signs nothing that matters.
const RSA_TEST_KEY: &str =
    "MIIEogIBAAKCAQEAxAUqVj2HCNF5unsAEvkZw3Z/bx/N4UUJk9DYpCTxrmd5XhMBh9ce04jhvkya+Dg+rjgGi7OmiRiqNzT3cPJh
Y7814d7VjQO4lQxb0ptvqGpF/vGJIsMQzDRGIK7dR1zey0Tv6u/sJC97i3zkOtFJOwcB+IJHG7nJvgKlZVVUlm1nwR9+JP1Nlf0q
WgL3JgcsfBcXZkuScZQ1/LZtoKfNDOKpzpo4ZC7I/G9f9u4Ma7tOBK/wYb8h0yJ+w4Gd6yohck5zzlXlX+8vjsV28BFebve3DA0I
UhGydhBj6UyR4h20K2mRriC4Lgk3Rs8NU9VjFZQhxwr/3NaWoWwSia9/swIDAQABAoIBAA4CHn3uRLWtHqlke+NfOOeeksnSuIhW
QjJ1lN3aJAlmLKa77fqStYnBePx8BgEiJ9yUdWdLbeXTROrQFrTUJYCW3BdpsNI0h17jdLZu1EJxYdIv2bCJxywIulBAnuCoMuXM
5eZgwfvuBsK3qKnJZhXZUNs9GC7TjqbNEpvUxsg/JhVn+/1UoAbKQxzXCvH8YqDVoHQpB/XOlAWc1aFOY2UYG3iX/w0GRCr5Y3dK
Jtg/CvgP+NocPrHKK4SYXROWrZko+juTdNQ6jQqdvpvX2fGajPQ5jg22jeCcALJOUhT0gPiGlIbkh/6a8zedxYmttVyox5DQN7wP
E0b9kLEL/NECgYEA+2WX3drzClRyuF2pkUfhaaV+iiLpNUbY6yDsfFp3zFM7anDIbaTCHxJ0lZd+8A5p5m/b4HAHi//u6ccTWkJj
Xq3ZbyrncNPb9MEbPGsQ54X7HJYKuA9xg1TRcWMK8GQQtXmyl7dU0ai9x3LUOzjU+rOwGz463VR6dNZ8Ssfso6MCgYEAx5v/XVBD
2tUwXvVfHyLdRpWJXi9vJdUhygq45xKIZ4OmLZdL1v2ONuVwlgav5yGbrP5oRwl2Kv19BzX+gKmVF43LAQ4lDVbJx30wmQyWi4v0
rKzOIBcVScSFlCMaLCZRGvOoww9A7wNJ+IBuvwEpSouWq1tECeuo/i2bRBop9LECgYAkfNJV+PldfnRIHhAGbhBhbQu4sOh4Oxgw
yE6KnfbVSR9Oi6ALieZC7ELPk3VxEiZ8s6+OG7R8tWDPvX0plIknrMPqRqfg0F8UXxK86i1B7UhNFdnobRVkomLjuiRUT7G9JTSu
oIVHCN7CnAABuHXxDTN6QMX6adB8NMVFdU77UQKBgB4fWoAYdsT1WyFZYgtu1XmrY1mFSv6olTrKN3EXiOImKdPDezxscyOxqDXb
uHvmxHlswwvFT8HZEx8ddNSxwsAVM8dq/QhwSm8CY20VSzqv2jKcuVZ6ZUoGkCn0yiRTe/XXQ2Z8TM5E7srDhvLoF/UZ75jYYwIk
QBJri3zRffdhAoGAKvgXBnWFfnIR/pzAhQhgoSV/XJlp2vu16M6s9AqcLiGGCG6mgxkxm0sLOT883idVqr2+Y86NVTiTmbQsfWcd
4S5x/Cdv11LRpEYiJEMSHvXLfnLaX3GnvG3f0xRzzcQCuEOgL2m/CITjH7LfwqDUFf2bcsf7WHpfGugdNn2Qkyc=";

/// `id-ecPublicKey`, 1.2.840.10045.2.1.
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
/// `prime256v1`, 1.2.840.10045.3.1.7.
const OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
/// `commonName`, 2.5.4.3.
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];

/// `PEM` text for `der` with `label`.
#[must_use]
pub fn pem(label: &str, der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .filter_map(|chunk| core::str::from_utf8(chunk).ok())
        .collect();
    format!(
        "-----BEGIN {label}-----
{}
-----END {label}-----
",
        lines.join(
            "
"
        )
    )
}

/// The PKCS#1 `RSAPrivateKey` of the RSA test identity, as DER.
///
/// # Errors
///
/// Never in practice: the constant is valid base64.
pub fn rsa_test_key_pkcs1() -> Result<Vec<u8>, &'static str> {
    let compact: String = RSA_TEST_KEY.split_whitespace().collect();
    STANDARD.decode(compact).map_err(|_| "the test key is not base64")
}

/// The same key wrapped as a PKCS#8 `PrivateKeyInfo`.
///
/// # Errors
///
/// As [`rsa_test_key_pkcs1`].
pub fn rsa_test_key_pkcs8() -> Result<Vec<u8>, &'static str> {
    let pkcs1 = rsa_test_key_pkcs1()?;
    let algorithm = tlv(SEQUENCE, &concat(&[&oid(OID_RSA_ENCRYPTION), &null()]));
    Ok(tlv(
        SEQUENCE,
        &concat(&[&small_integer(0), &algorithm, &tlv(OCTET_STRING, &pkcs1)]),
    ))
}

fn name(common_name: &str) -> Vec<u8> {
    let attribute = tlv(
        SEQUENCE,
        &concat(&[&oid(OID_COMMON_NAME), &tlv(UTF8_STRING, common_name.as_bytes())]),
    );
    tlv(SEQUENCE, &tlv(SET, &attribute))
}

/// The end of the validity of the certificates that [`identity`] makes: the first of January 2036.
#[must_use]
pub fn default_not_after() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2036, 1, 1, 0, 0, 0)
        .single()
        .unwrap_or(DateTime::UNIX_EPOCH)
}

/// A self-signed certificate (valid from 2026 until `end`, the content of a `UTCTime`) for `public_key` that `sign` signs.
fn certificate(
    common_name: &str,
    end: &[u8],
    key_info: &[u8],
    signature_algorithm: &[u8],
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, &'static str>,
) -> Result<Vec<u8>, &'static str> {
    let validity = tlv(
        SEQUENCE,
        &concat(&[&tlv(UTC_TIME, b"260101000000Z"), &tlv(UTC_TIME, end)]),
    );
    let to_be_signed = tlv(
        SEQUENCE,
        &concat(&[
            &tlv(CONTEXT_0, &small_integer(2)),
            &small_integer(7),
            signature_algorithm,
            &name(common_name),
            &validity,
            &name(common_name),
            key_info,
        ]),
    );
    let signature = sign(&to_be_signed)?;
    let mut bits = vec![0];
    bits.extend_from_slice(&signature);
    Ok(tlv(
        SEQUENCE,
        &concat(&[&to_be_signed, signature_algorithm, &tlv(BIT_STRING, &bits)]),
    ))
}

/// A new self-signed identity with the common name `common_name`, valid until [`default_not_after`].
///
/// # Errors
///
/// A short reason when the key cannot be made or used (never in practice).
pub fn identity(kind: KeyKind, common_name: &str) -> Result<Identity, &'static str> {
    identity_ending(kind, common_name, default_not_after())
}

/// A new self-signed identity with the common name `common_name` whose certificate ends at `not_after`: a time between 1950
/// and 2049, the years a `UTCTime` carries. The certificate has been valid since the first of January 2026 whatever its end
/// is. The tests of a renewal make an identity that ends later than the one it replaces, and the tests of an expired
/// certificate one that has ended.
///
/// # Errors
///
/// A short reason when the key cannot be made or used (never in practice).
pub fn identity_ending(kind: KeyKind, common_name: &str, not_after: DateTime<Utc>) -> Result<Identity, &'static str> {
    identity_with_end(
        kind,
        common_name,
        not_after.format("%y%m%d%H%M%SZ").to_string().as_bytes(),
    )
}

/// A new self-signed identity whose certificate ends at a time that cannot be read: the `UTCTime` of its end is not in UTC
/// (`YYMMDDHHMMSS+0100`), a form that a certificate may have and that [`CmsProfileSigner`](crate::profile::CmsProfileSigner)
/// does not read. A signer takes such a certificate at the start (it cannot tell whether it has run out), and a reload refuses it.
///
/// # Errors
///
/// A short reason when the key cannot be made or used (never in practice).
pub fn identity_without_readable_end(kind: KeyKind, common_name: &str) -> Result<Identity, &'static str> {
    identity_with_end(kind, common_name, b"360101000000+0100")
}

fn identity_with_end(kind: KeyKind, common_name: &str, end: &[u8]) -> Result<Identity, &'static str> {
    let random = SystemRandom::new();
    let bit_string = |key: &[u8]| {
        let mut bits = vec![0];
        bits.extend_from_slice(key);
        tlv(BIT_STRING, &bits)
    };
    match kind {
        KeyKind::Rsa => {
            let pkcs1 = rsa_test_key_pkcs1()?;
            let key = RsaKeyPair::from_der(&pkcs1).map_err(|_| "the RSA test key is unusable")?;
            let key_info = tlv(
                SEQUENCE,
                &concat(&[
                    &tlv(SEQUENCE, &concat(&[&oid(OID_RSA_ENCRYPTION), &null()])),
                    &bit_string(key.public_key().as_ref()),
                ]),
            );
            let algorithm = tlv(SEQUENCE, &concat(&[&oid(OID_SHA256_WITH_RSA), &null()]));
            let der = certificate(common_name, end, &key_info, &algorithm, |message| {
                let mut signature = vec![0; key.public().modulus_len()];
                key.sign(&RSA_PKCS1_SHA256, &random, message, &mut signature)
                    .map_err(|_| "the certificate cannot be signed")?;
                Ok(signature)
            })?;
            Ok(Identity {
                kind,
                certificate_pem: pem("CERTIFICATE", &der),
                private_key_pem: pem("RSA PRIVATE KEY", &pkcs1),
            })
        }
        KeyKind::EcdsaP256 => {
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random)
                .map_err(|_| "no elliptic curve key can be made")?;
            let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &random)
                .map_err(|_| "the elliptic curve key is unusable")?;
            let key_info = tlv(
                SEQUENCE,
                &concat(&[
                    &tlv(SEQUENCE, &concat(&[&oid(OID_EC_PUBLIC_KEY), &oid(OID_P256)])),
                    &bit_string(key.public_key().as_ref()),
                ]),
            );
            let algorithm = tlv(SEQUENCE, &oid(OID_ECDSA_SHA256));
            let der = certificate(common_name, end, &key_info, &algorithm, |message| {
                key.sign(&random, message)
                    .map(|signature| signature.as_ref().to_vec())
                    .map_err(|_| "the certificate cannot be signed")
            })?;
            Ok(Identity {
                kind,
                certificate_pem: pem("CERTIFICATE", &der),
                private_key_pem: pem("PRIVATE KEY", pkcs8.as_ref()),
            })
        }
    }
}
