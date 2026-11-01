//! The CMS `SignedData` of a signed configuration profile (RFC 5652).
//!
//! The layout is what `openssl smime -sign -nodetach -outform der` writes and what iOS and macOS verify: a `ContentInfo`
//! of type `signedData` whose `encapContentInfo` carries the profile itself (the signature is not detached), the
//! certificates of the signer and the chain, and one `SignerInfo` with signed attributes (content type, signing time and
//! the SHA-256 digest of the profile) that the signature covers.

use chrono::{DateTime, Datelike as _, Utc};
use ring::digest::{SHA256, digest};

use super::der::{
    CONTEXT_0, GENERALIZED_TIME, OCTET_STRING, SEQUENCE, SET, UTC_TIME, concat, null, oid, small_integer, tlv,
};
use super::x509::Certificate;

/// `id-data`, 1.2.840.113549.1.7.1.
pub(crate) const OID_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];
/// `id-signedData`, 1.2.840.113549.1.7.2.
pub(crate) const OID_SIGNED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
/// `id-contentType`, 1.2.840.113549.1.9.3.
const OID_CONTENT_TYPE: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03];
/// `id-messageDigest`, 1.2.840.113549.1.9.4.
const OID_MESSAGE_DIGEST: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04];
/// `id-signingTime`, 1.2.840.113549.1.9.5.
const OID_SIGNING_TIME: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05];
/// `id-sha256`, 2.16.840.1.101.3.4.2.1.
pub(crate) const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
/// `rsaEncryption`, 1.2.840.113549.1.1.1.
pub(crate) const OID_RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
/// `sha256WithRSAEncryption`, 1.2.840.113549.1.1.11 (the certificates of the test identities are signed with it).
#[cfg(any(test, feature = "testing"))]
pub(crate) const OID_SHA256_WITH_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
/// `ecdsa-with-SHA256`, 1.2.840.10045.4.3.2.
pub(crate) const OID_ECDSA_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];

/// The signature algorithm of the signer's key, as the `SignerInfo` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Algorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    RsaSha256,
    /// ECDSA over P-256 with SHA-256; the signature is the DER `ECDSA-Sig-Value`.
    EcdsaP256Sha256,
}

impl Algorithm {
    /// The `AlgorithmIdentifier` of the signature in the `SignerInfo`.
    fn identifier(self) -> Vec<u8> {
        match self {
            Self::RsaSha256 => tlv(SEQUENCE, &concat(&[&oid(OID_RSA_ENCRYPTION), &null()])),
            Self::EcdsaP256Sha256 => tlv(SEQUENCE, &oid(OID_ECDSA_SHA256)),
        }
    }
}

/// An attribute: its type and the one value it holds (already encoded).
fn attribute(kind: &[u8], value: &[u8]) -> Vec<u8> {
    tlv(SEQUENCE, &concat(&[&oid(kind), &tlv(SET, value)]))
}

/// The signing time as RFC 5652 section 11.3 writes it: `UTCTime` until 2049, `GeneralizedTime` from 2050.
fn time_value(at: DateTime<Utc>) -> Vec<u8> {
    if (1950..2050).contains(&at.year()) {
        tlv(UTC_TIME, at.format("%y%m%d%H%M%SZ").to_string().as_bytes())
    } else {
        tlv(GENERALIZED_TIME, at.format("%Y%m%d%H%M%SZ").to_string().as_bytes())
    }
}

/// The signed document for `content`: a DER `ContentInfo` with the `SignedData` of one signer.
///
/// `certificates` start with the certificate of the signer, whose issuer and serial number identify it; the others are the
/// chain that is sent along. `sign` produces the signature over the signed attributes in the form `algorithm` names.
///
/// # Errors
///
/// Whatever `sign` returns.
pub(crate) fn signed_data<E>(
    content: &[u8],
    signed_at: DateTime<Utc>,
    certificates: &[Certificate],
    algorithm: Algorithm,
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, E>,
) -> Result<Vec<u8>, SignedDataError<E>> {
    let signer = certificates.first().ok_or(SignedDataError::NoSigner)?;
    let content_digest = digest(&SHA256, content);

    // The signed attributes. A DER `SET OF` is ordered by the encodings of its members.
    let mut attributes = [
        attribute(OID_CONTENT_TYPE, &oid(OID_DATA)),
        attribute(OID_SIGNING_TIME, &time_value(signed_at)),
        attribute(OID_MESSAGE_DIGEST, &tlv(OCTET_STRING, content_digest.as_ref())),
    ];
    attributes.sort();
    let attributes = attributes.concat();
    // The signature covers the attributes as a `SET OF`; in the `SignerInfo` the same bytes are tagged `[0]`.
    let signature = sign(&tlv(SET, &attributes)).map_err(SignedDataError::Signing)?;

    let digest_algorithm = tlv(SEQUENCE, &concat(&[&oid(OID_SHA256), &null()]));
    let issuer_and_serial = tlv(SEQUENCE, &concat(&[&signer.issuer, &signer.serial]));
    let signer_info = tlv(
        SEQUENCE,
        &concat(&[
            &small_integer(1),
            &issuer_and_serial,
            &digest_algorithm,
            &tlv(CONTEXT_0, &attributes),
            &algorithm.identifier(),
            &tlv(OCTET_STRING, &signature),
        ]),
    );
    let encapsulated = tlv(
        SEQUENCE,
        &concat(&[&oid(OID_DATA), &tlv(CONTEXT_0, &tlv(OCTET_STRING, content))]),
    );
    let certificates: Vec<u8> = certificates
        .iter()
        .flat_map(|certificate| certificate.der.iter().copied())
        .collect();
    let body = tlv(
        SEQUENCE,
        &concat(&[
            &small_integer(1),
            &tlv(SET, &digest_algorithm),
            &encapsulated,
            &tlv(CONTEXT_0, &certificates),
            &tlv(SET, &signer_info),
        ]),
    );
    Ok(tlv(SEQUENCE, &concat(&[&oid(OID_SIGNED_DATA), &tlv(CONTEXT_0, &body)])))
}

/// Why no signed document came out.
#[derive(Debug)]
pub(crate) enum SignedDataError<E> {
    /// There is no certificate to name as the signer.
    NoSigner,
    /// The signature could not be made.
    Signing(E),
}
