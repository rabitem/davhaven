//! Tests of the CMS profile signer: the structure of what it writes, a verification of the signature that shares no code
//! with the signing, the keys and certificates it accepts and refuses, and the port contract.

use std::sync::Arc;

use chrono::{TimeZone as _, Utc};
use davhaven_port_tests::profile_signer;
use davhaven_ports::{PortErrorKind, ProfileSigner};
use ring::digest::{SHA256, digest};
use ring::signature::{ECDSA_P256_SHA256_ASN1, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
use secrecy::SecretString;

use super::cms::{OID_DATA, OID_ECDSA_SHA256, OID_RSA_ENCRYPTION, OID_SHA256, OID_SIGNED_DATA};
use super::der::{CONTEXT_0, OCTET_STRING, OID, SEQUENCE, SET, UTC_TIME, tlv};
use super::x509::{Certificate, parse_certificate, pem_blocks};
use super::*;
use crate::testing::{Identity, KeyKind, identity, pem, rsa_test_key_pkcs8};

const PROFILE: &[u8] =
    b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict><key>PayloadType</key>\
    <string>Configuration</string></dict></plist>\n";

fn at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2027, 1, 12, 10, 30, 15).unwrap()
}

fn secret(text: &str) -> SecretString {
    SecretString::from(text)
}

fn signer_of(identity: &Identity) -> CmsProfileSigner {
    CmsProfileSigner::from_pem(&identity.certificate_pem, &secret(&identity.private_key_pem)).unwrap()
}

/// What a verifier reads from a signed document.
struct Parsed {
    content_type: Vec<u8>,
    content: Vec<u8>,
    certificates: Vec<Vec<u8>>,
    issuer_and_serial: Vec<u8>,
    signed_attributes: Vec<u8>,
    attribute_encodings: Vec<Vec<u8>>,
    signature_algorithm: Vec<u8>,
    digest_algorithm: Vec<u8>,
    signature: Vec<u8>,
}

fn first(bytes: &[u8]) -> super::der::Element<'_> {
    super::der::Reader::new(bytes).next().unwrap()
}

fn parse(der: &[u8]) -> Parsed {
    let info = first(der);
    assert_eq!(info.tag, SEQUENCE);
    let mut info_fields = super::der::Reader::new(info.content);
    assert_eq!(info_fields.next().unwrap().content, OID_SIGNED_DATA);
    let explicit = info_fields.next().unwrap();
    assert_eq!(explicit.tag, CONTEXT_0);
    assert!(info_fields.next().is_none(), "nothing follows the signed data");
    let body = first(explicit.content);
    let mut fields = super::der::Reader::new(body.content);
    assert_eq!(fields.next().unwrap().content, [1], "version 1: the content is id-data");
    assert_eq!(fields.next().unwrap().tag, SET, "digest algorithms");
    let encapsulated = fields.next().unwrap();
    let certificates = fields.next().unwrap();
    assert_eq!(certificates.tag, CONTEXT_0);
    let signer_infos = fields.next().unwrap();
    assert_eq!(signer_infos.tag, SET);
    assert!(fields.next().is_none());

    let mut encapsulated_fields = super::der::Reader::new(encapsulated.content);
    let content_type = encapsulated_fields.next().unwrap().content.to_vec();
    let wrapper = encapsulated_fields.next().unwrap();
    assert_eq!(wrapper.tag, CONTEXT_0);
    let octets = first(wrapper.content);
    assert_eq!(
        octets.tag, OCTET_STRING,
        "the profile is in the document, not beside it"
    );

    let info_of_signer = first(signer_infos.content);
    let mut signer_fields = super::der::Reader::new(info_of_signer.content);
    assert_eq!(signer_fields.next().unwrap().content, [1]);
    let issuer_and_serial = signer_fields.next().unwrap().content.to_vec();
    let digest_algorithm = signer_fields.next().unwrap().encoded.to_vec();
    let attributes = signer_fields.next().unwrap();
    assert_eq!(attributes.tag, CONTEXT_0, "signed attributes");
    let signature_algorithm = signer_fields.next().unwrap().encoded.to_vec();
    let signature = signer_fields.next().unwrap();
    assert_eq!(signature.tag, OCTET_STRING);
    assert!(signer_fields.next().is_none());

    Parsed {
        content_type,
        content: octets.content.to_vec(),
        certificates: super::der::Reader::new(certificates.content)
            .map(|certificate| certificate.encoded.to_vec())
            .collect(),
        issuer_and_serial,
        signed_attributes: attributes.content.to_vec(),
        attribute_encodings: super::der::Reader::new(attributes.content)
            .map(|attribute| attribute.encoded.to_vec())
            .collect(),
        signature_algorithm,
        digest_algorithm,
        signature: signature.content.to_vec(),
    }
}

/// The value of the attribute of type `kind`.
fn attribute_value(parsed: &Parsed, kind: &[u8]) -> Vec<u8> {
    for attribute in super::der::Reader::new(&parsed.signed_attributes) {
        let mut parts = super::der::Reader::new(attribute.content);
        if parts.next().unwrap().content == kind {
            let values = parts.next().unwrap();
            assert_eq!(values.tag, SET);
            return first(values.content).encoded.to_vec();
        }
    }
    panic!("the signed attributes have no attribute {kind:?}");
}

/// Verifies the document the way a device does: the digest of the content against the signed attribute, the signature over
/// the attributes against the key of the certificate the signer info names.
fn verify(der: &[u8], identity: &Identity, content: &[u8]) -> Parsed {
    let parsed = parse(der);
    assert_eq!(parsed.content_type, OID_DATA);
    assert_eq!(parsed.content, content);
    let wanted = digest(&SHA256, content);
    assert_eq!(
        attribute_value(&parsed, &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04]),
        tlv(OCTET_STRING, wanted.as_ref()),
        "the signed attribute holds the digest of the profile"
    );
    assert_eq!(
        attribute_value(&parsed, &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03]),
        tlv(OID, OID_DATA),
        "the content type"
    );
    let mut sorted = parsed.attribute_encodings.clone();
    sorted.sort();
    assert_eq!(parsed.attribute_encodings, sorted, "a DER SET OF is in order");

    let blocks = pem_blocks(&identity.certificate_pem).unwrap();
    let signer: Certificate = parse_certificate(&blocks[0].der).unwrap();
    assert_eq!(
        parsed.issuer_and_serial,
        [signer.issuer.as_slice(), signer.serial.as_slice()].concat(),
        "the signer info names the certificate by issuer and serial number"
    );
    assert_eq!(
        parsed.certificates.first(),
        Some(&*blocks[0].der),
        "the certificate of the signer comes first"
    );
    assert_eq!(
        parsed.digest_algorithm,
        tlv(SEQUENCE, &[tlv(OID, OID_SHA256), vec![5, 0]].concat())
    );

    // The signature covers the attributes written as a SET OF, not as the [0] they travel in.
    let covered = tlv(SET, &parsed.signed_attributes);
    let algorithm: &dyn ring::signature::VerificationAlgorithm = match identity.kind {
        KeyKind::Rsa => {
            assert_eq!(
                parsed.signature_algorithm,
                tlv(SEQUENCE, &[tlv(OID, OID_RSA_ENCRYPTION), vec![5, 0]].concat())
            );
            &RSA_PKCS1_2048_8192_SHA256
        }
        KeyKind::EcdsaP256 => {
            assert_eq!(parsed.signature_algorithm, tlv(SEQUENCE, &tlv(OID, OID_ECDSA_SHA256)));
            &ECDSA_P256_SHA256_ASN1
        }
    };
    UnparsedPublicKey::new(algorithm, &signer.public_key)
        .verify(&covered, &parsed.signature)
        .expect("the signature verifies with the key of the certificate");
    // And with nothing else: a changed attribute set does not verify.
    let mut forged = covered;
    if let Some(byte) = forged.last_mut() {
        *byte ^= 1;
    }
    assert!(
        UnparsedPublicKey::new(algorithm, &signer.public_key)
            .verify(&forged, &parsed.signature)
            .is_err()
    );
    parsed
}

#[test]
fn an_rsa_signed_profile_verifies_and_carries_the_profile_and_the_certificate() {
    let identity = identity(KeyKind::Rsa, "Davhaven test").unwrap();
    let signed = signer_of(&identity).sign(PROFILE, at()).unwrap();
    let parsed = verify(&signed, &identity, PROFILE);
    assert_eq!(parsed.certificates.len(), 1);
    // The signing time is the one that was given, as a UTCTime.
    let time = attribute_value(&parsed, &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05]);
    assert_eq!(time, tlv(UTC_TIME, b"270112103015Z"));
}

#[test]
fn an_elliptic_curve_signed_profile_verifies() {
    let identity = identity(KeyKind::EcdsaP256, "Davhaven test").unwrap();
    let signed = signer_of(&identity).sign(PROFILE, at()).unwrap();
    verify(&signed, &identity, PROFILE);
}

#[test]
fn the_chain_goes_along_and_the_signer_is_the_first_certificate() {
    let leaf = identity(KeyKind::EcdsaP256, "Leaf").unwrap();
    let intermediate = identity(KeyKind::Rsa, "Intermediate").unwrap();
    let chain = format!("{}{}", leaf.certificate_pem, intermediate.certificate_pem);
    let signer = CmsProfileSigner::from_pem(&chain, &secret(&leaf.private_key_pem)).unwrap();
    let document = signer.sign(PROFILE, at()).unwrap();
    let parsed = parse(&document);
    assert_eq!(parsed.certificates.len(), 2);
    let leaf_der = pem_blocks(&leaf.certificate_pem).unwrap().remove(0).der.to_vec();
    let intermediate_der = pem_blocks(&intermediate.certificate_pem)
        .unwrap()
        .remove(0)
        .der
        .to_vec();
    assert_eq!(parsed.certificates, [leaf_der, intermediate_der]);
    // The chain in the other order names the intermediate as the signer, whose key is not the one that was given.
    let reversed = format!("{}{}", intermediate.certificate_pem, leaf.certificate_pem);
    let error = CmsProfileSigner::from_pem(&reversed, &secret(&leaf.private_key_pem)).unwrap_err();
    assert!(error.to_string().contains("first certificate"), "{error}");
}

#[test]
fn rsa_signatures_are_deterministic_and_the_time_of_a_far_future_is_a_generalized_time() {
    let identity = identity(KeyKind::Rsa, "Davhaven test").unwrap();
    let signer = signer_of(&identity);
    assert_eq!(signer.sign(PROFILE, at()).unwrap(), signer.sign(PROFILE, at()).unwrap());
    assert_ne!(
        signer.sign(PROFILE, at()).unwrap(),
        signer.sign(PROFILE, at() + chrono::Duration::seconds(1)).unwrap(),
        "the signing time is part of the document"
    );
    let late = Utc.with_ymd_and_hms(2051, 3, 4, 5, 6, 7).unwrap();
    let parsed = parse(&signer.sign(PROFILE, late).unwrap());
    let time = attribute_value(&parsed, &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05]);
    assert_eq!(time, tlv(0x18, b"20510304050607Z"));
}

#[test]
fn every_form_of_key_that_openssl_writes_is_accepted() {
    let rsa = identity(KeyKind::Rsa, "Davhaven test").unwrap();
    // PKCS#1 (`BEGIN RSA PRIVATE KEY`) is what the identity carries; PKCS#8 wraps the same key.
    let pkcs8 = pem("PRIVATE KEY", &rsa_test_key_pkcs8().unwrap());
    for key in [rsa.private_key_pem.clone(), pkcs8] {
        let signer = CmsProfileSigner::from_pem(&rsa.certificate_pem, &secret(&key)).unwrap();
        verify(&signer.sign(PROFILE, at()).unwrap(), &rsa, PROFILE);
    }
    // Text around the blocks (what `openssl x509 -text` and bag attributes write) is ignored.
    let noisy = format!(
        "Bag Attributes\n    friendlyName: calendar\nsubject=CN=Davhaven test\n{}",
        rsa.certificate_pem
    );
    assert!(CmsProfileSigner::from_pem(&noisy, &secret(&rsa.private_key_pem)).is_ok());
}

#[test]
fn keys_and_certificates_that_cannot_be_used_are_refused_with_a_reason_and_no_key_material() {
    let rsa = identity(KeyKind::Rsa, "Davhaven test").unwrap();
    let ec = identity(KeyKind::EcdsaP256, "Davhaven test").unwrap();
    let cases = [
        // The key of another certificate.
        (
            rsa.certificate_pem.clone(),
            ec.private_key_pem.clone(),
            "does not belong to the first certificate",
        ),
        (
            ec.certificate_pem.clone(),
            rsa.private_key_pem.clone(),
            "does not belong to the first certificate",
        ),
        // Nothing usable in the files.
        (String::new(), rsa.private_key_pem.clone(), "contains no certificate"),
        (rsa.certificate_pem.clone(), String::new(), "contains no private key"),
        (
            rsa.private_key_pem.clone(),
            rsa.private_key_pem.clone(),
            "contains no certificate",
        ),
        (
            rsa.certificate_pem.clone(),
            rsa.certificate_pem.clone(),
            "contains no private key",
        ),
        // Forms that need a conversion.
        (
            rsa.certificate_pem.clone(),
            pem("ENCRYPTED PRIVATE KEY", &[1, 2, 3]),
            "the key is encrypted",
        ),
        (ec.certificate_pem.clone(), pem("EC PRIVATE KEY", &[1, 2, 3]), "SEC1"),
        // Damage.
        (
            rsa.certificate_pem.clone(),
            pem("PRIVATE KEY", &[1, 2, 3]),
            "neither an RSA key",
        ),
        (
            pem("CERTIFICATE", &[1, 2, 3]),
            rsa.private_key_pem.clone(),
            "a certificate cannot be read",
        ),
        (
            "-----BEGIN CERTIFICATE-----\nAQID\n".to_owned(),
            rsa.private_key_pem.clone(),
            "is not closed",
        ),
    ];
    for (certificate, key, reason) in cases {
        let error = CmsProfileSigner::from_pem(&certificate, &secret(&key))
            .unwrap_err()
            .to_string();
        assert!(error.contains(reason), "{reason}: {error}");
        assert!(
            !error.contains("MII") && !error.contains("MIG"),
            "no key material in {error}"
        );
    }
}

#[test]
fn an_empty_profile_is_refused_and_the_signer_does_not_show_its_key() {
    let identity = identity(KeyKind::Rsa, "Davhaven test").unwrap();
    let signer = signer_of(&identity);
    assert_eq!(signer.sign(b"", at()).unwrap_err().kind, PortErrorKind::Invalid);
    let shown = format!("{signer:?}");
    assert!(shown.contains("RsaSha256") && !shown.contains("MII"), "{shown}");
}

#[test]
fn the_configuration_names_both_files_or_none() {
    let none = ProfileSigningConfig::default();
    assert!(
        CmsProfileSigner::from_config(&none).unwrap().is_none(),
        "off unless configured"
    );
    for config in [
        ProfileSigningConfig {
            certificate_file: Some("cert.pem".into()),
            private_key_file: None,
        },
        ProfileSigningConfig {
            certificate_file: None,
            private_key_file: Some("key.pem".into()),
        },
    ] {
        let error = CmsProfileSigner::from_config(&config).unwrap_err().to_string();
        assert!(error.contains("security.profile_signing"), "{error}");
    }
    let missing = ProfileSigningConfig {
        certificate_file: Some("/nonexistent/cert.pem".into()),
        private_key_file: Some("/nonexistent/key.pem".into()),
    };
    let error = CmsProfileSigner::from_config(&missing).unwrap_err().to_string();
    assert!(
        error.contains("certificate_file") && error.contains("/nonexistent/cert.pem"),
        "{error}"
    );
}

/// A directory of its own for one test, which goes with it, so that tests that run at the same time (several runs on one host)
/// never touch each other's files, and a failed assertion leaves nothing behind.
pub(super) struct Scratch(pub(super) std::path::PathBuf);

impl Scratch {
    pub(super) fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let number = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("davhaven-profile-signing-{}-{number}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}

#[test]
fn the_signer_is_built_from_files() {
    let identity = identity(KeyKind::EcdsaP256, "Davhaven test").unwrap();
    let scratch = Scratch::new();
    let (certificate, key) = (scratch.0.join("fullchain.pem"), scratch.0.join("privkey.pem"));
    std::fs::write(&certificate, &identity.certificate_pem).unwrap();
    std::fs::write(&key, &identity.private_key_pem).unwrap();
    let config = ProfileSigningConfig {
        certificate_file: Some(certificate),
        private_key_file: Some(key),
    };
    let signer = CmsProfileSigner::from_config(&config).unwrap().unwrap();
    verify(&signer.sign(PROFILE, at()).unwrap(), &identity, PROFILE);
}

#[test]
fn the_signer_warns_when_its_certificate_has_run_out_or_is_about_to() {
    let identity = identity(KeyKind::EcdsaP256, "Davhaven test").unwrap();
    let signer = signer_of(&identity);
    // The certificates of the test identities are valid until the first of January 2036.
    let end = Utc.with_ymd_and_hms(2036, 1, 1, 0, 0, 0).unwrap();
    assert_eq!(signer.not_after(), Some(end));
    let days = |days: i64| chrono::Duration::days(days);
    assert_eq!(
        signer.expiry_warning(end - days(EXPIRY_WARNING_DAYS + 1)),
        None,
        "good for a while yet"
    );
    let soon = signer.expiry_warning(end - days(EXPIRY_WARNING_DAYS)).unwrap();
    assert!(
        soon.contains("2036-01-01")
            && soon.contains("without a restart")
            && soon.contains(&format!("in {EXPIRY_WARNING_DAYS} days")),
        "{soon}"
    );
    for now in [end, end + days(30)] {
        let expired = signer.expiry_warning(now).unwrap();
        assert!(
            expired.contains("expired on 2036-01-01") && expired.contains("within a minute"),
            "{expired}"
        );
    }
}

#[test]
fn the_signers_satisfy_the_port_contract() {
    for kind in [KeyKind::Rsa, KeyKind::EcdsaP256] {
        let identity = identity(kind, "Davhaven test").unwrap();
        profile_signer::run_all(|| Arc::new(signer_of(&identity)));
    }
}
