//! Tests of the signer that follows its files: a renewal is picked up, a pair that cannot be used keeps the signer in use, an
//! unchanged pair is not read again, and the checks are paced by the clock they are given.
//!
//! The files are real (a directory of its own per test) and are replaced the way an ACME client does it: written beside and
//! renamed over. Time is only what the tests pass in.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use chrono::{Duration as Span, TimeZone as _};
use davhaven_port_tests::profile_signer;

use super::*;
use crate::profile::tests::Scratch;
use crate::profile::x509::pem_blocks;
use crate::testing::{Identity, KeyKind, identity, identity_ending, identity_without_readable_end};

const PROFILE: &[u8] = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict/></plist>";

fn at(year: i32, month: u32, day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).unwrap()
}

/// The moment the tests start: after the certificates were issued, before every certificate of the tests ends.
fn start() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2027, 1, 12, 10, 0, 0).unwrap()
}

fn minute() -> Span {
    Span::minutes(1)
}

/// The certificate of the signer in `identity`, as DER.
fn leaf(identity: &Identity) -> Vec<u8> {
    pem_blocks(&identity.certificate_pem).unwrap()[0].der.to_vec()
}

/// Whether a profile that `signer` signs now carries the certificate of `identity`.
fn signs_with(signer: &ReloadingProfileSigner, identity: &Identity) -> bool {
    let document = signer.sign(PROFILE, start()).unwrap();
    let wanted = leaf(identity);
    document.windows(wanted.len()).any(|window| window == wanted)
}

/// Replaces `path` the way an ACME client does: the new content is written beside it and renamed over it.
fn replace(path: &Path, content: &str) {
    let beside = path.with_extension("new");
    std::fs::write(&beside, content).unwrap();
    std::fs::rename(&beside, path).unwrap();
}

/// The text of a combined PEM file: the private key, then the certificate of the signer.
fn combined_pem(identity: &Identity) -> String {
    format!("{}{}", identity.private_key_pem, identity.certificate_pem)
}

/// The two files of a deployment, in a directory of their own.
struct Deployment {
    _scratch: Scratch,
    certificate: PathBuf,
    key: PathBuf,
}

impl Deployment {
    fn new(identity: &Identity) -> Self {
        let scratch = Scratch::new();
        let (certificate, key) = (scratch.0.join("fullchain.pem"), scratch.0.join("privkey.pem"));
        std::fs::write(&certificate, &identity.certificate_pem).unwrap();
        std::fs::write(&key, &identity.private_key_pem).unwrap();
        Self {
            _scratch: scratch,
            certificate,
            key,
        }
    }

    /// A deployment with one combined PEM file for both settings: the key, then the chain with the leaf first.
    fn combined(identity: &Identity) -> Self {
        let scratch = Scratch::new();
        let file = scratch.0.join("combined.pem");
        std::fs::write(&file, combined_pem(identity)).unwrap();
        Self {
            _scratch: scratch,
            certificate: file.clone(),
            key: file,
        }
    }

    /// Replaces the combined file the way a client does.
    fn renew_combined(&self, identity: &Identity) {
        replace(&self.certificate, &combined_pem(identity));
    }

    fn config(&self) -> ProfileSigningConfig {
        ProfileSigningConfig {
            certificate_file: Some(self.certificate.clone()),
            private_key_file: Some(self.key.clone()),
        }
    }

    fn signer(&self) -> ReloadingProfileSigner {
        ReloadingProfileSigner::from_config(&self.config()).unwrap().unwrap()
    }

    fn renew_certificate(&self, identity: &Identity) {
        replace(&self.certificate, &identity.certificate_pem);
    }

    fn renew_key(&self, identity: &Identity) {
        replace(&self.key, &identity.private_key_pem);
    }

    /// Both files, one rename after the other as the client does it.
    fn renew(&self, identity: &Identity) {
        self.renew_certificate(identity);
        self.renew_key(identity);
    }
}

#[test]
fn a_renewed_certificate_is_picked_up_at_the_next_check() {
    let old = identity_ending(KeyKind::Rsa, "old", at(2027, 3, 1)).unwrap();
    let new = identity_ending(KeyKind::EcdsaP256, "new", at(2027, 6, 1)).unwrap();
    let deployment = Deployment::new(&old);
    let signer = deployment.signer();
    assert_eq!(signer.generation(), 1);
    assert_eq!(signer.not_after(), Some(at(2027, 3, 1)));
    assert!(signs_with(&signer, &old));
    assert_eq!(
        signer.refresh(start()),
        Refresh::Unchanged,
        "the first check finds the files as they were read"
    );

    deployment.renew(&new);
    assert_eq!(
        signer.refresh(start() + Span::seconds(30)),
        Refresh::NotDue,
        "a check a minute after the last one, not before"
    );
    assert!(signs_with(&signer, &old), "so the renewal is not in use yet");

    assert_eq!(
        signer.refresh(start() + minute()),
        Refresh::Reloaded {
            not_after: Some(at(2027, 6, 1)),
            generation: 2
        }
    );
    assert_eq!(
        signer.not_after(),
        Some(at(2027, 6, 1)),
        "the certificate in use says so"
    );
    assert!(signs_with(&signer, &new));
    assert!(!signs_with(&signer, &old));
    assert_eq!(
        signer.refresh(start() + minute() * 2),
        Refresh::Unchanged,
        "the files the new signer was read from are the files now"
    );
    assert_eq!(signer.generation(), 2);
}

#[test]
fn a_certificate_renewed_for_the_same_key_is_picked_up_without_the_key_changing() {
    // `certbot --reuse-key`: the certificate is replaced, the key file is not touched.
    let old = identity_ending(KeyKind::Rsa, "old", at(2027, 3, 1)).unwrap();
    let new = identity_ending(KeyKind::Rsa, "new", at(2027, 6, 1)).unwrap();
    assert_eq!(old.private_key_pem, new.private_key_pem);
    let deployment = Deployment::new(&old);
    let signer = deployment.signer();
    deployment.renew_certificate(&new);
    assert_eq!(
        signer.refresh(start()),
        Refresh::Reloaded {
            not_after: Some(at(2027, 6, 1)),
            generation: 2
        }
    );
    assert!(signs_with(&signer, &new));
}

#[test]
fn a_pair_that_does_not_fit_keeps_the_signer_in_use_and_is_judged_once_while_the_files_stay_as_they_are() {
    let old = identity_ending(KeyKind::Rsa, "old", at(2027, 3, 1)).unwrap();
    let new = identity_ending(KeyKind::EcdsaP256, "new", at(2027, 6, 1)).unwrap();
    let deployment = Deployment::new(&old);
    let signer = deployment.signer();

    // The client renames the two files one after the other: for a moment the new certificate meets the old key.
    deployment.renew_certificate(&new);
    let Refresh::Kept { reason } = signer.refresh(start()) else {
        panic!("a key that does not belong to the certificate replaced the signer");
    };
    assert!(
        reason.contains("private_key_file") && reason.contains("does not belong"),
        "{reason}"
    );
    for line in old.private_key_pem.lines().filter(|line| line.len() > 20) {
        assert!(!reason.contains(line), "the reason quotes the key: {reason}");
    }
    assert!(signs_with(&signer, &old), "the signer in use signs on");
    assert_eq!(signer.generation(), 1);

    // Nothing changed since, and the pair is still unusable: every check says so again (the pass counts as failed for as long
    // as it lasts), but the files are not read and parsed again.
    let reads = signer.reads();
    assert_eq!(reads, 2, "the start and the look at the new pair");
    for later in [1, 2, 3] {
        assert_eq!(
            signer.refresh(start() + minute() * later),
            Refresh::Kept { reason: reason.clone() }
        );
    }
    assert_eq!(
        signer.reads(),
        reads,
        "an unchanged pair that was refused is not read again"
    );
    assert!(signs_with(&signer, &old));

    deployment.renew_key(&new);
    assert_eq!(
        signer.refresh(start() + minute() * 4),
        Refresh::Reloaded {
            not_after: Some(at(2027, 6, 1)),
            generation: 2
        },
        "the second rename of the renewal is a change, and it is looked at"
    );
    assert!(signs_with(&signer, &new));
    assert_eq!(signer.reads(), reads + 1);
}

#[test]
fn a_file_that_is_half_written_or_not_a_pem_keeps_the_signer_in_use() {
    let old = identity_ending(KeyKind::Rsa, "old", at(2027, 3, 1)).unwrap();
    let new = identity_ending(KeyKind::EcdsaP256, "new", at(2027, 6, 1)).unwrap();
    let deployment = Deployment::new(&old);
    let signer = deployment.signer();
    let truncated: String = new
        .certificate_pem
        .chars()
        .take(new.certificate_pem.len() / 2)
        .collect();
    let mut now = start();

    for (path, content, expected) in [
        (&deployment.certificate, "", "the file is empty"),
        (&deployment.certificate, truncated.as_str(), "is not closed"),
        (
            &deployment.certificate,
            "this is not a pem file\n",
            "the file contains no certificate",
        ),
        (&deployment.key, "-----BEGIN PRIVATE KEY-----\nAAAA\n", "is not closed"),
    ] {
        // Written in place and not renamed: the way a process that does not know better rewrites a file.
        std::fs::write(path, content).unwrap();
        let Refresh::Kept { reason } = signer.refresh(now) else {
            panic!("`{content}` replaced the signer");
        };
        assert!(reason.contains(expected), "{expected}: {reason}");
        assert!(signs_with(&signer, &old));
        assert_eq!(signer.generation(), 1);
        now += minute();
        // The pair in use is put back the way a client does it (a new file under each name), for the next round: files that
        // make the signer that is in use anyway change nothing.
        replace(&deployment.certificate, &old.certificate_pem);
        replace(&deployment.key, &old.private_key_pem);
        assert_eq!(
            signer.refresh(now),
            Refresh::Unchanged,
            "the files are good again, and the same"
        );
        assert_eq!(signer.generation(), 1);
        now += minute();
    }

    deployment.renew(&new);
    assert_eq!(
        signer.refresh(now),
        Refresh::Reloaded {
            not_after: Some(at(2027, 6, 1)),
            generation: 2
        }
    );
    assert!(signs_with(&signer, &new));
}

#[test]
fn a_certificate_that_has_ended_is_not_taken_but_one_that_ends_soon_is() {
    let old = identity_ending(KeyKind::Rsa, "old", at(2027, 6, 1)).unwrap();
    let ended = identity_ending(KeyKind::Rsa, "ended", at(2027, 1, 1)).unwrap();
    let deployment = Deployment::new(&old);
    let signer = deployment.signer();
    deployment.renew(&ended);
    let Refresh::Kept { reason } = signer.refresh(start()) else {
        panic!("a certificate that has ended replaced the signer");
    };
    assert!(reason.contains("ended on 2027-01-01"), "{reason}");
    assert!(signs_with(&signer, &old));
    assert_eq!(
        signer.not_after(),
        Some(at(2027, 6, 1)),
        "the gauge keeps the certificate in use"
    );

    let soon = identity_ending(KeyKind::Rsa, "soon", start() + Span::days(1)).unwrap();
    deployment.renew(&soon);
    assert!(
        matches!(
            signer.refresh(start() + minute()),
            Refresh::Reloaded { generation: 2, .. }
        ),
        "ending tomorrow is no reason to refuse it: the renewal is the better one"
    );
}

#[test]
fn a_certificate_that_has_ended_is_taken_at_the_start_and_warned_about() {
    // The start keeps what it always did: it serves (devices show the profiles as expired) and says so.
    let ended = identity_ending(KeyKind::Rsa, "ended", at(2027, 1, 1)).unwrap();
    let deployment = Deployment::new(&ended);
    let signer = deployment.signer();
    assert_eq!(signer.generation(), 1);
    let warning = signer.expiry_warning(start()).unwrap();
    assert!(warning.contains("expired on 2027-01-01"), "{warning}");
}

#[test]
fn a_file_that_vanishes_keeps_the_signer_and_comes_back_with_the_next_check() {
    let identity = identity_ending(KeyKind::Rsa, "Davhaven test", at(2027, 3, 1)).unwrap();
    let deployment = Deployment::new(&identity);
    let signer = deployment.signer();
    std::fs::remove_file(&deployment.certificate).unwrap();
    let Refresh::Kept { reason } = signer.refresh(start()) else {
        panic!("a missing file replaced the signer");
    };
    assert!(
        reason.contains("certificate_file") && reason.contains("cannot read the file"),
        "{reason}"
    );
    assert!(signs_with(&signer, &identity));

    // The file comes back as a renewed certificate. (Its common name is longer, so its length differs: a new file may get the
    // inode of the one that was removed, and a file of the same length written within the same tick of the file system clock
    // would carry the same metadata. A renewal is a new file beside the old one and 60 days later, which never does.)
    let renewed = identity_ending(KeyKind::Rsa, "Davhaven test, renewed certificate", at(2027, 6, 1)).unwrap();
    deployment.renew_certificate(&renewed);
    assert_eq!(
        signer.refresh(start() + minute()),
        Refresh::Reloaded {
            not_after: Some(at(2027, 6, 1)),
            generation: 2
        },
        "the file is a new file again"
    );
    assert!(signs_with(&signer, &renewed));
}

#[test]
fn files_that_did_not_change_are_not_read_again() {
    let identity = identity(KeyKind::EcdsaP256, "Davhaven test").unwrap();
    let deployment = Deployment::new(&identity);
    let signer = deployment.signer();
    let mut now = start();
    for _ in 0..5 {
        assert_eq!(signer.refresh(now), Refresh::Unchanged);
        now += minute() * 90;
    }
    assert_eq!(signer.generation(), 1, "no check rebuilt the signer");
    assert_eq!(signer.reads(), 1, "and none read the files: only the start did");
}

#[cfg(unix)]
#[test]
fn a_replacement_that_has_the_length_and_the_modification_time_of_the_file_is_still_noticed() {
    // The certificates differ in their end only: the same length, and with the time put back the same modification time. The
    // inode and the change time are what tell them apart.
    let old = identity_ending(KeyKind::Rsa, "same", at(2027, 3, 1)).unwrap();
    let new = identity_ending(KeyKind::Rsa, "same", at(2027, 6, 1)).unwrap();
    assert_eq!(old.certificate_pem.len(), new.certificate_pem.len());
    let deployment = Deployment::new(&old);
    let signer = deployment.signer();
    let modified = std::fs::metadata(&deployment.certificate).unwrap().modified().unwrap();
    let beside = deployment.certificate.with_extension("new");
    std::fs::write(&beside, &new.certificate_pem).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&beside)
        .unwrap()
        .set_modified(modified)
        .unwrap();
    std::fs::rename(&beside, &deployment.certificate).unwrap();
    assert_eq!(
        std::fs::metadata(&deployment.certificate).unwrap().modified().unwrap(),
        modified
    );
    assert!(matches!(
        signer.refresh(start()),
        Refresh::Reloaded { generation: 2, .. }
    ));
    assert!(signs_with(&signer, &new));
}

#[test]
fn the_clock_that_is_given_paces_the_checks() {
    let identity = identity(KeyKind::EcdsaP256, "Davhaven test").unwrap();
    let deployment = Deployment::new(&identity);
    let signer = deployment.signer();
    let first = start();
    assert_eq!(signer.refresh(first), Refresh::Unchanged);
    // A minute, less the tolerance that keeps a clock that stepped back by a second from doubling the delay.
    for sooner in [first, first + Span::milliseconds(54_999)] {
        assert_eq!(signer.refresh(sooner), Refresh::NotDue, "{sooner}");
    }
    assert_eq!(signer.refresh(first + Span::seconds(55)), Refresh::Unchanged);
    assert_eq!(
        signer.refresh(first + Span::seconds(55) + Span::seconds(54)),
        Refresh::NotDue,
        "the interval counts from the last check"
    );
    assert_eq!(
        signer.refresh(first + Span::seconds(55) + Span::seconds(55)),
        Refresh::Unchanged
    );
    // The clock went back (it was set, or the host was restored): a check is due at once instead of after the clock has
    // caught up with the time of the last one.
    assert_eq!(signer.refresh(first - Span::hours(1)), Refresh::Unchanged);
    assert_eq!(
        signer.refresh(first - Span::hours(1) + Span::seconds(1)),
        Refresh::NotDue
    );
}

#[test]
fn a_check_that_is_running_is_not_started_twice_and_signing_does_not_wait_for_it() {
    let identity = identity(KeyKind::EcdsaP256, "Davhaven test").unwrap();
    let deployment = Deployment::new(&identity);
    let signer = deployment.signer();
    signer.checking.store(true, Ordering::SeqCst);
    assert_eq!(signer.refresh(start()), Refresh::Busy);
    assert!(signs_with(&signer, &identity), "signing never looks at the check");
    signer.checking.store(false, Ordering::SeqCst);
    assert_eq!(
        signer.refresh(start()),
        Refresh::Unchanged,
        "the call that found the check running did not use up the interval"
    );
    assert!(
        !signer.checking.load(Ordering::SeqCst),
        "a check that ends clears its mark"
    );
}

#[test]
fn signing_off_is_no_signer() {
    assert!(
        ReloadingProfileSigner::from_config(&ProfileSigningConfig::default())
            .unwrap()
            .is_none()
    );
    let half = ProfileSigningConfig {
        certificate_file: Some("cert.pem".into()),
        private_key_file: None,
    };
    assert!(ReloadingProfileSigner::from_config(&half).is_err());
    let missing = ProfileSigningConfig {
        certificate_file: Some("/nonexistent/cert.pem".into()),
        private_key_file: Some("/nonexistent/key.pem".into()),
    };
    let error = ReloadingProfileSigner::from_config(&missing).unwrap_err().to_string();
    assert!(
        error.contains("certificate_file") && error.contains("/nonexistent/cert.pem"),
        "{error}"
    );
}

#[test]
fn the_debug_output_shows_neither_a_path_nor_key_material() {
    let identity = identity(KeyKind::Rsa, "Davhaven test").unwrap();
    let deployment = Deployment::new(&identity);
    let shown = format!("{:?}", deployment.signer());
    assert!(shown.contains("generation"), "{shown}");
    assert!(!shown.contains("privkey") && !shown.contains("MII"), "{shown}");
}

#[test]
fn the_reloading_signers_satisfy_the_port_contract() {
    for kind in [KeyKind::Rsa, KeyKind::EcdsaP256] {
        let identity = identity(kind, "Davhaven test").unwrap();
        let deployment = Deployment::new(&identity);
        profile_signer::run_all(|| Arc::new(deployment.signer()));
    }
}

#[test]
fn one_combined_file_for_both_settings_follows_a_renewal_with_the_same_key() {
    // The key, then the chain with the leaf first, in one file that both settings name; `certbot --reuse-key`.
    let old = identity_ending(KeyKind::Rsa, "old", at(2027, 3, 1)).unwrap();
    let new = identity_ending(KeyKind::Rsa, "new", at(2027, 6, 1)).unwrap();
    let deployment = Deployment::combined(&old);
    let signer = deployment.signer();
    assert_eq!(signer.not_after(), Some(at(2027, 3, 1)));
    assert!(signs_with(&signer, &old));
    assert_eq!(signer.refresh(start()), Refresh::Unchanged);

    deployment.renew_combined(&new);
    assert_eq!(
        signer.refresh(start() + minute()),
        Refresh::Reloaded {
            not_after: Some(at(2027, 6, 1)),
            generation: 2
        }
    );
    assert!(signs_with(&signer, &new));
    assert!(!signs_with(&signer, &old));
    assert_eq!(
        signer.reads(),
        2,
        "the file is read once for both settings, at the start and at the renewal"
    );
}

#[test]
fn one_combined_file_for_both_settings_follows_a_renewal_with_a_new_key() {
    // One rename replaces certificate and key together, so there is no moment in which they do not fit.
    let old = identity_ending(KeyKind::Rsa, "old", at(2027, 3, 1)).unwrap();
    let new = identity_ending(KeyKind::EcdsaP256, "new", at(2027, 6, 1)).unwrap();
    let deployment = Deployment::combined(&old);
    let signer = deployment.signer();
    deployment.renew_combined(&new);
    assert_eq!(
        signer.refresh(start()),
        Refresh::Reloaded {
            not_after: Some(at(2027, 6, 1)),
            generation: 2
        },
        "no `Kept` on the way: a combined file is never half renewed"
    );
    assert!(signs_with(&signer, &new));
    assert_eq!(signer.refresh(start() + minute()), Refresh::Unchanged);

    // And it keeps the rules of the pair: a file whose key does not belong to its certificate is refused as a whole.
    let mismatched = format!("{}{}", old.private_key_pem, new.certificate_pem);
    replace(&deployment.certificate, &mismatched);
    let Refresh::Kept { reason } = signer.refresh(start() + minute() * 2) else {
        panic!("a combined file with a key that does not belong to its certificate replaced the signer");
    };
    assert!(reason.contains("does not belong"), "{reason}");
    assert!(signs_with(&signer, &new));
}

#[test]
fn a_combined_file_may_hold_the_chain_before_the_key_and_a_file_without_a_key_is_refused() {
    let identity = identity_ending(KeyKind::EcdsaP256, "order", at(2027, 3, 1)).unwrap();
    let deployment = Deployment::combined(&identity);
    replace(
        &deployment.certificate,
        &format!("{}{}", identity.certificate_pem, identity.private_key_pem),
    );
    assert!(
        signs_with(&deployment.signer(), &identity),
        "the order of the blocks does not matter"
    );

    std::fs::write(&deployment.certificate, &identity.certificate_pem).unwrap();
    let error = ReloadingProfileSigner::from_config(&deployment.config())
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("private_key_file") && error.contains("no private key"),
        "{error}"
    );
}

#[test]
fn a_certificate_that_does_not_say_when_it_ends_is_taken_at_the_start_but_not_by_a_reload() {
    let old = identity_ending(KeyKind::Rsa, "old", at(2027, 6, 1)).unwrap();
    let unreadable = identity_without_readable_end(KeyKind::Rsa, "unreadable").unwrap();
    let deployment = Deployment::new(&unreadable);
    let boot = deployment.signer();
    assert_eq!(boot.not_after(), None);
    assert_eq!(boot.expiry_warning(start()), None, "the start cannot tell, and serves");

    let deployment = Deployment::new(&old);
    let signer = deployment.signer();
    deployment.renew_certificate(&unreadable);
    let Refresh::Kept { reason } = signer.refresh(start()) else {
        panic!("a certificate that does not say when it ends replaced the signer");
    };
    assert!(reason.contains("does not say when it ends"), "{reason}");
    assert_eq!(
        signer.not_after(),
        Some(at(2027, 6, 1)),
        "the gauge keeps the certificate in use"
    );
    let reads = signer.reads();
    assert!(matches!(signer.refresh(start() + minute()), Refresh::Kept { .. }));
    assert_eq!(signer.reads(), reads, "judged once");
}

#[test]
fn files_that_are_touched_or_copied_again_make_the_same_signer_and_change_nothing() {
    let identity = identity_ending(KeyKind::Rsa, "same", at(2027, 3, 1)).unwrap();
    let deployment = Deployment::new(&identity);
    let signer = deployment.signer();
    let mut now = start();

    // The same content under a new file (a re-copy), and a rewrite in place with the same content: both change the metadata.
    deployment.renew(&identity);
    assert_eq!(signer.refresh(now), Refresh::Unchanged, "no swap, no generation");
    assert_eq!(signer.generation(), 1);
    assert_eq!(
        signer.reads(),
        2,
        "the changed files were read, to find that they are the same"
    );
    now += minute();
    assert_eq!(signer.refresh(now), Refresh::Unchanged);
    assert_eq!(
        signer.reads(),
        2,
        "and the new metadata is the one that counts from now on"
    );

    std::fs::write(&deployment.certificate, &identity.certificate_pem).unwrap();
    now += minute();
    assert_eq!(signer.refresh(now), Refresh::Unchanged);
    assert_eq!(signer.generation(), 1);
    assert!(signs_with(&signer, &identity));

    // A change of the chain alone, with the same leaf, is a different signer: the chain goes into the signature.
    let chain = format!(
        "{}{}",
        identity.certificate_pem,
        identity_ending(KeyKind::EcdsaP256, "issuer", at(2030, 1, 1))
            .unwrap()
            .certificate_pem
    );
    replace(&deployment.certificate, &chain);
    now += minute();
    assert_eq!(
        signer.refresh(now),
        Refresh::Reloaded {
            not_after: Some(at(2027, 3, 1)),
            generation: 2
        }
    );
}
