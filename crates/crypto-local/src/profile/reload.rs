//! A profile signer that follows its files: a renewed certificate is in use within a minute, without a restart.
//!
//! An ACME client renews the certificate about every 60 days and replaces `fullchain.pem` and `privkey.pem` by an atomic
//! rename. [`ReloadingProfileSigner`] signs with the [`CmsProfileSigner`] it holds and exchanges it for a new one when the
//! files have changed. The work is split in two so that signing never waits for the file system:
//!
//! * [`sign`](ProfileSigner::sign) takes the signer in use from a lock that is held for the length of one pointer copy. It
//!   never touches a file, and a signature that is being made while the signer is exchanged finishes with the old one.
//! * [`refresh`](ReloadingProfileSigner::refresh) does all the file I/O. It is synchronous and blocks on the file system, so
//!   the caller (the worker of the server) runs it on the blocking pool with a time budget. The caller passes the time in,
//!   taken from its `Clock`: the checks are [`CHECK_INTERVAL`] apart by that clock (less [`CLOCK_TOLERANCE`], see there), and
//!   a call that comes sooner answers [`Refresh::NotDue`] without looking at a file.
//!
//! **The files.** The certificate file holds the certificate of the signer first and then its chain; the key file holds the
//! private key. Both settings may name the same file, a combined PEM with the key and then the chain (the leaf first), which
//! is read once. The files must be reachable by their **directory**: a rename-replace of a file that is bind-mounted into a
//! container on its own, a Compose or Swarm secret, or a Kubernetes volume mounted with `subPath` is never seen, because
//! the mount pins the file that was there at the start (`docs/operations/keys.md`).
//!
//! **Detecting a change.** A check reads the metadata of the files (length, modification time and, where the platform has
//! them, device, inode and change time, which is what a rename-replace changes whatever the modification time says) and
//! compares it with the metadata of the files the signer in use was read from. Only a difference makes it read and parse the
//! files. The metadata is taken *before* the contents are read, so a file that is replaced in between is read in its newer
//! form under the older stamp, and the next check reads it once more instead of missing the replacement.
//!
//! **A pair that cannot be used** never replaces a signer that works: a key that does not belong to the certificate (two
//! files are renamed one after the other, so for a moment they do not fit), a file that is empty, truncated or not PEM, a
//! certificate that has ended already or that does not say when it ends. The signer in use stays and [`Refresh::Kept`] carries
//! the reason (it names the key and the file, never key material). A pair that was read and refused is remembered with the
//! metadata of its files and is not read again while they stay as they are (every check still answers `Kept`, so the pass
//! counts as failed for as long as it lasts); a file that could not be read at all is tried again at every check. A change of
//! the files, the second rename of a renewal for one, is looked at as usual.
//!
//! **A pair that makes the same signer** (the files were touched, or copied again: the same certificates and the same key) is
//! no change: nothing is swapped, nothing is logged, the generation stays.

use core::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use davhaven_ports::{PluginError, PortError, ProfileSigner};

use super::{CmsProfileSigner, PLUGIN, Pems};
use crate::config::ProfileSigningConfig;

/// The time between two checks of the files, by the clock of the caller. A call that comes sooner looks at nothing.
pub const CHECK_INTERVAL: Duration = Duration::from_mins(1);

/// How much earlier than [`CHECK_INTERVAL`] a check may come. The caller sleeps a whole interval between its passes by a
/// clock that does not jump, and `now` comes from the wall clock, which does: an NTP step of a second back would make the
/// next pass look 59 seconds late for the check and put it off by a whole interval more. A few seconds of tolerance keep
/// that from doubling the delay; the checks are still about a minute apart.
pub const CLOCK_TOLERANCE: Duration = Duration::from_secs(5);

/// The value of the time of the last check before there was one.
const NEVER: i64 = i64::MIN;

/// What identifies one version of a file without reading it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileStamp {
    len: u64,
    modified: Option<SystemTime>,
    /// The device and the inode: an atomic rename puts another file under the name, which has another inode.
    #[cfg(unix)]
    inode: (u64, u64),
    /// The change time (seconds and nanoseconds), which the kernel sets whenever the file or its inode changes, and which
    /// nobody can set back: it catches a replacement that carries the modification time of the file it replaces.
    #[cfg(unix)]
    changed: (i64, i64),
}

impl FileStamp {
    /// The stamp of the file `key` names, following links (a mounted secret is usually a link to the current version).
    fn of(key: &str, path: &Path) -> Result<Self, PluginError> {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt as _;
        let metadata = std::fs::metadata(path).map_err(|error| {
            PluginError::invalid_config(
                PLUGIN,
                format!("`{key}` ({}): cannot read the file ({})", path.display(), error.kind()),
            )
        })?;
        Ok(Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            inode: (metadata.dev(), metadata.ino()),
            #[cfg(unix)]
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
}

/// The stamps of the two files of a signer.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Stamp {
    certificate: FileStamp,
    key: FileStamp,
}

impl Stamp {
    fn of(certificate_file: &Path, private_key_file: &Path) -> Result<Self, PluginError> {
        Ok(Self {
            certificate: FileStamp::of("certificate_file", certificate_file)?,
            key: FileStamp::of("private_key_file", private_key_file)?,
        })
    }
}

/// The signer in use.
struct Loaded {
    signer: CmsProfileSigner,
    /// How many signers this one is the successor of, plus one: the first is generation 1.
    generation: u64,
}

/// What the checks remember about the files.
struct Seen {
    /// The stamp of the files that the signer in use stands for: the files it was read from, or files that make the same signer.
    accepted: Stamp,
    /// The stamp of a pair that was read and refused, and the reason: not read again until the files change.
    refused: Option<(Stamp, String)>,
}

/// What a call of [`ReloadingProfileSigner::refresh`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refresh {
    /// The last check is less than [`CHECK_INTERVAL`] ago: nothing was looked at.
    NotDue,
    /// Another call is checking the files right now: nothing was looked at. (The caller runs `refresh` on a blocking thread
    /// and may give up on a call that hangs on the file system; the next call then comes back at once instead of piling up
    /// one blocked thread per minute.) A caller that gets this after a whole interval has a check that hangs, and says so.
    Busy,
    /// The files are the ones the signer in use stands for: they did not change, or they changed to files that make the same
    /// signer (touched, copied again).
    Unchanged,
    /// The files changed and the signer was replaced.
    Reloaded {
        /// When the certificate of the new signer ends.
        not_after: Option<DateTime<Utc>>,
        /// The generation of the new signer: 2 for the first renewal, and so on.
        generation: u64,
    },
    /// The files changed (or could not be looked at) and the new pair cannot be used. The signer in use stays. A pair that was
    /// read and refused is not read again until its files change, and every check says so again; a file that could not be read
    /// is tried again at the next check.
    Kept {
        /// Why, for the log: it names the key and the file and never contains key material.
        reason: String,
    },
}

/// Why a pair or a file was refused, for the log: the message of the error without the name of the plugin.
fn reason_of(error: &PluginError) -> String {
    match error {
        PluginError::InvalidConfig { message, .. } => message.clone(),
        other => other.to_string(),
    }
}

impl Refresh {
    fn kept(error: &PluginError) -> Self {
        Self::Kept {
            reason: reason_of(error),
        }
    }
}

/// Clears the flag of a running check when the check ends, however it ends.
struct Running<'a>(&'a AtomicBool);

impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// A profile signer that picks up a renewed certificate (see the module documentation).
pub struct ReloadingProfileSigner {
    certificate_file: PathBuf,
    private_key_file: PathBuf,
    /// The signer in use. Replaced as a whole; readers copy the pointer and let go of the lock.
    current: RwLock<Arc<Loaded>>,
    /// What the checks remember about the files. Only a check writes it, and one check runs at a time.
    seen: RwLock<Seen>,
    /// The time of the last check as milliseconds since the epoch, [`NEVER`] before the first.
    last_check: AtomicI64,
    /// Whether a check is running.
    checking: AtomicBool,
    /// How many times the contents of the files were read, the read at the start included.
    reads: AtomicU64,
}

impl fmt::Debug for ReloadingProfileSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReloadingProfileSigner")
            .field("generation", &self.generation())
            .field("not_after", &self.not_after())
            .finish_non_exhaustive()
    }
}

impl ReloadingProfileSigner {
    /// The signer the configuration names, or `None` when signing is off (no file is named). The files are read now, as
    /// [`CmsProfileSigner::from_config`] reads them; a pair that does not fit, or a certificate that has ended already, is
    /// the caller's to refuse or to warn about ([`expiry_warning`](Self::expiry_warning)), exactly as for that signer.
    /// (A *reload* is stricter: it refuses a certificate that has ended or that does not say when it ends.)
    ///
    /// The load is not a check: the first call of [`refresh`](Self::refresh) looks at the files at once.
    ///
    /// # Errors
    ///
    /// [`PluginError::InvalidConfig`] as for [`CmsProfileSigner::from_config`].
    pub fn from_config(config: &ProfileSigningConfig) -> Result<Option<Self>, PluginError> {
        config.validate()?;
        let (Some(certificate_file), Some(private_key_file)) = (&config.certificate_file, &config.private_key_file)
        else {
            return Ok(None);
        };
        // The stamp of the files first and then their contents: the order that the module documentation gives.
        let stamp = Stamp::of(certificate_file, private_key_file)?;
        let signer = CmsProfileSigner::from_files(certificate_file, private_key_file)?;
        Ok(Some(Self {
            certificate_file: certificate_file.clone(),
            private_key_file: private_key_file.clone(),
            current: RwLock::new(Arc::new(Loaded { signer, generation: 1 })),
            seen: RwLock::new(Seen {
                accepted: stamp,
                refused: None,
            }),
            last_check: AtomicI64::new(NEVER),
            checking: AtomicBool::new(false),
            reads: AtomicU64::new(1),
        }))
    }

    /// The signer in use.
    fn loaded(&self) -> Arc<Loaded> {
        Arc::clone(&self.current.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// When the certificate of the signer in use ends, if it says so in a form that can be read.
    pub fn not_after(&self) -> Option<DateTime<Utc>> {
        self.loaded().signer.not_after()
    }

    /// Which signer is in use: 1 for the one that was read at the start, one more for every renewal that was picked up.
    pub fn generation(&self) -> u64 {
        self.loaded().generation
    }

    /// How many times the contents of the files were read: once at the start, and then once for every look at files that
    /// changed (a pair that was refused is not read again until its files change, and unchanged files are not read at all).
    pub fn reads(&self) -> u64 {
        self.reads.load(Ordering::Relaxed)
    }

    /// What the operator should hear when the certificate in use has run out or is about to (see
    /// [`CmsProfileSigner::expiry_warning`]).
    pub fn expiry_warning(&self, now: DateTime<Utc>) -> Option<String> {
        self.loaded().signer.expiry_warning(now)
    }

    /// Whether a check is due at `now`: none was made yet, the last one is [`CHECK_INTERVAL`] ago (less [`CLOCK_TOLERANCE`]),
    /// or `now` is before the last one (the clock was set back: a check is overdue for sure, and waiting for the clock to catch
    /// up would stall the renewal).
    fn due(&self, now: DateTime<Utc>) -> bool {
        let last = self.last_check.load(Ordering::Acquire);
        let now = now.timestamp_millis();
        let millis = |span: Duration| i64::try_from(span.as_millis()).unwrap_or(i64::MAX);
        let wait = millis(CHECK_INTERVAL).saturating_sub(millis(CLOCK_TOLERANCE));
        last == NEVER || now < last || now.saturating_sub(last) >= wait
    }

    /// Looks at the files if the last look is a whole [`CHECK_INTERVAL`] ago by `now` (less [`CLOCK_TOLERANCE`]), and replaces
    /// the signer when they changed and the new pair works (see the module documentation).
    ///
    /// This blocks on the file system: call it on a blocking thread, never on an async worker thread.
    pub fn refresh(&self, now: DateTime<Utc>) -> Refresh {
        if !self.due(now) {
            return Refresh::NotDue;
        }
        if self
            .checking
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Refresh::Busy;
        }
        let _running = Running(&self.checking);
        // A check may have ended between the first test and the claim.
        if !self.due(now) {
            return Refresh::NotDue;
        }
        // Marked at the start: a check that fails or takes long still spaces the next one a whole interval from now.
        self.last_check.store(now.timestamp_millis(), Ordering::Release);
        self.check(now)
    }

    /// Remembers that the pair with `stamp` was read and refused, and says why.
    fn refuse(&self, stamp: Stamp, reason: String) -> Refresh {
        self.seen.write().unwrap_or_else(PoisonError::into_inner).refused = Some((stamp, reason.clone()));
        Refresh::Kept { reason }
    }

    fn check(&self, now: DateTime<Utc>) -> Refresh {
        let stamp = match Stamp::of(&self.certificate_file, &self.private_key_file) {
            Ok(stamp) => stamp,
            Err(error) => return Refresh::kept(&error),
        };
        {
            let seen = self.seen.read().unwrap_or_else(PoisonError::into_inner);
            if stamp == seen.accepted {
                return Refresh::Unchanged;
            }
            if let Some((refused, reason)) = &seen.refused
                && *refused == stamp
            {
                return Refresh::Kept { reason: reason.clone() };
            }
        }
        self.reads.fetch_add(1, Ordering::Relaxed);
        // A file that cannot be read is not remembered: the next check reads it again.
        let pems = match Pems::read(&self.certificate_file, &self.private_key_file) {
            Ok(pems) => pems,
            Err(error) => return Refresh::kept(&error),
        };
        let candidate = match pems.signer() {
            Ok(signer) => signer,
            Err(error) => return self.refuse(stamp, reason_of(&error)),
        };
        let not_after = candidate.not_after();
        match not_after {
            None => {
                return self.refuse(
                    stamp,
                    "the new certificate does not say when it ends in a form that can be read".to_owned(),
                );
            }
            Some(end) if end <= now => {
                return self.refuse(
                    stamp,
                    format!("the new certificate ended on {}", end.format("%Y-%m-%d")),
                );
            }
            Some(_) => {}
        }
        let current = self.loaded();
        let mut seen = self.seen.write().unwrap_or_else(PoisonError::into_inner);
        seen.accepted = stamp;
        seen.refused = None;
        if current.signer.same_identity(&candidate) {
            return Refresh::Unchanged;
        }
        let generation = current.generation.saturating_add(1);
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(Loaded {
            signer: candidate,
            generation,
        });
        Refresh::Reloaded { not_after, generation }
    }
}

impl ProfileSigner for ReloadingProfileSigner {
    fn sign(&self, profile: &[u8], signed_at: DateTime<Utc>) -> Result<Vec<u8>, PortError> {
        self.loaded().signer.sign(profile, signed_at)
    }
}

#[cfg(test)]
mod tests;
