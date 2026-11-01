//! Tests of the worker of the profile signer: a renewal is picked up through the clock of the worker, an unusable pair keeps the
//! signer in use, the gauge follows the leaf certificate in use and is absent while signing is off, and a hung file system ends
//! the pass at its budget.
//!
//! The files are real (a temporary directory per test), replaced the way an ACME client replaces them, and the metrics are
//! rendered by a Prometheus recorder that only the test thread sees.

use std::path::{Path, PathBuf};

use chrono::{TimeDelta, TimeZone as _};
use davhaven_crypto_local::config::ProfileSigningConfig;
use davhaven_crypto_local::testing::{Identity, KeyKind, identity_ending};
use davhaven_ports::ProfileSigner as _;
use davhaven_ports::testing::ManualClock;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

use super::*;
use crate::assembly::assemble;
use crate::config::Config;
use crate::registry::registry;

const PROFILE: &[u8] = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict/></plist>";

fn at(year: i32, month: u32, day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).unwrap()
}

/// The moment the tests start: after the certificates were issued, before every one of them ends.
fn start() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2027, 1, 12, 10, 0, 0).unwrap()
}

fn minute() -> TimeDelta {
    TimeDelta::minutes(1)
}

/// The value of the gauge of the certificate, if the recorder has the series.
fn gauge(handle: &PrometheusHandle) -> Option<f64> {
    let prefix = format!("{CERTIFICATE_EXPIRY_TIMESTAMP_SECONDS} ");
    handle
        .render()
        .lines()
        .find_map(|line| line.strip_prefix(&prefix).and_then(|value| value.trim().parse().ok()))
}

/// The two files of a deployment, in a directory of their own.
struct Files {
    _directory: tempfile::TempDir,
    certificate: PathBuf,
    key: PathBuf,
}

/// Replaces `path` the way an ACME client does: written beside, renamed over.
fn replace(path: &Path, content: &str) {
    let beside = path.with_extension("new");
    std::fs::write(&beside, content).unwrap();
    std::fs::rename(&beside, path).unwrap();
}

impl Files {
    fn new(identity: &Identity) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let (certificate, key) = (
            directory.path().join("fullchain.pem"),
            directory.path().join("privkey.pem"),
        );
        std::fs::write(&certificate, &identity.certificate_pem).unwrap();
        std::fs::write(&key, &identity.private_key_pem).unwrap();
        Self {
            _directory: directory,
            certificate,
            key,
        }
    }

    fn config(&self) -> ProfileSigningConfig {
        ProfileSigningConfig {
            certificate_file: Some(self.certificate.clone()),
            private_key_file: Some(self.key.clone()),
        }
    }

    fn signer(&self) -> Arc<ReloadingProfileSigner> {
        Arc::new(ReloadingProfileSigner::from_config(&self.config()).unwrap().unwrap())
    }
}

#[tokio::test]
async fn a_renewal_is_picked_up_through_the_clock_and_the_gauge_follows_the_leaf_in_use() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let _installed = metrics::set_default_local_recorder(&recorder);
    let old = identity_ending(KeyKind::Rsa, "old", at(2027, 3, 1)).unwrap();
    let new = identity_ending(KeyKind::EcdsaP256, "new", at(2027, 6, 1)).unwrap();
    let other = identity_ending(KeyKind::EcdsaP256, "other", at(2028, 1, 1)).unwrap();
    let files = Files::new(&old);
    let signer = files.signer();
    let clock = Arc::new(ManualClock::new(start()));
    let worker = ProfileSigningWorker::new(Arc::clone(&signer), Arc::<ManualClock>::clone(&clock));
    assert_eq!(worker.name(), "profile_signing");
    assert_eq!(worker.interval(), Duration::from_mins(1));
    assert_eq!(gauge(&handle), None, "nothing is published before the first pass");

    assert_eq!(
        worker.tick().await,
        WorkReport::idle(),
        "the files are as they were read"
    );
    assert_eq!(
        gauge(&handle),
        Some(f64::from(u32::try_from(at(2027, 3, 1).timestamp()).unwrap()))
    );

    // The client renames the files; the pass that follows by the clock of the worker takes them.
    replace(&files.certificate, &new.certificate_pem);
    replace(&files.key, &new.private_key_pem);
    assert_eq!(
        worker.tick().await,
        WorkReport::idle(),
        "the clock has not moved: the last check is not a minute old"
    );
    assert_eq!(signer.generation(), 1);
    clock.advance(minute());
    assert_eq!(
        worker.tick().await,
        WorkReport {
            processed: 1,
            failed: 0,
            more: false
        }
    );
    assert_eq!(signer.generation(), 2);
    assert_eq!(
        gauge(&handle),
        Some(f64::from(u32::try_from(at(2027, 6, 1).timestamp()).unwrap()))
    );
    assert!(signer.sign(PROFILE, clock.now()).is_ok());

    // The two files of the next renewal arrive one after the other: for a moment the certificate meets the old key.
    replace(&files.certificate, &other.certificate_pem);
    clock.advance(minute());
    assert_eq!(
        worker.tick().await,
        WorkReport {
            processed: 0,
            failed: 1,
            more: false
        },
        "a pair that does not fit is a failed pass"
    );
    assert_eq!(signer.generation(), 2, "and the signer in use stays");
    assert_eq!(
        gauge(&handle),
        Some(f64::from(u32::try_from(at(2027, 6, 1).timestamp()).unwrap())),
        "so does the gauge: it names the certificate in use"
    );
    assert!(signer.sign(PROFILE, clock.now()).is_ok());

    replace(&files.key, &other.private_key_pem);
    clock.advance(minute());
    assert_eq!(worker.tick().await.processed, 1);
    assert_eq!(
        gauge(&handle),
        Some(f64::from(u32::try_from(at(2028, 1, 1).timestamp()).unwrap()))
    );
}

#[tokio::test]
async fn the_worker_and_the_gauge_exist_only_while_signing_is_on() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let _installed = metrics::set_default_local_recorder(&recorder);
    let dev = r#"
        [server]
        mode = "dev"
        public_base_url = "http://localhost:8080"
        [plugins]
        store = "memory"
        mail_transport = "memory"
        templates = "minijinja"
        rate_limiter = "memory"
        http_client = "recording"
    "#;
    let registry = Arc::new(registry().unwrap());
    let names = |workers: &[Arc<dyn Worker>]| workers.iter().map(|worker| worker.name()).collect::<Vec<_>>();

    let off = assemble(Arc::new(Config::from_toml(dev).unwrap()), &registry)
        .await
        .unwrap();
    assert!(
        !names(&off.workers).contains(&"profile_signing"),
        "{:?}",
        names(&off.workers)
    );
    assert!(off.deps.profile_signer.is_none());
    assert!(!off.report.profile_signer.is_on());
    assert!(
        off.report
            .profile_signer
            .worker(Arc::new(ManualClock::new(start())))
            .is_none()
    );
    assert_eq!(gauge(&handle), None, "no series while signing is off");

    let identity = identity_ending(KeyKind::EcdsaP256, "on", at(2027, 6, 1)).unwrap();
    let files = Files::new(&identity);
    let on = assemble(
        Arc::new(
            Config::from_toml(&format!(
                "{dev}\n[security.profile_signing]\ncertificate_file = {:?}\nprivate_key_file = {:?}",
                files.certificate.display().to_string(),
                files.key.display().to_string()
            ))
            .unwrap(),
        ),
        &registry,
    )
    .await
    .unwrap();
    assert!(
        names(&on.workers).contains(&"profile_signing"),
        "{:?}",
        names(&on.workers)
    );
    assert!(on.deps.profile_signer.is_some());
    // The worker of the assembly publishes the gauge with its first pass, on the clock of the assembly.
    let worker = on
        .workers
        .iter()
        .find(|worker| worker.name() == "profile_signing")
        .unwrap();
    worker.tick().await;
    assert_eq!(
        gauge(&handle),
        Some(f64::from(u32::try_from(at(2027, 6, 1).timestamp()).unwrap()))
    );
}

#[test]
fn the_gauge_value_is_the_unix_second_and_saturates_far_out() {
    assert!((unix_seconds(at(2027, 3, 1)) - 1_803_859_200.0).abs() < f64::EPSILON);
    assert!((unix_seconds(at(1969, 12, 31)) - 0.0).abs() < f64::EPSILON);
    assert!((unix_seconds(at(9999, 1, 1)) - f64::from(u32::MAX)).abs() < f64::EPSILON);
}

/// A named pipe in place of a file, which the reader of a mount that went away would be: it is open for reading and writing
/// from the moment it exists, so a reader that opens it finds a writer and blocks in `read` for data that never comes. When the
/// guard is dropped, however the test ends (a failed assertion drops it on the way out), the writer is gone, the reader sees the
/// end of the file and the blocked thread returns: the test can fail instead of hanging the runtime that waits for the thread.
///
/// (Opening a pipe for reading and writing at once does not block on Linux; the tests of the hang run on Unix.)
#[cfg(unix)]
struct Hung {
    _pipe: std::fs::File,
}

#[cfg(unix)]
impl Hung {
    fn at(path: &Path) -> Self {
        std::fs::remove_file(path).unwrap();
        let made = std::process::Command::new("mkfifo").arg(path).status().unwrap();
        assert!(made.success(), "mkfifo");
        let pipe = std::fs::OpenOptions::new().read(true).write(true).open(path).unwrap();
        Self { _pipe: pipe }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn a_check_that_hangs_on_the_file_system_ends_the_pass_at_its_budget_and_is_reported_until_it_ends() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let _installed = metrics::set_default_local_recorder(&recorder);
    let old = identity_ending(KeyKind::Rsa, "old", at(2027, 3, 1)).unwrap();
    let files = Files::new(&old);
    let signer = files.signer();
    let clock = Arc::new(ManualClock::new(start()));
    let worker = ProfileSigningWorker::new(Arc::clone(&signer), Arc::<ManualClock>::clone(&clock))
        .with_budget(Duration::from_millis(50));
    let failed = WorkReport {
        processed: 0,
        failed: 1,
        more: false,
    };

    // The key file is replaced by a pipe that nobody writes to; declared after `files`, so it is let go of before them.
    let _hung = Hung::at(&files.key);

    // The check never ends, so the pass ends at its budget (a real one, short: a paused clock does not move on while a blocking
    // thread runs).
    assert_eq!(worker.tick().await, failed, "the pass ended at its budget");
    assert_eq!(signer.generation(), 1);
    assert!(
        signer.sign(PROFILE, clock.now()).is_ok(),
        "signing never waited for the file"
    );
    assert_eq!(
        gauge(&handle),
        Some(f64::from(u32::try_from(at(2027, 3, 1).timestamp()).unwrap())),
        "the gauge is published whatever the check did"
    );

    // A minute later the next pass finds the check still running. It starts no second one (a second blocked thread every
    // minute would end by using up the blocking pool) and says so as a failed pass: the outcome metric shows the hang for as long
    // as the mount stays hung. A worker with a long budget proves that it did not wait for a check of its own: it answers at
    // once, where a second blocked thread would have kept it for the whole budget.
    clock.advance(minute());
    let patient = ProfileSigningWorker::new(Arc::clone(&signer), Arc::<ManualClock>::clone(&clock));
    let started = std::time::Instant::now();
    assert_eq!(patient.tick().await, failed, "the check that hangs is reported again");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the pass came back at once instead of waiting for a check of its own: {:?}",
        started.elapsed()
    );
    assert_eq!(
        signer.refresh(clock.now()),
        Refresh::Busy,
        "and the signer says that a check is running, on this thread, without blocking it"
    );
    assert_eq!(signer.generation(), 1);
}
