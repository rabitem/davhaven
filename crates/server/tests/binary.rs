//! The `davhaven` binary as a process: the command line, the environment, the exit codes and the signals.
//!
//! These tests run the real executable (`CARGO_BIN_EXE_davhaven`) with `DAVHAVEN_*` variables and files, the way a
//! container does: `--version`, `config check` with `*_file` secrets and unknown variables, `serve` until `SIGTERM`
//! with `healthcheck` before and after, and (with `DATABASE_URL`) the administrative commands against a database of
//! their own: `migrate`, `admin bootstrap`, `admin bump-sync-epoch`, `admin purge-audit` and `admin rotate-keys`.
//!
//! The tests never poll and never sleep: a server process says what it is doing on standard error, and the tests read
//! that stream (the line `davhaven started` is the signal that the listeners are bound, the end of the stream is the
//! signal that the process has exited). The only clock is the upper bound of each wait, which turns a hang into a failure.

#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

mod support;

use std::io::{BufRead as _, BufReader};
use std::net::SocketAddr;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use davhaven_ports::{IdGenerator, UuidV7};
use serde_json::Value;
use sqlx::{Connection as _, PgConnection};
use support::{Client, database_url, free_port};
use tempfile::TempDir;
use tokio::io::AsyncReadExt as _;
use tokio::net::TcpListener;

/// The result of a command that ran to the end.
struct Finished {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

/// A `davhaven` command with an empty environment plus `env`.
fn davhaven(env: &[(&str, String)]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_davhaven"));
    command.env_clear();
    for (name, value) in env {
        command.env(name, value);
    }
    command
}

/// Runs `davhaven args` to the end.
fn run(env: &[(&str, String)], args: &[&str]) -> Finished {
    let output = davhaven(env).args(args).output().unwrap();
    Finished {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// The environment of a development server on three free loopback ports with the memory adapters.
fn dev_env() -> (Vec<(&'static str, String)>, SocketAddr, SocketAddr, SocketAddr) {
    let public: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let internal: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let ops: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let env = vec![
        ("DAVHAVEN_SERVER__MODE", "dev".to_owned()),
        ("DAVHAVEN_SERVER__PUBLIC_BASE_URL", "http://localhost:8080".to_owned()),
        ("DAVHAVEN_SERVER__SHUTDOWN_GRACE", "5s".to_owned()),
        ("DAVHAVEN_SERVER__LISTENERS__PUBLIC__BIND", public.to_string()),
        ("DAVHAVEN_SERVER__LISTENERS__INTERNAL__BIND", internal.to_string()),
        ("DAVHAVEN_SERVER__LISTENERS__OPS__BIND", ops.to_string()),
        ("DAVHAVEN_PLUGINS__STORE", "memory".to_owned()),
        ("DAVHAVEN_PLUGINS__MAIL_TRANSPORT", "memory".to_owned()),
        ("DAVHAVEN_PLUGINS__HTTP_CLIENT", "recording".to_owned()),
    ];
    (env, public, internal, ops)
}

/// The longest any wait for a server process may take; it only turns a hang into a failure.
const PATIENCE: Duration = Duration::from_secs(60);

/// A server process whose standard error is read line by line.
struct Server {
    child: Child,
    lines: Receiver<String>,
    log: String,
}

impl Server {
    fn start(env: &[(&str, String)]) -> Self {
        let mut child = davhaven(env)
            .arg("serve")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let (sender, lines) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            lines,
            log: String::new(),
        }
    }

    /// Reads the log until a line contains `needle`: `true` then, `false` when the process closed its standard error (it
    /// has exited) or `limit` passed first. The wait blocks on the stream; nothing polls.
    fn wait_for(&mut self, needle: &str, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    self.log.push_str(&line);
                    self.log.push('\n');
                    if line.contains(needle) {
                        return true;
                    }
                }
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => return false,
            }
        }
    }

    /// Waits until the server says that it started, then asks `davhaven healthcheck` (which reads the same environment).
    fn wait_ready(&mut self, env: &[(&str, String)]) {
        assert!(
            self.wait_for("davhaven started", PATIENCE),
            "the server did not start: {}",
            self.log
        );
        let ready = run(env, &["healthcheck"]);
        assert!(
            ready.status.success(),
            "the server started but is not ready: {}{}\n{}",
            ready.stdout,
            ready.stderr,
            self.log
        );
    }

    /// Reads the log to the end of the stream, which is the end of the process (it closes its standard error when it exits):
    /// `true`, or `false` when `limit` passed first.
    fn read_to_end(&mut self, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    self.log.push_str(&line);
                    self.log.push('\n');
                }
                Err(RecvTimeoutError::Disconnected) => return true,
                Err(RecvTimeoutError::Timeout) => return false,
            }
        }
    }

    /// Waits for the process to exit and returns its status and everything it logged.
    fn exit(mut self) -> (ExitStatus, String) {
        if !self.read_to_end(PATIENCE) {
            self.child.kill().unwrap();
            panic!("the server did not stop: {}", self.log);
        }
        (self.child.wait().unwrap(), self.log)
    }

    /// Sends SIGTERM and waits for the exit.
    fn terminate(self) -> (ExitStatus, String) {
        let sent = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .unwrap();
        assert!(sent.success(), "cannot signal the server");
        self.exit()
    }
}

#[test]
fn the_version_and_help_are_printed_and_a_wrong_command_line_exits_with_2() {
    let version = run(&[], &["--version"]);
    assert!(version.status.success());
    assert!(version.stdout.starts_with("davhaven "), "{}", version.stdout);
    let help = run(&[], &["--help"]);
    assert!(help.status.success());
    for command in ["serve", "migrate", "healthcheck", "config", "admin"] {
        assert!(help.stdout.contains(command), "{command}: {}", help.stdout);
    }
    let wrong = run(&[], &["frobnicate"]);
    assert_eq!(wrong.status.code(), Some(2), "{}", wrong.stderr);
}

#[test]
fn config_check_reads_the_file_the_environment_and_the_secret_files() {
    let directory = TempDir::new().unwrap();
    let key = directory.path().join("key");
    std::fs::write(&key, "0123456789abcdef0123456789abcdef0123456789\n").unwrap();
    let url = directory.path().join("database-url");
    std::fs::write(&url, "postgres://app:secret@localhost/davhaven\n").unwrap();
    let migration = directory.path().join("migration-url");
    std::fs::write(&migration, "postgres://owner:secret@localhost/davhaven\n").unwrap();
    let password = directory.path().join("smtp-password");
    std::fs::write(&password, "hunter2\n").unwrap();
    let file = directory.path().join("davhaven.toml");
    std::fs::write(
        &file,
        format!(
            "[server]\npublic_base_url = \"https://calendar.example.org\"\n\
             [[security.keys]]\nid = \"2027-01\"\nsecret_file = {key:?}\n\
             [plugin.smtp]\nhost = \"smtp.example.org\"\nport = 465\ntls = \"tls\"\nusername = \"mailer\"\n\
             password_file = {password:?}\n"
        ),
    )
    .unwrap();
    let env = [
        ("DAVHAVEN_DATABASE__URL_FILE", url.display().to_string()),
        ("DAVHAVEN_DATABASE__MIGRATION_URL_FILE", migration.display().to_string()),
        ("DAVHAVEN_OUTBOX__BATCH_SIZE", "7".to_owned()),
    ];
    let file_arg = file.display().to_string();
    let checked = run(&env, &["--config", &file_arg, "config", "check"]);
    assert!(checked.status.success(), "{}{}", checked.stdout, checked.stderr);
    assert!(
        checked
            .stdout
            .contains("configuration is valid (server.mode = production)"),
        "{}",
        checked.stdout
    );
    assert!(
        checked.stdout.contains("keys: 2027-01 (active: 2027-01)"),
        "{}",
        checked.stdout
    );
    assert!(checked.stdout.contains("\"batch_size\": 7"), "{}", checked.stdout);
    for secret in ["hunter2", "postgres://app:secret", "0123456789abcdef"] {
        assert!(
            !checked.stdout.contains(secret) && !checked.stderr.contains(secret),
            "{secret} leaked"
        );
    }

    // The path may come from the environment as well.
    let from_env = run(
        &[env.as_slice(), &[("DAVHAVEN_CONFIG", file_arg.clone())]].concat(),
        &["config", "check"],
    );
    assert!(from_env.status.success(), "{}", from_env.stderr);

    // A secret file that does not exist is found by the check, not at the first request.
    std::fs::remove_file(&migration).unwrap();
    let missing = run(&env, &["--config", &file_arg, "config", "check"]);
    assert_eq!(missing.status.code(), Some(1));
    assert!(
        missing.stderr.contains("migration_url_file") || missing.stderr.contains("migration"),
        "{}",
        missing.stderr
    );

    // An unknown variable fails the start, naming it.
    let typo = run(
        &[env.as_slice(), &[("DAVHAVEN_OUTBOX__BATCHSIZE", "7".to_owned())]].concat(),
        &["--config", &file_arg, "config", "check"],
    );
    assert_eq!(typo.status.code(), Some(1));
    assert!(
        typo.stderr.to_ascii_lowercase().contains("batchsize"),
        "{}",
        typo.stderr
    );
}

#[test]
fn production_refuses_the_memory_store_and_a_missing_public_url() {
    let directory = TempDir::new().unwrap();
    let key = directory.path().join("key");
    std::fs::write(
        &key,
        "0123456789abcdef0123456789abcdef0123456789
",
    )
    .unwrap();
    let keys = format!("[{{id=\"2027-01\",secret_file={:?}}}]", key.display().to_string());
    let memory = run(
        &[
            (
                "DAVHAVEN_SERVER__PUBLIC_BASE_URL",
                "https://calendar.example.org".to_owned(),
            ),
            ("DAVHAVEN_SECURITY__KEYS", keys),
            ("DAVHAVEN_PLUGINS__STORE", "memory".to_owned()),
        ],
        &["config", "check"],
    );
    assert_eq!(memory.status.code(), Some(1));
    assert!(memory.stderr.contains("plugins.store"), "{}", memory.stderr);
    let keyless = run(
        &[(
            "DAVHAVEN_SERVER__PUBLIC_BASE_URL",
            "https://calendar.example.org".to_owned(),
        )],
        &["config", "check"],
    );
    assert_eq!(keyless.status.code(), Some(1));
    assert!(keyless.stderr.contains("at least one key"), "{}", keyless.stderr);
    let nothing = run(&[], &["config", "check"]);
    assert_eq!(nothing.status.code(), Some(1));
    assert!(nothing.stderr.contains("public_base_url"), "{}", nothing.stderr);
}

#[tokio::test]
async fn serve_answers_until_sigterm_and_the_healthcheck_follows_it() {
    let (env, public, internal, ops) = dev_env();
    let mut server = Server::start(&env);
    server.wait_ready(&env);

    let ready = Client::new(ops).get("/readyz").await;
    assert_eq!(ready.status, 200, "{}", ready.text());
    let metrics = Client::new(ops).get("/metrics").await;
    assert_eq!(metrics.status, 200);
    assert!(
        metrics.text().contains("davhaven_worker_passes_total"),
        "{}",
        metrics.text()
    );
    assert_eq!(Client::new(public).get("/.well-known/caldav").await.status, 301);
    assert_eq!(
        Client::new(internal).get("/api/v1/tenants/x/principals").await.status,
        401
    );
    let healthy = run(&env, &["healthcheck"]);
    assert!(healthy.stdout.starts_with("ready"), "{}", healthy.stdout);

    let (status, log) = server.terminate();
    assert_eq!(status.code(), Some(0), "a clean shutdown exits 0: {log}");
    assert!(
        log.contains("davhaven started") && log.contains("termination requested"),
        "{log}"
    );
    let lines: Vec<Value> = log.lines().filter_map(|line| serde_json::from_str(line).ok()).collect();
    assert!(lines.len() >= 3, "the log is JSON, one object per line: {log}");
    assert!(lines.iter().any(|line| line["message"] == "stopped"), "{log}");
    let down = run(&env, &["healthcheck"]);
    assert_eq!(down.status.code(), Some(1), "nothing answers after the shutdown");
}

#[test]
fn a_port_that_is_taken_fails_the_start_with_the_name_of_the_listener() {
    let (env, public, _, _) = dev_env();
    let taken = std::net::TcpListener::bind(public).unwrap();
    let mut server = Server::start(&env);
    assert!(
        !server.wait_for("davhaven started", PATIENCE),
        "the server started on a port that is taken: {}",
        server.log
    );
    let (status, log) = server.exit();
    assert_eq!(status.code(), Some(1), "{log}");
    assert!(log.contains("public") && log.contains(&public.to_string()), "{log}");
    drop(taken);
}

/// A database of its own on the server of `DATABASE_URL`, dropped again at the end.
struct Scratch {
    admin_url: String,
    name: String,
    url: String,
}

impl Scratch {
    async fn create(admin_url: &str) -> Self {
        let name = format!("davhaven_cli_{}", UuidV7.new_id().simple());
        let mut connection = PgConnection::connect(admin_url).await.unwrap();
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&mut connection)
            .await
            .unwrap();
        let mut url = url::Url::parse(admin_url).unwrap();
        url.set_path(&format!("/{name}"));
        Self {
            admin_url: admin_url.to_owned(),
            name,
            url: url.to_string(),
        }
    }

    async fn drop_database(self) {
        let mut connection = PgConnection::connect(&self.admin_url).await.unwrap();
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE IF EXISTS {} WITH (FORCE)",
            self.name
        )))
        .execute(&mut connection)
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn the_administrative_commands_run_against_postgres() {
    let Some(admin_url) = database_url() else {
        return;
    };
    let scratch = Scratch::create(&admin_url).await;
    let directory = TempDir::new().unwrap();
    let key = directory.path().join("key");
    std::fs::write(&key, "0123456789abcdef0123456789abcdef0123456789\n").unwrap();
    let (mut env, _public, internal, ops) = dev_env();
    env.retain(|(name, _)| !name.starts_with("DAVHAVEN_PLUGINS__STORE"));
    env.push(("DAVHAVEN_PLUGINS__STORE", "postgres".to_owned()));
    env.push(("DAVHAVEN_DATABASE__URL", scratch.url.clone()));
    env.push(("DAVHAVEN_DATABASE__MIGRATE_ON_START", "false".to_owned()));
    env.push((
        "DAVHAVEN_SECURITY__KEYS",
        format!("[{{id=\"2027-01\",secret_file={:?}}}]", key.display().to_string()),
    ));

    // `serve` without a migrated schema does not become ready, `migrate` fixes that and can be repeated.
    let migrated = run(&env, &["migrate"]);
    assert!(migrated.status.success(), "{}{}", migrated.stdout, migrated.stderr);
    assert!(
        migrated.stdout.contains("migrated the schema from version none to"),
        "{}",
        migrated.stdout
    );
    let again = run(&env, &["migrate"]);
    assert!(again.stdout.contains("up to date at version"), "{}", again.stdout);

    // `admin bootstrap` is idempotent and keeps the secret out of everything but its file.
    let token_file = directory.path().join("token");
    let token_arg = token_file.display().to_string();
    let bootstrap = |extra: &[&str]| {
        let mut args = vec![
            "admin",
            "bootstrap",
            "--tenant",
            "cli",
            "--display-name",
            "CLI",
            "--login-domain",
            "cli.example",
        ];
        args.extend_from_slice(extra);
        run(&env, &args)
    };
    let first = bootstrap(&["--token-file", &token_arg]);
    assert!(first.status.success(), "{}{}", first.stdout, first.stderr);
    assert!(
        first.stderr.contains("tenant cli created") && first.stderr.contains("created; its secret"),
        "{}",
        first.stderr
    );
    let token = std::fs::read_to_string(&token_file).unwrap().trim().to_owned();
    assert!(token.starts_with("dvh_pat_"), "{token}");
    assert!(!first.stdout.contains(&token) && !first.stderr.contains(&token));
    let second = bootstrap(&["--token-file", &token_arg]);
    assert!(second.status.success(), "{}", second.stderr);
    assert!(
        second.stderr.contains("tenant cli exists") && second.stderr.contains("exists already"),
        "{}",
        second.stderr
    );

    // The server serves the tenant that the command made, and the token works.
    let mut server = Server::start(&env);
    server.wait_ready(&env);
    let internal = Client::new(internal);
    let listed = internal
        .api("GET", "/api/v1/tenants/cli/principals", &token, &Value::Null)
        .await;
    assert_eq!(listed.status, 200, "{}", listed.text());
    assert_eq!(Client::new(ops).get("/readyz").await.status, 200);
    let (status, log) = server.terminate();
    assert_eq!(status.code(), Some(0), "{log}");

    // Maintenance commands.
    let bumped = run(&env, &["admin", "bump-sync-epoch", "--all"]);
    assert!(bumped.status.success(), "{}", bumped.stderr);
    assert!(
        bumped.stdout.contains("collections have a new sync epoch"),
        "{}",
        bumped.stdout
    );
    let one = run(&env, &["admin", "bump-sync-epoch", "--tenant", "cli"]);
    assert!(one.status.success(), "{}", one.stderr);
    let nobody = run(&env, &["admin", "bump-sync-epoch", "--tenant", "nobody"]);
    assert_eq!(nobody.status.code(), Some(1));
    assert!(nobody.stderr.contains("no tenant `nobody`"), "{}", nobody.stderr);
    let purged = run(&env, &["admin", "purge-audit"]);
    assert!(purged.status.success(), "{}", purged.stderr);
    assert!(purged.stdout.contains("audit events removed"), "{}", purged.stdout);
    let rotated = run(&env, &["admin", "rotate-keys"]);
    assert!(rotated.status.success(), "{}", rotated.stderr);
    assert!(rotated.stdout.contains("active key `2027-01`"), "{}", rotated.stdout);

    scratch.drop_database().await;
}

#[tokio::test]
async fn traces_are_exported_over_grpc_to_the_configured_collector() {
    // A stand-in for the collector's gRPC port: it only has to see what the exporter says first. OTLP/gRPC is HTTP/2
    // with prior knowledge, so the first thing on the wire is the HTTP/2 connection preface; an OTLP/HTTP exporter would
    // send an HTTP/1.1 request line instead. (That the spans nest and continue the caller's trace is tested where the
    // request spans are made: `telemetry::tests`.)
    let collector = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", collector.local_addr().unwrap());
    let (mut env, _public, internal, _ops) = dev_env();
    env.push(("DAVHAVEN_OBSERVABILITY__OTLP__ENDPOINT", endpoint));
    env.push(("DAVHAVEN_OBSERVABILITY__OTLP__SAMPLE_RATIO", "1.0".to_owned()));
    env.push(("OTEL_BSP_SCHEDULE_DELAY", "100".to_owned()));
    let mut server = Server::start(&env);
    server.wait_ready(&env);

    // A well-formed token that nobody issued is looked up in the store: a call to a port, which is a span.
    let token = format!("dvh_pat_{}_{}", "a".repeat(12), "b".repeat(43));
    let refused = Client::new(internal)
        .api("GET", "/api/v1/tenants/acme/principals", &token, &Value::Null)
        .await;
    assert_eq!(refused.status, 401, "{}", refused.text());

    let accepted = tokio::time::timeout(Duration::from_secs(20), collector.accept()).await;
    let Ok(Ok((mut connection, _))) = accepted else {
        let (_, log) = server.terminate();
        panic!("the exporter never connected to the collector: {log}");
    };
    let mut preface = [0_u8; 24];
    tokio::time::timeout(Duration::from_secs(5), connection.read_exact(&mut preface))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        &preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
        "the exporter speaks gRPC (HTTP/2)"
    );
    drop(connection);
    let (status, log) = server.terminate();
    assert_eq!(status.code(), Some(0), "{log}");
}
