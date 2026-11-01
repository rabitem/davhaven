//! Helpers of the server's integration tests: a small HTTP/1.1 client for talking to the listeners over real
//! sockets, the free-port picker and the PostgreSQL gate.
//!
//! The client writes one request with `Connection: close` and reads the whole answer, so a test sees exactly the
//! bytes the server sent (status line, headers, body) and nothing a client library would normalise.

#![allow(dead_code, reason = "every test binary uses a different part of the support code")]
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

use std::fmt::Write as _;
use std::io::Write as _;
use std::net::SocketAddr;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

/// What the server answered.
#[derive(Debug, Clone)]
pub(crate) struct Reply {
    /// The status code.
    pub(crate) status: u16,
    /// The headers, names in lower case, in the order they arrived.
    pub(crate) headers: Vec<(String, String)>,
    /// The body, with chunked transfer encoding removed.
    pub(crate) body: Vec<u8>,
}

impl Reply {
    /// The first header with this (lower-case) name.
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// The body as text.
    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// The body as JSON.
    pub(crate) fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|error| panic!("not JSON ({error}): {}", self.text()))
    }
}

/// Decodes a chunked body.
fn dechunk(mut raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let Some(line_end) = raw.windows(2).position(|pair| pair == b"\r\n") else {
            return out;
        };
        let size_text = String::from_utf8_lossy(&raw[..line_end]).into_owned();
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("0").trim(), 16).unwrap_or(0);
        raw = &raw[line_end + 2..];
        if size == 0 || raw.len() < size {
            return out;
        }
        out.extend_from_slice(&raw[..size]);
        raw = raw.get(size + 2..).unwrap_or_default();
    }
}

/// Splits a raw answer into status, headers and body.
pub(crate) fn parse(raw: &[u8]) -> Reply {
    let head_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("not an HTTP answer: {:?}", String::from_utf8_lossy(raw)));
    let head = String::from_utf8_lossy(&raw[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("no status line in {head:?}"));
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let body = &raw[head_end + 4..];
    let chunked = headers
        .iter()
        .any(|(name, value)| name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked"));
    Reply {
        status,
        headers,
        body: if chunked { dechunk(body) } else { body.to_vec() },
    }
}

/// A client for one listener.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Client {
    address: SocketAddr,
}

impl Client {
    /// A client for the listener at `address`.
    pub(crate) const fn new(address: SocketAddr) -> Self {
        Self { address }
    }

    /// Sends one request and reads the answer.
    pub(crate) async fn send(&self, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Reply {
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
            self.address
        );
        for (name, value) in headers {
            write!(request, "{name}: {value}\r\n").unwrap();
        }
        if !body.is_empty() || matches!(method, "POST" | "PUT" | "PATCH") {
            write!(request, "Content-Length: {}\r\n", body.len()).unwrap();
        }
        request.push_str("\r\n");
        let mut stream = TcpStream::connect(self.address).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
        let mut raw = Vec::new();
        tokio::time::timeout(Duration::from_secs(30), stream.read_to_end(&mut raw))
            .await
            .expect("the server did not finish its answer")
            .unwrap();
        parse(&raw)
    }

    /// `GET path`.
    pub(crate) async fn get(&self, path: &str) -> Reply {
        self.send("GET", path, &[], &[]).await
    }

    /// A request with a bearer token and a JSON body (none for `Value::Null`).
    pub(crate) async fn api(&self, method: &str, path: &str, token: &str, body: &Value) -> Reply {
        let authorization = format!("Bearer {token}");
        let mut headers = vec![("Authorization", authorization.as_str())];
        let payload = if body.is_null() {
            Vec::new()
        } else {
            headers.push(("Content-Type", "application/json"));
            serde_json::to_vec(body).unwrap()
        };
        self.send(method, path, &headers, &payload).await
    }
}

/// `Authorization` header value of HTTP Basic credentials.
pub(crate) fn basic(login: &str, password: &str) -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{login}:{password}"))
    )
}

/// A TCP port that is free right now (the listener that found it is closed again, so there is a small window in
/// which another process could take it; the tests that need a known port accept that).
pub(crate) fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// Whether an environment value says "yes": anything but unset, empty, `0` and `false`.
fn truthy(value: Option<&str>) -> bool {
    value.is_some_and(|value| !matches!(value.trim().to_ascii_lowercase().as_str(), "" | "0" | "false"))
}

/// The PostgreSQL the tests run against, or `None` when the tests were told to skip.
///
/// # Panics
///
/// Without `DATABASE_URL`, unless `DAVHAVEN_ALLOW_NO_DB` is set and the run is not CI (`ENGINEERING_RULES` R9): a test
/// that needs PostgreSQL fails rather than report green having tested nothing.
pub(crate) fn database_url() -> Option<String> {
    if let Ok(url) = std::env::var("DATABASE_URL")
        && !url.is_empty()
    {
        return Some(url);
    }
    let in_ci = truthy(std::env::var("CI").ok().as_deref());
    let allowed = truthy(std::env::var("DAVHAVEN_ALLOW_NO_DB").ok().as_deref());
    assert!(
        allowed && !in_ci,
        "DATABASE_URL is not set: the PostgreSQL tests cannot run. Set it, or (outside CI) set DAVHAVEN_ALLOW_NO_DB=1 \
         to skip them explicitly"
    );
    drop(writeln!(
        std::io::stderr(),
        "SKIPPED (DAVHAVEN_ALLOW_NO_DB): DATABASE_URL is not set, nothing was tested against PostgreSQL"
    ));
    None
}

/// A database of its own on the cluster of `DATABASE_URL`, provisioned like production (`docs/operations/database.md`): an
/// **owner** role that owns the schema and migrates, and a **runtime** role that is `NOSUPERUSER NOBYPASSRLS`, owns nothing
/// and reaches the tables through the owner's default privileges. A server that connects as the runtime role is bound by
/// row-level security, which a superuser or an owner is not.
///
/// The roles and the database have names of their own (a random suffix), so parallel tests and the other suites do not meet,
/// and [`drop_all`](Self::drop_all) removes them again. They are created on whatever cluster `DATABASE_URL` names: point it
/// only at a throw-away server (local, or `DAVHAVEN_TEST_DB_THROWAWAY=1`, or `CI`).
pub(crate) struct Roles {
    admin_url: String,
    database: String,
    owner: String,
    runtime: String,
    /// The connection URL of the owner role: what `database.migration_url` takes.
    pub(crate) owner_url: String,
    /// The connection URL of the runtime role: what `database.url` takes.
    pub(crate) runtime_url: String,
    /// The URL of the superuser of the cluster on this database: a role that row-level security does not bind.
    pub(crate) superuser_url: String,
}

/// A statement that the support code assembles from names it generated itself, never from outside input.
fn raw(statement: String) -> sqlx::RawSql {
    sqlx::raw_sql(sqlx::AssertSqlSafe(statement))
}

/// Refuses to create roles on a server that is neither local nor declared throw-away.
fn refuse_shared_servers(admin_url: &str) {
    let url = url::Url::parse(admin_url).unwrap();
    let host = url.host_str().unwrap_or_default();
    let local = matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]" | "");
    let throwaway = truthy(std::env::var("DAVHAVEN_TEST_DB_THROWAWAY").ok().as_deref())
        || truthy(std::env::var("CI").ok().as_deref())
        || url.path().trim_start_matches('/').starts_with("davhaven_");
    assert!(
        local || throwaway,
        "DATABASE_URL names {host}, which is neither local nor declared throw-away: these tests create roles and databases. \
         Set DAVHAVEN_TEST_DB_THROWAWAY=1 if the server may be used for that"
    );
}

impl Roles {
    /// Creates the roles and the database on the cluster that `admin_url` (a superuser) names.
    pub(crate) async fn create(admin_url: &str) -> Self {
        use davhaven_ports::IdGenerator as _;
        use sqlx::Connection as _;
        use sqlx::PgConnection;

        refuse_shared_servers(admin_url);
        let suffix = davhaven_ports::UuidV7.new_id().simple().to_string();
        let tail = suffix.get(20..).unwrap_or_default();
        let owner = format!("s8_owner_{tail}");
        let runtime = format!("s8_runtime_{tail}");
        let database = format!("s8_db_{tail}");
        let mut admin = PgConnection::connect(admin_url).await.unwrap();
        for statement in [
            format!("CREATE ROLE {owner} LOGIN PASSWORD '{owner}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS"),
            format!("CREATE ROLE {runtime} LOGIN PASSWORD '{runtime}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS"),
            format!("CREATE DATABASE {database} OWNER {owner}"),
        ] {
            raw(statement).execute(&mut admin).await.unwrap();
        }
        let url_of = |role: &str| {
            let mut url = url::Url::parse(admin_url).unwrap();
            url.set_username(role).unwrap();
            url.set_password(Some(role)).unwrap();
            url.set_path(&format!("/{database}"));
            url.to_string()
        };
        // The privileges of the recipe in docs/operations/database.md, run in the new database.
        let mut inside = PgConnection::connect(&url_of_admin(admin_url, &database))
            .await
            .unwrap();
        for statement in [
            "REVOKE ALL ON SCHEMA public FROM PUBLIC".to_owned(),
            format!("ALTER SCHEMA public OWNER TO {owner}"),
            format!("GRANT USAGE ON SCHEMA public TO {runtime}"),
            format!(
                "ALTER DEFAULT PRIVILEGES FOR ROLE {owner} IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {runtime}"
            ),
            format!(
                "ALTER DEFAULT PRIVILEGES FOR ROLE {owner} IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {runtime}"
            ),
        ] {
            raw(statement).execute(&mut inside).await.unwrap();
        }
        Self {
            admin_url: admin_url.to_owned(),
            owner_url: url_of(&owner),
            runtime_url: url_of(&runtime),
            superuser_url: url_of_admin(admin_url, &database),
            database,
            owner,
            runtime,
        }
    }

    /// Drops the database and the roles.
    pub(crate) async fn drop_all(self) {
        use sqlx::Connection as _;
        use sqlx::PgConnection;

        let mut admin = PgConnection::connect(&self.admin_url).await.unwrap();
        for statement in [
            format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", self.database),
            format!("DROP ROLE IF EXISTS {}", self.runtime),
            format!("DROP ROLE IF EXISTS {}", self.owner),
        ] {
            raw(statement).execute(&mut admin).await.unwrap();
        }
    }
}

/// The URL of the superuser of `admin_url` on `database`.
fn url_of_admin(admin_url: &str, database: &str) -> String {
    let mut url = url::Url::parse(admin_url).unwrap();
    url.set_path(&format!("/{database}"));
    url.to_string()
}
