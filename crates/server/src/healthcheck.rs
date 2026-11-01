//! `davhaven healthcheck`: the probe for the container's `HEALTHCHECK`.
//!
//! The command asks `/readyz` of the ops listener and exits 0 when the instance is ready and 1 when it is not or
//! cannot be reached. The image is distroless (no shell, no `curl`), so the probe is the binary itself, with a small
//! HTTP/1.1 client written for this one request: it connects, sends `GET`, reads the answer (at most 64 KiB) and
//! looks at the status line and the body. The ops listener speaks plain HTTP on a private address, so no TLS and no
//! redirects.
//!
//! The address comes from the configuration (the listener that serves the `ops` route group; a wildcard bind
//! address is replaced by the loopback address of the same family) or from `--address`.
//!
//! **Timeouts.** The probe waits [`DEFAULT_TIMEOUT`] (5 s, also the `--timeout` of the Dockerfile's `HEALTHCHECK`) for
//! the answer. `/readyz` gives each component [`COMPONENT_TIMEOUT`](crate::ops::COMPONENT_TIMEOUT) (2 s), which is clearly
//! shorter, so a slow database or hook is reported by name in the 503 body instead of by the probe giving up first.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

use crate::config::Config;
use crate::error::ServerError;
use crate::listeners::RouteGroup;

/// The longest answer the probe reads.
const MAX_REPLY_BYTES: u64 = 64 * 1024;

/// The longest the probe waits for the whole exchange, as the text `--timeout` shows and accepts.
pub const DEFAULT_TIMEOUT_TEXT: &str = "5s";

/// The longest the probe waits for the whole exchange (the duration [`DEFAULT_TIMEOUT_TEXT`] spells).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// What the server answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The status code.
    pub status: u16,
    /// The body as text (lossy), as it came over the wire.
    pub body: String,
}

/// Parses an HTTP/1.1 response read until the connection closed.
fn parse(raw: &[u8]) -> Result<Reply, String> {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| "the answer is not an HTTP response".to_owned())?;
    let status_line = head.split("\r\n").next().unwrap_or_default();
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err("the answer is not an HTTP/1 response".to_owned());
    }
    let status = parts
        .next()
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| "the status line has no status code".to_owned())?;
    Ok(Reply {
        status,
        body: body.to_owned(),
    })
}

/// Sends `GET path` to `address` and returns the answer.
///
/// # Errors
///
/// [`ServerError::Command`] when the server cannot be reached, does not answer within `timeout` or does not speak
/// HTTP.
pub async fn get(address: SocketAddr, path: &str, timeout: Duration) -> Result<Reply, ServerError> {
    let failed = |reason: String| ServerError::Command(format!("GET http://{address}{path}: {reason}"));
    let exchange = async {
        let mut stream = TcpStream::connect(address).await.map_err(|error| error.to_string())?;
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {address}\r\nUser-Agent: davhaven-healthcheck\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|error| error.to_string())?;
        let mut raw = Vec::new();
        stream
            .take(MAX_REPLY_BYTES)
            .read_to_end(&mut raw)
            .await
            .map_err(|error| error.to_string())?;
        parse(&raw)
    };
    match tokio::time::timeout(timeout, exchange).await {
        Ok(Ok(reply)) => Ok(reply),
        Ok(Err(reason)) => Err(failed(reason)),
        Err(_elapsed) => Err(failed(format!("no answer within {}s", timeout.as_secs()))),
    }
}

/// The address of the ops listener, reachable from this host: the listener that serves the `ops` route group, with a
/// wildcard address replaced by the loopback address.
///
/// # Errors
///
/// [`ServerError::Command`] when no listener serves `ops` or its port is 0 (an address that is not known).
pub fn ops_address(config: &Config) -> Result<SocketAddr, ServerError> {
    let listener = config
        .server
        .listeners
        .resolved()
        .into_iter()
        .find(|listener| listener.routes.contains(&RouteGroup::Ops))
        .ok_or_else(|| {
            ServerError::Command("no listener serves the `ops` route group (server.listeners)".to_owned())
        })?;
    if listener.bind.port() == 0 {
        return Err(ServerError::Command(
            "the ops listener binds port 0, so its address is not known; use --address".to_owned(),
        ));
    }
    let ip = match listener.bind.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        other => other,
    };
    Ok(SocketAddr::new(ip, listener.bind.port()))
}

/// Asks `/readyz` at `address`: `Ok` with a line for the operator (`ready (address)`) when the instance is ready.
///
/// # Errors
///
/// [`ServerError::Command`] when the instance cannot be reached or answers anything but 200; the message carries
/// the status and the body of the answer, which names the component that is not ready.
pub async fn check(address: SocketAddr, timeout: Duration) -> Result<String, ServerError> {
    let reply = get(address, "/readyz", timeout).await?;
    if reply.status == 200 {
        Ok(format!("ready ({address})"))
    } else {
        Err(ServerError::Command(format!(
            "not ready: {} {}",
            reply.status,
            reply.body.trim()
        )))
    }
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;

    use super::*;

    /// A server that answers every connection with `response` and closes it.
    async fn canned(response: &'static str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let mut request = [0_u8; 1024];
                drop(stream.read(&mut request).await);
                drop(stream.write_all(response.as_bytes()).await);
                drop(stream.shutdown().await);
            }
        });
        address
    }

    #[test]
    fn responses_are_parsed() {
        let reply = parse(b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nX-A: b\r\n\r\n{\"status\":\"draining\"}")
            .unwrap();
        assert_eq!(reply.status, 503);
        assert_eq!(reply.body, "{\"status\":\"draining\"}");
        assert!(parse(b"not http").is_err());
        assert!(parse(b"SSH-2.0 x\r\n\r\n").is_err());
        assert!(parse(b"HTTP/1.1 abc\r\n\r\n").is_err());
    }

    #[tokio::test]
    async fn a_ready_instance_passes_and_a_draining_one_fails_with_the_reason() {
        let ready = canned("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
        assert!(check(ready, DEFAULT_TIMEOUT).await.unwrap().starts_with("ready"));
        let draining =
            canned("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 20\r\n\r\n{\"status\":\"draining\"}").await;
        let error = check(draining, DEFAULT_TIMEOUT).await.unwrap_err().to_string();
        assert!(error.contains("503") && error.contains("draining"), "{error}");
    }

    #[tokio::test]
    async fn an_address_nobody_listens_on_fails() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let error = check(address, DEFAULT_TIMEOUT).await.unwrap_err().to_string();
        assert!(error.contains("GET http://"), "{error}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_server_that_never_answers_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let held = tokio::spawn(async move {
            let accepted = listener.accept().await;
            std::future::pending::<()>().await;
            drop(accepted);
        });
        let error = check(address, Duration::from_secs(5)).await.unwrap_err().to_string();
        assert!(error.contains("no answer within 5s"), "{error}");
        held.abort();
    }

    #[test]
    fn the_ops_address_comes_from_the_listener_that_serves_ops() {
        let config = Config::from_toml(
            "[server]\npublic_base_url = \"https://cal.example.org\"\n[server.listeners.ops]\nbind = \"0.0.0.0:9191\"",
        )
        .unwrap();
        assert_eq!(ops_address(&config).unwrap(), "127.0.0.1:9191".parse().unwrap());
        let v6 = Config::from_toml(
            "[server]\npublic_base_url = \"https://cal.example.org\"\n[server.listeners.ops]\nbind = \"[::]:9191\"",
        )
        .unwrap();
        assert_eq!(ops_address(&v6).unwrap(), "[::1]:9191".parse().unwrap());
        let explicit = Config::from_toml(
            "[server]\npublic_base_url = \"https://cal.example.org\"\n[server.listeners.ops]\nbind = \"10.1.2.3:9090\"",
        )
        .unwrap();
        assert_eq!(ops_address(&explicit).unwrap(), "10.1.2.3:9090".parse().unwrap());
        let merged = Config::from_toml(
            "[server]\npublic_base_url = \"https://cal.example.org\"\n\
             [server.listeners.public]\nroutes = [\"wellknown\", \"dav\", \"web\", \"ops\"]\nbind = \"0.0.0.0:8080\"\n\
             [server.listeners.ops]\nenabled = false",
        )
        .unwrap();
        assert_eq!(ops_address(&merged).unwrap().port(), 8080);
        let none = Config::from_toml(
            "[server]\npublic_base_url = \"https://cal.example.org\"\n[server.listeners.ops]\nenabled = false",
        )
        .unwrap();
        assert!(
            ops_address(&none)
                .unwrap_err()
                .to_string()
                .contains("no listener serves")
        );
        let ephemeral = Config::from_toml(
            "[server]\npublic_base_url = \"https://cal.example.org\"\n[server.listeners.ops]\nbind = \"127.0.0.1:0\"",
        )
        .unwrap();
        assert!(ops_address(&ephemeral).unwrap_err().to_string().contains("port 0"));
    }
}
