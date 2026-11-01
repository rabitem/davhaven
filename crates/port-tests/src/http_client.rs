//! Contract suite of the `HttpClient` port.
//!
//! What every client promises (`ENGINEERING_RULES` R6): outbound HTTP is subject to the egress policy, and the
//! refusals are decided before anything is sent. The factory builds a client with the **default** policy (https
//! only, nothing but global unicast addresses, no allow lists), and the suite checks the SSRF table against it:
//! plain `http` and other schemes, credentials in the URL, and every notation of loopback, private, link-local,
//! carrier-grade NAT, unique-local, metadata and mapped addresses are `Rejected`, both by `send` and by
//! `validate_url`, and a public https address is acceptable to `validate_url`. A client that does not implement
//! `validate_url` fails the last case (the default answers `Unsupported`, so a URL is never accepted unchecked).
//! The messages of the refusals are quiet: they carry no URL, path, query or credentials, because webhook URLs and
//! the secrets in them must not reach logs or the `last_error` of an outbox record.
//!
//! The suite never opens a connection: every request it sends is refused by the policy, and the public address it
//! validates is a literal, which needs no DNS. Behaviour that needs a server (redirects, timeouts, size caps,
//! rebinding through DNS) is tested by the adapter itself.

use std::sync::Arc;

use davhaven_ports::{HttpClient, HttpPurpose, OutboundRequest, PortError, PortErrorKind};
use http::Method;
use url::Url;

use crate::suite::{Checks, ContractReport, Suite};

/// Schemes the default policy refuses.
pub const REFUSED_SCHEMES: [&str; 5] = [
    "http://8.8.8.8/",
    "http://hooks.example.org/",
    "ftp://8.8.8.8/",
    "file:///etc/passwd",
    "ws://8.8.8.8/",
];

/// Credentials in the URL.
pub const REFUSED_CREDENTIALS: [&str; 3] = [
    "https://user:secret@8.8.8.8/",
    "https://user@8.8.8.8/",
    "https://:secret@8.8.8.8/",
];

/// The SSRF table: targets the default policy refuses in every notation the URL parser reduces to an address.
pub const REFUSED_TARGETS: [&str; 34] = [
    "https://127.0.0.1/",
    "https://127.1/",
    "https://2130706433/",
    "https://0x7f000001/",
    "https://0x7f.0.0.1/",
    "https://017700000001/",
    "https://0177.0.0.1/",
    "https://127.0.0.1./",
    "https://0/",
    "https://0.0.0.0/",
    "https://10.0.0.1/",
    "https://172.16.0.1/",
    "https://172.31.255.255/",
    "https://192.168.1.1/",
    "https://100.64.0.1/",
    "https://169.254.169.254/latest/meta-data/",
    "https://169.254.1.1/",
    "https://100.100.100.200/",
    "https://168.63.129.16/",
    "https://255.255.255.255/",
    "https://224.0.0.1/",
    "https://[::1]/",
    "https://[::]/",
    "https://[::ffff:127.0.0.1]/",
    "https://[::ffff:7f00:1]/",
    "https://[::ffff:169.254.169.254]/",
    "https://[::127.0.0.1]/",
    "https://[64:ff9b::7f00:1]/",
    "https://[2002:7f00:1::]/",
    "https://[fe80::1]/",
    "https://[fc00::1]/",
    "https://[fd00:ec2::254]/",
    "https://[ff02::1]/",
    "https://[2001:db8::1]/",
];

/// A global unicast literal that the default policy accepts.
pub const ACCEPTED_TARGET: &str = "https://8.8.8.8/";

fn request(url: &str) -> Option<OutboundRequest> {
    Url::parse(url)
        .ok()
        .map(|url| OutboundRequest::new(Method::GET, url, HttpPurpose::Webhook))
}

/// Checks that the message of a refusal leaves out what the URL carries: the URL itself, a path longer than `/`, the
/// query and the credentials.
fn expect_quiet(checks: &mut Checks, error: &PortError, url: &Url, what: &str) {
    let message = error.message.to_ascii_lowercase();
    let mut secrets: Vec<String> = vec![url.as_str().to_ascii_lowercase()];
    if url.path().len() > 1 {
        secrets.push(url.path().to_ascii_lowercase());
    }
    if let Some(query) = url.query() {
        secrets.push(query.to_ascii_lowercase());
    }
    if !url.username().is_empty() {
        secrets.push(url.username().to_ascii_lowercase());
    }
    if let Some(password) = url.password() {
        secrets.push(password.to_ascii_lowercase());
    }
    for secret in secrets {
        checks.that(
            !message.contains(&secret),
            &format!(
                "{what}: the message of the refusal quotes {secret:?}: {}",
                error.message
            ),
        );
    }
}

/// Checks that `send` and `validate_url` both refuse `url` with `Rejected`, quietly.
async fn expect_refused(checks: &mut Checks, client: &dyn HttpClient, url: &str) {
    let (Some(outbound), Ok(parsed)) = (request(url), Url::parse(url)) else {
        checks.fail(format!("the suite could not parse {url}"));
        return;
    };
    let sent: Result<_, PortError> = client.send(outbound).await;
    if let Some(error) = checks.err(sent, &format!("send to {url}")) {
        checks.equal(
            &error.kind,
            &PortErrorKind::Rejected,
            &format!("the error kind of send to {url}"),
        );
        expect_quiet(checks, &error, &parsed, &format!("send to {url}"));
    }
    let validated = client.validate_url(&parsed).await;
    if let Some(error) = checks.err(validated, &format!("validate_url of {url}")) {
        checks.equal(
            &error.kind,
            &PortErrorKind::Rejected,
            &format!("the error kind of validate_url of {url}"),
        );
        expect_quiet(checks, &error, &parsed, &format!("validate_url of {url}"));
    }
}

/// Runs the suite against clients built by `factory` and returns the report.
pub async fn run<F>(factory: F) -> ContractReport
where
    F: Fn() -> Arc<dyn HttpClient>,
{
    let mut suite = Suite::new("http_client");
    let client = factory();

    let mut checks = Checks::new("schemes other than https are refused");
    for url in REFUSED_SCHEMES {
        expect_refused(&mut checks, client.as_ref(), url).await;
    }
    suite.record(checks);

    let mut checks = Checks::new("credentials in the URL are refused");
    for url in REFUSED_CREDENTIALS {
        expect_refused(&mut checks, client.as_ref(), url).await;
    }
    suite.record(checks);

    let mut checks = Checks::new("loopback, private, link-local, metadata and mapped addresses are refused");
    for url in REFUSED_TARGETS {
        expect_refused(&mut checks, client.as_ref(), url).await;
    }
    suite.record(checks);

    let mut checks = Checks::new("a public https address is acceptable");
    match Url::parse(ACCEPTED_TARGET) {
        Ok(url) => {
            checks.ok(
                client.validate_url(&url).await,
                "validate_url of a global unicast literal",
            );
        }
        Err(_) => checks.fail("the suite could not parse its public address"),
    }
    suite.record(checks);

    suite.finish()
}

/// Runs the suite and fails the running test when any case fails.
///
/// # Panics
///
/// When a case fails.
pub async fn run_all<F>(factory: F)
where
    F: Fn() -> Arc<dyn HttpClient>,
{
    run(factory).await.assert_ok();
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use davhaven_ports::OutboundResponse;

    use super::*;

    /// Refuses everything except https to the one public address, like the real policy does for the table.
    struct OnlyPublic;

    impl OnlyPublic {
        fn check(url: &Url) -> Result<(), PortError> {
            if url.scheme() == "https"
                && url.host_str() == Some("8.8.8.8")
                && url.username().is_empty()
                && url.password().is_none()
            {
                Ok(())
            } else {
                Err(PortError::rejected("egress policy"))
            }
        }
    }

    #[async_trait]
    impl HttpClient for OnlyPublic {
        async fn send(&self, request: OutboundRequest) -> Result<OutboundResponse, PortError> {
            Self::check(&request.url)?;
            Err(PortError::unavailable("no network in this double"))
        }

        async fn validate_url(&self, url: &Url) -> Result<(), PortError> {
            Self::check(url)
        }
    }

    /// Accepts everything: no policy at all.
    struct Open;

    #[async_trait]
    impl HttpClient for Open {
        async fn send(&self, _request: OutboundRequest) -> Result<OutboundResponse, PortError> {
            Err(PortError::unavailable("no network in this double"))
        }
    }

    /// Refuses with the wrong kind.
    struct WrongKind;

    #[async_trait]
    impl HttpClient for WrongKind {
        async fn send(&self, _request: OutboundRequest) -> Result<OutboundResponse, PortError> {
            Err(PortError::invalid("nope"))
        }

        async fn validate_url(&self, url: &Url) -> Result<(), PortError> {
            if url.host_str() == Some("8.8.8.8")
                && url.scheme() == "https"
                && url.username().is_empty()
                && url.password().is_none()
            {
                Ok(())
            } else {
                Err(PortError::invalid("nope"))
            }
        }
    }

    #[test]
    fn the_tables_parse_and_keep_their_promised_size() {
        for url in REFUSED_SCHEMES
            .iter()
            .chain(REFUSED_CREDENTIALS.iter())
            .chain(REFUSED_TARGETS.iter())
            .chain([ACCEPTED_TARGET].iter())
        {
            assert!(Url::parse(url).is_ok(), "{url}");
        }
        assert_eq!(REFUSED_TARGETS.len(), 34);
    }

    #[tokio::test]
    async fn a_policy_enforcing_client_satisfies_the_contract() {
        run_all(|| Arc::new(OnlyPublic)).await;
        assert_eq!(run(|| Arc::new(OnlyPublic)).await.case_count(), 4);
    }

    #[tokio::test]
    async fn a_client_without_policy_is_caught_in_every_case() {
        let report = run(|| Arc::new(Open)).await;
        assert_eq!(
            report.failed_cases(),
            vec![
                "schemes other than https are refused",
                "credentials in the URL are refused",
                "loopback, private, link-local, metadata and mapped addresses are refused",
                "a public https address is acceptable",
            ],
            "{report}"
        );
        assert!(
            report.to_string().contains("cannot validate URLs"),
            "a client that does not implement validate_url is told so: {report}"
        );
    }

    /// A client whose refusals quote the URL, which can carry a secret.
    struct Chatty;

    impl Chatty {
        fn check(url: &Url) -> Result<(), PortError> {
            if url.scheme() == "https" && url.host_str() == Some("8.8.8.8") && url.username().is_empty() {
                Ok(())
            } else {
                Err(PortError::rejected(format!("the egress policy refuses {url}")))
            }
        }
    }

    #[async_trait]
    impl HttpClient for Chatty {
        async fn send(&self, request: OutboundRequest) -> Result<OutboundResponse, PortError> {
            Self::check(&request.url)?;
            Err(PortError::unavailable("no network in this double"))
        }

        async fn validate_url(&self, url: &Url) -> Result<(), PortError> {
            Self::check(url)
        }
    }

    #[tokio::test]
    async fn refusals_that_quote_the_url_are_caught() {
        let report = run(|| Arc::new(Chatty)).await;
        assert!(!report.is_ok());
        assert!(
            report.to_string().contains("the message of the refusal quotes"),
            "{report}"
        );
    }

    #[tokio::test]
    async fn refusals_with_the_wrong_kind_are_caught() {
        let report = run(|| Arc::new(WrongKind)).await;
        assert!(!report.is_ok());
        assert!(report.to_string().contains("the error kind of send to"), "{report}");
    }
}
