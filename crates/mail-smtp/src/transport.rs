//! The `MailTransport` implementation.
//!
//! [`SmtpMailTransport`] hands mails to an SMTP relay with `lettre` (rustls with the ring provider, STARTTLS or
//! implicit TLS). The message itself is assembled by `davhaven-mime`, so the bytes are the same as the memory
//! transport captures; `lettre` only speaks SMTP.
//!
//! # One connection per mail
//!
//! Every mail opens its own connection and closes it when it is done. Mail volume is low (the outbox sends at most
//! `mail.rate_limit_per_minute` mails a minute), and a fresh connection means that a send that is cancelled
//! because it exceeded its deadline can never leave a half-spoken conversation for the next mail to trip over.
//! `lettre` applies its timeout to connecting only, so the adapter bounds the whole conversation itself: `timeout`
//! for connecting plus `timeout` for each command it expects (EHLO, MAIL, one RCPT per recipient, DATA, the end of
//! the data), and in any case no more than `total_timeout`, which is chosen to end before the outbox gives up on
//! the handler (`docs/mail.md`).
//!
//! # Classification of failures
//!
//! Failures are classified for the outbox (`MailTransport::send` documents the contract):
//!
//! | The relay or the network | Port error | The outbox |
//! | --- | --- | --- |
//! | connection refused, reset, TLS failure, `4xx`, authentication refused (`530`, `534`, `535`, `538`), no STARTTLS or no usable AUTH mechanism where the configuration requires one | `Unavailable` | retries, and the circuit breaker counts it |
//! | no answer in time | `Timeout` | retries, and the circuit breaker counts it |
//! | `5xx` whose enhanced status says the **mail or a recipient** is the problem: `5.1.x` (address), `5.2.x` (mailbox), `5.3.4` (too big), `5.4.x` (routing), `5.6.x` (content); a bare `551`, `552`, `553` or `550` | `Rejected` | dead-letters |
//! | any other `5xx`: `5.7.x` (policy: relay access denied, sender not allowed), `5.5.x`, a refusal at the greeting (`554`), anything else | `Unavailable` | retries: an operator fixes the relay, and the mail is not dead-lettered one by one |
//! | the mail cannot be encoded | `Invalid` | dead-letters |
//!
//! Error text never contains the relay's reply, which can quote the recipient's address, only the reply code. The
//! enhanced status (RFC 3463) is read from the reply to decide, and is not logged either.

use core::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use davhaven_domain::OutgoingMail;
use davhaven_mime::headers::address;
use davhaven_mime::message::assemble;
use davhaven_ports::{Clock, MailTransport, PluginError, PortError, PortLabel, SendReceipt, observe};
use lettre::address::Envelope;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::transport::smtp::extension::ClientId;
use lettre::transport::smtp::response::Response;
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use secrecy::{ExposeSecret, SecretString};

use crate::config::{PLUGIN, SmtpConfig, SmtpTls};

/// The label of the adapter in metrics and spans.
const LABEL: PortLabel = PortLabel::new("mail_transport", PLUGIN);

/// Reply codes that say the relay does not accept our credentials, not the mail: an operator fixes the
/// configuration, and the mail is delivered when the next attempt finds the relay working again.
const OPERATOR_FIXABLE_CODES: [&str; 4] = ["530", "534", "535", "538"];

/// The `MailTransport` of the SMTP adapter.
#[derive(Clone)]
pub struct SmtpMailTransport {
    host: String,
    port: u16,
    tls: Tls,
    credentials: Option<Arc<Credentials>>,
    ehlo_name: String,
    timeout: Duration,
    total_timeout: Duration,
    clock: Arc<dyn Clock>,
}

impl SmtpMailTransport {
    /// Prepares the transport; the relay is contacted when the first mail is sent.
    ///
    /// # Errors
    ///
    /// [`PluginError::InvalidConfig`] for a configuration that fails validation, and [`PluginError::Build`] when
    /// the TLS parameters cannot be created.
    pub fn new(
        config: &SmtpConfig,
        password: Option<&SecretString>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, PluginError> {
        config.validate()?;
        let host = config.host.trim().to_owned();
        let tls_parameters = || {
            TlsParameters::new(host.clone())
                .map_err(|_| PluginError::build(PLUGIN, PortError::internal("cannot initialise TLS")))
        };
        let tls = match config.tls {
            SmtpTls::Starttls => Tls::Required(tls_parameters()?),
            SmtpTls::Implicit => Tls::Wrapper(tls_parameters()?),
            SmtpTls::None => Tls::None,
        };
        // `lettre` takes the password as a plain `String` and does not zeroize it; the copy is made once here and
        // shared by every send, not cloned for each of them.
        let credentials = match (&config.username, password) {
            (Some(username), Some(password)) => Some(Arc::new(Credentials::new(
                username.clone(),
                password.expose_secret().to_owned(),
            ))),
            _ => None,
        };
        Ok(Self {
            host,
            port: config.port,
            tls,
            credentials,
            ehlo_name: config.ehlo_name.clone().unwrap_or_else(|| "localhost".to_owned()),
            timeout: config.timeout,
            total_timeout: config.total_timeout,
            clock,
        })
    }

    /// A transport that is dropped (and its connection closed) after one mail.
    ///
    /// `builder_dangerous` is `lettre`'s name for the builder that takes the TLS mode as given instead of deriving
    /// it from the URL scheme; the mode is [`Tls::Required`] (STARTTLS that must succeed, hostname verified) or
    /// [`Tls::Wrapper`] unless the configuration says `none`, and a relay that does not offer what is required
    /// fails the send instead of downgrading.
    fn client(&self) -> AsyncSmtpTransport<Tokio1Executor> {
        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(self.host.clone())
            .port(self.port)
            .tls(self.tls.clone())
            .hello_name(ClientId::Domain(self.ehlo_name.clone()))
            .timeout(Some(self.timeout));
        if let Some(credentials) = &self.credentials {
            builder = builder.credentials(Credentials::clone(credentials));
        }
        builder.build()
    }

    async fn deliver(&self, mail: &OutgoingMail) -> Result<SendReceipt, PortError> {
        mail.validate().map_err(|error| PortError::invalid(error.to_string()))?;
        let assembled = assemble(mail, self.clock.now()).map_err(|error| PortError::invalid(error.to_string()))?;
        let from = address(assembled.envelope_from()).map_err(|error| PortError::invalid(error.to_string()))?;
        let recipients = assembled
            .envelope_to()
            .iter()
            .map(address)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| PortError::invalid(error.to_string()))?;
        let commands = u32::try_from(recipients.len()).unwrap_or(u32::MAX).saturating_add(5);
        let envelope =
            Envelope::new(Some(from), recipients).map_err(|_| PortError::invalid("the envelope is invalid"))?;
        let deadline = self.timeout.saturating_mul(commands).min(self.total_timeout);
        let client = self.client();
        let response = tokio::time::timeout(deadline, client.send_raw(&envelope, assembled.bytes()))
            .await
            .map_err(|_| PortError::timeout("the relay did not answer in time"))?
            .map_err(|error| map_error(&error))?;
        Ok(SendReceipt {
            message_id: mail.message_id.clone(),
            transport_id: queue_id(&response),
        })
    }
}

impl fmt::Debug for SmtpMailTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmtpMailTransport")
            .field("port", &self.port)
            .field("authenticated", &self.credentials.is_some())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl MailTransport for SmtpMailTransport {
    async fn send(&self, mail: &OutgoingMail) -> Result<SendReceipt, PortError> {
        observe(LABEL, "send", self.deliver(mail)).await
    }
}

/// The relay's queue id from a `250` reply such as `2.0.0 Ok: queued as 4F3A12B0`, when it names one.
fn queue_id(response: &Response) -> Option<String> {
    response.message().find_map(|line| {
        let lower = line.to_ascii_lowercase();
        let start = lower.find("queued as ")? + "queued as ".len();
        let id: String = line
            .get(start..)?
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
            .take(64)
            .collect();
        (!id.is_empty()).then_some(id)
    })
}

/// The enhanced status code (RFC 3463: class, subject, detail) the relay put at the start of its reply, if it did.
/// The text of the reply stays inside this function.
fn enhanced_status(error: &lettre::transport::smtp::Error) -> Option<(u16, u16, u16)> {
    let reply = std::error::Error::source(error)?.to_string();
    let token = reply.split_whitespace().next()?;
    let mut parts = token.split('.').map(|part| part.parse::<u16>().ok());
    let (class, subject, detail) = (parts.next()??, parts.next()??, parts.next()??);
    (matches!(class, 2 | 4 | 5) && parts.next().is_none()).then_some((class, subject, detail))
}

/// Whether a permanent failure is about the mail or one of its recipients (the mail is dead) and not about the relay
/// or our standing with it (an operator fixes it, the mail waits).
///
/// The decision rests on the enhanced status code when the relay sends one: address (`5.1.x`), mailbox
/// (`5.2.x`), a message that is too big (`5.3.4`), routing of the recipient's domain (`5.4.x`) and content
/// (`5.6.x`) are the mail's; policy (`5.7.x`), protocol (`5.5.x`) and the rest are the relay's. Without one only
/// the codes of RFC 5321 that name the mailbox (`550`, `551`, `552`, `553`) count as the mail's: a refusal at the
/// greeting (`554`) is a relay that does not want us.
fn permanent_failure_is_the_mails(code: &str, enhanced: Option<(u16, u16, u16)>) -> bool {
    match enhanced {
        Some((5, subject, detail)) => matches!(subject, 1 | 2 | 4 | 6) || (subject, detail) == (3, 4),
        _ => matches!(code, "550" | "551" | "552" | "553"),
    }
}

/// Classifies an SMTP failure without quoting the relay's text.
fn map_error(error: &lettre::transport::smtp::Error) -> PortError {
    if let Some(code) = error.status() {
        let code = code.to_string();
        return if !error.is_permanent() {
            PortError::unavailable(format!("the relay answered with a temporary failure (SMTP {code})"))
        } else if OPERATOR_FIXABLE_CODES.contains(&code.as_str()) {
            PortError::unavailable(format!("the relay refused our credentials (SMTP {code})"))
        } else if permanent_failure_is_the_mails(&code, enhanced_status(error)) {
            PortError::rejected(format!("the relay refused the mail permanently (SMTP {code})"))
        } else {
            PortError::unavailable(format!("the relay refused us on grounds of its policy (SMTP {code})"))
        };
    }
    if error.is_timeout() {
        PortError::timeout("the relay did not answer in time")
    } else if error.is_tls() {
        PortError::unavailable("the TLS handshake with the relay failed")
    } else if error.is_client() {
        // The mail was assembled and checked before the send, so what `lettre` calls a client error here is what
        // the relay does not offer: STARTTLS that the configuration requires, an authentication mechanism. The
        // configuration is the operator's to fix, and the mail waits for it.
        PortError::unavailable("the relay does not offer what the configuration requires")
    } else {
        PortError::unavailable("the relay cannot be reached")
    }
}

#[cfg(test)]
mod tests {
    use lettre::transport::smtp::response::{Category, Code, Detail, Severity};

    use super::*;

    fn response(lines: &[&str]) -> Response {
        Response::new(
            Code::new(Severity::PositiveCompletion, Category::MailSystem, Detail::Zero),
            lines.iter().map(|line| (*line).to_owned()).collect(),
        )
    }

    #[test]
    fn queue_ids_are_read_from_the_usual_replies() {
        assert_eq!(
            queue_id(&response(&["2.0.0 Ok: queued as 4F3A12B0"])).as_deref(),
            Some("4F3A12B0")
        );
        assert_eq!(
            queue_id(&response(&["OK", "Queued as abc-123.x"])).as_deref(),
            Some("abc-123.x")
        );
        assert_eq!(queue_id(&response(&["2.0.0 OK 1234 gsmtp"])), None);
        assert_eq!(queue_id(&response(&["queued as "])), None);
        let long = format!("queued as {}", "a".repeat(200));
        assert_eq!(queue_id(&response(&[&long])).map(|id| id.len()), Some(64));
    }

    #[test]
    fn every_tls_setting_becomes_the_matching_mode_and_never_a_weaker_one() {
        let clock: Arc<dyn Clock> = Arc::new(davhaven_ports::testing::ManualClock::default());
        for (setting, host) in [
            (SmtpTls::Starttls, "smtp.example.org"),
            (SmtpTls::Implicit, "smtp.example.org"),
            (SmtpTls::None, "localhost"),
        ] {
            let config = SmtpConfig {
                host: host.to_owned(),
                tls: setting,
                ..SmtpConfig::default()
            };
            let transport = SmtpMailTransport::new(&config, None, Arc::clone(&clock)).unwrap();
            match (setting, &transport.tls) {
                (SmtpTls::Starttls, Tls::Required(_))
                | (SmtpTls::Implicit, Tls::Wrapper(_))
                | (SmtpTls::None, Tls::None) => {}
                (setting, other) => panic!("{setting:?} became {other:?}"),
            }
        }
    }

    #[test]
    fn permanent_failures_are_the_mails_only_when_the_reply_says_so() {
        // (code, enhanced status, the mail's?)
        for (code, enhanced, mails) in [
            ("550", Some((5, 1, 1)), true),
            ("550", Some((5, 1, 10)), true),
            ("553", Some((5, 1, 3)), true),
            ("552", Some((5, 2, 2)), true),
            ("552", Some((5, 3, 4)), true),
            ("554", Some((5, 4, 4)), true),
            ("554", Some((5, 6, 0)), true),
            ("550", Some((5, 7, 1)), false),
            ("554", Some((5, 7, 1)), false),
            ("550", Some((5, 7, 26)), false),
            ("554", Some((5, 5, 1)), false),
            ("554", Some((5, 0, 0)), false),
            ("550", Some((5, 3, 0)), false),
            ("550", None, true),
            ("551", None, true),
            ("552", None, true),
            ("553", None, true),
            ("554", None, false),
            ("521", None, false),
            ("555", None, false),
        ] {
            assert_eq!(
                permanent_failure_is_the_mails(code, enhanced),
                mails,
                "{code} {enhanced:?}"
            );
        }
    }

    #[test]
    fn the_whole_mail_is_bounded_by_the_total_timeout() {
        let clock: Arc<dyn Clock> = Arc::new(davhaven_ports::testing::ManualClock::default());
        let config = SmtpConfig::default();
        let transport = SmtpMailTransport::new(&config, None, clock).unwrap();
        // One recipient: connect plus five commands at 8 s each would be 48 s, the budget is 30 s.
        let commands = 6_u32;
        assert_eq!(
            transport.timeout.saturating_mul(commands).min(transport.total_timeout),
            Duration::from_secs(30)
        );
        assert!(
            transport.total_timeout < Duration::from_secs(36),
            "below 60 % of the default lease of the outbox"
        );
    }

    #[test]
    fn configuration_problems_are_reported_before_connecting() {
        let bad = SmtpConfig {
            port: 0,
            ..SmtpConfig::default()
        };
        let error =
            SmtpMailTransport::new(&bad, None, Arc::new(davhaven_ports::testing::ManualClock::default())).unwrap_err();
        assert!(error.to_string().contains("port"), "{error}");
    }

    #[test]
    fn debug_output_shows_neither_host_nor_password() {
        let config = SmtpConfig {
            host: "smtp.internal.example".to_owned(),
            username: Some("davhaven".to_owned()),
            password_file: Some("/unused".into()),
            tls: SmtpTls::None,
            ..SmtpConfig::default()
        };
        let password = SecretString::from("hunter2");
        let transport = SmtpMailTransport::new(
            &config,
            Some(&password),
            Arc::new(davhaven_ports::testing::ManualClock::default()),
        )
        .unwrap();
        let shown = format!("{transport:?}");
        assert!(shown.contains("authenticated: true"), "{shown}");
        assert!(
            !shown.contains("hunter2") && !shown.contains("internal") && !shown.contains("davhaven"),
            "{shown}"
        );
    }
}
