//! The SMTP adapter against an in-process relay.
//!
//! The relay speaks just enough SMTP (EHLO, AUTH PLAIN, MAIL, RCPT, DATA with dot unstuffing, RSET, NOOP, QUIT) to
//! check what the adapter puts on the wire and how it classifies the answers. It is plain text, so most tests use
//! `tls = "none"`; the TLS handshake is `lettre`'s and `rustls`'s business. What the adapter owns is that it never
//! sends in the clear when the configuration requires TLS: with `starttls` against a relay that does not offer
//! STARTTLS nothing but the greeting and EHLO ever reaches the relay.

#![expect(
    clippy::unwrap_used,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use std::sync::Arc;
use std::time::Duration;

use davhaven_domain::{
    CalendarPart, Email, HeaderText, ItipMethod, MailAttachment, Mailbox, MediaType, MessageId, OutgoingMail,
};
use davhaven_mail_smtp::config::{SmtpConfig, SmtpTls};
use davhaven_mail_smtp::transport::SmtpMailTransport;
use davhaven_ports::testing::ManualClock;
use davhaven_ports::{Clock, MailTransport, PortErrorKind};
use secrecy::SecretString;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// How the relay answers.
#[derive(Clone)]
struct Behaviour {
    greeting: &'static str,
    /// What the relay offers after `AUTH` (the mechanisms), when it offers a login at all.
    auth_offer: &'static str,
    rcpt_reply: &'static str,
    data_reply: &'static str,
    login: Option<(&'static str, &'static str)>,
    /// Close the connection right after accepting it.
    hang_up: bool,
    /// Reset the connection right after accepting it (a relay that is not there for us).
    reset: bool,
    /// Accept the connection and never speak.
    silent: bool,
}

impl Default for Behaviour {
    fn default() -> Self {
        Self {
            greeting: "220 relay.test ESMTP ready",
            auth_offer: "PLAIN",
            rcpt_reply: "250 2.1.5 Ok",
            data_reply: "250 2.0.0 Ok: queued as QUEUE42",
            login: None,
            hang_up: false,
            reset: false,
            silent: false,
        }
    }
}

/// One accepted message.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Received {
    from: String,
    to: Vec<String>,
    data: String,
    logged_in_as: Option<String>,
}

struct Relay {
    port: u16,
    received: Arc<Mutex<Vec<Received>>>,
    /// The verb of every command line the relay was sent (`EHLO`, `MAIL`, `AUTH`, ...), in order.
    commands: Arc<Mutex<Vec<String>>>,
    /// The names clients gave in `EHLO`, in order.
    greetings: Arc<Mutex<Vec<String>>>,
}

impl Relay {
    async fn start(behaviour: Behaviour) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let received = Arc::new(Mutex::new(Vec::new()));
        let commands = Arc::new(Mutex::new(Vec::new()));
        let greetings = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&received);
        let seen = Arc::clone(&commands);
        let names = Arc::clone(&greetings);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let behaviour = behaviour.clone();
                let sink = Arc::clone(&sink);
                let seen = Arc::clone(&seen);
                let names = Arc::clone(&names);
                tokio::spawn(async move {
                    if behaviour.hang_up {
                        drop(stream);
                    } else if behaviour.reset {
                        // A zero linger turns the close into a reset (RST) instead of a polite FIN.
                        #[expect(deprecated, reason = "the only way to make tokio send a reset; this is a test relay")]
                        drop(stream.set_linger(Some(Duration::ZERO)));
                        drop(stream);
                    } else if behaviour.silent {
                        // Keeps the connection open and says nothing until the test ends and drops the task.
                        let _open = stream;
                        std::future::pending::<()>().await;
                    } else {
                        drop(serve(stream, behaviour, sink, seen, names).await);
                    }
                });
            }
        });
        Self {
            port,
            received,
            commands,
            greetings,
        }
    }

    async fn messages(&self) -> Vec<Received> {
        self.received.lock().await.clone()
    }

    async fn commands(&self) -> Vec<String> {
        self.commands.lock().await.clone()
    }

    async fn greetings(&self) -> Vec<String> {
        self.greetings.lock().await.clone()
    }
}

async fn serve(
    stream: TcpStream,
    behaviour: Behaviour,
    sink: Arc<Mutex<Vec<Received>>>,
    seen: Arc<Mutex<Vec<String>>>,
    names: Arc<Mutex<Vec<String>>>,
) -> std::io::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();
    write
        .write_all(format!("{}\r\n", behaviour.greeting).as_bytes())
        .await?;
    if !behaviour.greeting.starts_with('2') {
        return Ok(());
    }
    let mut from = String::new();
    let mut to: Vec<String> = Vec::new();
    let mut logged_in_as = None;
    while let Some(line) = lines.next_line().await? {
        let upper = line.to_ascii_uppercase();
        seen.lock().await.push(
            upper
                .split(|c: char| c.is_whitespace() || c == ':')
                .next()
                .unwrap_or_default()
                .to_owned(),
        );
        if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            names
                .lock()
                .await
                .push(line.split_whitespace().nth(1).unwrap_or_default().to_owned());
            let mut reply = String::from("250-relay.test\r\n250-8BITMIME\r\n");
            if behaviour.login.is_some() {
                reply.push_str("250-AUTH ");
                reply.push_str(behaviour.auth_offer);
                reply.push_str("\r\n");
            }
            reply.push_str("250 SIZE 10485760\r\n");
            write.write_all(reply.as_bytes()).await?;
        } else if upper.starts_with("AUTH PLAIN") {
            let presented = line.split_whitespace().nth(2).unwrap_or_default();
            let accepted = behaviour.login.is_some_and(|(user, password)| {
                presented == STANDARD.encode(format!("\0{user}\0{password}").as_bytes())
            });
            if accepted {
                logged_in_as = behaviour.login.map(|(user, _)| user.to_owned());
                write.write_all(b"235 2.7.0 Authentication successful\r\n").await?;
            } else {
                write
                    .write_all(b"535 5.7.8 Authentication credentials invalid\r\n")
                    .await?;
            }
        } else if upper.starts_with("MAIL FROM:") {
            from = angle(&line);
            to.clear();
            write.write_all(b"250 2.1.0 Ok\r\n").await?;
        } else if upper.starts_with("RCPT TO:") {
            if behaviour.rcpt_reply.starts_with('2') {
                to.push(angle(&line));
            }
            write
                .write_all(format!("{}\r\n", behaviour.rcpt_reply).as_bytes())
                .await?;
        } else if upper == "DATA" {
            write.write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n").await?;
            let mut data = String::new();
            while let Some(body_line) = lines.next_line().await? {
                if body_line == "." {
                    break;
                }
                data.push_str(body_line.strip_prefix('.').unwrap_or(&body_line));
                data.push_str("\r\n");
            }
            // The line break before the final dot belongs to the terminator, not to the message.
            data.truncate(data.len().saturating_sub(2));
            if behaviour.data_reply.starts_with('2') {
                sink.lock().await.push(Received {
                    from: from.clone(),
                    to: to.clone(),
                    data,
                    logged_in_as: logged_in_as.clone(),
                });
            }
            write
                .write_all(format!("{}\r\n", behaviour.data_reply).as_bytes())
                .await?;
        } else if upper == "QUIT" {
            write.write_all(b"221 2.0.0 Bye\r\n").await?;
            return Ok(());
        } else {
            write.write_all(b"250 2.0.0 Ok\r\n").await?;
        }
    }
    Ok(())
}

/// The address between the angle brackets of a command line.
fn angle(line: &str) -> String {
    line.split_once('<')
        .and_then(|(_, rest)| rest.split_once('>'))
        .map(|(address, _)| address.to_owned())
        .unwrap_or_default()
}

fn email(text: &str) -> Email {
    Email::parse(text).unwrap()
}

fn mail(n: u32, text: &str) -> OutgoingMail {
    OutgoingMail {
        message_id: MessageId::parse(&format!("<smtp-{n}@mail.example.org>")).unwrap(),
        from: Mailbox::named(
            HeaderText::parse("Anna via Acme").unwrap(),
            email("noreply@mail.example.org"),
        ),
        sender: None,
        reply_to: Some(Mailbox::bare(email("anna@example.org"))),
        to: vec![Mailbox::bare(email("guest@example.net"))],
        subject: HeaderText::parse("Invitation: Planning").unwrap(),
        text: text.to_owned(),
        html: None,
        calendar: None,
        attachments: Vec::new(),
        headers: Vec::new(),
    }
}

fn transport(port: u16, timeout: Duration, credentials: Option<(&str, &str)>) -> SmtpMailTransport {
    let config = SmtpConfig {
        host: "127.0.0.1".to_owned(),
        port,
        username: credentials.map(|(user, _)| user.to_owned()),
        password_file: credentials.map(|_| PathBuf::from("/unused")),
        tls: SmtpTls::None,
        ehlo_name: None,
        timeout,
        total_timeout: timeout.saturating_mul(6),
        allow_insecure_transport: false,
    };
    let password = credentials.map(|(_, password)| SecretString::from(password));
    SmtpMailTransport::new(&config, password.as_ref(), Arc::new(ManualClock::default())).unwrap()
}

#[tokio::test]
async fn a_mail_arrives_byte_for_byte_with_its_envelope_and_the_queue_id() {
    let relay = Relay::start(Behaviour::default()).await;
    let transport = transport(relay.port, Duration::from_secs(5), None);
    let mut outgoing = mail(1, "Hello\n.A line that starts with a dot\n..and two\nGrüße\n");
    outgoing.html = Some("<p>Hello</p>".to_owned());
    outgoing.calendar = Some(CalendarPart {
        method: ItipMethod::Request,
        ics: "BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nEND:VCALENDAR\r\n".to_owned(),
    });
    outgoing.attachments = vec![MailAttachment {
        filename: HeaderText::parse("invite.ics").unwrap(),
        content_type: MediaType::parse("application/ics").unwrap(),
        data: b"BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nEND:VCALENDAR\r\n".to_vec(),
    }];

    let receipt = transport.send(&outgoing).await.unwrap();
    assert_eq!(receipt.message_id, outgoing.message_id);
    assert_eq!(receipt.transport_id.as_deref(), Some("QUEUE42"));

    let messages = relay.messages().await;
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].from, "noreply@mail.example.org");
    assert_eq!(messages[0].to, vec!["guest@example.net"]);
    let expected = davhaven_mime::message::assemble(&outgoing, ManualClock::default().now()).unwrap();
    assert_eq!(messages[0].data.as_bytes(), expected.bytes());
    assert!(messages[0].logged_in_as.is_none());
}

#[tokio::test]
async fn the_login_is_sent_when_the_relay_asks_for_it() {
    let relay = Relay::start(Behaviour {
        login: Some(("davhaven", "s3cret")),
        ..Behaviour::default()
    })
    .await;
    let transport = transport(relay.port, Duration::from_secs(5), Some(("davhaven", "s3cret")));
    transport.send(&mail(1, "Hi\n")).await.unwrap();
    assert_eq!(relay.messages().await[0].logged_in_as.as_deref(), Some("davhaven"));

    let wrong = transport_with_wrong_password(relay.port);
    let error = wrong.send(&mail(2, "Hi\n")).await.unwrap_err();
    assert_eq!(
        error.kind,
        PortErrorKind::Unavailable,
        "refused credentials are an operator problem, not the mail's: {error}"
    );
    assert!(error.message.contains("535"), "{error}");
    assert!(
        !error.message.contains("s3cret") && !error.message.contains("davhaven"),
        "{error}"
    );
}

fn transport_with_wrong_password(port: u16) -> SmtpMailTransport {
    transport(port, Duration::from_secs(5), Some(("davhaven", "wrong")))
}

#[tokio::test]
async fn answers_are_classified_for_the_outbox_without_quoting_the_relay() {
    let cases = [
        (
            "550 5.1.1 <guest@example.net>: Recipient address rejected",
            PortErrorKind::Rejected,
            "550",
        ),
        ("553 5.1.3 mailbox name not allowed", PortErrorKind::Rejected, "553"),
        ("552 5.2.2 mailbox full", PortErrorKind::Rejected, "552"),
        ("550 user unknown", PortErrorKind::Rejected, "550"),
        ("451 4.3.0 try again later", PortErrorKind::Unavailable, "451"),
        ("452 4.2.2 mailbox full", PortErrorKind::Unavailable, "452"),
        // Setup problems of the relay are not the mail's: the mail waits, the circuit breaker counts the failure and
        // an operator fixes the relay, instead of every queued invitation dying one by one.
        (
            "550 5.7.1 <guest@example.net>: Relay access denied",
            PortErrorKind::Unavailable,
            "550",
        ),
        (
            "554 5.7.1 sender address not allowed",
            PortErrorKind::Unavailable,
            "554",
        ),
        ("550 5.7.26 unauthenticated sender", PortErrorKind::Unavailable, "550"),
        ("554 5.5.1 no valid recipients", PortErrorKind::Unavailable, "554"),
    ];
    for (reply, kind, code) in cases {
        let relay = Relay::start(Behaviour {
            rcpt_reply: reply,
            ..Behaviour::default()
        })
        .await;
        let error = transport(relay.port, Duration::from_secs(5), None)
            .send(&mail(1, "Hi\n"))
            .await
            .unwrap_err();
        assert_eq!(error.kind, kind, "{reply}: {error}");
        assert!(error.message.contains(code), "{error}");
        assert!(
            !error.message.contains('@') && !error.message.contains("example.net"),
            "no address in {error}"
        );
        assert_eq!(relay.messages().await.len(), 0);
    }
    let relay = Relay::start(Behaviour {
        data_reply: "554 5.6.0 message content rejected",
        ..Behaviour::default()
    })
    .await;
    let error = transport(relay.port, Duration::from_secs(5), None)
        .send(&mail(1, "Hi\n"))
        .await
        .unwrap_err();
    assert_eq!(error.kind, PortErrorKind::Rejected, "{error}");
}

#[tokio::test]
async fn a_refusal_at_the_greeting_is_the_relays_and_not_the_mails() {
    let relay = Relay::start(Behaviour {
        greeting: "554 no SMTP service here",
        ..Behaviour::default()
    })
    .await;
    let error = transport(relay.port, Duration::from_secs(5), None)
        .send(&mail(1, "Hi\n"))
        .await
        .unwrap_err();
    assert_eq!(error.kind, PortErrorKind::Unavailable, "{error}");
    assert!(error.message.contains("554"), "{error}");
    assert!(
        relay.commands().await.is_empty(),
        "nothing was sent to a relay that does not talk to us"
    );
}

#[tokio::test]
async fn a_login_the_relay_cannot_take_is_an_operator_problem_and_nothing_is_delivered() {
    // The relay offers a mechanism the client does not speak: the configured login cannot be used.
    let relay = Relay::start(Behaviour {
        login: Some(("davhaven", "s3cret")),
        auth_offer: "XOAUTH2",
        ..Behaviour::default()
    })
    .await;
    let error = transport(relay.port, Duration::from_secs(5), Some(("davhaven", "s3cret")))
        .send(&mail(1, "Hi\n"))
        .await
        .unwrap_err();
    assert_eq!(
        error.kind,
        PortErrorKind::Unavailable,
        "the mail waits until the relay or the configuration is fixed: {error}"
    );
    assert_eq!(relay.messages().await.len(), 0, "nothing was delivered");
    let commands = relay.commands().await;
    assert!(!commands.iter().any(|command| command == "MAIL"), "{commands:?}");
    assert!(
        !error.message.contains("s3cret") && !error.message.contains("davhaven"),
        "{error}"
    );
}

#[tokio::test]
async fn the_ehlo_name_is_the_configured_one_and_never_the_name_of_the_machine() {
    let relay = Relay::start(Behaviour::default()).await;
    let mut config = SmtpConfig {
        host: "127.0.0.1".to_owned(),
        port: relay.port,
        tls: SmtpTls::None,
        ..SmtpConfig::default()
    };
    config.ehlo_name = Some("mail.example.org".to_owned());
    let named = SmtpMailTransport::new(&config, None, Arc::new(ManualClock::default())).unwrap();
    named.send(&mail(1, "Hi\n")).await.unwrap();
    config.ehlo_name = None;
    let unnamed = SmtpMailTransport::new(&config, None, Arc::new(ManualClock::default())).unwrap();
    unnamed.send(&mail(2, "Hi\n")).await.unwrap();
    assert_eq!(
        relay.greetings().await,
        vec!["mail.example.org".to_owned(), "localhost".to_owned()]
    );
}

#[tokio::test]
async fn unreachable_and_silent_relays_are_retryable() {
    let reset = Relay::start(Behaviour {
        reset: true,
        ..Behaviour::default()
    })
    .await;
    let refused = transport(reset.port, Duration::from_secs(2), None)
        .send(&mail(1, "Hi\n"))
        .await
        .unwrap_err();
    assert_eq!(refused.kind, PortErrorKind::Unavailable, "{refused}");

    let hanging_up = Relay::start(Behaviour {
        hang_up: true,
        ..Behaviour::default()
    })
    .await;
    let dropped = transport(hanging_up.port, Duration::from_secs(2), None)
        .send(&mail(1, "Hi\n"))
        .await
        .unwrap_err();
    assert!(dropped.kind.is_retryable(), "{dropped}");

    let silent = Relay::start(Behaviour {
        silent: true,
        ..Behaviour::default()
    })
    .await;
    let slow = transport(silent.port, Duration::from_millis(200), None)
        .send(&mail(1, "Hi\n"))
        .await
        .unwrap_err();
    assert_eq!(slow.kind, PortErrorKind::Timeout, "{slow}");
}

#[tokio::test]
async fn a_relay_that_does_not_offer_starttls_never_sees_the_mail_the_login_or_the_envelope() {
    let relay = Relay::start(Behaviour {
        login: Some(("davhaven", "s3cret")),
        ..Behaviour::default()
    })
    .await;
    let config = SmtpConfig {
        host: "127.0.0.1".to_owned(),
        port: relay.port,
        username: Some("davhaven".to_owned()),
        password_file: Some(PathBuf::from("/unused")),
        tls: SmtpTls::Starttls,
        ehlo_name: None,
        timeout: Duration::from_secs(5),
        total_timeout: Duration::from_secs(20),
        allow_insecure_transport: false,
    };
    let password = SecretString::from("s3cret");
    let strict = SmtpMailTransport::new(&config, Some(&password), Arc::new(ManualClock::default())).unwrap();

    let error = strict.send(&mail(1, "Hi\n")).await.unwrap_err();
    assert_eq!(
        error.kind,
        PortErrorKind::Unavailable,
        "an operator fixes the relay or the setting, and the mail waits: {error}"
    );
    assert!(relay.messages().await.is_empty(), "no mail arrived");
    let commands = relay.commands().await;
    for forbidden in ["MAIL", "RCPT", "DATA", "AUTH"] {
        assert!(
            !commands.iter().any(|command| command == forbidden),
            "{forbidden} reached a relay that cannot be reached securely: {commands:?}"
        );
    }
    assert!(
        commands.iter().any(|command| command == "EHLO"),
        "the relay was asked what it offers: {commands:?}"
    );
}

#[tokio::test]
async fn mails_that_cannot_be_assembled_never_reach_the_relay() {
    let relay = Relay::start(Behaviour::default()).await;
    let transport = transport(relay.port, Duration::from_secs(5), None);
    let mut nobody = mail(1, "Hi\n");
    nobody.to.clear();
    assert_eq!(transport.send(&nobody).await.unwrap_err().kind, PortErrorKind::Invalid);
    let mut wrong_method = mail(2, "Hi\n");
    wrong_method.calendar = Some(CalendarPart {
        method: ItipMethod::Request,
        ics: "BEGIN:VCALENDAR\r\nMETHOD:CANCEL\r\nEND:VCALENDAR\r\n".to_owned(),
    });
    assert_eq!(
        transport.send(&wrong_method).await.unwrap_err().kind,
        PortErrorKind::Invalid
    );
    assert_eq!(relay.messages().await.len(), 0);
}

#[tokio::test]
async fn the_adapter_passes_the_mail_contract() {
    let relay = Relay::start(Behaviour::default()).await;
    let port = relay.port;
    davhaven_port_tests::mail::run_all(move || Arc::new(transport(port, Duration::from_secs(5), None))).await;
    assert!(
        !relay.messages().await.is_empty(),
        "the contract delivers mails to the relay"
    );
}
