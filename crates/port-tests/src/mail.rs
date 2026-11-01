//! Contract suite of the `MailTransport` port.
//!
//! What every transport promises: a well-formed mail is accepted and the receipt names its `Message-ID`, sending
//! the same mail again (an outbox retry) is accepted, and a mail that cannot be sent at all, here one without a
//! recipient, is refused with an error instead of being swallowed. The capture transport of the test harness and
//! the SMTP adapter against a test relay run it.

use std::sync::Arc;

use davhaven_domain::{Email, HeaderText, Mailbox, MessageId, OutgoingMail};
use davhaven_ports::MailTransport;

use crate::suite::{Checks, ContractReport, Suite};

fn mailbox(address: &str) -> Option<Mailbox> {
    Email::parse(address).ok().map(Mailbox::bare)
}

/// A well-formed plain-text mail with the `Message-ID` `<contract-{n}@sender.example>` and the given recipients.
pub fn sample_mail(n: u32, recipients: &[&str]) -> Option<OutgoingMail> {
    Some(OutgoingMail {
        message_id: MessageId::parse(&format!("<contract-{n}@sender.example>")).ok()?,
        from: mailbox("noreply@sender.example")?,
        sender: None,
        reply_to: None,
        to: recipients
            .iter()
            .map(|address| mailbox(address))
            .collect::<Option<Vec<_>>>()?,
        subject: HeaderText::parse("Invitation: Planning").ok()?,
        text: "You are invited.\n".to_owned(),
        html: None,
        calendar: None,
        attachments: Vec::new(),
        headers: Vec::new(),
    })
}

/// Runs the suite against transports built by `factory` and returns the report.
pub async fn run<F>(factory: F) -> ContractReport
where
    F: Fn() -> Arc<dyn MailTransport>,
{
    let mut suite = Suite::new("mail");
    let transport = factory();

    let mut checks = Checks::new("a well-formed mail is accepted and receipted");
    match sample_mail(1, &["guest@elsewhere.example"]) {
        Some(mail) => {
            if let Some(receipt) = checks.ok(transport.send(&mail).await, "sending") {
                checks.equal(&receipt.message_id, &mail.message_id, "the Message-ID of the receipt");
            }
        }
        None => checks.fail("the suite could not build a mail"),
    }
    suite.record(checks);

    let mut checks = Checks::new("several recipients are accepted");
    match sample_mail(2, &["a@elsewhere.example", "b@elsewhere.example"]) {
        Some(mail) => {
            checks.ok(transport.send(&mail).await, "sending to two recipients");
        }
        None => checks.fail("the suite could not build a mail"),
    }
    suite.record(checks);

    let mut checks = Checks::new("sending the same mail again is accepted");
    match sample_mail(3, &["guest@elsewhere.example"]) {
        Some(mail) => {
            checks.ok(transport.send(&mail).await, "the first send");
            checks.ok(transport.send(&mail).await, "the retry");
        }
        None => checks.fail("the suite could not build a mail"),
    }
    suite.record(checks);

    let mut checks = Checks::new("a mail without recipient is refused");
    match sample_mail(4, &[]) {
        Some(mail) => {
            checks.err(transport.send(&mail).await, "sending without recipient");
        }
        None => checks.fail("the suite could not build a mail"),
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
    F: Fn() -> Arc<dyn MailTransport>,
{
    run(factory).await.assert_ok();
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use davhaven_ports::{PortError, SendReceipt};

    use super::*;

    /// A transport that validates like the real ones.
    struct Validating;

    #[async_trait]
    impl MailTransport for Validating {
        async fn send(&self, mail: &OutgoingMail) -> Result<SendReceipt, PortError> {
            mail.validate().map_err(|error| PortError::invalid(error.to_string()))?;
            Ok(SendReceipt {
                message_id: mail.message_id.clone(),
                transport_id: Some("queued".to_owned()),
            })
        }
    }

    /// A transport that accepts everything and makes up a receipt.
    struct Swallowing;

    #[async_trait]
    impl MailTransport for Swallowing {
        async fn send(&self, _mail: &OutgoingMail) -> Result<SendReceipt, PortError> {
            Ok(SendReceipt {
                message_id: MessageId::parse("<other@sender.example>")
                    .map_err(|e| PortError::invalid(e.to_string()))?,
                transport_id: None,
            })
        }
    }

    #[test]
    fn the_sample_mail_is_valid() {
        let mail = sample_mail(7, &["guest@elsewhere.example"]).unwrap();
        assert!(mail.validate().is_ok());
        assert_eq!(mail.message_id.as_str(), "<contract-7@sender.example>");
        assert!(sample_mail(7, &[]).unwrap().validate().is_err());
        assert!(sample_mail(7, &["not an address"]).is_none());
    }

    #[tokio::test]
    async fn a_validating_transport_satisfies_the_contract() {
        run_all(|| Arc::new(Validating)).await;
        assert_eq!(run(|| Arc::new(Validating)).await.case_count(), 4);
    }

    #[tokio::test]
    async fn a_transport_that_swallows_everything_is_caught() {
        let report = run(|| Arc::new(Swallowing)).await;
        let failed = report.failed_cases();
        assert!(
            failed.contains(&"a well-formed mail is accepted and receipted"),
            "{report}"
        );
        assert!(failed.contains(&"a mail without recipient is refused"), "{report}");
    }
}
