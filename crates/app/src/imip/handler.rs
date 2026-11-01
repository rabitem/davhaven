//! The `imip` outbox handler: turns an [`ImipJob`] into a mail and hands it to the transport.
//!
//! The outbox holds references only (object id, recipient, method, locale, template). At dispatch time the handler
//!
//! 1. loads the tenant and the object (or takes the snapshot of the job),
//! 2. asks the calendar backend for the iTIP message and the event it is about,
//! 3. resolves the people (organizer, attendee, the sender behind "via"), mints the RSVP link of an invitation,
//! 4. renders the template with the model of [`model`](super::model),
//! 5. composes the [`OutgoingMail`] (`Content-Class`, `Auto-Submitted`, the `text/calendar` alternative and the
//!    `invite.ics` attachment), applies the staging rules and the safety rails, and sends it.
//!
//! Everything but the send is deterministic for a record, so a retry produces the same mail: the `Message-ID` is
//! derived from the outbox id and the RSVP link from the key ring.
//!
//! # What a job is about
//!
//! * `REQUEST` is about the stored object: it needs the object for the RSVP link, so an invitation whose object was
//!   deleted before dispatch is dropped. A snapshot, when the job has one, is the text the mail is built from.
//!   Outbox records are not ordered, so before a link is minted the invitation is checked against the object as it
//!   is now: a recipient who is no longer an attendee gets no invitation (the cancellation that removed them is
//!   queued on its own), and an invitation older than the object (its `SEQUENCE` is lower) is dropped in favor of the
//!   newer one that is queued behind it.
//! * `CANCEL` is built from its snapshot and survives the deletion of the object.
//! * `REPLY` is built from its snapshot (the attendee's copy as it was when the attendee answered, which is gone
//!   when the answer is the deletion of the copy) or, without one, from the stored object. The answering attendee
//!   is named by the job (`replying_attendee`), never derived from the stored object, so the answer of a deleted
//!   copy still reaches the organizer.
//!
//! # Outcomes
//!
//! * sent, or dropped on purpose (object deleted before dispatch, staging allow list): the record is done;
//! * the relay or the network failed: `Retryable`;
//! * the rate limit or the breaker holds the mail back: the record is *deferred*, which neither counts as an
//!   attempt nor fails anything (a hold older than a week stops deferring and fails like a relay error);
//! * the relay refused the mail, the data or the tenant configuration cannot produce a mail: `Permanent`.
//!
//! The error texts are static: they end up in `outbox.last_error`, which must not carry addresses or relay output.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::{
    CalendarPart, CalendarUserAddress, DomainName, Email, ExtraHeader, HeaderName, HeaderText, ItipMethod,
    MailAttachment, Mailbox, MediaType, MessageId, OutgoingMail, PartStat, Tenant,
};
use davhaven_ports::{
    HandlerError, ImipJob, OutboxDecodeError, OutboxHandler, OutboxMessage, OutboxRecord, PortError, PortErrorKind,
    RenderRequest, Rendered, StoreError, Tx, TxMode, outbox::kind,
};
use secrecy::ExposeSecret;

use super::backend::{BackendError, CalendarBackend, IcalBackend, MessageRequest, Prepared};
use super::guard::{Gate, MailGuard, recipient_allowed};
use super::model::{self, MailModel, Person, Reply};
use super::rsvp;
use crate::config::{MailConfig, MailFromMode, OutboxConfig};
use crate::wiring::AppCore;

/// The counter of mails the transport accepted, labelled with the method.
pub const SENT_TOTAL: &str = "davhaven_mail_sent_total";
/// The counter of mails that were not sent because of a failure, labelled with the reason.
pub const FAILED_TOTAL: &str = "davhaven_mail_failed_total";
/// The counter of mails that were dropped on purpose, labelled with the reason.
pub const DROPPED_TOTAL: &str = "davhaven_mail_dropped_total";
/// The counter of mails the rate limit or the circuit breaker held back (not failures), labelled with the reason.
pub const HELD_TOTAL: &str = "davhaven_mail_held_total";
/// The counter of replies that went out in the service form (`From` is the tenant's address, `Reply-To` the
/// attendee) because the attendee's own address is not in the sender domain: receivers that expect the sender of a
/// `REPLY` to be the attendee (RFC 6047) may not apply them. `docs/interop.md` explains what to do about it.
pub const REPLY_SERVICE_FORM_TOTAL: &str = "davhaven_mail_reply_service_form_total";

/// The header that tells a tester whom a redirected mail was meant for (`mail.redirect_all_to`).
pub const REDIRECTED_FROM_HEADER: &str = "X-Davhaven-Redirected-From";

/// The longest display name or subject the composer puts into a header, in characters.
const MAX_HEADER_CHARS: usize = 200;

/// The longest name of a person or of the tenant in the "{person} via {tenant}" sender name, in characters.
const MAX_NAME_CHARS: usize = 80;

/// How long a mail may be held back by the rate limit or the breaker before holds count as failures.
const MAX_HOLD_AGE: chrono::Duration = chrono::Duration::days(7);

/// The share of the outbox lease that one send may take: the dispatcher cancels a handler after 80 % of the lease,
/// so the send has to end earlier and report its own timeout (which counts towards the circuit breaker).
const SEND_BUDGET_SHARE: f64 = 0.6;

/// The most time one send to the relay may take. The SMTP transport bounds its own conversation
/// (`plugin.smtp.total_timeout`), which has to stay below this; the handler enforces it for transports that do not.
pub fn send_budget(outbox: &OutboxConfig) -> Duration {
    outbox.lease.mul_f64(SEND_BUDGET_SHARE)
}

/// What became of a job that did not fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disposition {
    Sent,
    Dropped(&'static str),
}

/// Why a job did not finish: a label for the metric and the error the outbox sees.
#[derive(Debug)]
struct Refusal {
    reason: &'static str,
    error: HandlerError,
    /// The job is about something that is gone: the record is done, not failed.
    gone: bool,
}

fn permanent(reason: &'static str, text: &'static str) -> Refusal {
    Refusal {
        reason,
        error: HandlerError::permanent(text),
        gone: false,
    }
}

fn transient(reason: &'static str, text: &'static str) -> Refusal {
    Refusal {
        reason,
        error: HandlerError::retryable(text),
        gone: false,
    }
}

fn held(reason: &'static str, text: &'static str, after: Duration) -> Refusal {
    Refusal {
        reason,
        error: HandlerError::defer(after, text),
        gone: false,
    }
}

/// The job is about something that is gone; the record is done and counted as dropped for `reason`.
fn gone(reason: &'static str) -> Refusal {
    Refusal {
        reason,
        error: HandlerError::permanent("the message is about something that no longer exists"),
        gone: true,
    }
}

/// Ends the transaction of a job that turned out to be about something gone: it wrote nothing, and what it read is
/// committed, because [`gone`] is no failure (the record is done and counted as dropped).
async fn gone_after(tx: Box<dyn Tx>, reason: &'static str) -> Result<Identities, Refusal> {
    tx.commit().await?;
    Err(gone(reason))
}

impl From<StoreError> for Refusal {
    fn from(error: StoreError) -> Self {
        Self {
            reason: "store",
            error: HandlerError::from(error),
            gone: false,
        }
    }
}

impl From<BackendError> for Refusal {
    fn from(error: BackendError) -> Self {
        match error {
            BackendError::Invalid(_) => permanent("calendar", "the calendar data cannot be turned into a message"),
            BackendError::Unavailable(_) => transient("calendar", "the calendar layer is not available"),
        }
    }
}

/// The label of a method for metrics.
const fn method_label(method: ItipMethod) -> &'static str {
    match method {
        ItipMethod::Request => "request",
        ItipMethod::Cancel => "cancel",
        ItipMethod::Reply => "reply",
        _ => "other",
    }
}

/// Header text without control characters, cut to a sensible length.
fn header_text(text: &str) -> Result<HeaderText, Refusal> {
    let cleaned: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_HEADER_CHARS)
        .collect();
    HeaderText::parse(cleaned.trim()).map_err(|_| permanent("compose", "the mail cannot be composed"))
}

/// A mailbox for `email` with the display `name`, when there is one.
fn mailbox(name: Option<&str>, email: Email) -> Result<Mailbox, Refusal> {
    match name.map(str::trim).filter(|name| !name.is_empty()) {
        Some(name) => Ok(Mailbox::named(header_text(name)?, email)),
        None => Ok(Mailbox::bare(email)),
    }
}

fn extra_header(name: &str, value: &str) -> Result<ExtraHeader, Refusal> {
    Ok(ExtraHeader {
        name: HeaderName::parse(name).map_err(|_| permanent("compose", "the mail cannot be composed"))?,
        value: header_text(value)?,
    })
}

/// What the first transaction reads.
struct Loaded {
    tenant: Tenant,
    object: Option<davhaven_domain::StoredObject>,
}

/// The people of a mail and the pieces that depend on them.
struct Identities {
    organizer: Person,
    attendee: Person,
    reply: Option<Reply>,
    rsvp_url: Option<String>,
}

/// The `imip` handler.
pub struct ImipHandler {
    core: AppCore,
    backend: Arc<dyn CalendarBackend>,
    guard: MailGuard,
}

impl core::fmt::Debug for ImipHandler {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ImipHandler").finish_non_exhaustive()
    }
}

impl ImipHandler {
    /// Creates the handler with the iCalendar layer of the application.
    pub fn new(core: AppCore) -> Self {
        let backend = IcalBackend::new(core.deps().limits.ical.clone());
        Self::with_backend(core, Arc::new(backend))
    }

    /// Creates the handler with another calendar backend (tests).
    pub fn with_backend(core: AppCore, backend: Arc<dyn CalendarBackend>) -> Self {
        Self {
            core,
            backend,
            guard: MailGuard::default(),
        }
    }

    /// The tenant and the object, which is `None` once it was deleted. A tenant that is gone is `NotFound`: that
    /// error is the tenant's and nothing else's, because a missing object is a normal answer here.
    async fn load(&self, record: &OutboxRecord, job: &ImipJob) -> Result<Loaded, StoreError> {
        let mut tx = self
            .core
            .deps()
            .database
            .begin(record.tenant_id, TxMode::ReadOnly)
            .await?;
        let tenant = tx.tenant().get().await?;
        let object = match tx.objects().get_by_id(job.object).await {
            Ok(object) => Some(object),
            Err(StoreError::NotFound) => None,
            Err(error) => return Err(error),
        };
        tx.commit().await?;
        Ok(Loaded { tenant, object })
    }

    /// Resolves the people of the mail and, for an invitation, mints (or finds) the RSVP link.
    async fn identities(
        &self,
        record: &OutboxRecord,
        job: &ImipJob,
        loaded: &Loaded,
        prepared: &Prepared,
    ) -> Result<Identities, Refusal> {
        let mode = if job.method == ItipMethod::Request {
            TxMode::ReadWrite
        } else {
            TxMode::ReadOnly
        };
        let mut tx = self.core.deps().database.begin(record.tenant_id, mode).await?;
        let event = &prepared.event;
        let invited = event
            .organizer
            .as_ref()
            .ok_or_else(|| permanent("no_organizer", "the event has no organizer"))?;
        let organizer = person(tx.as_mut(), &invited.address, invited.common_name.as_deref()).await?;
        let (attendee, reply) = if job.method == ItipMethod::Reply {
            let answering = job
                .replying_attendee
                .as_ref()
                .ok_or_else(|| permanent("no_replying_attendee", "the reply names no answering attendee"))?;
            let listed = event
                .attendees
                .as_ref()
                .and_then(|list| list.iter().find(|attendee| &attendee.address == answering));
            let partstat = listed
                .and_then(|attendee| attendee.partstat)
                .filter(|partstat| *partstat != PartStat::NeedsAction)
                .ok_or_else(|| permanent("no_answer", "the reply carries no answer of the attendee"))?;
            let attendee = person(tx.as_mut(), answering, listed.and_then(|a| a.common_name.as_deref())).await?;
            (attendee, Some(Reply::new(partstat.as_ical(), job.comment.as_deref())))
        } else {
            let listed = event
                .attendees
                .as_ref()
                .and_then(|list| list.iter().find(|attendee| attendee.address == job.recipient));
            let name = listed
                .and_then(|attendee| attendee.common_name.as_deref())
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned);
            let email = job.recipient.email().map(|email| email.to_string());
            (Person { name, email }, None)
        };
        let rsvp_url = if job.method == ItipMethod::Request {
            let Some(object) = loaded.object.as_ref() else {
                return gone_after(tx, "object_gone").await;
            };
            let attendees = match tx.objects().attendees(object.id).await {
                Ok(attendees) => attendees,
                Err(StoreError::NotFound) => return gone_after(tx, "object_gone").await,
                Err(error) => return Err(error.into()),
            };
            if !attendees.iter().any(|attendee| attendee.address == job.recipient) {
                return gone_after(tx, "recipient_removed").await;
            }
            if prepared
                .event
                .sequence
                .is_some_and(|sequence| sequence < object.sequence)
            {
                return gone_after(tx, "superseded").await;
            }
            let token = match rsvp::link_token(&self.core, tx.as_mut(), object, &job.recipient).await {
                Ok(token) => token,
                // The object was deleted between the two transactions.
                Err(StoreError::NotFound) => return gone_after(tx, "object_gone").await,
                Err(error) => return Err(error.into()),
            };
            let urls = self.core.deps().urls.for_tenant(&loaded.tenant.settings);
            Some(urls.rsvp_url(token.expose_secret()).to_string())
        } else {
            None
        };
        tx.commit().await?;
        Ok(Identities {
            organizer,
            attendee,
            reply,
            rsvp_url,
        })
    }

    /// Everything but the send: the mail, or why there is none.
    async fn compose(&self, record: &OutboxRecord, job: &ImipJob) -> Result<Composed, Refusal> {
        let deps = self.core.deps();
        let recipient = job
            .recipient
            .email()
            .ok_or_else(|| permanent("no_recipient", "the recipient has no e-mail address"))?;
        if !recipient_allowed(&deps.config.mail, &recipient) {
            return Ok(Composed::Dropped("recipient_domain"));
        }
        let loaded = match self.load(record, job).await {
            Ok(loaded) => loaded,
            Err(StoreError::NotFound) => return Ok(Composed::Dropped("tenant_gone")),
            Err(error) => return Err(error.into()),
        };
        let Some(source) = source_of(job, &loaded) else {
            return Ok(Composed::Dropped("object_gone"));
        };
        // The tenant without a sender domain gets no mail, and is told so before anything is built.
        let (sender_address, sender_domain) = sender_identity(&loaded)?;
        let prepared = self
            .backend
            .prepare(
                &source,
                &MessageRequest {
                    method: job.method,
                    recipient: job.recipient.clone(),
                    replying_attendee: job.replying_attendee.clone(),
                    comment: model::clean_comment(job.comment.as_deref()),
                    dtstamp: record.created_at,
                    // An organizer without an e-mail address (a service account) is named by the address the mail comes
                    // from in a `REQUEST` or `CANCEL`: an `urn:uuid` means nothing to the mail client of a guest. A `REPLY`
                    // names the attendee who answers, whose address is a mail address.
                    stand_in_organizer: (job.method != ItipMethod::Reply)
                        .then(|| CalendarUserAddress::mailto(&sender_address)),
                },
            )
            .await?;
        let identities = self.identities(record, job, &loaded, &prepared).await?;
        // The person on whose behalf the mail is sent: the organizer, or the attendee who answers.
        let behalf = if job.method == ItipMethod::Reply {
            &identities.attendee
        } else {
            &identities.organizer
        };
        let senders = senders(
            &deps.config.mail,
            behalf,
            &tenant_name(&loaded),
            &sender_address,
            sender_domain,
        )?;
        let reply_to = senders.reachable_at();
        let rendered = self
            .render(job, &loaded, &identities, &prepared, reply_to.as_deref())
            .await?;
        let mail = build_mail(
            &self.core,
            Parts {
                record,
                job,
                identities: &identities,
                rendered,
                ics: prepared.ics,
                recipient,
                senders,
                sender_domain,
            },
        )?;
        Ok(Composed::Mail(Box::new(mail)))
    }

    /// Renders the template of the job with the model of the mail.
    async fn render(
        &self,
        job: &ImipJob,
        loaded: &Loaded,
        identities: &Identities,
        prepared: &Prepared,
        reply_to: Option<&str>,
    ) -> Result<Rendered, Refusal> {
        let settings = &loaded.tenant.settings;
        let event = model::event_model(&prepared.event, settings.timezone)
            .map_err(|_| permanent("no_start", "the event has no start"))?;
        let tenant_name = tenant_name(loaded);
        // Whether this mail updates an invitation sent earlier is a property of the version the mail is built
        // from, not of whatever is stored now: an old invitation that is still queued says what it said.
        let update = job.method == ItipMethod::Request && prepared.event.sequence.is_some_and(|sequence| sequence > 0);
        let template_model = MailModel {
            tenant: &tenant_name,
            organizer: &identities.organizer,
            attendee: &identities.attendee,
            event,
            update,
            rsvp_url: identities.rsvp_url.as_deref(),
            reply: identities.reply.as_ref(),
            reply_to,
        }
        .to_value();
        self.core
            .deps()
            .templates
            .render(RenderRequest {
                template: job.template.clone(),
                locale: job.locale.clone().unwrap_or_else(|| settings.locale.clone()),
                theme: settings.theme_name().to_owned(),
                model: template_model,
            })
            .await
            .map_err(|error| match error.kind {
                PortErrorKind::Invalid | PortErrorKind::Rejected | PortErrorKind::Unsupported => {
                    permanent("template", "the template could not be rendered")
                }
                PortErrorKind::Unavailable | PortErrorKind::Timeout | PortErrorKind::Internal => {
                    transient("template", "the template renderer is not available")
                }
            })
    }

    /// Sends the mail through the rate limit and the breaker.
    ///
    /// A mail that the rate limit or the open breaker holds back is deferred, not failed: nothing was tried, and
    /// the outbox must not count the hold against `outbox.max_attempts`.
    async fn transmit(&self, record: &OutboxRecord, mail: &OutgoingMail) -> Result<(), Refusal> {
        let deps = self.core.deps();
        let now = deps.clock.now();
        let may_defer = now - record.created_at < MAX_HOLD_AGE;
        match self
            .guard
            .admit(now, &deps.config.mail, deps.rate_limiter.as_ref())
            .await
        {
            Gate::Go => {}
            Gate::RateLimited { retry_after } if may_defer => {
                return Err(held(
                    "rate_limited",
                    "the mail rate limit holds the mail back",
                    retry_after,
                ));
            }
            Gate::BreakerOpen { retry_after } if may_defer => {
                return Err(held("breaker_open", "the mail relay is not answering", retry_after));
            }
            Gate::RateLimited { .. } => return Err(transient("rate_limited", "the mail rate limit is reached")),
            Gate::BreakerOpen { .. } => return Err(transient("breaker_open", "the mail relay is not answering")),
        }
        let budget = send_budget(&deps.config.outbox);
        let sent = match tokio::time::timeout(budget, deps.mail.send(mail)).await {
            Ok(result) => result,
            Err(_elapsed) => Err(PortError::timeout("the send exceeded its budget")),
        };
        match sent {
            Ok(_receipt) => {
                self.guard.reachable().await;
                Ok(())
            }
            Err(error) => Err(self.after_failure(&error, now).await),
        }
    }

    async fn after_failure(&self, error: &PortError, now: DateTime<Utc>) -> Refusal {
        let deps = self.core.deps();
        match error.kind {
            // The relay answered: it works, the mail is the problem.
            PortErrorKind::Rejected => {
                self.guard.reachable().await;
                permanent("rejected", "the mail relay refused the message")
            }
            PortErrorKind::Invalid => permanent("encoding", "the message cannot be encoded"),
            PortErrorKind::Unsupported => permanent("unsupported", "the mail transport cannot send this message"),
            PortErrorKind::Unavailable | PortErrorKind::Timeout | PortErrorKind::Internal => {
                self.guard.failed(now, &deps.config.mail, &deps.config.outbox).await;
                transient("unavailable", "the mail relay is not available")
            }
        }
    }

    async fn deliver(&self, record: &OutboxRecord, job: &ImipJob) -> Result<Disposition, Refusal> {
        let composed = match self.compose(record, job).await {
            Ok(composed) => composed,
            Err(refusal) if refusal.gone => return Ok(Disposition::Dropped(refusal.reason)),
            Err(refusal) => return Err(refusal),
        };
        match composed {
            Composed::Dropped(reason) => Ok(Disposition::Dropped(reason)),
            Composed::Mail(mail) => {
                self.transmit(record, &mail).await?;
                Ok(Disposition::Sent)
            }
        }
    }
}

/// The name shown after "via": the sender name of the tenant, or its display name.
fn tenant_name(loaded: &Loaded) -> String {
    loaded
        .tenant
        .settings
        .sender
        .display_name
        .clone()
        .unwrap_or_else(|| loaded.tenant.display_name.clone())
}

/// The calendar text the mail is built from: the snapshot of the job, or the stored object.
///
/// An invitation is about the stored object (it needs it for the RSVP link) and has nothing to say once it is
/// gone. A reply and a cancellation are built from their snapshot, which they carry because the object they are
/// about may be gone by dispatch time; without a snapshot they fall back to the stored object, and there is
/// nothing to say when that is gone too.
fn source_of(job: &ImipJob, loaded: &Loaded) -> Option<String> {
    if job.method == ItipMethod::Request && loaded.object.is_none() {
        return None;
    }
    match (&job.snapshot, &loaded.object) {
        (Some(snapshot), _) => Some(snapshot.clone()),
        (None, Some(object)) => Some(object.data.clone()),
        (None, None) => None,
    }
}

/// The result of composing a job.
enum Composed {
    Mail(Box<OutgoingMail>),
    Dropped(&'static str),
}

/// The pieces a mail is assembled from.
struct Parts<'a> {
    record: &'a OutboxRecord,
    job: &'a ImipJob,
    identities: &'a Identities,
    rendered: Rendered,
    ics: String,
    recipient: Email,
    senders: Senders,
    sender_domain: &'a DomainName,
}

/// `From`, `Sender` and `Reply-To` of a mail.
struct Senders {
    from: Mailbox,
    sender: Option<Mailbox>,
    reply_to: Option<Mailbox>,
}

impl Senders {
    /// The address a reply to the mail reaches a person at: the `Reply-To`, or the `From` when the mail is sent in the name
    /// of the person (the `Sender` is then the tenant's). `None` for a mail that comes from the tenant's no-reply address
    /// without a `Reply-To`.
    fn reachable_at(&self) -> Option<String> {
        match (&self.reply_to, &self.sender) {
            (Some(reply_to), _) => Some(reply_to.address.to_string()),
            (None, Some(_)) => Some(self.from.address.to_string()),
            (None, None) => None,
        }
    }
}

/// The address and the domain the tenant sends from.
fn sender_identity(loaded: &Loaded) -> Result<(Email, &DomainName), Refusal> {
    let settings = &loaded.tenant.settings;
    match (settings.sender.address(), settings.sender.domain.as_ref()) {
        (Some(address), Some(domain)) => Ok((address, domain)),
        _ => Err(permanent("no_sender", "the tenant has no sender domain")),
    }
}

/// Whether `email` lives in `domain` or one of its subdomains.
fn in_domain(email: &Email, domain: &str) -> bool {
    let host = email.domain();
    host == domain || host.strip_suffix(domain).is_some_and(|rest| rest.ends_with('.'))
}

/// The display name of a mail in the service form: "{person} via {tenant}", or the tenant alone when the person has no
/// name.
///
/// An address is never part of it, whatever the person is called (a display name that looks like an address is what
/// spoofing filters look for), and the pieces are shortened one by one before they are joined, so that a long name
/// can never push the "via" that tells the reader who really sent the mail out of the header.
fn service_name(person: Option<&str>, tenant: &str) -> String {
    let tenant = shortened(tenant, MAX_NAME_CHARS);
    match person
        .map(|name| shortened(name, MAX_NAME_CHARS))
        .filter(|name| !name.is_empty())
    {
        Some(person) => format!("{person} via {tenant}"),
        None => tenant,
    }
}

/// `text` with control characters turned into spaces, trimmed and cut to `max` characters.
fn shortened(text: &str, max: usize) -> String {
    let cleaned: String = text.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    cleaned
        .trim()
        .chars()
        .take(max)
        .collect::<String>()
        .trim_end()
        .to_owned()
}

/// `From`, `Sender` and `Reply-To` by `mail.from_mode`.
///
/// `service`: the sender address of the tenant named "{person} via {tenant}", `Reply-To` the person. `organizer`:
/// the person's own address, `Sender` the address of the tenant; only for people in the sender domain of the
/// tenant, everyone else is sent in the `service` form (the relay would not sign for their domain).
fn senders(
    config: &MailConfig,
    behalf: &Person,
    tenant_name: &str,
    sender_address: &Email,
    sender_domain: &DomainName,
) -> Result<Senders, Refusal> {
    let behalf_email = behalf.email.as_deref().and_then(|text| Email::parse(text).ok());
    match (config.from_mode, behalf_email) {
        (MailFromMode::Organizer, Some(email)) if in_domain(&email, sender_domain.as_str()) => Ok(Senders {
            from: mailbox(behalf.name.as_deref(), email)?,
            sender: Some(Mailbox::bare(sender_address.clone())),
            reply_to: None,
        }),
        (_, email) => {
            let display = service_name(behalf.name.as_deref(), tenant_name);
            Ok(Senders {
                from: Mailbox::named(header_text(&display)?, sender_address.clone()),
                sender: None,
                reply_to: email.map(|email| mailbox(behalf.name.as_deref(), email)).transpose()?,
            })
        }
    }
}

/// Composes the mail: addresses, headers, the alternatives and the attachment; applies `mail.redirect_all_to`.
fn build_mail(core: &AppCore, parts: Parts<'_>) -> Result<OutgoingMail, Refusal> {
    let Parts {
        record,
        job,
        identities,
        rendered,
        ics,
        recipient,
        senders,
        sender_domain,
    } = parts;
    let config = &core.deps().config.mail;
    // The person the mail is addressed to: the attendee, or for a reply the organizer.
    let addressee = if job.method == ItipMethod::Reply {
        &identities.organizer
    } else {
        &identities.attendee
    };
    let Senders { from, sender, reply_to } = senders;
    if job.method == ItipMethod::Reply && sender.is_none() {
        // RFC 6047 section 3: a receiver may only apply a REPLY whose sender is the attendee. The service form
        // cannot satisfy that; count it so that operators see how many replies depend on the receiver's leniency.
        metrics::counter!(REPLY_SERVICE_FORM_TOTAL).increment(1);
    }

    let mut headers = vec![
        extra_header("Content-Class", "urn:content-classes:calendarmessage")?,
        extra_header("Auto-Submitted", "auto-generated")?,
        extra_header("X-Auto-Response-Suppress", "OOF, AutoReply")?,
    ];
    let to = if let Some(redirect) = &config.redirect_all_to {
        headers.push(extra_header(REDIRECTED_FROM_HEADER, recipient.as_str())?);
        Mailbox::bare(redirect.clone())
    } else {
        mailbox(addressee.name.as_deref(), recipient)?
    };
    let mail = OutgoingMail {
        message_id: MessageId::for_outbox(record.id, sender_domain),
        from,
        sender,
        reply_to,
        to: vec![to],
        subject: header_text(&rendered.subject)?,
        text: rendered.text,
        html: Some(rendered.html).filter(|html| !html.trim().is_empty()),
        calendar: Some(CalendarPart {
            method: job.method,
            ics: ics.clone(),
        }),
        attachments: vec![MailAttachment {
            filename: header_text("invite.ics")?,
            content_type: MediaType::parse("application/ics")
                .map_err(|_| permanent("compose", "the mail cannot be composed"))?,
            data: ics.into_bytes(),
        }],
        headers,
    };
    mail.validate()
        .map_err(|_| permanent("compose", "the mail cannot be composed"))?;
    Ok(mail)
}

/// The person behind `address`: the principal when it is one of ours, otherwise what the event says.
async fn person(
    tx: &mut dyn Tx,
    address: &CalendarUserAddress,
    common_name: Option<&str>,
) -> Result<Person, StoreError> {
    let from_event = common_name
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned);
    let own = address.email().map(|email| email.to_string());
    Ok(match tx.principals().find_by_address(address).await? {
        Some(principal) => Person {
            name: Some(principal.display_name)
                .filter(|name| !name.trim().is_empty())
                .or(from_event),
            email: principal.email.map(|email| email.to_string()).or(own),
        },
        None => Person {
            name: from_event,
            email: own,
        },
    })
}

#[async_trait]
impl OutboxHandler for ImipHandler {
    fn kind(&self) -> &'static str {
        kind::IMIP
    }

    async fn handle(&self, record: &OutboxRecord) -> Result<(), HandlerError> {
        let job = match record.message() {
            Ok(OutboxMessage::Imip(job)) => job,
            Ok(other) => {
                return Err(HandlerError::permanent(format!(
                    "the record holds a `{}` message, not a mail",
                    other.kind()
                )));
            }
            Err(OutboxDecodeError::UnsupportedVersion { .. }) => {
                return Err(HandlerError::retryable("the payload was written by a newer version"));
            }
            Err(OutboxDecodeError::UnknownKind(_)) => {
                return Err(HandlerError::permanent("the record is not a message this build knows"));
            }
            Err(_) => return Err(HandlerError::permanent("the payload of the record cannot be decoded")),
        };
        match self.deliver(record, &job).await {
            Ok(Disposition::Sent) => {
                metrics::counter!(SENT_TOTAL, "method" => method_label(job.method)).increment(1);
                tracing::info!(outbox = %record.id, tenant = %record.tenant_id, method = method_label(job.method), "mail sent");
                Ok(())
            }
            Ok(Disposition::Dropped(reason)) => {
                metrics::counter!(DROPPED_TOTAL, "reason" => reason).increment(1);
                tracing::info!(outbox = %record.id, tenant = %record.tenant_id, reason, "mail dropped");
                Ok(())
            }
            Err(refusal) if refusal.error.is_deferred() => {
                metrics::counter!(HELD_TOTAL, "reason" => refusal.reason).increment(1);
                tracing::debug!(outbox = %record.id, tenant = %record.tenant_id, reason = refusal.reason, "mail held back");
                Err(refusal.error)
            }
            Err(refusal) => {
                metrics::counter!(FAILED_TOTAL, "reason" => refusal.reason).increment(1);
                tracing::warn!(
                    outbox = %record.id, tenant = %record.tenant_id, reason = refusal.reason,
                    retryable = refusal.error.is_retryable(), "mail not sent"
                );
                Err(refusal.error)
            }
        }
    }
}

#[cfg(test)]
mod tests;
