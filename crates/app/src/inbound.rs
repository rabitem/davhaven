//! Inbound iTIP: answers (and, when the tenant allows it, invitations and cancellations) that a mail gateway forwards
//! to `POST /api/v1/tenants/{tenant}/itip/inbound` (PLAN 2.8).
//!
//! A reply that an attendee sent from a mail client (the buttons of Gmail or Outlook) reaches the organizer's
//! mailbox, not the server. A gateway that receives such mail can forward the `text/calendar` part here, and the
//! server then treats it like any other answer. Because anybody can write mail, the endpoint is **off by default**
//! (`scheduling.inbound_itip.enabled`) and everything it does is checked:
//!
//! | Check | When it fails |
//! | --- | --- |
//! | the caller holds `itip:inbound` | `403` |
//! | the endpoint is enabled | `409` `feature-not-enabled` |
//! | the sender and the gateway are within their rate limits (a limiter that does not answer refuses too) | `429`, `503` |
//! | the message is a valid iTIP message (structure and limits as for a stored object) | `422` |
//! | the message was not seen before (its `Message-ID`) | `200` `duplicate` |
//! | the gateway verified the sender (`dmarc: pass`, unless `require_dmarc_pass` is off) | quarantine `dmarc_not_passed` |
//! | the `METHOD` is one the endpoint takes (`REPLY`, `REQUEST`, `CANCEL`) and the tenant enabled it (`reply` unless it enables `request` or `cancel`) | quarantine `method_not_supported`, `method_not_enabled` |
//! | `From` is the replying `ATTENDEE` (or, for an invitation, the `ORGANIZER`) | quarantine `sender_mismatch` |
//! | a reply is not for an attendee of the tenant (they answer in their calendar, not by mail) | quarantine `internal_attendee` |
//! | the message is about an event and has what it needs (a reply: one organizer and one attendee; an invitation: a `UID` and an `ORGANIZER`) | quarantine `unsupported_component`, `invalid_reply`, `invalid_message` |
//! | the `UID` names an organizer object of the tenant and the attendee is on it | quarantine `unknown_event`, `unknown_attendee` |
//! | the `SEQUENCE` of the reply is the one of the organizer's copy | quarantine `sequence_mismatch` |
//! | an invitation does not claim an organizer of the tenant, names somebody in the tenant, and no scanner refuses its attachments | quarantine `organizer_is_internal`, `no_internal_recipient`, `content_rejected` |
//!
//! A message that fails a check is **quarantined**, not applied: one copy of it is kept in the scheduling inbox of the
//! person it was meant for (flagged, never shown to clients; a message that names nobody in the tenant is not kept
//! at all, there is nobody it was meant for), `scheduling.reply_rejected` is emitted for replies and the audit log
//! records the rejection. The answer to the gateway is `200` with `outcome: quarantined` and the reason, so a gateway
//! does not retry what will never be applied. The reasons are `QuarantineReason`; `docs/interop.md` lists them.
//!
//! Messages are **deduplicated on the `Message-ID`**: the first time a message is dealt with (applied or quarantined,
//! whether anything was kept or not) the server records the `Message-ID` of the gateway as an idempotency key of the
//! calling token, in the transaction that deals with it; a second delivery finds it and answers `duplicate` without
//! doing anything, so a retry of a quarantined message emits no second event and writes no second audit record.
//!
//! Replies go through the `ItipProcessor` like every other answer. Invitations and cancellations from an
//! organizer outside the tenant are delivered to the attendees of the tenant through the same processor that
//! delivers an internal organizer's messages: into the scheduling inbox and, for invitations, as a copy by policy
//! (without the alarms of the sender, and after the content scanners looked at its attachments). An organizer is
//! never somebody the tenant knows: a message that claims an organizer of the tenant is quarantined
//! (`organizer_is_internal`), because mail does not authenticate them.

mod reason;

use std::fmt::Write as _;
use std::time::Duration;

use chrono::TimeDelta;
use davhaven_domain::audit::InboundItipAudit;
use davhaven_domain::events::SchedulingReplyPayload;
use davhaven_domain::{
    AdminOperation, AuditEvent, CalendarId, CalendarUserAddress, CuType, EventData, EventPayload, EventType, InboxItem,
    InboxItemId, ItipMethod, MediaType, ObjectId, ObjectUri, Principal, PrincipalId, PrincipalStatus, RequestContext,
    Tenant, TokenId, Uid,
};
use davhaven_ical::ErrorContext;
use davhaven_ical::itip::{ItipMessage, inline_attachments, parse_message, strip_alarms};
use davhaven_ports::{
    IdempotencyClaim, IdempotencyRecord, IdempotencyStatus, KeyPurpose, RateKey, ScanContext, ScanVerdict, StoreError,
    Tx, TxMode,
};
use davhaven_wire::{AuthVerdict, InboundItipRequest, InboundItipResponse, InboundOutcome};
use sha2::{Digest, Sha256};

pub(crate) use reason::QuarantineReason;

use crate::addresses::{Class, Directory};
use crate::audit::Journal;
use crate::authz::{admin, blocking, field_error, found, retrying};
use crate::error::{AppError, AppResult};
use crate::itip::{
    CopyOp, DeliveryScope, InternalDelivery, ItipProcessor, Notify, ReplyError, ReplyInput, organizer_copy,
    principal_of, wants_copy,
};
use crate::objects::prepare::etag_of;
use crate::wiring::AppCore;

/// The rate limit bucket of inbound messages, keyed by sender.
const RATE_BUCKET: &str = "itip_inbound";

/// The rate limit bucket of inbound messages, keyed by the gateway (the token that forwards them). The sender of a
/// mail is unauthenticated, so a limit per sender alone is dodged by varying `From`.
const RATE_BUCKET_GATEWAY: &str = "itip_inbound_gateway";

/// How long a sender that is over the limit is asked to wait when the limiter does not say.
const DEFAULT_WAIT: Duration = Duration::from_secs(60);

/// The longest `Message-ID` accepted, in characters (RFC 5322 limits a line to 998 octets).
const MAX_MESSAGE_ID_CHARS: usize = 998;

/// How long the `Message-ID` of a message that was dealt with is remembered.
const DEDUPLICATION_WINDOW: TimeDelta = TimeDelta::hours(24);

/// The inbound iTIP use case (see the module documentation).
#[derive(Debug, Clone)]
pub struct InboundService {
    core: AppCore,
    processor: ItipProcessor,
}

/// What an attempt decided.
#[derive(Debug)]
enum Verdict {
    /// The message was applied.
    Applied,
    /// A message with this `Message-ID` was dealt with before.
    Duplicate,
    /// The message is not applied: the reason and whom the quarantined copy is kept for.
    Quarantine {
        reason: QuarantineReason,
        /// The object the message was about, when it matched one.
        object: Option<(CalendarId, ObjectId)>,
        /// The people the message was meant for: the first of them keeps the one quarantined copy.
        keep_for: Vec<PrincipalId>,
    },
}

impl Verdict {
    fn quarantine(reason: QuarantineReason, keep_for: Vec<PrincipalId>) -> Self {
        Self::Quarantine {
            reason,
            object: None,
            keep_for,
        }
    }
}

/// What one attempt works on: the caller, the tenant, the mail the gateway forwarded, the iTIP message in it, what the
/// message says about the event and the name of its inbox item.
#[derive(Debug, Clone, Copy)]
struct Incoming<'a> {
    ctx: &'a RequestContext,
    tenant: &'a Tenant,
    request: &'a InboundItipRequest,
    message: &'a ItipMessage,
    data: Option<&'a EventData>,
    name: &'a ObjectUri,
}

/// What an invitation or a cancellation says about the event, and whom it names.
struct EventOfMessage<'a> {
    uid: &'a Uid,
    organizer: &'a CalendarUserAddress,
    wanted: &'a [CalendarUserAddress],
    directory: &'a Directory,
}

/// `bytes` as lower-case hexadecimal.
fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing into a `String` cannot fail.
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// The first 16 octets of the digest of `message_id` in its own domain, as hexadecimal.
fn digest_of(message_id: &str) -> String {
    let digest = Sha256::digest(format!("davhaven/itip-inbound/v1/{message_id}").as_bytes());
    hex(digest.get(..16).unwrap_or_default())
}

/// The name of the inbox item of a message: derived from its `Message-ID`.
fn item_name(message_id: &str) -> Result<ObjectUri, AppError> {
    ObjectUri::parse(&format!("inbound-{}.ics", digest_of(message_id))).map_err(AppError::internal)
}

/// The idempotency key under which a message is remembered as dealt with.
fn dedup_key(message_id: &str) -> String {
    format!("itip-inbound/{}", digest_of(message_id))
}

/// The master component of a message as the JSON event model: the identity, the organizer, the attendees.
fn describe(message: &ItipMessage) -> Option<EventData> {
    davhaven_ical::merge::to_event_data(&message.calendar, None).ok()
}

impl InboundService {
    /// Creates the service on the shared application core.
    pub fn new(core: AppCore) -> Self {
        Self {
            processor: ItipProcessor::new(core.clone()),
            core,
        }
    }

    /// Applies or quarantines a message a gateway forwarded.
    ///
    /// # Errors
    ///
    /// `Forbidden` without `itip:inbound`, `Conflict` (`feature-not-enabled`) while the endpoint is off, `Invalid`
    /// for a message that is not valid iTIP or an unusable `Message-ID`, `RateLimited` per sender and per gateway,
    /// `Unavailable` when the limiter or a content scanner does not answer.
    pub(crate) async fn receive(
        &self,
        ctx: &RequestContext,
        request: InboundItipRequest,
    ) -> AppResult<InboundItipResponse> {
        admin(ctx, AdminOperation::InboundItip)?;
        let deps = self.core.deps();
        if !deps.config.scheduling.inbound_itip.enabled {
            return Err(AppError::feature_not_enabled());
        }
        let message_id = request.message_id.trim();
        if message_id.is_empty()
            || message_id.chars().count() > MAX_MESSAGE_ID_CHARS
            || message_id.chars().any(char::is_control)
        {
            return Err(field_error("/message_id", "invalid", "The Message-ID is not usable."));
        }
        self.within_rate(ctx, &request).await?;
        let text = request.ical.clone();
        let message = blocking(&self.core, ErrorContext::Scheduling, move |limits| {
            parse_message(text.as_bytes(), limits)
        })
        .await?;
        let name = item_name(message_id)?;
        let key = dedup_key(message_id);
        let verdict = retrying(false, || self.attempt(ctx, &request, &message, &name, &key)).await?;
        Ok(match verdict {
            Verdict::Applied => InboundItipResponse {
                outcome: InboundOutcome::Applied,
                reason: None,
            },
            Verdict::Duplicate => InboundItipResponse {
                outcome: InboundOutcome::Duplicate,
                reason: None,
            },
            Verdict::Quarantine { reason, .. } => InboundItipResponse {
                outcome: InboundOutcome::Quarantined,
                reason: Some(reason.as_str().to_owned()),
            },
        })
    }

    /// Charges the message against the per-sender limit and the limit of the gateway that forwards it.
    async fn within_rate(&self, ctx: &RequestContext, request: &InboundItipRequest) -> AppResult<()> {
        self.charge(RATE_BUCKET, &format!("{}/{}", ctx.tenant, request.from))
            .await?;
        let gateway = ctx.actor.token().map_or_else(String::new, |token| token.to_string());
        self.charge(RATE_BUCKET_GATEWAY, &format!("{}/{gateway}", ctx.tenant))
            .await
    }

    /// Charges one message against a bucket. A limiter that does not answer refuses the message: this endpoint is
    /// reached by mail from anybody, and it must not be open while the thing that protects it is down.
    async fn charge(&self, bucket: &'static str, identity: &str) -> AppResult<()> {
        let deps = self.core.deps();
        let mac = deps
            .keyring
            .sign(
                KeyPurpose::CacheKey,
                format!("davhaven/itip-inbound-limit/v1/{bucket}/{identity}").as_bytes(),
            )
            .mac;
        let key = hex(mac.get(..16).unwrap_or_default());
        match deps.rate_limiter.check(&RateKey::new(bucket, key), 1).await {
            Ok(decision) if !decision.allowed => {
                Err(AppError::rate_limited(decision.retry_after.unwrap_or(DEFAULT_WAIT)))
            }
            Ok(_) => Ok(()),
            Err(error) => {
                tracing::warn!(kind = error.kind.as_str(), "the inbound iTIP limiter did not answer");
                Err(AppError::unavailable())
            }
        }
    }

    /// Remembers the message as dealt with. Answers `false` when it was remembered before.
    async fn claim(&self, tx: &mut dyn Tx, token: TokenId, key: &str) -> AppResult<bool> {
        let record = IdempotencyRecord {
            token_id: token,
            key: key.to_owned(),
            method: "POST".to_owned(),
            path: "/itip/inbound".to_owned(),
            fingerprint: key.to_owned(),
            status: IdempotencyStatus::InFlight,
            response_status: None,
            response: None,
            expires_at: self.core.deps().clock.now() + DEDUPLICATION_WINDOW,
        };
        Ok(matches!(
            tx.idempotency().claim(record).await?,
            IdempotencyClaim::Claimed
        ))
    }

    /// One attempt in one transaction: decides and, whatever the verdict, records it.
    async fn attempt(
        &self,
        ctx: &RequestContext,
        request: &InboundItipRequest,
        message: &ItipMessage,
        name: &ObjectUri,
        key: &str,
    ) -> AppResult<Verdict> {
        let deps = self.core.deps();
        let journal = Journal::new(&self.core, ctx);
        let mut tx = deps.database.begin(ctx.tenant, TxMode::ReadWrite).await?;
        let token = ctx.actor.token();
        if let Some(token) = token
            && !self.claim(tx.as_mut(), token, key).await?
        {
            tx.commit().await?;
            return Ok(Verdict::Duplicate);
        }
        let tenant = tx.tenant().get().await?;
        let data = describe(message);
        let incoming = Incoming {
            ctx,
            tenant: &tenant,
            request,
            message,
            data: data.as_ref(),
            name,
        };
        let verdict = match message.method {
            ItipMethod::Reply => self.reply(tx.as_mut(), &incoming).await,
            ItipMethod::Request | ItipMethod::Cancel => self.invitation(tx.as_mut(), &incoming).await,
            _ => Ok(Verdict::quarantine(QuarantineReason::MethodNotSupported, Vec::new())),
        }?;
        match &verdict {
            // The inbox holds the message already (it came through the token of another gateway, or its key ran out): the
            // key is completed like for every other verdict, so that the next delivery is answered from the key.
            Verdict::Duplicate => {}
            Verdict::Applied => {
                journal
                    .audit(
                        tx.as_mut(),
                        AuditEvent::InboundItipAccepted(InboundItipAudit {
                            method: Some(message.method),
                            object: None,
                            reason: None,
                        }),
                    )
                    .await?;
            }
            Verdict::Quarantine {
                reason,
                object,
                keep_for,
            } => {
                self.keep(tx.as_mut(), request, name, keep_for.first().copied()).await?;
                if message.method == ItipMethod::Reply {
                    let (calendar, object_id) = match object {
                        Some((calendar, object)) => (Some(*calendar), Some(*object)),
                        None => (None, None),
                    };
                    journal
                        .publish(
                            tx.as_mut(),
                            EventType::SchedulingReplyRejected,
                            EventPayload::SchedulingReply(SchedulingReplyPayload {
                                calendar,
                                object: object_id,
                                uid: data.as_ref().and_then(|data| data.uid.clone()),
                                attendee: None,
                                partstat: data
                                    .as_ref()
                                    .and_then(|data| data.attendees.as_ref())
                                    .and_then(|attendees| attendees.first())
                                    .and_then(|attendee| attendee.partstat),
                                reason: Some(reason.as_str().to_owned()),
                            }),
                        )
                        .await?;
                }
                journal
                    .audit(
                        tx.as_mut(),
                        AuditEvent::InboundItipRejected(InboundItipAudit {
                            method: Some(message.method),
                            object: object.map(|(_, object)| object),
                            reason: Some(reason.as_str().to_owned()),
                        }),
                    )
                    .await?;
            }
        }
        if let Some(token) = token {
            tx.idempotency().complete(token, key, 200, None).await?;
        }
        tx.commit().await?;
        Ok(verdict)
    }

    /// Keeps the quarantined message in the inbox of `person`, flagged so that no client ever sees it. One copy per
    /// message however many people it names: the mail is unauthenticated, and a forged one naming 200 recipients must
    /// not be stored 200 times.
    async fn keep(
        &self,
        tx: &mut dyn Tx,
        request: &InboundItipRequest,
        name: &ObjectUri,
        person: Option<PrincipalId>,
    ) -> AppResult<()> {
        let Some(principal) = person else {
            return Ok(());
        };
        let deps = self.core.deps();
        let now = deps.clock.now();
        let id = InboxItemId::from_uuid(deps.ids.new_id());
        let tenant_id = tx.tenant_id();
        match tx
            .inbox()
            .create(InboxItem {
                id,
                tenant_id,
                principal_id: principal,
                uri: name.clone(),
                etag: etag_of(&request.ical),
                data: request.ical.clone(),
                quarantined: true,
                created_at: now,
                updated_at: now,
                version: 1,
            })
            .await
        {
            Ok(_) | Err(StoreError::UniqueViolation(_)) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Whether the message was dealt with before by a gateway with another token: the inbox of `principal` has the item
    /// named after its `Message-ID` (the idempotency key of the calling token is the first line of defence).
    async fn seen(tx: &mut dyn Tx, principal: PrincipalId, name: &ObjectUri) -> AppResult<bool> {
        Ok(found(tx.inbox().get_by_uri(principal, name).await)?.is_some())
    }

    /// An answer: the organizer's copy takes it, if everything fits.
    async fn reply(&self, tx: &mut dyn Tx, incoming: &Incoming<'_>) -> AppResult<Verdict> {
        let Incoming {
            ctx,
            tenant,
            request,
            message,
            data,
            name,
        } = *incoming;
        let inbound = &self.core.deps().config.scheduling.inbound_itip;
        let (Some(data), method_enabled) = (
            data,
            tenant.settings.scheduling.inbound_methods.contains(&ItipMethod::Reply),
        ) else {
            return Ok(Verdict::quarantine(QuarantineReason::UnsupportedComponent, Vec::new()));
        };
        let (Some(uid), Some(organizer), [attendee]) = (
            data.uid.as_ref(),
            data.organizer.as_ref().map(|organizer| &organizer.address),
            data.attendees.as_deref().unwrap_or_default(),
        ) else {
            return Ok(Verdict::quarantine(QuarantineReason::InvalidReply, Vec::new()));
        };
        // Whose inbox keeps what is quarantined: the organizer's, when the tenant knows them.
        let organizer_principal = principal_of(&self.core, tx, tenant, organizer).await?;
        let keep_for: Vec<PrincipalId> = organizer_principal.iter().map(|principal| principal.id).collect();
        if let Some(principal) = &organizer_principal
            && Self::seen(tx, principal.id, name).await?
        {
            return Ok(Verdict::Duplicate);
        }
        if inbound.require_dmarc_pass && request.dmarc != AuthVerdict::Pass {
            return Ok(Verdict::quarantine(QuarantineReason::DmarcNotPassed, keep_for));
        }
        if !method_enabled {
            return Ok(Verdict::quarantine(QuarantineReason::MethodNotEnabled, keep_for));
        }
        // From is the replying attendee: a mail from one person cannot answer for another.
        let sender_is_attendee = attendee
            .address
            .email()
            .is_some_and(|email| email.as_str() == request.from.as_str());
        if !sender_is_attendee {
            return Ok(Verdict::quarantine(QuarantineReason::SenderMismatch, keep_for));
        }
        let Some(organizer_principal) = organizer_principal else {
            return Ok(Verdict::quarantine(QuarantineReason::UnknownEvent, keep_for));
        };
        // People of the tenant answer in their calendars; a mail that says it is from one of them proves nothing.
        if principal_of(&self.core, tx, tenant, &attendee.address).await?.is_some() {
            return Ok(Verdict::quarantine(QuarantineReason::InternalAttendee, keep_for));
        }
        let Some(copy) = organizer_copy(tx, tenant, &organizer_principal, uid).await? else {
            return Ok(Verdict::quarantine(QuarantineReason::UnknownEvent, keep_for));
        };
        let object = Some((copy.calendar_id, copy.id));
        let on_event = tx
            .objects()
            .attendees(copy.id)
            .await?
            .iter()
            .any(|row| row.address == attendee.address);
        if !on_event {
            return Ok(Verdict::Quarantine {
                reason: QuarantineReason::UnknownAttendee,
                object,
                keep_for,
            });
        }
        let outcome = self
            .processor
            .apply_reply(
                tx,
                ReplyInput {
                    ctx,
                    organizer: &copy,
                    message,
                    attendee: &attendee.address,
                    attendee_principal: None,
                    notify: Notify {
                        inbox_principal: Some(organizer_principal.id),
                        inbox_uri: Some(name),
                        text: &request.ical,
                    },
                    announce: false,
                },
            )
            .await;
        match outcome {
            Ok(_) => Ok(Verdict::Applied),
            Err(ReplyError::Rejected(rejection)) => Ok(Verdict::Quarantine {
                reason: rejection.into(),
                object,
                keep_for,
            }),
            Err(ReplyError::Failed(error)) => Err(error),
        }
    }

    /// An invitation or a cancellation of an organizer outside the tenant, for the attendees inside it.
    async fn invitation(&self, tx: &mut dyn Tx, incoming: &Incoming<'_>) -> AppResult<Verdict> {
        let Incoming {
            ctx,
            tenant,
            request,
            message,
            data,
            ..
        } = *incoming;
        let deps = self.core.deps();
        let inbound = &deps.config.scheduling.inbound_itip;
        let (Some(data), true) = (
            data,
            tenant.settings.scheduling.inbound_methods.contains(&message.method),
        ) else {
            return Ok(Verdict::quarantine(
                if data.is_some() {
                    QuarantineReason::MethodNotEnabled
                } else {
                    QuarantineReason::UnsupportedComponent
                },
                Vec::new(),
            ));
        };
        let (Some(uid), Some(organizer)) = (
            data.uid.as_ref(),
            data.organizer.as_ref().map(|organizer| &organizer.address),
        ) else {
            return Ok(Verdict::quarantine(QuarantineReason::InvalidMessage, Vec::new()));
        };
        let wanted: Vec<CalendarUserAddress> = data
            .attendees
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|attendee| attendee.address.clone())
            .collect();
        let mut all = wanted.clone();
        all.push(organizer.clone());
        let directory = Directory::load(tx, tenant, &deps.urls, &all).await?;
        let recipients: Vec<Principal> = wanted
            .iter()
            .filter_map(|address| match directory.classify(address, CuType::Individual) {
                Class::Internal(principal) | Class::Resource(principal) => Some(*principal),
                Class::Group | Class::External | Class::Unknown => None,
            })
            .filter(|principal| principal.status == PrincipalStatus::Active)
            .collect();
        let keep_for: Vec<PrincipalId> = recipients.iter().map(|principal| principal.id).collect();
        if let Some(first) = keep_for.first()
            && Self::seen(tx, *first, incoming.name).await?
        {
            return Ok(Verdict::Duplicate);
        }
        if inbound.require_dmarc_pass && request.dmarc != AuthVerdict::Pass {
            return Ok(Verdict::quarantine(QuarantineReason::DmarcNotPassed, keep_for));
        }
        // The sender is the organizer; and the organizer is nobody the tenant knows: mail does not prove that.
        if organizer
            .email()
            .is_none_or(|email| email.as_str() != request.from.as_str())
        {
            return Ok(Verdict::quarantine(QuarantineReason::SenderMismatch, keep_for));
        }
        if !matches!(directory.classify(organizer, CuType::Individual), Class::External) {
            return Ok(Verdict::quarantine(QuarantineReason::OrganizerIsInternal, keep_for));
        }
        if recipients.is_empty() {
            return Ok(Verdict::quarantine(QuarantineReason::NoInternalRecipient, keep_for));
        }
        if message.method == ItipMethod::Request && !self.attachments_are_clean(ctx, message).await? {
            return Ok(Verdict::quarantine(QuarantineReason::ContentRejected, keep_for));
        }
        let event = EventOfMessage {
            uid,
            organizer,
            wanted: &wanted,
            directory: &directory,
        };
        let deliveries = self.deliveries(tx, incoming, &event, recipients).await?;
        if deliveries.is_empty() {
            return Ok(Verdict::quarantine(QuarantineReason::UnknownEvent, keep_for));
        }
        let delivered = self
            .processor
            .deliver(
                tx,
                &DeliveryScope {
                    ctx,
                    uid,
                    organizers: std::slice::from_ref(organizer),
                },
                &deliveries,
            )
            .await?;
        if delivered == 0 {
            // Everybody has an event of somebody else under the UID: the message is about nothing they have.
            return Ok(Verdict::quarantine(QuarantineReason::UnknownEvent, keep_for));
        }
        Ok(Verdict::Applied)
    }

    /// Whether the content scanners find the inline attachments of the message clean. Without a scanner the answer
    /// is yes without looking.
    ///
    /// # Errors
    ///
    /// `Unavailable` when a scanner does not answer: content that was not scanned is not stored.
    async fn attachments_are_clean(&self, ctx: &RequestContext, message: &ItipMessage) -> AppResult<bool> {
        let scanners = &self.core.deps().content_scanners;
        if scanners.is_empty() {
            return Ok(true);
        }
        let calendar = message.calendar.clone();
        let attachments = blocking(&self.core, ErrorContext::Scheduling, move |_| {
            Ok(inline_attachments(&calendar))
        })
        .await?;
        for attachment in attachments {
            let context = ScanContext {
                tenant: ctx.tenant,
                content_type: attachment
                    .media_type
                    .as_deref()
                    .and_then(|text| MediaType::parse(text).ok()),
            };
            for scanner in scanners {
                match scanner.scan(&attachment.content, &context).await {
                    Ok(ScanVerdict::Clean) => {}
                    Ok(ScanVerdict::Infected(_)) => return Ok(false),
                    Err(error) => return Err(AppError::from(error)),
                }
            }
        }
        Ok(true)
    }

    /// What each recipient gets of an invitation or a cancellation: the message, and their copy of the event kept in
    /// step. The copy is the object the message describes, without the alarms of the sender (they are not the
    /// recipient's to have fire on their devices). A recipient who has a newer version, or an event of somebody
    /// else's under the UID, is dealt with by the delivery itself.
    async fn deliveries(
        &self,
        tx: &mut dyn Tx,
        incoming: &Incoming<'_>,
        event: &EventOfMessage<'_>,
        recipients: Vec<Principal>,
    ) -> AppResult<Vec<InternalDelivery>> {
        let Incoming {
            tenant,
            request,
            message,
            name,
            ..
        } = *incoming;
        let copy_text = if message.method == ItipMethod::Cancel {
            String::new()
        } else {
            let message = message.clone();
            blocking(&self.core, ErrorContext::Scheduling, move |_| {
                davhaven_ical::serialize::serialize(&strip_alarms(&message.object()))
            })
            .await?
        };
        let mut deliveries: Vec<InternalDelivery> = Vec::new();
        for principal in recipients {
            let existing = tx.objects().find_scheduling_uid(principal.id, event.uid).await?;
            let address = event
                .wanted
                .iter()
                .find(|address| matches!(event.directory.principal(address), Some(known) if known.id == principal.id))
                .cloned()
                .unwrap_or_else(|| event.organizer.clone());
            let copy = match (message.method, existing.is_some()) {
                (ItipMethod::Cancel, true) => CopyOp::Remove,
                (ItipMethod::Cancel, false) => continue,
                _ => CopyOp::Put {
                    text: copy_text.clone(),
                    create_in: wants_copy(&self.core, tx, tenant, event.organizer, None, &principal).await?,
                },
            };
            deliveries.push(InternalDelivery {
                principal,
                address,
                copy,
                messages: vec![request.ical.clone()],
                inbox_names: Some(vec![name.clone()]),
            });
        }
        Ok(deliveries)
    }
}

#[cfg(test)]
mod tests {
    use davhaven_domain::{IcalLimits, PartStat};

    use super::*;

    const REPLY: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Mail//EN\r\nMETHOD:REPLY\r\nBEGIN:VEVENT\r\nUID:ev-1\r\n\
        DTSTAMP:20270301T090000Z\r\nSEQUENCE:2\r\nORGANIZER:mailto:anna@acme.example\r\n\
        ATTENDEE;PARTSTAT=ACCEPTED:mailto:guest@example.net\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    #[test]
    fn the_inbox_item_is_named_after_the_message_id_alone() {
        let first = item_name("<abc@mail.example.org>").unwrap();
        assert_eq!(
            first,
            item_name("<abc@mail.example.org>").unwrap(),
            "a repeat finds the item"
        );
        assert_ne!(first, item_name("<abd@mail.example.org>").unwrap());
        assert!(first.as_str().starts_with("inbound-") && first.as_str().rsplit('.').next() == Some("ics"));
        assert_eq!(first.as_str().len(), "inbound-".len() + 32 + ".ics".len());
    }

    #[test]
    fn the_deduplication_key_follows_the_message_id_and_nothing_else() {
        assert_eq!(dedup_key("<a@b>"), dedup_key("<a@b>"));
        assert_ne!(dedup_key("<a@b>"), dedup_key("<a@c>"));
        assert!(dedup_key("<a@b>").starts_with("itip-inbound/"));
        assert_eq!(hex(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
    }

    #[test]
    fn a_reply_is_described_by_its_identity_organizer_and_attendee() {
        let message = parse_message(REPLY.as_bytes(), &IcalLimits::default()).unwrap();
        let data = describe(&message).unwrap();
        assert_eq!(data.uid.as_ref().map(Uid::as_str), Some("ev-1"));
        assert_eq!(data.sequence, Some(2));
        assert_eq!(
            data.attendees
                .as_ref()
                .and_then(|list| list.first())
                .and_then(|attendee| attendee.partstat),
            Some(PartStat::Accepted)
        );
        let organizer = data.organizer.unwrap().address;
        assert_eq!(
            organizer,
            CalendarUserAddress::parse("mailto:anna@acme.example").unwrap()
        );
        assert_eq!(data.attendees.unwrap().len(), 1);
    }

    #[test]
    fn free_busy_replies_are_not_events_and_have_no_description() {
        let fb = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Mail//EN\r\nMETHOD:REPLY\r\nBEGIN:VFREEBUSY\r\nUID:fb\r\n\
            DTSTAMP:20270301T090000Z\r\nDTSTART:20270301T090000Z\r\nDTEND:20270301T100000Z\r\n\
            ORGANIZER:mailto:anna@acme.example\r\nATTENDEE:mailto:guest@example.net\r\nEND:VFREEBUSY\r\nEND:VCALENDAR\r\n";
        let message = parse_message(fb.as_bytes(), &IcalLimits::default()).unwrap();
        assert!(describe(&message).is_none());
    }
}
