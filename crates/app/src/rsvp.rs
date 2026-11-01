//! RSVP pages and answers for external attendees (PLAN 2.13).
//!
//! An external attendee gets a link in the invitation mail (`/rsvp/{token}`). The edge authenticates the token like
//! any other credential; what arrives here is a [`RequestContext`] whose actor is `Actor::RsvpAttendee` with the
//! invitation and the address the link was issued to. This module is the application side of the two requests the
//! web surface serves:
//!
//! * **`GET`** (`RsvpService::page`) renders the invitation (summary, time, location and the organizer's name,
//!   nothing else) and a form with a CSRF token. It reads and changes nothing.
//! * **`POST`** (`RsvpService::answer`) records an answer of `ACCEPTED`, `DECLINED` or `TENTATIVE` with an optional
//!   remark of at most 500 characters. The answer is **repeatable**: the attendee can change their mind until the
//!   link expires.
//!
//! # One path for every answer
//!
//! The answer is not written into the organizer's copy here. It becomes the same small iTIP `REPLY` that a calendar
//! client or a mail gateway produces and goes through the `ItipProcessor`, which folds it into the organizer's copy
//! under the lock of its calendar, keeps the `Schedule-Tag` (a server merge), tells the organizer through the
//! scheduling inbox and announces `scheduling.reply_received`. The RSVP path adds what is its own: the use of the
//! link is recorded (`last_used_at`, `last_response`), the `rsvp.answered` event and the audit record, all in the
//! same transaction.
//!
//! # What a link protects against
//!
//! * A link that is unknown, expired or revoked never gets here (authentication fails and the web layer answers one
//!   identical 404); one that was revoked or expired between authentication and this transaction is treated the same
//!   way here.
//! * The form carries a CSRF token bound to the link and valid for one hour (`csrf`); an answer without a good token
//!   records nothing and shows the form again with a fresh token and the notice `invalid_csrf` (a page that was open
//!   for more than an hour is the usual cause, and the attendee should be able to try again, not read a bare error).
//!   An answer that is no answer and a remark that is too long are shown the same way (`invalid_answer`,
//!   `comment_too_long`). The same-origin check of `Origin` happens at the edge, before this code.
//! * The page of a cancelled event shows no form and refuses answers. (Cancelling revokes the links anyway.)
//!
//! The form posts to `?`, the address of the page itself: the application never holds the link, only the id of the
//! token row, and the page must not need to know it.

mod csrf;
mod model;

use davhaven_domain::audit::RsvpAudit;
use davhaven_domain::events::RsvpPayload;
use davhaven_domain::{
    Actor, AuditEvent, CalendarUserAddress, Channel, CredentialKind, ErrorKind, EventData, EventPayload, EventStatus,
    EventType, ObjectId, PartStat, Principal, RequestContext, RsvpToken, StoredObject, Tenant, TokenId,
};
use davhaven_ical::ErrorContext;
use davhaven_ical::itip::{ReplySpec, reply_message};
use davhaven_ports::{RenderRequest, TemplateName, Tx, TxMode};

use crate::audit::Journal;
use crate::authz::{blocking, clean_optional_text, found, retrying};
use crate::error::{AppError, AppResult};
use crate::itip::{ItipProcessor, Notify, Rejection, ReplyError, ReplyInput, principal_of};
use crate::services::{CsrfToken, RenderedPage, RsvpAnswer};
use crate::wiring::AppCore;

use model::Invitation;

/// The longest remark an attendee can give with an answer, in characters: what the organizer's copy keeps of it.
pub(crate) const MAX_COMMENT_CHARS: usize = davhaven_ical::itip::MAX_COMMENT_CHARS;

/// The RSVP use cases (see the module documentation).
#[derive(Debug, Clone)]
pub struct RsvpService {
    core: AppCore,
    processor: ItipProcessor,
}

/// Everything a page is made of: the link, the invitation and the people.
struct Loaded {
    tenant: Tenant,
    token: RsvpToken,
    object: StoredObject,
    event: EventData,
    organizer: String,
    current: PartStat,
}

impl Loaded {
    fn cancelled(&self) -> bool {
        self.event.status == Some(EventStatus::Cancelled)
    }

    fn invitation(&self) -> Invitation<'_> {
        Invitation {
            tenant: self
                .tenant
                .settings
                .sender
                .display_name
                .as_deref()
                .unwrap_or(&self.tenant.display_name),
            organizer: &self.organizer,
            event: &self.event,
            zone: self.tenant.settings.timezone,
        }
    }
}

impl RsvpService {
    /// Creates the service on the shared application core.
    pub fn new(core: AppCore) -> Self {
        Self {
            processor: ItipProcessor::new(core.clone()),
            core,
        }
    }

    /// The link the request came through: the invitation, the attendee and the token row.
    fn link(ctx: &RequestContext) -> AppResult<(ObjectId, &CalendarUserAddress, TokenId)> {
        let (Actor::RsvpAttendee { object, address }, Channel::Rsvp) = (&ctx.actor, ctx.channel) else {
            return Err(AppError::not_found());
        };
        let Some(credential) = ctx
            .credential
            .filter(|credential| credential.kind == CredentialKind::RsvpToken)
        else {
            return Err(AppError::not_found());
        };
        Ok((*object, address, TokenId::from_uuid(credential.id)))
    }

    /// Loads what the pages show. Every problem with the link is `NotFound`: one answer for unknown, expired,
    /// revoked and mismatching links, and for invitations that are gone.
    async fn load(&self, tx: &mut dyn Tx, ctx: &RequestContext) -> AppResult<Loaded> {
        let deps = self.core.deps();
        let (object_id, address, token_id) = Self::link(ctx)?;
        let token = found(tx.rsvp().get(token_id).await)?.ok_or_else(AppError::not_found)?;
        if token.object_id != object_id
            || &token.attendee_address != address
            || token.revoked_at.is_some()
            || token.expires_at <= deps.clock.now()
        {
            return Err(AppError::not_found());
        }
        let object = found(tx.objects().get_by_id(object_id).await)?.ok_or_else(AppError::not_found)?;
        let tenant = tx.tenant().get().await?;
        let current = tx
            .objects()
            .attendees(object.id)
            .await?
            .into_iter()
            .find(|row| &row.address == address)
            .map(|row| row.partstat)
            .ok_or_else(AppError::not_found)?;
        let text = object.data.clone();
        let event = blocking(&self.core, ErrorContext::Store, move |limits| {
            let calendar = davhaven_ical::parse::parse(text.as_bytes(), limits)?;
            davhaven_ical::merge::to_event_data(&calendar, None)
        })
        .await
        // A copy that cannot be read is nothing to answer; a worker that failed or ran out of time is not the link's
        // fault and is not told as if it were.
        .map_err(|error| match error.kind() {
            ErrorKind::Unavailable | ErrorKind::Internal | ErrorKind::RateLimited => error,
            _ => AppError::not_found(),
        })?;
        let organizer = self.organizer_name(tx, &tenant, &object, &event).await?;
        Ok(Loaded {
            tenant,
            token,
            object,
            event,
            organizer,
            current,
        })
    }

    /// The name the page calls the organizer: the display name of their principal, else the name the event gives,
    /// else nothing. Never an address.
    async fn organizer_name(
        &self,
        tx: &mut dyn Tx,
        tenant: &Tenant,
        object: &StoredObject,
        event: &EventData,
    ) -> AppResult<String> {
        if let Some(address) = &object.organizer_address
            && let Some(principal) = principal_of(&self.core, tx, tenant, address).await?
        {
            return Ok(principal.display_name);
        }
        Ok(event
            .organizer
            .as_ref()
            .and_then(|organizer| organizer.common_name.clone())
            .unwrap_or_default())
    }

    /// Renders `template` with `model` in the language of the visitor, else of the tenant.
    async fn render(
        &self,
        ctx: &RequestContext,
        tenant: &Tenant,
        template: &str,
        model: serde_json::Value,
    ) -> AppResult<RenderedPage> {
        let rendered = self
            .core
            .deps()
            .templates
            .render(RenderRequest {
                template: TemplateName::parse(template).map_err(AppError::internal)?,
                locale: ctx.locale.clone().unwrap_or_else(|| tenant.settings.locale.clone()),
                theme: tenant.settings.theme_name().to_owned(),
                model,
            })
            .await?;
        Ok(RenderedPage { html: rendered.html })
    }

    /// The invitation and the form to answer it.
    ///
    /// # Errors
    ///
    /// `NotFound` for every problem with the link, `Unavailable` when the page cannot be rendered.
    pub(crate) async fn page(&self, ctx: &RequestContext) -> AppResult<RenderedPage> {
        let deps = self.core.deps();
        let mut tx = deps.database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let loaded = self.load(tx.as_mut(), ctx).await?;
        tx.commit().await?;
        self.form(ctx, &loaded, None).await
    }

    /// Why an answer cannot be taken, as the notice the form shows: a wrong or expired CSRF token, an answer that is
    /// none, a remark that is too long.
    fn refusal(
        &self,
        ctx: &RequestContext,
        loaded: &Loaded,
        answer: &RsvpAnswer,
        csrf: &CsrfToken,
    ) -> Option<&'static str> {
        let deps = self.core.deps();
        let too_long = answer
            .comment
            .as_deref()
            .is_some_and(|text| text.chars().count() > MAX_COMMENT_CHARS);
        if !csrf::verify(
            deps.keyring.as_ref(),
            ctx.tenant,
            loaded.token.id,
            csrf.as_str(),
            deps.clock.now(),
        ) {
            Some("invalid_csrf")
        } else if !answer.partstat.is_answer() {
            Some("invalid_answer")
        } else if too_long {
            Some("comment_too_long")
        } else {
            None
        }
    }

    /// The page with its form and a fresh CSRF token, and the notice `error` when an answer was refused.
    async fn form(&self, ctx: &RequestContext, loaded: &Loaded, error: Option<&str>) -> AppResult<RenderedPage> {
        let deps = self.core.deps();
        let csrf = csrf::issue(deps.keyring.as_ref(), ctx.tenant, loaded.token.id, deps.clock.now());
        let model = loaded
            .invitation()
            .page(loaded.cancelled(), loaded.current, &csrf, error)
            .ok_or_else(AppError::not_found)?;
        self.render(ctx, &loaded.tenant, "rsvp_page", model).await
    }

    /// Records an answer and shows the confirmation.
    ///
    /// # Errors
    ///
    /// `NotFound` for every problem with the link, `Invalid` for a remark with control characters. A CSRF token that is
    /// wrong or expired, an answer other than accepted, declined or tentative and a remark longer than 500 characters
    /// are not errors: the form is shown again with the notice (`invalid_csrf`, `invalid_answer`,
    /// `comment_too_long`) and nothing is recorded.
    pub(crate) async fn answer(
        &self,
        ctx: &RequestContext,
        answer: RsvpAnswer,
        csrf: CsrfToken,
    ) -> AppResult<RenderedPage> {
        retrying(false, || self.answer_once(ctx, &answer, &csrf)).await
    }

    async fn answer_once(
        &self,
        ctx: &RequestContext,
        answer: &RsvpAnswer,
        csrf: &CsrfToken,
    ) -> AppResult<RenderedPage> {
        let deps = self.core.deps();
        let journal = Journal::new(&self.core, ctx);
        let mut tx = deps.database.begin(ctx.tenant, TxMode::ReadWrite).await?;
        // The link comes first: an unknown link is a 404 whatever the form says.
        let loaded = self.load(tx.as_mut(), ctx).await?;
        let (Some(organizer), true) = (loaded.object.organizer_address.clone(), !loaded.cancelled()) else {
            return Err(AppError::not_found());
        };
        let partstat = answer.partstat;
        if let Some(refusal) = self.refusal(ctx, &loaded, answer, csrf) {
            tx.commit().await?;
            return self.form(ctx, &loaded, Some(refusal)).await;
        }
        let comment = clean_optional_text("/comment", answer.comment.as_deref(), MAX_COMMENT_CHARS)?;
        let address = loaded.token.attendee_address.clone();
        let (uid, sequence, now) = (loaded.object.uid.clone(), loaded.object.sequence, deps.clock.now());
        let (to, who, remark) = (organizer.clone(), address.clone(), comment.clone());
        let (message, text) = blocking(&self.core, ErrorContext::Scheduling, move |_limits| {
            let message = reply_message(&ReplySpec {
                uid: &uid,
                organizer: &to,
                attendee: &who,
                partstat,
                sequence,
                dtstamp: now,
                comment: remark.as_deref(),
            })?;
            let text = davhaven_ical::serialize::serialize(&message.calendar)?;
            Ok((message, text))
        })
        .await?;
        let notify = match &loaded.object.organizer_address {
            Some(address) => principal_of(&self.core, tx.as_mut(), &loaded.tenant, address)
                .await?
                .map(|principal: Principal| principal.id),
            None => None,
        };
        let outcome = self
            .processor
            .apply_reply(
                tx.as_mut(),
                ReplyInput {
                    ctx,
                    organizer: &loaded.object,
                    message: &message,
                    attendee: &address,
                    attendee_principal: None,
                    notify: Notify {
                        inbox_principal: notify,
                        inbox_uri: None,
                        text: &text,
                    },
                    announce: false,
                },
            )
            .await;
        let report = match outcome {
            Ok(report) => report,
            // The invitation changed under the link (the attendee was removed, the event was replaced): the link
            // has nothing to answer any more.
            Err(ReplyError::Rejected(Rejection::UnknownEvent | Rejection::StaleSequence | Rejection::InvalidReply)) => {
                return Err(AppError::not_found());
            }
            Err(ReplyError::Failed(error)) => return Err(error),
        };
        tx.rsvp().record_use(loaded.token.id, Some(partstat)).await?;
        journal
            .audit(
                tx.as_mut(),
                AuditEvent::RsvpAnswered(RsvpAudit {
                    object: loaded.object.id,
                    partstat,
                }),
            )
            .await?;
        journal
            .publish(
                tx.as_mut(),
                EventType::RsvpAnswered,
                EventPayload::Rsvp(RsvpPayload {
                    calendar: report.calendar,
                    object: report.object,
                    uid: report.uid,
                    partstat,
                }),
            )
            .await?;
        let model = loaded.invitation().answered(partstat).ok_or_else(AppError::not_found)?;
        tx.commit().await?;
        self.render(ctx, &loaded.tenant, "rsvp_answered", model).await
    }
}
