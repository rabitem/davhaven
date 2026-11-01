//! Server-side scheduling: free-busy, the scheduling outbox and inbox, invitation responses, RSVP pages and the
//! inbound iTIP endpoint (PLAN 2.8, 2.13).

use core::fmt;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::{
    CalendarUserAddress, ETag, InboxItemId, PartStat, PrincipalName, PrivilegeSet, RequestContext, ResourcePath,
    TimeZoneName,
};
use davhaven_ical::filter::TimeRange;
use davhaven_ical::freebusy::BusyPeriod;
use davhaven_wire::mcp::WorkingHours;
use davhaven_wire::{EventView, InboundItipRequest, InboundItipResponse};

use super::calendars::CalendarRef;
use super::common::RenderedPage;
use super::objects::{CalendarDataSpec, ObjectSelector, ScheduleStatus};
use crate::error::{AppError, AppResult};

/// What a free-busy request looks at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FreeBusyTarget {
    /// One calendar collection (`free-busy-query` REPORT): the answer has one entry without an address.
    Collection(ResourcePath),
    /// People, by calendar user address (outbox `VFREEBUSY` request, MCP `free_busy`): the busy time of all
    /// calendars the caller may query, per person. Only principals of the caller's tenant are answered.
    Addresses(Vec<CalendarUserAddress>),
}

/// A free-busy request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreeBusyRequest {
    /// Whose busy time is asked.
    pub target: FreeBusyTarget,
    /// The range; bounded on both sides and at most `max_time_range_years` long.
    pub range: TimeRange,
}

/// The busy time of one person or calendar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreeBusyEntry {
    /// The address as the request named it; `None` for a collection.
    pub address: Option<CalendarUserAddress>,
    /// Whether the address resolved to a principal of the tenant. Unknown addresses have no periods.
    pub known: bool,
    /// The merged busy periods, ordered by start.
    pub periods: Vec<BusyPeriod>,
}

/// The answer of a free-busy request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreeBusyResult {
    /// The requested range.
    pub range: TimeRange,
    /// One entry per target, in request order.
    pub entries: Vec<FreeBusyEntry>,
    /// When the answer was made, by the `Clock` of the application: the `DTSTAMP` of a `VFREEBUSY` that a protocol
    /// layer renders from it (the layers have no clock of their own).
    pub generated_at: DateTime<Utc>,
}

/// A search for times when everybody is free (MCP `find_free_slots`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindSlotsRequest {
    /// The people who must all be free.
    pub addresses: Vec<CalendarUserAddress>,
    /// The search range; bounded on both sides.
    pub range: TimeRange,
    /// The length of a slot in minutes.
    pub duration_minutes: u32,
    /// Restricts slots to working hours.
    pub working_hours: Option<WorkingHours>,
    /// The time zone of the working hours; the caller's zone when absent.
    pub time_zone: Option<TimeZoneName>,
    /// The most slots to return.
    pub limit: Option<u32>,
}

/// A free slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slot {
    /// The start of the slot.
    pub start: DateTime<Utc>,
    /// The end of the slot.
    pub end: DateTime<Utc>,
}

/// The slots found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindSlotsResult {
    /// The slots, earliest first.
    pub slots: Vec<Slot>,
    /// Whether more slots exist than were returned.
    pub truncated: bool,
}

/// The answer for one recipient of an outbox POST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientResponse {
    /// The recipient.
    pub recipient: CalendarUserAddress,
    /// The request status (`2.0;Success` or an error) as a schedule status.
    pub status: ScheduleStatus,
    /// The `VFREEBUSY` reply for the recipient, when there is one.
    pub calendar_data: Option<String>,
}

/// The answer of an outbox POST (`CALDAV:schedule-response`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScheduleResponse {
    /// One response per recipient, in request order.
    pub responses: Vec<RecipientResponse>,
}

/// An item of a principal's scheduling inbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxItemView {
    /// The inbox item resource.
    pub path: ResourcePath,
    /// The item id.
    pub id: InboxItemId,
    /// The strong entity tag of the data.
    pub etag: ETag,
    /// The size of the iTIP message in bytes (`DAV:getcontentlength`), whether or not `data` is carried.
    pub size: u64,
    /// The iTIP message as iCalendar text; `None` in listings and for reads that ask for no data.
    pub data: Option<String>,
    /// What the caller may do with the item (`DAV:current-user-privilege-set`), derived by the application from the
    /// access the caller has to the inbox: the DAV layer renders it and decides nothing.
    pub privileges: PrivilegeSet,
    /// When the item was delivered.
    pub created_at: DateTime<Utc>,
}

/// One entry of the answer of [`SchedulingService::inbox_get_many`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InboxEntry {
    /// The item exists in the inbox and the caller may read it; it carries its data when the read asked for it.
    Found(InboxItemView),
    /// The path names no readable item of the inbox (a 404 entry in a multistatus).
    Missing(ResourcePath),
}

/// An object addressed across the JSON interfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectRef {
    /// The calendar that holds the object.
    pub calendar: CalendarRef,
    /// The object.
    pub object: ObjectSelector,
}

/// The caller's answer to an invitation (API and MCP `respond_to_invitation`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitationResponse {
    /// `accepted`, `declined` or `tentative`.
    pub partstat: PartStat,
    /// A comment for the organizer (at most 500 characters).
    pub comment: Option<String>,
}

/// An attendee's answer on the RSVP page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsvpAnswer {
    /// `accepted`, `declined` or `tentative`.
    pub partstat: PartStat,
    /// A comment for the organizer (at most 500 characters).
    pub comment: Option<String>,
}

/// The CSRF token of an RSVP form: bound to the RSVP token and valid for one hour (PLAN 2.13).
#[derive(Clone, PartialEq, Eq)]
pub struct CsrfToken(String);

impl CsrfToken {
    /// Wraps the token text of a form field.
    pub fn new(text: impl Into<String>) -> Self {
        Self(text.into())
    }

    /// The token text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CsrfToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CsrfToken(<redacted>)")
    }
}

/// Scheduling operations.
///
/// RSVP and feed requests are authenticated by the edge like any other (`Channel::Rsvp` with
/// `PresentedCredential::Rsvp`): the context's actor is `Actor::RsvpAttendee`. Unknown, expired and revoked RSVP
/// tokens never reach these methods; they fail in authentication and the web layer answers one identical 404.
#[async_trait]
pub trait SchedulingService: Send + Sync {
    /// Free-busy of a collection or of people.
    ///
    /// # Errors
    ///
    /// `Invalid` with `valid-filter` for unbounded or too long ranges, `NotFound` for invisible collections,
    /// `Forbidden`.
    async fn free_busy(&self, ctx: &RequestContext, request: FreeBusyRequest) -> AppResult<FreeBusyResult>;

    /// Finds slots when all listed people are free.
    ///
    /// # Errors
    ///
    /// `Invalid` for bad ranges and durations, `Forbidden`.
    async fn find_free_slots(&self, ctx: &RequestContext, request: FindSlotsRequest) -> AppResult<FindSlotsResult>;

    /// Handles a POST to a principal's scheduling outbox. Only `VFREEBUSY` requests are accepted.
    ///
    /// # Errors
    ///
    /// `Invalid` with `valid-scheduling-message`, `Forbidden` for other principals' outboxes, `NotFound`.
    async fn outbox_post(
        &self,
        ctx: &RequestContext,
        principal: &PrincipalName,
        body: String,
    ) -> AppResult<ScheduleResponse>;

    /// Lists the scheduling inbox of a principal (quarantined items are not listed).
    ///
    /// # Errors
    ///
    /// `NotFound` for inboxes the caller cannot see.
    async fn inbox_list(&self, ctx: &RequestContext, principal: &PrincipalName) -> AppResult<Vec<InboxItemView>>;

    /// Reads one inbox item with its data.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn inbox_get(&self, ctx: &RequestContext, path: &ResourcePath) -> AppResult<InboxItemView>;

    /// Reads several items of one inbox, in the order of `paths`: the bulk read behind `calendar-multiget`, behind
    /// listings that carry the messages and behind `sync-collection` of the inbox, which would otherwise read item
    /// by item (R14: no N+1).
    ///
    /// A path that is not an item of `inbox`, or that names no item the caller may read, is
    /// [`InboxEntry::Missing`]. With `spec.include_data` unset the items come without their messages (their entity
    /// tag, size and privileges only), which is how the changed members of a synchronization are read; otherwise the
    /// message is cut down to what `spec.projection` selects, like the data of calendar objects. Implementations
    /// read all items in one transaction and load the authorization facts once; reading item by item is what this
    /// method exists to avoid, so there is no default that does it. The default answers `Unsupported`;
    /// `SchedulingServiceImpl` implements the method.
    ///
    /// # Errors
    ///
    /// `NotFound` when the caller cannot see the inbox, `Forbidden` with `number-of-matches-within-limits` when more
    /// paths are named than `max_multiget_hrefs` allows (judged after the visibility of the inbox); infrastructure
    /// failures otherwise.
    async fn inbox_get_many(
        &self,
        ctx: &RequestContext,
        inbox: &ResourcePath,
        paths: Vec<ResourcePath>,
        spec: &CalendarDataSpec,
    ) -> AppResult<Vec<InboxEntry>> {
        let _ = (ctx, inbox, paths, spec);
        Err(AppError::unsupported())
    }

    /// Deletes one inbox item.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn inbox_delete(&self, ctx: &RequestContext, path: &ResourcePath) -> AppResult<()>;

    /// Answers an invitation as the caller: changes the caller's `PARTSTAT` on their copy and replies to the
    /// organizer through the same path as a DAV change.
    ///
    /// # Errors
    ///
    /// `NotFound` when the object is invisible or the caller is not an attendee, `Invalid` for answers other than
    /// accepted, declined and tentative, `Forbidden`.
    async fn respond(
        &self,
        ctx: &RequestContext,
        object: ObjectRef,
        response: InvitationResponse,
    ) -> AppResult<EventView>;

    /// Applies an iTIP message a mail gateway forwarded. Unauthenticated or mismatching messages are
    /// quarantined, not errors.
    ///
    /// # Errors
    ///
    /// `Forbidden` without `itip:inbound`, `Conflict` with `feature-not-enabled` when the endpoint is disabled,
    /// `Invalid` for unreadable messages, `RateLimited` per sender and per gateway, `Unavailable` when the rate
    /// limiter or a content scanner does not answer.
    async fn inbound_itip(&self, ctx: &RequestContext, request: InboundItipRequest) -> AppResult<InboundItipResponse>;

    /// Renders the RSVP page of the invitation the context's RSVP token belongs to. The read-only `GET` works
    /// without JavaScript and embeds a CSRF token for the form.
    ///
    /// # Errors
    ///
    /// `NotFound` for every token problem.
    async fn rsvp_page(&self, ctx: &RequestContext) -> AppResult<RenderedPage>;

    /// Records an RSVP answer (repeatable) and renders the confirmation. A wrong or expired CSRF token, an answer
    /// other than accepted, declined and tentative and a comment longer than 500 characters record nothing and
    /// render the form again with a fresh token and the notice `invalid_csrf`, `invalid_answer` or
    /// `comment_too_long` (the page is the answer; there is no error).
    ///
    /// # Errors
    ///
    /// `NotFound` for every token problem, `Invalid` for a comment with control characters.
    async fn rsvp_answer(&self, ctx: &RequestContext, answer: RsvpAnswer, csrf: CsrfToken) -> AppResult<RenderedPage>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csrf_tokens_are_not_debug_printed() {
        let token = CsrfToken::new("v1.abc.def");
        assert_eq!(token.as_str(), "v1.abc.def");
        assert!(!format!("{token:?}").contains("abc"));
    }
}
