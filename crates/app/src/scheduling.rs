//! Server-side scheduling (RFC 6638, PLAN 2.8): organizer and attendee processing, delivery, free-busy, the
//! scheduling inbox and outbox, answers through the API, RSVP pages and inbound iTIP.
//!
//! Two pieces live here, and they meet only in the transaction of a write:
//!
//! * [`Scheduler`] implements the seam of the object write path ([`ObjectScheduler`]): it decides, inside the
//!   transaction of every `PUT`, `DELETE` and JSON write, whether the write schedules, what the organizer's copy
//!   becomes, who is told what and how (see its documentation for the rules);
//! * [`SchedulingServiceImpl`] implements [`SchedulingService`]: free-busy and free slots, the outbox and inbox, the
//!   answer to an invitation through the API and MCP (`respond`), the RSVP page and the inbound iTIP endpoint.
//!
//! Install both on the object service and the scheduling service with one shared scheduler, so that the quotas are
//! shared (`build` does):
//!
//! ```ignore
//! let scheduler = Arc::new(Scheduler::new(core.clone()));
//! let objects = ObjectServiceImpl::with_scheduler(core.clone(), scheduler.clone());
//! let scheduling = SchedulingServiceImpl::with_scheduler(core.clone(), scheduler);
//! ```
//!
//! The outbox handler of the deliveries that are queued above the synchronous cap (`internal_delivery`) is one of
//! [`outbox::handlers`](crate::outbox::handlers), so every dispatcher has it.
//!
//! | Submodule | Responsibility |
//! | --- | --- |
//! | `scheduler` | the [`ObjectScheduler`]: roles, plans and the hand-over between `before_write` and `after_write` |
//! | `actor` | who writes: the principal, their addresses, and the owner of the calendar they write for |
//! | `organizer`, `plan`, `build` | the organizer's write: comparison, decision, classification, policy, messages |
//! | `attendee`, `cancel` | an attendee's write and the deletion of a scheduling object |
//! | `execute` | carrying out a plan: mails, deliveries, replies |
//! | `quota` | external recipients per organizer and hour, per tenant and day |
//! | `busy`, `freebusy` | busy time, free-busy and free slots |
//! | `inbox`, `outbox_post` | the scheduling collections of a principal |
//! | `respond` | `respond_to_invitation` |

mod actor;
mod attendee;
mod build;
mod busy;
mod cancel;
mod execute;
mod freebusy;
mod inbox;
mod organizer;
mod outbox_post;
mod plan;
mod quota;
mod respond;
mod scheduler;

use std::sync::Arc;

use async_trait::async_trait;
use davhaven_domain::{PrincipalName, RequestContext, ResourcePath};
use davhaven_ports::OutboxHandler;
use davhaven_wire::{EventView, InboundItipRequest, InboundItipResponse};

pub use scheduler::Scheduler;

use crate::error::AppResult;
use crate::inbound::InboundService;
use crate::objects::{ObjectScheduler, ObjectServiceImpl};
use crate::rsvp::RsvpService;
use crate::services::{
    CalendarDataSpec, CsrfToken, FindSlotsRequest, FindSlotsResult, FreeBusyRequest, FreeBusyResult, InboxEntry,
    InboxItemView, InvitationResponse, ObjectRef, RenderedPage, RsvpAnswer, ScheduleResponse, SchedulingService,
};
use crate::wiring::AppCore;

/// The extra outbox handlers of the scheduling use cases: none. `internal_delivery` is one of
/// [`outbox::handlers`](crate::outbox::handlers) and every dispatcher has it; the function stays so that callers
/// that pass its result to [`new_dispatcher`](crate::outbox::new_dispatcher) as extra handlers keep working.
pub fn handlers(_core: &AppCore) -> Vec<Arc<dyn OutboxHandler>> {
    Vec::new()
}

/// The [`SchedulingService`] of the application.
#[derive(Debug, Clone)]
pub struct SchedulingServiceImpl {
    core: AppCore,
    scheduler: Arc<Scheduler>,
    objects: ObjectServiceImpl,
    rsvp: RsvpService,
    inbound: InboundService,
}

impl SchedulingServiceImpl {
    /// Creates the service on the shared application core with a scheduler of its own.
    ///
    /// Prefer [`with_scheduler`](Self::with_scheduler) with the scheduler of the object service: quotas and the
    /// remarks of answers are kept by the scheduler, and two schedulers would count separately.
    pub fn new(core: AppCore) -> Self {
        let scheduler = Arc::new(Scheduler::new(core.clone()));
        Self::with_scheduler(core, scheduler)
    }

    /// Creates the service with the scheduler that the object service uses.
    pub fn with_scheduler(core: AppCore, scheduler: Arc<Scheduler>) -> Self {
        let installed: Arc<dyn ObjectScheduler> = Arc::<Scheduler>::clone(&scheduler);
        Self {
            objects: ObjectServiceImpl::with_scheduler(core.clone(), installed),
            rsvp: RsvpService::new(core.clone()),
            inbound: InboundService::new(core.clone()),
            scheduler,
            core,
        }
    }

    /// The shared application core: ports, configuration and limits.
    pub fn core(&self) -> &AppCore {
        &self.core
    }
}

#[async_trait]
impl SchedulingService for SchedulingServiceImpl {
    async fn free_busy(&self, ctx: &RequestContext, request: FreeBusyRequest) -> AppResult<FreeBusyResult> {
        self.query_free_busy(ctx, request).await
    }

    async fn find_free_slots(&self, ctx: &RequestContext, request: FindSlotsRequest) -> AppResult<FindSlotsResult> {
        self.search_free_slots(ctx, request).await
    }

    async fn outbox_post(
        &self,
        ctx: &RequestContext,
        principal: &PrincipalName,
        body: String,
    ) -> AppResult<ScheduleResponse> {
        self.post_outbox(ctx, principal, body).await
    }

    async fn inbox_list(&self, ctx: &RequestContext, principal: &PrincipalName) -> AppResult<Vec<InboxItemView>> {
        self.list_inbox(ctx, principal).await
    }

    async fn inbox_get(&self, ctx: &RequestContext, path: &ResourcePath) -> AppResult<InboxItemView> {
        self.read_inbox_item(ctx, path).await
    }

    async fn inbox_get_many(
        &self,
        ctx: &RequestContext,
        inbox: &ResourcePath,
        paths: Vec<ResourcePath>,
        spec: &CalendarDataSpec,
    ) -> AppResult<Vec<InboxEntry>> {
        self.read_inbox_items(ctx, inbox, paths, spec).await
    }

    async fn inbox_delete(&self, ctx: &RequestContext, path: &ResourcePath) -> AppResult<()> {
        self.delete_inbox_item(ctx, path).await
    }

    async fn respond(
        &self,
        ctx: &RequestContext,
        object: ObjectRef,
        response: InvitationResponse,
    ) -> AppResult<EventView> {
        self.respond_to_invitation(ctx, object, response).await
    }

    async fn inbound_itip(&self, ctx: &RequestContext, request: InboundItipRequest) -> AppResult<InboundItipResponse> {
        self.inbound.receive(ctx, request).await
    }

    async fn rsvp_page(&self, ctx: &RequestContext) -> AppResult<RenderedPage> {
        self.rsvp.page(ctx).await
    }

    async fn rsvp_answer(&self, ctx: &RequestContext, answer: RsvpAnswer, csrf: CsrfToken) -> AppResult<RenderedPage> {
        self.rsvp.answer(ctx, answer, csrf).await
    }
}
