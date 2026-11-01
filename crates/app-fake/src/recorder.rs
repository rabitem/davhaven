//! A double of the sharing and scheduling services that records what a protocol layer hands it.
//!
//! The fake application has no sharing and no scheduling: it answers `unsupported`, which the DAV layer renders as a
//! 501. A test that sees a 501 only knows that *something* reached the service, not what, and the DAV layer itself
//! answers 501 for a few requests it cannot express. The [`Recorder`] answers like a service with nothing in it (an
//! empty inbox, no notifications, every sharee applied, a free-busy answer without recipients) and keeps every call
//! with the arguments it got, so that a test says exactly what the layer under test handed on (the request as it read
//! it, the owner of an outbox, the paths of a bulk read, the conditions of a deletion) and that a stranger's request
//! never reached the service.

use std::sync::{Arc, MutexGuard, PoisonError};

use async_trait::async_trait;
use davhaven_app::AppServices;
use davhaven_app::error::{AppError, AppResult};
use davhaven_app::services::{
    CalendarDataSpec, CalendarRef, Conditions, CsrfToken, FindSlotsRequest, FindSlotsResult, FreeBusyRequest,
    FreeBusyResult, GrantSpec, InboxEntry, InboxItemView, InvitationResponse, InviteReply, InviteReplyOutcome,
    NotificationView, ObjectRef, PageRequest, RenderedPage, RsvpAnswer, ScheduleResponse, SchedulingService,
    ShareItemResult, ShareRequest, SharingService, Upserted, WritePrecondition,
};
use davhaven_domain::{PrincipalName, RequestContext, ResourcePath};
use davhaven_wire::{EventView, GrantView, InboundItipRequest, InboundItipResponse, Page};

/// The state of a double is touched for an instant and never across an await.
#[expect(clippy::disallowed_types, reason = "a test double with synchronous accessors")]
type Mutex<T> = std::sync::Mutex<T>;

/// One call of a protocol layer on a service, with the arguments the service received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Handed {
    /// `SharingService::share`.
    Share {
        /// The calendar collection.
        collection: ResourcePath,
        /// What the layer read from the body.
        request: ShareRequest,
    },
    /// `SharingService::reply_invite`.
    ReplyInvite {
        /// The home.
        home: ResourcePath,
        /// What the layer read from the body.
        reply: InviteReply,
    },
    /// `SharingService::list_notifications`.
    ListNotifications(PrincipalName),
    /// `SharingService::get_notification`.
    GetNotification(ResourcePath),
    /// `SharingService::get_notifications_many`.
    GetNotificationsMany {
        /// The notification collection.
        collection: ResourcePath,
        /// The notifications asked for, in order.
        paths: Vec<ResourcePath>,
    },
    /// `SharingService::delete_notification` and `delete_notification_if`.
    DeleteNotification {
        /// The notification.
        path: ResourcePath,
        /// The conditions of the request.
        conditions: WritePrecondition,
    },
    /// `SchedulingService::outbox_post`.
    OutboxPost {
        /// The owner of the outbox.
        owner: PrincipalName,
        /// The message, as sent.
        body: String,
    },
    /// `SchedulingService::inbox_list`.
    InboxList(PrincipalName),
    /// `SchedulingService::inbox_get`.
    InboxGet(ResourcePath),
    /// `SchedulingService::inbox_get_many`.
    InboxGetMany {
        /// The inbox.
        inbox: ResourcePath,
        /// The items asked for, in order.
        paths: Vec<ResourcePath>,
        /// What the request asked for of the messages: whether they are wanted at all, and in which selection.
        spec: CalendarDataSpec,
    },
    /// `SchedulingService::inbox_delete`.
    InboxDelete(ResourcePath),
}

/// The recording double: answers like a service with nothing in it, and keeps what it was asked.
#[derive(Debug, Default)]
pub struct Recorder {
    calls: Mutex<Vec<Handed>>,
}

impl Recorder {
    /// Replaces the sharing and scheduling services of `services` with a new recorder and returns it.
    pub fn install(services: &mut AppServices) -> Arc<Self> {
        let recorder = Arc::new(Self::default());
        services.sharing = Arc::<Self>::clone(&recorder);
        services.scheduling = Arc::<Self>::clone(&recorder);
        recorder
    }

    fn locked(&self) -> MutexGuard<'_, Vec<Handed>> {
        self.calls.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn record(&self, call: Handed) {
        self.locked().push(call);
    }

    /// Everything the services were asked, in order.
    pub fn calls(&self) -> Vec<Handed> {
        self.locked().clone()
    }

    /// Forgets what was recorded.
    pub fn clear(&self) {
        self.locked().clear();
    }
}

#[async_trait]
impl SharingService for Recorder {
    async fn share(
        &self,
        _ctx: &RequestContext,
        collection: &ResourcePath,
        request: ShareRequest,
    ) -> AppResult<Vec<ShareItemResult>> {
        self.record(Handed::Share {
            collection: collection.clone(),
            request: request.clone(),
        });
        // Every item applied: the answer is a plain 200.
        Ok(request
            .set
            .iter()
            .map(|sharee| sharee.address.clone())
            .chain(request.remove.iter().cloned())
            .map(|address| ShareItemResult { address, error: None })
            .collect())
    }

    async fn reply_invite(
        &self,
        _ctx: &RequestContext,
        home: &ResourcePath,
        reply: InviteReply,
    ) -> AppResult<InviteReplyOutcome> {
        self.record(Handed::ReplyInvite {
            home: home.clone(),
            reply,
        });
        Ok(InviteReplyOutcome::Declined)
    }

    async fn list_grants(
        &self,
        _ctx: &RequestContext,
        _calendar: &CalendarRef,
        _page: PageRequest,
    ) -> AppResult<Page<GrantView>> {
        Err(AppError::unsupported())
    }

    async fn put_grant(
        &self,
        _ctx: &RequestContext,
        _spec: GrantSpec,
        _conditions: Conditions,
    ) -> AppResult<Upserted<GrantView>> {
        Err(AppError::unsupported())
    }

    async fn delete_grant(
        &self,
        _ctx: &RequestContext,
        _calendar: &CalendarRef,
        _grantee: &PrincipalName,
        _conditions: Conditions,
    ) -> AppResult<()> {
        Err(AppError::unsupported())
    }

    async fn list_notifications(
        &self,
        _ctx: &RequestContext,
        principal: &PrincipalName,
    ) -> AppResult<Vec<NotificationView>> {
        self.record(Handed::ListNotifications(principal.clone()));
        Ok(Vec::new())
    }

    async fn get_notification(&self, _ctx: &RequestContext, path: &ResourcePath) -> AppResult<NotificationView> {
        self.record(Handed::GetNotification(path.clone()));
        Err(AppError::not_found())
    }

    async fn get_notifications_many(
        &self,
        _ctx: &RequestContext,
        collection: &ResourcePath,
        paths: Vec<ResourcePath>,
    ) -> AppResult<Vec<NotificationView>> {
        self.record(Handed::GetNotificationsMany {
            collection: collection.clone(),
            paths,
        });
        Ok(Vec::new())
    }

    async fn delete_notification(&self, _ctx: &RequestContext, path: &ResourcePath) -> AppResult<()> {
        self.record(Handed::DeleteNotification {
            path: path.clone(),
            conditions: WritePrecondition::none(),
        });
        Ok(())
    }

    async fn delete_notification_if(
        &self,
        _ctx: &RequestContext,
        path: &ResourcePath,
        preconditions: WritePrecondition,
    ) -> AppResult<()> {
        self.record(Handed::DeleteNotification {
            path: path.clone(),
            conditions: preconditions,
        });
        Ok(())
    }
}

#[async_trait]
impl SchedulingService for Recorder {
    async fn free_busy(&self, _ctx: &RequestContext, _request: FreeBusyRequest) -> AppResult<FreeBusyResult> {
        Err(AppError::unsupported())
    }

    async fn find_free_slots(&self, _ctx: &RequestContext, _request: FindSlotsRequest) -> AppResult<FindSlotsResult> {
        Err(AppError::unsupported())
    }

    async fn outbox_post(
        &self,
        _ctx: &RequestContext,
        principal: &PrincipalName,
        body: String,
    ) -> AppResult<ScheduleResponse> {
        self.record(Handed::OutboxPost {
            owner: principal.clone(),
            body,
        });
        Ok(ScheduleResponse::default())
    }

    async fn inbox_list(&self, _ctx: &RequestContext, principal: &PrincipalName) -> AppResult<Vec<InboxItemView>> {
        self.record(Handed::InboxList(principal.clone()));
        Ok(Vec::new())
    }

    async fn inbox_get(&self, _ctx: &RequestContext, path: &ResourcePath) -> AppResult<InboxItemView> {
        self.record(Handed::InboxGet(path.clone()));
        Err(AppError::not_found())
    }

    async fn inbox_get_many(
        &self,
        _ctx: &RequestContext,
        inbox: &ResourcePath,
        paths: Vec<ResourcePath>,
        spec: &CalendarDataSpec,
    ) -> AppResult<Vec<InboxEntry>> {
        self.record(Handed::InboxGetMany {
            inbox: inbox.clone(),
            paths: paths.clone(),
            spec: spec.clone(),
        });
        Ok(paths.into_iter().map(InboxEntry::Missing).collect())
    }

    async fn inbox_delete(&self, _ctx: &RequestContext, path: &ResourcePath) -> AppResult<()> {
        self.record(Handed::InboxDelete(path.clone()));
        Ok(())
    }

    async fn respond(
        &self,
        _ctx: &RequestContext,
        _object: ObjectRef,
        _response: InvitationResponse,
    ) -> AppResult<EventView> {
        Err(AppError::unsupported())
    }

    async fn inbound_itip(
        &self,
        _ctx: &RequestContext,
        _request: InboundItipRequest,
    ) -> AppResult<InboundItipResponse> {
        Err(AppError::unsupported())
    }

    async fn rsvp_page(&self, _ctx: &RequestContext) -> AppResult<RenderedPage> {
        Err(AppError::unsupported())
    }

    async fn rsvp_answer(
        &self,
        _ctx: &RequestContext,
        _answer: RsvpAnswer,
        _csrf: CsrfToken,
    ) -> AppResult<RenderedPage> {
        Err(AppError::unsupported())
    }
}
