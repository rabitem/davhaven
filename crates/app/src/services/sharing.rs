//! Calendar sharing: CalendarServer invitations and replies, API grants and notifications.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::{
    CalendarUserAddress, ETag, GrantAccess, NotificationId, NotificationKind, PrincipalName, PrivilegeSet,
    RequestContext, ResourcePath, Uid,
};
use davhaven_wire::{GrantView, GrantWrite, Page};

use super::calendars::CalendarRef;
use super::common::{Conditions, PageRequest, Upserted};
use super::objects::WritePrecondition;
use crate::error::{AppError, AppResult};

/// One sharee of a `CS:share` request (`CS:set`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareeSet {
    /// The sharee's calendar user address; only `mailto:` addresses of principals of the same tenant can be
    /// shared with.
    pub address: CalendarUserAddress,
    /// The sharee's display name as the owner's client shows it.
    pub common_name: Option<String>,
    /// The summary shown in the invitation.
    pub summary: Option<String>,
    /// The access to grant.
    pub access: GrantAccess,
}

/// The body of a `CS:share` POST on a calendar collection.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ShareRequest {
    /// Sharees to invite or whose access changes (`CS:set`).
    pub set: Vec<ShareeSet>,
    /// Sharees to remove (`CS:remove`).
    pub remove: Vec<CalendarUserAddress>,
}

/// The result for one sharee of a share request.
#[derive(Debug)]
pub struct ShareItemResult {
    /// The sharee's address as the request named it.
    pub address: CalendarUserAddress,
    /// `None` when the change was applied; otherwise why it was not (for example `Forbidden` with
    /// `invalid-sharee` for external addresses). Failures of single sharees do not fail the request.
    pub error: Option<AppError>,
}

/// The `CS:invite-reply` POST of a sharee to their calendar home.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteReply {
    /// The UID of the invitation that is answered (`CS:in-reply-to`).
    pub in_reply_to: Uid,
    /// Whether the invitation is accepted (`CS:invite-accepted`) or declined (`CS:invite-declined`).
    pub accepted: bool,
    /// The calendar being answered (`CS:hosturl`).
    pub host_url: Option<ResourcePath>,
    /// The sharee's summary of the invitation.
    pub summary: Option<String>,
}

/// The answer to an invitation reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteReplyOutcome {
    /// The invitation was accepted; the calendar is bound at this collection in the sharee's home
    /// (`CS:shared-as`).
    Accepted {
        /// The new binding.
        shared_as: ResourcePath,
    },
    /// The invitation was declined.
    Declined,
}

/// The natural keys and the body of a grant `PUT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantSpec {
    /// The shared calendar.
    pub calendar: CalendarRef,
    /// The user, group or service principal that is granted access.
    pub grantee: PrincipalName,
    /// The request body.
    pub body: GrantWrite,
}

/// A notification resource in a principal's notification collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationView {
    /// The notification resource.
    pub path: ResourcePath,
    /// The notification id.
    pub id: NotificationId,
    /// The UID of the invitation the notification refers to.
    pub uid: Uid,
    /// The strong entity tag of `body_xml`.
    pub etag: ETag,
    /// Invitation or invitation reply.
    pub kind: NotificationKind,
    /// The notification XML as served.
    pub body_xml: String,
    /// The size of `body_xml` in bytes (`DAV:getcontentlength`).
    pub size: u64,
    /// What the caller may do with the notification (`DAV:current-user-privilege-set`), derived by the application
    /// from the access the caller has to the collection: the DAV layer renders it and decides nothing.
    pub privileges: PrivilegeSet,
    /// When the notification was created.
    pub created_at: DateTime<Utc>,
    /// When the notification was last written. The application rewrites an invitation in place when the access of
    /// the sharee changes, so this is the date that goes with the entity tag (`Last-Modified`).
    pub updated_at: DateTime<Utc>,
}

/// Sharing and grants (PLAN 2.9).
#[async_trait]
pub trait SharingService: Send + Sync {
    /// Applies a `CS:share` request: invites or changes sharees and removes others. Only the owner and
    /// administrators may share; managed calendars cannot be shared through DAV.
    ///
    /// # Errors
    ///
    /// `NotFound` for invisible calendars, `Forbidden` without the `share` privilege or when sharing is
    /// disabled. Problems with single sharees are reported per item.
    async fn share(
        &self,
        ctx: &RequestContext,
        collection: &ResourcePath,
        request: ShareRequest,
    ) -> AppResult<Vec<ShareItemResult>>;

    /// Answers an invitation (`CS:invite-reply`): accepting binds the calendar in the sharee's home and notifies
    /// the owner; declining marks the grant declined.
    ///
    /// # Errors
    ///
    /// `NotFound` for unknown or foreign invitations, `Forbidden` for other principals' homes.
    async fn reply_invite(
        &self,
        ctx: &RequestContext,
        home: &ResourcePath,
        reply: InviteReply,
    ) -> AppResult<InviteReplyOutcome>;

    /// Lists the grants of a calendar ordered by id (management API).
    ///
    /// # Errors
    ///
    /// `NotFound`, `Forbidden`, `Invalid` for a bad cursor.
    async fn list_grants(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        page: PageRequest,
    ) -> AppResult<Page<GrantView>>;

    /// Creates or replaces the grant of one grantee (management API). Grants made through the API are
    /// effective immediately; the last write wins between the API and DAV sharing.
    ///
    /// # Errors
    ///
    /// `NotFound` for unknown calendars and grantees, `PreconditionFailed`, `Invalid` for grantees outside the
    /// tenant, `Forbidden`.
    async fn put_grant(
        &self,
        ctx: &RequestContext,
        spec: GrantSpec,
        conditions: Conditions,
    ) -> AppResult<Upserted<GrantView>>;

    /// Removes the grant of one grantee (management API).
    ///
    /// # Errors
    ///
    /// `NotFound`, `PreconditionFailed`, `Forbidden`.
    async fn delete_grant(
        &self,
        ctx: &RequestContext,
        calendar: &CalendarRef,
        grantee: &PrincipalName,
        conditions: Conditions,
    ) -> AppResult<()>;

    /// Lists the notifications of a principal.
    ///
    /// # Errors
    ///
    /// `NotFound` for homes the caller cannot see.
    async fn list_notifications(
        &self,
        ctx: &RequestContext,
        principal: &PrincipalName,
    ) -> AppResult<Vec<NotificationView>>;

    /// Reads one notification.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn get_notification(&self, ctx: &RequestContext, path: &ResourcePath) -> AppResult<NotificationView>;

    /// Reads several notifications of one collection by path, in the order of `paths`: what `sync-collection`
    /// needs to read the members that changed without reading the whole collection (R14). A path that is not a
    /// notification of `collection`, or that names nothing, is left out. The collection is resolved with the tenant of
    /// the path (404 for other tenants' and other principals' collections) in one transaction.
    ///
    /// # Errors
    ///
    /// `NotFound` for collections the caller cannot see, `Forbidden` with `number-of-matches-within-limits` for more
    /// paths than `max_multiget_hrefs` allows. The default answers `Unsupported`.
    async fn get_notifications_many(
        &self,
        ctx: &RequestContext,
        collection: &ResourcePath,
        paths: Vec<ResourcePath>,
    ) -> AppResult<Vec<NotificationView>> {
        let _ = (ctx, collection, paths);
        // unsupported-allowed: SharingServiceImpl implements the method; the default serves test doubles.
        Err(AppError::unsupported())
    }

    /// Deletes one notification (clients do this after showing it).
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn delete_notification(&self, ctx: &RequestContext, path: &ResourcePath) -> AppResult<()>;

    /// [`delete_notification`](Self::delete_notification) under the conditional headers of the request, evaluated
    /// against the stored entity tag **in the transaction that deletes**: the application rewrites an invitation in
    /// place, so a condition checked before the deletion could remove a newer version.
    ///
    /// # Errors
    ///
    /// As [`delete_notification`](Self::delete_notification), and `PreconditionFailed` when a condition does not hold
    /// (`If-Match` with another tag, `If-None-Match: *`, any `If-Schedule-Tag-Match`: a notification has no schedule
    /// tag). The default deletes without conditions and answers `Unsupported` when there are some.
    async fn delete_notification_if(
        &self,
        ctx: &RequestContext,
        path: &ResourcePath,
        preconditions: WritePrecondition,
    ) -> AppResult<()> {
        if preconditions == WritePrecondition::none() {
            self.delete_notification(ctx, path).await
        } else {
            // unsupported-allowed: SharingServiceImpl implements the method; the default serves test doubles.
            Err(AppError::unsupported())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use davhaven_domain::{ErrorKind, RequestId, TenantId};
    use uuid::Uuid;

    use super::*;

    /// A sharing service that implements only what it must and counts the notifications it deletes.
    #[derive(Default)]
    struct Minimal {
        deleted: AtomicU32,
    }

    #[async_trait]
    impl SharingService for Minimal {
        async fn share(
            &self,
            _: &RequestContext,
            _: &ResourcePath,
            _: ShareRequest,
        ) -> AppResult<Vec<ShareItemResult>> {
            Err(AppError::unsupported())
        }

        async fn reply_invite(
            &self,
            _: &RequestContext,
            _: &ResourcePath,
            _: InviteReply,
        ) -> AppResult<InviteReplyOutcome> {
            Err(AppError::unsupported())
        }

        async fn list_grants(&self, _: &RequestContext, _: &CalendarRef, _: PageRequest) -> AppResult<Page<GrantView>> {
            Err(AppError::unsupported())
        }

        async fn put_grant(&self, _: &RequestContext, _: GrantSpec, _: Conditions) -> AppResult<Upserted<GrantView>> {
            Err(AppError::unsupported())
        }

        async fn delete_grant(
            &self,
            _: &RequestContext,
            _: &CalendarRef,
            _: &PrincipalName,
            _: Conditions,
        ) -> AppResult<()> {
            Err(AppError::unsupported())
        }

        async fn list_notifications(&self, _: &RequestContext, _: &PrincipalName) -> AppResult<Vec<NotificationView>> {
            Err(AppError::unsupported())
        }

        async fn get_notification(&self, _: &RequestContext, _: &ResourcePath) -> AppResult<NotificationView> {
            Err(AppError::unsupported())
        }

        async fn delete_notification(&self, _: &RequestContext, _: &ResourcePath) -> AppResult<()> {
            self.deleted.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn ctx() -> RequestContext {
        RequestContext::internal(
            TenantId::from_uuid(Uuid::from_u128(1)),
            RequestId::from_uuid(Uuid::from_u128(2)),
        )
    }

    #[test]
    fn share_requests_default_to_empty() {
        let request = ShareRequest::default();
        assert!(request.set.is_empty() && request.remove.is_empty());
    }

    #[tokio::test]
    async fn a_service_that_cannot_evaluate_conditions_never_deletes_under_them() {
        // A condition that is not evaluated in the deleting transaction could remove a newer version of an invitation:
        // the provided method deletes only when there is no condition and refuses everything else.
        let service = Minimal::default();
        let item = ResourcePath::parse("/dav/calendars/acme/anna/notifications/invite-1.xml").unwrap();
        service
            .delete_notification_if(&ctx(), &item, WritePrecondition::none())
            .await
            .unwrap();
        assert_eq!(service.deleted.load(Ordering::SeqCst), 1);
        for conditions in [
            WritePrecondition::if_match(ETag::from_bytes(b"x")),
            WritePrecondition::create_only(),
        ] {
            let error = service
                .delete_notification_if(&ctx(), &item, conditions)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Unsupported);
        }
        assert_eq!(service.deleted.load(Ordering::SeqCst), 1, "nothing more was deleted");
        let collection = ResourcePath::parse("/dav/calendars/acme/anna/notifications/").unwrap();
        let many = service
            .get_notifications_many(&ctx(), &collection, vec![item])
            .await
            .unwrap_err();
        assert_eq!(many.kind(), ErrorKind::Unsupported);
    }
}
