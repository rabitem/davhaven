//! The services the fake does not implement: every method answers `unsupported`.
//!
//! The fake covers principals, calendars, objects and authentication. Protocol tests that need tenants, sharing,
//! scheduling, credentials, feeds, webhooks, provider accounts, audit, the outbox, assets or idempotency run against the
//! real application (`testkit`).

use async_trait::async_trait;
use davhaven_app::error::{AppError, AppResult};
use davhaven_app::services::{
    AssetService, AuditFilter, AuditService, CalendarRef, CallbackParams, ClientConfigKind, ClientConfigResponse,
    Conditional, Conditions, CredentialService, CsrfToken, ExternalAccountService, FeedResponse, FeedService,
    FindSlotsRequest, FindSlotsResult, FreeBusyRequest, FreeBusyResult, GrantSpec, IdempotencyKey, IdempotencyOutcome,
    IdempotencyService, IdempotencyState, InboxItemView, InvitationResponse, InviteReply, InviteReplyOutcome,
    MergePatch, NotificationView, ObjectRef, OutboxFilter, OutboxService, PageRequest, RenderedPage, RsvpAnswer,
    ScheduleResponse, SchedulingService, ShareItemResult, ShareRequest, SharingService, StaticAsset, TenantService,
    TenantSpec, Upserted, WebhookService,
};
use davhaven_domain::{
    CredentialId, DeliveryId, ExternalAccountId, OutboxId, PrincipalName, RequestContext, ResourcePath, TenantSlug,
    TokenId, WebhookId,
};
use davhaven_wire::{
    ApiTokenCreate, ApiTokenCreated, ApiTokenView, AppPasswordCreate, AppPasswordCreated, AppPasswordView,
    AuditEventView, AuthorizationUrl, DeliveryView, EventView, ExternalAccountView, FeedTokenCreate, FeedTokenCreated,
    FeedTokenView, GrantView, InboundItipRequest, InboundItipResponse, OutboxItemView, Page, ProviderView, TenantView,
    WebhookCreate, WebhookCreated, WebhookSecretRotated, WebhookView,
};

/// Answers `unsupported` for every method of every service trait it implements.
#[derive(Debug, Clone, Copy, Default)]
pub struct Unsupported;

#[async_trait]
impl TenantService for Unsupported {
    async fn list(&self, _ctx: &RequestContext, _page: PageRequest) -> AppResult<Page<TenantView>> {
        Err(AppError::unsupported())
    }

    async fn get(&self, _ctx: &RequestContext, _slug: &TenantSlug) -> AppResult<TenantView> {
        Err(AppError::unsupported())
    }

    async fn upsert(
        &self,
        _ctx: &RequestContext,
        _spec: TenantSpec,
        _conditions: Conditions,
    ) -> AppResult<Upserted<TenantView>> {
        Err(AppError::unsupported())
    }

    async fn patch(
        &self,
        _ctx: &RequestContext,
        _slug: &TenantSlug,
        _patch: MergePatch,
        _conditions: Conditions,
    ) -> AppResult<TenantView> {
        Err(AppError::unsupported())
    }

    async fn delete(&self, _ctx: &RequestContext, _slug: &TenantSlug, _conditions: Conditions) -> AppResult<()> {
        Err(AppError::unsupported())
    }
}

#[async_trait]
impl SharingService for Unsupported {
    async fn share(
        &self,
        _ctx: &RequestContext,
        _collection: &ResourcePath,
        _request: ShareRequest,
    ) -> AppResult<Vec<ShareItemResult>> {
        Err(AppError::unsupported())
    }

    async fn reply_invite(
        &self,
        _ctx: &RequestContext,
        _home: &ResourcePath,
        _reply: InviteReply,
    ) -> AppResult<InviteReplyOutcome> {
        Err(AppError::unsupported())
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
        _principal: &PrincipalName,
    ) -> AppResult<Vec<NotificationView>> {
        Err(AppError::unsupported())
    }

    async fn get_notification(&self, _ctx: &RequestContext, _path: &ResourcePath) -> AppResult<NotificationView> {
        Err(AppError::unsupported())
    }

    async fn delete_notification(&self, _ctx: &RequestContext, _path: &ResourcePath) -> AppResult<()> {
        Err(AppError::unsupported())
    }
}

#[async_trait]
impl SchedulingService for Unsupported {
    async fn free_busy(&self, _ctx: &RequestContext, _request: FreeBusyRequest) -> AppResult<FreeBusyResult> {
        Err(AppError::unsupported())
    }

    async fn find_free_slots(&self, _ctx: &RequestContext, _request: FindSlotsRequest) -> AppResult<FindSlotsResult> {
        Err(AppError::unsupported())
    }

    async fn outbox_post(
        &self,
        _ctx: &RequestContext,
        _principal: &PrincipalName,
        _body: String,
    ) -> AppResult<ScheduleResponse> {
        Err(AppError::unsupported())
    }

    async fn inbox_list(&self, _ctx: &RequestContext, _principal: &PrincipalName) -> AppResult<Vec<InboxItemView>> {
        Err(AppError::unsupported())
    }

    async fn inbox_get(&self, _ctx: &RequestContext, _path: &ResourcePath) -> AppResult<InboxItemView> {
        Err(AppError::unsupported())
    }

    async fn inbox_delete(&self, _ctx: &RequestContext, _path: &ResourcePath) -> AppResult<()> {
        Err(AppError::unsupported())
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

#[async_trait]
impl CredentialService for Unsupported {
    async fn list_app_passwords(
        &self,
        _ctx: &RequestContext,
        _principal: &PrincipalName,
        _page: PageRequest,
    ) -> AppResult<Page<AppPasswordView>> {
        Err(AppError::unsupported())
    }

    async fn create_app_password(
        &self,
        _ctx: &RequestContext,
        _principal: &PrincipalName,
        _request: AppPasswordCreate,
    ) -> AppResult<AppPasswordCreated> {
        Err(AppError::unsupported())
    }

    async fn revoke_app_password(
        &self,
        _ctx: &RequestContext,
        _principal: &PrincipalName,
        _id: CredentialId,
    ) -> AppResult<()> {
        Err(AppError::unsupported())
    }

    async fn list_api_tokens(&self, _ctx: &RequestContext, _page: PageRequest) -> AppResult<Page<ApiTokenView>> {
        Err(AppError::unsupported())
    }

    async fn create_api_token(&self, _ctx: &RequestContext, _request: ApiTokenCreate) -> AppResult<ApiTokenCreated> {
        Err(AppError::unsupported())
    }

    async fn revoke_api_token(&self, _ctx: &RequestContext, _id: TokenId) -> AppResult<()> {
        Err(AppError::unsupported())
    }

    async fn list_feed_tokens(
        &self,
        _ctx: &RequestContext,
        _principal: &PrincipalName,
        _page: PageRequest,
    ) -> AppResult<Page<FeedTokenView>> {
        Err(AppError::unsupported())
    }

    async fn create_feed_token(
        &self,
        _ctx: &RequestContext,
        _principal: &PrincipalName,
        _request: FeedTokenCreate,
    ) -> AppResult<FeedTokenCreated> {
        Err(AppError::unsupported())
    }

    async fn revoke_feed_token(
        &self,
        _ctx: &RequestContext,
        _principal: &PrincipalName,
        _id: TokenId,
    ) -> AppResult<()> {
        Err(AppError::unsupported())
    }

    async fn rotate_feed_token(
        &self,
        _ctx: &RequestContext,
        _principal: &PrincipalName,
        _id: TokenId,
    ) -> AppResult<FeedTokenCreated> {
        Err(AppError::unsupported())
    }

    async fn client_config(
        &self,
        _ctx: &RequestContext,
        _principal: &PrincipalName,
        _kind: ClientConfigKind,
    ) -> AppResult<ClientConfigResponse> {
        Err(AppError::unsupported())
    }
}

#[async_trait]
impl FeedService for Unsupported {
    async fn render(&self, _ctx: &RequestContext, _conditional: Conditional) -> AppResult<FeedResponse> {
        Err(AppError::unsupported())
    }
}

#[async_trait]
impl WebhookService for Unsupported {
    async fn create(&self, _ctx: &RequestContext, _request: WebhookCreate) -> AppResult<WebhookCreated> {
        Err(AppError::unsupported())
    }

    async fn list(&self, _ctx: &RequestContext, _page: PageRequest) -> AppResult<Page<WebhookView>> {
        Err(AppError::unsupported())
    }

    async fn get(&self, _ctx: &RequestContext, _id: WebhookId) -> AppResult<WebhookView> {
        Err(AppError::unsupported())
    }

    async fn patch(
        &self,
        _ctx: &RequestContext,
        _id: WebhookId,
        _patch: MergePatch,
        _conditions: Conditions,
    ) -> AppResult<WebhookView> {
        Err(AppError::unsupported())
    }

    async fn delete(&self, _ctx: &RequestContext, _id: WebhookId) -> AppResult<()> {
        Err(AppError::unsupported())
    }

    async fn rotate_secret(&self, _ctx: &RequestContext, _id: WebhookId) -> AppResult<WebhookSecretRotated> {
        Err(AppError::unsupported())
    }

    async fn ping(&self, _ctx: &RequestContext, _id: WebhookId) -> AppResult<DeliveryView> {
        Err(AppError::unsupported())
    }

    async fn deliveries(
        &self,
        _ctx: &RequestContext,
        _id: WebhookId,
        _page: PageRequest,
    ) -> AppResult<Page<DeliveryView>> {
        Err(AppError::unsupported())
    }

    async fn redeliver(&self, _ctx: &RequestContext, _id: WebhookId, _delivery: DeliveryId) -> AppResult<DeliveryView> {
        Err(AppError::unsupported())
    }
}

#[async_trait]
impl ExternalAccountService for Unsupported {
    async fn providers(&self, _ctx: &RequestContext) -> AppResult<Vec<ProviderView>> {
        Err(AppError::unsupported())
    }

    async fn start(
        &self,
        _ctx: &RequestContext,
        _provider: &str,
        _principal: &PrincipalName,
    ) -> AppResult<AuthorizationUrl> {
        Err(AppError::unsupported())
    }

    async fn complete(
        &self,
        _ctx: &RequestContext,
        _provider: &str,
        _params: CallbackParams,
    ) -> AppResult<RenderedPage> {
        Err(AppError::unsupported())
    }

    async fn list(&self, _ctx: &RequestContext, _page: PageRequest) -> AppResult<Page<ExternalAccountView>> {
        Err(AppError::unsupported())
    }

    async fn delete(&self, _ctx: &RequestContext, _id: ExternalAccountId) -> AppResult<()> {
        Err(AppError::unsupported())
    }
}

#[async_trait]
impl AuditService for Unsupported {
    async fn list(
        &self,
        _ctx: &RequestContext,
        _filter: AuditFilter,
        _page: PageRequest,
    ) -> AppResult<Page<AuditEventView>> {
        Err(AppError::unsupported())
    }
}

#[async_trait]
impl OutboxService for Unsupported {
    async fn list(
        &self,
        _ctx: &RequestContext,
        _filter: OutboxFilter,
        _page: PageRequest,
    ) -> AppResult<Page<OutboxItemView>> {
        Err(AppError::unsupported())
    }

    async fn retry(&self, _ctx: &RequestContext, _id: OutboxId) -> AppResult<OutboxItemView> {
        Err(AppError::unsupported())
    }
}

#[async_trait]
impl IdempotencyService for Unsupported {
    async fn begin(
        &self,
        _ctx: &RequestContext,
        _key: IdempotencyKey,
        _fingerprint: String,
    ) -> AppResult<IdempotencyState> {
        Err(AppError::unsupported())
    }

    async fn complete(
        &self,
        _ctx: &RequestContext,
        _key: &IdempotencyKey,
        _outcome: IdempotencyOutcome,
    ) -> AppResult<()> {
        Err(AppError::unsupported())
    }
}

#[async_trait]
impl AssetService for Unsupported {
    async fn get(&self, _ctx: &RequestContext, _theme: &str, _file: &str) -> AppResult<StaticAsset> {
        Err(AppError::unsupported())
    }
}
