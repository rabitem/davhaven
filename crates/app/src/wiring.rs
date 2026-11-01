//! `AppDeps` and the construction of `AppServices` from ports.
//!
//! The server builds the ports (through the plugin registry and directly for the pure ports), puts them into an
//! [`AppDeps`] together with the validated configuration and calls [`build`]. The result is the only thing the
//! protocol routers get. Every service is a struct in the module of the area that owns its behavior; this module
//! only wires them.

use core::fmt;
use std::sync::Arc;

use davhaven_domain::{Limits, PublicUrls};
use davhaven_ports::{
    Authenticator, Clock, ContentScanner, CredentialHasher, Database, EventSink, HttpClient, IdGenerator, KeyRing,
    MailTransport, OutboxHandler, ProfileSigner, Provider, RateLimiter, SchedulingPolicy, SecretSealer,
    TemplateRenderer,
};

use crate::assets::AssetServiceImpl;
use crate::audit::AuditServiceImpl;
use crate::calendars::CalendarServiceImpl;
use crate::config::AppConfig;
use crate::credentials::{AuthServiceImpl, CredentialServiceImpl, TenantDirectory};
use crate::feeds::FeedServiceImpl;
use crate::idempotency::IdempotencyServiceImpl;
use crate::oauth::ExternalAccountServiceImpl;
use crate::objects::ObjectServiceImpl;
use crate::outbox::{OutboxServiceImpl, WebhookServiceImpl};
use crate::principals::PrincipalServiceImpl;
use crate::provisioning::TenantServiceImpl;
use crate::scheduling::{Scheduler, SchedulingServiceImpl};
use crate::services::{AppClock, AppServices};
use crate::sharing::SharingServiceImpl;

/// Everything the application layer needs from the outside: the ports, the public URLs, the limits and the
/// application configuration.
///
/// The pure ports (`clock`, `ids`, `keyring`, `sealer`, `hasher`) are injected directly; the others come from the
/// plugin registry. All of them are shared handles, so cloning the deps is cheap.
#[derive(Clone)]
pub struct AppDeps {
    /// The time source. Logic-relevant timestamps always come from here, never from the database.
    pub clock: Arc<dyn Clock>,
    /// The id and randomness source.
    pub ids: Arc<dyn IdGenerator>,
    /// The key ring (signed cursors, CSRF tokens, credential peppers, cache keys).
    pub keyring: Arc<dyn KeyRing>,
    /// The secret sealer (webhook secrets, OAuth tokens, PKCE verifiers).
    pub sealer: Arc<dyn SecretSealer>,
    /// The credential hasher.
    pub hasher: Arc<dyn CredentialHasher>,
    /// The database.
    pub database: Arc<dyn Database>,
    /// The outbound HTTP client with the egress policy.
    pub http: Arc<dyn HttpClient>,
    /// The mail transport.
    pub mail: Arc<dyn MailTransport>,
    /// The template renderer for mail and web pages.
    pub templates: Arc<dyn TemplateRenderer>,
    /// The rate limiter.
    pub rate_limiter: Arc<dyn RateLimiter>,
    /// The scheduling policy.
    pub scheduling_policy: Arc<dyn SchedulingPolicy>,
    /// The authenticator chain, in order.
    pub authenticators: Vec<Arc<dyn Authenticator>>,
    /// The event sinks every domain event is delivered to.
    pub event_sinks: Vec<Arc<dyn EventSink>>,
    /// The outbox handlers that adapters contribute (`webhook`); the application adds its own (`imip`,
    /// `internal_delivery`, `domain_event`).
    pub outbox_handlers: Vec<Arc<dyn OutboxHandler>>,
    /// The calendar providers that are compiled in and selected.
    pub providers: Vec<Arc<dyn Provider>>,
    /// The content scanners applied to inline binary attachments.
    pub content_scanners: Vec<Arc<dyn ContentScanner>>,
    /// The signer of Apple configuration profiles, when the deployment provides a certificate (`None`: profiles are not
    /// signed). A pure port like the key ring, built from `[security.profile_signing]` and injected directly.
    pub profile_signer: Option<Arc<dyn ProfileSigner>>,
    /// Absolute URLs for mails, feeds and client configuration.
    pub urls: PublicUrls,
    /// The configured limits.
    pub limits: Limits,
    /// The application configuration.
    pub config: AppConfig,
}

impl fmt::Debug for AppDeps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppDeps")
            .field("authenticators", &self.authenticators.len())
            .field("event_sinks", &self.event_sinks.len())
            .field("outbox_handlers", &self.outbox_handlers.len())
            .field("providers", &self.providers.len())
            .field("content_scanners", &self.content_scanners.len())
            .field("profile_signer", &self.profile_signer.is_some())
            .field("urls", &self.urls)
            .finish_non_exhaustive()
    }
}

/// The shared state of the service implementations: the [`AppDeps`] behind one reference count.
///
/// Every service struct holds an `AppCore`; cloning it is cheap.
#[derive(Clone)]
pub struct AppCore {
    deps: Arc<AppDeps>,
    tenants: Arc<TenantDirectory>,
}

impl AppCore {
    /// Wraps the deps.
    pub fn new(deps: AppDeps) -> Self {
        Self {
            deps: Arc::new(deps),
            tenants: Arc::new(TenantDirectory::default()),
        }
    }

    /// The ports, URLs, limits and configuration.
    pub fn deps(&self) -> &AppDeps {
        &self.deps
    }

    /// The short-lived memory of the status of tenants that authentication consults.
    pub(crate) fn tenants(&self) -> &TenantDirectory {
        &self.tenants
    }

    /// The provider `name` that the deployment selected, whether it is switched on or not.
    pub(crate) fn provider(&self, name: &str) -> Option<&Arc<dyn Provider>> {
        self.deps.providers.iter().find(|provider| provider.name() == name)
    }
}

impl fmt::Debug for AppCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppCore")
            .field("deps", &self.deps)
            .finish_non_exhaustive()
    }
}

/// Wires the real service implementations onto the ports.
///
/// Until a service implements a method, it answers `AppError::unsupported()`; `xtask unsupported` lists
/// every remaining call. The object service and the scheduling service share one [`Scheduler`], which does the
/// server-side scheduling inside the transaction of every write.
pub fn build(deps: AppDeps) -> AppServices {
    build_from_core(&AppCore::new(deps))
}

/// Wires the service implementations onto an existing [`AppCore`].
///
/// The server builds the services and the workers of the application (`workers::build`) from one core, so that
/// the state the core holds (the memory of tenant status that authentication consults and provisioning
/// invalidates) is shared between them and cannot drift apart.
pub fn build_from_core(core: &AppCore) -> AppServices {
    // One scheduler serves the object write path and the scheduling service: it keeps the quotas of external
    // recipients and the remarks of answers, which both have to see.
    let scheduler = Arc::new(Scheduler::new(core.clone()));
    AppServices {
        auth: Arc::new(AuthServiceImpl::new(core.clone())),
        tenants: Arc::new(TenantServiceImpl::new(core.clone())),
        principals: Arc::new(PrincipalServiceImpl::new(core.clone())),
        calendars: Arc::new(CalendarServiceImpl::new(core.clone())),
        objects: Arc::new(ObjectServiceImpl::with_scheduler(
            core.clone(),
            Arc::<Scheduler>::clone(&scheduler),
        )),
        sharing: Arc::new(SharingServiceImpl::new(core.clone())),
        scheduling: Arc::new(SchedulingServiceImpl::with_scheduler(core.clone(), scheduler)),
        credentials: Arc::new(CredentialServiceImpl::new(core.clone())),
        feeds: Arc::new(FeedServiceImpl::new(core.clone())),
        webhooks: Arc::new(WebhookServiceImpl::new(core.clone())),
        external_accounts: Arc::new(ExternalAccountServiceImpl::new(core.clone())),
        audit: Arc::new(AuditServiceImpl::new(core.clone())),
        outbox: Arc::new(OutboxServiceImpl::new(core.clone())),
        assets: Arc::new(AssetServiceImpl::new(core.clone())),
        idempotency: Arc::new(IdempotencyServiceImpl::new(core.clone())),
        urls: core.deps().urls.clone(),
        limits: core.deps().limits.clone(),
        clock: {
            let clock = Arc::clone(&core.deps().clock);
            AppClock::new(move || clock.now())
        },
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use davhaven_domain::{
        CalendarUserAddress, ErrorKind, OutgoingMail, PartStat, PrincipalName, RequestContext, RequestId, TenantId,
    };
    use davhaven_ports::testing::{FixedHasher, FixedKeyRing, ManualClock, PlainSealer, SeqIds};
    use davhaven_ports::{
        AuthHint, AuthOutcome, FreeBusy, Invite, OutboundRequest, OutboundResponse, PolicyTenant, PortError,
        PresentedCredential, RateDecision, RateKey, RenderRequest, Rendered, ResourceRequest, SendReceipt, StoreError,
        TemplateName, TxMode,
    };
    use davhaven_wire::{Page, PrincipalView};
    use url::Url;
    use uuid::Uuid;

    use super::*;
    use crate::services::{
        AuditFilter, Conditions, MergePatch, OutboxFilter, PageRequest, PrincipalFilter, PrincipalSpec,
    };

    struct NoDatabase;

    #[async_trait]
    impl Database for NoDatabase {
        async fn begin(&self, _tenant: TenantId, _mode: TxMode) -> Result<Box<dyn davhaven_ports::Tx>, StoreError> {
            Err(StoreError::Unavailable)
        }

        async fn begin_system(&self) -> Result<Box<dyn davhaven_ports::SystemTx>, StoreError> {
            Err(StoreError::Unavailable)
        }

        async fn health(&self) -> davhaven_ports::Health {
            davhaven_ports::Health::Unhealthy("test double".to_owned())
        }
    }

    struct NoHttp;

    #[async_trait]
    impl HttpClient for NoHttp {
        async fn send(&self, _request: OutboundRequest) -> Result<OutboundResponse, PortError> {
            Err(PortError::unsupported())
        }
    }

    struct NoMail;

    #[async_trait]
    impl MailTransport for NoMail {
        async fn send(&self, _mail: &OutgoingMail) -> Result<SendReceipt, PortError> {
            Err(PortError::unsupported())
        }
    }

    struct NoTemplates;

    #[async_trait]
    impl TemplateRenderer for NoTemplates {
        async fn render(&self, _request: RenderRequest) -> Result<Rendered, PortError> {
            Err(PortError::unsupported())
        }

        fn catalog(&self) -> Vec<TemplateName> {
            Vec::new()
        }
    }

    struct AllowAll;

    #[async_trait]
    impl RateLimiter for AllowAll {
        async fn check(&self, _key: &RateKey, _cost: u32) -> Result<RateDecision, PortError> {
            Ok(RateDecision::allow(u32::MAX))
        }
    }

    struct NeverAuto;

    #[async_trait]
    impl SchedulingPolicy for NeverAuto {
        async fn auto_add(&self, _invite: &Invite) -> bool {
            false
        }

        async fn resource_reply(&self, _request: &ResourceRequest, _free_busy: &FreeBusy) -> Option<PartStat> {
            None
        }

        async fn external_allowed(&self, _tenant: &PolicyTenant, _address: &CalendarUserAddress) -> bool {
            false
        }
    }

    struct NoAuthenticator;

    #[async_trait]
    impl Authenticator for NoAuthenticator {
        async fn authenticate(
            &self,
            _credential: &PresentedCredential,
            _hint: &AuthHint,
        ) -> Result<AuthOutcome, PortError> {
            Ok(AuthOutcome::NotApplicable)
        }
    }

    fn deps() -> AppDeps {
        AppDeps {
            clock: Arc::new(ManualClock::default()),
            ids: Arc::new(SeqIds::new()),
            keyring: Arc::new(FixedKeyRing::default()),
            sealer: Arc::new(PlainSealer),
            hasher: Arc::new(FixedHasher::default()),
            database: Arc::new(NoDatabase),
            http: Arc::new(NoHttp),
            mail: Arc::new(NoMail),
            templates: Arc::new(NoTemplates),
            rate_limiter: Arc::new(AllowAll),
            scheduling_policy: Arc::new(NeverAuto),
            authenticators: vec![Arc::new(NoAuthenticator)],
            event_sinks: Vec::new(),
            outbox_handlers: Vec::new(),
            providers: Vec::new(),
            content_scanners: Vec::new(),
            profile_signer: None,
            urls: PublicUrls::new(Url::parse("https://cal.example.org").unwrap()).unwrap(),
            limits: Limits::default(),
            config: AppConfig::default(),
        }
    }

    fn ctx() -> RequestContext {
        RequestContext::internal(
            TenantId::from_uuid(Uuid::from_u128(1)),
            RequestId::from_uuid(Uuid::from_u128(2)),
        )
    }

    #[test]
    fn the_default_configuration_is_valid() {
        deps().config.validate().unwrap();
        deps().limits.validate().unwrap();
    }

    #[test]
    fn the_default_dispatcher_has_a_handler_for_every_kind_the_application_enqueues() {
        use davhaven_ports::outbox::kind;

        // The kinds the application itself writes into the outbox: invitations and answers by mail, deliveries above
        // the synchronous cap and domain events. (`webhook` records come from the adapter that handles them.)
        let core = AppCore::new(deps());
        let dispatcher = crate::outbox::new_dispatcher(&core, Vec::<Arc<dyn davhaven_ports::OutboxHandler>>::new());
        let kinds = dispatcher.kinds();
        for wanted in [kind::IMIP, kind::INTERNAL_DELIVERY, kind::DOMAIN_EVENT] {
            assert!(kinds.contains(&wanted), "no handler for `{wanted}`: {kinds:?}");
        }
    }

    #[test]
    fn build_carries_urls_and_limits() {
        let services = build(deps());
        assert_eq!(services.urls.public_base().as_str(), "https://cal.example.org/");
        assert_eq!(services.limits, Limits::default());
        let shown = format!("{services:?}");
        assert!(shown.contains("cal.example.org"), "{shown}");
        let cloned = services.clone();
        assert!(Arc::ptr_eq(&services.principals, &cloned.principals));
    }

    #[tokio::test]
    async fn implemented_services_reach_the_database_and_the_rest_answers_unsupported() {
        let services = build(deps());
        let ctx = ctx();
        let name = PrincipalName::parse("anna").unwrap();

        // The principal and audit services are implemented: the call reaches the (unreachable) database of this test.
        let error = services.principals.get(&ctx, &name).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Unavailable);

        let listed: Result<Page<PrincipalView>, _> = services
            .principals
            .list(&ctx, PrincipalFilter::default(), PageRequest::first())
            .await;
        assert_eq!(listed.unwrap_err().kind(), ErrorKind::Unavailable);

        let page = PageRequest::first();
        assert_eq!(
            services
                .audit
                .list(&ctx, AuditFilter::default(), page.clone())
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::Unavailable
        );
        assert_eq!(
            services.outbox.list_dead(&ctx, page).await.unwrap_err().kind(),
            ErrorKind::Unavailable
        );
        assert_eq!(
            services
                .outbox
                .list(&ctx, OutboxFilter::default(), PageRequest::first())
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::Unavailable
        );
        let patch = MergePatch::new(serde_json::json!({"display_name": "Anna"})).unwrap();
        assert_eq!(
            services
                .principals
                .patch(&ctx, &name, patch, Conditions::none())
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::Unavailable
        );
        let spec = PrincipalSpec {
            name: name.clone(),
            body: serde_json::from_str(r#"{"kind": "user", "display_name": "Anna"}"#).unwrap(),
        };
        assert_eq!(
            services
                .principals
                .upsert(&ctx, spec, Conditions::none())
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::Unavailable
        );
        // Scheduling is implemented as well: the inbox of a principal is read from the store.
        assert_eq!(
            services.scheduling.inbox_list(&ctx, &name).await.unwrap_err().kind(),
            ErrorKind::Unavailable
        );
    }
}
