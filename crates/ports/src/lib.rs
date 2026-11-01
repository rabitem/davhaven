//! Outbound ports of Davhaven.
//!
//! Every integration the application uses is a trait in this crate: storage (`Database` with per-aggregate
//! repositories), mail transport, templates, HTTP egress, authenticators, rate limiting, event sinks, outbox
//! handlers, calendar providers, content scanners, the scheduling policy and the pure ports (clock, id generator,
//! key ring, secret sealer, credential hasher).
//!
//! The crate also defines the port errors, the outbox message model, the `observe` wrapper every adapter uses and
//! the plugin registry that selects adapters by name. The `testing` feature provides test doubles
//! (`ManualClock`, `SeqIds`, `FixedKeyRing` and friends).
//!
//! # Where to look
//!
//! | Need | Module |
//! | --- | --- |
//! | Errors of adapters | [`error`] |
//! | Time, ids, keys, sealing, credential hashes | [`clock`], [`ids`], [`crypto`] |
//! | Storage | [`store`] |
//! | Mail, templates, outbound HTTP | [`mail`], [`templates`], [`http_client`] |
//! | Authentication, rate limiting, policy | [`auth`], [`rate_limit`], [`policy`] |
//! | Events, outbox, workers | [`event_sink`], [`outbox`], [`worker`] |
//! | Providers, scanners | [`provider`], [`scanner`] |
//! | Choosing adapters at startup | [`plugin`] |
//! | Adapter configuration helpers (`*_file` secrets) | [`config`] |
//! | Metrics and spans | [`mod@observe`] |
//!
//! Layering (`ENGINEERING_RULES` R1): this crate depends on `davhaven-domain` only. The application layer depends
//! on it; protocol crates never do.

#![forbid(unsafe_code)]

pub mod auth;
pub mod clock;
pub mod config;
pub mod crypto;
pub mod error;
pub mod event_sink;
pub mod http_client;
pub mod ids;
pub mod mail;
pub mod observe;
pub mod outbox;
pub mod plugin;
pub mod policy;
pub mod provider;
pub mod rate_limit;
pub mod scanner;
pub mod store;
pub mod templates;
pub mod worker;

#[cfg(feature = "testing")]
pub mod testing;

pub use auth::{AuthHint, AuthOutcome, Authenticated, Authenticator, PresentedCredential, RejectReason};
pub use clock::{Clock, SystemClock};
pub use config::{read_secret_file, resolve_secret};
pub use crypto::{
    CredentialHasher, KeyPurpose, KeyRing, ProfileSigner, SealAad, Sealed, SecretBytes, SecretSealer, Signature,
    StoredHash,
};
pub use error::{HandlerError, PluginError, PortError, PortErrorKind, StoreError, UniqueKey};
pub use event_sink::EventSink;
pub use http_client::{HttpClient, HttpPurpose, OutboundRequest, OutboundResponse};
pub use ids::{IdGenerator, IdGeneratorExt, UuidV7};
pub use mail::{MailTransport, SendReceipt};
pub use observe::{ErrorClass, PortLabel, observe};
pub use outbox::{
    DeliveryJob, ImipJob, NewOutbox, OutboxClaim, OutboxDecodeError, OutboxFailure, OutboxHandler, OutboxKey,
    OutboxMessage, OutboxRecord, OutboxStats, OutboxStatus, Reserved, WebhookDelivery,
};
pub use plugin::{
    Built, Cardinality, CheckFn, ConfigTree, KindInfo, KindReport, PluginCheck, PluginContext, PluginDescriptor,
    PluginRegistry, PluginSchema, PortKind, RunMode, parse_config,
};
pub use policy::{BusyPeriod, FreeBusy, Invite, PolicyTenant, ResourceRequest, SchedulingPolicy};
pub use provider::{
    OAuthGrant, OAuthProvider, OAuthTokens, Provider, RemoteCalendar, RemoteCalendarApi, RemoteChange, RemoteChanges,
};
pub use rate_limit::{FailureBackoff, IPV6_CLIENT_PREFIX_BITS, RateDecision, RateKey, RateLimiter, bucket_address};
pub use scanner::{ContentScanner, ScanContext, ScanVerdict};
pub use store::{
    AuditFilter, AuditPurge, AuditRepo, AuditRow, BindingRepo, BoundCalendar, CalendarFilter, CalendarRepo, Change,
    ChangeBatch, ChangeKind, ChangeRepo, CollectionProperty, CredentialLookup, CredentialOwner, CredentialRecord,
    CredentialRepo, CredentialUse, DEFAULT_IN_FLIGHT_LEASE, Database, DeliveryRecord, DeliveryStatus, Expected,
    ExternalAccountFilter, ExternalAccountRepo, GrantRepo, IdempotencyClaim, IdempotencyRecord, IdempotencyRepo,
    IdempotencyStatus, InboxRepo, InboxScope, IndexFilter, LeasedClaim, LookedUpCredential, MembershipDiff,
    MembershipRepo, NewAudit, NewTenantAudit, NewVersion, NotificationRepo, OAuthState, OAuthStateRepo, ObjectAttendee,
    ObjectHead, ObjectRepo, OutboxFilter, OutboxQueue, OutboxRepo, PageReq, PrincipalAddress, PrincipalFilter,
    PrincipalMatch, PrincipalQuery, PrincipalRepo, PropertyRepo, PropertyScope, Rehash, RetentionRepo, RsvpRepo,
    StorePage, SyncPosition, SystemTenantRepo, SystemTx, TenantAudit, TenantRepo, TimeRange, Tx, TxMode, WebhookRepo,
    WriteResult,
};
pub use templates::{RenderRequest, Rendered, TemplateName, TemplateNameError, TemplateRenderer, ThemeAsset};
pub use worker::{Health, Lifecycle, WorkReport, Worker};

#[cfg(test)]
mod thread_safety {
    //! Compile-time checks: every port is object safe and usable from spawned tasks.

    use std::future::Future;
    use std::sync::Arc;

    use davhaven_domain::{PrincipalId, TenantId};
    use uuid::Uuid;

    use super::*;

    fn send<T: ?Sized + Send>() {}

    fn send_sync<T: ?Sized + Send + Sync>() {}

    #[test]
    fn shared_ports_are_send_and_sync() {
        send_sync::<dyn Clock>();
        send_sync::<dyn IdGenerator>();
        send_sync::<dyn KeyRing>();
        send_sync::<dyn SecretSealer>();
        send_sync::<dyn CredentialHasher>();
        send_sync::<dyn HttpClient>();
        send_sync::<dyn Database>();
        send_sync::<dyn MailTransport>();
        send_sync::<dyn TemplateRenderer>();
        send_sync::<dyn Authenticator>();
        send_sync::<dyn RateLimiter>();
        send_sync::<dyn EventSink>();
        send_sync::<dyn OutboxHandler>();
        send_sync::<dyn OAuthProvider>();
        send_sync::<dyn RemoteCalendarApi>();
        send_sync::<dyn Provider>();
        send_sync::<dyn ContentScanner>();
        send_sync::<dyn SchedulingPolicy>();
        send_sync::<dyn Worker>();
        send_sync::<dyn Lifecycle>();
    }

    #[test]
    fn transactions_and_repositories_are_send() {
        send::<dyn Tx>();
        send::<dyn SystemTx>();
        send::<dyn TenantRepo>();
        send::<dyn PrincipalRepo>();
        send::<dyn MembershipRepo>();
        send::<dyn CalendarRepo>();
        send::<dyn BindingRepo>();
        send::<dyn PropertyRepo>();
        send::<dyn GrantRepo>();
        send::<dyn ObjectRepo>();
        send::<dyn ChangeRepo>();
        send::<dyn NotificationRepo>();
        send::<dyn InboxRepo>();
        send::<dyn CredentialRepo>();
        send::<dyn RsvpRepo>();
        send::<dyn OutboxRepo>();
        send::<dyn WebhookRepo>();
        send::<dyn ExternalAccountRepo>();
        send::<dyn OAuthStateRepo>();
        send::<dyn IdempotencyRepo>();
        send::<dyn AuditRepo>();
        send::<dyn SystemTenantRepo>();
        send::<dyn CredentialLookup>();
        send::<dyn OutboxQueue>();
        send::<dyn RetentionRepo>();
    }

    async fn tenant_flow(database: Arc<dyn Database>, tenant: TenantId) -> Result<(), StoreError> {
        let mut tx = database.begin(tenant, TxMode::ReadWrite).await?;
        tx.principals().get(PrincipalId::from_uuid(Uuid::nil())).await?;
        tx.outbox()
            .get(davhaven_domain::OutboxId::from_uuid(Uuid::nil()))
            .await?;
        tx.commit().await
    }

    async fn system_flow(database: Arc<dyn Database>) -> Result<(), StoreError> {
        let mut tx = database.begin_system().await?;
        let claimed = tx.outbox_claim().claim(10, std::time::Duration::from_secs(60)).await?;
        for record in &claimed {
            tx.outbox_claim().complete(record.key()).await?;
        }
        tx.commit().await
    }

    fn requires_send_future<F: Future + Send>(_flow: F) {}

    #[test]
    fn flows_over_dyn_ports_produce_send_futures() {
        // Never polled: constructing the futures proves the whole call chain is `Send`.
        fn tenant_future_is_send(database: Arc<dyn Database>, tenant: TenantId) {
            requires_send_future(tenant_flow(database, tenant));
        }
        fn system_future_is_send(database: Arc<dyn Database>) {
            requires_send_future(system_flow(database));
        }
        let _: fn(Arc<dyn Database>, TenantId) = tenant_future_is_send;
        let _: fn(Arc<dyn Database>) = system_future_is_send;
    }
}
