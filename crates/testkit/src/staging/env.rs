//! A deployed world as an environment of the matrices.
//!
//! [`Deployment`] answers what the matrices ask of an environment over HTTP alone. The state it shows is what the
//! management API shows with the administration tokens: for every tenant the calendars with their sync tokens (every
//! change of an object, a property, a share or a binding moves the token of the calendar it happens in, PLAN 2.7), the
//! principals with their versions and the outbox. That is less than the in-process application shows (no inbox, no mail
//! and no event capture), and it costs a handful of requests instead of reads of the store, so the matrices ask for it
//! only around the requests that can change something.

use std::sync::Arc;

use async_trait::async_trait;
use davhaven_domain::{FeedMode, PrincipalKind};
use davhaven_fixtures::{ActorRole, CalendarRole};
use davhaven_wire::credentials::FeedTokenCreate;
use davhaven_wire::{
    ApiTokenView, AppPasswordView, AuditEventView, CalendarView, EventView, FeedTokenView, MembershipSet,
    OutboxItemView, PrincipalView, TenantView, WebhookView,
};

use super::Deployment;
use super::api::{Api, WRITTEN};
use super::provision::{calendar_path, invitation_uid, principal_path, tenant_path};
use crate::credentials::CredentialBook;
use crate::handles::Actor;
use crate::matrix::Surface;
use crate::observe::Observation;
use crate::permissions::{Isolation, MatrixEnv, McpIds};
use crate::transport::Transport;

impl Deployment {
    /// Whether a case that may change something gets a world of its own by resetting the instance
    /// ([`Deployment::reset`]); without it such cases are left out of the matrices.
    #[must_use]
    pub const fn with_resets(mut self, resets: bool) -> Self {
        self.resets = resets;
        self
    }

    /// The state of both tenants as the management API shows it.
    ///
    /// # Errors
    ///
    /// The message of the request that failed.
    #[expect(
        clippy::too_many_lines,
        reason = "one read of each kind of state the management API shows, in the order of the report"
    )]
    pub async fn observe_http(&self) -> Result<Observation, String> {
        let mut observation = Observation::new();
        for tenant in [&self.world.names.tenant, &self.world.names.other_tenant] {
            let admin = self.admin(tenant);
            let base = tenant_path(tenant);
            let mut calendars: Vec<String> = admin
                .all::<CalendarView>("the calendars", &format!("{base}/calendars"))
                .await
                .map_err(|error| error.to_string())?
                .iter()
                .map(|calendar| {
                    format!(
                        "{}/{}:{}:{}:v{}:{}",
                        calendar.owner,
                        calendar.slug,
                        calendar.kind,
                        calendar.sync_token,
                        calendar.version,
                        calendar.display_name
                    )
                })
                .collect();
            calendars.sort();
            observation.insert(format!("calendars {tenant}"), calendars.join("; "));

            let principal_views = admin
                .all::<PrincipalView>("the principals", &format!("{base}/principals"))
                .await
                .map_err(|error| error.to_string())?;
            let mut principals: Vec<String> = principal_views
                .iter()
                .map(|principal| format!("{}:{}:v{}", principal.name, principal.status, principal.version))
                .collect();
            principals.sort();
            observation.insert(format!("principals {tenant}"), principals.join("; "));

            // What administration changes and the calendars do not show: the tenant, the credentials of every principal, the
            // members of the groups, the API tokens, the webhooks and the audit log.
            let view: TenantView = admin
                .get("the tenant", &base)
                .await
                .map_err(|error| error.to_string())?;
            let settings = serde_json::to_string(&view.settings).unwrap_or_default();
            observation.insert(
                format!("tenant {tenant}"),
                format!(
                    "{:?}:{}:v{}:{}:settings {}",
                    view.status,
                    view.login_domain.as_ref().map_or_else(String::new, ToString::to_string),
                    view.version,
                    view.display_name,
                    crate::observe::hash_of(&settings)
                ),
            );
            for principal in &principal_views {
                let who = format!("{tenant}/{}", principal.name);
                let path = format!("{base}/principals/{}", principal.name);
                if principal.kind == PrincipalKind::Group {
                    let members: MembershipSet = admin
                        .get("the members", &format!("{path}/members"))
                        .await
                        .map_err(|error| error.to_string())?;
                    observation.insert(
                        format!("members {who}"),
                        members
                            .members
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join("; "),
                    );
                }
                let mut passwords: Vec<String> = admin
                    .all::<AppPasswordView>("the app passwords", &format!("{path}/app-passwords"))
                    .await
                    .map_err(|error| error.to_string())?
                    .iter()
                    .map(|password| {
                        format!(
                            "{}:{}:revoked={}",
                            password.id,
                            password.label,
                            password.revoked_at.is_some()
                        )
                    })
                    .collect();
                passwords.sort();
                observation.insert(format!("app passwords {who}"), passwords.join("; "));
                let mut feeds: Vec<String> = admin
                    .all::<FeedTokenView>("the feed tokens", &format!("{path}/feed-tokens"))
                    .await
                    .map_err(|error| error.to_string())?
                    .iter()
                    .map(|token| {
                        format!(
                            "{}:{:?}:{:?}:revoked={}",
                            token.id,
                            token.mode,
                            token.calendar_ids,
                            token.revoked_at.is_some()
                        )
                    })
                    .collect();
                feeds.sort();
                observation.insert(format!("feed tokens {who}"), feeds.join("; "));
            }
            let mut tokens: Vec<String> = admin
                .all::<ApiTokenView>("the tokens", &format!("{base}/api-tokens"))
                .await
                .map_err(|error| error.to_string())?
                .iter()
                .map(|token| {
                    format!(
                        "{}:{:?}:{}:{:?}:revoked={}",
                        token.id,
                        token.kind,
                        token.label,
                        token.scopes,
                        token.revoked_at.is_some()
                    )
                })
                .collect();
            tokens.sort();
            observation.insert(format!("api tokens {tenant}"), tokens.join("; "));
            let mut webhooks: Vec<String> = admin
                .all::<WebhookView>("the webhooks", &format!("{base}/webhooks"))
                .await
                .map_err(|error| error.to_string())?
                .iter()
                .map(|webhook| {
                    format!(
                        "{}:{}:v{}:active={}:failures {}:rotated {:?}",
                        webhook.id,
                        webhook.url,
                        webhook.version,
                        webhook.active,
                        webhook.failure_count,
                        webhook.secret_rotated_at
                    )
                })
                .collect();
            webhooks.sort();
            observation.insert(format!("webhooks {tenant}"), webhooks.join("; "));
            let audit: Vec<String> = admin
                .all::<AuditEventView>("the audit log", &format!("{base}/audit-events"))
                .await
                .map_err(|error| error.to_string())?
                .iter()
                // The aggregates of failures that a refused request may add to are no change of anything.
                .filter(|event| !matches!(event.action.as_str(), "auth.failures" | "rate_limit.tripped" | "credential.used_after_revoke"))
                .map(|event| event.id.to_string())
                .collect();
            observation.insert(
                format!("audit {tenant}"),
                format!(
                    "{} records, the last {}",
                    audit.len(),
                    audit.last().map_or("none", String::as_str)
                ),
            );

            let mut outbox: Vec<String> = admin
                .all::<OutboxItemView>("the outbox", &format!("{base}/outbox"))
                .await
                .map_err(|error| error.to_string())?
                .iter()
                .map(|item| format!("{}:{}:{:?}", item.id, item.kind, item.status))
                .collect();
            outbox.sort();
            observation.insert(format!("outbox {tenant}"), outbox.join("; "));
        }
        Ok(observation)
    }

    /// The API as the owner of a calendar sees it: the administration token cannot read the events of personal and user
    /// calendars, the principal token of the owner can.
    fn api_for_events(&self, calendar: CalendarRole) -> Result<(Api, Api), String> {
        let fixture = self.world.calendar(calendar).map_err(|error| error.to_string())?;
        let admin = self.admin(fixture.key.tenant.as_str());
        let owner = self
            .world
            .principal_named(fixture.key.tenant.as_str(), fixture.key.owner.as_str())
            .ok()
            .and_then(|principal| principal.role)
            .and_then(|role| self.book.principal_token(role))
            .map_or_else(
                || admin.clone(),
                |token| Api::new(Arc::clone(&self.transport), Actor::bearer(token)),
            );
        Ok((admin, owner))
    }
}

#[async_trait]
impl MatrixEnv for Deployment {
    fn world(&self) -> &davhaven_fixtures::FixtureWorld {
        &self.world
    }

    fn book(&self) -> &CredentialBook {
        &self.book
    }

    fn transport(&self) -> Arc<dyn Transport> {
        Arc::clone(&self.transport)
    }

    async fn observe(&self) -> Result<Observation, String> {
        self.observe_http().await
    }

    fn observes_reads(&self) -> bool {
        false
    }

    fn inbound_itip(&self) -> Option<bool> {
        // The operator decides whether the endpoint is on; the administration matrix accepts both answers.
        None
    }

    fn may_delete_tenants(&self) -> bool {
        // The world is built inside the two tenants of the run: deleting one would end it.
        false
    }

    fn origin(&self) -> String {
        self.config.base_url.origin().ascii_serialization()
    }

    fn isolation(&self) -> Isolation {
        if self.resets {
            Isolation::PerCase
        } else {
            Isolation::Unavailable
        }
    }

    async fn fresh(&self) -> Result<Box<dyn MatrixEnv>, String> {
        let reset = self.reset().await.map_err(|error| error.to_string())?;
        Ok(Box::new(reset.with_resets(self.resets)))
    }

    fn has_calendar(&self, role: CalendarRole) -> bool {
        // A mirror calendar is made by the sync engine of a provider; the management API cannot make one.
        role != CalendarRole::Mirror
    }

    async fn mcp_ids(&self, calendar: CalendarRole) -> Result<McpIds, String> {
        let fixture = self.world.calendar(calendar).map_err(|error| error.to_string())?;
        let event = self.world.event(calendar).map_err(|error| error.to_string())?;
        let (admin, owner) = self.api_for_events(calendar)?;
        let path = calendar_path(&fixture.key);
        let view: CalendarView = admin
            .get("the calendar", &path)
            .await
            .map_err(|error| error.to_string())?;
        let by_key = format!("{path}/objects/by-key/{}", event.external_key);
        let object: EventView = match admin.get("the event", &by_key).await {
            Ok(object) => object,
            // Personal and user calendars are the owner's: the administration token does not reach their events.
            Err(_) => owner
                .get("the event", &by_key)
                .await
                .map_err(|error| error.to_string())?,
        };
        let id = object.id.ok_or_else(|| "the event has no id".to_owned())?;
        Ok(McpIds {
            calendar_id: view.id.to_string(),
            event_id: id.to_string(),
        })
    }

    async fn feed_token(&self, actor: ActorRole, calendar: CalendarRole) -> Result<Option<String>, String> {
        let Ok(principal) = self.world.principal(actor) else {
            return Ok(None);
        };
        let fixture = self.world.calendar(calendar).map_err(|error| error.to_string())?;
        if principal.tenant != fixture.key.tenant {
            // A calendar of another tenant cannot be put into a feed: there is no such feed.
            return Ok(None);
        }
        let admin = self.admin(principal.tenant.as_str());
        let view: CalendarView = admin
            .get("the calendar", &calendar_path(&fixture.key))
            .await
            .map_err(|error| error.to_string())?;
        let response = admin
            .send(
                "POST",
                &format!(
                    "{}/feed-tokens",
                    principal_path(principal.tenant.as_str(), principal.name.as_str())
                ),
                Some(&FeedTokenCreate {
                    mode: FeedMode::Full,
                    calendar_ids: vec![view.id],
                }),
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
        if !WRITTEN.contains(&response.status.as_u16()) {
            // The principal may not read the calendar (or is suspended): the instance makes no feed token for it.
            return Ok(None);
        }
        let created: davhaven_wire::FeedTokenCreated = response.json().map_err(|error| error.to_string())?;
        Ok(created
            .feed_url
            .path_segments()
            .and_then(|mut segments| segments.next_back().map(str::to_owned))
            .and_then(|name| name.strip_suffix(".ics").map(str::to_owned)))
    }

    async fn invitation_uid(&self) -> Result<Option<String>, String> {
        let principal = self
            .world
            .principal(ActorRole::PendingSharee)
            .map_err(|error| error.to_string())?;
        let actor = self
            .book
            .actor(ActorRole::PendingSharee, Surface::Dav, None)
            .ok_or_else(|| "the pending sharee has no app password".to_owned())?;
        invitation_uid(
            &self.transport,
            &actor,
            principal.tenant.as_str(),
            principal.name.as_str(),
        )
        .await
        .map_err(|error| error.to_string())
    }
}
