//! What a test can observe of the whole state of an application.
//!
//! The permission matrix asserts "no side effects on denial" (PLAN 3.2): a request that was refused changed nothing,
//! neither a sequence number, nor an object, a grant, a binding, a notification, an inbox, the outbox, a mail nor a
//! domain event. An [`Observation`] is that state as a sorted map of named facts, read from the store in one read
//! transaction per tenant and from the captures; [`Observation::diff`] says what differs between two observations.
//!
//! The facts are the application's, not the protocol's: they are read through the store ports, so a refused request that
//! left a trace the protocol never shows (an outbox record, a bumped sequence) is still seen.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use davhaven_domain::{PrincipalId, PrincipalKind};
use davhaven_ports::store::ApiTokenFilter;
use davhaven_ports::{
    AuditFilter, ExternalAccountFilter, InboxScope, OutboxFilter, PageReq, PrincipalFilter, Tx, TxMode,
};

use crate::app::{TestApp, TestAppError};

/// The state of an application as named facts.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Observation {
    facts: BTreeMap<String, String>,
}

impl Observation {
    /// An observation without facts.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a fact.
    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.facts.insert(name.into(), value.into());
    }

    /// The value of a fact.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.facts.get(name).map(String::as_str)
    }

    /// The number of facts.
    pub fn len(&self) -> usize {
        self.facts.len()
    }

    /// Whether nothing was observed.
    pub fn is_empty(&self) -> bool {
        self.facts.is_empty()
    }

    /// The facts that differ in `later`: changed, new and vanished ones, one line each.
    pub fn diff(&self, later: &Self) -> Vec<String> {
        let mut differences = Vec::new();
        for (name, before) in &self.facts {
            match later.facts.get(name) {
                None => differences.push(format!("{name}: `{before}` is gone")),
                Some(after) if after != before => differences.push(format!("{name}: `{before}` became `{after}`")),
                Some(_) => {}
            }
        }
        for (name, after) in &later.facts {
            if !self.facts.contains_key(name) {
                differences.push(format!("{name}: `{after}` appeared"));
            }
        }
        differences
    }
}

fn observe_error(what: &str, error: &impl core::fmt::Debug) -> TestAppError {
    TestAppError::Observe(format!("{what}: {error:?}"))
}

/// The calendars of a principal with their objects and grants.
async fn observe_calendars(
    tx: &mut dyn Tx,
    observation: &mut Observation,
    who: &str,
    principal: PrincipalId,
) -> Result<(), TestAppError> {
    let calendars = tx
        .calendars()
        .list_owned(principal)
        .await
        .map_err(|error| observe_error("the calendars", &error))?;
    let mut owned = String::new();
    for calendar in &calendars {
        let _ = write!(
            owned,
            "{}:{:?}:seq{}:v{}:{}; ",
            calendar.slug.as_str(),
            calendar.kind,
            calendar.sync_seq,
            calendar.version,
            calendar.display_name
        );
        let mut objects = String::new();
        let mut page = PageReq::first(1000);
        loop {
            let batch = tx
                .objects()
                .list(calendar.id, page)
                .await
                .map_err(|error| observe_error("the objects", &error))?;
            for object in &batch.items {
                let _ = write!(objects, "{}={}; ", object.uri.as_str(), object.etag.as_str());
            }
            match batch.next {
                Some(after) => page = page.after(after),
                None => break,
            }
        }
        observation.insert(format!("objects {who}/{}", calendar.slug.as_str()), objects);
        let mut grants: Vec<String> = tx
            .grants()
            .for_calendar(calendar.id)
            .await
            .map_err(|error| observe_error("the grants", &error))?
            .iter()
            .map(|grant| {
                format!(
                    "{:?}:{:?}:{:?}:v{}",
                    grant.grantee_id, grant.access, grant.status, grant.version
                )
            })
            .collect();
        grants.sort();
        observation.insert(format!("grants {who}/{}", calendar.slug.as_str()), grants.join("; "));
    }
    observation.insert(format!("calendars {who}"), owned);
    Ok(())
}

/// The bindings, notifications and scheduling inboxes of a principal.
async fn observe_home(
    tx: &mut dyn Tx,
    observation: &mut Observation,
    who: &str,
    principal: PrincipalId,
) -> Result<(), TestAppError> {
    let mut bindings: Vec<String> = tx
        .bindings()
        .list_for(principal)
        .await
        .map_err(|error| observe_error("the bindings", &error))?
        .iter()
        .map(|bound| {
            format!(
                "{}->{}:v{}:hidden={}",
                bound.binding.slug.as_str(),
                bound.calendar.slug.as_str(),
                bound.binding.version,
                bound.binding.hidden
            )
        })
        .collect();
    bindings.sort();
    observation.insert(format!("bindings {who}"), bindings.join("; "));

    let notifications: Vec<String> = tx
        .notifications()
        .list(principal)
        .await
        .map_err(|error| observe_error("the notifications", &error))?
        .iter()
        .map(|notification| format!("{}={}", notification.uri.as_str(), notification.etag.as_str()))
        .collect();
    observation.insert(format!("notifications {who}"), notifications.join("; "));

    for (scope, label) in [
        (InboxScope::Delivered, "inbox"),
        (InboxScope::Quarantined, "quarantine"),
    ] {
        let items: Vec<String> = tx
            .inbox()
            .list(principal, scope)
            .await
            .map_err(|error| observe_error("the scheduling inbox", &error))?
            .iter()
            .map(|item| format!("{}={}", item.uri.as_str(), item.etag.as_str()))
            .collect();
        observation.insert(format!("{label} {who}"), items.join("; "));
    }
    Ok(())
}

/// The records of the outbox of the tenant `tx` is bound to.
async fn observe_outbox(tx: &mut dyn Tx, observation: &mut Observation, tenant_slug: &str) -> Result<(), TestAppError> {
    let mut outbox = String::new();
    let mut page = PageReq::first(1000);
    loop {
        let batch = tx
            .outbox()
            .list(&OutboxFilter::default(), page)
            .await
            .map_err(|error| observe_error("the outbox", &error))?;
        for record in &batch.items {
            let _ = write!(outbox, "{}:{}:{:?}; ", record.id, record.kind, record.status);
        }
        match batch.next {
            Some(after) => page = page.after(after),
            None => break,
        }
    }
    observation.insert(format!("outbox {tenant_slug}"), outbox);
    Ok(())
}

/// The audit actions that a request can write although nothing was done: aggregates of failures, which a refused request may
/// add to.
const AUDIT_NOISE: [&str; 3] = ["auth.failures", "rate_limit.tripped", "credential.used_after_revoke"];

/// A short stable hash of a text (FNV-1a), for facts that would be too long to show.
pub(crate) fn hash_of(text: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.bytes() {
        hash = (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// What administration changes and the calendars do not show: the tenant row and its settings, every principal (new ones and
/// deleted ones included, not only the ones the world seeded), the members of the groups, the app passwords, feed tokens and
/// API tokens (ids, labels, scopes, revocations, versions; never a secret, never the time of the last use), the webhooks with
/// their deliveries and secret rotations, the external accounts of providers (status, mirror, version and a hash of the sealed
/// tokens and of the sync state, so that a refused request that touched an account or its grant shows), and the audit log. The
/// audit log has a record for everything administration does, so it catches what the others cannot name; the aggregates of
/// failures that a refused request may add to are left out.
#[expect(
    clippy::too_many_lines,
    reason = "one read of each kind of administrative state, in the order of the report"
)]
async fn observe_administration(
    tx: &mut dyn Tx,
    observation: &mut Observation,
    tenant_slug: &str,
) -> Result<(), TestAppError> {
    let tenant = tx
        .tenant()
        .get()
        .await
        .map_err(|error| observe_error("the tenant", &error))?;
    let settings = serde_json::to_string(&tenant.settings).unwrap_or_default();
    observation.insert(
        format!("tenant {tenant_slug}"),
        format!(
            "{:?}:{}:v{}:{}:settings {}",
            tenant.status,
            tenant
                .login_domain
                .as_ref()
                .map_or_else(String::new, ToString::to_string),
            tenant.version,
            tenant.display_name,
            hash_of(&settings)
        ),
    );

    let mut principals = Vec::new();
    let mut page = PageReq::first(1000);
    loop {
        let batch = tx
            .principals()
            .list(
                &PrincipalFilter {
                    include_deleted: true,
                    ..PrincipalFilter::default()
                },
                page,
            )
            .await
            .map_err(|error| observe_error("the principals", &error))?;
        principals.extend(batch.items);
        match batch.next {
            Some(after) => page = page.after(after),
            None => break,
        }
    }
    let mut listed: Vec<String> = principals
        .iter()
        .map(|principal| {
            format!(
                "{}:{:?}:{:?}:v{}:generation {}",
                principal.name.as_str(),
                principal.kind,
                principal.status,
                principal.version,
                principal.credential_generation
            )
        })
        .collect();
    listed.sort();
    observation.insert(format!("principals {tenant_slug}"), listed.join("; "));

    for principal in &principals {
        let who = format!("{tenant_slug}/{}", principal.name.as_str());
        if principal.kind == PrincipalKind::Group {
            let mut members: Vec<String> = tx
                .memberships()
                .members(principal.id)
                .await
                .map_err(|error| observe_error("the members", &error))?
                .iter()
                .map(ToString::to_string)
                .collect();
            members.sort();
            observation.insert(format!("members {who}"), members.join("; "));
        }
        let mut passwords: Vec<String> = tx
            .credentials()
            .list_app_passwords(principal.id)
            .await
            .map_err(|error| observe_error("the app passwords", &error))?
            .iter()
            .map(|password| {
                format!(
                    "{}:{}:revoked={}:v{}",
                    password.id,
                    password.label,
                    password.revoked_at.is_some(),
                    password.version
                )
            })
            .collect();
        passwords.sort();
        observation.insert(format!("app passwords {who}"), passwords.join("; "));
        let mut feeds: Vec<String> = tx
            .credentials()
            .list_feed_tokens(principal.id)
            .await
            .map_err(|error| observe_error("the feed tokens", &error))?
            .iter()
            .map(|token| {
                format!(
                    "{}:{:?}:{:?}:revoked={}:v{}",
                    token.id,
                    token.mode,
                    token.calendar_ids,
                    token.revoked_at.is_some(),
                    token.version
                )
            })
            .collect();
        feeds.sort();
        observation.insert(format!("feed tokens {who}"), feeds.join("; "));
    }

    let mut tokens = Vec::new();
    let mut page = PageReq::first(1000);
    loop {
        let batch = tx
            .credentials()
            .list_api_tokens(
                &ApiTokenFilter {
                    include_revoked: true,
                    ..ApiTokenFilter::default()
                },
                page,
            )
            .await
            .map_err(|error| observe_error("the API tokens", &error))?;
        tokens.extend(batch.items.iter().map(|token| {
            format!(
                "{}:{:?}:{}:{:?}:revoked={}:v{}",
                token.id,
                token.kind,
                token.label,
                token.scopes,
                token.revoked_at.is_some(),
                token.version
            )
        }));
        match batch.next {
            Some(after) => page = page.after(after),
            None => break,
        }
    }
    tokens.sort();
    observation.insert(format!("api tokens {tenant_slug}"), tokens.join("; "));

    let mut webhooks = Vec::new();
    let mut page = PageReq::first(1000);
    let mut subscriptions = Vec::new();
    loop {
        let batch = tx
            .webhooks()
            .list(page)
            .await
            .map_err(|error| observe_error("the webhooks", &error))?;
        subscriptions.extend(batch.items);
        match batch.next {
            Some(after) => page = page.after(after),
            None => break,
        }
    }
    for subscription in &subscriptions {
        let mut deliveries = Vec::new();
        let mut page = PageReq::first(1000);
        loop {
            let batch = tx
                .webhooks()
                .list_deliveries(subscription.id, page)
                .await
                .map_err(|error| observe_error("the deliveries", &error))?;
            deliveries.extend(batch.items.iter().map(|delivery| {
                format!(
                    "{}:{:?}:attempts {}:v{}",
                    delivery.id, delivery.status, delivery.attempts, delivery.version
                )
            }));
            match batch.next {
                Some(after) => page = page.after(after),
                None => break,
            }
        }
        deliveries.sort();
        webhooks.push(format!(
            "{}:{}:v{}:active={}:failures {}:rotated {:?}:{:?}:deliveries [{}]",
            subscription.id,
            subscription.url,
            subscription.version,
            subscription.active,
            subscription.failure_count,
            subscription.secret_rotated_at,
            subscription.events,
            deliveries.join(", ")
        ));
    }
    webhooks.sort();
    observation.insert(format!("webhooks {tenant_slug}"), webhooks.join("; "));

    let mut accounts = Vec::new();
    let mut page = PageReq::first(1000);
    loop {
        let batch = tx
            .external_accounts()
            .list(&ExternalAccountFilter::default(), page)
            .await
            .map_err(|error| observe_error("the external accounts", &error))?;
        accounts.extend(batch.items.iter().map(|account| {
            format!(
                "{}:{}:{}:{:?}:mirror {:?}:v{}:tokens {}:state {}",
                account.id,
                account.principal_id,
                account.provider,
                account.status,
                account.mirror_calendar_id,
                account.version,
                hash_of(&format!("{:?}", account.sealed_tokens)),
                hash_of(&account.sync_state.to_string())
            )
        }));
        match batch.next {
            Some(after) => page = page.after(after),
            None => break,
        }
    }
    accounts.sort();
    observation.insert(format!("external accounts {tenant_slug}"), accounts.join("; "));

    let mut audit = Vec::new();
    let mut page = PageReq::first(1000);
    loop {
        let batch = tx
            .audit()
            .list(&AuditFilter::default(), page)
            .await
            .map_err(|error| observe_error("the audit log", &error))?;
        audit.extend(
            batch
                .items
                .iter()
                .filter(|row| !AUDIT_NOISE.contains(&row.action.as_str()))
                .map(|row| row.id.to_string()),
        );
        match batch.next {
            Some(after) => page = page.after(after),
            None => break,
        }
    }
    observation.insert(
        format!("audit {tenant_slug}"),
        format!(
            "{} records, the last {}",
            audit.len(),
            audit.last().map_or("none", String::as_str)
        ),
    );
    Ok(())
}

impl TestApp {
    /// Reads the whole state of the application: every calendar of every principal with its sequence, objects and
    /// grants, the bindings, the notifications, the scheduling inboxes and the outbox of every tenant, the tenant row, the
    /// principals, memberships, credentials and webhooks of every tenant and its audit log, and the numbers of captured
    /// mails and events.
    ///
    /// # Errors
    ///
    /// [`TestAppError::Observe`] when the store cannot be read.
    pub async fn observe(&self) -> Result<Observation, TestAppError> {
        let mut observation = Observation::new();
        let database = &self.deps().database;
        let index = self.index();
        for (tenant_slug, tenant) in &index.tenants {
            let mut tx = database
                .begin(*tenant, TxMode::ReadOnly)
                .await
                .map_err(|error| observe_error("a read transaction", &error))?;
            for ((slug, name), principal) in &index.principals {
                if slug != tenant_slug {
                    continue;
                }
                let who = format!("{tenant_slug}/{name}");
                observe_calendars(tx.as_mut(), &mut observation, &who, *principal).await?;
                observe_home(tx.as_mut(), &mut observation, &who, *principal).await?;
            }
            observe_outbox(tx.as_mut(), &mut observation, tenant_slug).await?;
            observe_administration(tx.as_mut(), &mut observation, tenant_slug).await?;
            tx.commit()
                .await
                .map_err(|error| observe_error("the commit of a read transaction", &error))?;
        }
        observation.insert("mails", self.mails().count().await.to_string());
        observation.insert("events", self.events().count().await.to_string());
        Ok(observation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn differences_are_named_changed_new_and_gone() {
        let mut before = Observation::new();
        before.insert("a", "1");
        before.insert("b", "2");
        before.insert("c", "3");
        let mut after = Observation::new();
        after.insert("a", "1");
        after.insert("b", "20");
        after.insert("d", "4");
        assert_eq!(
            before.diff(&after),
            vec!["b: `2` became `20`", "c: `3` is gone", "d: `4` appeared"]
        );
        assert_eq!(before.diff(&before), Vec::<String>::new());
        assert_eq!(before.get("a"), Some("1"));
        assert_eq!(
            (before.len(), before.is_empty(), Observation::new().is_empty()),
            (3, false, true)
        );
    }

    #[tokio::test]
    async fn an_application_is_observed_whole_and_a_change_shows() {
        let app = TestApp::builder().build().await.unwrap();
        let before = app.observe().await.unwrap();
        assert!(
            before
                .get("calendars acme/olivia")
                .is_some_and(|text| text.contains("personal:")),
            "{before:?}"
        );
        assert!(
            before
                .get("objects acme/olivia/personal")
                .is_some_and(|text| text.contains("personal-event"))
        );
        assert_eq!(before.get("mails"), Some("0"));
        assert_eq!(
            before.diff(&app.observe().await.unwrap()),
            Vec::<String>::new(),
            "reading changes nothing"
        );

        let owner = app.actor(davhaven_fixtures::ActorRole::Owner).unwrap();
        let ics = davhaven_fixtures::EventBuilder::event("observe-1@acme.example")
            .summary("Observed")
            .starts(davhaven_fixtures::When::utc(2027, 6, 1, 9, 0))
            .ends(davhaven_fixtures::When::utc(2027, 6, 1, 10, 0))
            .build();
        let response = app
            .dav(&owner)
            .put("/dav/calendars/acme/olivia/personal/observe-1.ics", &ics)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status.as_u16(), 201, "{}", response.text());
        let changes = before.diff(&app.observe().await.unwrap());
        assert!(
            changes.iter().any(|line| line.starts_with("calendars acme/olivia")),
            "{changes:?}"
        );
        assert!(
            changes
                .iter()
                .any(|line| line.starts_with("objects acme/olivia/personal")),
            "{changes:?}"
        );
        assert!(
            changes.iter().any(|line| line.starts_with("outbox acme")),
            "the change wrote an event: {changes:?}"
        );
    }

    /// What administration changes is part of the state a refused request must leave alone: the tenant, its tokens and
    /// webhooks, and the audit log that records all of it.
    #[tokio::test]
    async fn what_administration_changes_shows_in_the_observation() {
        let app = TestApp::builder().build().await.unwrap();
        let admin = app.api(&app.token(davhaven_fixtures::ActorRole::TenantToken).unwrap());
        let before = app.observe().await.unwrap();
        for name in [
            "tenant acme",
            "principals acme",
            "api tokens acme",
            "webhooks acme",
            "audit acme",
        ] {
            assert!(before.get(name).is_some(), "`{name}` is observed: {before:?}");
        }
        assert_eq!(
            before.diff(&app.observe().await.unwrap()),
            Vec::<String>::new(),
            "reading changes nothing"
        );

        let created = admin
            .post_json(
                "/api/v1/tenants/acme/webhooks",
                &serde_json::json!({
                    "url": "https://hooks.example.net/observed",
                    "events": ["calendar.created"],
                    "description": "observed"
                }),
            )
            .unwrap()
            .send()
            .await
            .unwrap();
        assert_eq!(created.status.as_u16(), 201, "{}", created.text());
        let after_webhook = app.observe().await.unwrap();
        let changes = before.diff(&after_webhook);
        assert!(
            changes.iter().any(|line| line.starts_with("webhooks acme")),
            "{changes:?}"
        );
        assert!(
            changes.iter().any(|line| line.starts_with("audit acme")),
            "the audit log records it: {changes:?}"
        );

        let minted = admin
            .post_json(
                "/api/v1/tenants/acme/api-tokens",
                &serde_json::json!({"kind": "tenant", "label": "observed", "scopes": ["events:read"]}),
            )
            .unwrap()
            .send()
            .await
            .unwrap();
        assert_eq!(minted.status.as_u16(), 201, "{}", minted.text());
        let changes = after_webhook.diff(&app.observe().await.unwrap());
        assert!(
            changes.iter().any(|line| line.starts_with("api tokens acme")),
            "{changes:?}"
        );
        assert!(
            changes.iter().all(|line| !line.contains("dvh_pat_")),
            "no secret is observed: {changes:?}"
        );
    }
}
