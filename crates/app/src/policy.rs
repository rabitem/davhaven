//! The default `SchedulingPolicy`: invitation auto-add, resource replies and external policy.
//!
//! The policy decides the three questions of scheduling that deployments customise (PLAN 2.8). Two
//! implementations are selectable by name (`[plugins] scheduling_policy`), and a deployment can add its own adapter
//! that calls a service of its own:
//!
//! | Name | Invitations | Resources | Mail to external addresses |
//! | --- | --- | --- | --- |
//! | `default` | added to the attendee's calendar when `tenant.settings.scheduling.auto_add_invitations` says so | answer by free-busy: accept when free, decline when busy | `tenant.settings.scheduling.external` and its allowlist |
//! | `manual` | always wait in the scheduling inbox | never answer: a person does | the tenant's setting, as in `default` |
//!
//! Both take their per-tenant values from the settings the application passes with every question
//! ([`PolicyTenant`]); there is no per-tenant adapter instance (PLAN 2.3). The questions are infallible: an adapter
//! that consults an external service applies its own fail-open or fail-closed default.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use davhaven_domain::{CalendarUserAddress, PartStat};
use davhaven_ports::{
    Built, FreeBusy, Invite, PluginContext, PluginDescriptor, PluginError, PluginRegistry, PolicyTenant, PortKind,
    ResourceRequest, SchedulingPolicy, parse_config,
};
use schemars::Schema;

/// The name of the policy that follows the tenant settings and lets resources answer.
pub const DEFAULT: &str = "default";

/// The name of the policy that leaves every decision about invitations and resources to people.
pub const MANUAL: &str = "manual";

/// The default policy (`default`): the tenant settings decide, resources answer by free-busy.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultPolicy;

#[async_trait]
impl SchedulingPolicy for DefaultPolicy {
    async fn auto_add(&self, invite: &Invite) -> bool {
        invite.tenant.settings.scheduling.auto_add_invitations
    }

    /// A resource accepts a request when none of its busy periods collides with the request and declines when one
    /// does. The application hands over only the busy periods that collide with an instance of the request (it
    /// expands the instances itself), so any period in `free_busy` is a collision.
    async fn resource_reply(&self, _request: &ResourceRequest, free_busy: &FreeBusy) -> Option<PartStat> {
        Some(if free_busy.busy.is_empty() {
            PartStat::Accepted
        } else {
            PartStat::Declined
        })
    }

    async fn external_allowed(&self, tenant: &PolicyTenant, address: &CalendarUserAddress) -> bool {
        tenant.settings.scheduling.external_permits(address)
    }
}

/// The policy that decides nothing for people (`manual`): invitations wait in the inbox and resources never
/// answer. Mail to external addresses still follows the tenant's setting.
#[derive(Debug, Clone, Copy, Default)]
pub struct ManualPolicy;

#[async_trait]
impl SchedulingPolicy for ManualPolicy {
    async fn auto_add(&self, _invite: &Invite) -> bool {
        false
    }

    async fn resource_reply(&self, _request: &ResourceRequest, _free_busy: &FreeBusy) -> Option<PartStat> {
        None
    }

    async fn external_allowed(&self, tenant: &PolicyTenant, address: &CalendarUserAddress) -> bool {
        tenant.settings.scheduling.external_permits(address)
    }
}

/// Registers the `default` and `manual` policies with the plugin registry.
///
/// The server calls this next to the `register` functions of the adapter crates.
///
/// # Errors
///
/// [`PluginError::DuplicateName`] when the registry has one of them already.
pub fn register(registry: &mut PluginRegistry) -> Result<(), PluginError> {
    registry.register(
        PortKind::SCHEDULING_POLICY,
        PluginDescriptor::new(
            DEFAULT,
            "Follows the scheduling settings of each tenant: invitations are added to calendars automatically when the \
             tenant says so, resources accept or decline by free-busy, and mail to external addresses follows the \
             tenant's external policy.",
            no_options,
            build_default,
        ),
    )?;
    registry.register(
        PortKind::SCHEDULING_POLICY,
        PluginDescriptor::new(
            MANUAL,
            "Never adds invitations to calendars and never lets a resource answer on its own: people decide. Mail to \
             external addresses follows the tenant's external policy.",
            no_options,
            build_manual,
        ),
    )
}

/// Both policies take no configuration: an empty object that allows no key.
fn no_options() -> Schema {
    schemars::json_schema!({"type": "object", "additionalProperties": false})
}

/// The future a plugin build returns.
type Building = Pin<Box<dyn Future<Output = Result<Built<dyn SchedulingPolicy>, PluginError>> + Send>>;

/// Checks that no configuration was given.
fn expect_no_options(plugin: &str, config: serde_json::Value) -> Result<(), PluginError> {
    let options: serde_json::Map<String, serde_json::Value> = parse_config(plugin, config)?;
    if options.is_empty() {
        Ok(())
    } else {
        Err(PluginError::invalid_config(
            plugin,
            "this policy takes no configuration",
        ))
    }
}

fn build_default(_context: PluginContext, config: serde_json::Value) -> Building {
    Box::pin(async move {
        expect_no_options(DEFAULT, config)?;
        let policy: Arc<dyn SchedulingPolicy> = Arc::new(DefaultPolicy);
        Ok(Built::new(policy))
    })
}

fn build_manual(_context: PluginContext, config: serde_json::Value) -> Building {
    Box::pin(async move {
        expect_no_options(MANUAL, config)?;
        let policy: Arc<dyn SchedulingPolicy> = Arc::new(ManualPolicy);
        Ok(Built::new(policy))
    })
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, TimeZone, Utc};
    use davhaven_domain::{CalendarId, ExternalPolicy, PrincipalId, TenantId, TenantSettings};
    use davhaven_ports::testing::{FixedHasher, FixedKeyRing, ManualClock, PlainSealer, SeqIds};
    use davhaven_ports::{BusyPeriod, ConfigTree, RunMode};
    use serde_json::json;
    use uuid::Uuid;

    use super::*;

    fn at(hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2027, 5, 4, hour, 0, 0).unwrap()
    }

    fn tenant(edit: impl FnOnce(&mut TenantSettings)) -> PolicyTenant {
        let mut settings = TenantSettings::default();
        edit(&mut settings);
        PolicyTenant {
            id: TenantId::from_uuid(Uuid::from_u128(1)),
            settings: Arc::new(settings),
        }
    }

    fn address(text: &str) -> CalendarUserAddress {
        CalendarUserAddress::parse(text).unwrap()
    }

    fn request(recurring: bool) -> ResourceRequest {
        ResourceRequest {
            tenant: tenant(|_| {}),
            resource: PrincipalId::from_uuid(Uuid::from_u128(2)),
            organizer: address("mailto:anna@acme.example"),
            start: at(10),
            end: at(11),
            recurring,
        }
    }

    fn busy(start: u32, end: u32) -> FreeBusy {
        FreeBusy {
            busy: vec![BusyPeriod {
                start: at(start),
                end: at(end),
            }],
        }
    }

    #[tokio::test]
    async fn the_default_policy_adds_invitations_as_the_tenant_says() {
        let invite = |tenant| Invite {
            tenant,
            organizer: address("mailto:anna@acme.example"),
            attendee: PrincipalId::from_uuid(Uuid::from_u128(3)),
            calendar: CalendarId::from_uuid(Uuid::from_u128(4)),
        };
        assert!(DefaultPolicy.auto_add(&invite(tenant(|_| {}))).await);
        assert!(
            !DefaultPolicy
                .auto_add(&invite(tenant(
                    |settings| settings.scheduling.auto_add_invitations = false
                )))
                .await
        );
    }

    #[tokio::test]
    async fn the_default_policy_lets_a_resource_accept_when_it_is_free_and_decline_when_it_is_busy() {
        let policy = DefaultPolicy;
        assert_eq!(
            policy.resource_reply(&request(false), &FreeBusy::default()).await,
            Some(PartStat::Accepted)
        );
        assert_eq!(
            policy.resource_reply(&request(false), &busy(9, 11)).await,
            Some(PartStat::Declined),
            "the application hands over the periods that collide with an instance: any period is a collision"
        );
        assert_eq!(
            policy.resource_reply(&request(true), &busy(14, 15)).await,
            Some(PartStat::Declined),
            "for a recurring request as well"
        );
        assert_eq!(
            policy.resource_reply(&request(true), &FreeBusy::default()).await,
            Some(PartStat::Accepted)
        );
    }

    #[tokio::test]
    async fn external_mail_follows_allow_allowlist_and_deny() {
        let guest = address("mailto:guest@example.net");
        let other = address("mailto:other@example.org");
        let allow = tenant(|_| {});
        let deny = tenant(|settings| settings.scheduling.external = ExternalPolicy::Deny);
        let listed = tenant(|settings| {
            settings.scheduling.external = ExternalPolicy::Allowlist;
            settings.scheduling.external_allowlist = vec!["example.net".to_owned()];
        });
        let policies: [Arc<dyn SchedulingPolicy>; 2] = [Arc::new(DefaultPolicy), Arc::new(ManualPolicy)];
        for policy in policies {
            assert!(policy.external_allowed(&allow, &guest).await);
            assert!(!policy.external_allowed(&deny, &guest).await);
            assert!(policy.external_allowed(&listed, &guest).await);
            assert!(!policy.external_allowed(&listed, &other).await);
        }
    }

    #[tokio::test]
    async fn the_manual_policy_decides_nothing_for_people() {
        let invite = Invite {
            tenant: tenant(|_| {}),
            organizer: address("mailto:anna@acme.example"),
            attendee: PrincipalId::from_uuid(Uuid::from_u128(3)),
            calendar: CalendarId::from_uuid(Uuid::from_u128(4)),
        };
        assert!(!ManualPolicy.auto_add(&invite).await);
        assert_eq!(
            ManualPolicy.resource_reply(&request(false), &FreeBusy::default()).await,
            None
        );
    }

    fn context() -> PluginContext {
        PluginContext::new(
            Arc::new(ManualClock::default()),
            Arc::new(SeqIds::new()),
            Arc::new(FixedKeyRing::default()),
            Arc::new(PlainSealer),
            Arc::new(FixedHasher::default()),
            RunMode::Production,
        )
    }

    #[tokio::test]
    async fn both_policies_are_registered_once_and_build_in_production() {
        let mut registry = PluginRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.names(PortKind::SCHEDULING_POLICY), vec!["default", "manual"]);
        assert!(matches!(
            register(&mut registry),
            Err(PluginError::DuplicateName { .. })
        ));
        assert!(
            registry
                .report()
                .iter()
                .any(|kind| kind.kind.name == "scheduling_policy" && kind.is_sufficient())
        );
        for name in ["default", "manual"] {
            let built = registry
                .build_single(PortKind::SCHEDULING_POLICY, name, &context(), &ConfigTree::new())
                .await
                .unwrap();
            assert!(built.workers.is_empty() && built.lifecycle.is_none());
        }
        let tree = ConfigTree::new().with("default", json!({"auto_add": true}));
        assert!(
            registry
                .build_single(PortKind::SCHEDULING_POLICY, "default", &context(), &tree)
                .await
                .is_err(),
            "the policies take no configuration"
        );
    }
}
