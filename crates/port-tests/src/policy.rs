//! Contract suite of the `SchedulingPolicy` port.
//!
//! What every scheduling policy promises, whatever it consults to decide:
//!
//! * a question gets the same answer when it is asked again (the application asks more than once while it
//!   plans, delivers and mails, and the answers must agree);
//! * a resource that answers a booking on its own gives an *answer* (accepted, declined or tentative), never a
//!   status that is no answer (`NEEDS-ACTION`, `DELEGATED`, ...).
//!
//! The contract does not say *what* a policy decides: accepting invitations automatically or leaving them in the
//! inbox, answering for resources (and whether a collision with busy time means "decline": a room is taken, a pool
//! of equipment may still have units left) or leaving them to people, allowing or refusing mail to outside
//! addresses are the choices a deployment makes with its policy (PLAN 2.8). The shipped policies have cases of
//! their own next to their implementation.

use std::sync::Arc;

use chrono::{DateTime, TimeZone, Utc};
use davhaven_domain::{CalendarId, CalendarUserAddress, ExternalPolicy, PrincipalId, TenantId, TenantSettings};
use davhaven_ports::{BusyPeriod, FreeBusy, Invite, PolicyTenant, ResourceRequest, SchedulingPolicy};
use uuid::Uuid;

use crate::suite::{Checks, ContractReport, Suite};

fn at(hour: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2027, 5, 4, hour, 0, 0)
        .single()
        .unwrap_or(DateTime::UNIX_EPOCH)
}

fn tenant(edit: impl FnOnce(&mut TenantSettings)) -> PolicyTenant {
    let mut settings = TenantSettings::default();
    edit(&mut settings);
    PolicyTenant {
        id: TenantId::from_uuid(Uuid::from_u128(1)),
        settings: Arc::new(settings),
    }
}

/// The tenants the cases ask about: the defaults, one that refuses outside mail and one that lists a domain.
fn tenants() -> Vec<(&'static str, PolicyTenant)> {
    vec![
        ("the default tenant", tenant(|_| {})),
        (
            "a tenant that refuses mail to outside addresses",
            tenant(|settings| settings.scheduling.external = ExternalPolicy::Deny),
        ),
        (
            "a tenant with an allowlist",
            tenant(|settings| {
                settings.scheduling.external = ExternalPolicy::Allowlist;
                settings.scheduling.external_allowlist = vec!["example.net".to_owned()];
            }),
        ),
        (
            "a tenant that does not add invitations by itself",
            tenant(|settings| settings.scheduling.auto_add_invitations = false),
        ),
    ]
}

/// Addresses of every shape the application hands to a policy.
fn addresses() -> Vec<CalendarUserAddress> {
    [
        "mailto:guest@example.net",
        "mailto:Other.Guest@EXAMPLE.org",
        "mailto:a@b.c",
    ]
    .iter()
    .filter_map(|text| CalendarUserAddress::parse(text).ok())
    .collect()
}

fn organizer() -> CalendarUserAddress {
    CalendarUserAddress::urn_uuid(PrincipalId::from_uuid(Uuid::from_u128(5)))
}

fn booking(tenant: &PolicyTenant, start: u32, end: u32, recurring: bool) -> ResourceRequest {
    ResourceRequest {
        tenant: tenant.clone(),
        resource: PrincipalId::from_uuid(Uuid::from_u128(2)),
        organizer: organizer(),
        start: at(start),
        end: at(end),
        recurring,
    }
}

fn busy(periods: &[(u32, u32)]) -> FreeBusy {
    FreeBusy {
        busy: periods
            .iter()
            .map(|(start, end)| BusyPeriod {
                start: at(*start),
                end: at(*end),
            })
            .collect(),
    }
}

/// Runs the suite against policies built by `factory` and returns the report.
pub async fn run<F>(factory: F) -> ContractReport
where
    F: Fn() -> Arc<dyn SchedulingPolicy>,
{
    let mut suite = Suite::new("policy");
    let policy = factory();

    let mut checks = Checks::new("the same question gets the same answer");
    for (name, tenant) in tenants() {
        let invite = Invite {
            tenant: tenant.clone(),
            organizer: organizer(),
            attendee: PrincipalId::from_uuid(Uuid::from_u128(3)),
            calendar: CalendarId::from_uuid(Uuid::from_u128(4)),
        };
        let (first, second) = (policy.auto_add(&invite).await, factory().auto_add(&invite).await);
        checks.equal(&first, &second, &format!("auto_add for {name}"));
        for address in addresses() {
            let (first, second) = (
                policy.external_allowed(&tenant, &address).await,
                factory().external_allowed(&tenant, &address).await,
            );
            checks.equal(&first, &second, &format!("external_allowed for {name} and {address}"));
        }
        for (what, request, free_busy) in [
            ("a free resource", booking(&tenant, 10, 11, false), busy(&[])),
            ("a busy resource", booking(&tenant, 10, 11, false), busy(&[(10, 11)])),
            ("a recurring booking", booking(&tenant, 10, 11, true), busy(&[(14, 15)])),
        ] {
            let (first, second) = (
                policy.resource_reply(&request, &free_busy).await,
                factory().resource_reply(&request, &free_busy).await,
            );
            checks.equal(&first, &second, &format!("resource_reply for {name}, {what}"));
        }
    }
    suite.record(checks);

    let mut checks = Checks::new("an automatic answer of a resource is an answer");
    for (name, tenant) in tenants() {
        for (what, request, free_busy) in [
            ("free", booking(&tenant, 10, 11, false), busy(&[])),
            ("busy", booking(&tenant, 10, 11, false), busy(&[(9, 12)])),
            ("recurring and free", booking(&tenant, 10, 11, true), busy(&[])),
            (
                "recurring and busy",
                booking(&tenant, 10, 11, true),
                busy(&[(10, 11), (34, 35)]),
            ),
        ] {
            if let Some(answer) = policy.resource_reply(&request, &free_busy).await {
                checks.that(
                    answer.is_answer(),
                    &format!("{name}, {what}: {answer:?} is accepted, declined or tentative"),
                );
            }
        }
    }
    suite.record(checks);

    suite.finish()
}

/// Runs the suite and fails the running test when any case fails.
///
/// # Panics
///
/// When a case fails.
pub async fn run_all<F>(factory: F)
where
    F: Fn() -> Arc<dyn SchedulingPolicy>,
{
    run(factory).await.assert_ok();
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use async_trait::async_trait;
    use davhaven_domain::PartStat;

    use super::*;

    /// A policy that answers by free-busy and decides nothing else.
    struct ByFreeBusy;

    #[async_trait]
    impl SchedulingPolicy for ByFreeBusy {
        async fn auto_add(&self, _invite: &Invite) -> bool {
            true
        }

        async fn resource_reply(&self, request: &ResourceRequest, free_busy: &FreeBusy) -> Option<PartStat> {
            let collides = if request.recurring {
                !free_busy.busy.is_empty()
            } else {
                free_busy.is_busy(request.start, request.end)
            };
            Some(if collides {
                PartStat::Declined
            } else {
                PartStat::Accepted
            })
        }

        async fn external_allowed(&self, _tenant: &PolicyTenant, _address: &CalendarUserAddress) -> bool {
            false
        }
    }

    /// A policy that leaves everything to people.
    struct Manual;

    #[async_trait]
    impl SchedulingPolicy for Manual {
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

    /// A policy that answers a resource with a status that is no answer.
    struct NeedsAction;

    #[async_trait]
    impl SchedulingPolicy for NeedsAction {
        async fn auto_add(&self, _invite: &Invite) -> bool {
            true
        }

        async fn resource_reply(&self, _request: &ResourceRequest, _free_busy: &FreeBusy) -> Option<PartStat> {
            Some(PartStat::NeedsAction)
        }

        async fn external_allowed(&self, _tenant: &PolicyTenant, _address: &CalendarUserAddress) -> bool {
            true
        }
    }

    /// A policy whose answers alternate.
    struct Flip(AtomicBool);

    #[async_trait]
    impl SchedulingPolicy for Flip {
        async fn auto_add(&self, _invite: &Invite) -> bool {
            self.0.fetch_xor(true, Ordering::SeqCst)
        }

        async fn resource_reply(&self, _request: &ResourceRequest, _free_busy: &FreeBusy) -> Option<PartStat> {
            None
        }

        async fn external_allowed(&self, _tenant: &PolicyTenant, _address: &CalendarUserAddress) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn policies_that_decide_differently_satisfy_the_contract() {
        run_all(|| Arc::new(ByFreeBusy)).await;
        run_all(|| Arc::new(Manual)).await;
        assert_eq!(run(|| Arc::new(Manual)).await.case_count(), 2);
    }

    #[tokio::test]
    async fn an_answer_that_is_none_is_caught() {
        let report = run(|| Arc::new(NeedsAction)).await;
        assert!(
            report
                .failed_cases()
                .contains(&"an automatic answer of a resource is an answer"),
            "{report}"
        );
    }

    #[tokio::test]
    async fn unstable_answers_are_caught() {
        let report = run(|| Arc::new(Flip(AtomicBool::new(false)))).await;
        assert!(
            report
                .failed_cases()
                .contains(&"the same question gets the same answer"),
            "{report}"
        );
    }
}
