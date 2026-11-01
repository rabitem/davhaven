//! A scheduler that records what the write path offers it, for tests of the seam the scheduling service plugs into.

use std::sync::Arc;

use async_trait::async_trait;
use davhaven_testkit::davhaven_app::error::{AppError, AppResult};
use davhaven_testkit::davhaven_app::objects::{
    DeleteFacts, ObjectScheduler, ObjectServiceImpl, ScheduleTagPlan, ScheduledWrite, WriteFacts, Written,
};
use davhaven_testkit::davhaven_app::services::{RecipientStatus, ScheduleOutcome, ScheduleStatus};
use davhaven_testkit::davhaven_domain::CalendarUserAddress;
use davhaven_testkit::davhaven_ports::Tx;

use super::support::{Mutex, World, locked};

type Calls = Arc<Mutex<Vec<String>>>;

/// A scheduler that records its calls and does what the test tells it.
#[derive(Clone, Default)]
pub(crate) struct Recording {
    calls: Calls,
    /// The text the scheduler makes the write store instead of the client's.
    pub(crate) rewrite: Arc<Mutex<Option<String>>>,
    /// Whether the stored `Schedule-Tag` stays.
    pub(crate) keep_tag: Arc<Mutex<bool>>,
    /// Whether `after_write` refuses.
    pub(crate) fail_after: Arc<Mutex<bool>>,
    /// Whether stale attendee writes are merged.
    pub(crate) merge_stale: bool,
}

impl Recording {
    /// A scheduler that merges attendee writes that are stale by `ETag` but current by `Schedule-Tag`.
    pub(crate) fn merging() -> Self {
        Self {
            merge_stale: true,
            ..Self::default()
        }
    }

    /// The calls the scheduler has seen, in order.
    pub(crate) fn calls(&self) -> Vec<String> {
        locked(&self.calls).clone()
    }
}

#[async_trait]
impl ObjectScheduler for Recording {
    async fn before_write(&self, _tx: &mut dyn Tx, facts: &WriteFacts<'_>) -> AppResult<ScheduledWrite> {
        locked(&self.calls).push(format!(
            "before_write {} existing={} notify={}",
            facts.uri,
            facts.existing.is_some(),
            facts.notify_attendees
        ));
        let mut plan = ScheduledWrite::default();
        plan.data.clone_from(&locked(&self.rewrite));
        if *locked(&self.keep_tag) {
            plan.schedule_tag = ScheduleTagPlan::Keep;
        }
        Ok(plan)
    }

    async fn after_write(
        &self,
        _tx: &mut dyn Tx,
        facts: &WriteFacts<'_>,
        written: &Written<'_>,
    ) -> AppResult<ScheduleOutcome> {
        locked(&self.calls).push(format!("after_write {} seq={}", facts.uri, written.seq));
        if *locked(&self.fail_after) {
            return Err(AppError::forbidden());
        }
        Ok(ScheduleOutcome {
            recipients: vec![RecipientStatus {
                address: CalendarUserAddress::parse("mailto:ben@acme.example").unwrap(),
                status: ScheduleStatus::Delivered,
            }],
        })
    }

    async fn before_delete(&self, _tx: &mut dyn Tx, facts: &DeleteFacts<'_>) -> AppResult<ScheduleOutcome> {
        locked(&self.calls).push(format!(
            "before_delete {} notify={}",
            facts.existing.uri, facts.notify_attendees
        ));
        Ok(ScheduleOutcome::none())
    }

    fn merges_stale_attendee_writes(&self) -> bool {
        self.merge_stale
    }
}

/// The object service with `scheduler` installed.
pub(crate) fn service_with(world: &World, scheduler: &Recording) -> ObjectServiceImpl {
    ObjectServiceImpl::with_scheduler(world.core.clone(), Arc::new(scheduler.clone()))
}
