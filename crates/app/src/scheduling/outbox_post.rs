//! The scheduling outbox: `POST` of a `VFREEBUSY` request (RFC 6638 section 5, PLAN 2.8 "Outbox POST accepts
//! VFREEBUSY only").
//!
//! A CalDAV client asks when attendees are free by posting an iTIP `REQUEST` that holds one `VFREEBUSY` to its own
//! outbox. Everything else a client could post (an invitation, a cancellation, a reply) is refused: invitations and
//! cancellations are not posted, they happen when the organizer's copy of the event is written (implicit scheduling,
//! PLAN 2.8), and a `REPLY` happens when the attendee changes their copy.
//!
//! The iCalendar layer checks the message like every other (`parse_message`: structure, limits, one UID, only the
//! components the method allows) and reads the request itself (`davhaven_ical::freebusy::read_request`): this module
//! never looks at iCalendar text.
//!
//! The answer for a person of the tenant is the status `2.0;Success` (the DAV layer writes it for
//! `ScheduleStatus::Delivered` in a `schedule-response`) with their `VFREEBUSY`; every other address is `3.7`.

use davhaven_domain::{Operation, Precondition, PrincipalName, RequestContext, ResourcePath, Uid};
use davhaven_ical::ErrorContext;
use davhaven_ical::filter::TimeRange;
use davhaven_ical::freebusy::{FreeBusyReport, read_request, render_freebusy};
use davhaven_ical::itip::parse_message;
use davhaven_ports::TxMode;

use super::SchedulingServiceImpl;
use crate::authz::{blocking, enforce, home_facts, home_of, require_scope};
use crate::error::{AppError, AppResult, SafeMessage};
use crate::principals::address_set;
use crate::services::{RecipientResponse, ScheduleResponse, ScheduleStatus};

impl SchedulingServiceImpl {
    /// Answers a `VFREEBUSY` request posted to the outbox of `principal`.
    pub(super) async fn post_outbox(
        &self,
        ctx: &RequestContext,
        principal: &PrincipalName,
        body: String,
    ) -> AppResult<ScheduleResponse> {
        require_scope(ctx, Operation::PostOutbox)?;
        let deps = self.core.deps();
        // The home and the decision first: whoever may not post here learns nothing about the message.
        let (tenant, addresses) = {
            let mut tx = deps.database.begin(ctx.tenant, TxMode::ReadOnly).await?;
            let home = home_of(tx.as_mut(), ctx, principal).await?;
            let outbox = ResourcePath::Outbox {
                tenant: home.tenant.slug.clone(),
                principal: home.principal.name.clone(),
            };
            enforce(
                ctx,
                &home_facts(&home.tenant, &home.principal),
                Operation::PostOutbox,
                || outbox.href(),
            )?;
            let rows = tx.principals().addresses(home.principal.id).await?;
            tx.commit().await?;
            let addresses = address_set(&home.tenant, &home.principal, &rows);
            (home.tenant.clone(), addresses)
        };
        let ask = blocking(&self.core, ErrorContext::Scheduling, move |limits| {
            let message = parse_message(body.as_bytes(), limits)?;
            let ask = read_request(&message)?;
            TimeRange::new(Some(ask.start), Some(ask.end)).validate_bounded(limits)?;
            Ok(ask)
        })
        .await?;
        if !addresses.contains(&ask.organizer) {
            return Err(AppError::forbidden()
                .with_public_message(SafeMessage::from_static(
                    "The ORGANIZER of a free-busy request must be the owner of the outbox.",
                ))
                .with_precondition(Precondition::OrganizerAllowed));
        }
        let range = TimeRange::new(Some(ask.start), Some(ask.end));
        let mut tx = deps.database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let people = self.people(tx.as_mut(), &tenant, &ask.attendees).await?;
        let lists = self.busy_of_people(tx.as_mut(), &tenant, &people, range).await?;
        tx.commit().await?;
        let now = deps.clock.now();
        let mut responses = Vec::with_capacity(people.len());
        for (person, periods) in people.into_iter().zip(lists) {
            if person.principal.is_none() {
                responses.push(RecipientResponse {
                    recipient: person.address,
                    status: ScheduleStatus::UnknownAddress,
                    calendar_data: None,
                });
                continue;
            }
            let report = FreeBusyReport {
                organizer: Some(ask.organizer.clone()),
                attendee: person.address.clone(),
                range,
                periods,
                dtstamp: now,
                uid: Uid::from_uuid(deps.ids.new_id()),
            };
            let data =
                render_freebusy(&report).map_err(|error| AppError::from_ical(error, ErrorContext::Scheduling))?;
            responses.push(RecipientResponse {
                recipient: person.address,
                status: ScheduleStatus::Delivered,
                calendar_data: Some(data),
            });
        }
        Ok(ScheduleResponse { responses })
    }
}
