//! The scheduling tools: `free_busy` and `find_free_slots`.
//!
//! Both answer about people of the caller's tenant by their calendar user addresses and reveal when they are busy,
//! never why: the services return merged busy periods without titles, locations or attendees. A person the tenant does
//! not know has no periods (`known: false`) rather than an error. That does tell the assistant which addresses exist,
//! which is acceptable within a tenant: principal search over DAV exposes the same information to every member.

use davhaven_app::AppResult;
use davhaven_app::services::{BusyKind, BusyPeriod, FindSlotsRequest, FreeBusyRequest, FreeBusyTarget};
use davhaven_wire::mcp::{
    FindFreeSlotsInput, FindFreeSlotsOutput, FreeBusyInput, FreeBusyOutput, McpBusyKind, McpFreeBusyEntry, McpPeriod,
    McpSlot,
};

use super::Settings;
use crate::caller::Caller;
use crate::input::{self, DEFAULT_SLOTS, MAX_SLOTS};

/// The wire form of a kind of busy time.
const fn busy_kind(kind: BusyKind) -> McpBusyKind {
    match kind {
        BusyKind::Busy => McpBusyKind::Busy,
        BusyKind::BusyTentative => McpBusyKind::BusyTentative,
        BusyKind::BusyUnavailable => McpBusyKind::BusyUnavailable,
    }
}

/// The wire form of a busy period.
fn period(period: &BusyPeriod) -> McpPeriod {
    McpPeriod {
        start: period.start,
        end: period.end,
        kind: busy_kind(period.kind),
    }
}

/// `free_busy`: the busy periods of the listed people in a range, one entry per address in request order.
pub(super) async fn free_busy(
    caller: &Caller<'_>,
    settings: &Settings<'_>,
    input: FreeBusyInput,
) -> AppResult<FreeBusyOutput> {
    let addresses = input::calendar_addresses(&input.addresses)?;
    let range = input::time_range(input.start, input.end, settings.config.max_range_days)?;
    let result = caller
        .services
        .scheduling
        .free_busy(
            &caller.ctx,
            FreeBusyRequest {
                target: FreeBusyTarget::Addresses(addresses),
                range,
            },
        )
        .await?;
    // The answer has one entry per address in request order; each is labelled with the text the assistant sent.
    let entries = result
        .entries
        .iter()
        .enumerate()
        .map(|(index, entry)| McpFreeBusyEntry {
            address: input
                .addresses
                .get(index)
                .cloned()
                .or_else(|| entry.address.as_ref().map(ToString::to_string))
                .unwrap_or_default(),
            known: entry.known,
            busy: entry.periods.iter().map(period).collect(),
        })
        .collect();
    Ok(FreeBusyOutput { entries })
}

/// `find_free_slots`: when everybody is free for `duration_minutes`, optionally inside working hours.
pub(super) async fn find_free_slots(
    caller: &Caller<'_>,
    settings: &Settings<'_>,
    input: FindFreeSlotsInput,
) -> AppResult<FindFreeSlotsOutput> {
    let addresses = input::calendar_addresses(&input.addresses)?;
    let range = input::time_range(input.start, input.end, settings.config.max_range_days)?;
    let cap = MAX_SLOTS.min(settings.config.max_results);
    let limit = input::page_size(input.limit, DEFAULT_SLOTS, cap);
    let result = caller
        .services
        .scheduling
        .find_free_slots(
            &caller.ctx,
            FindSlotsRequest {
                addresses,
                range,
                duration_minutes: input.duration_minutes,
                working_hours: input.working_hours,
                time_zone: input.time_zone,
                limit: Some(limit),
            },
        )
        .await?;
    Ok(FindFreeSlotsOutput {
        slots: result
            .slots
            .iter()
            .map(|slot| McpSlot {
                start: slot.start,
                end: slot.end,
            })
            .collect(),
        truncated: result.truncated,
    })
}
