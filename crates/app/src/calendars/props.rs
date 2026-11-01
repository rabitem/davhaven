//! PROPPATCH: per-binding properties and shared calendar properties.
//!
//! Per-binding properties (display name, color, order, `schedule-calendar-transp`, default alarms and every
//! property the server does not interpret) are always writable by the binding's principal and stored on the binding
//! (PLAN 2.6). The description and the default time zone belong to the calendar itself and need write access.
//! A PROPPATCH is atomic: when one property is refused, none is applied and the others report `424`.

use davhaven_domain::{
    Calendar, CalendarSlug, Decision, ErrorKind, EventType, Operation, Precondition, PrincipalName, RequestContext,
    ResourcePath, TenantSlug, decide,
};
use davhaven_ical::ErrorContext;
use davhaven_ports::{CollectionProperty, PropertyScope, TxMode};

use super::CalendarServiceImpl;
use super::dav::{MAX_DESCRIPTION, MAX_DISPLAY_NAME};
use super::manage::calendar_payload;
use crate::audit::Journal;
use crate::authz::{
    blocking, check_color, clean_name, clean_optional_text, enforce, facts_for, lock_one, resolve_home, retrying,
};
use crate::error::{AppError, AppResult};
use crate::services::{PropPatch, PropPatchOutcome, PropertyChange, PropertyOutcome, PropertyStatus};

/// The verdict on a value that needs no store: a display name, a description or a color that is not acceptable.
fn value_status(change: &PropertyChange) -> PropertyStatus {
    let ok = match change {
        PropertyChange::DisplayName(Some(name)) => clean_name("/displayname", name, MAX_DISPLAY_NAME).is_ok(),
        PropertyChange::Description(value) => {
            clean_optional_text("/calendar-description", value.as_deref(), MAX_DESCRIPTION).is_ok()
        }
        PropertyChange::Color(Some(color)) => check_color("/calendar-color", Some(color)).is_ok(),
        _ => true,
    };
    if ok {
        PropertyStatus::Applied
    } else {
        PropertyStatus::Conflict
    }
}

/// What the check of the time zone value of one change found.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ZoneCheck {
    /// The change carries no time zone value (or clears it): there is nothing to parse.
    NotCarried,
    /// The value is one `VTIMEZONE` the server can name.
    Usable,
    /// The value is refused; the precondition says why.
    Refused(Precondition),
    /// The value was not parsed, because the caller could not change shared properties when the checks ran. A caller
    /// who may by the time the transaction decides still does not get the value applied unparsed (PLAN 2.15).
    NotChecked,
}

/// What the verdicts need to know besides the changes.
struct Judge<'a> {
    /// Whether the caller may change the shared properties of the calendar.
    may_write_shared: bool,
    /// What the check of the time zone value of every change found, in request order.
    zone_checks: &'a [ZoneCheck],
    /// The names of the dead properties the binding has now.
    names: Vec<(String, String)>,
    max_size: usize,
    max_count: usize,
}

impl Judge<'_> {
    /// The status of every change, in request order. Dead properties are counted as the patch would leave them.
    fn statuses(mut self, changes: &[PropertyChange]) -> Vec<PropertyStatus> {
        let mut statuses = Vec::with_capacity(changes.len());
        for (change, zone_check) in changes.iter().zip(self.zone_checks) {
            let status = match change {
                PropertyChange::Description(_) | PropertyChange::Timezone(_) if !self.may_write_shared => {
                    PropertyStatus::Forbidden
                }
                PropertyChange::Timezone(_) if matches!(zone_check, ZoneCheck::Refused(_)) => PropertyStatus::Conflict,
                // The right to change the zone came after the value was not parsed (the caller gained it between the
                // two decisions): the value is not applied unparsed, and the same request succeeds when it is repeated.
                PropertyChange::Timezone(Some(_)) if *zone_check == ZoneCheck::NotChecked => PropertyStatus::Forbidden,
                PropertyChange::Dead { name, value_xml } => {
                    self.dead(&(name.namespace.clone(), name.local.clone()), value_xml.as_deref())
                }
                other => value_status(other),
            };
            statuses.push(status);
        }
        statuses
    }

    fn dead(&mut self, key: &(String, String), value: Option<&str>) -> PropertyStatus {
        match value {
            Some(value) if key.0.len().saturating_add(key.1.len()).saturating_add(value.len()) > self.max_size => {
                PropertyStatus::InsufficientStorage
            }
            Some(_) if !self.names.contains(key) && self.names.len() >= self.max_count => {
                PropertyStatus::InsufficientStorage
            }
            Some(_) => {
                if !self.names.contains(key) {
                    self.names.push(key.clone());
                }
                PropertyStatus::Applied
            }
            None => {
                self.names.retain(|candidate| candidate != key);
                PropertyStatus::Applied
            }
        }
    }
}

/// The per-property answer of a PROPPATCH: when anything failed, what would have been applied reports `424`. A value
/// that is refused for a reason a precondition names (a time zone that is no `VTIMEZONE`: `valid-calendar-data`)
/// carries it, so that the protocol layer can say which one; the properties that depend on it do not.
fn outcome_of(changes: &[PropertyChange], statuses: &[PropertyStatus], zone_checks: &[ZoneCheck]) -> PropPatchOutcome {
    let failed = statuses.iter().any(|status| *status != PropertyStatus::Applied);
    PropPatchOutcome {
        results: changes
            .iter()
            .zip(statuses)
            .zip(zone_checks)
            .map(|((change, status), zone_check)| PropertyOutcome {
                name: change.name(),
                status: if failed && *status == PropertyStatus::Applied {
                    PropertyStatus::FailedDependency
                } else {
                    *status
                },
                precondition: match zone_check {
                    ZoneCheck::Refused(precondition) if *status == PropertyStatus::Conflict => {
                        Some(precondition.clone())
                    }
                    _ => None,
                },
            })
            .collect(),
    }
}

impl CalendarServiceImpl {
    /// Applies a PROPPATCH to a bound collection.
    pub(super) async fn patch_properties(
        &self,
        ctx: &RequestContext,
        path: &ResourcePath,
        edit: PropPatch,
    ) -> AppResult<PropPatchOutcome> {
        let ResourcePath::Collection {
            tenant,
            principal,
            binding,
        } = path
        else {
            return Err(AppError::not_found());
        };
        // A time zone is parsed on a blocking thread before the transaction opens. Parsing is work a caller who
        // may not change the zone must not be able to ask for, so a patch that carries one is decided first (one
        // more load of the facts, only for such patches); every other patch is decided once, in its transaction.
        let carries_zone = edit
            .changes
            .iter()
            .any(|change| matches!(change, PropertyChange::Timezone(Some(_))));
        let may_write_shared = if carries_zone {
            let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
            let home = resolve_home(tx.as_mut(), ctx, tenant, principal).await?;
            let binding = tx.bindings().get_by_slug(home.principal.id, binding).await?;
            let facts = facts_for(tx.as_mut(), ctx, binding.calendar_id).await?;
            enforce(ctx, &facts, Operation::PropPatchBinding, || path.href())?;
            tx.commit().await?;
            decide(&ctx.subject(), ctx.channel, &facts, Operation::UpdateCalendar) == Decision::Allow
        } else {
            true
        };
        // Time zones are parsed before the transaction opens, and only for a caller who may change them.
        let mut zone_checks = Vec::with_capacity(edit.changes.len());
        for change in &edit.changes {
            let check = match change {
                PropertyChange::Timezone(Some(_)) if !may_write_shared => ZoneCheck::NotChecked,
                PropertyChange::Timezone(Some(ics)) => {
                    let ics = ics.clone();
                    match blocking(&self.core, ErrorContext::Store, move |limits| {
                        davhaven_ical::tz::calendar_timezone(&ics, limits).map(|_| ())
                    })
                    .await
                    {
                        Ok(()) => ZoneCheck::Usable,
                        // The machine's problem is not a statement about the value.
                        Err(error) if matches!(error.kind(), ErrorKind::Unavailable | ErrorKind::Internal) => {
                            return Err(error);
                        }
                        // RFC 4791 section 5.2.2: the value of `calendar-timezone` must be a valid iCalendar object
                        // with one `VTIMEZONE`, whatever exactly is wrong with it.
                        Err(error) => ZoneCheck::Refused(Precondition::ValidCalendarData(
                            error.public_message().as_str().to_owned(),
                        )),
                    }
                }
                _ => ZoneCheck::NotCarried,
            };
            zone_checks.push(check);
        }
        retrying(false, || {
            self.patch_once(ctx, path, (tenant, principal, binding), &edit, &zone_checks)
        })
        .await
    }

    async fn patch_once(
        &self,
        ctx: &RequestContext,
        path: &ResourcePath,
        target: (&TenantSlug, &PrincipalName, &CalendarSlug),
        edit: &PropPatch,
        zone_checks: &[ZoneCheck],
    ) -> AppResult<PropPatchOutcome> {
        let (tenant_slug, principal, slug) = target;
        let limits = &self.core.deps().limits.dav;
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadWrite).await?;
        let home = resolve_home(tx.as_mut(), ctx, tenant_slug, principal).await?;
        let mut binding = tx.bindings().get_by_slug(home.principal.id, slug).await?;
        let mut calendar: Calendar = lock_one(tx.as_mut(), binding.calendar_id).await?;
        let facts = facts_for(tx.as_mut(), ctx, calendar.id).await?;
        enforce(ctx, &facts, Operation::PropPatchBinding, || path.href())?;
        let existing = tx
            .properties()
            .list(calendar.id, PropertyScope::Binding(binding.id))
            .await?;
        let statuses = Judge {
            may_write_shared: decide(&ctx.subject(), ctx.channel, &facts, Operation::UpdateCalendar) == Decision::Allow,
            zone_checks,
            names: existing
                .iter()
                .map(|property| (property.ns.clone(), property.name.clone()))
                .collect(),
            max_size: usize::try_from(limits.max_dead_property_size).unwrap_or(usize::MAX),
            max_count: usize::try_from(limits.max_dead_properties).unwrap_or(usize::MAX),
        }
        .statuses(&edit.changes);
        let outcome = outcome_of(&edit.changes, &statuses, zone_checks);
        if statuses.iter().any(|status| *status != PropertyStatus::Applied) {
            // Nothing is applied: the transaction ends without a write.
            tx.commit().await?;
            return Ok(outcome);
        }
        let original = binding.clone();
        let mut shared_changed = false;
        for change in &edit.changes {
            match change {
                PropertyChange::DisplayName(value) => {
                    // What is stored is what was validated: the trimmed name.
                    binding.display_name = match value {
                        Some(name) => Some(clean_name("/displayname", name, MAX_DISPLAY_NAME)?),
                        None => None,
                    };
                }
                PropertyChange::Color(value) => binding.color = check_color("/calendar-color", value.as_deref())?,
                PropertyChange::Order(value) => binding.sort_order = *value,
                PropertyChange::ScheduleTransparency(value) => binding.schedule_transp = *value,
                PropertyChange::Description(value) => {
                    shared_changed = true;
                    calendar.description =
                        clean_optional_text("/calendar-description", value.as_deref(), MAX_DESCRIPTION)?;
                }
                PropertyChange::Timezone(value) => {
                    shared_changed = true;
                    calendar.timezone_ics.clone_from(value);
                }
                PropertyChange::Dead { name, value_xml } => {
                    let scope = PropertyScope::Binding(binding.id);
                    match value_xml {
                        Some(value) => {
                            tx.properties()
                                .set(CollectionProperty {
                                    calendar_id: calendar.id,
                                    scope,
                                    ns: name.namespace.clone(),
                                    name: name.local.clone(),
                                    value_xml: value.clone(),
                                })
                                .await?;
                        }
                        None => {
                            tx.properties()
                                .remove(calendar.id, scope, &name.namespace, &name.local)
                                .await?;
                        }
                    }
                }
            }
        }
        if binding != original {
            tx.bindings().update(binding, original.version).await?;
        }
        if shared_changed {
            let stored = tx.calendars().update(calendar.clone(), calendar.version).await?;
            // The description and the time zone are the calendar's own: webhook consumers learn of the change the
            // way they do when the management API makes it.
            Journal::new(&self.core, ctx)
                .publish(tx.as_mut(), EventType::CalendarUpdated, calendar_payload(&stored))
                .await?;
        } else {
            // Property and binding changes move the `CTag` so that other clients of the principal refresh.
            tx.calendars().touch(calendar.id).await?;
        }
        tx.commit().await?;
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn judge(may_write_shared: bool, zone_checks: &[ZoneCheck]) -> Vec<PropertyStatus> {
        let changes: Vec<PropertyChange> = zone_checks
            .iter()
            .map(|_| PropertyChange::Timezone(Some("BEGIN:VCALENDAR".to_owned())))
            .collect();
        Judge {
            may_write_shared,
            zone_checks,
            names: Vec::new(),
            max_size: 4096,
            max_count: 50,
        }
        .statuses(&changes)
    }

    #[test]
    fn a_time_zone_is_applied_only_when_it_was_parsed() {
        let refused = ZoneCheck::Refused(Precondition::ValidCalendarData("no VTIMEZONE".to_owned()));
        assert_eq!(
            judge(true, &[ZoneCheck::Usable, refused.clone(), ZoneCheck::NotChecked]),
            [
                PropertyStatus::Applied,
                PropertyStatus::Conflict,
                PropertyStatus::Forbidden
            ],
            "a value that was not parsed is not applied, even when the caller may change the zone by now"
        );
        assert_eq!(
            judge(false, &[ZoneCheck::Usable, refused, ZoneCheck::NotChecked]),
            [PropertyStatus::Forbidden; 3],
            "a caller who may not change the zone is refused whatever the check found"
        );
    }

    #[test]
    fn only_a_refused_zone_names_a_precondition_and_the_others_depend_on_it() {
        let changes = [
            PropertyChange::Timezone(Some("x".to_owned())),
            PropertyChange::Order(Some(1)),
        ];
        let refusal = Precondition::ValidCalendarData("no VTIMEZONE".to_owned());
        let outcome = outcome_of(
            &changes,
            &[PropertyStatus::Conflict, PropertyStatus::Applied],
            &[ZoneCheck::Refused(refusal.clone()), ZoneCheck::NotCarried],
        );
        let shape: Vec<(PropertyStatus, Option<Precondition>)> = outcome
            .results
            .into_iter()
            .map(|result| (result.status, result.precondition))
            .collect();
        assert_eq!(
            shape,
            [
                (PropertyStatus::Conflict, Some(refusal)),
                (PropertyStatus::FailedDependency, None)
            ]
        );
    }
}
