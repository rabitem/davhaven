//! Applying replies to the organizer's copy and recording the delivery status.

use chrono::TimeDelta;
use davhaven_domain::{CalendarUserAddress, EventTime, IcalLimits, ItipMethod, PartStat};

use super::message::ItipMessage;
use super::{sequence_of, strip_schedule_in, utc_zones};
use crate::calendar::{
    Moment, Node, Param, Prop, address_of, entry_from_line, entry_moment, entry_text, escape_text, param_value,
    partstat_of,
};
use crate::error::{IcalError, LimitKind};
use crate::filter::TimeRange;
use crate::merge::{instance_set, master_index, override_from_master, override_index, set_param};
use crate::parse::ParsedCalendar;
use crate::zones::Zones;

/// The property that keeps the comment of an attendee on the organizer's copy. It is CalendarServer's, which Calendar on macOS
/// shows next to the attendee: one per attendee and component, naming the attendee in [`COMMENT_REF`] and the reply it came with
/// in [`COMMENT_STAMP`]. It stays on the organizer's copy: `build_message` does not copy it into what the other attendees
/// receive.
pub(crate) const ATTENDEE_COMMENT: &str = "X-CALENDARSERVER-ATTENDEE-COMMENT";
/// The parameter of [`ATTENDEE_COMMENT`] that names the attendee the comment is from.
const COMMENT_REF: &str = "X-CALENDARSERVER-ATTENDEE-REF";
/// The parameter of [`ATTENDEE_COMMENT`] that says when the attendee answered (the `DTSTAMP` of the reply, in UTC).
const COMMENT_STAMP: &str = "X-CALENDARSERVER-DTSTAMP";

/// The most characters of an attendee's comment the organizer's copy keeps: the limit of the RSVP page and of the mail, so that
/// an attendee who writes the comment into a `REPLY` (a mail gateway, a CalDAV client) cannot make the organizer's copy larger
/// than the comment of any other answer can, however long the `COMMENT` of the message is.
pub const MAX_COMMENT_CHARS: usize = 500;

/// The effect of a `REPLY` on the organizer's copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyApplication {
    /// The organizer copy with the attendee's `PARTSTAT` updated and the attendee's comment kept on it: an answer that comes
    /// with a `COMMENT` writes it as an `X-CALENDARSERVER-ATTENDEE-COMMENT` of the component the answer is for (replacing
    /// the attendee's earlier one), and an answer without one removes the earlier comment, which belonged to the earlier
    /// answer. The comment is returned in `comment` as well, for the organizer's notification.
    pub updated: ParsedCalendar,
    /// The attendee whose answer was applied.
    pub attendee: CalendarUserAddress,
    /// The answer.
    pub partstat: PartStat,
    /// The instances the reply applied to; empty for the whole series.
    pub instances: Vec<EventTime>,
    /// Whether the `SEQUENCE` of the reply matched the organizer copy (stale replies are rejected by the
    /// caller).
    pub sequence_matches: bool,
    /// The remark of the attendee (`COMMENT` of the reply), if there is one.
    pub comment: Option<String>,
}

/// One component of a reply, read.
struct Answer {
    rid: Option<Moment>,
    partstat: PartStat,
    sequence: i64,
    /// The `COMMENT` of the component, if it has a non-empty one.
    comment: Option<String>,
    /// The `DTSTAMP` of the component, in the form of a UTC date-time, when it has one.
    stamp: Option<String>,
}

/// Whether the entry is an [`ATTENDEE_COMMENT`].
fn is_attendee_comment(entry: &calcard::icalendar::ICalendarEntry) -> bool {
    matches!(&entry.name, Prop::Other(name) if name.eq_ignore_ascii_case(ATTENDEE_COMMENT))
}

/// The attendee an [`ATTENDEE_COMMENT`] names.
fn comment_attendee(entry: &calcard::icalendar::ICalendarEntry) -> Option<CalendarUserAddress> {
    entry
        .params
        .iter()
        .find(|param| matches!(&param.name, Param::Other(name) if name.eq_ignore_ascii_case(COMMENT_REF)))
        .and_then(|param| param.value.as_text())
        .and_then(|text| CalendarUserAddress::parse(text).ok())
}

/// The calendar without the comments that attendees gave with their answers. They are for the organizer: the people who read
/// the organizer's copy through a subscription feed (a bearer link that can be passed on) are not told what an attendee wrote.
#[must_use]
pub fn strip_attendee_comments(calendar: ParsedCalendar) -> ParsedCalendar {
    let mut root = calendar.root;
    for node in &mut root.children {
        node.entries.retain(|entry| !is_attendee_comment(entry));
    }
    ParsedCalendar::from_root(root)
}

/// Gives the comments back to the server on an organizer's write (see `apply_organizer_changes`): whatever comments the
/// client sent on `node` go (nobody who can write the organizer's copy can put words in an attendee's mouth), and the comment
/// that `reference` (the stored component of the same instance) holds for each of the `answered` attendees comes back.
pub(super) fn restore_comments(node: &mut Node, reference: Option<&Node>, answered: &[CalendarUserAddress]) {
    node.entries.retain(|entry| !is_attendee_comment(entry));
    let Some(reference) = reference else {
        return;
    };
    let kept: Vec<calcard::icalendar::ICalendarEntry> = reference
        .entries
        .iter()
        .filter(|entry| {
            is_attendee_comment(entry) && comment_attendee(entry).is_some_and(|who| answered.contains(&who))
        })
        .cloned()
        .collect();
    node.entries.extend(kept);
}

/// Removes the comments of the attendees whose answer goes back to `NEEDS-ACTION`: a comment belongs to its answer, and
/// there is no answer any more.
pub(super) fn drop_comments(node: &mut Node, reset: impl Fn(&CalendarUserAddress) -> bool) {
    node.entries
        .retain(|entry| !(is_attendee_comment(entry) && comment_attendee(entry).is_some_and(|who| reset(&who))));
}

/// Makes the comment of `attendee` on `target` the one of the answer: the earlier one goes, the new one (if the answer has one)
/// takes its place at the end of the component.
fn keep_comment(
    target: &mut Node,
    attendee: &CalendarUserAddress,
    comment: Option<&str>,
    stamp: Option<&str>,
) -> Result<(), IcalError> {
    target
        .entries
        .retain(|entry| !(is_attendee_comment(entry) && comment_attendee(entry).as_ref() == Some(attendee)));
    let Some(comment) = comment else {
        return Ok(());
    };
    let stamp = stamp.map_or_else(String::new, |stamp| format!(";{COMMENT_STAMP}={stamp}"));
    let line = format!(
        "{ATTENDEE_COMMENT};{COMMENT_REF}={}{stamp}:{}",
        param_value(attendee.as_str()),
        escape_text(comment)
    );
    target.entries.push(entry_from_line(&line)?);
    Ok(())
}

/// Applies the `REPLY` in `reply` to the organizer copy `organizer_copy` with the default limits.
///
/// The application calls [`apply_reply_with`], which takes the configured limits and the address the reply came
/// from; this form trusts the attendee named in the reply and is meant for tests.
///
/// # Errors
///
/// As [`apply_reply_with`].
pub fn apply_reply(organizer_copy: &ParsedCalendar, reply: &ItipMessage) -> Result<ReplyApplication, IcalError> {
    apply_reply_with(organizer_copy, reply, &IcalLimits::default(), None)
}

/// Applies the `REPLY` in `reply` to the organizer copy `organizer_copy`.
///
/// * The reply's `ATTENDEE` must be on the organizer copy, and when `expected_attendee` is given (the address
///   the message was sent from, checked by the caller against the sender, never taken from the body) it must be
///   that address: a reply that names somebody else is refused, so an attendee cannot answer for another.
/// * A reply to an instance without an override creates the override in the copy. The instances are looked up
///   in one expansion for the whole reply, and a reply may name at most `max_recurrence_dates` instances, within
///   `max_time_range_years` of each other.
/// * A reply without `RECURRENCE-ID` answers the whole series: the master and every override that still carries
///   the attendee's earlier answer to the series are updated; an override the attendee answered differently
///   keeps that answer.
/// * The result must still be an object the server stores: no more components than `max_components`, no larger
///   than `max_resource_size`.
/// * The attendee's comment is cut to [`MAX_COMMENT_CHARS`]. When the comments are what makes the result larger than
///   `max_resource_size` (every override an answer to the series reaches carries one), the answer is applied without
///   them: an attendee's remark never makes the organizer's copy unreadable or the next answers impossible.
///
/// # Errors
///
/// [`IcalError::Invalid`] when the reply does not match the object (unknown attendee or instance, answers of
/// several attendees, an attendee other than the expected one, a method other than `REPLY`);
/// [`IcalError::Limit`] when the reply names too many instances or the result is too large.
pub fn apply_reply_with(
    organizer_copy: &ParsedCalendar,
    reply: &ItipMessage,
    limits: &IcalLimits,
    expected_attendee: Option<&CalendarUserAddress>,
) -> Result<ReplyApplication, IcalError> {
    match apply(organizer_copy, reply, limits, expected_attendee, true) {
        // The comments are what made the copy too large: the answer counts, the remarks do not.
        Err(IcalError::Limit(LimitKind::ResourceSize)) => {
            apply(organizer_copy, reply, limits, expected_attendee, false)
        }
        result => result,
    }
}

/// The `DTSTAMP` of a component of a reply as a UTC date-time (`20270210T080000Z`), when it has one in UTC.
fn stamp_of(component: &Node) -> Option<String> {
    match component.first(&Prop::Dtstamp).and_then(entry_moment) {
        Some(Moment::Utc(utc)) => Some(format!("{}Z", utc.format("%Y%m%dT%H%M%S"))),
        _ => None,
    }
}

/// [`apply_reply_with`] with or without writing the comments of the answers on the copy.
fn apply(
    organizer_copy: &ParsedCalendar,
    reply: &ItipMessage,
    limits: &IcalLimits,
    expected_attendee: Option<&CalendarUserAddress>,
    write_comments: bool,
) -> Result<ReplyApplication, IcalError> {
    if reply.method != ItipMethod::Reply {
        return Err(IcalError::invalid("only a REPLY can be applied"));
    }
    let reply_zones = utc_zones(&reply.calendar.root);
    let mut root = organizer_copy.root.clone();
    let zones = utc_zones(&root);
    let uid = organizer_copy
        .root
        .children
        .iter()
        .filter(|node| node.component_kind().is_some())
        .find_map(Node::uid);
    let mut attendee: Option<CalendarUserAddress> = None;
    let mut comment: Option<String> = None;
    let mut answers: Vec<Answer> = Vec::new();
    let max_instances = usize::try_from(limits.max_recurrence_dates).unwrap_or(usize::MAX);
    for component in reply
        .calendar
        .root
        .children
        .iter()
        .filter(|node| node.component_kind().is_some())
    {
        if component.uid() != uid {
            return Err(IcalError::invalid("the reply is for another event"));
        }
        let entries: Vec<&calcard::icalendar::ICalendarEntry> = component.all(&Prop::Attendee).collect();
        let [entry] = entries.as_slice() else {
            return Err(IcalError::invalid("a REPLY needs exactly one ATTENDEE per component"));
        };
        let address =
            address_of(entry).ok_or_else(|| IcalError::invalid("the ATTENDEE of the reply is not a valid address"))?;
        if attendee.as_ref().is_some_and(|previous| previous != &address) {
            return Err(IcalError::invalid("a REPLY must come from one attendee"));
        }
        if expected_attendee.is_some_and(|expected| expected != &address) {
            return Err(IcalError::invalid(
                "the reply answers for another attendee than the one who sent it",
            ));
        }
        let own_comment = component
            .first(&Prop::Comment)
            .and_then(entry_text)
            .filter(|text| !text.is_empty())
            .map(|text| text.chars().take(MAX_COMMENT_CHARS).collect::<String>());
        if comment.is_none() {
            comment.clone_from(&own_comment);
        }
        answers.push(Answer {
            rid: component.first(&Prop::RecurrenceId).and_then(entry_moment),
            partstat: partstat_of(entry),
            sequence: sequence_of(component),
            comment: own_comment.filter(|_| write_comments),
            stamp: stamp_of(component),
        });
        attendee = Some(address);
    }
    let attendee = attendee.ok_or_else(|| IcalError::invalid("the reply holds no component"))?;
    if answers.len() > max_instances {
        return Err(IcalError::Limit(LimitKind::RecurrenceDates));
    }
    check_instances(&root, &zones, limits, &answers)?;
    // The answer to the series first, so that the answers to single instances win over it.
    answers.sort_by_key(|answer| answer.rid.is_some());
    let mut sequence_matches = true;
    let mut partstat: Option<PartStat> = None;
    let mut instances: Vec<EventTime> = Vec::new();
    for answer in &answers {
        let index = match &answer.rid {
            None => master_index(&root).ok_or_else(|| IcalError::invalid("the object has no master component"))?,
            Some(rid) => override_target(&mut root, &zones, rid)?,
        };
        let target = root
            .children
            .get_mut(index)
            .ok_or_else(|| IcalError::invalid("the component is missing"))?;
        let previous = set_answer(target, &attendee, answer.partstat)?;
        keep_comment(target, &attendee, answer.comment.as_deref(), answer.stamp.as_deref())?;
        if answer.sequence != sequence_of(target) {
            sequence_matches = false;
        }
        match &answer.rid {
            Some(rid) => instances.push(rid.to_event_time(&reply_zones)),
            None => carry_to_overrides(&mut root, &attendee, previous, answer)?,
        }
        if partstat.is_none() || answer.rid.is_none() {
            partstat = Some(answer.partstat);
        }
    }
    check_result(&root, limits)?;
    Ok(ReplyApplication {
        updated: ParsedCalendar::from_root(root),
        attendee,
        partstat: partstat.unwrap_or_default(),
        instances,
        sequence_matches,
        comment,
    })
}

/// Checks in one expansion that every instance the reply names without an override exists.
fn check_instances(root: &Node, zones: &Zones, limits: &IcalLimits, answers: &[Answer]) -> Result<(), IcalError> {
    let missing: Vec<&Moment> = answers
        .iter()
        .filter_map(|answer| answer.rid.as_ref())
        .filter(|rid| override_index(root, zones, rid).is_none())
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    let instants: Vec<_> = missing.iter().filter_map(|rid| zones.to_utc(rid)).collect();
    let (Some(first), Some(last)) = (instants.iter().min().copied(), instants.iter().max().copied()) else {
        return Err(IcalError::invalid(
            "the reply names an instance the event does not have",
        ));
    };
    let reach = TimeDelta::try_days(2).unwrap_or_default();
    let window = TimeRange::new(first.checked_sub_signed(reach), last.checked_add_signed(reach));
    window.validate_bounded(limits).map_err(|error| match error {
        IcalError::Limit(LimitKind::TimeRange) => IcalError::invalid("the reply names instances too far apart"),
        other => other,
    })?;
    let known = instance_set(root, zones, limits, &window)?;
    if missing.iter().all(|rid| known.contains(zones, rid)) {
        Ok(())
    } else {
        Err(IcalError::invalid(
            "the reply names an instance the event does not have",
        ))
    }
}

/// The index of the override for `rid`; an instance of the series that has no override gets one, copied from
/// the master. That the instance exists has been checked.
fn override_target(root: &mut Node, zones: &Zones, rid: &Moment) -> Result<usize, IcalError> {
    if let Some(index) = override_index(root, zones, rid) {
        return Ok(index);
    }
    let master = master_index(root).ok_or_else(|| IcalError::invalid("the object has no master component"))?;
    let node = override_from_master(root, master, rid, zones)?;
    root.children.push(node);
    Ok(root.children.len().saturating_sub(1))
}

/// Writes the answer of `attendee` on the component and returns the answer it had before.
fn set_answer(target: &mut Node, attendee: &CalendarUserAddress, answer: PartStat) -> Result<PartStat, IcalError> {
    let stored = target
        .entries
        .iter_mut()
        .find(|candidate| candidate.name == Prop::Attendee && address_of(candidate).as_ref() == Some(attendee))
        .ok_or_else(|| IcalError::invalid("the attendee is not on the event"))?;
    let previous = partstat_of(stored);
    set_param(stored, &Param::Partstat, "PARTSTAT", answer.as_ical())?;
    Ok(previous)
}

/// An answer to the series also answers the overrides that still carry the earlier answer (they were copied from
/// the master); one the attendee answered differently stays.
fn carry_to_overrides(
    root: &mut Node,
    attendee: &CalendarUserAddress,
    previous: PartStat,
    answer: &Answer,
) -> Result<(), IcalError> {
    for node in root
        .children
        .iter_mut()
        .filter(|node| node.component_kind().is_some() && node.is_override())
    {
        let mut carried = false;
        for entry in node
            .entries
            .iter_mut()
            .filter(|entry| entry.name == Prop::Attendee && address_of(entry).as_ref() == Some(attendee))
        {
            if partstat_of(entry) == previous {
                set_param(entry, &Param::Partstat, "PARTSTAT", answer.partstat.as_ical())?;
                carried = true;
            }
        }
        // The comment goes with the answer, to every instance the answer reached.
        if carried {
            keep_comment(node, attendee, answer.comment.as_deref(), answer.stamp.as_deref())?;
        }
    }
    Ok(())
}

/// A reply may not grow the object past what the server stores.
fn check_result(root: &Node, limits: &IcalLimits) -> Result<(), IcalError> {
    let components = root.children.len();
    if components > usize::try_from(limits.max_components).unwrap_or(usize::MAX) {
        return Err(IcalError::Limit(LimitKind::Components));
    }
    let text = crate::serialize::serialize(&ParsedCalendar::from_root(root.clone()))?;
    if u64::try_from(text.len()).unwrap_or(u64::MAX) > limits.max_resource_size {
        return Err(IcalError::Limit(LimitKind::ResourceSize));
    }
    Ok(())
}

/// Writes the `SCHEDULE-STATUS` of `attendee` into the organizer copy (`1.2` delivered, `1.0` queued, `1.1`
/// iMIP sent, `3.7` unknown address, `5.x` failed). Does not touch any other property.
///
/// # Errors
///
/// [`IcalError::Invalid`] when the attendee is not on the object or the status is not of the form `n.n`.
pub fn set_schedule_status(
    organizer_copy: &ParsedCalendar,
    attendee: &CalendarUserAddress,
    status: &str,
) -> Result<ParsedCalendar, IcalError> {
    let parts: Vec<&str> = status.split('.').collect();
    let well_formed = (2..=3).contains(&parts.len())
        && status.len() <= 16
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()));
    if !well_formed {
        return Err(IcalError::invalid("a schedule status looks like 1.2"));
    }
    let mut root = organizer_copy.root.clone();
    let mut found = false;
    for node in root.children.iter_mut().filter(|node| node.component_kind().is_some()) {
        for entry in node
            .entries
            .iter_mut()
            .filter(|entry| entry.name == Prop::Attendee && address_of(entry).as_ref() == Some(attendee))
        {
            set_param(entry, &Param::ScheduleStatus, "SCHEDULE-STATUS", status)?;
            found = true;
        }
    }
    if !found {
        return Err(IcalError::invalid("the attendee is not on the event"));
    }
    Ok(ParsedCalendar::from_root(root))
}

/// Removes every `SCHEDULE-*` parameter (`SCHEDULE-AGENT`, `SCHEDULE-STATUS`, `SCHEDULE-FORCE-SEND`) from a
/// calendar that leaves the server.
///
/// # Errors
///
/// Never fails today; the `Result` keeps the signature stable.
pub fn strip_schedule_params(calendar: &ParsedCalendar) -> Result<ParsedCalendar, IcalError> {
    let mut root = calendar.root.clone();
    strip_schedule_in(&mut root);
    Ok(ParsedCalendar::from_root(root))
}
