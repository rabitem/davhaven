//! Searching events across calendars (MCP `list_events` and `search_events`).
//!
//! The search reads the calendars the caller can read, narrows the objects with the index pre-filter and the exact
//! range filter, and returns the events. With `expand` every instance of a recurring event is one result carrying
//! its `recurrence_id`; otherwise every object is one result. Text search looks into summary, description and
//! location, case-insensitively, and needs at least two characters.
//!
//! # Order and paging
//!
//! The store pages objects by id, not by start, so the order of the results depends on how much there is to look
//! at. A request examines at most `max_scanned_objects` objects and builds at most [`MAX_KEYS`] result positions:
//!
//! * **Chronological.** When the whole search fits (the usual case: a range of days or weeks), the results are
//!   ordered by start, then by object id, and the cursor is the position `(start, id)` after the last result of the
//!   page, so concurrent changes never repeat or skip a result that did not change. Only positions are kept for the
//!   whole search; the events themselves are built for the page.
//! * **Scan order.** When the search does not fit, the scan is cut where its bound was reached and the page is
//!   what the scan found up to there; the cursor is the **position of the scan** (calendar, object and, inside an
//!   expanded series, the start of the last instance), and the next request continues behind it. A page is shown
//!   ordered by start, the pages follow the scan. A client that follows the cursors sees every result exactly once,
//!   and a result without a cursor means "no more events", never "stopped early" (MCP `truncated` is a cursor that
//!   exists). A cursor of one kind is not usable once the search has grown into the other kind (`Invalid`, start
//!   again).
//!
//! # What a caller may read
//!
//! For a caller that reads through MCP, events that are private to others (class `PRIVATE` or `CONFIDENTIAL`, in a
//! calendar the caller does not own) come out as the time they block (the `sight` module), and a text search never
//! matches their text: it could otherwise be used to read what the events say by asking for strings and watching
//! which events come back.
//!
//! # Bounds
//!
//! The expansion of recurring events is bounded by the page and by the number of positions: it does not materialize
//! an instance the text filter rejects, builds the events of the page only, and checks a wall-clock deadline
//! between instances. The cursors are signed with the key ring and bound to the tenant and to the search they were
//! made for (the calendars it names, its range, its text and whether it expands), so a client cannot forge a position
//! and a cursor of one search is refused by another: it would skip or repeat results.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use davhaven_domain::{
    AccessFacts, Calendar, CalendarId, CalendarKind, Classification, Decision, EventData, EventTime, ObjectId,
    Operation, PrincipalId, RequestContext, StoredObject, TimeZoneName, decide,
};
use davhaven_ical::ErrorContext;
use davhaven_ports::{CalendarFilter, KeyPurpose, PageReq, Signature, TxMode};
use davhaven_wire::{Cursor, EventView, Page};
use uuid::Uuid;

use super::ObjectServiceImpl;
use super::events::Linker;
use super::locate::{ApiCalendar, api_calendar};
use super::query::{index_filter_of, zone_of};
use super::sight::{hides, masks};
use crate::authz::{Deadline, blocking, field_error, found, require_scope};
use crate::error::{AppError, AppResult, SafeMessage};
use crate::services::{CalendarDataSpec, EventSearch, ObjectFilter, PageRequest};

/// The shortest text search.
const MIN_TEXT_CHARS: usize = 2;

/// The size of the pages the scan reads from the store.
const SCAN_PAGE: u32 = 200;

/// The most result positions a chronological search keeps. A search with more is answered in scan order.
const MAX_KEYS: usize = 100_000;

/// Where a request continues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Continue {
    /// Behind the result with this start (microseconds since the epoch) and object id.
    Chronological { start: i64, object: Uuid },
    /// Behind this position of the scan.
    Scan(Position),
}

/// A position of the scan: everything up to it has been looked at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Position {
    calendar: Uuid,
    /// The last object looked at; the nil id before the first object of the calendar.
    object: Uuid,
    /// For an expanded series: the start of the last instance delivered, in microseconds since the epoch.
    instance: Option<i64>,
}

fn bad_cursor() -> AppError {
    let message = SafeMessage::from_static(
        "The cursor is not valid for this search: pass the cursor of the previous page with the same arguments.",
    );
    AppError::invalid(message.clone()).with_field_error("/cursor", "invalid", message)
}

fn instance_text(instance: Option<i64>) -> String {
    instance.map_or_else(|| "n".to_owned(), |micros| micros.to_string())
}

/// What a cursor is bound to besides the tenant and the position: the search it continues. A cursor that is carried to
/// another search (another calendar, range, text or expansion) would skip or repeat results, so it is refused.
fn fingerprint(search: &EventSearch, needle: Option<&str>) -> String {
    let micros = |at: Option<DateTime<Utc>>| at.map_or_else(|| "-".to_owned(), |at| at.timestamp_micros().to_string());
    let (start, end) = search.range.map_or((None, None), |range| (range.start, range.end));
    format!(
        "{:?}/{}/{}/{}/{}",
        search.calendars,
        micros(start),
        micros(end),
        needle.unwrap_or_default(),
        search.expand
    )
}

/// What a signature covers.
fn payload(ctx: &RequestContext, fingerprint: &str, position: &Continue) -> Vec<u8> {
    match position {
        Continue::Chronological { start, object } => format!(
            "davhaven/cursor/c1/{}/search/{fingerprint}/{start}/{}",
            ctx.tenant,
            object.simple()
        ),
        Continue::Scan(position) => format!(
            "davhaven/cursor/s1/{}/search/{fingerprint}/{}/{}/{}",
            ctx.tenant,
            position.calendar.simple(),
            position.object.simple(),
            instance_text(position.instance)
        ),
    }
    .into_bytes()
}

/// The position a signed cursor names.
fn open_cursor(
    core: &crate::wiring::AppCore,
    ctx: &RequestContext,
    fingerprint: &str,
    cursor: &Cursor,
) -> AppResult<Continue> {
    // `c1.{kid}.{start}.{object}.{mac}` or `s1.{kid}.{calendar}.{object}.{instance}.{mac}`; the key id may contain
    // dots, so the text is read from the right.
    let text = cursor.as_str();
    let (position, kid, mac) = match text.get(..3) {
        Some("c1.") => {
            let mut parts = text.rsplitn(4, '.');
            let (Some(mac), Some(object), Some(start), Some(head)) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                return Err(bad_cursor());
            };
            let kid = head.strip_prefix("c1.").ok_or_else(bad_cursor)?;
            (
                Continue::Chronological {
                    start: start.parse().map_err(|_| bad_cursor())?,
                    object: Uuid::parse_str(object).map_err(|_| bad_cursor())?,
                },
                kid,
                mac,
            )
        }
        Some("s1.") => {
            let mut parts = text.rsplitn(5, '.');
            let (Some(mac), Some(instance), Some(object), Some(calendar), Some(head)) =
                (parts.next(), parts.next(), parts.next(), parts.next(), parts.next())
            else {
                return Err(bad_cursor());
            };
            let kid = head.strip_prefix("s1.").ok_or_else(bad_cursor)?;
            (
                Continue::Scan(Position {
                    calendar: Uuid::parse_str(calendar).map_err(|_| bad_cursor())?,
                    object: Uuid::parse_str(object).map_err(|_| bad_cursor())?,
                    instance: match instance {
                        "n" => None,
                        micros => Some(micros.parse().map_err(|_| bad_cursor())?),
                    },
                }),
                kid,
                mac,
            )
        }
        _ => return Err(bad_cursor()),
    };
    let mac = URL_SAFE_NO_PAD.decode(mac).map_err(|_| bad_cursor())?;
    if core.deps().keyring.verify(
        KeyPurpose::Cursor,
        &payload(ctx, fingerprint, &position),
        &Signature::new(kid, mac),
    ) {
        Ok(position)
    } else {
        Err(bad_cursor())
    }
}

fn make_cursor(
    core: &crate::wiring::AppCore,
    ctx: &RequestContext,
    fingerprint: &str,
    position: &Continue,
) -> AppResult<Cursor> {
    let signature = core
        .deps()
        .keyring
        .sign(KeyPurpose::Cursor, &payload(ctx, fingerprint, position));
    let mac = URL_SAFE_NO_PAD.encode(&signature.mac);
    let text = match position {
        Continue::Chronological { start, object } => {
            format!("c1.{}.{start}.{}.{mac}", signature.kid, object.simple())
        }
        Continue::Scan(position) => format!(
            "s1.{}.{}.{}.{}.{mac}",
            signature.kid,
            position.calendar.simple(),
            position.object.simple(),
            instance_text(position.instance)
        ),
    };
    Cursor::parse(&text).map_err(AppError::internal)
}

/// Whether the text of an event contains `needle` (lower case).
fn contains_text(data: &EventData, needle: &str) -> bool {
    [&data.summary, &data.description, &data.location]
        .into_iter()
        .flatten()
        .any(|field| field.to_lowercase().contains(needle))
}

/// Whether an event matches the text a search looks for: its text contains `needle` and the caller may read that
/// text. With `mask` (the caller reads through MCP in a calendar it does not own), an event that is only busy time to the
/// caller never matches, so that a search cannot be used to find out what the hidden text says (see the `sight` module).
fn matches_text(data: &EventData, class: Classification, needle: &str, mask: bool) -> bool {
    !(mask && hides(class, data)) && contains_text(data, needle)
}

/// One result of a search. Positions only (`object` and `data` are `None`) while the whole search is ordered;
/// complete when the event itself is built.
struct Found {
    calendar: CalendarId,
    object_id: ObjectId,
    object: Option<StoredObject>,
    start: DateTime<Utc>,
    /// The start of the instance when the series was expanded.
    instance: Option<i64>,
    data: Option<EventData>,
}

/// What a read of a batch of objects is to do.
struct Reading<'a> {
    calendar: CalendarId,
    range: Option<davhaven_ical::filter::TimeRange>,
    expand: bool,
    needle: Option<&'a str>,
    /// Whether to build only the positions of the events.
    positions_only: bool,
    /// The most results to produce; the read stops there.
    budget: usize,
    /// An instance after which the first object of the batch resumes (a scan cursor stands inside it).
    resume: Option<(ObjectId, i64)>,
    /// Build only these instances of these objects (the events of a chronological page); an unexpanded object is
    /// built whole when it is listed.
    only: Option<&'a HashMap<ObjectId, BTreeSet<i64>>>,
    /// Whether the caller reads through MCP in a calendar it does not own: events that are busy time to the caller
    /// never match a text search.
    mask: bool,
    deadline: Deadline,
}

/// Reads the events of `objects`: one per object, or one per instance inside the range when `expand` is set, up to
/// the budget. Instances the text filter rejects are never built.
fn read_blocking(
    objects: Vec<StoredObject>,
    reading: &Reading<'_>,
    zone_ics: Option<&str>,
    limits: &davhaven_domain::IcalLimits,
) -> Result<Vec<Found>, davhaven_ical::IcalError> {
    let zone: TimeZoneName = zone_of(zone_ics, limits);
    let mut found: Vec<Found> = Vec::new();
    for object in objects {
        reading.deadline.check()?;
        if found.len() >= reading.budget {
            break;
        }
        let wanted = match reading.only {
            Some(only) => match only.get(&object.id) {
                Some(instances) => Some(instances),
                None => continue,
            },
            None => None,
        };
        let calendar = davhaven_ical::parse::parse(object.data.as_bytes(), limits)?;
        let master = davhaven_ical::merge::to_event_data(&calendar, None)?;
        let (true, Some(range)) = (reading.expand, reading.range) else {
            if reading
                .needle
                .is_some_and(|needle| !matches_text(&master, object.class, needle, reading.mask))
            {
                continue;
            }
            let start = object
                .first_start
                .or_else(|| master.start.as_ref().and_then(|start| start.to_utc(zone)))
                .unwrap_or(DateTime::<Utc>::MAX_UTC);
            found.push(Found {
                calendar: reading.calendar,
                object_id: object.id,
                object: (!reading.positions_only).then_some(object),
                start,
                instance: None,
                data: (!reading.positions_only).then_some(master),
            });
            continue;
        };
        let after = reading
            .resume
            .filter(|(id, _)| *id == object.id)
            .map(|(_, micros)| micros);
        let master_matches = reading
            .needle
            .is_none_or(|needle| matches_text(&master, object.class, needle, reading.mask));
        for instance in davhaven_ical::expand::expand_in_zone(&calendar, &range, limits, zone)? {
            reading.deadline.check()?;
            if found.len() >= reading.budget {
                break;
            }
            let micros = instance.start.timestamp_micros();
            if after.is_some_and(|after| micros <= after) || wanted.is_some_and(|wanted| !wanted.contains(&micros)) {
                continue;
            }
            let data = if instance.is_override {
                let data = davhaven_ical::merge::to_event_data(&calendar, Some(&instance.recurrence_id))?;
                if reading
                    .needle
                    .is_some_and(|needle| !matches_text(&data, object.class, needle, reading.mask))
                {
                    continue;
                }
                Some(data)
            } else {
                // An instance without an override of its own says what the master says: when the master does not
                // match the text, no instance does, and none is built.
                if !master_matches {
                    continue;
                }
                if reading.positions_only {
                    None
                } else {
                    let mut data = master.clone();
                    let times = |at: DateTime<Utc>| {
                        if instance.all_day {
                            EventTime::Date(at.date_naive())
                        } else {
                            EventTime::Utc(at)
                        }
                    };
                    data.start = Some(times(instance.start));
                    if data.end.is_some() || data.duration.is_none() {
                        data.end = Some(times(instance.end));
                        data.duration = None;
                    }
                    data.recurrence = None;
                    data.recurrence_id = Some(instance.recurrence_id.clone());
                    Some(data)
                }
            };
            found.push(Found {
                calendar: reading.calendar,
                object_id: object.id,
                object: (!reading.positions_only).then(|| object.clone()),
                start: instance.start,
                instance: Some(micros),
                data: if reading.positions_only { None } else { data },
            });
        }
    }
    Ok(found)
}

/// One event of the page with the position the scan stands at behind it.
struct Hit {
    position: Position,
    start: DateTime<Utc>,
    id: Uuid,
    view: EventView,
}

/// What a search is made of besides the transaction.
struct Inputs<'a> {
    search: &'a EventSearch,
    filter: &'a ObjectFilter,
    needle: Option<&'a str>,
    size: usize,
    /// The principal who searches, when the search acts as one.
    principal: Option<PrincipalId>,
    /// Whether the caller reads through MCP: in calendars that are not their own, what is private to others is busy time.
    masking: bool,
    /// What a cursor of this search is bound to ([`fingerprint`]).
    fingerprint: String,
}

/// The positions of the results of a search: start in microseconds, object, calendar.
type Keys = Vec<(i64, Uuid, CalendarId)>;

/// What a read of objects asks besides the objects.
struct Read {
    positions_only: bool,
    budget: usize,
    resume: Option<(ObjectId, i64)>,
    only: Option<HashMap<ObjectId, BTreeSet<i64>>>,
}

impl Read {
    /// Positions of every result, as many as the budget allows.
    fn positions(budget: usize) -> Self {
        Self {
            positions_only: true,
            budget,
            resume: None,
            only: None,
        }
    }

    /// The events themselves, up to the budget, resuming inside an object when the cursor stands there.
    fn events(budget: usize, resume: Option<(ObjectId, i64)>) -> Self {
        Self {
            positions_only: false,
            budget,
            resume,
            only: None,
        }
    }

    /// The events at exactly these positions.
    fn at(only: HashMap<ObjectId, BTreeSet<i64>>) -> Self {
        Self {
            positions_only: false,
            budget: usize::MAX,
            resume: None,
            only: Some(only),
        }
    }
}

impl ObjectServiceImpl {
    /// The calendars a search covers, each with the caller's facts, in the order of their ids: the named ones, or
    /// every calendar the caller can list objects of. Principals find theirs through their bindings and the
    /// calendars they see without one (groups, grants); a tenant token, which has no home, through the group and
    /// managed calendars of the tenant, the only ones its scopes reach.
    async fn searchable(
        &self,
        tx: &mut dyn davhaven_ports::Tx,
        ctx: &RequestContext,
        search: &EventSearch,
    ) -> AppResult<Vec<ApiCalendar>> {
        if !search.calendars.is_empty() {
            let mut named: BTreeMap<CalendarId, ApiCalendar> = BTreeMap::new();
            for reference in &search.calendars {
                let target = api_calendar(tx, ctx, reference, Operation::ListObjects, false).await?;
                named.insert(target.calendar.id, target);
            }
            return Ok(named.into_values().collect());
        }
        let tenant = tx.tenant().get().await?;
        let mut all: BTreeMap<CalendarId, Calendar> = BTreeMap::new();
        if let Some(principal) = ctx.principal() {
            for bound in tx.bindings().list_for(principal).await? {
                // A calendar the principal hid from their home stays out of what is searched for them.
                if !bound.binding.hidden {
                    all.insert(bound.calendar.id, bound.calendar);
                }
            }
            for calendar in tx.calendars().visible_without_binding(principal).await? {
                all.insert(calendar.id, calendar);
            }
        } else {
            for kind in [CalendarKind::Group, CalendarKind::Managed] {
                let filter = CalendarFilter {
                    kind: Some(kind),
                    ..CalendarFilter::default()
                };
                let mut page = PageReq::first(1000);
                loop {
                    let batch = tx.calendars().list(&filter, page).await?;
                    for calendar in batch.items {
                        all.insert(calendar.id, calendar);
                    }
                    match batch.next {
                        Some(after) => page = page.after(after),
                        None => break,
                    }
                }
            }
        }
        let ids: Vec<CalendarId> = all.keys().copied().collect();
        let facts: HashMap<CalendarId, AccessFacts> = tx
            .calendars()
            .access_facts_many(&ids, ctx.principal())
            .await?
            .into_iter()
            .collect();
        let subject = ctx.subject();
        Ok(all
            .into_values()
            .filter_map(|calendar| {
                let facts = facts.get(&calendar.id)?.clone();
                (decide(&subject, ctx.channel, &facts, Operation::ListObjects) == Decision::Allow).then(|| {
                    ApiCalendar {
                        tenant: tenant.clone(),
                        calendar,
                        facts,
                    }
                })
            })
            .collect())
    }

    /// Checks the parts of a search that need no store and returns the lower-cased text to look for.
    fn checked_needle(&self, search: &EventSearch) -> AppResult<Option<String>> {
        let needle = match &search.text {
            Some(text) => {
                let text = text.trim().to_lowercase();
                if text.chars().count() < MIN_TEXT_CHARS {
                    return Err(field_error(
                        "/text",
                        "too-short",
                        "The search text needs at least two characters.",
                    ));
                }
                Some(text)
            }
            None => None,
        };
        let limits = &self.core.deps().limits.ical;
        if search.expand && search.range.is_none() {
            return Err(field_error(
                "/range",
                "required",
                "Expanding recurring events needs a time range.",
            ));
        }
        if let Some(range) = &search.range {
            let checked = if search.expand {
                range.validate_bounded(limits)
            } else {
                range.validate(limits)
            };
            checked.map_err(|error| AppError::from_ical(error, ErrorContext::Query))?;
        }
        Ok(needle)
    }

    /// Reads one batch of objects of a calendar on a blocking thread.
    async fn read_batch(
        &self,
        target: &ApiCalendar,
        inputs: &Inputs<'_>,
        needle: Option<&str>,
        objects: Vec<StoredObject>,
        read: Read,
    ) -> AppResult<Vec<Found>> {
        let zone = target.calendar.timezone_ics.clone();
        let (calendar, range, expand) = (target.calendar.id, inputs.search.range, inputs.search.expand);
        let needle = needle.map(str::to_owned);
        let deadline = Deadline::of(&self.core);
        let mask = inputs.masking && inputs.principal != Some(target.facts.owner);
        blocking(&self.core, ErrorContext::Query, move |limits| {
            let reading = Reading {
                calendar,
                range,
                expand,
                needle: needle.as_deref(),
                positions_only: read.positions_only,
                budget: read.budget,
                resume: read.resume,
                only: read.only.as_ref(),
                mask,
                deadline,
            };
            read_blocking(objects, &reading, zone.as_deref(), limits)
        })
        .await
    }

    /// Searches events across calendars; see the module documentation for the order and the cursors.
    pub(crate) async fn search(
        &self,
        ctx: &RequestContext,
        search: EventSearch,
        page: PageRequest,
    ) -> AppResult<Page<EventView>> {
        require_scope(ctx, Operation::ListObjects)?;
        let needle = self.checked_needle(&search)?;
        let size = usize::try_from(self.core.deps().limits.api.page_size(page.limit)).unwrap_or(usize::MAX);
        let fingerprint = fingerprint(&search, needle.as_deref());
        let after = page
            .cursor
            .as_ref()
            .map(|cursor| open_cursor(&self.core, ctx, &fingerprint, cursor))
            .transpose()?;
        let filter = ObjectFilter {
            range: search.range,
            ..ObjectFilter::default()
        };
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let calendars = self.searchable(tx.as_mut(), ctx, &search).await?;
        let inputs = Inputs {
            search: &search,
            filter: &filter,
            needle: needle.as_deref(),
            size,
            principal: ctx.principal(),
            masking: masks(ctx),
            fingerprint,
        };
        // A scan cursor continues the scan; otherwise the whole search is tried in chronological order first.
        if !matches!(after, Some(Continue::Scan(_))) {
            match self.collect_keys(tx.as_mut(), &calendars, &inputs).await? {
                Some(keys) => {
                    let cursor = match after {
                        Some(Continue::Chronological { start, object }) => Some((start, object)),
                        _ => None,
                    };
                    let page = self
                        .chronological_page(tx.as_mut(), ctx, &calendars, &inputs, keys, cursor)
                        .await?;
                    tx.commit().await?;
                    return Ok(page);
                }
                None if after.is_some() => {
                    // The search grew beyond what can be ordered since the cursor was made.
                    return Err(AppError::invalid(SafeMessage::from_static(
                        "The search has grown too large for this cursor; start again.",
                    )));
                }
                None => {}
            }
        }
        let from = match after {
            Some(Continue::Scan(position)) => Some(position),
            _ => None,
        };
        let page = self.scan_page(tx.as_mut(), ctx, &calendars, &inputs, from).await?;
        tx.commit().await?;
        Ok(page)
    }

    /// The positions of every result of the search, or `None` when the search is larger than a chronological
    /// order can be kept for (more objects than `max_scanned_objects` to look at, or more than [`MAX_KEYS`] results).
    async fn collect_keys(
        &self,
        tx: &mut dyn davhaven_ports::Tx,
        calendars: &[ApiCalendar],
        inputs: &Inputs<'_>,
    ) -> AppResult<Option<Keys>> {
        let max_scanned = usize::try_from(self.core.deps().limits.api.max_scanned_objects).unwrap_or(usize::MAX);
        let index = index_filter_of(inputs.filter);
        let mut keys: Keys = Vec::new();
        let mut scanned = 0_usize;
        for target in calendars {
            let mut request = PageReq::first(SCAN_PAGE);
            loop {
                let batch = tx.objects().query(target.calendar.id, &index, request).await?;
                scanned += batch.items.len();
                if scanned > max_scanned {
                    return Ok(None);
                }
                let matched = self
                    .evaluate(
                        target.calendar.timezone_ics.as_deref(),
                        batch.items,
                        inputs.filter,
                        &CalendarDataSpec::metadata_only(),
                    )
                    .await?;
                let objects: Vec<StoredObject> = matched.into_iter().map(|(object, _)| object).collect();
                let budget = MAX_KEYS.saturating_sub(keys.len()).saturating_add(1);
                let read = self
                    .read_batch(target, inputs, inputs.needle, objects, Read::positions(budget))
                    .await?;
                keys.extend(read.into_iter().map(|found| {
                    (
                        found.start.timestamp_micros(),
                        found.object_id.as_uuid(),
                        found.calendar,
                    )
                }));
                if keys.len() > MAX_KEYS {
                    return Ok(None);
                }
                match batch.next {
                    Some(next) => request = request.after(next),
                    None => break,
                }
            }
        }
        Ok(Some(keys))
    }

    /// One page of a chronological search: the keys ordered, cut after the cursor, the events of the page built.
    async fn chronological_page(
        &self,
        tx: &mut dyn davhaven_ports::Tx,
        ctx: &RequestContext,
        calendars: &[ApiCalendar],
        inputs: &Inputs<'_>,
        mut keys: Keys,
        cursor: Option<(i64, Uuid)>,
    ) -> AppResult<Page<EventView>> {
        keys.sort_by_key(|(start, object, _)| (*start, *object));
        if let Some(cursor) = cursor {
            keys.retain(|(start, object, _)| (*start, *object) > cursor);
        }
        let more = keys.len() > inputs.size;
        keys.truncate(inputs.size);
        let next = if more {
            keys.last()
                .map(|(start, object, _)| Continue::Chronological {
                    start: *start,
                    object: *object,
                })
                .map(|position| make_cursor(&self.core, ctx, &inputs.fingerprint, &position))
                .transpose()?
        } else {
            None
        };
        // The events of the page: the objects of its keys, read again and built for the instances the keys name.
        let mut by_calendar: BTreeMap<CalendarId, HashMap<ObjectId, BTreeSet<i64>>> = BTreeMap::new();
        for (start, object, calendar) in &keys {
            by_calendar
                .entry(*calendar)
                .or_default()
                .entry(ObjectId::from_uuid(*object))
                .or_default()
                .insert(*start);
        }
        let mut events: Vec<Found> = Vec::with_capacity(keys.len());
        for (calendar, wanted) in by_calendar {
            let Some(target) = calendars.iter().find(|target| target.calendar.id == calendar) else {
                continue;
            };
            let mut objects: Vec<StoredObject> = Vec::with_capacity(wanted.len());
            for object in wanted.keys() {
                // An object that was deleted since the keys were made is left out of the page.
                if let Some(object) = found(tx.objects().get_by_id(*object).await)?
                    && object.calendar_id == calendar
                {
                    objects.push(object);
                }
            }
            events.extend(self.read_batch(target, inputs, None, objects, Read::at(wanted)).await?);
        }
        let mut views: Vec<(DateTime<Utc>, Uuid, EventView)> = Vec::with_capacity(events.len());
        let mut linkers: HashMap<CalendarId, Linker> = HashMap::new();
        for event in events {
            let (Some(object), Some(data)) = (event.object, event.data) else {
                continue;
            };
            let Some(target) = calendars.iter().find(|target| target.calendar.id == event.calendar) else {
                continue;
            };
            let linker = match linkers.entry(event.calendar) {
                std::collections::hash_map::Entry::Occupied(known) => known.into_mut(),
                std::collections::hash_map::Entry::Vacant(slot) => slot.insert(self.linker(tx, ctx, target).await?),
            };
            views.push((event.start, object.id.as_uuid(), linker.view(&object, data)));
        }
        views.sort_by_key(|(start, id, _)| (*start, *id));
        Ok(Page::new(views.into_iter().map(|(_, _, view)| view).collect(), next))
    }

    /// One page of a search in scan order, continuing behind `from`; see the module documentation.
    async fn scan_page(
        &self,
        tx: &mut dyn davhaven_ports::Tx,
        ctx: &RequestContext,
        calendars: &[ApiCalendar],
        inputs: &Inputs<'_>,
        from: Option<Position>,
    ) -> AppResult<Page<EventView>> {
        let max_scanned = usize::try_from(self.core.deps().limits.api.max_scanned_objects).unwrap_or(usize::MAX);
        let mut scan = Scan {
            hits: Vec::new(),
            scanned: 0,
            frontier: None,
            finished: true,
            // One more result than the page holds tells whether the scan has more to give.
            want: inputs.size.saturating_add(1),
            max_scanned,
        };
        for (number, target) in calendars.iter().enumerate() {
            if self.scan_calendar(tx, ctx, target, inputs, from, &mut scan).await? == Step::Stop {
                break;
            }
            if scan.scanned >= max_scanned
                && let Some(next_calendar) = calendars.get(number + 1)
            {
                // The calendar ended where the bound did: the scan goes on at the start of the next one.
                scan.frontier = Some(Position {
                    calendar: next_calendar.calendar.id.as_uuid(),
                    object: Uuid::nil(),
                    instance: None,
                });
                scan.finished = false;
                break;
            }
        }
        let Scan {
            mut hits,
            frontier,
            finished,
            ..
        } = scan;
        let more = hits.len() > inputs.size;
        let next_position = if more {
            // The page is cut inside what the scan produced: the cursor stands behind its last result.
            hits.get(inputs.size.saturating_sub(1)).map(|hit| hit.position)
        } else if finished {
            None
        } else {
            frontier
        };
        hits.truncate(inputs.size);
        let next = next_position
            .map(|position| make_cursor(&self.core, ctx, &inputs.fingerprint, &Continue::Scan(position)))
            .transpose()?;
        hits.sort_by_key(|hit| (hit.start, hit.id));
        Ok(Page::new(hits.into_iter().map(|hit| hit.view).collect(), next))
    }

    /// Scans one calendar into `scan`, from the cursor when it stands in this calendar. `Stop` when the page is full
    /// or the scan bound was reached inside the calendar.
    async fn scan_calendar(
        &self,
        tx: &mut dyn davhaven_ports::Tx,
        ctx: &RequestContext,
        target: &ApiCalendar,
        inputs: &Inputs<'_>,
        from: Option<Position>,
        scan: &mut Scan,
    ) -> AppResult<Step> {
        let calendar_id = target.calendar.id;
        let index = index_filter_of(inputs.filter);
        let mut resume: Option<(ObjectId, i64)> = None;
        let mut leftover: Option<StoredObject> = None;
        let mut after_object: Option<Uuid> = None;
        if let Some(position) = from {
            if calendar_id.as_uuid() < position.calendar {
                return Ok(Step::Next);
            }
            if calendar_id.as_uuid() == position.calendar {
                after_object = (!position.object.is_nil()).then_some(position.object);
                if let Some(instance) = position.instance {
                    // The cursor stands inside a series: the rest of its instances come first.
                    let id = ObjectId::from_uuid(position.object);
                    leftover =
                        found(tx.objects().get_by_id(id).await)?.filter(|object| object.calendar_id == calendar_id);
                    resume = Some((id, instance));
                }
            }
        }
        let mut linker: Option<Linker> = None;
        let mut request = PageReq {
            limit: SCAN_PAGE,
            after: after_object,
        };
        loop {
            let batch = tx.objects().query(calendar_id, &index, request).await?;
            let last_object = batch.items.last().map(|object| object.id.as_uuid());
            let mut objects = batch.items;
            scan.scanned += objects.len();
            if let Some(object) = leftover.take() {
                objects.insert(0, object);
            }
            let matched = self
                .evaluate(
                    target.calendar.timezone_ics.as_deref(),
                    objects,
                    inputs.filter,
                    &CalendarDataSpec::metadata_only(),
                )
                .await?;
            let objects: Vec<StoredObject> = matched.into_iter().map(|(object, _)| object).collect();
            let read = self
                .read_batch(
                    target,
                    inputs,
                    inputs.needle,
                    objects,
                    Read::events(scan.want.saturating_sub(scan.hits.len()), resume.take()),
                )
                .await?;
            if !read.is_empty() && linker.is_none() {
                linker = Some(self.linker(tx, ctx, target).await?);
            }
            for event in read {
                let (Some(linker), Some(object), Some(data)) = (linker.as_ref(), event.object, event.data) else {
                    continue;
                };
                scan.hits.push(Hit {
                    position: Position {
                        calendar: calendar_id.as_uuid(),
                        object: object.id.as_uuid(),
                        instance: event.instance,
                    },
                    start: event.start,
                    id: object.id.as_uuid(),
                    view: linker.view(&object, data),
                });
            }
            if scan.hits.len() >= scan.want {
                scan.finished = false;
                return Ok(Step::Stop);
            }
            if let Some(last) = last_object {
                scan.frontier = Some(Position {
                    calendar: calendar_id.as_uuid(),
                    object: last,
                    instance: None,
                });
            }
            match batch.next {
                Some(next) => {
                    request = request.after(next);
                    if scan.scanned >= scan.max_scanned {
                        scan.finished = false;
                        return Ok(Step::Stop);
                    }
                }
                None => return Ok(Step::Next),
            }
        }
    }
}

/// What a scan in scan order has collected so far.
struct Scan {
    hits: Vec<Hit>,
    scanned: usize,
    /// Where the scan stands after the last object it finished.
    frontier: Option<Position>,
    /// Whether the scan ran to the end.
    finished: bool,
    /// The results that fill the page and one more.
    want: usize,
    max_scanned: usize,
}

/// Whether the scan goes on with the next calendar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Next,
    Stop,
}
