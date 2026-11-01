//! `calendar-multiget` and `calendar-query`: the index pre-filter of the store, the exact evaluation with
//! `davhaven-ical`, and the projection of `calendar-data`.
//!
//! Queries are answered in two steps (PLAN 2.7, "Query semantics"): the store returns a *superset* of the matches
//! from its index (time range, component, UID, external key), and the objects of that superset are then judged
//! exactly with the filter of the request. Stored bytes are returned verbatim unless the request asks for a
//! projection (component and property selection, `expand`, `limit-recurrence-set`).
//!
//! Both steps are bounded by the DAV limits (`limits.dav`): a query that has to read the text of its candidates (an
//! exact filter) examines at most `max_query_candidates` of them and returns at most `max_query_results` objects
//! and `max_query_bytes` bytes of calendar data; beyond that it answers `DAV:number-of-matches-within-limits`. The
//! bytes are counted while the data is built, per object, so a projection that expands every instance of a
//! recurring event stops at the budget instead of after the page. A `multiget` names at most
//! `max_multiget_hrefs` resources (403, PLAN 2.15).

use std::collections::HashMap;

use davhaven_domain::{
    ComponentKind, IcalLimits, ObjectUri, Operation, Precondition, RequestContext, ResourcePath, StoredObject,
};
use davhaven_ical::filter::{CalendarFilter, CompFilter, TimeRange as IcalRange};
use davhaven_ical::{ErrorContext, IcalError};
use davhaven_ports::{IndexFilter, ObjectHead, PageReq, StoreError, TimeRange, TxMode};

use super::ObjectServiceImpl;
use super::locate::{Located, Target, locate};
use crate::authz::{Deadline, blocking, enforce};
use crate::error::{AppError, AppResult, SafeMessage};
use crate::services::{CalendarDataSpec, MultigetEntry, ObjectFilter, ObjectHit};

/// The size of the pages a query reads from the store.
const PAGE: u32 = 200;

fn too_many() -> AppError {
    AppError::invalid(SafeMessage::from_static("The query matches too many resources."))
        .with_precondition(Precondition::NumberOfMatchesWithinLimits)
}

/// The floating zone of a calendar: its `calendar-timezone`, or UTC when it has none.
pub(crate) fn zone_of(ics: Option<&str>, limits: &IcalLimits) -> davhaven_domain::TimeZoneName {
    ics.and_then(|ics| davhaven_ical::tz::calendar_timezone(ics, limits).ok())
        .unwrap_or_default()
}

/// The pre-filter the index can answer for a request.
pub(crate) fn index_filter_of(filter: &ObjectFilter) -> IndexFilter {
    let mut index = IndexFilter {
        component: filter.component,
        uid: filter.uid.clone(),
        external_key: filter.external_key.clone(),
        ..IndexFilter::all()
    };
    let mut range: Option<IcalRange> = filter.range;
    if let Some(query) = &filter.calendar_filter
        && let [child] = query.root.comp_filters.as_slice()
        && !child.is_not_defined
    {
        if index.component.is_none() {
            index.component = ComponentKind::from_ical(&child.name);
        }
        if range.is_none() {
            range = child.time_range;
        }
    }
    index.time_range = range.map(|range| TimeRange {
        start: range.start,
        end: range.end,
    });
    index
}

/// The filter that checks a time range against the main component of an object.
fn range_filter(range: IcalRange, component: ComponentKind) -> CalendarFilter {
    CalendarFilter {
        root: CompFilter {
            name: "VCALENDAR".to_owned(),
            is_not_defined: false,
            time_range: None,
            prop_filters: Vec::new(),
            comp_filters: vec![CompFilter {
                name: component.as_ical().to_owned(),
                is_not_defined: false,
                time_range: Some(range),
                prop_filters: Vec::new(),
                comp_filters: Vec::new(),
            }],
        },
    }
}

/// What the evaluation of one batch of candidates produced: the matches with their (projected) data.
pub(crate) type Matched = Vec<(StoredObject, Option<String>)>;

/// What an evaluation may spend besides the limits of the data: when it must stop, and how many bytes of
/// calendar data it may build.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Pace {
    deadline: Option<Deadline>,
    max_bytes: usize,
}

impl Pace {
    /// No deadline and no byte budget.
    #[cfg(test)]
    pub(crate) const fn unbounded() -> Self {
        Self {
            deadline: None,
            max_bytes: usize::MAX,
        }
    }

    /// Stops at the wall-clock deadline of a blocking job and at `max_bytes` of data.
    pub(crate) fn new(core: &crate::wiring::AppCore, max_bytes: usize) -> Self {
        Self {
            deadline: Some(Deadline::of(core)),
            max_bytes,
        }
    }
}

/// Judges candidates exactly and projects their data, on a blocking thread.
#[cfg(test)]
fn evaluate_blocking(
    candidates: Vec<StoredObject>,
    filter: &ObjectFilter,
    data: &CalendarDataSpec,
    calendar_zone: Option<&str>,
    limits: &IcalLimits,
) -> Result<Matched, IcalError> {
    evaluate_paced(candidates, filter, data, calendar_zone, limits, &Pace::unbounded()).map(|(matched, _)| matched)
}

/// [`evaluate_blocking`] that stops between objects at the deadline and as soon as the data it built exceeds the
/// byte budget; the flag says that it did (the matches are then incomplete).
fn evaluate_paced(
    candidates: Vec<StoredObject>,
    filter: &ObjectFilter,
    data: &CalendarDataSpec,
    calendar_zone: Option<&str>,
    limits: &IcalLimits,
    pace: &Pace,
) -> Result<(Matched, bool), IcalError> {
    let zone = zone_of(calendar_zone, limits);
    let exact = filter.calendar_filter.is_some() || filter.range.is_some();
    let project = data.include_data && !data.projection.is_identity();
    let mut matched = Vec::with_capacity(candidates.len());
    let mut bytes = 0_usize;
    for object in candidates {
        if let Some(deadline) = pace.deadline {
            deadline.check()?;
        }
        if !exact && !project {
            let text = data.include_data.then(|| object.data.clone());
            bytes = bytes.saturating_add(text.as_ref().map_or(0, String::len));
            if bytes > pace.max_bytes {
                return Ok((matched, true));
            }
            matched.push((object, text));
            continue;
        }
        let calendar = davhaven_ical::parse::parse(object.data.as_bytes(), limits)?;
        if let Some(query) = &filter.calendar_filter
            && !davhaven_ical::filter::matches_in_zone(&calendar, query, limits, zone)?
        {
            continue;
        }
        if let Some(range) = filter.range
            && !davhaven_ical::filter::matches_in_zone(&calendar, &range_filter(range, object.component), limits, zone)?
        {
            continue;
        }
        let text = if !data.include_data {
            None
        } else if project {
            Some(davhaven_ical::projection::project_in_zone(
                &calendar,
                &data.projection,
                limits,
                zone,
            )?)
        } else {
            Some(object.data.clone())
        };
        bytes = bytes.saturating_add(text.as_ref().map_or(0, String::len));
        if bytes > pace.max_bytes {
            return Ok((matched, true));
        }
        matched.push((object, text));
    }
    Ok((matched, false))
}

impl ObjectServiceImpl {
    /// Judges a batch of candidates and projects their data (see [`evaluate_blocking`]).
    pub(crate) async fn evaluate(
        &self,
        calendar_zone: Option<&str>,
        candidates: Vec<StoredObject>,
        filter: &ObjectFilter,
        data: &CalendarDataSpec,
    ) -> AppResult<Matched> {
        let filter = filter.clone();
        let data = data.clone();
        let zone = calendar_zone.map(str::to_owned);
        let pace = Pace::new(&self.core, usize::MAX);
        blocking(&self.core, ErrorContext::Query, move |limits| {
            evaluate_paced(candidates, &filter, &data, zone.as_deref(), limits, &pace).map(|(matched, _)| matched)
        })
        .await
    }

    /// [`evaluate`](Self::evaluate) under a byte budget: `None` when the data the matches need exceeds it.
    async fn evaluate_within(
        &self,
        calendar_zone: Option<&str>,
        candidates: Vec<StoredObject>,
        filter: &ObjectFilter,
        data: &CalendarDataSpec,
        max_bytes: usize,
    ) -> AppResult<Option<Matched>> {
        let filter = filter.clone();
        let data = data.clone();
        let zone = calendar_zone.map(str::to_owned);
        let pace = Pace::new(&self.core, max_bytes);
        let (matched, over) = blocking(&self.core, ErrorContext::Query, move |limits| {
            evaluate_paced(candidates, &filter, &data, zone.as_deref(), limits, &pace)
        })
        .await?;
        Ok((!over).then_some(matched))
    }

    /// `calendar-multiget`: the listed objects of one collection, in request order.
    pub(crate) async fn multiget_objects(
        &self,
        ctx: &RequestContext,
        collection: &ResourcePath,
        paths: Vec<ResourcePath>,
        data: CalendarDataSpec,
    ) -> AppResult<Vec<MultigetEntry>> {
        let Some((target, None)) = Target::of(collection) else {
            return Err(AppError::not_found());
        };
        let max = usize::try_from(self.core.deps().limits.dav.max_multiget_hrefs).unwrap_or(usize::MAX);
        if paths.len() > max {
            // PLAN 2.15: more hrefs than the limit allows is `403`, not a statement about matches.
            return Err(AppError::forbidden().with_public_message(SafeMessage::from_static(
                "The request names more resources than a multiget accepts.",
            )));
        }
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let located = locate(tx.as_mut(), ctx, target, false).await?;
        enforce(ctx, &located.facts, Operation::ListObjects, || collection.href())?;
        let home_collection = located.collection_path();
        let mut wanted: Vec<ObjectUri> = paths
            .iter()
            .filter_map(|path| match path {
                ResourcePath::Object { object, .. } if path.parent().as_ref() == Some(&home_collection) => {
                    Some(object.clone())
                }
                _ => None,
            })
            .collect();
        wanted.sort();
        wanted.dedup();
        // Pages of the size the other reads use: up to a thousand full objects at once would be a lot of memory.
        let mut views: HashMap<ObjectUri, ObjectHit> = HashMap::new();
        for chunk in wanted.chunks(usize::try_from(PAGE).unwrap_or(200)) {
            let filter = IndexFilter {
                uris: Some(chunk.to_vec()),
                ..IndexFilter::all()
            };
            let page = tx
                .objects()
                .query(located.calendar.id, &filter, PageReq::first(PAGE))
                .await?;
            let matched = self
                .evaluate(
                    located.calendar.timezone_ics.as_deref(),
                    page.items,
                    &ObjectFilter::default(),
                    &data,
                )
                .await?;
            views.extend(
                matched
                    .into_iter()
                    .map(|(object, text)| (object.uri.clone(), located.view(&object, text))),
            );
        }
        tx.commit().await?;
        Ok(paths
            .into_iter()
            .map(|path| match &path {
                ResourcePath::Object { object, .. } if path.parent().as_ref() == Some(&home_collection) => {
                    match views.get(object) {
                        Some(view) => MultigetEntry::Found(view.clone()),
                        None => MultigetEntry::Missing(path),
                    }
                }
                _ => MultigetEntry::Missing(path),
            })
            .collect())
    }

    /// `calendar-query`: the objects matching a filter, ordered by resource name.
    pub(crate) async fn query_objects(
        &self,
        ctx: &RequestContext,
        collection: &ResourcePath,
        filter: ObjectFilter,
        data: CalendarDataSpec,
    ) -> AppResult<Vec<ObjectHit>> {
        let Some((target, None)) = Target::of(collection) else {
            return Err(AppError::not_found());
        };
        let limits = self.core.deps().limits.ical.clone();
        if let Some(query) = &filter.calendar_filter {
            davhaven_ical::filter::validate_filter(query, &limits)
                .map_err(|error| AppError::from_ical(error, ErrorContext::Query))?;
        }
        if let Some(range) = &filter.range {
            range
                .validate(&limits)
                .map_err(|error| AppError::from_ical(error, ErrorContext::Query))?;
        }
        let mut tx = self.core.deps().database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let located = locate(tx.as_mut(), ctx, target, false).await?;
        enforce(ctx, &located.facts, Operation::ListObjects, || collection.href())?;
        let index = index_filter_of(&filter);
        let exact = filter.calendar_filter.is_some() || filter.range.is_some();
        let dav = &self.core.deps().limits.dav;
        let max_candidates = usize::try_from(dav.max_query_candidates).unwrap_or(usize::MAX);
        let max_results = usize::try_from(dav.max_query_results).unwrap_or(usize::MAX);
        let max_bytes = usize::try_from(dav.max_query_bytes).unwrap_or(usize::MAX);
        let mut hits: Vec<ObjectHit> = Vec::new();
        let mut scanned = 0_usize;
        let mut bytes = 0_usize;
        let mut page = PageReq::first(PAGE);
        loop {
            // Without data and without an exact filter the heads of the index are enough.
            let batch = if !exact && !data.include_data {
                match tx.objects().query_index(located.calendar.id, &index, page).await {
                    Ok(heads) => Some(heads),
                    Err(StoreError::Unsupported) => None,
                    Err(error) => return Err(error.into()),
                }
            } else {
                None
            };
            let next = if let Some(heads) = batch {
                scanned += heads.items.len();
                hits.extend(heads.items.iter().map(|head| head_view(&located, head)));
                heads.next
            } else {
                let objects = tx.objects().query(located.calendar.id, &index, page).await?;
                scanned += objects.items.len();
                // Candidates that have to be read are bounded; with nothing to judge every candidate is a match and
                // the results are bounded instead.
                if exact && scanned > max_candidates {
                    return Err(too_many());
                }
                let Some(matched) = self
                    .evaluate_within(
                        located.calendar.timezone_ics.as_deref(),
                        objects.items,
                        &filter,
                        &data,
                        max_bytes.saturating_sub(bytes),
                    )
                    .await?
                else {
                    return Err(too_many());
                };
                for (object, text) in matched {
                    bytes += text.as_ref().map_or(0, String::len);
                    hits.push(located.view(&object, text));
                }
                objects.next
            };
            if hits.len() > max_results || bytes > max_bytes {
                return Err(too_many());
            }
            match next {
                Some(after) => page = page.after(after),
                None => break,
            }
        }
        tx.commit().await?;
        hits.sort_by_key(|hit| hit.path.format());
        Ok(hits)
    }
}

/// The view of an object head (no data).
fn head_view(located: &Located, head: &ObjectHead) -> ObjectHit {
    let object = StoredObject {
        id: head.id,
        tenant_id: located.calendar.tenant_id,
        calendar_id: head.calendar_id,
        owner_id: head.owner_id,
        uri: head.uri.clone(),
        uid: head.uid.clone(),
        etag: head.etag.clone(),
        schedule_tag: head.schedule_tag.clone(),
        content_hash: head.content_hash.clone(),
        component: head.component,
        data: String::new(),
        size: head.size,
        first_start: head.first_start,
        last_end: head.last_end,
        is_recurring: head.is_recurring,
        is_scheduling: head.is_scheduling,
        organizer_address: head.organizer_address.clone(),
        sequence: head.sequence,
        class: head.class,
        external_key: head.external_key.clone(),
        origin: head.origin.clone(),
        created_at: head.created_at,
        updated_at: head.updated_at,
        version: head.version,
    };
    located.view(&object, None)
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::*;

    fn range(start: u32, end: u32) -> IcalRange {
        IcalRange::new(
            Some(Utc.with_ymd_and_hms(2027, 3, 1, start, 0, 0).unwrap()),
            Some(Utc.with_ymd_and_hms(2027, 3, 1, end, 0, 0).unwrap()),
        )
    }

    #[test]
    fn the_pre_filter_takes_component_and_range_from_a_single_child_filter() {
        let query = range_filter(range(9, 17), ComponentKind::Todo);
        let filter = ObjectFilter {
            calendar_filter: Some(query),
            ..ObjectFilter::default()
        };
        let index = index_filter_of(&filter);
        assert_eq!(index.component, Some(ComponentKind::Todo));
        assert_eq!(
            index.time_range,
            Some(TimeRange {
                start: range(9, 17).start,
                end: range(9, 17).end
            })
        );
    }

    #[test]
    fn explicit_fields_win_over_the_filter_and_unusable_filters_prefilter_nothing() {
        let mut query = range_filter(range(9, 17), ComponentKind::Todo);
        query.root.comp_filters.push(query.root.comp_filters[0].clone());
        let filter = ObjectFilter {
            calendar_filter: Some(query),
            component: Some(ComponentKind::Event),
            range: Some(range(1, 2)),
            ..ObjectFilter::default()
        };
        let index = index_filter_of(&filter);
        assert_eq!(index.component, Some(ComponentKind::Event));
        assert_eq!(index.time_range.map(|r| r.start), Some(range(1, 2).start));
        assert_eq!(index_filter_of(&ObjectFilter::default()), IndexFilter::all());
    }

    mod evaluation {
        //! The exact judgment of candidates and the projection of their data.

        use chrono::{DateTime, TimeZone, Utc};
        use davhaven_domain::{
            CalendarId, Classification, ContentHash, ETag, ObjectId, PrincipalId, ScheduleTag, TenantId, Uid,
        };
        use davhaven_fixtures::event::{EventBuilder, When};
        use davhaven_ical::filter::{Collation, PropFilter, TextMatch};
        use davhaven_ical::projection::Projection;
        use uuid::Uuid;

        use super::*;

        fn stored(uid: &str, data: String, component: ComponentKind) -> StoredObject {
            let at = DateTime::UNIX_EPOCH;
            StoredObject {
                id: ObjectId::from_uuid(Uuid::from_u128(1)),
                tenant_id: TenantId::from_uuid(Uuid::from_u128(2)),
                calendar_id: CalendarId::from_uuid(Uuid::from_u128(3)),
                owner_id: PrincipalId::from_uuid(Uuid::from_u128(4)),
                uri: ObjectUri::parse(&format!("{uid}.ics")).unwrap(),
                uid: Uid::parse(uid).unwrap(),
                etag: ETag::from_bytes(data.as_bytes()),
                schedule_tag: None::<ScheduleTag>,
                content_hash: ContentHash::from_digest([0; 32]),
                component,
                size: u64::try_from(data.len()).unwrap_or(0),
                data,
                first_start: None,
                last_end: None,
                is_recurring: false,
                is_scheduling: false,
                organizer_address: None,
                sequence: 0,
                class: Classification::Public,
                external_key: None,
                origin: None,
                created_at: at,
                updated_at: at,
                version: 1,
            }
        }

        fn event(uid: &str, summary: &str, day: u32) -> StoredObject {
            let text = EventBuilder::event(uid)
                .summary(summary)
                .starts(When::utc(2027, 3, day, 9, 0))
                .ends(When::utc(2027, 3, day, 10, 0))
                .build();
            stored(uid, text, ComponentKind::Event)
        }

        fn todo(uid: &str, summary: &str) -> StoredObject {
            stored(
                uid,
                EventBuilder::todo(uid).summary(summary).build(),
                ComponentKind::Todo,
            )
        }

        fn summary_filter(component: &str, value: &str, collation: Collation, negate: bool) -> CalendarFilter {
            CalendarFilter {
                root: CompFilter {
                    name: "VCALENDAR".to_owned(),
                    is_not_defined: false,
                    time_range: None,
                    prop_filters: Vec::new(),
                    comp_filters: vec![CompFilter {
                        name: component.to_owned(),
                        is_not_defined: false,
                        time_range: None,
                        prop_filters: vec![PropFilter {
                            name: "SUMMARY".to_owned(),
                            is_not_defined: false,
                            time_range: None,
                            text_match: Some(TextMatch {
                                value: value.to_owned(),
                                collation,
                                negate,
                            }),
                            param_filters: Vec::new(),
                        }],
                        comp_filters: Vec::new(),
                    }],
                },
            }
        }

        fn judged(candidates: Vec<StoredObject>, filter: &ObjectFilter, data: &CalendarDataSpec) -> Vec<String> {
            evaluate_blocking(candidates, filter, data, None, &IcalLimits::default())
                .unwrap()
                .into_iter()
                .map(|(object, _)| object.uid.as_str().to_owned())
                .collect()
        }

        fn candidates() -> Vec<StoredObject> {
            vec![
                event("standup", "Standup", 1),
                event("lunch", "Team lunch", 2),
                todo("task", "Stand up straight"),
            ]
        }

        #[test]
        fn a_text_match_judges_the_property_of_the_named_component_only() {
            let data = CalendarDataSpec::default();
            let by = |value: &str, collation, negate| ObjectFilter {
                calendar_filter: Some(summary_filter("VEVENT", value, collation, negate)),
                ..ObjectFilter::default()
            };
            assert_eq!(
                judged(candidates(), &by("STAND", Collation::AsciiCasemap, false), &data),
                vec!["standup"],
                "case-insensitively, and not the to-do whose summary also contains the text"
            );
            assert_eq!(
                judged(candidates(), &by("stand", Collation::AsciiCasemap, true), &data),
                vec!["lunch"],
                "negated"
            );
            assert!(
                judged(candidates(), &by("STAND", Collation::Octet, false), &data).is_empty(),
                "`i;octet` compares bytes"
            );
            assert_eq!(
                judged(
                    candidates(),
                    &ObjectFilter {
                        calendar_filter: Some(summary_filter("VTODO", "stand", Collation::AsciiCasemap, false)),
                        ..ObjectFilter::default()
                    },
                    &data
                ),
                vec!["task"]
            );
        }

        #[test]
        fn a_range_and_a_filter_must_both_hold() {
            let data = CalendarDataSpec::default();
            let first_day = IcalRange::new(
                Some(Utc.with_ymd_and_hms(2027, 3, 1, 0, 0, 0).unwrap()),
                Some(Utc.with_ymd_and_hms(2027, 3, 2, 0, 0, 0).unwrap()),
            );
            let both = ObjectFilter {
                range: Some(first_day),
                calendar_filter: Some(summary_filter("VEVENT", "team", Collation::AsciiCasemap, false)),
                ..ObjectFilter::default()
            };
            assert!(
                judged(candidates(), &both, &data).is_empty(),
                "the lunch is on the second day"
            );
            let only_range = ObjectFilter {
                range: Some(first_day),
                ..ObjectFilter::default()
            };
            assert_eq!(
                judged(candidates(), &only_range, &data),
                vec!["standup", "task"],
                "a to-do without dates matches every range (RFC 4791 section 9.9)"
            );
        }

        #[test]
        fn candidates_are_only_parsed_when_something_needs_the_text() {
            let broken = stored("broken", "this is not iCalendar".to_owned(), ComponentKind::Event);
            // No filter, no projection: the store's answer is passed on, with the stored text.
            let passed = evaluate_blocking(
                vec![broken.clone()],
                &ObjectFilter::default(),
                &CalendarDataSpec::default(),
                None,
                &IcalLimits::default(),
            )
            .unwrap();
            assert_eq!(passed.len(), 1);
            assert_eq!(passed[0].1.as_deref(), Some("this is not iCalendar"));
            let metadata = evaluate_blocking(
                vec![broken.clone()],
                &ObjectFilter::default(),
                &CalendarDataSpec::metadata_only(),
                None,
                &IcalLimits::default(),
            )
            .unwrap();
            assert_eq!(metadata[0].1, None);
            // A filter or a projection has to read it.
            let filtered = evaluate_blocking(
                vec![broken],
                &ObjectFilter {
                    calendar_filter: Some(summary_filter("VEVENT", "x", Collation::AsciiCasemap, false)),
                    ..ObjectFilter::default()
                },
                &CalendarDataSpec::default(),
                None,
                &IcalLimits::default(),
            );
            assert!(filtered.is_err());
        }

        #[test]
        fn data_is_the_stored_text_unless_a_projection_changes_it() {
            let daily = stored(
                "daily",
                EventBuilder::event("daily")
                    .summary("Daily")
                    .starts(When::utc(2027, 3, 1, 9, 0))
                    .ends(When::utc(2027, 3, 1, 10, 0))
                    .rrule("FREQ=DAILY;COUNT=5")
                    .build(),
                ComponentKind::Event,
            );
            let verbatim = evaluate_blocking(
                vec![daily.clone()],
                &ObjectFilter::default(),
                &CalendarDataSpec::default(),
                None,
                &IcalLimits::default(),
            )
            .unwrap();
            assert_eq!(verbatim[0].1.as_deref(), Some(daily.data.as_str()));

            let window = IcalRange::new(
                Some(Utc.with_ymd_and_hms(2027, 3, 2, 0, 0, 0).unwrap()),
                Some(Utc.with_ymd_and_hms(2027, 3, 4, 0, 0, 0).unwrap()),
            );
            let expanded = evaluate_blocking(
                vec![daily],
                &ObjectFilter {
                    range: Some(window),
                    ..ObjectFilter::default()
                },
                &CalendarDataSpec {
                    include_data: true,
                    projection: Projection {
                        expand: Some(window),
                        ..Projection::default()
                    },
                },
                None,
                &IcalLimits::default(),
            )
            .unwrap();
            let text = expanded[0].1.as_deref().unwrap();
            assert_eq!(text.matches("BEGIN:VEVENT").count(), 2, "{text}");
            assert!(!text.contains("RRULE"), "{text}");
        }
    }
}
