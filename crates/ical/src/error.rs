//! `IcalError` and the limit kinds reported when iCalendar data exceeds configured limits.
//!
//! Messages in [`IcalError::Invalid`] and the rule variants are written for clients: they describe what is wrong
//! with the data ("DTEND is before DTSTART") and never contain internal details, so the application may pass them
//! on as the text of the precondition it answers with. Everything unexpected is a bug in `davhaven-ical`, not an
//! error value.
//!
//! # What an error means depends on the request
//!
//! The same [`IcalError`] is a different answer on a `PUT`, on a `REPORT` and on an iTIP message: an invalid
//! value is `CALDAV:valid-calendar-data` when a client stores an object, `CALDAV:valid-filter` when it comes from
//! a query and `CALDAV:valid-scheduling-message` when it comes from a scheduling message, and a time range outside
//! the date limits is `CALDAV:min-date-time` on a `PUT` (RFC 4791 defines it for stored data only) but a filter
//! error on a query. [`ErrorContext`] names the three situations and [`IcalError::precondition_in`] maps an error
//! for one of them. The application chooses the context from the entry point it called; the table is in
//! `docs/ical.md`.

use davhaven_domain::Precondition;

/// Which configured limit was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LimitKind {
    /// The resource is larger than `max_resource_size`.
    ResourceSize,
    /// The object has more components than `max_components`.
    Components,
    /// A component has more properties than `max_properties_per_component`.
    Properties,
    /// A property value is longer than `max_value_length`.
    ValueLength,
    /// An instance (or the object as a whole: the distinct attendees of all its components) has more attendees
    /// than `max_attendees_per_instance`.
    Attendees,
    /// A component has more alarms than `max_alarms`.
    Alarms,
    /// A component has more `RDATE`/`EXDATE` values than `max_recurrence_dates`.
    RecurrenceDates,
    /// Components are nested deeper than `max_nesting`.
    Nesting,
    /// A `VTIMEZONE` has more observances than `max_observances`, or its rules produce too many transitions.
    Observances,
    /// An inline binary `ATTACH` is larger than `max_inline_attach_bytes`.
    InlineAttachment,
    /// An expansion would produce more than `max_instances` instances.
    Instances,
    /// An expansion needs more than `max_iterator_steps` steps.
    IteratorSteps,
    /// A date is before `min_year`.
    MinDateTime,
    /// A date is after `max_year`.
    MaxDateTime,
    /// A time range or free-busy span is longer than `max_time_range_years`.
    TimeRange,
    /// A recurrence rule repeats more often than hourly: `FREQ=SECONDLY` or `FREQ=MINUTELY` (the name is
    /// historical; `FREQ=HOURLY` is accepted).
    SubDailyFrequency,
    /// Processing exceeded the wall-clock budget `time_budget_ms`. Unlike every other limit this depends on the
    /// load of the machine and not on the data, so it is transient: the application answers it as unavailable
    /// (503), never as invalid data.
    TimeBudget,
}

/// The situation an [`IcalError`] is answered in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorContext {
    /// A client stores an object: `PUT`, `MKCALENDAR`-time validation, API and MCP writes, batch items and every
    /// merge or removal that produces an object to store.
    Store,
    /// A client reads: `calendar-query` filters, `time-range`s, `calendar-data` projections (`expand`,
    /// `limit-recurrence-set`), free-busy computation and the exact matching that follows the index pre-filter.
    Query,
    /// An iTIP message is processed: inbound messages, replies, and the messages the server builds.
    Scheduling,
}

impl ErrorContext {
    /// Every context.
    pub const ALL: [Self; 3] = [Self::Store, Self::Query, Self::Scheduling];
}

impl LimitKind {
    /// Every limit kind.
    pub const ALL: [Self; 17] = [
        Self::ResourceSize,
        Self::Components,
        Self::Properties,
        Self::ValueLength,
        Self::Attendees,
        Self::Alarms,
        Self::RecurrenceDates,
        Self::Nesting,
        Self::Observances,
        Self::InlineAttachment,
        Self::Instances,
        Self::IteratorSteps,
        Self::MinDateTime,
        Self::MaxDateTime,
        Self::TimeRange,
        Self::SubDailyFrequency,
        Self::TimeBudget,
    ];

    /// A short lowercase name for logs and metrics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ResourceSize => "resource_size",
            Self::Components => "components",
            Self::Properties => "properties",
            Self::ValueLength => "value_length",
            Self::Attendees => "attendees",
            Self::Alarms => "alarms",
            Self::RecurrenceDates => "recurrence_dates",
            Self::Nesting => "nesting",
            Self::Observances => "observances",
            Self::InlineAttachment => "inline_attachment",
            Self::Instances => "instances",
            Self::IteratorSteps => "iterator_steps",
            Self::MinDateTime => "min_date_time",
            Self::MaxDateTime => "max_date_time",
            Self::TimeRange => "time_range",
            Self::SubDailyFrequency => "sub_daily_frequency",
            Self::TimeBudget => "time_budget",
        }
    }

    /// The text a client sees for this limit (safe to show; no internals).
    pub const fn client_message(self) -> &'static str {
        match self {
            Self::ResourceSize => "the calendar object is too large",
            Self::Components => "the calendar object has too many components",
            Self::Properties => "a component has too many properties",
            Self::ValueLength => "a property value is too long",
            Self::Attendees => "the event has too many attendees",
            Self::Alarms => "a component has too many alarms",
            Self::RecurrenceDates => "a component has too many RDATE or EXDATE values",
            Self::Nesting => "components are nested too deeply",
            Self::Observances => "a time zone has too many observances",
            Self::InlineAttachment => "an inline attachment is too large",
            Self::Instances => "the recurrence set has too many instances",
            Self::IteratorSteps => "the recurrence rule needs too many steps to evaluate",
            Self::MinDateTime => "a date is before the earliest date the server accepts",
            Self::MaxDateTime => "a date is after the latest date the server accepts",
            Self::TimeRange => "the time range is too long",
            Self::SubDailyFrequency => "recurrence rules more frequent than hourly are not supported",
            Self::TimeBudget => "the request takes too long to process",
        }
    }

    /// The CalDAV precondition a client sees when it stores data that exceeds this limit (PLAN 2.15): the
    /// storing case of [`LimitKind::precondition_in`] ([`ErrorContext::Store`]), with a return type that cannot be `None`.
    ///
    /// [`LimitKind::TimeBudget`] is a transient failure and not a property of the data, so it has no
    /// precondition: [`LimitKind::precondition_in`] and [`IcalError::precondition`] return `None` for it and the
    /// application answers it as unavailable. This method cannot say "none" and keeps reporting
    /// `valid-calendar-data` for it; do not use it for that limit.
    pub fn precondition(self) -> Precondition {
        self.precondition_in(ErrorContext::Store)
            .unwrap_or_else(|| Precondition::ValidCalendarData(self.client_message().to_owned()))
    }

    /// The precondition a client sees for this limit in `context`; `None` when the failure is transient and has
    /// no precondition ([`LimitKind::TimeBudget`]).
    ///
    /// * Storing: the limits of PLAN 2.15 (`max-resource-size`, `max-attendees-per-instance`, `max-instances`,
    ///   `min-date-time`, `max-date-time`; the rest is `valid-calendar-data`).
    /// * Querying: what the request asked for is too much (a long or out-of-range time range, an expansion with
    ///   too many instances, a filter nested too deeply) is `valid-filter`; `min-date-time`, `max-date-time` and
    ///   `max-instances` are RFC 4791 preconditions of `PUT` only. Limits of the stored data keep their `PUT`
    ///   precondition.
    /// * Scheduling: `max-resource-size` for an oversized message, `valid-scheduling-message` for every other
    ///   limit.
    pub fn precondition_in(self, context: ErrorContext) -> Option<Precondition> {
        if self == Self::TimeBudget {
            return None;
        }
        let invalid = || Precondition::ValidCalendarData(self.client_message().to_owned());
        Some(match context {
            ErrorContext::Store => match self {
                Self::ResourceSize => Precondition::MaxResourceSize,
                Self::Attendees => Precondition::MaxAttendeesPerInstance,
                Self::Instances | Self::IteratorSteps => Precondition::MaxInstances,
                Self::MinDateTime => Precondition::MinDateTime,
                Self::MaxDateTime => Precondition::MaxDateTime,
                Self::TimeRange => Precondition::ValidFilter,
                _ => invalid(),
            },
            ErrorContext::Query => match self {
                Self::Instances
                | Self::IteratorSteps
                | Self::MinDateTime
                | Self::MaxDateTime
                | Self::TimeRange
                | Self::Nesting => Precondition::ValidFilter,
                Self::ResourceSize => Precondition::MaxResourceSize,
                Self::Attendees => Precondition::MaxAttendeesPerInstance,
                _ => invalid(),
            },
            ErrorContext::Scheduling => match self {
                Self::ResourceSize => Precondition::MaxResourceSize,
                _ => Precondition::ValidSchedulingMessage,
            },
        })
    }
}

impl core::fmt::Display for LimitKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Errors of the iCalendar layer.
///
/// The enum is `non_exhaustive`: new kinds of rejection are added without breaking matches elsewhere.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IcalError {
    /// The data is not acceptable iCalendar; the text is safe to show to the client.
    #[error("invalid iCalendar data: {0}")]
    Invalid(String),
    /// A configured limit was exceeded.
    #[error("iCalendar limit exceeded: {0}")]
    Limit(LimitKind),
    /// The operation (or an input feature) is not supported; the text names it.
    #[error("not supported: {0}")]
    Unsupported(String),
    /// The data breaks a restriction on calendar object resources (RFC 4791 section 5.3.2.1): a `METHOD`, more
    /// than one component type, components with different UIDs, a duplicate `RECURRENCE-ID` or more than one
    /// master component. Answered as `CALDAV:valid-calendar-object-resource`; the text is safe to show.
    #[error("not a valid calendar object resource: {0}")]
    ObjectRule(String),
    /// The components of the object name different organizers (RFC 6638 `CALDAV:same-organizer-in-all-components`);
    /// the text is safe to show.
    #[error("the organizer differs between components: {0}")]
    OrganizerMismatch(String),
}

impl IcalError {
    /// An [`IcalError::Invalid`] with a client-safe message.
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    /// An [`IcalError::Unsupported`] naming what is not supported.
    pub fn unsupported(what: impl Into<String>) -> Self {
        Self::Unsupported(what.into())
    }

    /// An [`IcalError::ObjectRule`] with a client-safe message.
    pub fn object_rule(message: impl Into<String>) -> Self {
        Self::ObjectRule(message.into())
    }

    /// An [`IcalError::OrganizerMismatch`] with a client-safe message.
    pub fn organizer_mismatch(message: impl Into<String>) -> Self {
        Self::OrganizerMismatch(message.into())
    }

    /// The text a client may see: the message of the rejection or the description of the limit; `None` for
    /// unsupported operations, whose text names an internal gap.
    pub fn client_message(&self) -> Option<&str> {
        match self {
            Self::Invalid(message) | Self::ObjectRule(message) | Self::OrganizerMismatch(message) => Some(message),
            Self::Limit(kind) => Some(kind.client_message()),
            Self::Unsupported(_) => None,
        }
    }

    /// Whether repeating the request later may succeed because the failure depends on the load of the server and
    /// not on the data ([`LimitKind::TimeBudget`]). Transient errors are answered as unavailable (503).
    pub const fn is_transient(&self) -> bool {
        matches!(self, Self::Limit(LimitKind::TimeBudget))
    }

    /// The precondition a DAV client sees when it stores data; see [`IcalError::precondition_in`].
    pub fn precondition(&self) -> Option<Precondition> {
        self.precondition_in(ErrorContext::Store)
    }

    /// The precondition a DAV client sees in `context`, or `None` for unsupported operations (server-side gaps,
    /// not client errors) and for transient failures ([`IcalError::is_transient`]).
    ///
    /// | Error | Store | Query | Scheduling |
    /// | --- | --- | --- | --- |
    /// | invalid data | `valid-calendar-data` | `valid-filter` | `valid-scheduling-message` |
    /// | calendar object resource rule | `valid-calendar-object-resource` | `valid-filter` | `valid-scheduling-message` |
    /// | organizer mismatch | `same-organizer-in-all-components` | `valid-filter` | `valid-scheduling-message` |
    /// | limit | [`LimitKind::precondition_in`] | | |
    pub fn precondition_in(&self, context: ErrorContext) -> Option<Precondition> {
        match (self, context) {
            (Self::Limit(kind), context) => kind.precondition_in(context),
            (Self::Unsupported(_), _) => None,
            (Self::Invalid(message), ErrorContext::Store) => Some(Precondition::ValidCalendarData(message.clone())),
            (Self::ObjectRule(_), ErrorContext::Store) => Some(Precondition::ValidCalendarObjectResource),
            (Self::OrganizerMismatch(_), ErrorContext::Store) => Some(Precondition::SameOrganizerInAllComponents),
            (_, ErrorContext::Query) => Some(Precondition::ValidFilter),
            (_, ErrorContext::Scheduling) => Some(Precondition::ValidSchedulingMessage),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The precondition code of every limit in every context, written out by hand from the RFCs and PLAN 2.15.
    const EXPECTED: [(LimitKind, [Option<&str>; 3]); 17] = [
        // (kind, [store, query, scheduling])
        (
            LimitKind::ResourceSize,
            [
                Some("max-resource-size"),
                Some("max-resource-size"),
                Some("max-resource-size"),
            ],
        ),
        (
            LimitKind::Components,
            [
                Some("valid-calendar-data"),
                Some("valid-calendar-data"),
                Some("valid-scheduling-message"),
            ],
        ),
        (
            LimitKind::Properties,
            [
                Some("valid-calendar-data"),
                Some("valid-calendar-data"),
                Some("valid-scheduling-message"),
            ],
        ),
        (
            LimitKind::ValueLength,
            [
                Some("valid-calendar-data"),
                Some("valid-calendar-data"),
                Some("valid-scheduling-message"),
            ],
        ),
        (
            LimitKind::Attendees,
            [
                Some("max-attendees-per-instance"),
                Some("max-attendees-per-instance"),
                Some("valid-scheduling-message"),
            ],
        ),
        (
            LimitKind::Alarms,
            [
                Some("valid-calendar-data"),
                Some("valid-calendar-data"),
                Some("valid-scheduling-message"),
            ],
        ),
        (
            LimitKind::RecurrenceDates,
            [
                Some("valid-calendar-data"),
                Some("valid-calendar-data"),
                Some("valid-scheduling-message"),
            ],
        ),
        (
            LimitKind::Nesting,
            [
                Some("valid-calendar-data"),
                Some("valid-filter"),
                Some("valid-scheduling-message"),
            ],
        ),
        (
            LimitKind::Observances,
            [
                Some("valid-calendar-data"),
                Some("valid-calendar-data"),
                Some("valid-scheduling-message"),
            ],
        ),
        (
            LimitKind::InlineAttachment,
            [
                Some("valid-calendar-data"),
                Some("valid-calendar-data"),
                Some("valid-scheduling-message"),
            ],
        ),
        (
            LimitKind::Instances,
            [
                Some("max-instances"),
                Some("valid-filter"),
                Some("valid-scheduling-message"),
            ],
        ),
        (
            LimitKind::IteratorSteps,
            [
                Some("max-instances"),
                Some("valid-filter"),
                Some("valid-scheduling-message"),
            ],
        ),
        (
            LimitKind::MinDateTime,
            [
                Some("min-date-time"),
                Some("valid-filter"),
                Some("valid-scheduling-message"),
            ],
        ),
        (
            LimitKind::MaxDateTime,
            [
                Some("max-date-time"),
                Some("valid-filter"),
                Some("valid-scheduling-message"),
            ],
        ),
        (
            LimitKind::TimeRange,
            [
                Some("valid-filter"),
                Some("valid-filter"),
                Some("valid-scheduling-message"),
            ],
        ),
        (
            LimitKind::SubDailyFrequency,
            [
                Some("valid-calendar-data"),
                Some("valid-calendar-data"),
                Some("valid-scheduling-message"),
            ],
        ),
        (LimitKind::TimeBudget, [None, None, None]),
    ];

    #[test]
    fn every_limit_maps_to_the_documented_precondition_in_every_context() {
        assert_eq!(LimitKind::ALL.len(), EXPECTED.len());
        for (kind, codes) in EXPECTED {
            assert!(LimitKind::ALL.contains(&kind), "{kind}");
            for (context, expected) in ErrorContext::ALL.into_iter().zip(codes) {
                let found = kind.precondition_in(context).map(|precondition| precondition.code());
                assert_eq!(found, expected, "{kind} in {context:?}");
            }
        }
    }

    #[test]
    fn the_store_mapping_is_the_default() {
        for kind in LimitKind::ALL {
            let stored = kind.precondition_in(ErrorContext::Store);
            assert_eq!(IcalError::Limit(kind).precondition(), stored, "{kind}");
            if let Some(precondition) = stored {
                assert_eq!(kind.precondition(), precondition, "{kind}");
            } else {
                // `precondition` cannot say "none": the transient limit falls back to invalid data there.
                assert_eq!(kind, LimitKind::TimeBudget);
                assert!(matches!(kind.precondition(), Precondition::ValidCalendarData(_)));
            }
        }
    }

    #[test]
    fn limit_names_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for kind in LimitKind::ALL {
            assert!(seen.insert(kind.as_str()), "{kind}");
            assert_eq!(kind.to_string(), kind.as_str());
        }
    }

    #[test]
    fn client_messages_never_mention_internals() {
        for kind in LimitKind::ALL {
            let text = kind.client_message();
            assert!(text.len() > 5, "{text}");
            assert!(text.len() < 80, "{text}");
            assert!(
                !text.contains("calcard") && !text.contains("panicked") && !text.contains("::"),
                "{text}"
            );
            for context in ErrorContext::ALL {
                if let Some(Precondition::ValidCalendarData(shown)) = kind.precondition_in(context) {
                    assert_eq!(shown, text);
                }
            }
        }
    }

    #[test]
    fn rule_violations_have_their_own_preconditions() {
        let cases = [
            (
                IcalError::invalid("DTEND is before DTSTART"),
                [
                    Some(Precondition::ValidCalendarData("DTEND is before DTSTART".to_owned())),
                    Some(Precondition::ValidFilter),
                    Some(Precondition::ValidSchedulingMessage),
                ],
            ),
            (
                IcalError::object_rule("METHOD"),
                [
                    Some(Precondition::ValidCalendarObjectResource),
                    Some(Precondition::ValidFilter),
                    Some(Precondition::ValidSchedulingMessage),
                ],
            ),
            (
                IcalError::organizer_mismatch("ORGANIZER"),
                [
                    Some(Precondition::SameOrganizerInAllComponents),
                    Some(Precondition::ValidFilter),
                    Some(Precondition::ValidSchedulingMessage),
                ],
            ),
            (IcalError::unsupported("VTODO recurrence"), [None, None, None]),
            (
                IcalError::Limit(LimitKind::Instances),
                [
                    Some(Precondition::MaxInstances),
                    Some(Precondition::ValidFilter),
                    Some(Precondition::ValidSchedulingMessage),
                ],
            ),
            (IcalError::Limit(LimitKind::TimeBudget), [None, None, None]),
        ];
        for (error, expected) in cases {
            for (context, expected) in ErrorContext::ALL.into_iter().zip(expected) {
                assert_eq!(error.precondition_in(context), expected, "{error} in {context:?}");
            }
        }
    }

    #[test]
    fn only_the_time_budget_is_transient() {
        for kind in LimitKind::ALL {
            assert_eq!(
                IcalError::Limit(kind).is_transient(),
                kind == LimitKind::TimeBudget,
                "{kind}"
            );
        }
        assert!(!IcalError::invalid("x").is_transient());
        assert!(!IcalError::object_rule("x").is_transient());
        assert!(!IcalError::unsupported("x").is_transient());
    }

    #[test]
    fn client_messages_of_errors() {
        assert_eq!(IcalError::invalid("a").client_message(), Some("a"));
        assert_eq!(IcalError::object_rule("b").client_message(), Some("b"));
        assert_eq!(IcalError::organizer_mismatch("c").client_message(), Some("c"));
        assert_eq!(
            IcalError::Limit(LimitKind::Alarms).client_message(),
            Some(LimitKind::Alarms.client_message())
        );
        assert_eq!(IcalError::unsupported("secret detail").client_message(), None);
    }

    #[test]
    fn display_is_informative() {
        assert_eq!(IcalError::invalid("x").to_string(), "invalid iCalendar data: x");
        assert_eq!(
            IcalError::Limit(LimitKind::Alarms).to_string(),
            "iCalendar limit exceeded: alarms"
        );
        assert_eq!(IcalError::unsupported("y").to_string(), "not supported: y");
        assert_eq!(
            IcalError::object_rule("z").to_string(),
            "not a valid calendar object resource: z"
        );
        assert_eq!(
            IcalError::organizer_mismatch("w").to_string(),
            "the organizer differs between components: w"
        );
    }
}
