//! Configurable limits for iCalendar data, WebDAV requests and the management API.
//!
//! The defaults are the table of PLAN 2.15. Each struct is the typed form of one part of the `[limits]`
//! configuration section: unknown keys are rejected, every key has a default and [`validate`](IcalLimits::validate)
//! rejects values that make no sense (zero sizes, inverted date ranges). Limits protect the server from
//! resource exhaustion, so they are enforced where the data is parsed, not where it is stored.

use chrono::{DateTime, NaiveDate, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Error for a limits section with an unusable value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid limit `{field}`: {reason}")]
pub struct LimitsError {
    field: &'static str,
    reason: &'static str,
}

impl LimitsError {
    const fn new(field: &'static str, reason: &'static str) -> Self {
        Self { field, reason }
    }

    /// The name of the offending key.
    pub const fn field(&self) -> &'static str {
        self.field
    }

    /// The rule that was violated.
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

fn require_positive(field: &'static str, value: u64) -> Result<(), LimitsError> {
    if value == 0 {
        Err(LimitsError::new(field, "must be greater than zero"))
    } else {
        Ok(())
    }
}

/// Limits applied when parsing, validating, indexing and expanding iCalendar data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct IcalLimits {
    /// Largest accepted calendar object resource in bytes (`C:max-resource-size`).
    pub max_resource_size: u64,
    /// Most components in one object.
    pub max_components: u32,
    /// Most properties in one component.
    pub max_properties_per_component: u32,
    /// Longest unfolded property value in bytes.
    pub max_value_length: u32,
    /// Most attendees per instance (`C:max-attendees-per-instance`).
    pub max_attendees_per_instance: u32,
    /// Most `VALARM` components per component.
    pub max_alarms: u32,
    /// Most `RDATE` plus `EXDATE` values per component.
    pub max_recurrence_dates: u32,
    /// Deepest component nesting.
    pub max_nesting: u32,
    /// Most observances in one `VTIMEZONE`.
    pub max_observances: u32,
    /// Largest inline binary `ATTACH` in bytes.
    pub max_inline_attach_bytes: u64,
    /// Most instances one expansion may produce (`C:max-instances`).
    pub max_instances: u32,
    /// Most iterator steps one expansion may take.
    pub max_iterator_steps: u32,
    /// Earliest accepted year (`C:min-date-time`).
    pub min_year: i32,
    /// Latest accepted year (`C:max-date-time`).
    pub max_year: i32,
    /// Longest time-range or free-busy span in years (`C:valid-filter`).
    pub max_time_range_years: u32,
    /// Wall-clock budget for parsing and expansion in milliseconds.
    pub time_budget_ms: u64,
}

impl Default for IcalLimits {
    fn default() -> Self {
        Self {
            max_resource_size: 1_048_576,
            max_components: 1_000,
            max_properties_per_component: 500,
            max_value_length: 65_536,
            max_attendees_per_instance: 200,
            max_alarms: 10,
            max_recurrence_dates: 1_000,
            max_nesting: 4,
            max_observances: 200,
            max_inline_attach_bytes: 262_144,
            max_instances: 3_000,
            max_iterator_steps: 100_000,
            min_year: 1900,
            max_year: 2100,
            max_time_range_years: 10,
            time_budget_ms: 2_000,
        }
    }
}

impl IcalLimits {
    /// Checks that every limit is usable.
    ///
    /// # Errors
    ///
    /// Returns a [`LimitsError`] naming the first unusable key.
    pub fn validate(&self) -> Result<(), LimitsError> {
        require_positive("max_resource_size", self.max_resource_size)?;
        require_positive("max_components", self.max_components.into())?;
        require_positive("max_properties_per_component", self.max_properties_per_component.into())?;
        require_positive("max_value_length", self.max_value_length.into())?;
        require_positive("max_attendees_per_instance", self.max_attendees_per_instance.into())?;
        require_positive("max_nesting", self.max_nesting.into())?;
        require_positive("max_instances", self.max_instances.into())?;
        require_positive("max_iterator_steps", self.max_iterator_steps.into())?;
        require_positive("max_time_range_years", self.max_time_range_years.into())?;
        require_positive("time_budget_ms", self.time_budget_ms)?;
        if self.min_year >= self.max_year {
            return Err(LimitsError::new("min_year", "must be before max_year"));
        }
        if self.min_date_time().is_none() || self.max_date_time().is_none() {
            return Err(LimitsError::new("min_year", "years must be representable"));
        }
        Ok(())
    }

    /// The earliest accepted instant: January 1st of `min_year`, 00:00 UTC.
    pub fn min_date_time(&self) -> Option<DateTime<Utc>> {
        year_start(self.min_year)
    }

    /// The latest accepted instant: January 1st of `max_year`, 00:00 UTC.
    pub fn max_date_time(&self) -> Option<DateTime<Utc>> {
        year_start(self.max_year)
    }
}

fn year_start(year: i32) -> Option<DateTime<Utc>> {
    NaiveDate::from_ymd_opt(year, 1, 1)?
        .and_hms_opt(0, 0, 0)
        .map(|naive| naive.and_utc())
}

/// Limits applied to WebDAV requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct DavLimits {
    /// Deepest XML element nesting.
    pub max_xml_depth: u32,
    /// Most XML elements in one request body.
    pub max_xml_elements: u32,
    /// Most attributes on one XML element.
    pub max_xml_attributes: u32,
    /// Most distinct XML namespaces declared in one request body.
    pub max_xml_namespaces: u32,
    /// Largest PROPFIND, PROPPATCH or REPORT body in bytes.
    pub max_request_body: u64,
    /// Most hrefs in one `calendar-multiget`.
    pub max_multiget_hrefs: u32,
    /// Most dead properties per binding.
    pub max_dead_properties: u32,
    /// Largest dead property, counting its namespace, its name and its value, in bytes.
    pub max_dead_property_size: u32,
    /// Largest `multistatus` answer in bytes. An answer that grows beyond it is cut off: the response for the
    /// request URI says 507 `number-of-matches-within-limits` and the client asks for the rest in smaller steps.
    pub max_response_bytes: u64,
    /// Most candidates one `calendar-query` examines against its exact filter; more is
    /// `number-of-matches-within-limits`. A query without a filter that needs the text matches every candidate and is
    /// bound by `max_query_results` alone.
    pub max_query_candidates: u32,
    /// Most objects one `calendar-query` returns.
    pub max_query_results: u32,
    /// Most bytes of calendar data one `calendar-query` returns.
    pub max_query_bytes: u64,
    /// Most members one `sync-collection` listing holds (an initial listing that needs more is refused).
    pub max_sync_members: u32,
    /// Most sharees (`CS:set` and `CS:remove` together) one `CS:share` request may name. Every sharee is a lookup of the
    /// application and a notification in the sharee's collection, so the number is bound on its own and not by the
    /// size of a multiget.
    pub max_sharees_per_request: u32,
    /// Most `property-search` elements or `search-token`s one principal search may have: every term is a condition
    /// the store evaluates on every principal of the tenant.
    pub max_search_terms: u32,
}

impl Default for DavLimits {
    fn default() -> Self {
        Self {
            max_xml_depth: 32,
            max_xml_elements: 10_000,
            max_xml_attributes: 32,
            max_xml_namespaces: 64,
            max_request_body: 262_144,
            max_multiget_hrefs: 1_000,
            max_dead_properties: 50,
            max_dead_property_size: 4_096,
            max_response_bytes: 33_554_432,
            max_query_candidates: 10_000,
            max_query_results: 10_000,
            max_query_bytes: 64 * 1024 * 1024,
            max_sync_members: 100_000,
            max_sharees_per_request: 100,
            max_search_terms: 8,
        }
    }
}

impl DavLimits {
    /// Checks that every limit is usable.
    ///
    /// # Errors
    ///
    /// Returns a [`LimitsError`] naming the first unusable key.
    pub fn validate(&self) -> Result<(), LimitsError> {
        require_positive("max_xml_depth", self.max_xml_depth.into())?;
        require_positive("max_xml_elements", self.max_xml_elements.into())?;
        require_positive("max_xml_attributes", self.max_xml_attributes.into())?;
        require_positive("max_xml_namespaces", self.max_xml_namespaces.into())?;
        require_positive("max_request_body", self.max_request_body)?;
        require_positive("max_multiget_hrefs", self.max_multiget_hrefs.into())?;
        require_positive("max_dead_property_size", self.max_dead_property_size.into())?;
        require_positive("max_response_bytes", self.max_response_bytes)?;
        require_positive("max_query_candidates", self.max_query_candidates.into())?;
        require_positive("max_query_results", self.max_query_results.into())?;
        require_positive("max_query_bytes", self.max_query_bytes)?;
        require_positive("max_sync_members", self.max_sync_members.into())?;
        require_positive("max_sharees_per_request", self.max_sharees_per_request.into())?;
        require_positive("max_search_terms", self.max_search_terms.into())?;
        Ok(())
    }
}

/// Limits applied to the management API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ApiLimits {
    /// Largest JSON request body in bytes.
    pub max_json_body: u64,
    /// Largest batch request body in bytes.
    pub max_batch_body: u64,
    /// Most items in one batch upsert.
    pub max_batch_items: u32,
    /// Page size when the client sends no `limit`.
    pub default_page_size: u32,
    /// Largest page size a client may ask for.
    pub max_page_size: u32,
    /// Most objects one request of the event listings and of the event search reads from the store before it
    /// answers with the page it has and a cursor that continues behind them.
    pub max_scanned_objects: u32,
}

impl Default for ApiLimits {
    fn default() -> Self {
        Self {
            max_json_body: 1_048_576,
            max_batch_body: 10_485_760,
            max_batch_items: 1_000,
            default_page_size: 50,
            max_page_size: 200,
            max_scanned_objects: 5_000,
        }
    }
}

impl ApiLimits {
    /// Checks that every limit is usable.
    ///
    /// # Errors
    ///
    /// Returns a [`LimitsError`] naming the first unusable key.
    pub fn validate(&self) -> Result<(), LimitsError> {
        require_positive("max_json_body", self.max_json_body)?;
        require_positive("max_batch_body", self.max_batch_body)?;
        require_positive("max_batch_items", self.max_batch_items.into())?;
        require_positive("default_page_size", self.default_page_size.into())?;
        require_positive("max_page_size", self.max_page_size.into())?;
        require_positive("max_scanned_objects", self.max_scanned_objects.into())?;
        if self.max_batch_body < self.max_json_body {
            return Err(LimitsError::new(
                "max_batch_body",
                "must not be smaller than max_json_body",
            ));
        }
        if self.default_page_size > self.max_page_size {
            return Err(LimitsError::new("default_page_size", "must not exceed max_page_size"));
        }
        Ok(())
    }

    /// The page size to use for a client's `limit` parameter: the default without one, never above the maximum
    /// and never zero.
    pub fn page_size(&self, requested: Option<u32>) -> u32 {
        requested.unwrap_or(self.default_page_size).clamp(1, self.max_page_size)
    }
}

/// All limits together, as passed to the application layer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Limits {
    /// iCalendar limits.
    pub ical: IcalLimits,
    /// WebDAV limits.
    pub dav: DavLimits,
    /// Management API limits.
    pub api: ApiLimits,
}

impl Limits {
    /// Validates every section.
    ///
    /// # Errors
    ///
    /// Returns the first [`LimitsError`] of any section.
    pub fn validate(&self) -> Result<(), LimitsError> {
        self.ical.validate()?;
        self.dav.validate()?;
        self.api.validate()
    }
}

#[cfg(test)]
mod tests {
    use chrono::Datelike;

    use super::*;

    #[test]
    fn ical_defaults_are_the_plan_table() {
        let limits = IcalLimits::default();
        assert_eq!(limits.max_resource_size, 1024 * 1024);
        assert_eq!(limits.max_components, 1000);
        assert_eq!(limits.max_properties_per_component, 500);
        assert_eq!(limits.max_value_length, 64 * 1024);
        assert_eq!(limits.max_attendees_per_instance, 200);
        assert_eq!(limits.max_alarms, 10);
        assert_eq!(limits.max_recurrence_dates, 1000);
        assert_eq!(limits.max_nesting, 4);
        assert_eq!(limits.max_observances, 200);
        assert_eq!(limits.max_inline_attach_bytes, 256 * 1024);
        assert_eq!(limits.max_instances, 3000);
        assert_eq!(limits.max_iterator_steps, 100_000);
        assert_eq!((limits.min_year, limits.max_year), (1900, 2100));
        assert_eq!(limits.max_time_range_years, 10);
        limits.validate().unwrap();
    }

    #[test]
    fn dav_defaults_are_the_plan_table() {
        let limits = DavLimits::default();
        assert_eq!(limits.max_xml_depth, 32);
        assert_eq!(limits.max_xml_elements, 10_000);
        assert_eq!(limits.max_xml_attributes, 32);
        assert_eq!(limits.max_xml_namespaces, 64);
        assert_eq!(limits.max_request_body, 256 * 1024);
        assert_eq!(limits.max_multiget_hrefs, 1000);
        assert_eq!(limits.max_dead_properties, 50);
        assert_eq!(limits.max_dead_property_size, 4 * 1024);
        assert_eq!(limits.max_response_bytes, 32 * 1024 * 1024);
        assert_eq!(limits.max_query_candidates, 10_000);
        assert_eq!(limits.max_query_results, 10_000);
        assert_eq!(limits.max_query_bytes, 64 * 1024 * 1024);
        assert_eq!(limits.max_sync_members, 100_000);
        assert_eq!(limits.max_sharees_per_request, 100);
        assert_eq!(limits.max_search_terms, 8);
        limits.validate().unwrap();
    }

    #[test]
    fn api_defaults_are_the_plan_table() {
        let limits = ApiLimits::default();
        assert_eq!(limits.max_json_body, 1024 * 1024);
        assert_eq!(limits.max_batch_body, 10 * 1024 * 1024);
        assert_eq!(limits.max_batch_items, 1000);
        assert_eq!(limits.default_page_size, 50);
        assert_eq!(limits.max_page_size, 200);
        assert_eq!(limits.max_scanned_objects, 5000);
        limits.validate().unwrap();
        assert_eq!(Limits::default().validate(), Ok(()));
    }

    #[test]
    fn date_bounds_are_the_start_of_the_configured_years() {
        let limits = IcalLimits::default();
        let min = limits.min_date_time().unwrap();
        let max = limits.max_date_time().unwrap();
        assert_eq!((min.year(), min.month(), min.day()), (1900, 1, 1));
        assert_eq!((max.year(), max.month(), max.day()), (2100, 1, 1));
        assert_eq!(min.to_rfc3339(), "1900-01-01T00:00:00+00:00");
    }

    #[test]
    fn partial_sections_keep_defaults_and_unknown_keys_fail() {
        let limits: IcalLimits = serde_json::from_str(r#"{"max_instances": 10}"#).unwrap();
        assert_eq!(limits.max_instances, 10);
        assert_eq!(limits.max_components, 1000);
        assert_eq!(serde_json::from_str::<IcalLimits>("{}").unwrap(), IcalLimits::default());
        assert!(serde_json::from_str::<IcalLimits>(r#"{"max_instance": 10}"#).is_err());
        assert!(serde_json::from_str::<DavLimits>(r#"{"depth": 1}"#).is_err());
        assert!(serde_json::from_str::<ApiLimits>(r#"{"max_page": 1}"#).is_err());
        assert!(serde_json::from_str::<ApiLimits>(r#"{"max_page_size": -1}"#).is_err());
    }

    #[test]
    fn nonsensical_values_are_rejected_with_the_key_name() {
        let check = |edit: &dyn Fn(&mut IcalLimits)| {
            let mut limits = IcalLimits::default();
            edit(&mut limits);
            limits.validate().unwrap_err().field()
        };
        assert_eq!(check(&|l| l.max_resource_size = 0), "max_resource_size");
        assert_eq!(check(&|l| l.max_instances = 0), "max_instances");
        assert_eq!(check(&|l| l.time_budget_ms = 0), "time_budget_ms");
        assert_eq!(check(&|l| l.min_year = 2100), "min_year");
        assert_eq!(check(&|l| l.max_year = 1800), "min_year");
        assert_eq!(check(&|l| l.max_year = i32::MAX), "min_year");
        let dav = DavLimits {
            max_xml_depth: 0,
            ..DavLimits::default()
        };
        assert_eq!(dav.validate().unwrap_err().field(), "max_xml_depth");
        let dav = DavLimits {
            max_response_bytes: 0,
            ..DavLimits::default()
        };
        assert_eq!(dav.validate().unwrap_err().field(), "max_response_bytes");
        let api = ApiLimits {
            max_page_size: 10,
            ..ApiLimits::default()
        };
        assert_eq!(api.validate().unwrap_err().field(), "default_page_size");
        let api = ApiLimits {
            max_batch_body: 1,
            ..ApiLimits::default()
        };
        assert_eq!(api.validate().unwrap_err().field(), "max_batch_body");
        assert_eq!(
            LimitsError::new("x", "must be sane").to_string(),
            "invalid limit `x`: must be sane"
        );
        let all = Limits {
            dav: DavLimits {
                max_multiget_hrefs: 0,
                ..DavLimits::default()
            },
            ..Limits::default()
        };
        assert_eq!(all.validate().unwrap_err().field(), "max_multiget_hrefs");
    }

    #[test]
    fn page_sizes_are_clamped() {
        let api = ApiLimits::default();
        assert_eq!(api.page_size(None), 50);
        assert_eq!(api.page_size(Some(10)), 10);
        assert_eq!(api.page_size(Some(0)), 1);
        assert_eq!(api.page_size(Some(10_000)), 200);
    }
}
