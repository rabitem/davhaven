//! Subscription feeds (iCalendar over HTTPS, full or busy-only).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::{ETag, EventDuration, RequestContext};

use crate::error::AppResult;

/// The conditional headers of a feed request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Conditional {
    /// `If-None-Match`: the entity tag the client already has.
    pub if_none_match: Option<ETag>,
}

/// A rendered feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedBody {
    /// The strong entity tag of `body`.
    pub etag: ETag,
    /// The iCalendar document (`text/calendar; charset=utf-8`).
    pub body: String,
    /// The calendar name (`X-WR-CALNAME`).
    pub calendar_name: String,
    /// When the newest included object last changed.
    pub last_modified: Option<DateTime<Utc>>,
    /// The refresh interval advertised to subscribers (`feeds.refresh_interval`).
    pub refresh_interval: EventDuration,
}

/// The answer to a feed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedResponse {
    /// The client's copy is current (304).
    NotModified {
        /// The entity tag to repeat in the response.
        etag: ETag,
    },
    /// The feed content (200).
    Body(FeedBody),
}

/// Feed rendering. The feed token is the context's credential (`Actor::FeedReader`); calendar access is checked
/// again on every request, and revoked or unknown tokens never get here (the web layer answers 404).
#[async_trait]
pub trait FeedService: Send + Sync {
    /// Renders the feed of the context's token: the master events and overrides inside the configured window,
    /// with `VTIMEZONE` per `TZID`. Busy feeds show hashed UIDs and a localized "Busy"; private and confidential
    /// events are busy-only for non-owners in every mode.
    ///
    /// # Errors
    ///
    /// `NotFound` when the token's calendars are no longer readable or the tenant disabled feeds.
    async fn render(&self, ctx: &RequestContext, conditional: Conditional) -> AppResult<FeedResponse>;
}
