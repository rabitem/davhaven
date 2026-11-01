//! Subscription feeds (iCalendar over HTTPS, full or busy-only).
//!
//! A feed is the events of the calendars of a feed token inside a window around the start of the current UTC day
//! (`feeds.window_past_days` before it, `feeds.window_future_days` after it), rendered as one `VCALENDAR` (PLAN 2.13):
//!
//! * recurring events appear as the master with the overrides inside the window, every `TZID` with one `VTIMEZONE`;
//! * the header carries `X-WR-CALNAME`, `REFRESH-INTERVAL` and `X-PUBLISHED-TTL` (`feeds.refresh_interval`);
//! * in **busy mode** every event is reduced to its time: a summary that is the tenant's own text for the language of the
//!   feed's owner (`busy_text_by_locale` of its settings; or `busy_text`, one text for every language, where the map has none
//!   for the language) or, when the tenant names none, a localized "Busy" (the `feed_busy` template of the tenant's theme in
//!   the language of the feed's owner, the built-in text when the renderer has none), a UID that is a keyed hash of the real
//!   one, no attendees, no description, no location; transparent and cancelled events are skipped;
//! * events with `CLASS:PRIVATE` or `CLASS:CONFIDENTIAL` are busy-only for everyone but the owner of the calendar,
//!   in every mode;
//! * the calendars' access is **checked again on every request** with the principal of the token: a calendar the
//!   principal can no longer read drops out of the feed, and a feed without readable calendars is `NotFound`, like a
//!   revoked token, a tenant that turned feeds off and a principal that is suspended or deleted.
//!
//! # The entity tag, and a 304 before the work
//!
//! A subscriber polls the same feed every few minutes, and almost every answer is "nothing changed". The strong `ETag`
//! is therefore **derived from what the document is made of**, not from the document: the calendars it reads (their
//! sync epoch and sequence number, which every change of an object advances, and their version, which every change
//! of the calendar itself advances), who sees them (the owner view decides which events are busy-only), the mode, the
//! localized busy text, the name, the window, the limits and **the build** (see `Identity`). That is known after one
//! read of the token and of the calendars, so `If-None-Match` is compared **before any object is read or rendered**,
//! and a current subscriber costs a handful of small queries instead of the parsing of every event of a year. Two
//! documents with the same entity tag are the same bytes, and a document whose parts changed has another tag, so the
//! tag stays a strong validator (RFC 9110 section 8.8.1); it is no longer the hash of the bytes.
//!
//! What renders the document is part of what it is made of: the version and the revision that the image was built
//! from (`DAVHAVEN_REVISION`, which the image build passes), and the version of the time zone database that the
//! `VTIMEZONE` components are rendered from. A release that changes how a feed is rendered or which zone rules it
//! carries therefore changes the tag of every feed, and every subscriber reads its feed once after the upgrade; none
//! of them is told "not modified" about bytes that the new code would write differently. A build without a revision
//! (a development build) has `FEED_FORMAT_VERSION` for that, which is raised when the rendering changes.
//!
//! The window is anchored at the start of the UTC day (`feeds.window_past_days` before it, `feeds.window_future_days`
//! after it), not at the instant of the request: what a document contains depends on the window, so an entity tag
//! that is computed without rendering needs a window that changes rarely, and a calendar subscription does not need
//! a boundary that is exact to the second.
//!
//! # Size
//!
//! A feed holds at most `feeds.max_objects` objects and `feeds.max_bytes` bytes of calendar data; a feed that needs
//! more is **cut** after them (and logged), it does not fail. The objects are rendered in chunks, each on a blocking
//! thread with its own time budget and a deadline the job checks between objects, so the size of a feed is no reason
//! for it to time out, and a request that gave up does not leave a job running.
//!
//! # Text handling
//!
//! The parts are the serialized, projected calendars of the objects. They are joined into one document on their
//! content lines: a line that continues in the next one (RFC 5545 section 3.1) is read as one, and the `TZID`
//! parameters are found before the first colon that is not inside a quoted parameter value.

use std::fmt::Write as _;

use async_trait::async_trait;
use chrono::{DateTime, Duration, DurationRound as _, Utc};
use davhaven_domain::settings::MAX_BUSY_TEXT_CHARS;
use davhaven_domain::{
    Actor, Calendar, CalendarId, Channel, Decision, ETag, EventDuration, FeedMode, IcalLimits, Operation, PrincipalId,
    PrincipalStatus, RequestContext, ScopeSet, StoredObject, Subject, TenantId, TokenId, decide,
};
use davhaven_ical::busy::BusyOptions;
use davhaven_ical::filter::{CalendarFilter, CompFilter, TimeRange};
use davhaven_ical::projection::Projection;
use davhaven_ical::{ErrorContext, IcalError};
use davhaven_ports::{IndexFilter, KeyPurpose, PageReq, RenderRequest, TemplateName, TxMode};

use crate::authz::{Deadline, blocking};
use crate::error::{AppError, AppResult};
use crate::services::{Conditional, FeedBody, FeedResponse, FeedService};
use crate::texts;
use crate::wiring::AppCore;

/// How many objects one blocking job renders.
const CHUNK: usize = 200;

/// A busy summary as it may appear in a feed: no control characters, at most [`MAX_BUSY_TEXT_CHARS`] characters.
fn clean_summary(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_control())
        .take(MAX_BUSY_TEXT_CHARS)
        .collect()
}

/// The version of the document format: raised when the rendering changes in a way that no input of `Identity` shows. A
/// build that carries its revision (the images do) shows it by itself; this is for the builds that do not.
const FEED_FORMAT_VERSION: u32 = 1;

/// The revision the build is of: the git revision that the image build passes in `DAVHAVEN_REVISION`, empty for a build
/// without one.
const REVISION: &str = match option_env!("DAVHAVEN_REVISION") {
    Some(revision) => revision,
    None => "",
};

/// What a feed document is made of, as far as it is known before any object is read: the input of its entity tag.
struct Identity<'a> {
    tenant: TenantId,
    mode: FeedMode,
    /// The window, from and to.
    window: (DateTime<Utc>, DateTime<Utc>),
    refresh: &'a EventDuration,
    /// The most objects and bytes a feed holds.
    size: (usize, usize),
    locale: &'a davhaven_domain::Locale,
    /// The summary of a busy block, in the locale.
    busy_summary: &'a str,
    /// The keyed salt of the hashed UIDs of busy blocks (it changes with the token and with the key ring).
    salt: &'a [u8],
    name: &'a str,
    /// The limits that decide what an expansion and a projection keep.
    limits: &'a IcalLimits,
    /// The calendars the feed reads, in the order they are read, with whether the reader owns them. What a calendar
    /// shows of itself (its name, its time zone) changes its `version`, so the version stands for it.
    calendars: &'a [(Calendar, bool)],
}

impl Identity<'_> {
    /// The strong entity tag: the hash of the parts above. Free text is written with its length, so that no two
    /// different identities have the same text.
    fn etag(&self) -> ETag {
        fn text(out: &mut String, name: &str, value: &str) {
            // Writing into a `String` cannot fail.
            let _ = writeln!(out, "{name}={}:{value}", value.len());
        }
        let mut out = String::new();
        let _ = writeln!(out, "davhaven/feed/{FEED_FORMAT_VERSION}");
        // What renders the document: this build and the time zone database of its `VTIMEZONE` components.
        text(&mut out, "build", env!("CARGO_PKG_VERSION"));
        text(&mut out, "revision", REVISION);
        text(&mut out, "tzdb", chrono_tz::IANA_TZDB_VERSION);
        let _ = writeln!(out, "tenant={}", self.tenant);
        let _ = writeln!(out, "mode={}", self.mode.as_str());
        let _ = writeln!(
            out,
            "window={}..{}",
            self.window.0.timestamp(),
            self.window.1.timestamp()
        );
        text(&mut out, "refresh", self.refresh.as_str());
        let _ = writeln!(out, "size={}/{}", self.size.0, self.size.1);
        text(&mut out, "locale", self.locale.as_str());
        text(&mut out, "busy", self.busy_summary);
        let salt = self.salt.iter().fold(String::new(), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        });
        let _ = writeln!(out, "salt={salt}");
        text(&mut out, "name", self.name);
        text(
            &mut out,
            "limits",
            &serde_json::to_string(self.limits).unwrap_or_default(),
        );
        for (calendar, owner_view) in self.calendars {
            let _ = writeln!(
                out,
                "calendar={} owner={owner_view} epoch={} seq={} version={}",
                calendar.id, calendar.sync_epoch, calendar.sync_seq, calendar.version
            );
        }
        ETag::from_bytes(out.as_bytes())
    }
}

/// The start of the UTC day that contains `time`.
fn day_start(time: DateTime<Utc>) -> DateTime<Utc> {
    time.duration_trunc(Duration::days(1)).unwrap_or(time)
}

/// The [`FeedService`] of the application.
#[derive(Debug, Clone)]
pub struct FeedServiceImpl {
    core: AppCore,
}

impl FeedServiceImpl {
    /// Creates the service on the shared application core.
    pub fn new(core: AppCore) -> Self {
        Self { core }
    }

    /// The shared application core: ports, configuration and limits.
    pub fn core(&self) -> &AppCore {
        &self.core
    }
}

/// An object of a feed with the facts that decide how it is rendered.
struct Member {
    object: StoredObject,
    zone: Option<String>,
    owner_view: bool,
}

/// Escapes text for a property value (RFC 5545 section 3.3.11).
fn escape_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            ';' => out.push_str("\\;"),
            ',' => out.push_str("\\,"),
            '\n' => out.push_str("\\n"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// Folds a content line at 75 octets, continuing with a space (RFC 5545 section 3.1).
fn fold(line: &str) -> String {
    let mut out = String::with_capacity(line.len() + line.len() / 70 * 3);
    let mut width = 0;
    for character in line.chars() {
        let size = character.len_utf8();
        if width + size > 75 {
            out.push_str("\r\n ");
            width = 1;
        }
        out.push(character);
        width += size;
    }
    out
}

/// A component of a serialized calendar: the physical lines as they were written (what the document is made of)
/// and the content lines they form once folded lines are joined (what is looked into).
struct Block {
    physical: Vec<String>,
    logical: Vec<String>,
}

impl Block {
    fn new() -> Self {
        Self {
            physical: Vec::new(),
            logical: Vec::new(),
        }
    }

    /// Adds a physical line; a line that starts with a space or a tab continues the content line before it.
    fn push(&mut self, line: &str) {
        self.physical.push(line.to_owned());
        match (line.strip_prefix([' ', '\t']), self.logical.last_mut()) {
            (Some(rest), Some(last)) => last.push_str(rest),
            _ => self.logical.push(line.to_owned()),
        }
    }

    /// Whether the block is the component `name` (`VTIMEZONE`).
    fn is(&self, name: &str) -> bool {
        self.logical
            .first()
            .and_then(|line| line.get(..6))
            .is_some_and(|begin| begin.eq_ignore_ascii_case("BEGIN:"))
            && self
                .logical
                .first()
                .and_then(|line| line.get(6..))
                .is_some_and(|found| found.trim().eq_ignore_ascii_case(name))
    }
}

/// The top-level components of a serialized calendar.
fn components(text: &str) -> Vec<Block> {
    let mut blocks: Vec<Block> = Vec::new();
    let mut current: Option<(String, Block)> = None;
    let mut depth = 0_u32;
    for line in text.lines() {
        // A continuation line never starts or ends a component.
        let continuation = line.starts_with([' ', '\t']);
        let upper = line.to_ascii_uppercase();
        if !continuation && let Some(name) = upper.strip_prefix("BEGIN:") {
            depth += 1;
            if depth == 2 {
                current = Some((name.trim().to_owned(), Block::new()));
            }
        }
        if depth >= 2
            && let Some((_, block)) = current.as_mut()
        {
            block.push(line);
        }
        if !continuation && let Some(name) = upper.strip_prefix("END:") {
            if depth == 2
                && current.as_ref().is_some_and(|(open, _)| open == name.trim())
                && let Some((_, block)) = current.take()
            {
                blocks.push(block);
            }
            depth = depth.saturating_sub(1);
        }
    }
    blocks
}

/// Splits `text` at the separators that are outside double quotes.
fn split_unquoted(text: &str, separator: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut quoted = false;
    let mut start = 0;
    for (index, character) in text.char_indices() {
        if character == '"' {
            quoted = !quoted;
        } else if character == separator && !quoted {
            parts.push(text.get(start..index).unwrap_or_default());
            start = index + character.len_utf8();
        }
    }
    parts.push(text.get(start..).unwrap_or_default());
    parts
}

/// The name and the parameters of a content line, and its value: the first colon outside a quoted parameter value
/// ends the head.
fn split_line(line: &str) -> (&str, &str) {
    let mut quoted = false;
    for (index, character) in line.char_indices() {
        if character == '"' {
            quoted = !quoted;
        } else if character == ':' && !quoted {
            return (
                line.get(..index).unwrap_or_default(),
                line.get(index + 1..).unwrap_or_default(),
            );
        }
    }
    (line, "")
}

/// The `TZID` of a `VTIMEZONE` block: the value of its own `TZID` property, not of a nested component's or of a
/// property whose name only starts with the letters.
fn tzid_of(block: &Block) -> Option<&str> {
    block
        .logical
        .iter()
        .map(|line| split_line(line))
        .find(|(head, _)| {
            split_unquoted(head, ';')
                .first()
                .is_some_and(|name| name.eq_ignore_ascii_case("TZID"))
        })
        .map(|(_, value)| value.trim())
}

/// The values of the `TZID` parameters of the property lines of a component, in order of appearance.
fn used_tzids(block: &Block) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for line in &block.logical {
        // Parameters are in front of the first colon that is not inside a quoted value; what follows is the value
        // of the property.
        let (head, _) = split_line(line);
        for parameter in split_unquoted(head, ';').into_iter().skip(1) {
            let Some((name, value)) = parameter.split_once('=') else {
                continue;
            };
            let value = value.trim_matches('"');
            if name.eq_ignore_ascii_case("TZID") && !value.is_empty() && !found.iter().any(|known| known == value) {
                found.push(value.to_owned());
            }
        }
    }
    found
}

/// The `VTIMEZONE` blocks for the time zones the events use but no part defines, with observances for `window`.
/// Only zones of the time zone database are rendered; a `TZID` that is none stays as the client wrote it.
fn missing_zones(
    events: &[Block],
    zones: &[(String, Block)],
    window: (DateTime<Utc>, DateTime<Utc>),
) -> Vec<(String, Block)> {
    let mut added: Vec<(String, Block)> = Vec::new();
    for tzid in events.iter().flat_map(used_tzids) {
        let known = |name: &str| zones.iter().chain(added.iter()).any(|(key, _)| key == name);
        if known(&tzid) {
            continue;
        }
        let Ok(Some(zone)) = davhaven_ical::tz::resolve_tzid(&tzid) else {
            continue;
        };
        if zone.as_str() != tzid {
            continue;
        }
        if let Ok(text) = davhaven_ical::tz::render_vtimezone(zone, window.0, window.1) {
            let mut block = Block::new();
            for line in text.lines() {
                block.push(line);
            }
            added.push((tzid, block));
        }
    }
    added
}

/// Joins the calendars of the members into one document. Every `TZID` the events use comes with a `VTIMEZONE`, the
/// one the objects carried or, for the time zones of the database, one rendered for `window`.
fn assemble(name: &str, refresh: &EventDuration, parts: &[String], window: (DateTime<Utc>, DateTime<Utc>)) -> String {
    let mut zones: Vec<(String, Block)> = Vec::new();
    let mut events: Vec<Block> = Vec::new();
    for part in parts {
        for block in components(part) {
            if block.is("VTIMEZONE") {
                let key = tzid_of(&block).unwrap_or_default().to_owned();
                if !zones.iter().any(|(known, _)| known == &key) {
                    zones.push((key, block));
                }
            } else {
                events.push(block);
            }
        }
    }
    let added = missing_zones(&events, &zones, window);
    zones.extend(added);
    let mut lines: Vec<String> = vec![
        "BEGIN:VCALENDAR".to_owned(),
        "VERSION:2.0".to_owned(),
        "PRODID:-//Davhaven//Feed//EN".to_owned(),
        "CALSCALE:GREGORIAN".to_owned(),
        "METHOD:PUBLISH".to_owned(),
        fold(&format!("X-WR-CALNAME:{}", escape_text(name))),
        format!("REFRESH-INTERVAL;VALUE=DURATION:{}", refresh.as_str()),
        format!("X-PUBLISHED-TTL:{}", refresh.as_str()),
    ];
    for (_, block) in zones {
        lines.extend(block.physical);
    }
    for block in events {
        lines.extend(block.physical);
    }
    lines.push("END:VCALENDAR".to_owned());
    let mut document = lines.join("\r\n");
    document.push_str("\r\n");
    document
}

/// The filter that keeps the objects with an instance inside the window.
fn window_filter(window: TimeRange, component: davhaven_domain::ComponentKind) -> CalendarFilter {
    CalendarFilter {
        root: CompFilter {
            name: "VCALENDAR".to_owned(),
            is_not_defined: false,
            time_range: None,
            prop_filters: Vec::new(),
            comp_filters: vec![CompFilter {
                name: component.as_ical().to_owned(),
                is_not_defined: false,
                time_range: Some(window),
                prop_filters: Vec::new(),
                comp_filters: Vec::new(),
            }],
        },
    }
}

/// How one chunk of members is rendered.
struct Render<'a> {
    window: TimeRange,
    mode: FeedMode,
    busy_summary: &'a str,
    uid_salt: &'a [u8],
    deadline: Deadline,
}

/// Renders the members that fall into the window; one serialized calendar per object that contributes.
fn render_blocking(
    members: Vec<Member>,
    render: &Render<'_>,
    limits: &IcalLimits,
) -> Result<Vec<(String, DateTime<Utc>)>, IcalError> {
    let mut parts = Vec::with_capacity(members.len());
    for member in members {
        render.deadline.check()?;
        let zone = crate::objects::zone_of(member.zone.as_deref(), limits);
        let calendar = davhaven_ical::parse::parse(member.object.data.as_bytes(), limits)?;
        if !davhaven_ical::filter::matches_in_zone(
            &calendar,
            &window_filter(render.window, member.object.component),
            limits,
            zone,
        )? {
            continue;
        }
        let busy_only =
            render.mode == FeedMode::Busy || crate::authz::busy_only(member.object.class, member.owner_view);
        let text = if busy_only {
            let options = BusyOptions {
                summary: render.busy_summary,
                uid_salt: render.uid_salt,
            };
            match davhaven_ical::busy::strip_to_busy(&calendar, &options)? {
                Some(stripped) => davhaven_ical::serialize::serialize(&stripped)?,
                None => continue,
            }
        } else {
            let projection = Projection {
                limit_recurrence_set: Some(render.window),
                ..Projection::default()
            };
            // What attendees wrote to the organizer with their answers stays out of a feed: the link can be passed on.
            let calendar = davhaven_ical::itip::strip_attendee_comments(calendar);
            davhaven_ical::projection::project_in_zone(&calendar, &projection, limits, zone)?
        };
        parts.push((text, member.object.updated_at));
    }
    Ok(parts)
}

impl FeedServiceImpl {
    /// The calendars of the token the principal can still read, with one load of the facts.
    async fn readable(
        &self,
        tx: &mut dyn davhaven_ports::Tx,
        principal: PrincipalId,
        token: TokenId,
        ids: &[CalendarId],
    ) -> AppResult<Vec<(Calendar, bool)>> {
        let subject = Subject::new(Actor::FeedReader { principal, token }, ScopeSet::empty());
        let calendars = tx.calendars().get_many(ids).await?;
        let found: Vec<CalendarId> = calendars.iter().map(|calendar| calendar.id).collect();
        let facts: std::collections::HashMap<CalendarId, davhaven_domain::AccessFacts> = tx
            .calendars()
            .access_facts_many(&found, Some(principal))
            .await?
            .into_iter()
            .collect();
        let mut readable = Vec::with_capacity(calendars.len());
        for calendar in calendars {
            let allowed = facts
                .get(&calendar.id)
                .is_some_and(|facts| decide(&subject, Channel::Feed, facts, Operation::ReadFeed) == Decision::Allow);
            if allowed {
                let owner_view = calendar.owner_id == principal;
                readable.push((calendar, owner_view));
            }
        }
        Ok(readable)
    }

    /// The objects of the calendars inside the window, up to the size limits `(objects, bytes)`; a feed that needs
    /// more is cut there.
    async fn collect_members(
        tx: &mut dyn davhaven_ports::Tx,
        calendars: &[(Calendar, bool)],
        index: &IndexFilter,
        (max_objects, max_bytes): (usize, usize),
        token: TokenId,
    ) -> AppResult<Vec<Member>> {
        let mut members: Vec<Member> = Vec::new();
        let mut bytes = 0_usize;
        for (calendar, owner_view) in calendars {
            let mut page = PageReq::first(500);
            loop {
                let batch = tx.objects().query(calendar.id, index, page).await?;
                for object in batch.items {
                    bytes += object.data.len();
                    members.push(Member {
                        object,
                        zone: calendar.timezone_ics.clone(),
                        owner_view: *owner_view,
                    });
                    if members.len() >= max_objects || bytes >= max_bytes {
                        tracing::warn!(token = %token, "a feed reached its size limit and is cut");
                        return Ok(members);
                    }
                }
                match batch.next {
                    Some(after) => page = page.after(after),
                    None => break,
                }
            }
        }
        Ok(members)
    }

    /// Renders the members in chunks, each on a blocking thread with a time budget of its own: a large feed is slow,
    /// not broken.
    async fn render_chunks(
        &self,
        mut members: Vec<Member>,
        window: TimeRange,
        mode: FeedMode,
        summary: &str,
        salt: &[u8],
    ) -> AppResult<Vec<(String, DateTime<Utc>)>> {
        let mut parts: Vec<(String, DateTime<Utc>)> = Vec::with_capacity(members.len());
        while !members.is_empty() {
            let chunk: Vec<Member> = members.drain(..members.len().min(CHUNK)).collect();
            let (summary, salt, deadline) = (summary.to_owned(), salt.to_vec(), Deadline::of(&self.core));
            parts.extend(
                blocking(&self.core, ErrorContext::Query, move |limits| {
                    let render = Render {
                        window,
                        mode,
                        busy_summary: &summary,
                        uid_salt: &salt,
                        deadline,
                    };
                    render_blocking(chunk, &render, limits)
                })
                .await?,
            );
        }
        Ok(parts)
    }

    /// The summary of a busy block: the text the tenant named for the owner's language (`busy_text_by_locale` of its
    /// settings, then `busy_text`: [`TenantSettings::busy_text_for`](davhaven_domain::TenantSettings::busy_text_for)), or
    /// else the `feed_busy` template of the tenant's theme in the owner's language; the built-in text when the renderer
    /// cannot answer. Whatever the source, no control character reaches the feed, and the text is cut at
    /// [`MAX_BUSY_TEXT_CHARS`] characters.
    async fn busy_text(&self, settings: &davhaven_domain::TenantSettings, locale: &davhaven_domain::Locale) -> String {
        if let Some(text) = settings.busy_text_for(locale).map(clean_summary)
            && !text.trim().is_empty()
        {
            return text;
        }
        let theme = settings.theme_name();
        let rendered = match TemplateName::parse("feed_busy") {
            Ok(template) => {
                self.core
                    .deps()
                    .templates
                    .render(RenderRequest {
                        template,
                        locale: locale.clone(),
                        theme: theme.to_owned(),
                        model: serde_json::json!({}),
                    })
                    .await
            }
            Err(_) => return texts::busy_summary(locale).to_owned(),
        };
        match rendered {
            Ok(rendered) => {
                let text = clean_summary(&rendered.subject);
                if text.trim().is_empty() {
                    texts::busy_summary(locale).to_owned()
                } else {
                    text
                }
            }
            Err(_) => texts::busy_summary(locale).to_owned(),
        }
    }
}

#[async_trait]
impl FeedService for FeedServiceImpl {
    async fn render(&self, ctx: &RequestContext, conditional: Conditional) -> AppResult<FeedResponse> {
        let Actor::FeedReader { principal, token } = ctx.actor else {
            return Err(AppError::not_found());
        };
        let deps = self.core.deps();
        let anchor = day_start(deps.clock.now());
        let span = (
            anchor - Duration::days(i64::from(deps.config.feeds.window_past_days)),
            anchor + Duration::days(i64::from(deps.config.feeds.window_future_days)),
        );
        let window = TimeRange::new(Some(span.0), Some(span.1));
        let max_objects = usize::try_from(deps.config.feeds.max_objects).unwrap_or(usize::MAX);
        let max_bytes = usize::try_from(deps.config.feeds.max_bytes).unwrap_or(usize::MAX);
        let mut tx = deps.database.begin(ctx.tenant, TxMode::ReadOnly).await?;
        let tenant = tx.tenant().get().await?;
        if !tenant.settings.feeds_enabled {
            return Err(AppError::not_found());
        }
        let row = tx.credentials().get_feed_token(token).await?;
        if row.revoked_at.is_some() || row.principal_id != principal {
            return Err(AppError::not_found());
        }
        // A suspended or deleted principal has no feed, whatever the token says (the edge refuses it as well).
        let owner = tx.principals().get(principal).await?;
        if owner.status != PrincipalStatus::Active {
            return Err(AppError::not_found());
        }
        let calendars = self.readable(tx.as_mut(), principal, token, &row.calendar_ids).await?;
        if calendars.is_empty() {
            return Err(AppError::not_found());
        }
        let locale = owner.locale.clone().unwrap_or_else(|| tenant.settings.locale.clone());
        let salt = deps
            .keyring
            .sign(KeyPurpose::CacheKey, format!("davhaven/busy-uid/v1/{token}").as_bytes())
            .mac;
        let mode = row.mode;
        let summary = self.busy_text(&tenant.settings, &locale).await;
        let name = match calendars.as_slice() {
            [(single, _)] => single.display_name.clone(),
            _ => tenant.display_name.clone(),
        };
        let etag = Identity {
            tenant: tenant.id,
            mode,
            window: span,
            refresh: &deps.config.feeds.refresh_interval,
            size: (max_objects, max_bytes),
            locale: &locale,
            busy_summary: &summary,
            salt: &salt,
            name: &name,
            limits: &deps.limits.ical,
            calendars: &calendars,
        }
        .etag();
        // The client has this very document: nothing is read or rendered.
        if conditional.if_none_match.as_ref() == Some(&etag) {
            tx.commit().await?;
            return Ok(FeedResponse::NotModified { etag });
        }
        let index = IndexFilter {
            time_range: Some(davhaven_ports::TimeRange {
                start: window.start,
                end: window.end,
            }),
            ..IndexFilter::all()
        };
        let members = Self::collect_members(tx.as_mut(), &calendars, &index, (max_objects, max_bytes), token).await?;
        tx.commit().await?;
        let parts = self.render_chunks(members, window, mode, &summary, &salt).await?;
        let last_modified = parts.iter().map(|(_, at)| *at).max();
        let texts: Vec<String> = parts.into_iter().map(|(text, _)| text).collect();
        let body = assemble(&name, &deps.config.feeds.refresh_interval, &texts, span);
        Ok(FeedResponse::Body(FeedBody {
            etag,
            body,
            calendar_name: name,
            last_modified,
            refresh_interval: deps.config.feeds.refresh_interval.clone(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVENT: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\nBEGIN:VTIMEZONE\r\nTZID:Europe/Berlin\r\nBEGIN:STANDARD\r\nDTSTART:19701025T030000\r\nTZOFFSETFROM:+0200\r\nTZOFFSETTO:+0100\r\nEND:STANDARD\r\nEND:VTIMEZONE\r\nBEGIN:VEVENT\r\nUID:a\r\nDTSTART;TZID=Europe/Berlin:20270301T100000\r\nSUMMARY:One\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    fn window() -> (DateTime<Utc>, DateTime<Utc>) {
        (
            DateTime::from_timestamp(1_790_000_000, 0).unwrap_or_default(),
            DateTime::from_timestamp(1_830_000_000, 0).unwrap_or_default(),
        )
    }

    fn block(lines: &[&str]) -> Block {
        let mut block = Block::new();
        for line in lines {
            block.push(line);
        }
        block
    }

    #[test]
    fn components_are_split_at_the_top_level_only() {
        let blocks = components(EVENT);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].physical.first().map(String::as_str), Some("BEGIN:VTIMEZONE"));
        assert!(
            blocks[0].physical.iter().any(|line| line == "BEGIN:STANDARD"),
            "nested components stay inside"
        );
        assert_eq!(blocks[1].physical.first().map(String::as_str), Some("BEGIN:VEVENT"));
        assert_eq!(tzid_of(&blocks[0]), Some("Europe/Berlin"));
        assert!(blocks[0].is("VTIMEZONE") && blocks[1].is("vevent") && !blocks[1].is("VTIMEZONE"));
    }

    #[test]
    fn a_document_has_the_header_one_zone_per_tzid_and_every_event() {
        let second = EVENT.replace("UID:a", "UID:b").replace("One", "Two");
        let refresh = EventDuration::parse("PT15M").unwrap();
        let document = assemble("Team, \"calendar\"; 1", &refresh, &[EVENT.to_owned(), second], window());
        assert!(document.starts_with("BEGIN:VCALENDAR\r\nVERSION:2.0\r\n"), "{document}");
        assert!(document.ends_with("END:VCALENDAR\r\n"));
        assert!(
            document.contains("X-WR-CALNAME:Team\\, \"calendar\"\\; 1\r\n"),
            "{document}"
        );
        assert!(document.contains("REFRESH-INTERVAL;VALUE=DURATION:PT15M\r\n"));
        assert!(document.contains("X-PUBLISHED-TTL:PT15M\r\n"));
        assert_eq!(
            document.matches("BEGIN:VTIMEZONE").count(),
            1,
            "one definition per TZID"
        );
        assert_eq!(document.matches("BEGIN:VEVENT").count(), 2);
        assert!(!document.contains("PRODID:-//x//EN"), "the feed has its own PRODID");
        assert!(document.lines().all(|line| line.len() <= 76), "lines are folded");
    }

    #[test]
    fn long_names_are_folded_and_text_is_escaped() {
        let folded = fold(&format!("X-WR-CALNAME:{}", "ä".repeat(60)));
        for line in folded.split("\r\n") {
            assert!(line.len() <= 76, "{line}");
        }
        assert_eq!(folded.replace("\r\n ", ""), format!("X-WR-CALNAME:{}", "ä".repeat(60)));
        assert_eq!(escape_text("a,b;c\\d\ne"), "a\\,b\\;c\\\\d\\ne");
    }

    fn zoned(uid: &str, tzid: &str) -> String {
        format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\nBEGIN:VEVENT\r\nUID:{uid}\r\n\
             DTSTART;TZID={tzid}:20270301T100000\r\nDTEND;TZID={tzid}:20270301T110000\r\n\
             SUMMARY:DTSTART;TZID=Europe/Paris:20270301T100000\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
        )
    }

    #[test]
    fn time_zones_the_events_use_but_no_object_defines_are_added_once() {
        let refresh = EventDuration::parse("PT15M").unwrap();
        let parts = [
            zoned("a", "Europe/Berlin"),
            zoned("b", "Europe/Berlin"),
            zoned("c", "America/New_York"),
            zoned("d", "Nowhere/Land"),
            EVENT.replace("UID:a", "UID:e"),
        ];
        let document = assemble("Team", &refresh, &parts, window());
        for expected in ["TZID:Europe/Berlin", "TZID:America/New_York"] {
            assert_eq!(
                document.matches(&format!("\r\n{expected}\r\n")).count(),
                1,
                "{expected}\n{document}"
            );
        }
        assert_eq!(document.matches("BEGIN:VTIMEZONE").count(), 2, "{document}");
        assert!(
            !document.contains("TZID:Nowhere/Land"),
            "a zone that is none stays as the client wrote it"
        );
        assert!(
            !document.contains("TZID:Europe/Paris"),
            "text in a value is not a parameter: {document}"
        );
        assert_eq!(document.matches("BEGIN:VEVENT").count(), 5);
        let vtimezone = document.find("BEGIN:VTIMEZONE").unwrap_or_default();
        let first_event = document.find("BEGIN:VEVENT").unwrap_or_default();
        assert!(vtimezone < first_event, "definitions come before the events");
    }

    #[test]
    fn tzids_are_read_from_parameters_only() {
        let block = block(&[
            "BEGIN:VEVENT",
            "DTSTART;TZID=Europe/Berlin:20270301T100000",
            "DTEND;VALUE=DATE-TIME;TZID=\"America/New_York\":20270301T110000",
            "EXDATE;TZID=Europe/Berlin:20270302T100000",
            "SUMMARY:A;TZID=Europe/Paris:b",
            "END:VEVENT",
        ]);
        assert_eq!(
            used_tzids(&block),
            vec!["Europe/Berlin".to_owned(), "America/New_York".to_owned()]
        );
    }

    #[test]
    fn a_tzid_parameter_split_by_a_fold_is_still_found() {
        let block = block(&[
            "BEGIN:VEVENT",
            "DTSTART;VALUE=DATE-TIME;TZ",
            " ID=Europe/Be",
            " rlin:20270301T100000",
            "ATTENDEE;CN=\"Anna: the",
            "  boss\";TZID=Asia/Tokyo:mailto:a@example.org",
            "SUMMARY:Lunch",
            " TZID=Europe/Paris;is-text",
            "END:VEVENT",
        ]);
        assert_eq!(
            used_tzids(&block),
            vec!["Europe/Berlin".to_owned(), "Asia/Tokyo".to_owned()],
            "continuation lines are part of their property, and a colon inside a quoted value ends nothing"
        );
        assert_eq!(block.physical.len(), 9, "the document keeps the physical lines");
    }

    #[test]
    fn the_tzid_of_a_zone_is_its_own_property() {
        let zone = block(&[
            "BEGIN:VTIMEZONE",
            "X-TZID-NOTE:not this",
            "TZIDX:nor this",
            "TZID:Europe/Berlin",
            "END:VTIMEZONE",
        ]);
        assert_eq!(tzid_of(&zone), Some("Europe/Berlin"));
        let parameterized = block(&["BEGIN:VTIMEZONE", "TZID;X-FOO=bar:Asia/Tokyo", "END:VTIMEZONE"]);
        assert_eq!(tzid_of(&parameterized), Some("Asia/Tokyo"));
    }
}
