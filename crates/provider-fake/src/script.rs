//! Scripted remote calendars, changes and failures.
//!
//! A [`Script`] is the whole remote world of the fake provider: the account it signs in, its calendars, their events, the
//! tokens it has issued and the failures it has been told to cause. The provider reads it on every call and the test writes
//! it between calls, from the same handle (clones share the state), so a test says what the remote does next instead of
//! building a server.
//!
//! The world keeps a **change log**: every `put_event` and `remove_event` advances a sequence number, and a cursor of the
//! delta mode is that number, so the fake answers "what changed since" exactly as a provider with a change feed does. In
//! the snapshot mode it lists every event on every call, as the real adapters do.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, PoisonError};

use chrono::{DateTime, Duration, Utc};
use davhaven_ports::{Clock, PortError, RemoteCalendar};

/// The state is locked for an instant and never across an await.
#[expect(clippy::disallowed_types, reason = "a test double with synchronous accessors")]
type Mutex<T> = std::sync::Mutex<T>;

/// What the fake does to the calendar calls: answer the changes since a cursor, or list the whole calendar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// `changes_since` answers a delta for a cursor it issued and a snapshot for none, like a provider with a change feed.
    #[default]
    Delta,
    /// `changes_since` answers a snapshot on every call, like the adapters of 1.0.
    Snapshot,
}

/// The call a failure is meant for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Call {
    /// `OAuthProvider::exchange`.
    Exchange,
    /// `OAuthProvider::refresh`.
    Refresh,
    /// `OAuthProvider::revoke`.
    Revoke,
    /// `RemoteCalendarApi::list_calendars`.
    ListCalendars,
    /// `RemoteCalendarApi::changes_since`.
    Changes,
}

impl Call {
    /// The name the call goes by in [`Script::calls`].
    pub const fn name(self) -> &'static str {
        match self {
            Self::Exchange => "exchange",
            Self::Refresh => "refresh",
            Self::Revoke => "revoke",
            Self::ListCalendars => "list_calendars",
            Self::Changes => "changes_since",
        }
    }
}

/// One entry of the change log.
#[derive(Debug, Clone)]
struct Logged {
    seq: u64,
    calendar: String,
    remote_id: String,
    etag: String,
    /// `None` for a deletion.
    ics: Option<String>,
}

pub(crate) struct State {
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) mode: Mode,
    pub(crate) calendars: Vec<RemoteCalendar>,
    events: BTreeMap<String, BTreeMap<String, (String, String)>>,
    log: Vec<Logged>,
    seq: u64,
    /// The oldest sequence number a cursor may carry; older cursors are stale.
    floor: u64,
    /// The challenge of every authorization that was started, with the redirect address it named.
    pub(crate) challenges: BTreeMap<String, String>,
    accepted_codes: BTreeMap<String, String>,
    rejected_codes: BTreeSet<String>,
    used_codes: BTreeSet<String>,
    access_tokens: BTreeMap<String, DateTime<Utc>>,
    refresh_tokens: BTreeSet<String>,
    revoked: Vec<String>,
    pub(crate) access_ttl: Duration,
    pub(crate) rotate_refresh: bool,
    pub(crate) client_refused: bool,
    failures: VecDeque<(Call, PortError)>,
    calls: Vec<String>,
    issued: u64,
}

/// The remote world of the fake provider. Clones share it.
#[derive(Clone)]
pub struct Script {
    pub(crate) state: Arc<Mutex<State>>,
}

impl core::fmt::Debug for Script {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let state = self.lock();
        f.debug_struct("Script")
            .field("mode", &state.mode)
            .field("calendars", &state.calendars.len())
            .field("log", &state.log.len())
            .finish_non_exhaustive()
    }
}

/// The ICS of a one-hour event, for tests that need some content.
///
/// `start` and `end` are UTC date-times in the form `20270105T090000Z`.
pub fn simple_event(uid: &str, summary: &str, start: &str, end: &str) -> String {
    [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//Davhaven//fake provider//EN",
        "BEGIN:VEVENT",
        &format!("UID:{uid}"),
        "DTSTAMP:20261001T000000Z",
        &format!("DTSTART:{start}"),
        &format!("DTEND:{end}"),
        &format!("SUMMARY:{summary}"),
        "END:VEVENT",
        "END:VCALENDAR",
        "",
    ]
    .join("\r\n")
}

impl Script {
    /// A world with one primary calendar `primary` named `Fake calendar`, no events and no failures. Tokens expire an hour
    /// after the time of `clock`.
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                clock,
                mode: Mode::Delta,
                calendars: vec![RemoteCalendar::new("primary", "Fake calendar").primary()],
                events: BTreeMap::new(),
                log: Vec::new(),
                seq: 0,
                floor: 0,
                challenges: BTreeMap::new(),
                accepted_codes: BTreeMap::new(),
                rejected_codes: BTreeSet::new(),
                used_codes: BTreeSet::new(),
                access_tokens: BTreeMap::new(),
                refresh_tokens: BTreeSet::new(),
                revoked: Vec::new(),
                access_ttl: Duration::hours(1),
                rotate_refresh: false,
                client_refused: false,
                failures: VecDeque::new(),
                calls: Vec::new(),
                issued: 0,
            })),
        }
    }

    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Chooses what `changes_since` answers (see [`Mode`]).
    pub fn set_mode(&self, mode: Mode) {
        self.lock().mode = mode;
    }

    /// Replaces the calendars of the account.
    pub fn set_calendars(&self, calendars: Vec<RemoteCalendar>) {
        self.lock().calendars = calendars;
    }

    /// Creates or replaces an event of `calendar`; the change log records it.
    pub fn put_event(&self, calendar: &str, remote_id: &str, ics: impl Into<String>) {
        let mut state = self.lock();
        state.seq += 1;
        let seq = state.seq;
        let ics = ics.into();
        let etag = format!("\"fake-{seq}\"");
        state
            .events
            .entry(calendar.to_owned())
            .or_default()
            .insert(remote_id.to_owned(), (etag.clone(), ics.clone()));
        state.log.push(Logged {
            seq,
            calendar: calendar.to_owned(),
            remote_id: remote_id.to_owned(),
            etag,
            ics: Some(ics),
        });
    }

    /// Deletes an event of `calendar`; the change log records it. Deleting what is not there changes nothing.
    pub fn remove_event(&self, calendar: &str, remote_id: &str) {
        let mut state = self.lock();
        let existed = state
            .events
            .get_mut(calendar)
            .and_then(|events| events.remove(remote_id))
            .is_some();
        if !existed {
            return;
        }
        state.seq += 1;
        let seq = state.seq;
        state.log.push(Logged {
            seq,
            calendar: calendar.to_owned(),
            remote_id: remote_id.to_owned(),
            etag: format!("\"fake-{seq}\""),
            ics: None,
        });
    }

    /// The ICS of an event the remote holds now.
    pub fn event(&self, calendar: &str, remote_id: &str) -> Option<String> {
        self.lock()
            .events
            .get(calendar)
            .and_then(|events| events.get(remote_id))
            .map(|(_, ics)| ics.clone())
    }

    /// The remote ids of the events the remote holds in `calendar`, sorted.
    pub fn event_ids(&self, calendar: &str) -> Vec<String> {
        self.lock()
            .events
            .get(calendar)
            .map(|events| events.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Makes the change log forget its past: a cursor that was issued before this call is stale afterwards, and
    /// `changes_since` answers `Invalid` for it, as a provider does when a sync token has expired.
    pub fn forget_history(&self) {
        let mut state = self.lock();
        state.floor = state.seq + 1;
    }

    /// The code `code` is accepted once and signs in the account `account_ref`. Without a call to this, `fake-<name>` is
    /// accepted and signs in `<name>@fake.example`.
    pub fn accept_code(&self, code: &str, account_ref: &str) {
        self.lock()
            .accepted_codes
            .insert(code.to_owned(), account_ref.to_owned());
    }

    /// The code `code` is refused, as a provider refuses one that expired.
    pub fn reject_code(&self, code: &str) {
        self.lock().rejected_codes.insert(code.to_owned());
    }

    /// The person removed the application's access: every token issued so far stops working.
    pub fn revoke_access(&self) {
        let mut state = self.lock();
        state.access_tokens.clear();
        state.refresh_tokens.clear();
    }

    /// The provider forgets the access tokens it issued and keeps the refresh tokens, as when it revokes an access token before
    /// its time: the next call with an old access token is refused, and a refresh gives a new one.
    pub fn revoke_access_tokens(&self) {
        self.lock().access_tokens.clear();
    }

    /// Issues an access token and a refresh token as if a person had consented, for a test that starts after the
    /// connection. Returns `(access, refresh)`.
    pub fn issue_tokens(&self) -> (String, String) {
        let mut state = self.lock();
        let (access, _expires) = state.issue_access();
        let refresh = state.issue_refresh();
        (access, refresh)
    }

    /// How long an access token lives (default one hour).
    pub fn set_access_ttl(&self, ttl: Duration) {
        self.lock().access_ttl = ttl;
    }

    /// Whether a refresh answers a new refresh token and retires the old one (the Microsoft behavior); the default keeps
    /// the refresh token (the Google behavior).
    pub fn rotate_refresh_tokens(&self, rotate: bool) {
        self.lock().rotate_refresh = rotate;
    }

    /// The remote refuses the client of the deployment (a wrong, rotated or expired client secret): every `exchange` and
    /// `refresh` answers `Invalid`, as the adapters answer `invalid_client`, until this is called with `false`.
    pub fn refuse_client(&self, refused: bool) {
        self.lock().client_refused = refused;
    }

    /// The next call of this kind fails with `error`; calls that are scripted so are used up in order.
    pub fn fail_next(&self, call: Call, error: PortError) {
        self.lock().failures.push_back((call, error));
    }

    /// The calls the provider received, in order, as `exchange`, `refresh`, `revoke`, `list_calendars` and
    /// `changes_since <calendar> <cursor or ->`.
    pub fn calls(&self) -> Vec<String> {
        self.lock().calls.clone()
    }

    /// How often `call` was made.
    pub fn count(&self, call: Call) -> usize {
        let name = call.name();
        self.lock()
            .calls
            .iter()
            .filter(|made| made.as_str() == name || made.strip_prefix(name).is_some_and(|rest| rest.starts_with(' ')))
            .count()
    }

    /// The tokens that were revoked, in order.
    pub fn revoked_tokens(&self) -> Vec<String> {
        self.lock().revoked.clone()
    }

    /// The access tokens that work now.
    pub fn live_access_tokens(&self) -> Vec<String> {
        let state = self.lock();
        let now = state.clock.now();
        state
            .access_tokens
            .iter()
            .filter(|(_, expires)| **expires > now)
            .map(|(token, _)| token.clone())
            .collect()
    }
}

impl State {
    /// Records a call and takes the failure scripted for it, if any.
    pub(crate) fn enter(&mut self, call: Call, detail: Option<String>) -> Result<(), PortError> {
        self.calls.push(match detail {
            Some(detail) => format!("{} {detail}", call.name()),
            None => call.name().to_owned(),
        });
        if let Some(position) = self.failures.iter().position(|(wanted, _)| *wanted == call)
            && let Some((_, error)) = self.failures.remove(position)
        {
            return Err(error);
        }
        Ok(())
    }

    /// Issues a fresh access token.
    pub(crate) fn issue_access(&mut self) -> (String, DateTime<Utc>) {
        self.issued += 1;
        let token = format!("fake-access-{}", self.issued);
        let expires = self.clock.now() + self.access_ttl;
        self.access_tokens.insert(token.clone(), expires);
        (token, expires)
    }

    /// Issues a fresh refresh token.
    pub(crate) fn issue_refresh(&mut self) -> String {
        self.issued += 1;
        let token = format!("fake-refresh-{}", self.issued);
        self.refresh_tokens.insert(token.clone());
        token
    }

    /// Takes a refresh token out of use; whether it was valid.
    pub(crate) fn retire_refresh(&mut self, token: &str) -> bool {
        self.refresh_tokens.remove(token)
    }

    pub(crate) fn knows_refresh(&self, token: &str) -> bool {
        self.refresh_tokens.contains(token)
    }

    pub(crate) fn record_revoked(&mut self, token: &str) {
        self.revoked.push(token.to_owned());
        self.refresh_tokens.remove(token);
        self.access_tokens.remove(token);
    }

    /// Whether `token` is an access token that works now.
    pub(crate) fn access_is_valid(&self, token: &str) -> bool {
        self.access_tokens
            .get(token)
            .is_some_and(|expires| *expires > self.clock.now())
    }

    /// The account a code signs in, taking the code out of use. `None` when the provider refuses the code.
    pub(crate) fn redeem_code(&mut self, code: &str) -> Option<String> {
        if self.rejected_codes.contains(code) || !self.used_codes.insert(code.to_owned()) {
            return None;
        }
        if let Some(account) = self.accepted_codes.remove(code) {
            return Some(account);
        }
        let name = code.strip_prefix("fake-").filter(|name| !name.is_empty())?;
        Some(format!("{name}@fake.example"))
    }

    pub(crate) fn has_calendar(&self, calendar: &str) -> bool {
        self.calendars.iter().any(|candidate| candidate.remote_id == calendar)
    }

    /// Every event of `calendar`, in the order of the remote ids, as the changes of a listing.
    pub(crate) fn listing(&self, calendar: &str) -> Vec<(String, String, String)> {
        self.events
            .get(calendar)
            .map(|events| {
                events
                    .iter()
                    .map(|(id, (etag, ics))| (id.clone(), etag.clone(), ics.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The cursor of the delta mode for the present state.
    pub(crate) fn cursor(&self) -> String {
        format!("fake-cursor-{}", self.seq)
    }

    /// The sequence number a cursor carries, when it is one this world issued and is not stale.
    pub(crate) fn seq_of(&self, cursor: &str) -> Option<u64> {
        let seq: u64 = cursor.strip_prefix("fake-cursor-")?.parse().ok()?;
        (seq >= self.floor && seq <= self.seq).then_some(seq)
    }

    /// What changed in `calendar` after `since`: the last state of every event that was touched, `None` for a deletion.
    pub(crate) fn changes_after(&self, calendar: &str, since: u64) -> Vec<(String, String, Option<String>)> {
        let mut latest: BTreeMap<&str, &Logged> = BTreeMap::new();
        for entry in self
            .log
            .iter()
            .filter(|entry| entry.calendar == calendar && entry.seq > since)
        {
            latest.insert(entry.remote_id.as_str(), entry);
        }
        latest
            .into_iter()
            .map(|(id, entry)| (id.to_owned(), entry.etag.clone(), entry.ics.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use davhaven_ports::testing::ManualClock;

    use super::*;

    fn script() -> (Script, ManualClock) {
        let clock = ManualClock::default();
        (Script::new(Arc::new(clock.clone())), clock)
    }

    #[test]
    fn events_are_put_changed_and_removed_with_a_log() {
        let (script, _clock) = script();
        script.put_event(
            "primary",
            "e1",
            simple_event("u1", "One", "20270105T090000Z", "20270105T100000Z"),
        );
        script.put_event("primary", "e2", "two");
        script.put_event("primary", "e1", "one again");
        script.remove_event("primary", "e2");
        script.remove_event("primary", "never-there");
        assert_eq!(script.event("primary", "e1").as_deref(), Some("one again"));
        assert_eq!(script.event_ids("primary"), vec!["e1".to_owned()]);
        let state = script.lock();
        assert_eq!(state.seq, 4, "a deletion of what is not there is not a change");
        let after_first = state.changes_after("primary", 1);
        assert_eq!(
            after_first
                .iter()
                .map(|(id, _, ics)| (id.as_str(), ics.as_deref()))
                .collect::<Vec<_>>(),
            vec![("e1", Some("one again")), ("e2", None)],
            "the last state of every touched event, a deletion as None"
        );
        assert_eq!(state.cursor(), "fake-cursor-4");
    }

    #[test]
    fn cursors_are_valid_until_the_history_is_forgotten() {
        let (script, _clock) = script();
        script.put_event("primary", "e1", "x");
        let cursor = script.lock().cursor();
        assert_eq!(script.lock().seq_of(&cursor), Some(1));
        assert_eq!(script.lock().seq_of("fake-cursor-9"), None, "from the future");
        assert_eq!(script.lock().seq_of("other"), None);
        script.forget_history();
        assert_eq!(script.lock().seq_of(&cursor), None, "stale");
        script.put_event("primary", "e2", "y");
        assert_eq!(script.lock().seq_of("fake-cursor-2"), Some(2));
    }

    #[test]
    fn codes_work_once_and_default_to_the_name_after_the_prefix() {
        let (script, _clock) = script();
        script.accept_code("special", "anna@elsewhere.example");
        script.reject_code("fake-expired");
        let mut state = script.lock();
        assert_eq!(state.redeem_code("fake-anna").as_deref(), Some("anna@fake.example"));
        assert_eq!(state.redeem_code("fake-anna"), None, "an authorization code works once");
        assert_eq!(state.redeem_code("special").as_deref(), Some("anna@elsewhere.example"));
        assert_eq!(state.redeem_code("fake-expired"), None);
        assert_eq!(state.redeem_code("unknown"), None);
        assert_eq!(state.redeem_code("fake-"), None);
    }

    #[test]
    fn tokens_expire_with_the_clock_and_are_taken_away_by_revocation() {
        let (script, clock) = script();
        let (token, expires) = script.lock().issue_access();
        assert_eq!(expires, clock.now() + Duration::hours(1));
        assert!(script.lock().access_is_valid(&token));
        clock.advance(Duration::hours(2));
        assert!(!script.lock().access_is_valid(&token));
        let (second, _) = script.lock().issue_access();
        let refresh = script.lock().issue_refresh();
        script.revoke_access();
        assert!(!script.lock().access_is_valid(&second));
        assert!(!script.lock().knows_refresh(&refresh));
    }

    #[test]
    fn a_scripted_failure_hits_the_next_call_of_its_kind_only() {
        let (script, _clock) = script();
        script.fail_next(Call::Changes, PortError::timeout("slow"));
        assert!(script.lock().enter(Call::ListCalendars, None).is_ok());
        assert!(
            script
                .lock()
                .enter(Call::Changes, Some("primary -".to_owned()))
                .is_err()
        );
        assert!(script.lock().enter(Call::Changes, Some("primary -".to_owned())).is_ok());
        assert_eq!(script.count(Call::Changes), 2);
        assert_eq!(script.count(Call::ListCalendars), 1);
        assert_eq!(script.count(Call::Exchange), 0);
        assert_eq!(
            script.calls(),
            vec!["list_calendars", "changes_since primary -", "changes_since primary -"]
        );
    }
}
