//! Google Calendar provider: OAuth (PKCE) and pull-only import into a mirror calendar.
//!
//! All HTTP goes through the `HttpClient` port and therefore through the egress policy; the crate depends on no HTTP client
//! library.
//!
//! | Module | Contents |
//! | --- | --- |
//! | [`config`] | the `[providers.google]` table: client id and secret, redirect URI, the window of the import |
//! | [`oauth`] | [`GoogleOAuth`](oauth::GoogleOAuth): the authorization code flow with PKCE, refresh and revocation |
//! | [`api`] | [`GoogleCalendars`](api::GoogleCalendars): the calendars of the account and the events of the window |
//! | [`provider`] | [`GoogleProvider`](provider::GoogleProvider): the `Provider` of the two |
//! | [`plugin`] | `register`, the plugin descriptor |
//!
//! `ics` turns the JSON events of Google into iCalendar objects (one per series) and `transport` is the HTTP side both halves
//! share. The recorded exchanges the tests replay are in `tests/fixtures`.
//!
//! Only the primary calendar of the account is mirrored, only events (not tasks or birthdays), and attendees, organizers and
//! alarms are not imported. The provider is pull-only: it asks for the read-only scope.

#![forbid(unsafe_code)]

pub mod api;
pub mod config;
mod ics;
pub mod oauth;
pub mod plugin;
pub mod provider;
mod transport;
