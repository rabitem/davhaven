//! Microsoft 365 calendar provider: OAuth (PKCE) and pull-only import into a mirror calendar.
//!
//! All HTTP goes through the `HttpClient` port and therefore through the egress policy; the crate depends on no HTTP client
//! library.
//!
//! | Module | Contents |
//! | --- | --- |
//! | [`config`] | the `[providers.microsoft]` table: client id and secret, redirect URI, the directory, the window of the import |
//! | [`oauth`] | [`MicrosoftOAuth`](oauth::MicrosoftOAuth): the authorization code flow with PKCE and refresh |
//! | [`api`] | [`MicrosoftCalendars`](api::MicrosoftCalendars): the calendars of the account and the events of the window |
//! | [`provider`] | [`MicrosoftProvider`](provider::MicrosoftProvider): the `Provider` of the two |
//! | [`plugin`] | `register`, the plugin descriptor |
//!
//! `ics` turns the JSON events of Microsoft Graph into iCalendar objects (one per occurrence) and `transport` is the HTTP side both
//! halves share. The recorded exchanges the tests replay are in `tests/fixtures`.
//!
//! Only the default calendar of the account is mirrored, and attendees, organizers and alarms are not imported. The provider is
//! pull-only: it asks for the read-only permission.

#![forbid(unsafe_code)]

pub mod api;
pub mod config;
mod ics;
pub mod oauth;
pub mod plugin;
pub mod provider;
mod transport;
