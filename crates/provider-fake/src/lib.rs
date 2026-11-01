//! A scriptable calendar provider for tests of the provider sync engine and the OAuth flow.
//!
//! The crate is the second implementation of the `provider` kind (`ENGINEERING_RULES` R2) next to the adapters of Google and
//! Microsoft. [`FakeProvider`](provider::FakeProvider) is a small, strict provider (PKCE is checked, an authorization code
//! works once, tokens expire with the clock and can be revoked) whose remote world, its calendars, events and failures, is a
//! [`Script`](script::Script) the test writes. The sync engine, the management API and the OAuth callback run against it
//! without a network, and it runs the same contract suite (`davhaven_port_tests::provider`) as the real adapters.
//!
//! | Module | Contents |
//! | --- | --- |
//! | [`provider`] | [`FakeProvider`](provider::FakeProvider): `Provider`, `OAuthProvider` and `RemoteCalendarApi` over a script |
//! | [`script`] | the remote world: calendars, events, the change log, issued tokens and scripted failures |
//! | [`config`] | the (empty) table of the plugin |
//! | [`plugin`] | `register`, the plugin descriptor |
//!
//! It is a **fake**: production mode refuses it (its descriptor says so), and the server has it only with the cargo
//! feature `provider-fake`.

#![forbid(unsafe_code)]

pub mod config;
pub mod plugin;
pub mod provider;
pub mod script;
