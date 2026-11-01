//! The iMIP composer: renders templates and builds iTIP mails at dispatch time.
//!
//! The outbox holds an `ImipJob` (object id, recipient, method, locale, template) and no rendered content. The
//! [`ImipHandler`] (kind `imip`) turns it into an `OutgoingMail`:
//!
//! 1. the calendar data (the stored object, or the snapshot of the job) goes through a [`CalendarBackend`]
//!    (`davhaven-ical` in production), which yields the event and the iTIP text;
//! 2. the people are resolved against the principals of the tenant, and an invitation gets its RSVP link
//!    (`rsvp`);
//! 3. the template is rendered with the `model` documented in `docs/templates.md`;
//! 4. the mail is composed (`From` and `Reply-To` by `mail.from_mode`, `Message-ID` from the outbox id, the
//!    `text/calendar` alternative, `invite.ics`, `Content-Class`, `Auto-Submitted`), the staging rules and the safety
//!    rails of [`guard`] apply, and the transport sends it.
//!
//! `docs/mail.md` describes the mail, the headers, the staging rules and the failure behavior for operators.

pub mod backend;
pub mod guard;
mod handler;
mod model;
mod rsvp;

pub use backend::{BackendError, CalendarBackend, IcalBackend, MessageRequest, Prepared};
pub use handler::{
    DROPPED_TOTAL, FAILED_TOTAL, HELD_TOTAL, ImipHandler, REDIRECTED_FROM_HEADER, REPLY_SERVICE_FORM_TOTAL, SENT_TOTAL,
    send_budget,
};
