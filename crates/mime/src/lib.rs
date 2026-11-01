//! Assembly of `OutgoingMail` values into RFC 5322 messages.
//!
//! Produces the iMIP structure (`multipart/mixed` with `multipart/alternative` text, HTML and `text/calendar`
//! parts plus an `application/ics` attachment) with RFC 2047 encoded headers.

#![forbid(unsafe_code)]

pub mod headers;
pub mod message;
