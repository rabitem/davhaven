//! The requests of the permission matrix on the web pages: subscription feeds and RSVP pages.
//!
//! Both identify by a token in the URL and carry no credentials in a header. A feed token belongs to a principal and
//! lists calendars; access is checked again on every request, so a token of a principal who cannot read a calendar
//! shows nothing of it (404). Nobody of the fixture world holds an RSVP token, so the pages answer the 404 of an
//! unknown token to every actor; the states of a real RSVP token (valid, expired, revoked) are tested by the scheduling
//! matrix.

use davhaven_fixtures::{feed_token_secret, rsvp_token_secret};

use super::{MatrixEnv, Plan, Probe, request};
use crate::handles::Actor;
use crate::matrix::{Case, Operation, Resolution, Surface};

/// Plans a case on the feed and RSVP surfaces.
pub async fn plan(env: &dyn MatrixEnv, case: &Case, _resolution: &Resolution, _seq: usize) -> Plan {
    match case.operation {
        Operation::ReadFeed => {
            let token = match env.feed_token(case.actor, case.calendar).await {
                Ok(Some(token)) => token,
                Ok(None) => feed_token_secret("matrix:unknown"),
                Err(error) => return Plan::Skip(format!("the feed token cannot be made: {error}")),
            };
            Plan::Probes(vec![Probe::new(
                "GET of the feed",
                request(&Actor::Anonymous, "GET", &format!("/feeds/{token}.ics")),
            )])
        }
        Operation::RsvpView => {
            let token = rsvp_token_secret("matrix:unknown");
            Plan::Probes(vec![Probe::new(
                "GET of an RSVP page",
                request(&Actor::Anonymous, "GET", &format!("/rsvp/{token}")),
            )])
        }
        Operation::RsvpAnswer => {
            let token = rsvp_token_secret("matrix:unknown");
            Plan::Probes(vec![Probe::new(
                "POST of an answer",
                request(&Actor::Anonymous, "POST", &format!("/rsvp/{token}"))
                    .header("origin", &env.origin())
                    .content(
                        "application/x-www-form-urlencoded",
                        "partstat=ACCEPTED&csrf=x".to_owned(),
                    ),
            )])
        }
        other => Plan::NotApplicable(format!(
            "{other} does not exist on {}",
            match case.surface {
                Surface::Feed => "feeds",
                _ => "RSVP pages",
            }
        )),
    }
}
