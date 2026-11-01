//! The catalog of template names.
//!
//! The catalog is the contract between the application and the themes: the application renders these names with
//! the models documented in `docs/templates.md`, and a theme (the built-in default theme or a directory of a
//! deployment) provides them in the languages it supports. [`Template::sample_models`] returns models that carry
//! every field, optional ones included, and reach every branch of the built-in templates; the renderer uses them to
//! check at startup that a theme renders under strict undefined behavior, and the tests render every
//! template × locale × theme with them.
//!
//! Optional fields of a model are always present and `null` when absent, so a template can test them
//! (`{% if event.location %}`) without tripping over strict undefined behavior.

use davhaven_ports::TemplateName;
use serde_json::{Value, json};

/// What a template produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A mail: subject and plain text are required, HTML is optional.
    Mail,
    /// A web page: HTML is required, the subject is the page title.
    Page,
    /// A snippet of text: only the subject is used.
    Snippet,
}

/// A template of the catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Template {
    /// The invitation (or its update) mailed to an external attendee.
    ImipRequest,
    /// The cancellation mailed to an external attendee.
    ImipCancel,
    /// The reply of an internal attendee mailed to an external organizer.
    ImipReply,
    /// The RSVP page: the invitation and the form to answer it.
    RsvpPage,
    /// The page shown after an answer was recorded.
    RsvpAnswered,
    /// The page for a link that cannot be served: unknown, expired or revoked RSVP and feed links and every other failure of
    /// the web surface, worded by the `status` of the failure.
    RsvpUnavailable,
    /// The page the OAuth callback of a calendar provider ends on.
    OauthResult,
    /// The localized summary of busy blocks in feeds ("Busy").
    FeedBusy,
}

impl Template {
    /// Every template, in name order.
    pub const ALL: [Self; 8] = [
        Self::FeedBusy,
        Self::ImipCancel,
        Self::ImipReply,
        Self::ImipRequest,
        Self::OauthResult,
        Self::RsvpAnswered,
        Self::RsvpPage,
        Self::RsvpUnavailable,
    ];

    /// The name used in render requests and in theme file names.
    pub const fn name(self) -> &'static str {
        match self {
            Self::ImipRequest => "imip_request",
            Self::ImipCancel => "imip_cancel",
            Self::ImipReply => "imip_reply",
            Self::RsvpPage => "rsvp_page",
            Self::RsvpAnswered => "rsvp_answered",
            Self::RsvpUnavailable => "rsvp_unavailable",
            Self::OauthResult => "oauth_result",
            Self::FeedBusy => "feed_busy",
        }
    }

    /// What the template produces.
    pub const fn kind(self) -> Kind {
        match self {
            Self::ImipRequest | Self::ImipCancel | Self::ImipReply => Kind::Mail,
            Self::RsvpPage | Self::RsvpAnswered | Self::RsvpUnavailable | Self::OauthResult => Kind::Page,
            Self::FeedBusy => Kind::Snippet,
        }
    }

    /// The template of a name, if it is in the catalog.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|template| template.name() == name)
    }

    /// The name as a [`TemplateName`].
    ///
    /// # Panics
    ///
    /// Never: the catalog names are valid template names (a unit test checks every one).
    #[expect(
        clippy::expect_used,
        reason = "the catalog names are valid template names; a unit test parses every one"
    )]
    pub fn template_name(self) -> TemplateName {
        TemplateName::parse(self.name()).expect("catalog names are valid template names")
    }

    /// The parts a theme must provide for this template in every locale it supports: `(subject, html, text)`.
    pub const fn required_parts(self) -> (bool, bool, bool) {
        match self.kind() {
            Kind::Mail => (true, false, true),
            Kind::Page => (false, true, false),
            Kind::Snippet => (true, false, false),
        }
    }

    /// A model with every field the template may use.
    pub fn sample_model(self) -> Value {
        let mut models = self.sample_models();
        models.swap_remove(0)
    }

    /// Models that together reach every branch of the template: the full model first, then variants without the
    /// optional parts, for updates, for all-day events and for the error states of pages.
    pub fn sample_models(self) -> Vec<Value> {
        match self {
            Self::ImipRequest | Self::ImipCancel => {
                let full = mail_model(false, &Value::Null);
                let mut update = full.clone();
                put(&mut update, &["update"], Value::Bool(true));
                vec![full, update, bare(mail_model(false, &Value::Null))]
            }
            Self::ImipReply => {
                let mut full = mail_model(false, &json!({ "partstat": "ACCEPTED", "comment": "See you there." }));
                put(&mut full, &["rsvp_url"], Value::Null);
                let mut declined = full.clone();
                put(
                    &mut declined,
                    &["reply"],
                    json!({ "partstat": "DECLINED", "comment": null }),
                );
                let mut tentative = declined.clone();
                put(&mut tentative, &["reply", "partstat"], json!("TENTATIVE"));
                let bare_reply = bare(mail_model(false, &json!({ "partstat": "ACCEPTED", "comment": null })));
                vec![full, declined, tentative, bare_reply]
            }
            Self::RsvpPage => {
                let full = json!({
                    "tenant": { "name": "Example Organisation" },
                    "event": page_event_model(),
                    "organizer": { "name": "Anna Example" },
                    "cancelled": false,
                    "current": "NEEDS-ACTION",
                    "error": null,
                    "form": { "action": "/rsvp/dvh_rsvp_token", "csrf": "csrf-token", "comment_max": 500 },
                });
                let variant = |path: &[&str], value: Value| {
                    let mut model = full.clone();
                    put(&mut model, path, value);
                    model
                };
                vec![
                    full.clone(),
                    variant(&["cancelled"], Value::Bool(true)),
                    variant(&["current"], json!("ACCEPTED")),
                    variant(&["current"], json!("DECLINED")),
                    variant(&["current"], json!("TENTATIVE")),
                    variant(&["error"], json!("invalid_csrf")),
                    variant(&["error"], json!("invalid_answer")),
                    variant(&["error"], json!("comment_too_long")),
                    variant(&["event"], bare_event_model()),
                ]
            }
            Self::RsvpAnswered => {
                let full = json!({
                    "tenant": { "name": "Example Organisation" },
                    "event": page_event_model(),
                    "organizer": { "name": "Anna Example" },
                    "answer": "ACCEPTED",
                    "link": "/rsvp/dvh_rsvp_token",
                });
                let variant = |path: &[&str], value: Value| {
                    let mut model = full.clone();
                    put(&mut model, path, value);
                    model
                };
                vec![
                    full.clone(),
                    variant(&["answer"], json!("DECLINED")),
                    variant(&["answer"], json!("TENTATIVE")),
                    variant(&["event"], bare_event_model()),
                ]
            }
            // The page of a link that cannot be served says what to do by the status of the failure.
            Self::RsvpUnavailable => [404, 429, 503, 422]
                .into_iter()
                .map(|status| json!({ "status": status }))
                .collect(),
            Self::FeedBusy => vec![json!({})],
            Self::OauthResult => vec![
                json!({ "success": true, "provider": "Example Provider" }),
                json!({ "success": false, "provider": "Example Provider" }),
            ],
        }
    }
}

/// Sets the member at `path` of `model` (the parents must exist; a path that does not leaves the model alone,
/// which a unit test of the sample models would notice).
fn put(model: &mut Value, path: &[&str], value: Value) {
    let Some((last, parents)) = path.split_last() else {
        return;
    };
    let mut cursor = model;
    for key in parents {
        match cursor.get_mut(*key) {
            Some(next) => cursor = next,
            None => return,
        }
    }
    if let Some(object) = cursor.as_object_mut() {
        object.insert((*last).to_owned(), value);
    }
}

fn event_model() -> Value {
    json!({
        "summary": "Planning <session> & coffee",
        "description": "Agenda:\n1. Roadmap\n2. Budget",
        "location": "Room 4, Main Street 1",
        "start": { "date": "2027-01-12", "time": "10:00", "zone": "Europe/Berlin" },
        "end": { "date": "2027-01-12", "time": "11:30", "zone": "Europe/Berlin" },
        "all_day": false,
        "recurring": false,
    })
}

/// The event of the pages the RSVP link opens: the same model without the description. The link is a credential in a
/// mail and the page needs no authentication, so it shows what PLAN 2.13 allows (summary, time, location and the
/// organizer's name) and never the description, which can hold dial-in codes and internal notes. The application
/// supplies `null`; a theme cannot depend on a value that is never there.
fn page_event_model() -> Value {
    let mut model = event_model();
    put(&mut model, &["description"], Value::Null);
    model
}

/// An all-day event without any optional field.
fn bare_event_model() -> Value {
    json!({
        "summary": "Offsite",
        "description": null,
        "location": null,
        "start": { "date": "2027-01-12", "time": null, "zone": null },
        "end": null,
        "all_day": true,
        "recurring": true,
    })
}

fn mail_model(update: bool, reply: &Value) -> Value {
    json!({
        "tenant": { "name": "Example Organisation" },
        "organizer": { "name": "Anna Example", "email": "anna@example.org" },
        "attendee": { "name": "Guest Example", "email": "guest@example.net" },
        "event": event_model(),
        "update": update,
        "rsvp_url": "https://calendar.example.org/rsvp/dvh_rsvp_token",
        "reply": reply,
        "reply_to": "anna@example.org",
    })
}

/// A variant of a mail model without the optional parts.
fn bare(mut model: Value) -> Value {
    put(&mut model, &["event"], bare_event_model());
    put(&mut model, &["rsvp_url"], Value::Null);
    put(&mut model, &["attendee", "name"], Value::Null);
    // The mail of an organizer without an e-mail address comes from the no-reply address: nobody to reply to.
    put(&mut model, &["reply_to"], Value::Null);
    model
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_catalog_is_sorted_and_its_names_are_valid_template_names() {
        let names: Vec<&str> = Template::ALL.iter().map(|template| template.name()).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
        for template in Template::ALL {
            assert_eq!(template.template_name().as_str(), template.name());
            assert_eq!(Template::from_name(template.name()), Some(template));
        }
        assert_eq!(Template::from_name("imip_requests"), None);
        assert_eq!(Template::ALL.len(), 8);
    }

    #[test]
    fn every_kind_requires_the_parts_the_application_uses() {
        for template in Template::ALL {
            let (subject, html, text) = template.required_parts();
            match template.kind() {
                Kind::Mail => assert!(subject && text && !html, "{template:?}"),
                Kind::Page => assert!(html && !subject && !text, "{template:?}"),
                Kind::Snippet => assert!(subject && !html && !text, "{template:?}"),
            }
        }
    }

    #[test]
    fn sample_models_are_objects_with_every_optional_field_present() {
        for template in Template::ALL {
            let models = template.sample_models();
            assert_ne!(models.len(), 0);
            assert!(models.iter().all(Value::is_object), "{template:?}");
            assert_eq!(models[0], template.sample_model());
        }
        let request = Template::ImipRequest.sample_model();
        for key in [
            "tenant",
            "organizer",
            "attendee",
            "event",
            "update",
            "rsvp_url",
            "reply",
            "reply_to",
        ] {
            assert!(request.get(key).is_some(), "{key}");
        }
        for key in [
            "summary",
            "description",
            "location",
            "start",
            "end",
            "all_day",
            "recurring",
        ] {
            assert!(request["event"].get(key).is_some(), "{key}");
        }
        assert_eq!(Template::ImipReply.sample_model()["reply"]["partstat"], "ACCEPTED");
    }

    #[test]
    fn the_pages_of_an_rsvp_link_never_get_a_description() {
        for template in [Template::RsvpPage, Template::RsvpAnswered] {
            for model in template.sample_models() {
                assert_eq!(model["event"]["description"], Value::Null, "{template:?}: {model}");
            }
        }
        assert_ne!(
            Template::ImipRequest.sample_model()["event"]["description"],
            Value::Null,
            "mails to the attendee do carry it"
        );
    }

    #[test]
    fn variants_really_differ_from_the_full_model() {
        let requests = Template::ImipRequest.sample_models();
        assert_eq!(requests[1]["update"], true);
        assert_eq!(requests[2]["event"]["end"], Value::Null);
        assert_eq!(requests[2]["rsvp_url"], Value::Null);
        assert_eq!(requests[2]["attendee"]["name"], Value::Null);
        let replies = Template::ImipReply.sample_models();
        assert_eq!(replies[1]["reply"]["partstat"], "DECLINED");
        assert_eq!(replies[2]["reply"]["partstat"], "TENTATIVE");
        assert_eq!(replies[3]["reply"]["comment"], Value::Null);
        let pages = Template::RsvpPage.sample_models();
        assert_eq!(pages[1]["cancelled"], true);
        assert_eq!(pages[2]["current"], "ACCEPTED");
        assert_eq!(pages[5]["error"], "invalid_csrf");
        assert_eq!(pages[8]["event"]["location"], Value::Null);
        let answered = Template::RsvpAnswered.sample_models();
        assert_eq!(answered[1]["answer"], "DECLINED");
        assert_eq!(Template::OauthResult.sample_models()[1]["success"], false);
        // A path that does not exist leaves a model alone.
        let mut model = json!({"a": 1});
        put(&mut model, &["missing", "deeper"], json!(2));
        assert_eq!(model, json!({"a": 1}));
    }
}
