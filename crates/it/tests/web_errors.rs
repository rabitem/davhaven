//! The failures of the web surface through the real routes, services and template renderer: a link that does not work is the
//! page of the theme of the deployment in the language of the visitor, the same page for every cause, and nothing of the
//! request is in it.

use davhaven_testkit::{TestApp, TestResponse};

/// A token of the format of the RSVP links that nothing issued.
fn unknown_rsvp_token() -> String {
    format!("dvh_rsvp_abcdefghijkl_{}", "u".repeat(43))
}

/// A token of the format of the feed links that nothing issued.
fn unknown_feed_token() -> String {
    format!("dvh_feed_abcdefghijkl_{}", "u".repeat(43))
}

fn status(response: &TestResponse) -> u16 {
    response.status.as_u16()
}

#[tokio::test]
async fn a_link_that_does_not_work_is_the_themed_page_in_the_language_of_the_visitor() {
    let app = TestApp::builder().build().await.unwrap();
    let rsvp = unknown_rsvp_token();
    let feed = unknown_feed_token();

    for (language, heading, lang) in [
        // The first language the theme ships wins: French is skipped, `de-AT` is German.
        ("fr, de-AT;q=0.9, en;q=0.5", "Dieser Link ist nicht gültig", "de"),
        ("en-GB, de;q=0.5", "This link is not valid", "en"),
        ("de", "Dieser Link ist nicht gültig", "de"),
    ] {
        let answers = [
            app.rsvp()
                .view(&rsvp)
                .header("accept-language", language)
                .send()
                .await
                .unwrap(),
            app.feed(&feed)
                .get()
                .header("accept-language", language)
                .send()
                .await
                .unwrap(),
        ];
        for answer in answers {
            let body = answer.text();
            assert_eq!(status(&answer), 404, "{language}: {}", answer.excerpt(120));
            assert!(body.contains(heading), "{language}: {body}");
            assert!(body.contains(&format!("lang=\"{lang}\"")), "{language}: {body}");
            assert_eq!(answer.header("content-type"), Some("text/html; charset=utf-8"));
            assert_eq!(answer.header("vary"), Some("Accept-Language"));
            assert_eq!(answer.header("cache-control"), Some("no-store"));
            assert!(
                answer
                    .header("content-security-policy")
                    .is_some_and(|policy| policy.contains("default-src 'none'")),
                "{language}"
            );
            // Nothing the request chose is in the page: no token, no path.
            assert!(
                !body.contains("uuuuuuuu") && !body.contains("/rsvp/") && !body.contains("/feeds/"),
                "{language}: {body}"
            );
        }
    }

    // A visitor who named no language, or none that the theme ships, gets the default language of the deployment.
    for language in [None, Some("fr, es;q=0.5")] {
        let mut request = app.rsvp().view(&rsvp);
        if let Some(language) = language {
            request = request.header("accept-language", language);
        }
        let answer = request.send().await.unwrap();
        assert_eq!(status(&answer), 404);
        assert!(
            answer.text().contains("This link is not valid"),
            "{language:?}: {}",
            answer.text()
        );
    }
}

#[tokio::test]
async fn every_failure_of_the_web_surface_is_a_page_of_the_theme_with_its_own_status() {
    let app = TestApp::builder().build().await.unwrap();
    // A token that cannot be one, and an answer to a link that is not valid, are the themed page as well.
    let unknown_path = app
        .rsvp()
        .view("x")
        .header("accept-language", "de")
        .send()
        .await
        .unwrap();
    assert_eq!(status(&unknown_path), 404);
    assert!(
        unknown_path.text().contains("Dieser Link ist nicht gültig"),
        "{}",
        unknown_path.text()
    );
    let answer_to_a_dead_link = app
        .rsvp()
        .answer(
            &unknown_rsvp_token(),
            "https://cal.example.org",
            &[("partstat", "ACCEPTED")],
        )
        .header("accept-language", "de")
        .send()
        .await
        .unwrap();
    assert!(
        answer_to_a_dead_link.text().contains("lang=\"de\""),
        "an answer to a link that is not valid is the themed page as well: {}",
        answer_to_a_dead_link.excerpt(200)
    );
    assert_ne!(status(&answer_to_a_dead_link), 200);
}
