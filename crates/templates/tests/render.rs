//! Every template × locale × theme renders under strict undefined behavior (`ENGINEERING_RULES` R15), the output is
//! snapshot-tested, and the pages of the default theme keep their accessibility promises (WCAG 2.1 AA: language,
//! landmarks, labelled controls, no scripts, contrast of the built-in colors).

#![expect(
    clippy::unwrap_used,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

use davhaven_domain::Locale;
use std::sync::Arc;

use davhaven_ports::testing::ManualClock;
use davhaven_ports::{RenderRequest, Rendered};
use davhaven_templates::catalog::{Kind, Template};
use davhaven_templates::config::{MiniJinjaConfig, TemplatesConfig};
use davhaven_templates::renderer::MiniJinjaRenderer;
use serde_json::Value;

const LOCALES: [&str; 2] = ["de", "en"];

fn engine() -> MiniJinjaRenderer {
    MiniJinjaRenderer::new(
        &TemplatesConfig::default(),
        &MiniJinjaConfig::default(),
        Arc::new(ManualClock::default()),
    )
    .unwrap()
}

fn render(engine: &MiniJinjaRenderer, template: Template, locale: &str, model: Value) -> Rendered {
    engine
        .render_now(&RenderRequest {
            template: template.template_name(),
            locale: Locale::parse(locale).unwrap(),
            theme: "default".to_owned(),
            model,
        })
        .unwrap()
}

fn show(output: &Rendered) -> String {
    format!(
        "subject: {}\n\n--- html ---\n{}\n--- text ---\n{}",
        output.subject, output.html, output.text
    )
}

#[test]
fn the_output_of_every_template_in_every_locale_is_reviewed() {
    let engine = engine();
    for template in Template::ALL {
        for locale in LOCALES {
            let output = render(&engine, template, locale, template.sample_model());
            insta::assert_snapshot!(format!("{}_{locale}", template.name()), show(&output));
        }
    }
}

#[test]
fn the_variants_of_the_models_are_reviewed_for_the_mails() {
    let engine = engine();
    let update = Template::ImipRequest.sample_models().swap_remove(1);
    let bare = Template::ImipRequest.sample_models().swap_remove(2);
    for locale in LOCALES {
        insta::assert_snapshot!(
            format!("imip_request_update_{locale}"),
            show(&render(&engine, Template::ImipRequest, locale, update.clone()))
        );
        insta::assert_snapshot!(
            format!("imip_request_bare_{locale}"),
            show(&render(&engine, Template::ImipRequest, locale, bare.clone()))
        );
        for (index, name) in [(1, "declined"), (2, "tentative"), (3, "bare")] {
            let model = Template::ImipReply.sample_models().swap_remove(index);
            insta::assert_snapshot!(
                format!("imip_reply_{name}_{locale}"),
                show(&render(&engine, Template::ImipReply, locale, model))
            );
        }
    }
}

#[test]
fn every_variant_of_every_model_renders_in_every_locale() {
    let engine = engine();
    for template in Template::ALL {
        for locale in ["de", "en", "de-AT", "en-GB", "fr", "ja"] {
            for model in template.sample_models() {
                let output = render(&engine, template, locale, model);
                assert!(!output.subject.is_empty(), "{template:?} {locale}");
            }
        }
    }
}

#[test]
fn mails_carry_no_scripts_and_no_remote_content() {
    let engine = engine();
    for template in Template::ALL
        .into_iter()
        .filter(|template| template.kind() == Kind::Mail)
    {
        for locale in LOCALES {
            for model in template.sample_models() {
                let output = render(&engine, template, locale, model);
                let html = output.html.to_ascii_lowercase();
                for forbidden in ["<script", "javascript:", "<img", "<iframe", "<link", "@import", "src="] {
                    assert!(!html.contains(forbidden), "{template:?} {locale}: {forbidden}");
                }
                assert!(html.contains("lang=\""), "{template:?} {locale}");
                assert!(html.contains("<title>"), "{template:?} {locale}");
                assert!(
                    !output.text.contains("<p") && !output.text.contains("<td"),
                    "plain text without markup"
                );
            }
        }
    }
}

#[test]
fn pages_work_without_javascript_and_load_nothing_from_outside() {
    let engine = engine();
    for template in Template::ALL
        .into_iter()
        .filter(|template| template.kind() == Kind::Page)
    {
        for locale in LOCALES {
            for model in template.sample_models() {
                let output = render(&engine, template, locale, model);
                let html = output.html.to_ascii_lowercase();
                for forbidden in [
                    "<script",
                    "javascript:",
                    " onclick",
                    " onload",
                    "<iframe",
                    "<style",
                    " style=",
                    "@import",
                    "http://",
                    "https://",
                ] {
                    assert!(!html.contains(forbidden), "{template:?} {locale}: {forbidden}\n{html}");
                }
                assert!(html.starts_with("<!doctype html>"), "{template:?} {locale}");
                assert!(
                    html.contains(&format!("<html lang=\"{locale}\">")),
                    "{template:?} {locale}"
                );
                assert!(
                    html.contains("<title>") && !html.contains("<title></title>"),
                    "{template:?} {locale}"
                );
                // The page CSP allows styles from the own origin only: the one link is the theme's style sheet.
                assert_eq!(
                    html.matches("<link").count(),
                    1,
                    "{template:?} {locale}: one style sheet"
                );
                assert!(
                    html.contains("<link rel=\"stylesheet\" href=\"/assets/default/page.css\">"),
                    "{template:?} {locale}"
                );
                assert_eq!(html.matches("<main>").count(), 1, "one main landmark");
                assert_eq!(html.matches("<h1>").count(), 1, "one top-level heading");
                assert!(html.contains("name=\"viewport\""), "responsive");
            }
        }
    }
}

#[test]
fn the_rsvp_form_is_labelled_and_posts_the_documented_fields() {
    let engine = engine();
    for locale in LOCALES {
        let output = render(&engine, Template::RsvpPage, locale, Template::RsvpPage.sample_model());
        let html = output.html;
        assert!(
            html.contains("<form method=\"post\" action=\"/rsvp/dvh_rsvp_token\">"),
            "{html}"
        );
        assert!(html.contains("<input type=\"hidden\" name=\"csrf\" value=\"csrf-token\">"));
        assert!(html.contains("<label for=\"comment\">") && html.contains("id=\"comment\" name=\"comment\""));
        assert!(html.contains("maxlength=\"500\""));
        for answer in ["ACCEPTED", "TENTATIVE", "DECLINED"] {
            assert!(
                html.contains(&format!("name=\"partstat\" value=\"{answer}\"")),
                "{answer}"
            );
        }
        assert!(
            html.contains("role=\"group\" aria-label="),
            "the buttons form a labelled group"
        );
        let cancelled = render(
            &engine,
            Template::RsvpPage,
            locale,
            Template::RsvpPage.sample_models().swap_remove(1),
        );
        assert!(!cancelled.html.contains("<form"), "a cancelled event offers no form");
        assert!(cancelled.html.contains("role=\"status\""));
        let failed = render(
            &engine,
            Template::RsvpPage,
            locale,
            Template::RsvpPage.sample_models().swap_remove(5),
        );
        assert!(failed.html.contains("role=\"alert\""), "errors are announced");
    }
}

#[test]
fn the_page_texts_of_the_default_theme_are_written_for_both_languages() {
    let engine = engine();
    for template in [
        Template::RsvpPage,
        Template::RsvpAnswered,
        Template::RsvpUnavailable,
        Template::OauthResult,
    ] {
        let german = render(&engine, template, "de", template.sample_model());
        let english = render(&engine, template, "en", template.sample_model());
        assert_ne!(german.html, english.html, "{template:?}");
        if template != Template::RsvpPage {
            // The title of the RSVP page is the summary of the event, which no language changes.
            assert_ne!(german.subject, english.subject, "{template:?}");
        }
    }
}

#[test]
fn the_page_of_a_link_that_cannot_be_served_says_what_to_do_by_the_status_of_the_failure() {
    let engine = engine();
    for (locale, expected) in [
        (
            "de",
            [
                "Dieser Link ist nicht gültig",
                "Zu viele Anfragen",
                "Vorübergehend nicht verfügbar",
                "konnte nicht verarbeitet werden",
            ],
        ),
        (
            "en",
            [
                "This link is not valid",
                "Too many requests",
                "Temporarily not available",
                "could not be processed",
            ],
        ),
    ] {
        for (status, heading) in [404, 429, 503, 422].into_iter().zip(expected) {
            let page = render(
                &engine,
                Template::RsvpUnavailable,
                locale,
                serde_json::json!({ "status": status }),
            );
            assert!(page.html.contains(heading), "{locale} {status}: {}", page.html);
            assert!(page.html.contains(&format!("lang=\"{locale}\"")), "{locale} {status}");
            assert!(page.html.contains("<main>"), "one main landmark: {locale} {status}");
            assert_eq!(page.html.matches("<h1>").count(), 1, "one heading: {locale} {status}");
            assert!(
                !page.subject.is_empty() && !page.subject.contains('{'),
                "{locale} {status}: {}",
                page.subject
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Contrast of the built-in colors (WCAG 2.1 AA: 4.5:1 for text)
// ---------------------------------------------------------------------------------------------------------------

const PAGE_STYLES: &str = include_str!("../themes/default/assets/page.css");

fn channel(value: u8) -> f64 {
    let c = f64::from(value) / 255.0;
    if c <= 0.039_28 {
        c / 12.92
    } else {
        ((c + 0.055) / 1.055).powf(2.4)
    }
}

fn luminance(hex: &str) -> f64 {
    let digits = hex.trim_start_matches('#');
    let value = |range: std::ops::Range<usize>| u8::from_str_radix(digits.get(range).unwrap(), 16).unwrap();
    0.2126 * channel(value(0..2)) + 0.7152 * channel(value(2..4)) + 0.0722 * channel(value(4..6))
}

fn contrast(a: &str, b: &str) -> f64 {
    let (la, lb) = (luminance(a), luminance(b));
    (la.max(lb) + 0.05) / (la.min(lb) + 0.05)
}

/// The custom properties declared in a `:root{...}` block of the layout's style sheet.
fn palette(block: &str) -> std::collections::BTreeMap<String, String> {
    block
        .split(';')
        .filter_map(|declaration| {
            let (name, value) = declaration.split_once(':')?;
            let name = name.trim().strip_prefix("--")?;
            Some((name.to_owned(), value.trim().to_owned()))
        })
        .filter(|(_, value)| value.starts_with('#'))
        .collect()
}

#[test]
fn the_colors_of_the_default_theme_meet_wcag_aa_in_light_and_dark() {
    let light_block = PAGE_STYLES.split(":root{").nth(1).unwrap().split('}').next().unwrap();
    let dark_block = PAGE_STYLES
        .split("(prefers-color-scheme:dark){:root{")
        .nth(1)
        .unwrap()
        .split('}')
        .next()
        .unwrap();
    for (scheme, block) in [("light", light_block), ("dark", dark_block)] {
        let colors = palette(block);
        for (foreground, background) in [
            ("text", "bg"),
            ("text", "card"),
            ("muted", "bg"),
            ("muted", "card"),
            ("accent", "card"),
            ("accent", "bg"),
            ("accent-text", "accent"),
            ("danger", "card"),
        ] {
            let ratio = contrast(&colors[foreground], &colors[background]);
            assert!(ratio >= 4.5, "{scheme}: {foreground} on {background} is {ratio:.2}:1");
        }
        // The focus ring uses the text color and must be visible against the card as well (3:1 for components).
        assert!(contrast(&colors["text"], &colors["card"]) >= 3.0);
    }
}

#[test]
fn the_contrast_arithmetic_matches_the_wcag_reference_values() {
    assert!((contrast("#000000", "#ffffff") - 21.0).abs() < 0.01);
    assert!((contrast("#777777", "#ffffff") - 4.48).abs() < 0.02);
    assert!((contrast("#ffffff", "#ffffff") - 1.0).abs() < 1e-9);
}
