//! The `TemplateRenderer` implementation.
//!
//! [`MiniJinjaRenderer`] renders the templates of the catalog from the loaded themes. A request names a template,
//! a locale, a theme and a JSON model; the renderer
//!
//! 1. finds the template files: the theme the request is rendered in is the requested theme, or the configured default
//!    theme when the requested one is not loaded ([`Themes::render_theme`]); locales are tried from the most specific to
//!    English ([`crate::locale::fallback_chain`]), and the files a theme lacks come from the themes it falls back to (see
//!    [`Themes`]: the configured default theme, `default` and the built-in theme), so a theme can bring only its layout;
//! 2. renders subject, HTML and text under strict undefined behavior with the model, plus the reserved variables
//!    `locale` (the locale of the files that were found), `theme` (the theme the request was rendered in), `now` (the
//!    time of the renderer's [`Clock`] in UTC: `date`, `time`, `zone` and `year`) and `year`;
//! 3. makes the subject a single line (control characters and runs of white space become one space) so that it can
//!    never carry a header break, and ends the text with one line break.
//!
//! [`EchoRenderer`] is the second selectable implementation: it renders nothing and returns the model, which is
//! what the tests of consumers want.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Datelike as _, Utc};
use davhaven_domain::Locale;
use davhaven_ports::{
    Clock, PluginError, PortError, PortLabel, RenderRequest, Rendered, TemplateName, TemplateRenderer, ThemeAsset,
    observe,
};
use minijinja::ErrorKind;
use minijinja::value::{Serde, Value};

use crate::catalog::Template;
use crate::config::{MiniJinjaConfig, PLUGIN, TemplatesConfig, is_valid_theme_name};
use crate::locale::fallback_chain_of;
use crate::theme::{BUILTIN_THEME, Part, ThemeFiles, Themes, builtin, read_dir};

/// The label of the adapter in metrics and spans.
const LABEL: PortLabel = PortLabel::new("templates", PLUGIN);

/// The longest subject the renderer returns, in characters.
const MAX_SUBJECT_CHARS: usize = 300;

/// The moment the checks at startup render with, the value of the reserved variables `now` and `year` there:
/// 2027-01-12T10:00:00Z.
const SAMPLE_NOW_TIMESTAMP: i64 = 1_799_748_000;

/// The moment the checks at startup render with.
pub(crate) fn sample_now() -> DateTime<Utc> {
    DateTime::from_timestamp(SAMPLE_NOW_TIMESTAMP, 0).unwrap_or_default()
}

/// A clock that stands at [`sample_now`]: the renderer that `davhaven config check` loads only to check the themes.
#[derive(Debug, Clone, Copy)]
struct SampleClock;

impl Clock for SampleClock {
    fn now(&self) -> DateTime<Utc> {
        sample_now()
    }
}

/// The clock of a renderer that only checks the themes and renders nothing for a reader.
pub(crate) fn sample_clock() -> Arc<dyn Clock> {
    Arc::new(SampleClock)
}

/// The reserved variable `now`: the moment in UTC in the form of the date objects of the models
/// (`{ "date": "2027-01-12", "time": "10:00", "zone": "UTC" }`, which `when()` formats), and its `year`.
fn now_value(now: DateTime<Utc>) -> serde_json::Value {
    serde_json::json!({
        "date": now.format("%Y-%m-%d").to_string(),
        "time": now.format("%H:%M").to_string(),
        "zone": "UTC",
        "year": now.year(),
    })
}

/// The template context: the model plus the reserved variables `locale`, `theme`, `now` and `year`.
///
/// # Errors
///
/// A description of the problem when the model is not a JSON object.
pub(crate) fn context(
    model: &serde_json::Value,
    locale: &str,
    theme: &str,
    now: DateTime<Utc>,
) -> Result<Value, String> {
    let serde_json::Value::Object(members) = model else {
        return Err("the model must be a JSON object".to_owned());
    };
    let mut members = members.clone();
    members.insert("locale".to_owned(), serde_json::Value::String(locale.to_owned()));
    members.insert("theme".to_owned(), serde_json::Value::String(theme.to_owned()));
    members.insert("now".to_owned(), now_value(now));
    members.insert("year".to_owned(), serde_json::Value::from(now.year()));
    Ok(Value::from(Serde(&members)))
}

/// A single-line subject: control characters and runs of white space collapse into one space, the ends are
/// trimmed and the length is capped.
pub fn single_line(text: &str) -> String {
    let mut out = String::with_capacity(text.len().min(MAX_SUBJECT_CHARS));
    let mut pending_space = false;
    for c in text.chars() {
        if c.is_whitespace() || c.is_control() {
            pending_space = !out.is_empty();
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        out.push(c);
        if out.chars().count() >= MAX_SUBJECT_CHARS {
            break;
        }
    }
    out
}

/// A plain text body: no trailing white space and exactly one final line break (nothing for an empty body).
fn tidy_text(text: &str) -> String {
    let trimmed = text.trim_end();
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("{trimmed}\n")
    }
}

/// Maps an engine error to a port error: a model that lacks a field or has the wrong type is the caller's
/// problem (`Invalid`), everything else is a broken theme (`Internal`). The text names the template and line but
/// never a model value (the environment runs without debug output).
fn map_error(error: &minijinja::Error) -> PortError {
    match error.kind() {
        ErrorKind::UndefinedError | ErrorKind::InvalidOperation => {
            PortError::invalid(format!("the model does not fit the template: {error}"))
        }
        ErrorKind::OutOfFuel => PortError::internal(format!("the template exceeded its render budget: {error}")),
        _ => PortError::internal(format!("the template failed: {error}")),
    }
}

/// The `TemplateRenderer` of the `minijinja` plugin.
pub struct MiniJinjaRenderer {
    themes: Themes,
    default_locale: Locale,
    clock: Arc<dyn Clock>,
}

impl core::fmt::Debug for MiniJinjaRenderer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MiniJinjaRenderer")
            .field("themes", &self.themes)
            .field("default_locale", &self.default_locale)
            .finish_non_exhaustive()
    }
}

impl MiniJinjaRenderer {
    /// Loads the built-in theme and the themes of the configured directories (later directories win) and checks
    /// them. The reserved variables `now` and `year` follow `clock`: the plugin passes the clock of the server, tests a
    /// `ManualClock`, so that nothing renders from the wall clock by default.
    ///
    /// # Errors
    ///
    /// [`PluginError::InvalidConfig`] for invalid configuration, unreadable or invalid theme files, themes that
    /// do not render, and a `default_theme` that is not loaded.
    pub fn new(
        templates: &TemplatesConfig,
        renderer: &MiniJinjaConfig,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, PluginError> {
        Self::load(templates, renderer, clock).map(|(renderer, _warnings)| renderer)
    }

    /// As [`new`](Self::new), and what the operator should be told although nothing is wrong enough to refuse: a theme
    /// directory that holds no theme (a volume that is not mounted looks like that).
    ///
    /// # Errors
    ///
    /// As [`new`](Self::new).
    pub fn load(
        templates: &TemplatesConfig,
        renderer: &MiniJinjaConfig,
        clock: Arc<dyn Clock>,
    ) -> Result<(Self, Vec<String>), PluginError> {
        templates.validate()?;
        renderer.validate()?;
        let mut themes = vec![builtin()];
        let mut warnings = Vec::new();
        for dir in &renderer.theme_dirs {
            let found = read_dir(dir).map_err(|error| PluginError::invalid_config(PLUGIN, error.to_string()))?;
            if found.is_empty() {
                warnings.push(format!(
                    "`plugin.minijinja.theme_dirs` names `{}`, which holds no theme (a theme is a subdirectory named with \
                     a-z, 0-9, - and _): is the volume mounted?",
                    dir.display()
                ));
            }
            themes.extend(found);
        }
        Self::from_themes(themes, templates, renderer.fuel, clock).map(|renderer| (renderer, warnings))
    }

    /// Loads the themes only to check them, as `davhaven config check` does: the clock stands still at the moment the
    /// sample models render with, and the renderer is not meant to render anything for a reader.
    ///
    /// # Errors
    ///
    /// As [`new`](Self::new).
    pub fn check(templates: &TemplatesConfig, renderer: &MiniJinjaConfig) -> Result<Vec<String>, PluginError> {
        Self::load(templates, renderer, sample_clock()).map(|(_renderer, warnings)| warnings)
    }

    /// Compiles ready-made themes (the first is replaced by later themes of the same name).
    ///
    /// # Errors
    ///
    /// As [`MiniJinjaRenderer::new`].
    pub fn from_themes(
        themes: Vec<ThemeFiles>,
        templates: &TemplatesConfig,
        fuel: u64,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, PluginError> {
        let themes = Themes::build(themes, &templates.default_theme, fuel)
            .map_err(|error| PluginError::invalid_config(PLUGIN, error.to_string()))?;
        if !themes.has_theme(&templates.default_theme) {
            let loaded: Vec<&str> = themes.theme_names().filter(|name| *name != BUILTIN_THEME).collect();
            return Err(PluginError::invalid_config(
                PLUGIN,
                format!(
                    "`default_theme` `{}` is not a loaded theme (loaded: {})",
                    templates.default_theme,
                    loaded.join(", ")
                ),
            ));
        }
        Ok(Self {
            themes,
            default_locale: templates.default_locale.clone(),
            clock,
        })
    }

    /// The loaded themes (the hidden built-in copy excluded).
    pub fn theme_names(&self) -> Vec<&str> {
        self.themes
            .theme_names()
            .filter(|name| *name != BUILTIN_THEME)
            .collect()
    }

    /// Renders a request synchronously.
    ///
    /// # Errors
    ///
    /// `Invalid` for unknown templates and models that do not fit, `Internal` for broken themes.
    pub fn render_now(&self, request: &RenderRequest) -> Result<Rendered, PortError> {
        self.render_in(request, core::slice::from_ref(&request.locale))
    }

    /// Renders a request synchronously for a visitor who named several languages, best first: the first one in which a theme
    /// of the request has the template wins, then the default locale (see [`crate::locale::fallback_chain_of`]). With no
    /// language named the request's own locale applies.
    ///
    /// # Errors
    ///
    /// As [`render_now`](Self::render_now).
    pub fn render_preferring_now(&self, request: &RenderRequest, preferred: &[Locale]) -> Result<Rendered, PortError> {
        if preferred.is_empty() {
            self.render_now(request)
        } else {
            self.render_in(request, preferred)
        }
    }

    fn render_in(&self, request: &RenderRequest, preferred: &[Locale]) -> Result<Rendered, PortError> {
        let template = Template::from_name(request.template.as_str())
            .ok_or_else(|| PortError::invalid("the template is not in the catalog"))?;
        let locales = fallback_chain_of(preferred, &self.default_locale);
        // The request is rendered in one theme; the themes it falls back to are part of it (see `Themes`).
        let resolved = self
            .themes
            .resolve(template, &locales, request.theme.as_str())
            .ok_or_else(|| PortError::internal("no theme provides the template"))?;
        let context =
            context(&request.model, resolved.locale, resolved.theme, self.clock.now()).map_err(PortError::invalid)?;
        let render = |part: Part| -> Result<String, PortError> {
            resolved.entry.part(part).map_or_else(
                || Ok(String::new()),
                |name| self.themes.render(name, &context).map_err(|error| map_error(&error)),
            )
        };
        Ok(Rendered {
            subject: single_line(&render(Part::Subject)?),
            html: render(Part::Html)?,
            text: tidy_text(&render(Part::Text)?),
        })
    }
}

#[async_trait]
impl TemplateRenderer for MiniJinjaRenderer {
    async fn render(&self, request: RenderRequest) -> Result<Rendered, PortError> {
        observe(LABEL, "render", async { self.render_now(&request) }).await
    }

    async fn render_preferring(&self, request: RenderRequest, preferred: &[Locale]) -> Result<Rendered, PortError> {
        observe(LABEL, "render", async {
            self.render_preferring_now(&request, preferred)
        })
        .await
    }

    fn catalog(&self) -> Vec<TemplateName> {
        catalog()
    }

    /// The asset of the theme, or of the first theme of its layers that has a file of that name (the same order
    /// templates fall back in), so a page that links `/assets/{theme}/page.css` finds a style sheet whichever theme it
    /// was rendered in.
    fn asset(&self, theme: &str, file: &str) -> Option<ThemeAsset> {
        if !is_valid_theme_name(theme) || !crate::assets::is_valid_name(file) {
            return None;
        }
        self.themes.asset(theme, file)
    }
}

/// The names of the catalog, sorted.
fn catalog() -> Vec<TemplateName> {
    Template::ALL.into_iter().map(Template::template_name).collect()
}

/// The `echo` implementation: returns the model instead of rendering.
#[derive(Debug, Clone, Copy, Default)]
pub struct EchoRenderer;

/// What `observe` labels the echo renderer with.
const ECHO_LABEL: PortLabel = PortLabel::new("templates", crate::plugin::ECHO);

#[async_trait]
impl TemplateRenderer for EchoRenderer {
    async fn render(&self, request: RenderRequest) -> Result<Rendered, PortError> {
        observe(ECHO_LABEL, "render", async {
            if Template::from_name(request.template.as_str()).is_none() {
                return Err(PortError::invalid("the template is not in the catalog"));
            }
            let json = serde_json::to_string_pretty(&request.model)
                .map_err(|_| PortError::invalid("the model is not JSON"))?;
            let html = format!("<pre>{}</pre>", minijinja::HtmlEscape(&json));
            Ok(Rendered {
                subject: format!("{} ({})", request.template, request.locale),
                html,
                text: format!("{json}\n"),
            })
        })
        .await
    }

    fn catalog(&self) -> Vec<TemplateName> {
        catalog()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use davhaven_ports::PortErrorKind;
    use serde_json::json;

    use super::*;
    use crate::catalog::Kind;

    /// The clock of the tests: it stands at 2027-01-01 until a test moves it.
    fn test_clock() -> Arc<dyn Clock> {
        Arc::new(davhaven_ports::testing::ManualClock::default())
    }

    fn renderer() -> MiniJinjaRenderer {
        MiniJinjaRenderer::new(&TemplatesConfig::default(), &MiniJinjaConfig::default(), test_clock()).unwrap()
    }

    fn request(template: Template, locale: &str, theme: &str, model: serde_json::Value) -> RenderRequest {
        RenderRequest {
            template: template.template_name(),
            locale: Locale::parse(locale).unwrap(),
            theme: theme.to_owned(),
            model,
        }
    }

    #[test]
    fn single_lines_never_carry_a_line_break() {
        assert_eq!(
            single_line("  Einladung:\r\nBcc: x@y.z\t\tteam  "),
            "Einladung: Bcc: x@y.z team"
        );
        assert_eq!(single_line("\n\n"), "");
        assert_eq!(single_line("a\u{0}b\u{85}c\u{2028}d"), "a b c d");
        assert_eq!(single_line(&"x".repeat(1000)).chars().count(), MAX_SUBJECT_CHARS);
        assert!(single_line("Müller & Söhne 日本語").contains("日本語"));
    }

    #[test]
    fn text_bodies_end_with_exactly_one_line_break() {
        assert_eq!(tidy_text("a\n\n\n"), "a\n");
        assert_eq!(tidy_text("a"), "a\n");
        assert_eq!(tidy_text(" \n"), "");
    }

    #[test]
    fn contexts_add_the_reserved_variables_and_refuse_other_models() {
        let now = DateTime::from_timestamp(1_799_748_000, 0).unwrap();
        let value = context(&json!({"a": 1, "locale": "x", "year": 1999}), "de", "default", now).unwrap();
        assert_eq!(
            value.get_attr("locale").unwrap().as_str(),
            Some("de"),
            "the renderer wins over the model"
        );
        assert_eq!(value.get_attr("theme").unwrap().as_str(), Some("default"));
        assert_eq!(value.get_attr("a").unwrap().as_i64(), Some(1));
        assert_eq!(
            value.get_attr("year").unwrap().as_i64(),
            Some(2027),
            "the renderer wins over the model"
        );
        let moment = value.get_attr("now").unwrap();
        for (key, expected) in [("date", "2027-01-12"), ("time", "10:00"), ("zone", "UTC")] {
            assert_eq!(moment.get_attr(key).unwrap().as_str(), Some(expected), "{key}");
        }
        assert_eq!(moment.get_attr("year").unwrap().as_i64(), Some(2027));
        for bad in [json!([1]), json!("text"), json!(null), json!(5)] {
            assert!(context(&bad, "en", "default", now).is_err());
        }
    }

    #[tokio::test]
    async fn every_template_renders_in_every_locale_with_every_sample_model() {
        let renderer = renderer();
        for template in Template::ALL {
            for locale in ["de", "en", "de-AT", "fr"] {
                for model in template.sample_models() {
                    let output = renderer
                        .render(request(template, locale, "default", model))
                        .await
                        .unwrap();
                    let context = format!("{template:?} in {locale}");
                    assert!(!output.subject.is_empty(), "{context}");
                    assert!(!output.subject.contains(['\r', '\n']), "{context}");
                    match template.kind() {
                        Kind::Mail => assert!(!output.html.is_empty() && !output.text.is_empty(), "{context}"),
                        Kind::Page => assert!(!output.html.is_empty() && output.text.is_empty(), "{context}"),
                        Kind::Snippet => assert!(output.html.is_empty() && output.text.is_empty(), "{context}"),
                    }
                }
            }
        }
    }

    /// The page of an unknown link for a visitor who ranked `preferred` (the best first).
    async fn page_for(renderer: &MiniJinjaRenderer, preferred: &[&str]) -> String {
        let preferred: Vec<Locale> = preferred.iter().map(|tag| Locale::parse(tag).unwrap()).collect();
        let best = preferred.first().cloned().unwrap_or_else(Locale::en);
        let asked = request(
            Template::RsvpUnavailable,
            best.as_str(),
            "default",
            json!({ "status": 404 }),
        );
        renderer.render_preferring(asked, &preferred).await.unwrap().html
    }

    #[tokio::test]
    async fn a_visitor_who_ranked_several_languages_gets_the_first_one_that_the_theme_ships() {
        let renderer = renderer();
        // The themes ship German and English: Spanish and French are skipped, the first language that exists wins.
        assert!(
            page_for(&renderer, &["fr", "es", "de-AT", "en"])
                .await
                .contains("lang=\"de\"")
        );
        assert!(page_for(&renderer, &["fr", "en", "de"]).await.contains("lang=\"en\""));
        // Nothing the theme ships: the default locale (English unless configured).
        assert!(page_for(&renderer, &["fr", "es"]).await.contains("lang=\"en\""));
        // No language named: the request's own locale applies.
        let own = renderer
            .render_preferring(
                request(Template::RsvpUnavailable, "de", "default", json!({ "status": 404 })),
                &[],
            )
            .await
            .unwrap();
        assert!(own.html.contains("lang=\"de\""), "{}", own.html);
        // A renderer that does not override the method still renders in the best language: the default is `render`.
        let echo = EchoRenderer
            .render_preferring(
                request(Template::RsvpUnavailable, "fr", "default", json!({ "status": 404 })),
                &[Locale::parse("de").unwrap()],
            )
            .await
            .unwrap();
        assert!(echo.subject.contains("(de)"), "{}", echo.subject);
    }

    #[tokio::test]
    async fn locales_fall_back_and_the_reserved_variable_names_the_locale_that_was_found() {
        let renderer = renderer();
        let german = renderer
            .render(request(Template::FeedBusy, "de-AT", "default", json!({})))
            .await
            .unwrap();
        assert_eq!(german.subject, "Beschäftigt");
        let english = renderer
            .render(request(Template::FeedBusy, "en-GB", "default", json!({})))
            .await
            .unwrap();
        assert_eq!(english.subject, "Busy");
        let french = renderer
            .render(request(Template::FeedBusy, "fr", "default", json!({})))
            .await
            .unwrap();
        assert_eq!(french.subject, "Busy", "unsupported languages fall back to English");
        let defaults = MiniJinjaRenderer::new(
            &TemplatesConfig {
                default_locale: Locale::de(),
                ..TemplatesConfig::default()
            },
            &MiniJinjaConfig::default(),
            test_clock(),
        )
        .unwrap();
        let fallback = defaults
            .render(request(Template::FeedBusy, "fr", "default", json!({})))
            .await
            .unwrap();
        assert_eq!(
            fallback.subject, "Beschäftigt",
            "the configured default locale comes before English"
        );
        let page = renderer
            .render(request(
                Template::RsvpUnavailable,
                "de",
                "default",
                json!({ "status": 404 }),
            ))
            .await
            .unwrap();
        assert!(page.html.contains("lang=\"de\""), "{}", page.html);
    }

    #[tokio::test]
    async fn unknown_themes_fall_back_to_the_default_theme() {
        let renderer = renderer();
        for theme in ["", "corporate", "../../etc", "@builtin", "Default"] {
            let output = renderer
                .render(request(Template::FeedBusy, "en", theme, json!({})))
                .await
                .unwrap();
            assert_eq!(output.subject, "Busy", "{theme}");
        }
        assert_eq!(renderer.theme_names(), vec!["default"]);
    }

    #[tokio::test]
    async fn a_request_without_a_theme_is_rendered_in_the_configured_default_theme() {
        let corporate = crate::theme::ThemeFiles {
            name: "corporate".to_owned(),
            origin: "test".to_owned(),
            files: std::collections::BTreeMap::from([("feed_busy.en.subject".to_owned(), "Corporate busy".to_owned())]),
            assets: std::collections::BTreeMap::new(),
        };
        let templates = TemplatesConfig {
            default_theme: "corporate".to_owned(),
            ..TemplatesConfig::default()
        };
        let renderer = MiniJinjaRenderer::from_themes(
            vec![builtin(), corporate],
            &templates,
            MiniJinjaConfig::default().fuel,
            test_clock(),
        )
        .unwrap();
        // The tenant names no theme (the empty name), or one that is not loaded: the deployment's default theme.
        for theme in ["", "not-loaded"] {
            let output = renderer
                .render(request(Template::FeedBusy, "en", theme, json!({})))
                .await
                .unwrap();
            assert_eq!(output.subject, "Corporate busy", "{theme:?}");
        }
        // A tenant that names the theme `default` keeps it, whatever the deployment chose as its default.
        let named = renderer
            .render(request(Template::FeedBusy, "en", "default", json!({})))
            .await
            .unwrap();
        assert_eq!(named.subject, "Busy");
    }

    fn theme(name: &str, files: &[(&str, &str)]) -> ThemeFiles {
        ThemeFiles {
            name: name.to_owned(),
            origin: "test".to_owned(),
            files: files
                .iter()
                .map(|(file, source)| ((*file).to_owned(), (*source).to_owned()))
                .collect(),
            assets: std::collections::BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn now_and_the_year_follow_the_clock_of_the_renderer() {
        let corporate = theme(
            "corporate",
            &[(
                "feed_busy.en.subject",
                "Busy {{ year }} {{ now.date }} {{ now.time }} {{ now.zone }}",
            )],
        );
        let clock = davhaven_ports::testing::ManualClock::default();
        let renderer = MiniJinjaRenderer::from_themes(
            vec![builtin(), corporate],
            &TemplatesConfig::default(),
            200_000,
            Arc::new(clock.clone()),
        )
        .unwrap();
        let subject = |renderer: &MiniJinjaRenderer| {
            renderer
                .render_now(&request(Template::FeedBusy, "en", "corporate", json!({})))
                .unwrap()
                .subject
        };
        assert_eq!(subject(&renderer), "Busy 2027 2027-01-01 00:00 UTC");
        clock.advance(chrono::Duration::days(366) + chrono::Duration::hours(13));
        assert_eq!(
            subject(&renderer),
            "Busy 2028 2028-01-02 13:00 UTC",
            "the year of the footer follows the clock and not the build"
        );
    }

    #[tokio::test]
    async fn a_theme_with_only_its_layout_renders_the_default_content_and_links_its_own_style_sheet() {
        let mut corporate = theme(
            "corporate",
            &[
                (
                    "_page.html",
                    "<!doctype html><html lang=\"{{ locale }}\"><head><title>{% block title %}{% endblock %}</title>\
                     <link rel=\"stylesheet\" href=\"/assets/{{ theme }}/page.css\"></head>\
                     <body class=\"corporate\"><main>{% block content %}{% endblock %}</main>\
                     <footer>(c) {{ year }}</footer></body></html>",
                ),
                (
                    "_mail.html",
                    "<body class=\"corporate\">{% block content %}{% endblock %}</body>",
                ),
            ],
        );
        corporate.assets.insert(
            "page.css".to_owned(),
            crate::assets::asset("text/css; charset=utf-8", b"body{color:#123}".to_vec()),
        );
        let templates = TemplatesConfig {
            default_theme: "corporate".to_owned(),
            ..TemplatesConfig::default()
        };
        let renderer =
            MiniJinjaRenderer::from_themes(vec![builtin(), corporate], &templates, 200_000, test_clock()).unwrap();
        // A tenant without a theme follows the deployment's default theme.
        let page = renderer
            .render_now(&request(
                Template::RsvpPage,
                "en",
                "",
                Template::RsvpPage.sample_model(),
            ))
            .unwrap();
        assert!(page.html.contains("class=\"corporate\""), "{}", page.html);
        assert!(page.html.contains("/assets/corporate/page.css"), "{}", page.html);
        assert!(
            page.html.contains("(c) 2027"),
            "the year is the one of the injected clock: {}",
            page.html
        );
        assert!(
            page.html.contains("<form method=\"post\""),
            "the content is the default's: {}",
            page.html
        );
        let sheet = renderer.asset("corporate", "page.css").unwrap();
        assert_eq!(
            sheet.body.as_ref(),
            b"body{color:#123}",
            "the theme's own style sheet is the one that is served"
        );
        let mail = renderer
            .render_now(&request(
                Template::ImipRequest,
                "de",
                "corporate",
                Template::ImipRequest.sample_model(),
            ))
            .unwrap();
        assert!(mail.html.contains("class=\"corporate\""), "{}", mail.html);
        assert!(
            mail.text.contains("Gesendet von"),
            "the text mail needs no layout: {}",
            mail.text
        );
    }

    #[test]
    fn a_theme_directory_that_holds_no_theme_is_reported_and_not_refused() {
        let root = std::env::temp_dir().join(format!("davhaven-renderer-empty-{}", std::process::id()));
        drop(std::fs::remove_dir_all(&root));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("README.md"), "no themes here").unwrap();
        let (renderer, warnings) = MiniJinjaRenderer::load(
            &TemplatesConfig::default(),
            &MiniJinjaConfig {
                theme_dirs: vec![root.clone()],
                ..MiniJinjaConfig::default()
            },
            test_clock(),
        )
        .unwrap();
        assert_eq!(renderer.theme_names(), vec!["default"]);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].contains("theme_dirs") && warnings[0].contains("holds no theme"),
            "{warnings:?}"
        );
        drop(std::fs::remove_dir_all(&root));
    }

    #[tokio::test]
    async fn missing_fields_and_unknown_templates_are_invalid_not_empty() {
        let renderer = renderer();
        let missing = renderer
            .render(request(
                Template::ImipRequest,
                "en",
                "default",
                json!({"tenant": {"name": "x"}}),
            ))
            .await
            .unwrap_err();
        assert_eq!(missing.kind, PortErrorKind::Invalid, "{missing}");
        let not_an_object = renderer
            .render(request(Template::ImipRequest, "en", "default", json!([])))
            .await
            .unwrap_err();
        assert_eq!(not_an_object.kind, PortErrorKind::Invalid);
        let unknown = RenderRequest {
            template: TemplateName::parse("no_such_template").unwrap(),
            locale: Locale::en(),
            theme: "default".to_owned(),
            model: json!({}),
        };
        assert_eq!(renderer.render(unknown).await.unwrap_err().kind, PortErrorKind::Invalid);
        let wrong_type = {
            let mut model = Template::ImipRequest.sample_model();
            model["event"]["start"]["date"] = json!("12.01.2027");
            renderer
                .render(request(Template::ImipRequest, "en", "default", model))
                .await
                .unwrap_err()
        };
        assert_eq!(wrong_type.kind, PortErrorKind::Invalid, "{wrong_type}");
        assert!(!missing.message.contains("Example"), "{}", missing.message);
    }

    #[test]
    fn a_model_that_makes_a_theme_run_past_its_budget_fails_the_render_instead_of_hanging_it() {
        // A theme whose work grows with the model passes the checks at startup (the sample model is small) and
        // must still not let a large model keep a worker busy: the fuel stops it, and the failure is the theme's.
        let heavy = theme(
            "heavy",
            &[(
                "feed_busy.en.subject",
                "{% for item in items|default([]) %}{% for n in range(1000) %}{% endfor %}{% endfor %}Busy",
            )],
        );
        let renderer = MiniJinjaRenderer::from_themes(
            vec![builtin(), heavy],
            &TemplatesConfig::default(),
            200_000,
            test_clock(),
        )
        .unwrap();
        let small = renderer
            .render_now(&request(Template::FeedBusy, "en", "heavy", json!({"items": [1]})))
            .unwrap();
        assert_eq!(small.subject, "Busy");
        let error = renderer
            .render_now(&request(
                Template::FeedBusy,
                "en",
                "heavy",
                json!({"items": vec![1; 1000]}),
            ))
            .unwrap_err();
        assert_eq!(error.kind, PortErrorKind::Internal, "{error}");
        assert!(error.message.contains("render budget"), "{error}");
    }

    #[tokio::test]
    async fn user_text_is_escaped_in_html_and_left_alone_in_text() {
        let renderer = renderer();
        let output = renderer
            .render(request(
                Template::ImipRequest,
                "en",
                "default",
                Template::ImipRequest.sample_model(),
            ))
            .await
            .unwrap();
        assert!(
            output.html.contains("Planning &lt;session&gt; &amp; coffee"),
            "{}",
            output.html
        );
        assert!(!output.html.contains("<session>"));
        assert!(output.text.contains("Planning <session> & coffee"), "{}", output.text);
        assert_eq!(output.subject, "Invitation: Planning <session> & coffee");
        assert!(
            output.html.contains("Agenda:<br>"),
            "descriptions keep their line breaks: {}",
            output.html
        );
    }

    #[tokio::test]
    async fn a_hostile_subject_cannot_break_the_header() {
        let renderer = renderer();
        let mut model = Template::ImipRequest.sample_model();
        model["event"]["summary"] = json!("Lunch\r\nBcc: evil@example.net\r\n\r\nbody");
        let output = renderer
            .render(request(Template::ImipRequest, "en", "default", model))
            .await
            .unwrap();
        assert!(!output.subject.contains(['\r', '\n']), "{:?}", output.subject);
        assert!(davhaven_domain::HeaderText::parse(&output.subject).is_ok());
    }

    #[tokio::test]
    async fn rendering_is_deterministic() {
        let renderer = renderer();
        let first = renderer
            .render(request(
                Template::ImipRequest,
                "de",
                "default",
                Template::ImipRequest.sample_model(),
            ))
            .await
            .unwrap();
        let second = renderer
            .render(request(
                Template::ImipRequest,
                "de",
                "default",
                Template::ImipRequest.sample_model(),
            ))
            .await
            .unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn the_default_theme_must_be_loaded() {
        let error = MiniJinjaRenderer::new(
            &TemplatesConfig {
                default_theme: "corporate".to_owned(),
                ..TemplatesConfig::default()
            },
            &MiniJinjaConfig::default(),
            test_clock(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("default_theme") && error.contains("corporate") && error.contains("loaded: default"),
            "{error}"
        );
    }

    #[test]
    fn the_catalog_lists_every_template_sorted() {
        let names: Vec<String> = renderer().catalog().iter().map(ToString::to_string).collect();
        assert_eq!(
            names,
            vec![
                "feed_busy",
                "imip_cancel",
                "imip_reply",
                "imip_request",
                "oauth_result",
                "rsvp_answered",
                "rsvp_page",
                "rsvp_unavailable"
            ]
        );
    }

    #[tokio::test]
    async fn the_echo_renderer_returns_the_model() {
        let echo = EchoRenderer;
        let output = echo
            .render(request(
                Template::OauthResult,
                "de",
                "any",
                json!({"success": true, "note": "<b>"}),
            ))
            .await
            .unwrap();
        assert_eq!(output.subject, "oauth_result (de)");
        assert!(output.text.contains("\"success\": true"), "{}", output.text);
        assert!(output.html.contains("&lt;b&gt;"), "{}", output.html);
        let unknown = RenderRequest {
            template: TemplateName::parse("nope").unwrap(),
            locale: Locale::en(),
            theme: String::new(),
            model: json!({}),
        };
        assert_eq!(echo.render(unknown).await.unwrap_err().kind, PortErrorKind::Invalid);
        assert_eq!(echo.catalog().len(), Template::ALL.len());
    }

    #[tokio::test]
    async fn both_implementations_satisfy_the_template_contract() {
        davhaven_port_tests::templates::run_all(|| Arc::new(renderer())).await;
        davhaven_port_tests::templates::run_all(|| Arc::new(EchoRenderer)).await;
    }

    #[test]
    fn assets_come_from_the_theme_and_fall_back_to_the_built_in_ones() {
        let renderer = renderer();
        let sheet = renderer.asset("default", "page.css").unwrap();
        assert_eq!(sheet.content_type, "text/css; charset=utf-8");
        assert_eq!(
            renderer.asset("no-such-theme", "page.css"),
            Some(sheet),
            "an unknown theme gets the built-in sheet"
        );
        assert!(renderer.asset("default", "other.css").is_none());
        for (theme, file) in [("Default", "page.css"), ("..", "page.css"), ("default", "../page.css")] {
            assert!(renderer.asset(theme, file).is_none(), "{theme} / {file}");
        }
        assert!(
            EchoRenderer.asset("default", "page.css").is_none(),
            "the echo renderer has no assets"
        );
    }
}
