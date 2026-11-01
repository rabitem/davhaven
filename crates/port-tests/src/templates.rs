//! Contract suite of the `TemplateRenderer` port.
//!
//! What every renderer promises: the catalog is sorted and free of duplicates; a template outside the catalog is
//! `Invalid`; a model that does not fit a template is `Invalid` (never `Internal`, which is a broken theme, and
//! never silently rendered with holes); the subject is a single line, so that it can never carry a header break;
//! rendering is deterministic; an unknown theme or locale is no error by itself, because the renderer falls
//! back; and an empty theme name, which is what a tenant without a theme of its own asks for, means the default theme of
//! the renderer. The suite renders every template of the catalog with an empty model, which no real template fits, so it
//! needs no knowledge of the models; the models themselves are tested by the adapter. Assets (`asset`) are optional,
//! but no renderer resolves a name that could leave the theme.

use std::sync::Arc;

use davhaven_domain::Locale;
use davhaven_ports::{PortErrorKind, RenderRequest, TemplateName, TemplateRenderer};

use crate::suite::{Checks, ContractReport, Suite};

fn request(template: &TemplateName, locale: &str, theme: &str) -> Option<RenderRequest> {
    Some(RenderRequest {
        template: template.clone(),
        locale: Locale::parse(locale).ok()?,
        theme: theme.to_owned(),
        model: serde_json::json!({}),
    })
}

/// `RenderRequest::theme` is empty when the tenant names no theme. The renderer then uses its own default theme, which is
/// what it also uses for a name it has not loaded, so the two must render the same (or fail the same).
async fn empty_theme_means_the_default(renderer: &dyn TemplateRenderer, catalog: &[TemplateName]) -> Checks {
    let mut checks = Checks::new("an empty theme name means the default theme of the renderer");
    for name in catalog {
        let (Some(empty), Some(unknown)) = (request(name, "en", ""), request(name, "en", "no-such-theme")) else {
            checks.fail("the suite could not build a request");
            continue;
        };
        let empty = renderer.render(empty).await;
        let unknown = renderer.render(unknown).await;
        checks.equal(
            &empty,
            &unknown,
            &format!("`{name}` rendered with no theme and with a theme that is not loaded"),
        );
    }
    checks
}

/// Runs the suite against renderers built by `factory` and returns the report.
pub async fn run<F>(factory: F) -> ContractReport
where
    F: Fn() -> Arc<dyn TemplateRenderer>,
{
    let mut suite = Suite::new("templates");
    let renderer = factory();
    let catalog = renderer.catalog();

    let mut checks = Checks::new("the catalog is sorted, unique and not empty");
    checks.that(!catalog.is_empty(), "the catalog lists templates");
    let mut sorted = catalog.clone();
    sorted.sort();
    sorted.dedup();
    checks.equal(&catalog, &sorted, "the catalog");
    checks.equal(&renderer.catalog(), &catalog, "the catalog of a second call");
    suite.record(checks);

    let mut checks = Checks::new("a template outside the catalog is invalid");
    match TemplateName::parse("definitely_not_a_template")
        .ok()
        .and_then(|name| request(&name, "en", "default"))
    {
        Some(unknown) => {
            if let Some(error) = checks.err(renderer.render(unknown).await, "rendering an unknown template") {
                checks.equal(&error.kind, &PortErrorKind::Invalid, "the error kind");
            }
        }
        None => checks.fail("the suite could not build a request"),
    }
    suite.record(checks);

    let mut checks = Checks::new("a model that fits no template is invalid, never internal");
    for name in &catalog {
        let Some(outbound) = request(name, "en", "default") else {
            checks.fail("the suite could not build a request");
            continue;
        };
        match renderer.render(outbound).await {
            Ok(output) => {
                checks.that(
                    !output.subject.contains(['\r', '\n']) && !output.subject.chars().any(char::is_control),
                    &format!("the subject of `{name}` is a single line without control characters"),
                );
            }
            Err(error) => checks.equal(
                &error.kind,
                &PortErrorKind::Invalid,
                &format!("the error kind of `{name}`"),
            ),
        }
    }
    suite.record(checks);

    let mut checks = Checks::new("rendering is deterministic");
    for name in &catalog {
        let (Some(first), Some(second)) = (request(name, "en", "default"), request(name, "en", "default")) else {
            checks.fail("the suite could not build a request");
            continue;
        };
        let first = renderer.render(first).await;
        let second = renderer.render(second).await;
        checks.equal(&first, &second, &format!("two renderings of `{name}`"));
    }
    suite.record(checks);

    let mut checks = Checks::new("unknown themes and locales fall back instead of failing");
    for name in &catalog {
        let (Some(known), Some(unknown)) = (request(name, "en", "default"), request(name, "xx-YY", "no-such-theme"))
        else {
            checks.fail("the suite could not build a request");
            continue;
        };
        let known = renderer.render(known).await;
        let unknown = renderer.render(unknown).await;
        checks.equal(
            &known.as_ref().map(|_| ()).map_err(|error| error.kind),
            &unknown.as_ref().map(|_| ()).map_err(|error| error.kind),
            &format!("the outcome of `{name}` with an unknown theme and locale"),
        );
    }
    suite.record(checks);

    suite.record(empty_theme_means_the_default(renderer.as_ref(), &catalog).await);

    let mut checks = Checks::new("assets never resolve names that are no plain file names");
    for (theme, file) in [
        ("default", ""),
        ("default", ".."),
        ("default", "../page.css"),
        ("default", "sub/page.css"),
        ("default", "..\\page.css"),
        ("..", "page.css"),
        ("default/..", "page.css"),
        ("", "page.css"),
        ("default", "no-such-file-anywhere.css"),
    ] {
        checks.that(
            renderer.asset(theme, file).is_none(),
            &format!("the asset `{theme}` / `{file}` does not exist"),
        );
    }
    suite.record(checks);

    suite.finish()
}

/// Runs the suite and fails the running test when any case fails.
///
/// # Panics
///
/// When a case fails.
pub async fn run_all<F>(factory: F)
where
    F: Fn() -> Arc<dyn TemplateRenderer>,
{
    run(factory).await.assert_ok();
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use davhaven_ports::{PortError, Rendered};

    use super::*;

    /// A renderer with one template `greeting` that fits only models with a `name`.
    struct Greeting {
        names: Vec<&'static str>,
        subject: &'static str,
        accept_unknown: bool,
        requires_name: bool,
    }

    impl Greeting {
        fn good() -> Self {
            Self {
                names: vec!["greeting"],
                subject: "Hello",
                accept_unknown: false,
                requires_name: true,
            }
        }
    }

    #[async_trait]
    impl TemplateRenderer for Greeting {
        async fn render(&self, request: RenderRequest) -> Result<Rendered, PortError> {
            if !self.accept_unknown && !self.names.contains(&request.template.as_str()) {
                return Err(PortError::invalid("unknown template"));
            }
            if self.requires_name && request.model.get("name").is_none() {
                return Err(PortError::invalid("the model lacks `name`"));
            }
            Ok(Rendered {
                subject: self.subject.to_owned(),
                html: String::new(),
                text: String::new(),
            })
        }

        fn catalog(&self) -> Vec<TemplateName> {
            self.names
                .iter()
                .filter_map(|name| TemplateName::parse(name).ok())
                .collect()
        }
    }

    /// Fails with the wrong error kind for a model that does not fit.
    struct Broken;

    #[async_trait]
    impl TemplateRenderer for Broken {
        async fn render(&self, request: RenderRequest) -> Result<Rendered, PortError> {
            if request.template.as_str() == "greeting" {
                Err(PortError::internal("theme is broken"))
            } else {
                Err(PortError::invalid("unknown template"))
            }
        }

        fn catalog(&self) -> Vec<TemplateName> {
            TemplateName::parse("greeting").into_iter().collect()
        }
    }

    #[tokio::test]
    async fn a_well_behaved_renderer_satisfies_the_contract() {
        run_all(|| Arc::new(Greeting::good())).await;
        assert_eq!(run(|| Arc::new(Greeting::good())).await.case_count(), 7);
    }

    #[tokio::test]
    async fn an_unsorted_catalog_is_caught() {
        let report = run(|| {
            Arc::new(Greeting {
                names: vec!["b_template", "a_template"],
                ..Greeting::good()
            })
        })
        .await;
        assert_eq!(
            report.failed_cases(),
            vec!["the catalog is sorted, unique and not empty"],
            "{report}"
        );
    }

    #[tokio::test]
    async fn accepting_unknown_templates_is_caught() {
        let report = run(|| {
            Arc::new(Greeting {
                accept_unknown: true,
                requires_name: false,
                ..Greeting::good()
            })
        })
        .await;
        assert_eq!(
            report.failed_cases(),
            vec!["a template outside the catalog is invalid"],
            "{report}"
        );
    }

    #[tokio::test]
    async fn subjects_with_line_breaks_are_caught() {
        let report = run(|| {
            Arc::new(Greeting {
                subject: "Hello\r\nBcc: evil@example.net",
                requires_name: false,
                ..Greeting::good()
            })
        })
        .await;
        assert_eq!(
            report.failed_cases(),
            vec!["a model that fits no template is invalid, never internal"],
            "{report}"
        );
    }

    /// A renderer that takes an empty theme name literally instead of as the default theme.
    struct Literal(Greeting);

    #[async_trait]
    impl TemplateRenderer for Literal {
        async fn render(&self, request: RenderRequest) -> Result<Rendered, PortError> {
            let no_theme = request.theme.is_empty();
            let mut rendered = self.0.render(request).await?;
            if no_theme {
                "a theme without a name".clone_into(&mut rendered.subject);
            }
            Ok(rendered)
        }

        fn catalog(&self) -> Vec<TemplateName> {
            self.0.catalog()
        }
    }

    #[tokio::test]
    async fn an_empty_theme_that_does_not_mean_the_default_is_caught() {
        let report = run(|| {
            Arc::new(Literal(Greeting {
                requires_name: false,
                ..Greeting::good()
            }))
        })
        .await;
        assert_eq!(
            report.failed_cases(),
            vec!["an empty theme name means the default theme of the renderer"],
            "{report}"
        );
    }

    /// A renderer that answers every asset request, whatever the name.
    struct Careless(Greeting);

    #[async_trait]
    impl TemplateRenderer for Careless {
        async fn render(&self, request: RenderRequest) -> Result<Rendered, PortError> {
            self.0.render(request).await
        }

        fn catalog(&self) -> Vec<TemplateName> {
            self.0.catalog()
        }

        fn asset(&self, _theme: &str, _file: &str) -> Option<davhaven_ports::ThemeAsset> {
            Some(davhaven_ports::ThemeAsset {
                content_type: "text/css",
                body: bytes::Bytes::from_static(b"x"),
                etag: davhaven_domain::ETag::from_bytes(b"x"),
            })
        }
    }

    #[tokio::test]
    async fn resolving_names_that_could_leave_the_theme_is_caught() {
        let report = run(|| Arc::new(Careless(Greeting::good()))).await;
        assert_eq!(
            report.failed_cases(),
            vec!["assets never resolve names that are no plain file names"],
            "{report}"
        );
    }

    #[tokio::test]
    async fn internal_errors_for_bad_models_are_caught() {
        let report = run(|| Arc::new(Broken)).await;
        assert_eq!(
            report.failed_cases(),
            vec!["a model that fits no template is invalid, never internal"],
            "{report}"
        );
    }
}
