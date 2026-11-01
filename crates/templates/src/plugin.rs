//! Registration of the adapter in the plugin registry.
//!
//! Two plugins of the `templates` kind: `minijinja` (the renderer with themes) and `echo` (returns the model;
//! for tests of consumers). `echo` is refused in production mode: it would put the data of events and the names of
//! attendees into mails as JSON (`ENGINEERING_RULES` R3, PLAN 2.3).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use davhaven_ports::{
    Built, PluginCheck, PluginContext, PluginDescriptor, PluginError, PluginRegistry, PortKind, TemplateRenderer,
    parse_config,
};
use schemars::Schema;
use serde::Deserialize;

use crate::config::{MiniJinjaConfig, MiniJinjaPluginConfig, PLUGIN, TemplatesConfig, split_plugin_table};
use crate::renderer::{EchoRenderer, MiniJinjaRenderer};

/// The name of the `echo` plugin.
pub const ECHO: &str = "echo";

/// The `[plugin.echo]` table: it has no keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct EchoConfig {}

/// The future a plugin build returns.
type Building = Pin<Box<dyn Future<Output = Result<Built<dyn TemplateRenderer>, PluginError>> + Send>>;

/// Registers the `minijinja` and `echo` plugins.
///
/// # Errors
///
/// [`PluginError::DuplicateName`] when the registry has them already.
pub fn register(registry: &mut PluginRegistry) -> Result<(), PluginError> {
    registry.register(
        PortKind::TEMPLATES,
        PluginDescriptor::new(
            PLUGIN,
            "Renders mail and page templates with MiniJinja under strict undefined behavior and auto-escaping; German \
             and English default theme, themes are directories that bring only what they change.",
            minijinja_schema,
            build_minijinja,
        )
        .with_dedicated_table(TABLE)
        .with_check(check_minijinja),
    )?;
    registry.register(
        PortKind::TEMPLATES,
        PluginDescriptor::new(
            ECHO,
            "Renders nothing: returns the model as JSON. For tests of consumers; refused in production mode.",
            echo_schema,
            build_echo,
        )
        // It would put the data of events and the names of attendees into mails as JSON.
        .with_refused_in_production()
        .with_check(check_echo),
    )
}

/// The dedicated table of the `minijinja` renderer besides `[plugin.templates.minijinja]` (PLAN F0.9): the theme and
/// locale defaults.
pub const TABLE: &str = "templates";

/// The table of the `minijinja` renderer as its two configurations, the theme and locale defaults and the plugin's own
/// keys: the one reading that `build` and the check of `davhaven config check` share, so that the check says what
/// `serve` will say. Loading the renderer validates them.
fn config(table: serde_json::Value) -> Result<(TemplatesConfig, MiniJinjaConfig), PluginError> {
    let (templates, renderer) = split_plugin_table(table);
    let templates: TemplatesConfig = parse_config(PLUGIN, templates)?;
    let renderer: MiniJinjaConfig = parse_config(PLUGIN, renderer)?;
    Ok((templates, renderer))
}

/// The check of `davhaven config check`: the table parses and validates as `build` would have it, and **the themes are
/// loaded**: the theme directories are read, every file is compiled, every template of every theme is rendered with the
/// sample models, the layouts are asked whether they keep the content, and `default_theme` must be one of the loaded
/// themes. A broken template or a theme that does not exist fails here and not at the first mail.
///
/// # Errors
///
/// [`PluginError::InvalidConfig`] naming the key, the theme or the file.
fn check_minijinja(check: &PluginCheck<'_>) -> Result<Vec<String>, PluginError> {
    let (templates, renderer) = config(check.table.clone())?;
    MiniJinjaRenderer::check(&templates, &renderer)
}

/// The check of `davhaven config check` for `echo`: the table has no keys, and a typo in it names the key.
///
/// # Errors
///
/// [`PluginError::InvalidConfig`] naming the key.
fn check_echo(check: &PluginCheck<'_>) -> Result<Vec<String>, PluginError> {
    parse_config::<EchoConfig>(ECHO, check.table.clone())?;
    Ok(Vec::new())
}

fn minijinja_schema() -> Schema {
    schemars::schema_for!(MiniJinjaPluginConfig)
}

fn echo_schema() -> Schema {
    schemars::schema_for!(EchoConfig)
}

fn build_minijinja(context: PluginContext, table: serde_json::Value) -> Building {
    Box::pin(async move {
        let (templates, renderer) = config(table)?;
        // The reserved variables `now` and `year` come from the clock of the server.
        let clock = Arc::clone(&context.clock);
        // Reading and compiling themes is blocking work; it happens once at startup.
        let built = tokio::task::spawn_blocking(move || MiniJinjaRenderer::new(&templates, &renderer, clock))
            .await
            .map_err(|_| PluginError::invalid_config(PLUGIN, "loading the themes was interrupted"))??;
        let port: Arc<dyn TemplateRenderer> = Arc::new(built);
        Ok(Built::new(port))
    })
}

fn build_echo(_context: PluginContext, table: serde_json::Value) -> Building {
    Box::pin(async move {
        let _config: EchoConfig = parse_config(ECHO, table)?;
        let port: Arc<dyn TemplateRenderer> = Arc::new(EchoRenderer);
        Ok(Built::new(port))
    })
}

#[cfg(test)]
mod tests {
    use davhaven_ports::ConfigTree;
    use serde_json::json;

    use super::*;

    fn registry() -> PluginRegistry {
        let mut registry = PluginRegistry::new();
        register(&mut registry).unwrap();
        registry
    }

    async fn build_with(name: &str, config: serde_json::Value) -> Result<Built<dyn TemplateRenderer>, PluginError> {
        let tree = ConfigTree::new().with(name, config);
        registry()
            .build_single(PortKind::TEMPLATES, name, &PluginContext::for_tests(), &tree)
            .await
    }

    #[test]
    fn both_plugins_are_registered_with_their_schemas() {
        let mut registry = registry();
        assert_eq!(registry.names(PortKind::TEMPLATES), vec!["echo", "minijinja"]);
        assert!(matches!(
            register(&mut registry),
            Err(PluginError::DuplicateName { .. })
        ));
        let schemas = registry.schemas();
        let minijinja = schemas.iter().find(|schema| schema.name == "minijinja").unwrap();
        for key in ["theme_dirs", "fuel", "default_theme", "default_locale"] {
            assert!(minijinja.schema.as_value()["properties"].get(key).is_some(), "{key}");
        }
    }

    #[tokio::test]
    async fn the_echo_renderer_is_refused_in_production() {
        use davhaven_ports::RunMode;
        use davhaven_ports::testing::{FixedHasher, FixedKeyRing, ManualClock, PlainSealer, SeqIds};

        let production = PluginContext::new(
            Arc::new(ManualClock::default()),
            Arc::new(SeqIds::new()),
            Arc::new(FixedKeyRing::default()),
            Arc::new(PlainSealer),
            Arc::new(FixedHasher::default()),
            RunMode::Production,
        );
        let tree = ConfigTree::new().with("echo", json!({}));
        let error = registry()
            .build_single(PortKind::TEMPLATES, "echo", &production, &tree)
            .await
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(error.contains("production"), "{error}");
        assert!(registry().refused_in_production("templates", "echo"));
        assert!(!registry().refused_in_production("templates", "minijinja"));
        let tree = ConfigTree::new().with("minijinja", json!({}));
        registry()
            .build_single(PortKind::TEMPLATES, "minijinja", &production, &tree)
            .await
            .expect("the real renderer runs in production");
    }

    /// What `davhaven config check` says about a table, from the check the descriptor carries.
    fn checked(table: &serde_json::Value) -> Result<Vec<String>, PluginError> {
        registry()
            .check_table("templates", "minijinja", table, davhaven_ports::RunMode::Production)
            .expect("the renderer has a check of its own")
    }

    #[test]
    fn the_descriptor_names_its_table_and_the_check_loads_the_themes() {
        let registry = registry();
        assert_eq!(registry.dedicated_table("templates", "minijinja"), Some("templates"));
        assert_eq!(registry.dedicated_table("templates", "echo"), None);
        assert_eq!(checked(&json!({})).unwrap(), Vec::<String>::new());
        assert_eq!(
            checked(&json!({"default_locale": "de", "fuel": 50_000})).unwrap(),
            Vec::<String>::new()
        );

        // A theme that does not exist is refused by the check and not only by the build.
        let error = checked(&json!({"default_theme": "corporate"})).unwrap_err().to_string();
        assert!(
            error.contains("default_theme") && error.contains("corporate"),
            "{error}"
        );
        for (table, key) in [
            (json!({"fuel": 0}), "fuel"),
            (json!({"default_theme": "Not Valid"}), "default_theme"),
            (json!({"theme_dir": ["/x"]}), "theme_dir"),
            (json!({"theme_dirs": ["/nonexistent/davhaven-themes"]}), "nonexistent"),
        ] {
            let error = checked(&table).unwrap_err().to_string();
            assert!(error.contains(key), "{key}: {error}");
        }
    }

    #[test]
    fn the_check_of_the_echo_renderer_accepts_the_defaults_and_names_a_typo() {
        for table in [serde_json::Value::Null, json!({})] {
            let verdict = registry()
                .check_table("templates", "echo", &table, davhaven_ports::RunMode::Dev)
                .expect("the echo renderer has a check of its own")
                .unwrap();
            assert!(verdict.is_empty(), "{verdict:?}");
        }
        let error = registry()
            .check_table(
                "templates",
                "echo",
                &json!({"pretty": true}),
                davhaven_ports::RunMode::Dev,
            )
            .expect("the echo renderer has a check of its own")
            .unwrap_err()
            .to_string();
        assert!(error.contains("pretty") && error.contains("echo"), "{error}");
    }

    #[test]
    fn a_layout_that_drops_the_content_fails_the_check_with_theme_and_layout() {
        let root = std::env::temp_dir().join(format!("davhaven-templates-layout-{}", std::process::id()));
        drop(std::fs::remove_dir_all(&root));
        let theme = root.join("corporate");
        std::fs::create_dir_all(&theme).unwrap();
        std::fs::write(theme.join("_mail.html"), "<body>no blocks</body>").unwrap();
        let error = checked(&json!({"theme_dirs": [&root], "default_theme": "corporate"}))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("corporate") && error.contains("_mail.html") && error.contains("content"),
            "{error}"
        );
        // The same layout with its content block is accepted.
        std::fs::write(
            theme.join("_mail.html"),
            "<body>{% block content %}{% endblock %}</body>",
        )
        .unwrap();
        assert_eq!(
            checked(&json!({"theme_dirs": [&root], "default_theme": "corporate"})).unwrap(),
            Vec::<String>::new()
        );
        drop(std::fs::remove_dir_all(&root));
    }

    #[test]
    fn a_broken_template_of_a_theme_directory_fails_the_check_with_theme_and_file() {
        let root = std::env::temp_dir().join(format!("davhaven-templates-check-{}", std::process::id()));
        drop(std::fs::remove_dir_all(&root));
        let theme = root.join("corporate");
        std::fs::create_dir_all(&theme).unwrap();
        std::fs::write(theme.join("feed_busy.en.subject"), "Occupied {% if %}").unwrap();
        let error = checked(&json!({"theme_dirs": [&root], "default_theme": "corporate"}))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("corporate") && error.contains("feed_busy.en.subject") && error.contains("does not compile"),
            "{error}"
        );

        // A template that compiles but uses what the application does not provide fails when it is rendered.
        std::fs::write(theme.join("feed_busy.en.subject"), "{{ tenant.name }}").unwrap();
        let error = checked(&json!({"theme_dirs": [&root]})).unwrap_err().to_string();
        assert!(
            error.contains("corporate") && error.contains("does not render"),
            "{error}"
        );

        // The theme as it should be: accepted, and the theme is the default theme the table names.
        std::fs::write(theme.join("feed_busy.en.subject"), "Occupied").unwrap();
        assert_eq!(
            checked(&json!({"theme_dirs": [&root], "default_theme": "corporate"})).unwrap(),
            Vec::<String>::new()
        );
        drop(std::fs::remove_dir_all(&root));
    }

    #[tokio::test]
    async fn the_built_renderer_uses_the_clock_of_the_server_for_now_and_the_year() {
        use davhaven_ports::testing::ManualClock;

        let root = std::env::temp_dir().join(format!("davhaven-templates-clock-{}", std::process::id()));
        drop(std::fs::remove_dir_all(&root));
        let theme = root.join("corporate");
        std::fs::create_dir_all(&theme).unwrap();
        std::fs::write(theme.join("feed_busy.en.subject"), "Busy {{ year }}").unwrap();
        let clock = ManualClock::default();
        let mut context = PluginContext::for_tests();
        context.clock = Arc::new(clock.clone());
        let tree = ConfigTree::new().with("minijinja", json!({"theme_dirs": [&root]}));
        let built = registry()
            .build_single(PortKind::TEMPLATES, "minijinja", &context, &tree)
            .await
            .unwrap();
        let request = davhaven_ports::RenderRequest {
            template: crate::catalog::Template::FeedBusy.template_name(),
            locale: davhaven_domain::Locale::en(),
            theme: "corporate".to_owned(),
            model: json!({}),
        };
        assert_eq!(built.port.render(request.clone()).await.unwrap().subject, "Busy 2027");
        clock.advance(chrono::Duration::days(400));
        assert_eq!(built.port.render(request).await.unwrap().subject, "Busy 2028");
        drop(std::fs::remove_dir_all(&root));
    }

    #[tokio::test]
    async fn the_defaults_build_and_render() {
        for name in ["minijinja", "echo"] {
            let built = build_with(name, json!({})).await.unwrap();
            assert!(built.workers.is_empty() && built.lifecycle.is_none());
            assert_eq!(built.port.catalog().len(), 8);
        }
    }

    #[tokio::test]
    async fn the_combined_table_is_split_validated_and_typos_are_named() {
        build_with("minijinja", json!({"default_locale": "de", "fuel": 50_000}))
            .await
            .unwrap();
        for (config, key) in [
            (json!({"fuel": 0}), "fuel"),
            (json!({"default_theme": "Not Valid"}), "default_theme"),
            (json!({"default_theme": "corporate"}), "corporate"),
            (json!({"theme_dir": ["/x"]}), "theme_dir"),
            (json!({"default_locale": "not a locale"}), "BCP 47"),
            (json!({"theme_dirs": ["/nonexistent/davhaven-themes"]}), "nonexistent"),
        ] {
            let error = build_with("minijinja", config)
                .await
                .map(|_| ())
                .unwrap_err()
                .to_string();
            assert!(error.contains(key), "{key}: {error}");
        }
        assert!(build_with("echo", json!({"x": 1})).await.map(|_| ()).is_err());
    }

    #[tokio::test]
    async fn theme_directories_extend_the_catalog_of_themes() {
        let root = std::env::temp_dir().join(format!("davhaven-templates-plugin-{}", std::process::id()));
        drop(std::fs::remove_dir_all(&root));
        let theme = root.join("corporate");
        std::fs::create_dir_all(theme.join("assets")).unwrap();
        std::fs::write(theme.join("feed_busy.en.subject"), "Occupied").unwrap();
        std::fs::write(theme.join("assets").join("logo.svg"), "<svg/>").unwrap();
        let built = build_with("minijinja", json!({"theme_dirs": [root], "default_theme": "corporate"}))
            .await
            .unwrap();
        let request = davhaven_ports::RenderRequest {
            template: crate::catalog::Template::FeedBusy.template_name(),
            locale: davhaven_domain::Locale::en(),
            theme: "corporate".to_owned(),
            model: json!({}),
        };
        assert_eq!(built.port.render(request.clone()).await.unwrap().subject, "Occupied");
        let logo = built.port.asset("corporate", "logo.svg").unwrap();
        assert_eq!(
            (logo.content_type, logo.body.as_ref()),
            ("image/svg+xml", b"<svg/>".as_slice())
        );
        assert!(
            built.port.asset("corporate", "page.css").is_some(),
            "the built-in sheet is the fallback"
        );
        let german = davhaven_ports::RenderRequest {
            locale: davhaven_domain::Locale::de(),
            ..request
        };
        assert_eq!(
            built.port.render(german).await.unwrap().subject,
            "Beschäftigt",
            "templates a theme lacks come from the built-in theme"
        );
        drop(std::fs::remove_dir_all(&root));
    }
}
