//! Configuration of the renderer and theme directories.
//!
//! Two tables: `[templates]` holds the defaults the renderer falls back to (`default_theme`, `default_locale`),
//! `[plugin.minijinja]` configures the renderer itself (theme directories that override the built-in theme and the
//! render budget).

use std::path::PathBuf;

use davhaven_domain::Locale;
use davhaven_ports::PluginError;
use schemars::JsonSchema;
use serde::Deserialize;

/// The name of the plugin.
pub const PLUGIN: &str = "minijinja";

/// The `[templates]` table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct TemplatesConfig {
    /// The theme used when a tenant names none or names one that does not exist.
    pub default_theme: String,
    /// The locale used when neither the recipient nor the tenant has one (de and en ship with the server).
    pub default_locale: Locale,
}

impl Default for TemplatesConfig {
    fn default() -> Self {
        Self {
            default_theme: "default".to_owned(),
            default_locale: Locale::en(),
        }
    }
}

/// Whether `theme` is a valid theme name: 1 to 64 characters of `a-z`, `0-9`, `-` and `_` (the rule of the tenant
/// settings).
pub fn is_valid_theme_name(theme: &str) -> bool {
    !theme.is_empty()
        && theme.len() <= 64
        && theme
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

impl TemplatesConfig {
    /// Checks the theme name.
    ///
    /// # Errors
    ///
    /// [`PluginError::InvalidConfig`] for an invalid `default_theme`.
    pub fn validate(&self) -> Result<(), PluginError> {
        if is_valid_theme_name(&self.default_theme) {
            Ok(())
        } else {
            Err(PluginError::invalid_config(
                PLUGIN,
                "`default_theme` must be 1 to 64 characters of a-z, 0-9, - and _",
            ))
        }
    }
}

/// The `[plugin.minijinja]` table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct MiniJinjaConfig {
    /// Directories with themes (`{dir}/{theme}/{template}.{locale}.…`); a theme found here replaces the
    /// built-in theme of the same name. Later directories win.
    pub theme_dirs: Vec<PathBuf>,
    /// The most instructions one template render may take (`minijinja` fuel); a template that exceeds it fails.
    pub fuel: u64,
}

impl Default for MiniJinjaConfig {
    fn default() -> Self {
        Self {
            theme_dirs: Vec::new(),
            fuel: 200_000,
        }
    }
}

impl MiniJinjaConfig {
    /// Checks the render budget.
    ///
    /// # Errors
    ///
    /// [`PluginError::InvalidConfig`] for `fuel = 0`.
    pub fn validate(&self) -> Result<(), PluginError> {
        if self.fuel == 0 {
            return Err(PluginError::invalid_config(PLUGIN, "`fuel` must be greater than zero"));
        }
        Ok(())
    }
}

/// The keys of `[templates]`.
const TEMPLATES_KEYS: [&str; 2] = ["default_theme", "default_locale"];

/// Everything the `minijinja` plugin is configured with: the keys of `[plugin.minijinja]` (`theme_dirs`, `fuel`)
/// and the keys of `[templates]` (`default_theme`, `default_locale`), which the server passes along in the same
/// table because a plugin is built from one value.
///
/// This type documents the combined table (the generated configuration reference lists it); the plugin reads the
/// two parts with their own structs ([`split_plugin_table`]) so that every typo is still reported by key.
#[derive(Debug, Clone, JsonSchema)]
pub struct MiniJinjaPluginConfig {
    /// The renderer's own keys.
    #[serde(flatten)]
    pub renderer: MiniJinjaConfig,
    /// The defaults the renderer falls back to.
    #[serde(flatten)]
    pub templates: TemplatesConfig,
}

/// Splits the table of the plugin into the part of `[templates]` and the part of `[plugin.minijinja]`.
///
/// Keys that belong to neither stay in the second part, where `MiniJinjaConfig` refuses them by name. A table that
/// is not an object is returned as the second part unchanged (and refused there).
pub fn split_plugin_table(value: serde_json::Value) -> (serde_json::Value, serde_json::Value) {
    let serde_json::Value::Object(members) = value else {
        return (serde_json::Value::Object(serde_json::Map::new()), value);
    };
    let (templates, renderer): (serde_json::Map<_, _>, serde_json::Map<_, _>) = members
        .into_iter()
        .partition(|(key, _)| TEMPLATES_KEYS.contains(&key.as_str()));
    (
        serde_json::Value::Object(templates),
        serde_json::Value::Object(renderer),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_plugin_table_splits_into_its_two_parts() {
        let (templates, renderer) = split_plugin_table(serde_json::json!({
            "default_theme": "corporate",
            "theme_dirs": ["/etc/davhaven/themes"],
            "default_locale": "de",
            "fuel": 1000,
            "typo": true,
        }));
        assert_eq!(
            templates,
            serde_json::json!({"default_theme": "corporate", "default_locale": "de"})
        );
        assert_eq!(
            renderer,
            serde_json::json!({"theme_dirs": ["/etc/davhaven/themes"], "fuel": 1000, "typo": true})
        );
        let parsed: TemplatesConfig = davhaven_ports::parse_config(PLUGIN, templates).unwrap();
        assert_eq!(parsed.default_theme, "corporate");
        assert!(
            davhaven_ports::parse_config::<MiniJinjaConfig>(PLUGIN, renderer).is_err(),
            "the typo stays visible"
        );
        let (none, whole) = split_plugin_table(serde_json::Value::Null);
        assert_eq!((none, whole), (serde_json::json!({}), serde_json::Value::Null));
        let (_, scalar) = split_plugin_table(serde_json::json!("text"));
        assert!(davhaven_ports::parse_config::<MiniJinjaConfig>(PLUGIN, scalar).is_err());
    }

    #[test]
    fn the_combined_table_has_a_schema_with_all_four_keys() {
        let schema = schemars::schema_for!(MiniJinjaPluginConfig);
        let properties = schema.as_value()["properties"].as_object().unwrap().clone();
        for key in ["theme_dirs", "fuel", "default_theme", "default_locale"] {
            assert!(properties.contains_key(key), "{key}");
        }
    }

    #[test]
    fn defaults_match_the_plan() {
        let templates: TemplatesConfig = davhaven_ports::parse_config(PLUGIN, serde_json::json!({})).unwrap();
        assert_eq!(templates.default_theme, "default");
        assert_eq!(templates.default_locale.as_str(), "en");
        templates.validate().unwrap();
        let renderer: MiniJinjaConfig = davhaven_ports::parse_config(PLUGIN, serde_json::json!({})).unwrap();
        assert_eq!(renderer.theme_dirs.len(), 0);
        renderer.validate().unwrap();
    }

    #[test]
    fn keys_parse_and_typos_are_refused() {
        let templates: TemplatesConfig = davhaven_ports::parse_config(
            PLUGIN,
            serde_json::json!({"default_theme": "corporate", "default_locale": "de-DE"}),
        )
        .unwrap();
        assert_eq!(templates.default_locale.as_str(), "de-DE");
        assert!(
            davhaven_ports::parse_config::<TemplatesConfig>(
                PLUGIN,
                serde_json::json!({"default_locale": "not a locale"})
            )
            .is_err()
        );
        assert!(davhaven_ports::parse_config::<TemplatesConfig>(PLUGIN, serde_json::json!({"theme": "x"})).is_err());
        let renderer: MiniJinjaConfig =
            davhaven_ports::parse_config(PLUGIN, serde_json::json!({"theme_dirs": ["/etc/davhaven/themes"]})).unwrap();
        assert_eq!(renderer.theme_dirs, vec![PathBuf::from("/etc/davhaven/themes")]);
    }

    #[test]
    fn theme_names_follow_the_tenant_rule() {
        for good in ["default", "corporate-2", "a_b"] {
            assert!(is_valid_theme_name(good), "{good}");
        }
        for bad in ["", "Upper", "with space", "slash/dir", &"a".repeat(65)] {
            assert!(!is_valid_theme_name(bad), "{bad}");
        }
        let broken = TemplatesConfig {
            default_theme: "../etc".to_owned(),
            ..TemplatesConfig::default()
        };
        assert!(broken.validate().unwrap_err().to_string().contains("default_theme"));
        let no_fuel = MiniJinjaConfig {
            fuel: 0,
            ..MiniJinjaConfig::default()
        };
        assert!(no_fuel.validate().unwrap_err().to_string().contains("fuel"));
    }
}
