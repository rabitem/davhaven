//! The configuration of the `eicar` scanner: none.

use schemars::JsonSchema;
use serde::Deserialize;

/// The name of the plugin (`plugins.content_scanners = ["eicar"]`).
pub const PLUGIN: &str = "eicar";

/// The `[plugin.content_scanner.eicar]` table: it has no keys, and a typo in it is still an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct EicarConfig {}
