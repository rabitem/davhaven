//! The configuration of the `fake` provider: none.

use schemars::JsonSchema;
use serde::Deserialize;

/// The `[plugin.provider.fake]` table: it has no keys, and a typo in it is still an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct FakeConfig {}
