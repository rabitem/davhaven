//! The generated configuration reference (`docs/configuration.md`).
//!
//! [`configuration_reference`] renders the reference from the JSON Schemas of the configuration structures: the
//! `Config` of this crate (and with it the tables owned by the crates the server always uses) and the schema every
//! registered plugin publishes for its table. The text is committed as `docs/configuration.md`;
//! `cargo xtask config-docs --check` fails when the committed file differs from what the code generates, so the
//! reference cannot drift from the code (R3). The introductory sections are written here, next to the code that
//! implements what they describe.

use std::fmt::Write as _;

use davhaven_ports::PluginRegistry;
use davhaven_ports::plugin::KINDS;
use schemars::Schema;
use serde_json::Value;

use crate::config::{Config, ENV_PREFIX};
use crate::schema::{is_table, properties, resolve};

/// One key of a table.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Row {
    key: String,
    kind: String,
    default: String,
    description: String,
}

/// The type of a key in words.
fn describe_type(schema: &Value, defs: &Value) -> String {
    let schema = resolve(schema, defs);
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        return one_of(values.iter().filter_map(Value::as_str));
    }
    if let Some(variants) = schema.get("oneOf").and_then(Value::as_array) {
        let names: Vec<&str> = variants
            .iter()
            .filter_map(|variant| variant.get("const").and_then(Value::as_str))
            .collect();
        if names.len() == variants.len() && !names.is_empty() {
            return one_of(names.into_iter());
        }
    }
    if let Some(options) = schema.get("anyOf").and_then(Value::as_array) {
        let inner: Vec<&Value> = options
            .iter()
            .filter(|option| option.get("type").and_then(Value::as_str) != Some("null"))
            .collect();
        if let [only] = inner.as_slice()
            && inner.len() < options.len()
        {
            return format!("{}, optional", describe_type(only, defs));
        }
    }
    match schema.get("type") {
        Some(Value::String(name)) => simple_type(name, schema, defs),
        Some(Value::Array(names)) => {
            let names: Vec<&str> = names.iter().filter_map(Value::as_str).collect();
            let main: Vec<&str> = names.iter().copied().filter(|name| *name != "null").collect();
            let text = main
                .first()
                .map_or_else(|| "any".to_owned(), |name| simple_type(name, schema, defs));
            if names.contains(&"null") {
                format!("{text}, optional")
            } else {
                text
            }
        }
        _ => "any".to_owned(),
    }
}

fn simple_type(name: &str, schema: &Value, defs: &Value) -> String {
    match name {
        "array" => {
            let item = schema
                .get("items")
                .map_or_else(|| "any".to_owned(), |items| describe_type(items, defs));
            format!("list of {item}")
        }
        "object" => "table".to_owned(),
        other => other.to_owned(),
    }
}

fn one_of<'a>(values: impl Iterator<Item = &'a str>) -> String {
    let quoted: Vec<String> = values.map(|value| format!("`\"{value}\"`")).collect();
    format!("one of {}", quoted.join(", "))
}

/// A default value as it is written in a configuration file.
fn describe_default(schema: &Value) -> String {
    match schema.get("default") {
        None => "-".to_owned(),
        Some(Value::String(text)) if text.is_empty() => "`\"\"`".to_owned(),
        Some(Value::String(text)) => format!("`\"{text}\"`"),
        Some(Value::Array(items)) if items.is_empty() => "`[]`".to_owned(),
        Some(Value::Null) => "unset".to_owned(),
        Some(other) => format!("`{other}`"),
    }
}

/// A description on one line, safe inside a table cell.
fn cell(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace('|', "\\|")
}

/// The rows of a table: one per key, tables inside tables flattened into dotted keys.
fn rows(schema: &Value, defs: &Value, prefix: &str, out: &mut Vec<Row>) {
    for (key, sub) in properties(schema, defs) {
        let resolved = resolve(sub, defs);
        let name = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        if is_table(resolved, defs) && resolved.get("type").and_then(Value::as_str) == Some("object") {
            rows(resolved, defs, &name, out);
        } else {
            let description = sub
                .get("description")
                .or_else(|| resolved.get("description"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            out.push(Row {
                key: name,
                kind: describe_type(sub, defs),
                default: if sub.get("default").is_some() {
                    describe_default(sub)
                } else {
                    describe_default(resolved)
                },
                description: cell(description),
            });
        }
    }
}

/// Renders rows as a Markdown table.
fn render_rows(rows: &[Row], out: &mut String) {
    out.push_str("| Key | Type | Default | Description |\n| --- | --- | --- | --- |\n");
    for row in rows {
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | {} |",
            row.key,
            cell(&row.kind),
            cell(&row.default),
            row.description
        );
    }
    out.push('\n');
}

/// Renders the keys of a schema as a Markdown table.
fn table(schema: &Schema, out: &mut String) {
    let root = schema.as_value();
    let defs = root.get("$defs").unwrap_or(&Value::Null);
    let mut collected = Vec::new();
    rows(root, defs, "", &mut collected);
    if collected.is_empty() {
        out.push_str("This table has no keys.\n\n");
        return;
    }
    render_rows(&collected, out);
}

/// The description of a table of `Config`.
fn section_note(name: &str) -> Option<&'static str> {
    match name {
        "database" => Some("The table of the `postgres` plugin; see [Plugins](#plugins), kind `database`."),
        "templates" => Some("Defaults of the `minijinja` plugin; see [Plugins](#plugins), kind `templates`."),
        "webhooks" => {
            Some("The table of the `webhook` outbox handler; see [Plugins](#plugins), kind `outbox_handler`.")
        }
        "plugin" => Some(
            "`[plugin.<kind>.<name>]`: the table of the adapter called `<name>` of the kind `<kind>` (`[plugin.<name>]` when \
             the name is selected for one kind only); its keys are listed per adapter under [Plugins](#plugins).",
        ),
        "providers" => Some(
            "`[providers.google]` and `[providers.microsoft]` are the tables of the providers (see [Providers](#providers)); \
             `[providers.sync]` holds what is the same for every provider: how often and how the connected accounts are pulled.",
        ),
        _ => None,
    }
}

/// The order of the tables in the reference: the order of the plan (F0.9).
const SECTION_ORDER: [&str; 17] = [
    "server",
    "database",
    "plugins",
    "plugin",
    "mail",
    "templates",
    "scheduling",
    "sharing",
    "limits",
    "security",
    "retention",
    "webhooks",
    "outbox",
    "feeds",
    "mcp",
    "providers",
    "observability",
];

const INTRODUCTION: &str = r#"# Configuration reference

This page is generated from the code by `cargo xtask config-docs`; do not edit it. CI fails when it is out of date. It is
generated from a build with **every cargo feature** of `davhaven-server` (`--all-features`), so that optional adapters are
documented; the container image is built with the default features, and what needs another one says so where it is
described. `davhaven config reference` inside the image prints the reference of the image's own build.

## How the configuration is read

Davhaven reads one TOML file and the environment, in this order of increasing precedence: the defaults of this
page, the file named by `--config <path>` (or the environment variable `DAVHAVEN_CONFIG`), and the environment
variables with the prefix `DAVHAVEN_`. A named file must exist. Without a file the environment alone configures the
server, which is how the container image is usually configured.

* **Environment variables** use `__` (two underscores) as the separator of nested keys, and single underscores stay
  in key names: `DAVHAVEN_SERVER__SHUTDOWN_GRACE=30s` sets `server.shutdown_grace`, and
  `DAVHAVEN_DATABASE__MIGRATION_URL_FILE=/run/secrets/migration-url` sets `database.migration_url_file`. Lists are
  written as `DAVHAVEN_PLUGINS__EVENT_SINKS=["log"]`. `DAVHAVEN_CONFIG` is the one variable that is not a key.
* **Unknown keys fail the start**, in the file and in the environment, and the error names the key. So does a
  `[plugin...]` table for an adapter this build does not contain, and a table for an adapter that is not
  selected under `[plugins]` is reported as a warning by `davhaven config check`.
* **An adapter is configured by its kind and its name.** The table of the adapter `smtp` of the kind `mail_transport` is
  `[plugin.mail_transport.smtp]`, and `[plugin.smtp]` means the same when no other selected adapter is called `smtp`.
  Names repeat across kinds (`memory` is a store, a mail transport and a rate limiter; `noop` is an authenticator, an
  outbox handler and a rate limiter), so a name that is selected for several kinds needs the kind in the table:
  `[plugin.mail_transport.memory]` and `[plugin.rate_limiter.memory]` are two tables of two adapters, while
  `[plugin.memory]` with keys in it is refused as ambiguous. Environment variables follow the same path:
  `DAVHAVEN_PLUGIN__MAIL_TRANSPORT__MEMORY__MAX_MESSAGES=100`. A few adapters are configured in tables of their own
  (`[database]`, `[security.auth]`, `[security.egress]`, `[webhooks]`, `[templates]`, `[providers.<name>]`); the
  [Plugins](#plugins) section says where each adapter's table is. A key may be set in only one of an adapter's places.
* **Secrets are never inline-only.** Every secret has a `*_file` variant that names a file with the secret
  (`database.url_file`, `plugin.smtp.password_file`, `security.keys[].secret_file`, ...). One trailing line break of
  the file is ignored. `davhaven config check` reads every such file, so a missing or unreadable secret is found
  before the first request. Inline values (`database.url`) exist for development; the output of `config check`
  redacts them.
* **Durations** are written as text: `500ms`, `30s`, `5m`, `1h`, `7d`. **Sizes** are bytes. The iCalendar duration
  of `feeds.refresh_interval` is the one exception (`PT15M`).
* **Tenant settings** (theme, sender, locale, scheduling policy, ...) are data, set through the management API, and are
  not part of this file.

`server.mode` is `production` unless you say `dev`. Production refuses the adapters that drop or fake work (the
in-memory store and mail transport, the `echo` renderer, the `noop` rate limiter, the recording HTTP client and the
`eicar` test scanner) and requires signing keys; the in-process rate limiter (`memory`) is the limiter of a single
instance and stays allowed. Development generates a key ring for the process when none is configured: credentials,
cursors, CSRF tokens and sealed data then do not survive a restart.

## The key ring

`security.keys` lists the keys of the key ring:

```toml
[[security.keys]]
id = "2027-01"
secret_file = "/run/secrets/davhaven-key-2027-01"

[[security.keys]]
id = "2026-07"
secret_file = "/run/secrets/davhaven-key-2026-07"

[security]
active_key_id = "2027-01"
```

* `id` is 1 to 32 characters of `a-z`, `0-9`, `-` and `_`. It is stored next to hashes, signatures and sealed data, so
  data stays verifiable after a rotation. Never reuse an id for another secret.
* The secret file contains **one secret of at least 32 characters, as printed by the tool that made it**: a base64 or
  hex encoding of 32 or more random bytes, for example `openssl rand -base64 48` or `openssl rand -hex 32`. The file
  content (one trailing line break removed) is the key material as it is: the server does not decode it, it derives
  the subkeys of every purpose (credential pepper, RSVP tokens, CSRF, cursors, cache keys, sealing) from it with
  HKDF-SHA256. A file of fewer than 32 characters is refused with the key id in the message.
* `active_key_id` names the key that signs, hashes and seals new data; without it the first key is active. The other
  keys only verify and open. See [`operations/keys.md`](operations/keys.md) for rotation.

## Listeners

`server.listeners.<name>` configures the three listeners: `public` (`wellknown`, `dav`, `web`), `internal` (`api`,
`mcp`) and `ops` (`ops`: `/healthz`, `/readyz`, `/metrics`). Each has `enabled`, `bind` and `routes`; a route group is
served by exactly one listener, and merging everything onto one listener is a list of all six groups. The default
binds are `0.0.0.0:8080` for `public` and the loopback addresses `127.0.0.1:8081` and `127.0.0.1:9090` for the other two;
a deployment that exposes them says so. `davhaven config check` warns when a listener that serves the `ops` group
(`/metrics`, `/readyz`, which need no credentials) is bound to an address that is not loopback.

`server.http.header_read_timeout` and `server.http.max_header_bytes` apply to every connection. A client that does not
finish its request head in time is disconnected, and so is a connection that has no request in flight for that long,
whatever protocol it speaks and whether it ever sent a request (a client that connects and sends nothing, or only a part
of the HTTP/2 preface, does not hold its socket). HTTP/2 connections are pinged at the same interval and closed when the
peer does not answer. `server.max_connections` caps the open connections of each listener (`server.http.concurrency_limit`
counts requests, not sockets); further clients wait in the accept queue of the operating system. An oversized request head
answers 431 in the form of the surface the path belongs to; values of `max_header_bytes` below 8192 are enforced on the
parsed request, because the HTTP library cannot buffer less (and what the library refuses itself answers 431 without a
body).

## Shutdown

On `SIGTERM` or `SIGINT` the server answers `/readyz` with 503 `draining`, keeps accepting connections for
`server.shutdown_delay` (zero by default; set it to the time your load balancer needs to notice), then stops accepting and
gives the requests in flight and the workers `server.shutdown_grace` to finish. What is still running at the end of the
grace period, connections included, is cut off. The shutdown hooks of the workers and adapters (the outbox hands back its
leases, the database closes its pool) then share five seconds, and the traces are flushed within four. The process is gone at
most `server.shutdown_delay + server.shutdown_grace + 10s` after the signal; the server logs that figure when it starts, and
the container needs a stop timeout that is longer.

## Mail transport

`plugin.smtp.tls` selects how the connection to the relay is secured: `"starttls"` (the default, port 587; the upgrade
to TLS is mandatory), `"implicit"` (TLS from the first byte, port 465; `"tls"` is accepted as another spelling of it) and
`"none"` (no encryption: for a capture server such as Mailpit). Production refuses `"none"` for a relay on another host,
because invitations and RSVP links would cross the network in the clear: `localhost` and the loopback addresses are
this host, any other name is another host (names are not resolved). `plugin.smtp.allow_insecure_transport = true`
accepts it for a capture server on a private network, such as the mail catcher of a staging deployment, and it never
accepts a login: with `plugin.smtp.username` and `plugin.smtp.password_file` set, production refuses `"none"` to another
host whatever the opt-in says, because a capture server needs no login. In `dev` mode the choice is the operator's.
`config check` applies the same rules as the start, and warns when mail travels unencrypted because of the opt-in and
when the opt-in is set but has no effect. The password is read from `plugin.smtp.password_file`.
`plugin.smtp.total_timeout` has to stay below 60 % of `outbox.lease`; `config check` refuses a combination that does
not.

## Observability

Logs go to standard error, one JSON object per line (`observability.log_format = "text"` for development), filtered
by `observability.log_filter` or, for a debugging session, by the `RUST_LOG` environment variable. The ops listener
serves the Prometheus metrics at `/metrics`. When `observability.otlp.endpoint` is set to the OTLP/gRPC port of a
collector (`http://otel-collector:4317`, the OTLP default) the server exports its spans there, sampled with
`observability.otlp.sample_ratio`; the export is plain gRPC without TLS and the endpoint may not carry credentials, so run
the collector on the local network and let it carry the traffic onwards. `observability.dav_capture` records the DAV
exchanges of the listed tenants (credentials redacted) as JSON files in a directory (mode 0700), which is how real client
traffic becomes test fixtures. Only exchanges that were authenticated as a user of a listed tenant are written, bodies are
read within the DAV limits and the request timeout, and responses of unknown or large size pass through unrecorded. It is
off by default, `config check` warns when it is on, and production mode refuses it unless
`observability.dav_capture.allow_in_production` says that a staging instance captures on purpose.

`davhaven config check` prints the **effective** configuration: the defaults of this build with the file and the
environment laid over them and the secrets redacted (credentials in URLs, whatever the key is called, and values under keys
that are named like secrets). `--explicit` prints only what the file and the environment say.
"#;

/// The plugins and tables that need a cargo feature the default build does not have, as `(kind, name, feature)`. The
/// reference is rendered with every feature on (so that optional plugins are documented), but the container image is built with
/// the default features: what needs one of these is marked, so the reader knows it is not in the image.
const OPTIONAL_FEATURES: &[(&str, &str, &str)] = &[("provider", "fake", "provider-fake")];

/// The cargo feature that brings a plugin, when it is not a default one.
fn feature_of(kind: &str, name: &str) -> Option<&'static str> {
    OPTIONAL_FEATURES
        .iter()
        .find(|(optional_kind, optional_name, _)| *optional_kind == kind && *optional_name == name)
        .map(|(_, _, feature)| *feature)
}

/// The sentence that marks an optional plugin, empty for a default one.
fn feature_note(kind: &str, name: &str) -> String {
    feature_of(kind, name).map_or_else(String::new, |feature| {
        format!("Part of builds with the cargo feature `{feature}`; the default build (the container image) does not have it.\n\n")
    })
}

/// Where the table of a plugin lives, as the reference shows it.
fn plugin_location(registry: &PluginRegistry, kind: &str, name: &str) -> String {
    let qualified = format!("`[plugin.{kind}.{name}]`");
    // The descriptor of the plugin says it: the table of its own that the plan gives it.
    if let Some(table) = registry.dedicated_table(kind, name) {
        return format!("`[{table}]` (or {qualified})");
    }
    let others: Vec<&str> = registry
        .report()
        .iter()
        .filter(|entry| entry.kind.name != kind && entry.plugins.contains(&name))
        .map(|entry| entry.kind.name)
        .collect();
    if others.is_empty() {
        format!("{qualified} (or `[plugin.{name}]`)")
    } else {
        format!(
            "{qualified}. The name `{name}` is used by other kinds too ({}), so `[plugin.{name}]` with keys in it is \
             refused as ambiguous when more than one of them is selected: write the kind",
            others.join(", ")
        )
    }
}

/// The plugins section: for every kind, what is selected by default and what each plugin is configured by.
fn plugins_section(registry: &PluginRegistry, out: &mut String) {
    let defaults = crate::config::PluginsConfig::default();
    out.push_str(
        "## Plugins\n\nThe adapters of the ports a deployment chooses are selected by name in `[plugins]` and \
         configured by one table each, written with the kind of the adapter (`[plugin.<kind>.<name>]`, see \
         above). This reference describes a build with every cargo feature of `davhaven-server`, so that optional \
         plugins are documented; the container image is built with the default features, and the plugins that need \
         another feature are marked with it. A plugin that is not compiled in is not listed and cannot be selected. \
         Kinds with *list* cardinality take several plugins (`authenticator` is an ordered chain: the first one that \
         recognises the credential decides).\n\n",
    );
    let schemas = registry.schemas();
    for kind in KINDS {
        let names = defaults.names(&kind).unwrap_or_default();
        let _ = writeln!(
            out,
            "### `{}`\n\nSelected by `plugins.{}` ({}); default {}.\n",
            kind.name,
            kind.config_key,
            kind.cardinality.as_str(),
            match kind.cardinality {
                davhaven_ports::Cardinality::Single => format!("`\"{}\"`", names.join(", ")),
                _ => format!("`{names:?}`"),
            }
        );
        let of_kind: Vec<_> = schemas.iter().filter(|schema| schema.kind == kind.name).collect();
        if of_kind.is_empty() {
            out.push_str("No plugin of this kind is part of this build.\n\n");
            continue;
        }
        for plugin in of_kind {
            let _ = writeln!(
                out,
                "#### `{}`\n\n{}\n\n{}Configured by {}.\n",
                plugin.name,
                cell(plugin.description),
                feature_note(kind.name, plugin.name),
                plugin_location(registry, kind.name, plugin.name)
            );
            table(&plugin.schema, out);
        }
    }
}

/// The provider tables that are part of this build: the schemas of `[providers.google]` and `[providers.microsoft]` of
/// the providers that are compiled in.
fn provider_schemas() -> Vec<(&'static str, &'static str, Schema)> {
    #[cfg_attr(
        not(any(feature = "provider-google", feature = "provider-microsoft")),
        expect(unused_mut, reason = "a build without providers has none to add")
    )]
    let mut found: Vec<(&'static str, &'static str, Schema)> = Vec::new();
    #[cfg(feature = "provider-google")]
    {
        found.push((
            "providers.google",
            "google",
            schemars::schema_for!(davhaven_provider_google::config::GoogleConfig),
        ));
    }
    #[cfg(feature = "provider-microsoft")]
    {
        found.push((
            "providers.microsoft",
            "microsoft",
            schemars::schema_for!(davhaven_provider_microsoft::config::MicrosoftConfig),
        ));
    }
    found
}

/// The text of `docs/configuration.md`.
pub fn configuration_reference(registry: &PluginRegistry) -> String {
    let mut out = String::from(INTRODUCTION);
    out.push_str("\n## Tables\n\n");
    let root = schemars::schema_for!(Config);
    let root_value = root.as_value();
    let defs = root_value.get("$defs").unwrap_or(&Value::Null);
    let members = properties(root_value, defs);
    for name in SECTION_ORDER {
        let Some((_, schema)) = members.iter().find(|(key, _)| key.as_str() == name) else {
            continue;
        };
        let _ = writeln!(out, "### `[{name}]`\n");
        if let Some(note) = section_note(name) {
            let _ = writeln!(out, "{note}\n");
        }
        if is_table(schema, defs) {
            let mut collected = Vec::new();
            rows(schema, defs, "", &mut collected);
            render_rows(&collected, &mut out);
        }
    }
    let providers = provider_schemas();
    out.push_str(
        "## Providers\n\nCalendar providers are cargo features of the server (`provider-google`, `provider-microsoft`), which the \
         default build (the container image) has, and are disabled in the configuration by default. Select one with \
         `plugins.providers` and switch it on with `enabled = true`. ",
    );
    if providers.is_empty() {
        out.push_str("This build contains none.\n\n");
    } else {
        out.push_str(
            "A provider that is enabled needs its client credentials, and its `redirect_uri` must be the callback of this \
             server, `{server.public_base_url}/oauth/{provider}/callback`: `davhaven config check` compares the two. The \
             OAuth client of a provider is asked for read access to calendars only.\n\n",
        );
        for (name, plugin, schema) in &providers {
            let _ = writeln!(out, "### `[{name}]`\n");
            out.push_str(&feature_note("provider", plugin));
            table(schema, &mut out);
        }
    }
    plugins_section(registry, &mut out);
    let _ = write!(
        out,
        "## Environment variables\n\nEvery key above has the variable `{ENV_PREFIX}` + its path in capitals with `.` \
         written as `__`, for example `{ENV_PREFIX}OUTBOX__BATCH_SIZE`, `{ENV_PREFIX}SERVER__LISTENERS__OPS__BIND` and \
         `{ENV_PREFIX}PLUGIN__MAIL_TRANSPORT__SMTP__HOST`. `DAVHAVEN_CONFIG` names the configuration file.\n"
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::registry;

    #[test]
    fn the_reference_lists_every_table_and_plugin() {
        let text = configuration_reference(&registry().unwrap());
        for table in SECTION_ORDER {
            assert!(text.contains(&format!("### `[{table}]`")), "{table}");
        }
        for key in [
            "`mode`",
            "`http.header_read_timeout`",
            "`lease`",
            "`audit_days`",
            "`otlp.endpoint`",
            "`log_filter`",
            "`ical.max_resource_size`",
        ] {
            assert!(text.contains(key), "{key} is missing from the reference");
        }
        for plugin in [
            "postgres",
            "memory",
            "smtp",
            "minijinja",
            "local",
            "egress",
            "webhook",
            "eicar",
            "manual",
        ] {
            assert!(text.contains(&format!("#### `{plugin}`")), "{plugin}");
        }
        assert!(
            text.contains("`plugin.smtp.tls`") || text.contains("`tls`"),
            "the SMTP table is described"
        );
        assert!(text.contains("openssl rand -base64 48"), "the key format is documented");
    }

    #[test]
    fn a_name_that_serves_several_kinds_says_to_write_the_kind() {
        let text = configuration_reference(&registry().unwrap());
        assert!(
            text.contains("`[plugin.mail_transport.memory]`") && text.contains("`[plugin.rate_limiter.memory]`"),
            "every `memory` adapter is configured by its own kind's table"
        );
        assert!(
            text.contains("is refused as ambiguous"),
            "the reference says what happens to the shared spelling"
        );
        assert!(
            !text.contains("Configured by `[plugin.memory]`."),
            "three adapters named memory cannot share one table"
        );
        assert!(
            text.contains("`[database]` (or `[plugin.database.postgres]`)"),
            "{text}"
        );
    }

    #[test]
    fn plugins_that_need_a_cargo_feature_are_marked_with_it() {
        let registry = registry().unwrap();
        // The marks come from one list; every plugin of it that this build registers carries its mark.
        for schema in registry.schemas() {
            if let Some(feature) = feature_of(schema.kind, schema.name) {
                assert!(feature_note(schema.kind, schema.name).contains(feature));
            }
        }
        let text = configuration_reference(&registry);
        assert!(
            text.contains("the default build (the container image)"),
            "the introduction of the plugins says what the image contains"
        );
        assert!(
            text.contains("This reference describes a build with every cargo feature"),
            "the reference does not claim that every plugin it lists is in the image"
        );
        #[cfg(feature = "provider-fake")]
        assert!(
            text.contains("Part of builds with the cargo feature `provider-fake`"),
            "the plugin of an optional provider is marked"
        );
        assert_eq!(
            feature_of("provider", "google"),
            None,
            "the providers of Google and Microsoft are in the image and need no mark"
        );
        #[cfg(feature = "provider-google")]
        assert!(
            !text.contains("cargo feature `provider-google`; the default build"),
            "the table of a provider that the image has is not marked as optional"
        );
        assert_eq!(
            feature_of("mail_transport", "smtp"),
            None,
            "a default plugin needs no mark"
        );
    }

    #[test]
    fn every_default_selection_is_shown_by_the_name_the_plugins_table_gives() {
        let text = configuration_reference(&registry().unwrap());
        for kind in KINDS {
            let names = crate::config::PluginsConfig::default().names(&kind).unwrap();
            let shown = match kind.cardinality {
                davhaven_ports::Cardinality::Single => format!("default `\"{}\"`.", names.join(", ")),
                _ => format!("default `{names:?}`."),
            };
            assert!(text.contains(&shown), "{}: {shown}", kind.name);
        }
    }
    #[test]
    fn the_reference_is_deterministic() {
        let registry = registry().unwrap();
        assert_eq!(configuration_reference(&registry), configuration_reference(&registry));
    }

    #[test]
    fn types_and_defaults_are_described_in_words() {
        let schema = schemars::schema_for!(Config);
        let value = schema.as_value();
        let defs = value.get("$defs").unwrap();
        let mut collected = Vec::new();
        rows(&value["properties"]["server"], defs, "", &mut collected);
        let mode = collected.iter().find(|row| row.key == "mode").unwrap();
        assert!(
            mode.kind.contains("production") && mode.kind.contains("dev"),
            "{mode:?}"
        );
        let timeout = collected
            .iter()
            .find(|row| row.key == "http.header_read_timeout")
            .unwrap();
        assert_eq!(timeout.kind, "string");
        assert!(timeout.description.contains("headers"), "{timeout:?}");
        assert_eq!(cell("a | b\n  c"), "a \\| b c");
    }
}
