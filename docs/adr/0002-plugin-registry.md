# ADR-0002: Plugin registry

- Status: accepted
- Date: 2026-10-24
- Scope: PLAN 2.3

## Context

Every integration of Davhaven is a port (R2). Deployments choose some adapters (which database, which mail
transport, which authenticators, which webhook handlers) and must be able to do so through configuration, not
code. Other ports have exactly one production implementation and only need a test double. A general dependency
injection framework or link-time plugin discovery would add magic that contributors and reviewers must understand.

## Decision

1. **Selected by name.** The registry in `davhaven-ports::plugin` selects adapters by name only for ports a
   deployment actually chooses:

   | Shape | Port kinds |
   | --- | --- |
   | single | `DATABASE`, `MAIL_TRANSPORT`, `TEMPLATES`, `HTTP_CLIENT`, `RATE_LIMITER`, `SCHEDULING_POLICY` |
   | ordered chain | `AUTHENTICATOR` |
   | set | `EVENT_SINK`, `OUTBOX_HANDLER`, `PROVIDER`, `CONTENT_SCANNER` |

2. **Injected directly.** `Clock`, `IdGenerator`, `SecretSealer`, `KeyRing` and `CredentialHasher` are not
   selectable: each has one production implementation and a test double and is passed in directly.

3. **Explicit registration.** Each adapter crate exports `pub fn register(reg: &mut PluginRegistry)`. The server
   calls these functions behind `#[cfg(feature = "...")]`. No `inventory`, `linkme` or other link-time
   registration.

4. **Descriptors.** `PluginDescriptor<P> { name, description, config_schema, build }`; `build` receives a
   `PluginContext` and the adapter's own configuration (`[plugin.<name>]`) as JSON and returns
   `Built<P> { port, lifecycle, workers }`. Every adapter configuration is a `Deserialize + JsonSchema` struct with
   `deny_unknown_fields`; `xtask config-docs` generates `docs/configuration.md` from the schemas.

5. **Tiers.** Ports are built in tiers: tier 0 (clock, ids, key ring, sealer, hasher, HTTP client), tier 1
   (database), tier 2 (everything else). `PluginContext` exposes the already built lower tiers, so a webhook
   handler can use the HTTP client and the database.

6. **Per-tenant variation is data.** Themes, senders, locales and policies are arguments to the port methods,
   never separate adapter instances per tenant.

7. **Production guard.** With `server.mode = "production"` the memory adapters for store, mail and rate limiting
   are refused at startup.

8. **Introspection test.** A registry test asserts that every selectable kind has at least two implementations
   (or one plus a documented empty set) and that the default configuration resolves.

9. **The descriptor says what only the plugin knows about its configuration.** A plugin
   is configured by `[plugin.<kind>.<name>]` (names repeat across kinds, ADR-0013); some have a table of
   their own besides it (`[security.auth]` for the local authenticator). `PluginDescriptor::dedicated_table` records that table
   (the dotted key) and `PluginDescriptor::check` is the plugin's own judgement of its table, which `davhaven config
   check` runs without building anything: it parses the table into the adapter's configuration struct, applies the
   validation of `build`, reads the files the table names and returns warnings (the renderer loads its themes, the SMTP
   relay and the database apply the transport rule of production). The same goes for what production refuses:
   `PluginDescriptor::with_refused_in_production` marks the plugins that drop or fake work, the registry refuses to
   build them with `RunMode::Production`, and `config check` asks the registry (`refused_in_production`), so the two
   answer from one flag. The server holds no list of adapters for any of it; a plugin without a check is checked
   against its JSON Schema. Descriptors are built with `PluginDescriptor::new(..)` and the `with_dedicated_table`, `with_check`
   and `with_refused_in_production` builders, which are `const`, so a descriptor can stay a constant of its crate.
   `PluginDescriptor`, `PluginCheck` and `PluginSchema` are `#[non_exhaustive]` (their members stay public to read), so
   that the next member is additive and no plugin crate builds them as struct literals; `PluginCheck` prints its mode
   and the keys of its table and never a value, because the table can carry inline secrets.
   **A dedicated table has one owner.** `PluginRegistry::register` refuses a descriptor that names the table of another
   (`PluginError::DuplicateTable`, whatever the kind) and the tables `plugin` and `plugins` and everything under them
   (`PluginError::InvalidTable`), so a plugin never receives the keys that are written for another. The server
   binds each table it carries to one kind (`config::DEDICATED_TABLES`: `database` belongs to the kind `database`,
   `security.auth` to `authenticator`, and so on), so that a descriptor of another kind that names `[database]` is
   refused, and the URLs and credentials in it reach no scanner.

## Consequences

- Adding an adapter means one crate, one `register` function, one feature in `davhaven-server` and its contract
  suite in `davhaven-port-tests`; nothing else changes. If the adapter has validation rules, a table of its own that the
  server carries already, or a flag for production, its descriptor carries them (see 9); the server needs no edit. A
  **new** dedicated table still needs a typed raw field in the server's `Config` and one row, with the kind it
  belongs to, in `config::DEDICATED_TABLES`: the server keeps the section it reads, the descriptor says who is configured by
  it.
- The configuration reference is generated from the same schemas the registry validates against, so it cannot
  drift.
- The registry is ordinary code: easy to debug, no global state, no initialisation order surprises.
- Pure ports stay simple constructor arguments, which keeps tests deterministic (`ManualClock`, `SeqIds`).

## Alternatives considered

- **Registry for every port**: rejected; clocks and key rings are never chosen by deployments, and selection by
  name would only add indirection.
- **`inventory`/`linkme` auto-registration**: rejected; implicit, platform-sensitive and hard to feature-gate.
- **Dynamic libraries**: rejected; no stable Rust ABI, and unsafe code is forbidden (R6).
