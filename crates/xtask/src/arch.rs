//! `arch-check`: the layering rules of `ENGINEERING_RULES.md` R1 and PLAN 2.1, checked on the normal, build and
//! dev-dependencies of every workspace crate, plus manifest hygiene (workspace lints, workspace dependencies and
//! `#![forbid(unsafe_code)]` in every crate root) and the fuzz packages (`fuzz.rs`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use cargo_metadata::{DependencyKind, MetadataCommand, TargetKind};

use crate::{XtaskError, print_line};

/// Prefix of every workspace crate except `xtask`.
const PREFIX: &str = "davhaven-";

/// Adapter crates (PLAN 2.1).
const ADAPTERS: &[&str] = &[
    "store-postgres",
    "store-memory",
    "mime",
    "mail-smtp",
    "mail-memory",
    "templates",
    "auth-local",
    "crypto-local",
    "http-egress",
    "hooks-webhook",
    "ratelimit-memory",
    "scanner-eicar",
    "provider-google",
    "provider-microsoft",
    "provider-fake",
];

/// Protocol crates.
const PROTOCOLS: &[&str] = &["dav", "api", "web", "mcp"];

/// Crates that exist only for tests.
const TEST_CRATES: &[&str] = &["app-fake", "fixtures", "port-tests", "testkit", "it", "conformance"];

/// Crates without I/O and without an async runtime.
const PURE: &[&str] = &["domain", "ical"];

/// External crates that bring I/O or an async runtime and therefore stay out of the pure crates.
const IO_LIBRARIES: &[&str] = &[
    "async-std",
    "async-trait",
    "axum",
    "futures",
    "hyper",
    "hyper-util",
    "lettre",
    "mio",
    "reqwest",
    "rmcp",
    "smol",
    "sqlx",
    "tokio",
    "tokio-util",
    "tower",
    "tower-http",
];

/// HTTP client libraries; only the egress adapter and the test harness may use them.
const HTTP_CLIENTS: &[&str] = &[
    "attohttpc",
    "awc",
    "curl",
    "hyper-rustls",
    "hyper-tls",
    "isahc",
    "reqwest",
    "surf",
    "ureq",
];

/// The HTTP client libraries that a crate other than the egress adapter may use, as `(crate, library)`: the trace
/// exporter of the server (`opentelemetry-otlp` with its gRPC or HTTP transport) talks to the collector that the operator
/// configures, which is no tenant-controlled destination and never receives event data; ADR-0013 and R1 record the
/// exception. It is the only one.
const EXPORTER_EXCEPTIONS: &[(&str, &str)] = &[("server", "opentelemetry-otlp")];

/// Crates allowed to depend on an HTTP client library.
const HTTP_CLIENT_USERS: &[&str] = &["http-egress", "testkit", "it", "conformance"];

/// Test crates that may enable the `testing` feature of a workspace crate on a normal dependency: the test doubles of
/// `davhaven-ports` and the throwaway certificates and private keys of `davhaven-crypto-local`.
const TESTING_FEATURE_USERS: &[&str] = &["fixtures", "port-tests", "testkit"];

/// Which workspace crates a crate may depend on.
#[derive(Debug, Clone, Copy)]
enum Allowed {
    /// Exactly these crates.
    Only(&'static [&'static str]),
    /// Every workspace crate except these (and itself).
    AllExcept(&'static [&'static str]),
}

/// One row of the layer table.
#[derive(Debug, Clone, Copy)]
struct Layer {
    /// Crate name without the `davhaven-` prefix.
    name: &'static str,
    /// Allowed normal and build dependencies (also allowed as dev-dependencies).
    normal: Allowed,
    /// Additional crates allowed as dev-dependencies only.
    dev_extra: &'static [&'static str],
}

const fn layer(name: &'static str, normal: &'static [&'static str], dev_extra: &'static [&'static str]) -> Layer {
    Layer {
        name,
        normal: Allowed::Only(normal),
        dev_extra,
    }
}

const PROTOCOL_DEV: &[&str] = &["app-fake", "fixtures"];
const ADAPTER_DEV: &[&str] = &["fixtures", "port-tests"];
const ADAPTER: &[&str] = &["ports", "domain"];

/// The layer table of PLAN 2.1 ("May depend on").
const LAYERS: &[Layer] = &[
    layer("domain", &[], &[]),
    layer("ical", &["domain"], &[]),
    layer("ports", &["domain"], &[]),
    layer("wire", &["domain"], &["fixtures"]),
    layer("app", &["domain", "ical", "ports", "wire"], &["fixtures"]),
    layer("app-fake", &["app", "domain", "wire"], &["fixtures"]),
    layer("http", &["app", "domain", "wire"], PROTOCOL_DEV),
    layer("dav", &["app", "domain", "ical", "http"], PROTOCOL_DEV),
    layer("api", &["app", "domain", "wire", "http"], PROTOCOL_DEV),
    layer("web", &["app", "domain", "wire", "http"], PROTOCOL_DEV),
    layer("mcp", &["app", "domain", "wire", "http"], PROTOCOL_DEV),
    layer("store-postgres", ADAPTER, ADAPTER_DEV),
    layer("store-memory", ADAPTER, ADAPTER_DEV),
    layer("mime", &["domain"], &["fixtures"]),
    layer("mail-smtp", &["ports", "domain", "mime"], ADAPTER_DEV),
    layer("mail-memory", &["ports", "domain", "mime"], ADAPTER_DEV),
    layer("templates", ADAPTER, ADAPTER_DEV),
    layer("auth-local", ADAPTER, ADAPTER_DEV),
    layer("crypto-local", ADAPTER, ADAPTER_DEV),
    layer("http-egress", ADAPTER, ADAPTER_DEV),
    layer("hooks-webhook", &["ports", "domain", "wire"], ADAPTER_DEV),
    layer("ratelimit-memory", ADAPTER, ADAPTER_DEV),
    layer("scanner-eicar", ADAPTER, ADAPTER_DEV),
    layer("provider-google", ADAPTER, ADAPTER_DEV),
    layer("provider-microsoft", ADAPTER, ADAPTER_DEV),
    layer("provider-fake", ADAPTER, ADAPTER_DEV),
    Layer {
        name: "server",
        normal: Allowed::AllExcept(&[
            "app-fake",
            "fixtures",
            "port-tests",
            "testkit",
            "it",
            "conformance",
            "xtask",
        ]),
        // `fixtures` for the fixtures world. The server hosts no plugin of its own (every plugin is an adapter crate or
        // the application's), so it runs no contract suite: the adapters do (R2).
        dev_extra: &["fixtures"],
    },
    layer("fixtures", &["domain", "ical", "ports"], &[]),
    layer("port-tests", &["ports", "domain", "fixtures"], &[]),
    Layer {
        name: "testkit",
        normal: Allowed::AllExcept(&["it", "conformance", "xtask"]),
        dev_extra: &[],
    },
    layer("it", &["testkit"], &[]),
    layer("conformance", &["testkit"], &[]),
    // The `contracts` command renders documents that these crates generate: the OpenAPI document of the API and
    // the MCP tool and event schemas of the wire crate.
    layer("xtask", &["api", "wire"], &[]),
];

/// Kind of a dependency edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Normal,
    Build,
    Dev,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Normal => "dependency",
            Kind::Build => "build-dependency",
            Kind::Dev => "dev-dependency",
        }
    }
}

/// A declared dependency of a workspace crate.
#[derive(Debug, Clone)]
struct Dep {
    name: String,
    kind: Kind,
    features: Vec<String>,
}

/// A workspace crate with its declared dependencies.
#[derive(Debug, Clone)]
struct Krate {
    name: String,
    deps: Vec<Dep>,
}

/// Runs the check on the current workspace; `Ok(false)` when violations were found.
pub(crate) fn run() -> Result<bool, XtaskError> {
    let metadata = MetadataCommand::new().no_deps().exec()?;
    let root = metadata.workspace_root.clone().into_std_path_buf();
    let packages = metadata.workspace_packages();

    let mut crates = Vec::with_capacity(packages.len());
    let mut violations = BTreeSet::new();
    for package in &packages {
        let name = package.name.to_string();
        crates.push(Krate {
            name: name.clone(),
            deps: package
                .dependencies
                .iter()
                .map(|d| Dep {
                    name: d.name.clone(),
                    kind: match d.kind {
                        DependencyKind::Development => Kind::Dev,
                        DependencyKind::Build => Kind::Build,
                        _ => Kind::Normal,
                    },
                    features: d.features.clone(),
                })
                .collect(),
        });

        let manifest_path = package.manifest_path.clone().into_std_path_buf();
        let text = read(&manifest_path)?;
        let manifest: toml::Table = toml::from_str(&text).map_err(|source| XtaskError::Toml {
            path: manifest_path.clone(),
            source: Box::new(source),
        })?;
        violations.extend(manifest_violations(&name, &manifest));

        for target in &package.targets {
            let is_root = target.kind.iter().any(|k| {
                matches!(
                    k,
                    TargetKind::Lib | TargetKind::RLib | TargetKind::Bin | TargetKind::ProcMacro
                )
            });
            if is_root {
                let path = target.src_path.clone().into_std_path_buf();
                let source = read(&path)?;
                let shown = path.strip_prefix(&root).unwrap_or(&path).display().to_string();
                violations.extend(root_source_violations(&name, &shown, &source));
            }
        }
    }
    violations.extend(graph_violations(&crates));
    violations.extend(crate::fuzz::violations(&root)?);

    let edges: usize = crates.iter().map(|c| c.deps.len()).sum();
    if violations.is_empty() {
        print_line(format_args!(
            "arch-check: {} crates, {edges} declared dependencies: ok",
            crates.len()
        ));
        Ok(true)
    } else {
        for violation in &violations {
            print_line(format_args!("error: {violation}"));
        }
        print_line(format_args!("arch-check: {} violation(s)", violations.len()));
        Ok(false)
    }
}

/// The text of a file, or the error that names it.
pub(crate) fn read(path: &Path) -> Result<String, XtaskError> {
    std::fs::read_to_string(path).map_err(|source| XtaskError::Read {
        path: path.to_path_buf(),
        source,
    })
}

/// Short name of a workspace crate (`davhaven-dav` → `dav`), `None` if it does not follow the convention.
fn short_name(name: &str) -> Option<&str> {
    if name == "xtask" {
        Some(name)
    } else {
        name.strip_prefix(PREFIX)
    }
}

fn find_layer(short: &str) -> Option<&'static Layer> {
    LAYERS.iter().find(|l| l.name == short)
}

fn allows(layer: &Layer, dep: &str, kind: Kind) -> bool {
    let normal = match layer.normal {
        Allowed::Only(list) => list.contains(&dep),
        Allowed::AllExcept(list) => dep != layer.name && !list.contains(&dep),
    };
    normal || (kind == Kind::Dev && layer.dev_extra.contains(&dep))
}

fn describe(layer: &Layer) -> String {
    let normal = match layer.normal {
        Allowed::Only([]) => "no workspace crate".to_owned(),
        Allowed::Only(list) => list.join(", "),
        Allowed::AllExcept(list) => format!("any workspace crate except {}", list.join(", ")),
    };
    if layer.dev_extra.is_empty() {
        normal
    } else {
        format!("{normal}; dev-only: {}", layer.dev_extra.join(", "))
    }
}

/// The rule behind a forbidden edge between two workspace crates.
fn reason(from: &str, to: &str) -> &'static str {
    if PROTOCOLS.contains(&from) && (to == "ports" || ADAPTERS.contains(&to)) {
        "protocol crates never depend on ports or adapters (R1)"
    } else if ADAPTERS.contains(&from) && ADAPTERS.contains(&to) {
        "adapters never depend on other adapters, except mail adapters on `mime` (R1)"
    } else if to == "testkit" {
        "`testkit` is used only by `it` and `conformance` (R1)"
    } else if TEST_CRATES.contains(&to) {
        "production crates never depend on test crates (PLAN 2.1)"
    } else {
        "not allowed by the layer table (PLAN 2.1)"
    }
}

/// All dependency-graph violations: layer table, external libraries and dev-dependency cycles.
fn graph_violations(crates: &[Krate]) -> BTreeSet<String> {
    let mut out = layer_violations(crates);
    out.extend(external_violations(crates));
    out.extend(dev_cycle_violations(crates));
    out
}

fn layer_violations(crates: &[Krate]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let members: BTreeSet<&str> = crates.iter().map(|c| c.name.as_str()).collect();

    for layer in LAYERS {
        let full = if layer.name == "xtask" {
            layer.name.to_owned()
        } else {
            format!("{PREFIX}{}", layer.name)
        };
        if !members.contains(full.as_str()) {
            out.insert(format!(
                "`{full}` is listed in the layer table but is not a workspace member"
            ));
        }
    }

    for krate in crates {
        let Some(short) = short_name(&krate.name) else {
            out.insert(format!(
                "`{}` does not follow the `{PREFIX}<name>` naming convention",
                krate.name
            ));
            continue;
        };
        let Some(layer) = find_layer(short) else {
            out.insert(format!(
                "`{}` is not in the layer table of `xtask arch-check` (PLAN 2.1)",
                krate.name
            ));
            continue;
        };
        for dep in &krate.deps {
            if !members.contains(dep.name.as_str()) {
                continue;
            }
            let Some(dep_short) = short_name(&dep.name) else {
                continue;
            };
            if !allows(layer, dep_short, dep.kind) {
                out.insert(format!(
                    "`{}` has a {} on `{}`: {}; allowed: {}",
                    krate.name,
                    dep.kind.label(),
                    dep.name,
                    reason(short, dep_short),
                    describe(layer)
                ));
            }
        }
    }
    out
}

fn is_http_client(dep: &Dep) -> bool {
    let has = |pred: &dyn Fn(&str) -> bool| dep.features.iter().any(|f| pred(f));
    match dep.name.as_str() {
        name if HTTP_CLIENTS.contains(&name) => true,
        "hyper" => has(&|f| f == "client"),
        "hyper-util" => has(&|f| f == "full" || f.starts_with("client")),
        // The OTLP exporter brings an HTTP client with each of its transports.
        "opentelemetry-otlp" => has(&|f| f == "grpc-tonic" || f.contains("reqwest") || f.contains("hyper-client")),
        "tonic" => true,
        "rmcp" => has(&|f| f.contains("client") || f.contains("reqwest") || f == "auth"),
        _ => false,
    }
}

fn external_violations(crates: &[Krate]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for krate in crates {
        let Some(short) = short_name(&krate.name) else { continue };
        for dep in &krate.deps {
            let exporter = EXPORTER_EXCEPTIONS.contains(&(short, dep.name.as_str()));
            if !HTTP_CLIENT_USERS.contains(&short) && !exporter && is_http_client(dep) {
                out.insert(format!(
                    "`{}` has a {} on the HTTP client library `{}`: only `{PREFIX}http-egress` may talk HTTP to the \
                     outside (R1)",
                    krate.name,
                    dep.kind.label(),
                    dep.name
                ));
            }
            // The `testing` feature of a workspace crate holds what only tests may have: the test doubles of the ports, the
            // throwaway certificates and keys of the local crypto. No crate of the product enables it on a normal dependency.
            let testing_feature = dep.name.starts_with(PREFIX) && dep.features.iter().any(|f| f == "testing");
            if testing_feature && dep.kind != Kind::Dev && !TESTING_FEATURE_USERS.contains(&short) {
                out.insert(format!(
                    "`{}` enables the `testing` feature of `{}` on a {}: test doubles and throwaway keys are for tests and \
                     test crates only (R1)",
                    krate.name,
                    dep.name,
                    dep.kind.label()
                ));
            }
            if PURE.contains(&short) && dep.kind != Kind::Dev && IO_LIBRARIES.contains(&dep.name.as_str()) {
                out.insert(format!(
                    "`{}` depends on `{}`: `domain` and `ical` have no I/O and no async runtime (R1)",
                    krate.name, dep.name
                ));
            }
        }
    }
    out
}

/// Dev-dependencies on crates that (transitively) depend on the crate itself.
fn dev_cycle_violations(crates: &[Krate]) -> BTreeSet<String> {
    let members: BTreeSet<&str> = crates.iter().map(|c| c.name.as_str()).collect();
    let normal: BTreeMap<&str, Vec<&str>> = crates
        .iter()
        .map(|c| {
            let deps = c
                .deps
                .iter()
                .filter(|d| d.kind != Kind::Dev && members.contains(d.name.as_str()))
                .map(|d| d.name.as_str())
                .collect();
            (c.name.as_str(), deps)
        })
        .collect();

    let mut out = BTreeSet::new();
    for krate in crates {
        for dep in krate
            .deps
            .iter()
            .filter(|d| d.kind == Kind::Dev && members.contains(d.name.as_str()))
        {
            if reaches(&normal, &dep.name, &krate.name) {
                out.insert(format!(
                    "`{}` has a dev-dependency on `{}`, which depends on `{}`: a crate may dev-depend only on \
                     crates that do not depend on it (R1)",
                    krate.name, dep.name, krate.name
                ));
            }
        }
    }
    out
}

/// Whether `from` reaches `to` through normal and build dependencies (or is `to`).
fn reaches(graph: &BTreeMap<&str, Vec<&str>>, from: &str, to: &str) -> bool {
    let mut seen = BTreeSet::new();
    let mut stack = vec![from];
    while let Some(node) = stack.pop() {
        if node == to {
            return true;
        }
        if seen.insert(node)
            && let Some(next) = graph.get(node)
        {
            stack.extend(next.iter().copied());
        }
    }
    false
}

/// Manifest hygiene: inherited workspace lints (R17) and dependencies declared once in the workspace (R11).
fn manifest_violations(name: &str, manifest: &toml::Table) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let inherits_lints = manifest
        .get("lints")
        .and_then(toml::Value::as_table)
        .and_then(|lints| lints.get("workspace"))
        .and_then(toml::Value::as_bool)
        .unwrap_or(false);
    if !inherits_lints {
        out.insert(format!(
            "`{name}` must inherit the workspace lints (`[lints] workspace = true`, R17)"
        ));
    }

    let mut tables: Vec<(String, &toml::Table)> = Vec::new();
    collect_dependency_tables(manifest, "", &mut tables);
    if let Some(targets) = manifest.get("target").and_then(toml::Value::as_table) {
        for (cfg, target) in targets {
            if let Some(target) = target.as_table() {
                collect_dependency_tables(target, &format!("target.{cfg}."), &mut tables);
            }
        }
    }
    for (section, table) in tables {
        for (dep, spec) in table {
            let inherited = spec
                .as_table()
                .and_then(|t| t.get("workspace"))
                .and_then(toml::Value::as_bool)
                .unwrap_or(false);
            if !inherited {
                out.insert(format!(
                    "`{name}` declares `{dep}` in [{section}] without `workspace = true`: declare it once in \
                     [workspace.dependencies] and inherit it (R11)"
                ));
            }
        }
    }
    out
}

fn collect_dependency_tables<'a>(table: &'a toml::Table, prefix: &str, out: &mut Vec<(String, &'a toml::Table)>) {
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(deps) = table.get(section).and_then(toml::Value::as_table) {
            out.push((format!("{prefix}{section}"), deps));
        }
    }
}

/// Every crate root forbids unsafe code (R6).
fn root_source_violations(name: &str, path: &str, source: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let forbids = source.lines().any(|line| line.trim() == "#![forbid(unsafe_code)]");
    if !forbids {
        out.insert(format!(
            "`{name}`: crate root `{path}` must contain `#![forbid(unsafe_code)]` (R6)"
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full(short: &str) -> String {
        if short == "xtask" {
            short.to_owned()
        } else {
            format!("{PREFIX}{short}")
        }
    }

    fn dep(name: &str, kind: Kind) -> Dep {
        Dep {
            name: name.to_owned(),
            kind,
            features: Vec::new(),
        }
    }

    /// A workspace that satisfies the layer table: every crate depends on what its row allows.
    fn valid_workspace() -> Vec<Krate> {
        LAYERS
            .iter()
            .map(|layer| {
                let deps = match layer.normal {
                    Allowed::Only(list) => list.iter().map(|d| dep(&full(d), Kind::Normal)).collect(),
                    Allowed::AllExcept(_) => vec![dep(&full("app"), Kind::Normal)],
                };
                Krate {
                    name: full(layer.name),
                    deps,
                }
            })
            .collect()
    }

    fn with_dep(mut crates: Vec<Krate>, from: &str, dep: Dep) -> Vec<Krate> {
        let krate = crates
            .iter_mut()
            .find(|c| c.name == full(from))
            .expect("crate in workspace");
        krate.deps.push(dep);
        crates
    }

    fn violations(crates: &[Krate]) -> Vec<String> {
        graph_violations(crates).into_iter().collect()
    }

    #[test]
    fn layer_table_is_consistent_with_itself() {
        assert!(
            violations(&valid_workspace()).is_empty(),
            "{:?}",
            violations(&valid_workspace())
        );
    }

    #[test]
    fn protocol_crates_never_depend_on_ports_or_adapters() {
        for kind in [Kind::Normal, Kind::Dev] {
            let crates = with_dep(valid_workspace(), "dav", dep(&full("ports"), kind));
            let found = violations(&crates);
            assert_eq!(found.len(), 1, "{found:?}");
            assert!(
                found[0].contains("protocol crates never depend on ports or adapters"),
                "{found:?}"
            );
        }
        let crates = with_dep(valid_workspace(), "api", dep(&full("store-memory"), Kind::Dev));
        assert!(violations(&crates)[0].contains("protocol crates never depend on ports or adapters"));
    }

    #[test]
    fn adapters_never_depend_on_other_adapters_except_mime() {
        let crates = with_dep(
            valid_workspace(),
            "auth-local",
            dep(&full("crypto-local"), Kind::Normal),
        );
        assert!(violations(&crates)[0].contains("adapters never depend on other adapters"));
        assert!(allows(find_layer("mail-smtp").expect("row"), "mime", Kind::Normal));
        assert!(!allows(find_layer("store-memory").expect("row"), "mime", Kind::Normal));
    }

    #[test]
    fn only_it_and_conformance_use_testkit() {
        let crates = with_dep(valid_workspace(), "server", dep(&full("testkit"), Kind::Dev));
        assert!(violations(&crates)[0].contains("`testkit` is used only by `it` and `conformance`"));
        let crates = with_dep(valid_workspace(), "it", dep(&full("testkit"), Kind::Dev));
        assert_eq!(violations(&crates), Vec::<String>::new());
    }

    #[test]
    fn production_crates_never_depend_on_test_crates() {
        let crates = with_dep(valid_workspace(), "app", dep(&full("fixtures"), Kind::Normal));
        assert!(violations(&crates)[0].contains("production crates never depend on test crates"));
        let crates = with_dep(valid_workspace(), "app", dep(&full("fixtures"), Kind::Dev));
        assert_eq!(violations(&crates), Vec::<String>::new());
    }

    #[test]
    fn dev_dependency_cycles_are_reported() {
        let crates = vec![
            Krate {
                name: full("a"),
                deps: vec![dep(&full("b"), Kind::Dev)],
            },
            Krate {
                name: full("b"),
                deps: vec![dep(&full("c"), Kind::Normal)],
            },
            Krate {
                name: full("c"),
                deps: vec![dep(&full("a"), Kind::Normal)],
            },
        ];
        let found: Vec<String> = dev_cycle_violations(&crates).into_iter().collect();
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("`davhaven-a` has a dev-dependency on `davhaven-b`"));

        let acyclic = vec![
            Krate {
                name: full("a"),
                deps: vec![dep(&full("b"), Kind::Dev)],
            },
            Krate {
                name: full("b"),
                deps: vec![dep(&full("c"), Kind::Normal)],
            },
            Krate {
                name: full("c"),
                deps: vec![dep(&full("a"), Kind::Dev)],
            },
        ];
        assert!(dev_cycle_violations(&acyclic).is_empty());
    }

    #[test]
    fn only_the_egress_adapter_uses_http_clients() {
        let crates = with_dep(valid_workspace(), "dav", dep("reqwest", Kind::Dev));
        assert!(violations(&crates)[0].contains("HTTP client library `reqwest`"));
        let crates = with_dep(valid_workspace(), "http-egress", dep("reqwest", Kind::Normal));
        assert_eq!(violations(&crates), Vec::<String>::new());

        let mut hyper_util = dep("hyper-util", Kind::Normal);
        hyper_util.features = vec!["server-auto".to_owned()];
        assert_eq!(
            violations(&with_dep(valid_workspace(), "server", hyper_util.clone())),
            Vec::<String>::new()
        );
        hyper_util.features.push("client-legacy".to_owned());
        assert_eq!(violations(&with_dep(valid_workspace(), "server", hyper_util)).len(), 1);
    }

    #[test]
    fn the_trace_exporter_of_the_server_is_the_one_exception_to_the_http_client_rule() {
        let mut exporter = dep("opentelemetry-otlp", Kind::Normal);
        exporter.features = vec!["grpc-tonic".to_owned()];
        assert_eq!(
            violations(&with_dep(valid_workspace(), "server", exporter.clone())),
            Vec::<String>::new(),
            "the server's exporter talks to the operator's collector"
        );
        let found = violations(&with_dep(valid_workspace(), "app", exporter.clone()));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0].contains("HTTP client library `opentelemetry-otlp`"),
            "{found:?}"
        );
        for feature in ["reqwest-client", "hyper-client"] {
            let mut other = dep("opentelemetry-otlp", Kind::Normal);
            other.features = vec![feature.to_owned()];
            assert_eq!(
                violations(&with_dep(valid_workspace(), "dav", other)).len(),
                1,
                "{feature}"
            );
        }
        // Without a client transport the crate is no HTTP client.
        let mut plain = dep("opentelemetry-otlp", Kind::Normal);
        plain.features = vec!["trace".to_owned()];
        assert_eq!(
            violations(&with_dep(valid_workspace(), "dav", plain)),
            Vec::<String>::new()
        );
        assert_eq!(
            violations(&with_dep(valid_workspace(), "dav", dep("tonic", Kind::Normal))).len(),
            1
        );
    }

    #[test]
    fn the_contract_suites_of_the_ports_are_run_by_the_adapters_and_not_by_the_server() {
        let crates = with_dep(valid_workspace(), "scanner-eicar", dep(&full("port-tests"), Kind::Dev));
        assert_eq!(
            violations(&crates),
            Vec::<String>::new(),
            "an adapter runs the suite of its port"
        );
        let crates = with_dep(
            valid_workspace(),
            "scanner-eicar",
            dep(&full("port-tests"), Kind::Normal),
        );
        assert_eq!(violations(&crates).len(), 1, "never as a normal dependency");
        let crates = with_dep(valid_workspace(), "server", dep(&full("port-tests"), Kind::Dev));
        assert_eq!(violations(&crates).len(), 1, "no plugin lives in the server");
        let crates = with_dep(valid_workspace(), "dav", dep(&full("port-tests"), Kind::Dev));
        assert_eq!(violations(&crates).len(), 1, "only the adapters");
    }

    #[test]
    fn pure_crates_have_no_async_runtime() {
        let crates = with_dep(valid_workspace(), "domain", dep("tokio", Kind::Normal));
        assert!(violations(&crates)[0].contains("no I/O and no async runtime"));
        let crates = with_dep(valid_workspace(), "ical", dep("tokio", Kind::Dev));
        assert_eq!(violations(&crates), Vec::<String>::new());
    }

    #[test]
    fn port_test_doubles_stay_in_tests() {
        let mut testing = dep(&full("ports"), Kind::Normal);
        testing.features = vec!["testing".to_owned()];
        let found = violations(&with_dep(valid_workspace(), "app", testing.clone()));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("enables the `testing` feature"), "{found:?}");
        assert_eq!(
            violations(&with_dep(valid_workspace(), "fixtures", testing.clone())),
            Vec::<String>::new()
        );
        testing.kind = Kind::Dev;
        assert_eq!(
            violations(&with_dep(valid_workspace(), "app", testing)),
            Vec::<String>::new()
        );
    }

    #[test]
    fn throwaway_keys_stay_in_tests() {
        // The `testing` feature of the local crypto holds certificates and private keys that are public: whatever signs profiles
        // for real must never enable it, the server least of all.
        let mut testing = dep(&full("crypto-local"), Kind::Normal);
        testing.features = vec!["testing".to_owned()];
        let found = violations(&with_dep(valid_workspace(), "server", testing.clone()));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0].contains("enables the `testing` feature of `davhaven-crypto-local`"),
            "{found:?}"
        );
        assert_eq!(
            violations(&with_dep(valid_workspace(), "testkit", testing.clone())),
            Vec::<String>::new()
        );
        testing.kind = Kind::Dev;
        assert_eq!(
            violations(&with_dep(valid_workspace(), "server", testing)),
            Vec::<String>::new()
        );
        // Without the feature the crate is an ordinary dependency.
        assert_eq!(
            violations(&with_dep(
                valid_workspace(),
                "server",
                dep(&full("crypto-local"), Kind::Normal)
            )),
            Vec::<String>::new()
        );
    }

    #[test]
    fn unknown_and_missing_crates_are_reported() {
        let mut crates = valid_workspace();
        crates.push(Krate {
            name: full("surprise"),
            deps: Vec::new(),
        });
        crates.retain(|c| c.name != full("mime"));
        let found = violations(&crates);
        assert!(
            found
                .iter()
                .any(|v| v.contains("`davhaven-surprise` is not in the layer table")),
            "{found:?}"
        );
        assert!(
            found
                .iter()
                .any(|v| v.contains("`davhaven-mime` is listed in the layer table")),
            "{found:?}"
        );
    }

    #[test]
    fn manifests_inherit_lints_and_workspace_dependencies() {
        let good: toml::Table = toml::from_str(
            "[dependencies]\nserde.workspace = true\ntokio = { workspace = true, features = [\"rt\"] }\n\
             [target.'cfg(unix)'.dev-dependencies]\nlibc = { workspace = true }\n[lints]\nworkspace = true\n",
        )
        .expect("valid toml");
        assert!(manifest_violations("davhaven-x", &good).is_empty());

        let bad: toml::Table = toml::from_str(
            "[dependencies]\nserde = \"1\"\n[target.'cfg(unix)'.build-dependencies]\ncc = { version = \"1\" }\n",
        )
        .expect("valid toml");
        let found: Vec<String> = manifest_violations("davhaven-x", &bad).into_iter().collect();
        assert_eq!(found.len(), 3, "{found:?}");
        assert!(found.iter().any(|v| v.contains("must inherit the workspace lints")));
        assert!(found.iter().any(|v| v.contains("`serde` in [dependencies]")));
        assert!(
            found
                .iter()
                .any(|v| v.contains("`cc` in [target.cfg(unix).build-dependencies]"))
        );
    }

    #[test]
    fn a_forbidden_edge_names_the_rule_and_what_the_row_allows() {
        let found = violations(&with_dep(valid_workspace(), "domain", dep(&full("ical"), Kind::Normal)));
        assert_eq!(
            found,
            vec![
                "`davhaven-domain` has a dependency on `davhaven-ical`: not allowed by the layer table (PLAN 2.1); \
                 allowed: no workspace crate"
                    .to_owned()
            ]
        );
        let found = violations(&with_dep(valid_workspace(), "dav", dep(&full("api"), Kind::Dev)));
        assert_eq!(
            found,
            vec![
                "`davhaven-dav` has a dev-dependency on `davhaven-api`: not allowed by the layer table (PLAN 2.1); \
                 allowed: app, domain, ical, http; dev-only: app-fake, fixtures"
                    .to_owned()
            ]
        );
    }

    #[test]
    fn dev_only_crates_are_refused_as_build_dependencies() {
        // The dev-only column covers dev-dependencies alone: a build script runs in every build of the crate.
        let found = violations(&with_dep(valid_workspace(), "app", dep(&full("fixtures"), Kind::Build)));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0].starts_with("`davhaven-app` has a build-dependency on `davhaven-fixtures`: production crates"),
            "{found:?}"
        );
    }

    #[test]
    fn the_rows_that_allow_every_crate_still_exclude_the_test_crates_above_them() {
        let found = violations(&with_dep(
            valid_workspace(),
            "testkit",
            dep(&full("conformance"), Kind::Normal),
        ));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0].contains("any workspace crate except it, conformance, xtask"),
            "{found:?}"
        );
        let found = violations(&with_dep(
            valid_workspace(),
            "server",
            dep(&full("app-fake"), Kind::Normal),
        ));
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(
            violations(&with_dep(
                valid_workspace(),
                "server",
                dep(&full("store-postgres"), Kind::Normal)
            )),
            Vec::<String>::new()
        );
    }

    #[test]
    fn external_libraries_are_not_judged_by_the_layer_table() {
        // A crates.io library whose name starts with the prefix is no workspace crate either.
        let crates = with_dep(valid_workspace(), "domain", dep("serde", Kind::Normal));
        let crates = with_dep(crates, "domain", dep(&full("unrelated"), Kind::Normal));
        assert_eq!(violations(&crates), Vec::<String>::new());
    }

    #[test]
    fn a_crate_outside_the_naming_convention_is_reported() {
        let mut crates = valid_workspace();
        crates.push(Krate {
            name: "helper".to_owned(),
            deps: vec![dep(&full("ports"), Kind::Normal)],
        });
        assert_eq!(
            violations(&crates),
            vec!["`helper` does not follow the `davhaven-<name>` naming convention".to_owned()]
        );
    }

    #[test]
    fn client_features_turn_server_libraries_into_http_clients() {
        let with_features = |name: &str, features: &[&str]| Dep {
            name: name.to_owned(),
            kind: Kind::Normal,
            features: features.iter().map(|feature| (*feature).to_owned()).collect(),
        };
        for (library, features) in [
            ("hyper", &["client"][..]),
            ("hyper-util", &["full"][..]),
            ("rmcp", &["client"][..]),
            ("rmcp", &["transport-streamable-http-client-reqwest"][..]),
            ("rmcp", &["auth"][..]),
        ] {
            let found = violations(&with_dep(valid_workspace(), "mcp", with_features(library, features)));
            assert_eq!(found.len(), 1, "{library} {features:?}: {found:?}");
        }
        for (library, features) in [
            ("hyper", &["server", "http1"][..]),
            ("rmcp", &["server", "transport-streamable-http-server"][..]),
        ] {
            assert_eq!(
                violations(&with_dep(valid_workspace(), "mcp", with_features(library, features))),
                Vec::<String>::new(),
                "{library} {features:?}"
            );
        }
    }

    #[test]
    fn the_repository_passes_its_own_check() {
        assert!(run().unwrap(), "`cargo xtask arch-check` reports violations");
    }

    #[test]
    fn crate_roots_forbid_unsafe_code() {
        assert!(root_source_violations("x", "src/lib.rs", "//! Docs.\n\n#![forbid(unsafe_code)]\n").is_empty());
        assert_eq!(root_source_violations("x", "src/lib.rs", "//! Docs.\n").len(), 1);
        // A weaker attribute or one that is commented out does not count.
        assert_eq!(
            root_source_violations("x", "src/lib.rs", "#![deny(unsafe_code)]\n").len(),
            1
        );
        assert_eq!(
            root_source_violations("x", "src/lib.rs", "// #![forbid(unsafe_code)]\n").len(),
            1
        );
    }

    #[test]
    fn opting_out_of_the_workspace_explicitly_is_a_violation_too() {
        let manifest: toml::Table = toml::from_str(
            "[dependencies]\nlocal = { path = \"../local\" }\nserde = { workspace = false, version = \"1\" }\n\
             [lints]\nworkspace = false\n",
        )
        .expect("valid toml");
        let found: Vec<String> = manifest_violations("davhaven-x", &manifest).into_iter().collect();
        assert_eq!(found.len(), 3, "{found:?}");
        assert!(
            found.iter().any(|v| v.contains("`local` in [dependencies]")),
            "{found:?}"
        );
        assert!(
            found.iter().any(|v| v.contains("`serde` in [dependencies]")),
            "{found:?}"
        );
    }
}
