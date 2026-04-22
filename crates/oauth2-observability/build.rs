// Emits `APP_INFO_VERSION` = the workspace root crate's `[package].version`.
//
// The `app_info` Prometheus gauge and the OpenTelemetry `service.version`
// resource attribute must reflect the *application* version, not the
// `oauth2-observability` library crate's version. Workspace members are
// released together but carry their own `version` field in each crate
// manifest, which drifts because the release workflow only bumps the root
// `Cargo.toml` — leaving observability's `env!("CARGO_PKG_VERSION")` stale.
//
// Reading the workspace root at build time and exposing it as a custom
// `rustc-env` var keeps the single source of truth (root `[package].version`)
// without widening the release script's scope.

use std::path::PathBuf;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR is always set for build scripts");
    let workspace_root: PathBuf = PathBuf::from(&manifest_dir)
        .join("..")
        .join("..")
        .canonicalize()
        .expect("workspace root resolvable from oauth2-observability crate");
    let root_cargo_toml = workspace_root.join("Cargo.toml");

    println!("cargo:rerun-if-changed={}", root_cargo_toml.display());

    let text = std::fs::read_to_string(&root_cargo_toml)
        .unwrap_or_else(|e| panic!("read {}: {e}", root_cargo_toml.display()));

    let version = parse_root_package_version(&text).unwrap_or_else(|| {
        panic!(
            "workspace root {} has no [package].version — APP_INFO_VERSION cannot be resolved",
            root_cargo_toml.display()
        )
    });

    println!("cargo:rustc-env=APP_INFO_VERSION={version}");
}

/// Extract `version = "…"` from the first `[package]` section of the root
/// `Cargo.toml`. Stops scanning when the next `[section]` header appears, so
/// versions inside `[dependencies]` or `[workspace.package]` can't be picked
/// up by accident.
fn parse_root_package_version(text: &str) -> Option<String> {
    let mut in_package = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line == "[package]" {
            in_package = true;
            continue;
        }
        if in_package && line.starts_with('[') && line.ends_with(']') {
            break;
        }
        if in_package {
            if let Some(rest) = line.strip_prefix("version") {
                let rest = rest.trim_start();
                if let Some(rest) = rest.strip_prefix('=') {
                    let rest = rest.trim().trim_matches('"');
                    if !rest.is_empty() {
                        return Some(rest.to_string());
                    }
                }
            }
        }
    }
    None
}
