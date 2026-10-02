//! OpenTelemetry family coherence guard (resolved-dependency graph).
//!
//! ## Root cause this guards
//!
//! This workspace pins a single, lockstep OpenTelemetry family:
//!
//! ```text
//! opentelemetry 0.32, opentelemetry_sdk 0.32, opentelemetry-otlp 0.32,
//! opentelemetry-proto 0.32, paired with tracing-opentelemetry 0.33
//! ```
//!
//! The family is chosen to match `reqwest-tracing 0.7.1` (pinned here).
//! `reqwest-tracing 0.7.1` exposes features `opentelemetry_0_20` ..
//! `opentelemetry_0_32` and has NO `opentelemetry_0_33`; see
//! `crates/oauth2-social-login/Cargo.toml`, which selects `opentelemetry_0_32`.
//! Its `opentelemetry_0_32` injection reads the current span through
//! `tracing-opentelemetry 0.33`, which is linked against `opentelemetry 0.32`.
//!
//! A partial bump (e.g. `opentelemetry_sdk` to 0.33 while `opentelemetry`
//! stays 0.32) makes Cargo unify BOTH `opentelemetry` 0.32 and 0.33 into the
//! graph. The `SdkTracerProvider: TracerProvider` / `SpanExporter` impls then
//! no longer apply to the 0.32 traits the workspace imports (build break), and
//! — worse — a *consistent* 0.33 bump compiles but silently drops
//! `traceparent` (see `otel_outbound_propagation.rs`).
//!
//! ## What this test asserts
//!
//! 1. **Resolved graph is single-row.** `Cargo.lock` contains exactly one
//!    version each of `opentelemetry`, `opentelemetry_sdk`, `opentelemetry-otlp`
//!    and `opentelemetry-proto`, all on the same `0.32` minor. This check
//!    reads the `Cargo.lock` package rows, i.e. the versions Cargo resolved
//!    into the dependency graph — not unified features.
//! 2. **tracing-opentelemetry is pinned to the pairing 0.33** and resolves to a
//!    single row.
//! 3. **The social-login seam selects the matching feature.** The member's
//!    *actual production dependency feature selection* for `reqwest-tracing`
//!    must contain `opentelemetry_0_32` and must not contain any
//!    `opentelemetry_0_33`-style selection, because reqwest-tracing 0.7.1 does
//!    not publish one.
//!
//! ## Why (3) parses Cargo metadata instead of matching strings
//!
//! An earlier revision of this guard read the member `Cargo.toml` as raw text
//! and asserted `body.contains("opentelemetry_0_32")`. That false-passes when
//! the feature is only *mentioned* — in a comment, a doc note, or a feature
//! definition — while the actual `features = [...]` selection on the
//! `reqwest-tracing` dependency is empty.
//!
//! This guard therefore asks Cargo itself. `cargo metadata --no-deps` reports
//! each manifest dependency with the feature list its own declaration requests.
//! A per-dependency `features = [...]` declaration is a property of that
//! dependency's manifest entry, independent of feature unification (Cargo does
//! not unify feature lists across the normal/dev/build entries of one manifest,
//! and `--no-deps` never resolves the graph). The guard reads the member's
//! production (`kind: null` / normal) entry specifically: that is the edge
//! `cargo build` compiles, while a root **dev-dependency** on `reqwest-tracing`
//! does not stand in for it.
//!
//! The guard is fail-closed: if `cargo metadata` cannot run, cannot be parsed,
//! or the member's production `reqwest-tracing` dependency is absent, the test
//! panics (fails) rather than skipping.
//!
//! `--locked` and `--offline` keep the metadata query read-only and
//! network-free: it reuses the committed `Cargo.lock` and never touches the
//! registry.
//!
//! This test is deliberately build-free at the crate level (it shells out to
//! `cargo metadata`, which only reads manifests/lock) so it is fast and
//! red-capable on exactly the split-brain state, in any CI job.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR for the root crate is the workspace root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Parse `Cargo.lock` into `name -> [versions]` for `[[package]]` entries.
///
/// `Cargo.lock` is TOML, but a full TOML parser is not available as a test
/// dependency. This scans the `[[package]]` records directly, which is stable
/// and avoids adding a dependency just for the guard.
fn lock_versions(lock_path: &Path) -> BTreeMap<String, Vec<String>> {
    let body = fs::read_to_string(lock_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", lock_path.display()));
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut current_name: Option<String> = None;
    for raw in body.lines() {
        let line = raw.trim();
        if line == "[[package]]" {
            current_name = None;
            continue;
        }
        if let Some(rest) = line.strip_prefix("name = ") {
            current_name = Some(rest.trim().trim_matches('"').to_string());
            continue;
        }
        if let Some(rest) = line.strip_prefix("version = ") {
            if let Some(name) = &current_name {
                out.entry(name.clone())
                    .or_default()
                    .push(rest.trim().trim_matches('"').to_string());
            }
        }
    }
    out
}

fn minor_of(version: &str) -> String {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[0], parts[1])
    } else {
        version.to_string()
    }
}

const EXPECTED_MINOR: &str = "0.32";

/// A single dependency's requested features, read back from Cargo itself.
#[derive(Debug)]
struct DepSelection {
    /// `kind` as reported by cargo metadata: `"normal"`, `"dev"` or `"build"`.
    kind: String,
    /// Feature names the manifest actually requests for this dependency.
    features: Vec<String>,
}

/// Ask Cargo for the *actual* requested feature selection of a dependency of a
/// workspace member.
///
/// Uses `cargo metadata --no-deps --locked --offline`, which reads manifests
/// and the lock file only. Each manifest dependency is reported with the exact
/// `features = [...]` list its own declaration requests (a per-declaration
/// property, independent of feature unification). `--locked`/`--offline` keep
/// the query read-only and network-free.
///
/// Fail closed: any error (running cargo, non-zero exit, JSON parse, member or
/// dependency missing) panics so the guard cannot silently pass.
fn requested_dep_selections(
    root: &Path,
    member_package: &str,
    dep_name: &str,
) -> Vec<DepSelection> {
    let out = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string()))
        .args([
            "metadata",
            "--format-version",
            "1",
            "--all-features",
            "--no-deps",
            "--locked",
            "--offline",
        ])
        .current_dir(root)
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "guard requires `cargo metadata` to inspect the actual production feature \
                 selection, but it could not be executed: {e}"
            )
        });

    if !out.status.success() {
        panic!(
            "`cargo metadata --all-features --no-deps --locked --offline` failed with status {}. \
             This guard fails closed rather than skipping the actual feature-selection check.\n\
             stderr:\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let json: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("cannot parse `cargo metadata` JSON: {e}"));

    let packages = json
        .get("packages")
        .and_then(|p| p.as_array())
        .unwrap_or_else(|| panic!("`cargo metadata` output has no `packages` array"));

    let member = packages
        .iter()
        .find(|p| p.get("name").and_then(|n| n.as_str()) == Some(member_package))
        .unwrap_or_else(|| {
            panic!(
                "`cargo metadata` did not report the `{member_package}` package; cannot \
                 verify its actual `{dep_name}` feature selection"
            )
        });

    let mut found = Vec::new();
    for dep in member
        .get("dependencies")
        .and_then(|d| d.as_array())
        .unwrap_or(&Vec::new())
    {
        if dep.get("name").and_then(|n| n.as_str()) != Some(dep_name) {
            continue;
        }
        let kind = match dep.get("kind").and_then(|k| k.as_str()) {
            Some("dev") => "dev",
            Some("build") => "build",
            // null normal dependencies, plus any future unknown kind, are
            // treated as production so the guard does not miss a real edge.
            _ => "normal",
        };
        let features = dep
            .get("features")
            .and_then(|f| f.as_array())
            .map(|fs| {
                fs.iter()
                    .filter_map(|f| f.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        found.push(DepSelection {
            kind: kind.to_string(),
            features,
        });
    }

    found
}

/// The shared check: the production `reqwest-tracing` selection of
/// `oauth2-social-login`, read from Cargo metadata.
///
/// `root` is the workspace root to inspect (`CARGO_MANIFEST_DIR` for the real
/// workspace; a tempfile fixture for the regressions). Returns the requested
/// features of the single production (`kind: null` / normal) dependency entry,
/// or an error for every fail-closed case. Both the real workspace test and the
/// fixture regressions call this one function, so a regression cannot pass by
/// exercising a private re-implementation of the predicate.
fn check_social_login_selection(root: &Path) -> Result<Vec<String>, String> {
    let selections = requested_dep_selections(root, "oauth2-social-login", "reqwest-tracing");

    let production: Vec<&DepSelection> = selections.iter().filter(|s| s.kind == "normal").collect();
    if production.len() != 1 {
        return Err(format!(
            "oauth2-social-login must declare exactly one production (normal) `reqwest-tracing` \
             dependency; cargo metadata reported {selections:#?}. This guard fails closed rather \
             than matching a comment or doc string."
        ));
    }

    let actual = production[0].features.clone();
    if !actual.iter().any(|f| f == "opentelemetry_0_32") {
        return Err(format!(
            "missing selection: oauth2-social-login's production `reqwest-tracing` dependency \
             does not actually request the `opentelemetry_0_32` feature (actual selection: \
             {actual:?}). A comment or doc string mentioning the feature name cannot rescue a \
             missing actual selection, because the reqwest-tracing 0.7.1 tracing-opentelemetry \
             0.33 bridge is only compiled in when the feature is selected."
        ));
    }
    if actual.iter().any(|f| f.starts_with("opentelemetry_0_33")) {
        return Err(format!(
            "oauth2-social-login's production `reqwest-tracing` dependency selects an \
             `opentelemetry_0_33`-style feature ({actual:?}), but reqwest-tracing 0.7.1 does not \
             publish that feature; the OTel family must stay on 0.32"
        ));
    }
    Ok(actual)
}

/// Write a minimal, parsable single-member workspace whose
/// `oauth2-social-login` package declares `reqwest-tracing` with the given
/// feature selection. `comment_mention` controls whether the manifest carries a
/// *comment* that mentions `opentelemetry_0_32` — text no raw-string matcher
/// could see through. Returns the workspace root.
fn write_social_login_fixture(dir: &Path, features: &[&str], comment_mention: bool) -> PathBuf {
    let member = dir.join("crates/oauth2-social-login");
    fs::create_dir_all(member.join("src")).unwrap();
    let feature_list = features
        .iter()
        .map(|f| format!("\"{f}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let comment = if comment_mention {
        "# `opentelemetry_0_32` matches the workspace OTel family; kept as a note even when \
         the selection below is dropped.\n"
    } else {
        ""
    };
    let manifest = "# Fixture workspace used by the coherence guard regressions.\n\
                    [workspace]\n\
                    members = [\"crates/oauth2-social-login\"]\n\
                    resolver = \"2\"\n\
                    \n\
                    [workspace.package]\n\
                    rust-version = \"1.88\"\n";
    fs::write(dir.join("Cargo.toml"), manifest).unwrap();
    fs::write(
        member.join("src/lib.rs"),
        "// fixture lib target for the coherence guard\n",
    )
    .unwrap();
    let member_manifest = format!(
        "[package]\n\
         name = \"oauth2-social-login\"\n\
         version = \"0.6.2\"\n\
         edition = \"2021\"\n\
         rust-version.workspace = true\n\
         \n\
         [dependencies]\n\
         reqwest = {{ version = \"0.13\", default-features = false, features = [\"json\"] }}\n\
         {comment}reqwest-tracing = {{ version = \"0.7.1\", default-features = false, features = [{feature_list}] }}\n"
    );
    fs::write(member.join("Cargo.toml"), member_manifest).unwrap();
    dir.to_path_buf()
}

#[test]
fn resolved_otel_family_is_single_row_and_coherent() {
    let lock = workspace_root().join("Cargo.lock");
    let versions = lock_versions(&lock);

    let mut failures = Vec::new();
    for name in [
        "opentelemetry",
        "opentelemetry_sdk",
        "opentelemetry-otlp",
        "opentelemetry-proto",
    ] {
        match versions.get(name) {
            None => failures.push(format!("{name}: not present in Cargo.lock")),
            Some(vs) => {
                if vs.len() != 1 {
                    failures.push(format!(
                        "{name}: {} resolved versions {vs:?} — the OTel family must \
                         resolve to a single row (a split graph silently drops \
                         traceparent and/or breaks trait impls)",
                        vs.len()
                    ));
                    continue;
                }
                let got = minor_of(&vs[0]);
                if got != EXPECTED_MINOR {
                    failures.push(format!(
                        "{name}: resolved {} (minor {got}) but the supported, \
                         reqwest-tracing-compatible family requires minor {EXPECTED_MINOR}",
                        vs[0]
                    ));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "OpenTelemetry resolved-dependency family is incoherent:\n  - {}",
        failures.join("\n  - ")
    );
}

#[test]
fn tracing_opentelemetry_pairs_with_pinned_family() {
    // tracing-opentelemetry is versioned one ahead: opentelemetry 0.32 pairs
    // with tracing-opentelemetry 0.33 (0.34 pairs with 0.33).
    let lock = workspace_root().join("Cargo.lock");
    let versions = lock_versions(&lock);
    let rows = versions
        .get("tracing-opentelemetry")
        .unwrap_or_else(|| panic!("tracing-opentelemetry absent from Cargo.lock"));
    assert_eq!(
        rows.len(),
        1,
        "tracing-opentelemetry must resolve to exactly one row, got {rows:?}"
    );
    assert_eq!(
        minor_of(&rows[0]),
        "0.33",
        "tracing-opentelemetry resolved to {} but must be 0.33 to pair with \
         opentelemetry 0.32",
        rows[0]
    );
}

#[test]
fn social_login_selects_reqwest_tracing_feature_matching_resolved_family() {
    match check_social_login_selection(&workspace_root()) {
        Ok(actual) => {
            let _ = actual;
        }
        Err(e) => panic!("{e}"),
    }
}

/// Regression: a comment that merely *mentions* the expected feature name must
/// not make the guard pass when the actual feature selection is absent.
///
/// This calls the production guard (`check_social_login_selection`) on a real
/// tempfile workspace fixture that retains the comment but declares
/// `features = []`. The raw-text technique the guard replaced is modelled here
/// only as the negative control it must not be fooled by; the guard's own
/// predicate is exercised by the same call as the real workspace test.
#[test]
fn comments_cannot_rescue_a_missing_actual_selection() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = write_social_login_fixture(dir.path(), &[], true);

    // The raw-text predicate the guard used to rely on *is* fooled by the
    // comment; this is exactly the false-pass corner.
    let manifest = fs::read_to_string(root.join("crates/oauth2-social-login/Cargo.toml")).unwrap();
    assert!(
        manifest.contains("opentelemetry_0_32"),
        "fixture must retain the comment mentioning the feature name"
    );

    let result = check_social_login_selection(&root);
    let err = result.expect_err(
        "the guard must fail closed on a comment-preserving missing selection; a raw-text \
         matcher would false-pass here",
    );
    assert!(
        err.contains("missing selection"),
        "failure must name the missing actual selection, got: {err}"
    );
}

/// Regression: only the exact token satisfies the selection. A prefix-superset
/// or wrong-family token must not. Calls the SAME guard as production on real
/// fixtures, so a reverted guard breaks this test.
#[test]
fn prefix_and_wrong_tokens_do_not_satisfy_the_selection() {
    let dir = tempfile::tempdir().expect("tempdir");
    for features in [
        vec!["opentelemetry_0_32_bogus"],
        vec!["opentelemetry_0_33"],
        vec![],
    ] {
        let root = write_social_login_fixture(dir.path(), &features, true);
        let err = check_social_login_selection(&root).expect_err(&format!(
            "selection {features:?} must not satisfy the guard"
        ));
        assert!(
            err.starts_with("missing selection"),
            "selection {features:?} must fail specifically for the missing selection, got: {err}"
        );
    }
}

/// Positive control: the exact production selection passes the same guard.
#[test]
fn exact_production_selection_passes_the_guard() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = write_social_login_fixture(dir.path(), &["opentelemetry_0_32"], true);
    let actual = check_social_login_selection(&root)
        .expect("the exact `opentelemetry_0_32` selection must pass the guard");
    assert!(actual.iter().any(|f| f == "opentelemetry_0_32"));
}
