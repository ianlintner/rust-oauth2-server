//! Compliance report generator for the RFC test suite.
//!
//! Walks `tests/compliance_*.rs`, parses structured `@rfc / @section /
//! @requirement / @level / @url` doc-comment annotations on each
//! `#[actix_web::test]` (or `#[test]`), optionally folds in runtime
//! pass/fail/ignored status from a `cargo test --message-format=json`
//! transcript, and emits three reports:
//!
//! * `docs/compliance/RFC_COMPLIANCE.md`     — published to the docs site
//! * `target/compliance-report.json`         — machine-readable artifact
//! * `target/compliance-junit.xml`           — JUnit XML for CI integrations
//!
//! Usage
//! -----
//! ```text
//! # Just regenerate Markdown / JSON / JUnit from source annotations:
//! cargo run --bin compliance_report
//!
//! # Fold in real test results:
//! cargo test --tests --no-fail-fast -- -Z unstable-options \
//!     --format json --report-time | tee target/compliance-tests.jsonl
//! cargo run --bin compliance_report -- --results target/compliance-tests.jsonl
//!
//! # Stable Rust alternative (libtest-mimic / test harness):
//! CARGO_TERM_COLOR=never cargo test --tests --no-fail-fast \
//!     -- --format=json -Zunstable-options 2> /dev/null \
//!     > target/compliance-tests.jsonl || true
//! cargo run --bin compliance_report -- --results target/compliance-tests.jsonl
//! ```
//!
//! Design notes
//! ------------
//! Pure stdlib + `serde_json` — no `syn`, `regex`, or proc-macro deps.
//! Annotation extraction is line-oriented and tolerant of formatting
//! variations (leading whitespace, indented `///`).

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

// -----------------------------------------------------------------------------
// Data model
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize)]
struct Annotation {
    /// Function name as written in source (e.g. `rfc6749_s4_1_1_authorize_requires_response_type`).
    test_name: String,
    /// Source file relative to repo root (e.g. `tests/compliance_rfc6749.rs`).
    source_file: String,
    /// 1-indexed line number of the `fn` declaration.
    source_line: usize,
    /// Cargo test target name (e.g. `compliance_rfc6749`). Used to build the
    /// fully qualified test path that libtest reports in JSON output.
    test_target: String,
    /// RFC number (e.g. `"6749"`).
    rfc: String,
    /// Section within the RFC (e.g. `"4.1.1"`).
    section: String,
    /// Plain-language requirement string (one line).
    requirement: String,
    /// RFC 2119 keyword: `"MUST" | "SHOULD" | "MAY"` (uppercase).
    level: String,
    /// Direct link to the relevant RFC section.
    url: String,
    /// `true` if the test is gated with `#[ignore]`. Reason captured separately.
    ignored: bool,
    /// Reason from `#[ignore = "..."]`, if any.
    ignore_reason: Option<String>,
    /// Resolved status from cargo test JSON (`"passed"`, `"failed"`,
    /// `"ignored"`, or `"unknown"` when no results file was provided).
    status: String,
}

#[derive(Default)]
struct ResultsMap {
    /// `compliance_rfc6749::rfc6749_s4_1_1_authorize_requires_response_type` ->
    /// `"ok" | "failed" | "ignored"`.
    by_full_name: BTreeMap<String, String>,
}

// -----------------------------------------------------------------------------
// Source parsing
// -----------------------------------------------------------------------------

/// Parse a single test file and return all annotated test functions.
///
/// Annotations are recognised when at least `@rfc` and `@section` tags are
/// present in the contiguous `///` comment block immediately above the
/// `#[actix_web::test]` / `#[test]` attribute on a `fn` declaration.
fn parse_source_file(path: &Path) -> Vec<Annotation> {
    let Ok(contents) = fs::read_to_string(path) else {
        return Vec::new();
    };

    let source_file = path
        .strip_prefix(repo_root())
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");

    let test_target = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();

    let mut out = Vec::new();
    let mut doc_buffer: Vec<String> = Vec::new();
    let mut saw_test_attr = false;
    let mut ignored = false;
    let mut ignore_reason: Option<String> = None;

    for (idx, raw_line) in contents.lines().enumerate() {
        let trimmed = raw_line.trim_start();

        if let Some(rest) = trimmed.strip_prefix("///") {
            // Inside a doc-comment block: accumulate.
            doc_buffer.push(rest.trim_start().to_string());
            continue;
        }

        if trimmed.starts_with("#[") {
            // Attribute line. Track #[test] / #[actix_web::test] / #[ignore].
            if trimmed.starts_with("#[test]")
                || trimmed.starts_with("#[actix_web::test]")
                || trimmed.starts_with("#[tokio::test")
            {
                saw_test_attr = true;
            }
            if trimmed.starts_with("#[ignore") {
                ignored = true;
                if let Some(eq_pos) = trimmed.find('=') {
                    let after_eq = &trimmed[eq_pos + 1..];
                    if let Some(start) = after_eq.find('"') {
                        if let Some(end_rel) = after_eq[start + 1..].find('"') {
                            ignore_reason =
                                Some(after_eq[start + 1..start + 1 + end_rel].to_string());
                        }
                    }
                }
            }
            continue;
        }

        if trimmed.starts_with("fn ") || trimmed.starts_with("async fn ") {
            if saw_test_attr {
                if let Some(name) = extract_fn_name(trimmed) {
                    if let Some(ann) = build_annotation(
                        &doc_buffer,
                        name,
                        idx + 1,
                        &source_file,
                        &test_target,
                        ignored,
                        ignore_reason.clone(),
                    ) {
                        out.push(ann);
                    }
                }
            }
            // Reset for next item regardless of whether we matched.
            doc_buffer.clear();
            saw_test_attr = false;
            ignored = false;
            ignore_reason = None;
            continue;
        }

        // Any other non-blank line breaks the doc-buffer association.
        if !trimmed.is_empty() {
            doc_buffer.clear();
            saw_test_attr = false;
            ignored = false;
            ignore_reason = None;
        }
    }

    out
}

fn extract_fn_name(line: &str) -> Option<String> {
    // Strip leading "async fn " or "fn " and read identifier up to '('.
    let after_keyword = match line.strip_prefix("async fn ") {
        Some(rest) => rest,
        None => line.strip_prefix("fn ")?,
    };
    let name: String = after_keyword
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn build_annotation(
    doc_buffer: &[String],
    fn_name: String,
    fn_line: usize,
    source_file: &str,
    test_target: &str,
    ignored: bool,
    ignore_reason: Option<String>,
) -> Option<Annotation> {
    let mut rfc = None;
    let mut section = None;
    let mut requirement = None;
    let mut level = None;
    let mut url = None;

    for line in doc_buffer {
        let line = line.trim();
        let Some(rest) = line.strip_prefix('@') else {
            continue;
        };
        let (key, value) = match rest.split_once(char::is_whitespace) {
            Some(pair) => pair,
            None => continue,
        };
        let value = value.trim().to_string();
        match key {
            "rfc" => rfc = Some(value),
            "section" => section = Some(value),
            "requirement" => requirement = Some(value),
            "level" => level = Some(value.to_uppercase()),
            "url" => url = Some(value),
            _ => {}
        }
    }

    // Require at minimum @rfc + @section, otherwise this isn't a tagged test.
    let rfc = rfc?;
    let section = section?;

    Some(Annotation {
        test_name: fn_name,
        source_file: source_file.to_string(),
        source_line: fn_line,
        test_target: test_target.to_string(),
        rfc,
        section,
        requirement: requirement.unwrap_or_default(),
        level: level.unwrap_or_else(|| "MUST".to_string()),
        url: url.unwrap_or_default(),
        ignored,
        ignore_reason,
        // Filled in later when results are folded in.
        status: "unknown".to_string(),
    })
}

// -----------------------------------------------------------------------------
// Cargo test JSON parsing
// -----------------------------------------------------------------------------

fn parse_results_file(path: &Path) -> ResultsMap {
    let mut map = ResultsMap::default();
    let Ok(contents) = fs::read_to_string(path) else {
        eprintln!(
            "warning: could not read results file {} — falling back to status=unknown",
            path.display()
        );
        return map;
    };
    // Heuristically detect format: nightly libtest emits JSONL, stable emits
    // pretty text lines (`test <name> ... ok`). We parse whichever appears.
    let looks_like_json = contents
        .lines()
        .find(|l| !l.trim().is_empty())
        .map(|l| l.trim_start().starts_with('{'))
        .unwrap_or(false);

    if looks_like_json {
        parse_results_jsonl(&contents, &mut map);
    } else {
        parse_results_pretty(&contents, &mut map);
    }
    map
}

fn parse_results_jsonl(contents: &str, map: &mut ResultsMap) {
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // libtest JSON event:  {"type":"test","event":"ok","name":"<crate>::<fn>"}
        let Ok(json) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if json.get("type").and_then(|v| v.as_str()) != Some("test") {
            continue;
        }
        let Some(name) = json.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(event) = json.get("event").and_then(|v| v.as_str()) else {
            continue;
        };
        let status = match event {
            "ok" => "passed",
            "failed" => "failed",
            "ignored" => "ignored",
            _ => continue,
        };
        map.by_full_name
            .insert(name.to_string(), status.to_string());
    }
}

/// Parse stable libtest "pretty" format:
///
/// ```text
/// test rfc6749_s4_1_1_authorize_requires_response_type ... ok
/// test some::other::test ... FAILED
/// test foo ... ignored
/// ```
///
/// Tests that print to stdout while running can interleave their output
/// between `test <name> ... ` and the trailing status token, splitting the
/// status onto a later line:
///
/// ```text
/// test test_vector_q_jar_request_parameter ... interleaved stdout
/// ok
/// ```
///
/// We track a `pending_name` for any `test <name> ... ` line whose suffix
/// did NOT contain a recognised status token, and resolve it on the next
/// bare `ok|FAILED|ignored` line.
///
/// Test names lack the crate prefix in stable pretty output (e.g.
/// `rfc6749_s4_1_1_…` instead of `compliance_rfc6749::rfc6749_s4_1_1_…`),
/// so we record them under the bare name and reconcile downstream.
fn parse_results_pretty(contents: &str, map: &mut ResultsMap) {
    let mut pending_name: Option<String> = None;
    for line in contents.lines() {
        let trimmed = line.trim();

        // Resolve a previously deferred status if this line is a bare token.
        if let Some(name) = pending_name.take() {
            let token = trimmed
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_end_matches(',');
            if let Some(status) = match_status_token(token) {
                map.by_full_name.insert(name, status.to_string());
                continue;
            }
            // Otherwise drop the pending name; the test output is malformed
            // for our purposes and the test will surface as `unknown`.
        }

        let Some(rest) = trimmed.strip_prefix("test ") else {
            continue;
        };
        let Some((name, after)) = rest.split_once(" ... ") else {
            continue;
        };
        // `after` may look like "ok", "FAILED", "ignored", "ok (1.23s)",
        // or — when the test wrote to stdout mid-run — arbitrary user
        // output with the real status on a later line.
        let status_token = after
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_end_matches(',');
        match match_status_token(status_token) {
            Some(status) => {
                map.by_full_name
                    .insert(name.trim().to_string(), status.to_string());
            }
            None => {
                // Defer until we see a bare ok/FAILED/ignored on a later line.
                pending_name = Some(name.trim().to_string());
            }
        }
    }
}

fn match_status_token(token: &str) -> Option<&'static str> {
    match token.to_ascii_lowercase().as_str() {
        "ok" => Some("passed"),
        "failed" => Some("failed"),
        "ignored" => Some("ignored"),
        _ => None,
    }
}

fn fill_status(annotations: &mut [Annotation], results: &ResultsMap) {
    for ann in annotations.iter_mut() {
        // Nightly libtest JSON reports `<target>::<fn_name>`; stable pretty
        // output uses just `<fn_name>`. Try both.
        let qualified = format!("{}::{}", ann.test_target, ann.test_name);
        if let Some(s) = results.by_full_name.get(&qualified) {
            ann.status.clone_from(s);
        } else if let Some(s) = results.by_full_name.get(&ann.test_name) {
            ann.status.clone_from(s);
        } else if ann.ignored {
            // No results entry — fall back to attribute-only status.
            ann.status = "ignored".to_string();
        }
    }
}

// -----------------------------------------------------------------------------
// Output: Markdown
// -----------------------------------------------------------------------------

fn render_markdown(annotations: &[Annotation], have_results: bool) -> String {
    let mut grouped: BTreeMap<String, Vec<&Annotation>> = BTreeMap::new();
    for ann in annotations {
        grouped.entry(ann.rfc.clone()).or_default().push(ann);
    }
    // Sort RFC groups: numeric RFCs ascending → OIDC specs (alpha) → drafts (alpha) → other.
    let mut rfc_order: Vec<String> = grouped.keys().cloned().collect();
    rfc_order.sort_by_key(|a| rfc_sort_key(a));

    let mut out = String::new();
    out.push_str("# RFC Compliance Matrix\n\n");
    out.push_str(
        "_This file is generated by `cargo run --bin compliance_report`. \
         Do not edit by hand — re-run the generator to regenerate._\n\n",
    );

    // Top-level summary
    let total = annotations.len();
    let passed = annotations.iter().filter(|a| a.status == "passed").count();
    let failed = annotations.iter().filter(|a| a.status == "failed").count();
    let ignored = annotations.iter().filter(|a| a.status == "ignored").count();
    let unknown = annotations.iter().filter(|a| a.status == "unknown").count();

    out.push_str("## Summary\n\n");
    out.push_str(&format!("- **Total annotated tests:** {total}\n"));
    if have_results {
        out.push_str(&format!("- **Passing:** {passed}\n"));
        out.push_str(&format!("- **Failing:** {failed}\n"));
        out.push_str(&format!("- **Ignored:** {ignored}\n"));
        if unknown > 0 {
            out.push_str(&format!("- **Unknown (no result reported):** {unknown}\n"));
        }
        let denom = (passed + failed + ignored).max(1);
        let score = (passed * 100) / denom;
        out.push_str(&format!(
            "- **Compliance score (passed / passed+failed+ignored):** {score}%\n"
        ));
    } else {
        out.push_str("- _Run with `--results <jsonl>` to fold in `cargo test` outcomes._\n");
    }
    out.push('\n');

    // Per-RFC tables
    for rfc in &rfc_order {
        let entries = &grouped[rfc];
        out.push_str(&format!("## {}\n\n", rfc_heading(rfc)));
        out.push_str("| Status | Section | Level | Requirement | Test |\n");
        out.push_str("|---|---|---|---|---|\n");
        let mut sorted = entries.clone();
        sorted.sort_by(|a, b| {
            section_sort_key(&a.section)
                .cmp(&section_sort_key(&b.section))
                .then(a.test_name.cmp(&b.test_name))
        });
        for ann in sorted {
            let status_emoji = match ann.status.as_str() {
                "passed" => "✅",
                "failed" => "❌",
                "ignored" => "⚠️",
                _ => "·",
            };
            let section_link = if ann.url.is_empty() {
                format!("§{}", ann.section)
            } else {
                format!("[§{}]({})", ann.section, ann.url)
            };
            // Render test name as bare code with file location appended.
            // Avoids broken relative links under `mkdocs strict: true` while
            // staying useful when reading the file directly on GitHub.
            let test_link = format!(
                "`{}` <br/><sub>{}:{}</sub>",
                ann.test_name, ann.source_file, ann.source_line
            );
            let level = if ann.level.is_empty() {
                "—".to_string()
            } else {
                ann.level.clone()
            };
            let mut req = escape_md_table_cell(&ann.requirement);
            if ann.ignored {
                if let Some(reason) = &ann.ignore_reason {
                    req.push_str(&format!(" _(ignored: {})_", escape_md_table_cell(reason)));
                } else {
                    req.push_str(" _(ignored)_");
                }
            }
            out.push_str(&format!(
                "| {status_emoji} | {section_link} | {level} | {req} | {test_link} |\n"
            ));
        }
        out.push('\n');
    }

    out.push_str("---\n\n");
    out.push_str(
        "Legend:  \
         ✅ passing test &middot; \
         ❌ failing test &middot; \
         ⚠️ ignored / pending &middot; \
         · status unknown (no test results provided)\n",
    );
    out
}

fn escape_md_table_cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

/// Sort RFC group keys: numeric RFCs ascending, then OIDC specs (alpha),
/// then drafts (alpha), then anything else (alpha). Numeric keys parse into
/// `(0, n, "")`, OIDC keys into `(1, 0, name)`, drafts into `(2, 0, name)`,
/// other strings into `(3, 0, name)`.
fn rfc_sort_key(rfc: &str) -> (u8, u32, String) {
    if let Ok(n) = rfc.parse::<u32>() {
        return (0, n, String::new());
    }
    let lower = rfc.to_ascii_lowercase();
    if lower.starts_with("oidc-") {
        (1, 0, lower)
    } else if lower.starts_with("draft-") {
        (2, 0, lower)
    } else {
        (3, 0, lower)
    }
}

/// Render a friendly per-group heading. Numeric keys become `RFC <n>`;
/// known OIDC family keys get a human label; drafts and unknown strings
/// fall back to a verbatim rendering.
fn rfc_heading(rfc: &str) -> String {
    if rfc.parse::<u32>().is_ok() {
        return format!("RFC {rfc}");
    }
    match rfc {
        "oidc-core-1.0" => "OpenID Connect Core 1.0".to_string(),
        "oidc-discovery-1.0" => "OpenID Connect Discovery 1.0".to_string(),
        "oidc-session-1.0" => "OpenID Connect Session Management 1.0".to_string(),
        "oidc-frontchannel-1.0" => "OpenID Connect Front-Channel Logout 1.0".to_string(),
        "oidc-backchannel-1.0" => "OpenID Connect Back-Channel Logout 1.0".to_string(),
        "oidc-rpinit-1.0" => "OpenID Connect RP-Initiated Logout 1.0".to_string(),
        "oidc-mrt-1.0" => "OAuth 2.0 Multiple Response Type Encoding Practices".to_string(),
        "oidc-registration-1.0" => "OpenID Connect Dynamic Client Registration 1.0".to_string(),
        "draft-ietf-oauth-status-list" => {
            "OAuth 2.0 Token Status List (draft-ietf-oauth-status-list)".to_string()
        }
        other => other.to_string(),
    }
}

/// Sort sections numerically: `4.1.1` before `4.1.2` before `10.5`.
fn section_sort_key(s: &str) -> Vec<u32> {
    s.split('.')
        .map(|part| {
            part.chars()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
        })
        .map(|num| num.parse::<u32>().unwrap_or(u32::MAX))
        .collect()
}

// -----------------------------------------------------------------------------
// Output: JSON
// -----------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct JsonReport<'a> {
    schema_version: u32,
    generated_at: String,
    have_results: bool,
    summary: JsonSummary,
    annotations: &'a [Annotation],
}

#[derive(serde::Serialize)]
struct JsonSummary {
    total: usize,
    passed: usize,
    failed: usize,
    ignored: usize,
    unknown: usize,
    by_rfc: BTreeMap<String, RfcSummary>,
}

#[derive(serde::Serialize)]
struct RfcSummary {
    total: usize,
    passed: usize,
    failed: usize,
    ignored: usize,
    unknown: usize,
}

fn build_json_report<'a>(annotations: &'a [Annotation], have_results: bool) -> JsonReport<'a> {
    let mut by_rfc: BTreeMap<String, RfcSummary> = BTreeMap::new();
    for ann in annotations {
        let entry = by_rfc.entry(ann.rfc.clone()).or_insert(RfcSummary {
            total: 0,
            passed: 0,
            failed: 0,
            ignored: 0,
            unknown: 0,
        });
        entry.total += 1;
        match ann.status.as_str() {
            "passed" => entry.passed += 1,
            "failed" => entry.failed += 1,
            "ignored" => entry.ignored += 1,
            _ => entry.unknown += 1,
        }
    }

    let summary = JsonSummary {
        total: annotations.len(),
        passed: annotations.iter().filter(|a| a.status == "passed").count(),
        failed: annotations.iter().filter(|a| a.status == "failed").count(),
        ignored: annotations.iter().filter(|a| a.status == "ignored").count(),
        unknown: annotations.iter().filter(|a| a.status == "unknown").count(),
        by_rfc,
    };

    // Use a fixed-shape RFC3339 date string without pulling in `chrono`.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let generated_at = format!("unix:{now}");

    JsonReport {
        schema_version: 1,
        generated_at,
        have_results,
        summary,
        annotations,
    }
}

// -----------------------------------------------------------------------------
// Output: JUnit XML
// -----------------------------------------------------------------------------

fn render_junit(annotations: &[Annotation]) -> String {
    let mut by_rfc: BTreeMap<String, Vec<&Annotation>> = BTreeMap::new();
    for ann in annotations {
        by_rfc.entry(ann.rfc.clone()).or_default().push(ann);
    }

    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str("<testsuites name=\"rfc-compliance\">\n");
    let mut rfc_order: Vec<String> = by_rfc.keys().cloned().collect();
    rfc_order.sort_by_key(|a| rfc_sort_key(a));
    for rfc in &rfc_order {
        let tests = &by_rfc[rfc];
        let total = tests.len();
        let failures = tests.iter().filter(|a| a.status == "failed").count();
        let skipped = tests.iter().filter(|a| a.status == "ignored").count();
        let suite_name = rfc_heading(rfc);
        out.push_str(&format!(
            "  <testsuite name=\"{}\" tests=\"{total}\" failures=\"{failures}\" skipped=\"{skipped}\">\n",
            xml_escape(&suite_name),
        ));
        for ann in tests {
            // For numeric RFCs: `rfc6749.section_4_1_1`. For named specs:
            // `oidc-core-1.0.section_3_1_2_1`.
            let classname_prefix = if ann.rfc.parse::<u32>().is_ok() {
                format!("rfc{}", ann.rfc)
            } else {
                ann.rfc.clone()
            };
            let classname = format!(
                "{}.section_{}",
                classname_prefix,
                ann.section.replace('.', "_")
            );
            out.push_str(&format!(
                "    <testcase classname=\"{}\" name=\"{}\">\n",
                xml_escape(&classname),
                xml_escape(&ann.test_name)
            ));
            match ann.status.as_str() {
                "failed" => {
                    out.push_str(&format!(
                        "      <failure message=\"{}\">{}</failure>\n",
                        xml_escape(&format!(
                            "RFC {} §{} failing: {}",
                            ann.rfc, ann.section, ann.requirement
                        )),
                        xml_escape(&ann.url),
                    ));
                }
                "ignored" => {
                    let msg = ann
                        .ignore_reason
                        .as_deref()
                        .unwrap_or("test marked #[ignore]");
                    out.push_str(&format!(
                        "      <skipped message=\"{}\"/>\n",
                        xml_escape(msg)
                    ));
                }
                "unknown" => {
                    out.push_str(
                        "      <skipped message=\"no test results provided to compliance_report\"/>\n",
                    );
                }
                _ => {}
            }
            // Embed the RFC link as system-out for downstream tooling.
            if !ann.url.is_empty() {
                out.push_str(&format!(
                    "      <system-out>{}</system-out>\n",
                    xml_escape(&ann.url)
                ));
            }
            out.push_str("    </testcase>\n");
        }
        out.push_str("  </testsuite>\n");
    }
    out.push_str("</testsuites>\n");
    out
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

// -----------------------------------------------------------------------------
// Filesystem helpers
// -----------------------------------------------------------------------------

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is set when running via cargo. Falls back to CWD.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn discover_test_files(tests_dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(tests_dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // Anything that *might* contain RFC annotations. The parser ignores
        // files with no @rfc/@section tags, so this is a cheap pre-filter.
        if !name.ends_with(".rs") {
            continue;
        }
        // Anything that *might* contain RFC annotations. The parser ignores
        // files with no @rfc/@section tags, so this is a cheap pre-filter.
        // Patterns: `compliance_*.rs`, `rfc*.rs` (e.g. `rfc8252_native_apps.rs`),
        // `rfc_compliance.rs`, and `phase*_rfc_compliance.rs`.
        let is_compliance_like = name.starts_with("compliance_")
            || name.starts_with("rfc")
            || name == "rfc_compliance.rs"
            || (name.starts_with("phase") && name.contains("_rfc_"));
        if is_compliance_like {
            out.push(path);
        }
    }
    out.sort();
    out
}

fn write_file(path: &Path, contents: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = fs::File::create(path)?;
    f.write_all(contents.as_bytes())?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Entry point
// -----------------------------------------------------------------------------

struct Args {
    results: Option<PathBuf>,
    markdown_out: PathBuf,
    json_out: PathBuf,
    junit_out: PathBuf,
}

fn parse_args() -> Args {
    let root = repo_root();
    let mut results = None;
    let mut markdown_out = root.join("docs/compliance/RFC_COMPLIANCE.md");
    let mut json_out = root.join("target/compliance-report.json");
    let mut junit_out = root.join("target/compliance-junit.xml");

    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--results" => {
                i += 1;
                if let Some(v) = argv.get(i) {
                    results = Some(PathBuf::from(v));
                }
            }
            "--markdown" => {
                i += 1;
                if let Some(v) = argv.get(i) {
                    markdown_out = PathBuf::from(v);
                }
            }
            "--json" => {
                i += 1;
                if let Some(v) = argv.get(i) {
                    json_out = PathBuf::from(v);
                }
            }
            "--junit" => {
                i += 1;
                if let Some(v) = argv.get(i) {
                    junit_out = PathBuf::from(v);
                }
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            _ => {
                eprintln!("warning: unknown argument: {}", argv[i]);
            }
        }
        i += 1;
    }

    Args {
        results,
        markdown_out,
        json_out,
        junit_out,
    }
}

fn print_help() {
    println!(
        "compliance_report — generate RFC compliance reports from annotated tests\n\n\
         USAGE:\n    \
         cargo run --bin compliance_report -- [OPTIONS]\n\n\
         OPTIONS:\n    \
         --results <FILE>     libtest JSONL output from `cargo test --format json`\n    \
         --markdown <PATH>    Markdown output (default: docs/compliance/RFC_COMPLIANCE.md)\n    \
         --json <PATH>        JSON output     (default: target/compliance-report.json)\n    \
         --junit <PATH>       JUnit XML       (default: target/compliance-junit.xml)\n    \
         --help               Show this help"
    );
}

fn main() -> ExitCode {
    let args = parse_args();
    let root = repo_root();
    let tests_dir = root.join("tests");

    let files = discover_test_files(&tests_dir);
    if files.is_empty() {
        eprintln!(
            "error: no candidate test files found in {}",
            tests_dir.display()
        );
        return ExitCode::FAILURE;
    }

    let mut annotations: Vec<Annotation> = Vec::new();
    for path in &files {
        annotations.extend(parse_source_file(path));
    }

    let have_results = args.results.is_some();
    if let Some(results_path) = &args.results {
        let results = parse_results_file(results_path);
        fill_status(&mut annotations, &results);
    } else {
        // No results file: pre-mark `#[ignore]`d tests as ignored, leave others unknown.
        for ann in annotations.iter_mut() {
            if ann.ignored {
                ann.status = "ignored".to_string();
            }
        }
    }

    if annotations.is_empty() {
        eprintln!(
            "error: scanned {} files but found zero `@rfc`-tagged tests",
            files.len()
        );
        return ExitCode::FAILURE;
    }

    let md = render_markdown(&annotations, have_results);
    let json_report = build_json_report(&annotations, have_results);
    let json = serde_json::to_string_pretty(&json_report).expect("serialize JSON report");
    let xml = render_junit(&annotations);

    if let Err(e) = write_file(&args.markdown_out, &md) {
        eprintln!("error writing {}: {e}", args.markdown_out.display());
        return ExitCode::FAILURE;
    }
    if let Err(e) = write_file(&args.json_out, &json) {
        eprintln!("error writing {}: {e}", args.json_out.display());
        return ExitCode::FAILURE;
    }
    if let Err(e) = write_file(&args.junit_out, &xml) {
        eprintln!("error writing {}: {e}", args.junit_out.display());
        return ExitCode::FAILURE;
    }

    println!(
        "compliance_report: {} annotated tests across {} files",
        annotations.len(),
        files.len()
    );
    println!("  markdown -> {}", args.markdown_out.display());
    println!("  json     -> {}", args.json_out.display());
    println!("  junit    -> {}", args.junit_out.display());

    ExitCode::SUCCESS
}
