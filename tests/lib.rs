use cargo_didiuse::{MatchKind, analyze_advisory_db_against_crate, analyze_report_against_crate};
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
};
use tempfile::TempDir;

#[test]
fn extracts_target_functions_from_affects_functions() {
    let temp_dir = TempDir::new().expect("failed to create temporary test directory");
    let crate_root = temp_dir.path().join("consumer");
    create_minimal_crate(&crate_root, "pub fn run() {}");

    let report_path = temp_dir.path().join("report.json");
    write_affects_report(&report_path, &["vulnerablepackage::ExampleStruct::broken"]);

    let result = analyze_report_against_crate(&report_path, &crate_root)
        .expect("analysis should succeed for affects.functions report");

    assert_eq!(
        result.target_functions,
        vec!["vulnerablepackage::ExampleStruct::broken"]
    );
}

#[test]
fn falls_back_to_affected_functions_when_needed() {
    let temp_dir = TempDir::new().expect("failed to create temporary test directory");
    let crate_root = temp_dir.path().join("consumer");
    create_minimal_crate(&crate_root, "pub fn run() {}");

    let report_path = temp_dir.path().join("report.json");
    write_fallback_report(&report_path, &["vulnerablepackage::ExampleStruct::broken"]);

    let result = analyze_report_against_crate(&report_path, &crate_root)
        .expect("analysis should succeed for fallback affected_functions report");

    assert_eq!(
        result.target_functions,
        vec!["vulnerablepackage::ExampleStruct::broken"]
    );
}

#[test]
fn detects_direct_fully_qualified_call() {
    let temp_dir = TempDir::new().expect("failed to create temporary test directory");
    let crate_root = temp_dir.path().join("consumer");
    create_minimal_crate(
        &crate_root,
        r#"
pub fn run() {
    vulnerablepackage::ExampleStruct::broken();
}
"#,
    );

    let report_path = temp_dir.path().join("report.json");
    write_affects_report(&report_path, &["vulnerablepackage::ExampleStruct::broken"]);

    let result = analyze_report_against_crate(&report_path, &crate_root)
        .expect("analysis should succeed for direct call test");

    assert!(result.vulnerable_used);
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].match_kind, MatchKind::DirectPathCall);
    assert_eq!(
        result.findings[0].vulnerable_function,
        "vulnerablepackage::ExampleStruct::broken"
    );
}

#[test]
fn detects_alias_resolved_call() {
    let temp_dir = TempDir::new().expect("failed to create temporary test directory");
    let crate_root = temp_dir.path().join("consumer");
    create_minimal_crate(
        &crate_root,
        r#"
use vulnerablepackage::ExampleStruct;

pub fn run() {
    ExampleStruct::broken();
}
"#,
    );

    let report_path = temp_dir.path().join("report.json");
    write_affects_report(&report_path, &["vulnerablepackage::ExampleStruct::broken"]);

    let result = analyze_report_against_crate(&report_path, &crate_root)
        .expect("analysis should succeed for alias-resolved call test");

    assert!(result.vulnerable_used);
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].match_kind, MatchKind::AliasResolvedCall);
    assert_eq!(result.findings[0].matched_call, "ExampleStruct::broken");
}

#[test]
fn detects_heuristic_method_call_with_imported_type() {
    let temp_dir = TempDir::new().expect("failed to create temporary test directory");
    let crate_root = temp_dir.path().join("consumer");
    create_minimal_crate(
        &crate_root,
        r#"
use vulnerablepackage::ExampleStruct;

pub fn run(item: ExampleStruct) {
    item.broken();
}
"#,
    );

    let report_path = temp_dir.path().join("report.json");
    write_affects_report(&report_path, &["vulnerablepackage::ExampleStruct::broken"]);

    let result = analyze_report_against_crate(&report_path, &crate_root)
        .expect("analysis should succeed for heuristic method-call test");

    assert!(result.vulnerable_used);
    assert_eq!(result.findings.len(), 1);
    assert_eq!(
        result.findings[0].match_kind,
        MatchKind::HeuristicMethodCall
    );
    assert_eq!(
        result.findings[0].vulnerable_function,
        "vulnerablepackage::ExampleStruct::broken"
    );
}

#[test]
fn ignores_non_vulnerable_functions() {
    let temp_dir = TempDir::new().expect("failed to create temporary test directory");
    let crate_root = temp_dir.path().join("consumer");
    create_minimal_crate(
        &crate_root,
        r#"
pub fn run() {
    vulnerablepackage::ExampleStruct::not_broken();
}
"#,
    );

    let report_path = temp_dir.path().join("report.json");
    write_affects_report(&report_path, &["vulnerablepackage::ExampleStruct::broken"]);

    let result = analyze_report_against_crate(&report_path, &crate_root)
        .expect("analysis should succeed for non-vulnerable function test");

    assert!(!result.vulnerable_used);
    assert!(result.findings.is_empty());
}

#[test]
fn integration_myterriblecode_sample_detects_expected_calls() {
    let report_path = PathBuf::from(&format!(
        "{}/test_data/vuln_report.json",
        env!("CARGO_MANIFEST_DIR")
    ));
    let consuming_crate = PathBuf::from(&format!(
        "{}/test_data/test_implementation",
        env!("CARGO_MANIFEST_DIR")
    ));

    let result = analyze_report_against_crate(&report_path, &consuming_crate)
        .expect("analysis should succeed for myterriblecode integration sample");

    assert!(result.vulnerable_used);
    assert!(result.findings.iter().any(|finding| {
        finding.vulnerable_function == "vulnerablepackage::ExampleStruct::broken"
    }));

    assert!(result.findings.iter().any(|finding| {
        finding.file.ends_with("src/lib.rs") && finding.match_kind == MatchKind::DirectPathCall
    }));
    assert!(result.findings.iter().any(|finding| {
        finding.file.ends_with("src/aliasimport.rs")
            && finding.match_kind == MatchKind::AliasResolvedCall
    }));
    assert!(result.findings.iter().any(|finding| {
        finding.file.ends_with("src/used_as_dot.rs")
            && finding.match_kind == MatchKind::HeuristicMethodCall
            && finding.vulnerable_function == "vulnerablepackage::ExampleStruct::dot_broken"
    }));

    let main_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|finding| finding.file.ends_with("src/main.rs"))
        .collect();
    assert_eq!(main_findings.len(), 2);
    assert!(
        main_findings
            .iter()
            .any(|finding| finding.match_kind == MatchKind::AliasResolvedCall)
    );
    assert!(
        main_findings
            .iter()
            .any(|finding| finding.match_kind == MatchKind::HeuristicMethodCall)
    );
}

#[test]
fn integration_workspace_layout_detects_member_crate_usage() {
    let report_path = PathBuf::from(&format!(
        "{}/test_data/vuln_report.json",
        env!("CARGO_MANIFEST_DIR")
    ));
    let workspace_root = PathBuf::from(&format!(
        "{}/test_data/workspace_layout",
        env!("CARGO_MANIFEST_DIR")
    ));

    let result = analyze_report_against_crate(&report_path, &workspace_root)
        .expect("analysis should succeed for workspace root integration sample");

    let workspace_member_source = Path::new("crates")
        .join("consumer")
        .join("src")
        .join("lib.rs");

    assert!(result.vulnerable_used);
    assert!(result.findings.iter().any(|finding| {
        finding.file.ends_with(&workspace_member_source)
            && finding.match_kind == MatchKind::DirectPathCall
            && finding.vulnerable_function == "vulnerablepackage::ExampleStruct::broken"
    }));
}

#[test]
fn loads_targets_from_advisory_db_and_detects_usage() {
    let temp_dir = TempDir::new().expect("failed to create temporary test directory");
    let crate_root = temp_dir.path().join("consumer");
    create_minimal_crate(
        &crate_root,
        r#"
pub fn run() {
    vulnerablepackage::ExampleStruct::broken();
}
"#,
    );
    write_test_lockfile(&crate_root.join("Cargo.lock"), "0.1.0");

    let advisory_db_root = temp_dir.path().join("advisory-db");
    write_advisory_db_entry(
        &advisory_db_root,
        "vulnerablepackage",
        "RUSTSEC-2026-12345",
        "vulnerablepackage::ExampleStruct::broken",
    );

    let result = analyze_advisory_db_against_crate(Some(&advisory_db_root), &crate_root)
        .expect("analysis should succeed for advisory-db mode");

    assert_eq!(
        result.target_functions,
        vec!["vulnerablepackage::ExampleStruct::broken"]
    );
    assert!(result.vulnerable_used);
    assert!(result.findings.iter().any(|finding| {
        finding.vulnerable_function == "vulnerablepackage::ExampleStruct::broken"
            && finding.match_kind == MatchKind::DirectPathCall
    }));
}

#[test]
fn advisory_db_mode_uses_lockfile_versions() {
    let temp_dir = TempDir::new().expect("failed to create temporary test directory");
    let crate_root = temp_dir.path().join("consumer");
    create_minimal_crate(
        &crate_root,
        r#"
pub fn run() {
    vulnerablepackage::ExampleStruct::broken();
}
"#,
    );
    write_test_lockfile(&crate_root.join("Cargo.lock"), "10.0.0");

    let advisory_db_root = temp_dir.path().join("advisory-db");
    write_advisory_db_entry(
        &advisory_db_root,
        "vulnerablepackage",
        "RUSTSEC-2026-12345",
        "vulnerablepackage::ExampleStruct::broken",
    );

    let result = analyze_advisory_db_against_crate(Some(&advisory_db_root), &crate_root)
        .expect("analysis should succeed for advisory-db version filtering test");

    assert!(result.target_functions.is_empty());
    assert!(!result.vulnerable_used);
    assert!(result.findings.is_empty());
}

fn create_minimal_crate(crate_root: &Path, source: &str) {
    write_file(
        &crate_root.join("Cargo.toml"),
        r#"[package]
name = "consumer"
version = "0.1.0"
edition = "2024"
"#,
    );
    write_file(&crate_root.join("src/lib.rs"), source);
}

fn write_affects_report(report_path: &Path, functions: &[&str]) {
    let function_values: Vec<_> = functions.iter().map(|entry| json!(entry)).collect();
    let report = json!({
        "affected": [{
            "ecosystem_specific": {
                "affects": {
                    "functions": function_values
                }
            }
        }]
    });
    write_file(report_path, &report.to_string());
}

fn write_fallback_report(report_path: &Path, functions: &[&str]) {
    let function_values: Vec<_> = functions.iter().map(|entry| json!(entry)).collect();
    let report = json!({
        "affected": [{
            "ecosystem_specific": {
                "affects": {
                    "functions": []
                },
                "affected_functions": function_values
            }
        }]
    });
    write_file(report_path, &report.to_string());
}

fn write_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("failed to create parent directories");
    }
    fs::write(path, contents).expect("failed to write test file");
}

fn write_test_lockfile(lockfile_path: &Path, vulnerable_package_version: &str) {
    let lockfile = format!(
        r#"# This file is automatically @generated by Cargo.
version = 4

[[package]]
name = "consumer"
version = "0.1.0"
dependencies = [
 "vulnerablepackage",
]

[[package]]
name = "vulnerablepackage"
version = "{vulnerable_package_version}"
"#
    );

    write_file(lockfile_path, &lockfile);
}

fn write_advisory_db_entry(
    advisory_db_root: &Path,
    package_name: &str,
    advisory_id: &str,
    function_path: &str,
) {
    let advisory_path = advisory_db_root
        .join("crates")
        .join(package_name)
        .join(format!("{advisory_id}.md"));
    let advisory = format!(
        r#"```toml
id = "{advisory_id}"
package = "{package_name}"
date = "2026-01-01"

[versions]
patched = [">= 9.9.9"]

[affected]
functions = {{ "{function_path}" = ["< 9.9.9"] }}
```

# Test Advisory

Used for integration tests.
"#
    );

    write_file(&advisory_path, &advisory);
}
