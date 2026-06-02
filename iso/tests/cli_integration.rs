// CLI integration tests for `iso9660-forensic inspect`.
// RED phase: tests fail until main.rs is implemented.

use std::path::Path;
use assert_cmd::Command;
use predicates::prelude::*;

fn iso_path(name: &str) -> String {
    format!(
        "{}/tests/data/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    )
}

fn cmd() -> Command {
    Command::cargo_bin("iso9660-forensic").unwrap()
}

// ── Exit codes ────────────────────────────────────────────────────────────────

#[test]
fn inspect_exits_zero_on_valid_iso() {
    cmd()
        .arg("inspect")
        .arg(iso_path("udf_bridge.iso"))
        .assert()
        .success();
}

#[test]
fn inspect_exits_nonzero_on_missing_file() {
    cmd()
        .arg("inspect")
        .arg("/nonexistent/path/nowhere.iso")
        .assert()
        .failure();
}

#[test]
fn inspect_exits_nonzero_on_no_args() {
    cmd()
        .arg("inspect")
        .assert()
        .failure();
}

// ── Output content (udf_bridge.iso) ──────────────────────────────────────────

#[test]
fn inspect_reports_udf_present() {
    cmd()
        .arg("inspect")
        .arg(iso_path("udf_bridge.iso"))
        .assert()
        .success()
        .stdout(predicate::str::contains("UDF").and(
            predicate::str::contains("yes").or(predicate::str::contains("true"))
        ));
}

#[test]
fn inspect_reports_session_count() {
    cmd()
        .arg("inspect")
        .arg(iso_path("udf_bridge.iso"))
        .assert()
        .success()
        .stdout(predicate::str::contains("Session").or(predicate::str::contains("session")));
}

#[test]
fn inspect_reports_sector_mode() {
    cmd()
        .arg("inspect")
        .arg(iso_path("udf_bridge.iso"))
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"(?i)(mode|sector)").unwrap());
}

#[test]
fn inspect_lists_root_directory() {
    cmd()
        .arg("inspect")
        .arg(iso_path("udf_bridge.iso"))
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"(?i)(root|directory|dir)").unwrap());
}

// ── rock_ridge.iso ────────────────────────────────────────────────────────────

#[test]
fn inspect_reports_rock_ridge_present() {
    let rr_iso = iso_path("rock_ridge.iso");
    if !Path::new(&rr_iso).exists() {
        return; // skip if test fixture absent
    }
    cmd()
        .arg("inspect")
        .arg(&rr_iso)
        .assert()
        .success()
        .stdout(predicate::str::contains("Rock Ridge").and(
            predicate::str::contains("yes").or(predicate::str::contains("true"))
        ));
}

// ── --help ────────────────────────────────────────────────────────────────────

#[test]
fn help_flag_prints_usage() {
    cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("inspect"));
}
