// End-to-end tests for the `iso9660` binary.
//
// Exercises every subcommand and the main.rs dispatch / error paths by
// invoking the compiled binary against the real sample ISO images.

use assert_cmd::Command;
use predicates::prelude::*;

/// Path to a sample ISO in the sibling `iso` crate's test data.
fn iso(name: &str) -> String {
    format!("{}/../iso/tests/data/{}", env!("CARGO_MANIFEST_DIR"), name)
}

fn bin() -> Command {
    Command::cargo_bin("iso9660").unwrap()
}

fn rr_exists() -> bool {
    std::path::Path::new(&iso("rock_ridge.iso")).exists()
}

// ── top-level ─────────────────────────────────────────────────────────────────

#[test]
fn help_prints_usage() {
    bin().arg("--help").assert().success()
        .stdout(predicate::str::contains("Forensic inspection"));
}

#[test]
fn version_prints() {
    bin().arg("--version").assert().success()
        .stdout(predicate::str::contains("iso9660"));
}

#[test]
fn no_args_is_error() {
    bin().assert().failure();
}

#[test]
fn unknown_subcommand_is_error() {
    bin().arg("frobnicate").assert().failure();
}

// ── info ──────────────────────────────────────────────────────────────────────

#[test]
fn info_valid_iso_exits_zero() {
    if !rr_exists() { return; }
    bin().args(["info", &iso("rock_ridge.iso")]).assert().success()
        .stdout(predicate::str::contains("ROCK_RIDGE"))
        .stdout(predicate::str::contains("Rock Ridge"))
        .stdout(predicate::str::contains("Boot Catalog"));
}

#[test]
fn info_missing_file_is_error() {
    bin().args(["info", "/nonexistent/xyz.iso"]).assert().failure()
        .stderr(predicate::str::contains("cannot open"));
}

#[test]
fn info_not_an_iso_is_error() {
    // A real file that is not an ISO.
    bin().args(["info", env!("CARGO_MANIFEST_DIR")]).assert().failure();
}

// ── ls ────────────────────────────────────────────────────────────────────────

#[test]
fn ls_lists_root() {
    if !rr_exists() { return; }
    bin().args(["ls", &iso("rock_ridge.iso")]).assert().success()
        .stdout(predicate::str::contains("hello.txt"))
        .stdout(predicate::str::contains("subdir"));
}

#[test]
fn ls_recursive() {
    if !rr_exists() { return; }
    bin().args(["ls", &iso("rock_ridge.iso"), "-R"]).assert().success()
        .stdout(predicate::str::contains("subdir/deep.txt"));
}

#[test]
fn ls_subdir_path() {
    if !rr_exists() { return; }
    bin().args(["ls", &iso("rock_ridge.iso"), "subdir"]).assert().success()
        .stdout(predicate::str::contains("deep.txt"));
}

#[test]
fn ls_missing_path_errors() {
    if !rr_exists() { return; }
    bin().args(["ls", &iso("rock_ridge.iso"), "nope"]).assert().failure();
}

// ── extract (x / e) ─────────────────────────────────────────────────────────

#[test]
fn x_to_stdout() {
    if !rr_exists() { return; }
    bin().args(["x", &iso("rock_ridge.iso"), "hello.txt", "--stdout"])
        .assert().success()
        .stdout(predicate::str::contains("hello from iso corpus"));
}

#[test]
fn x_to_output_dir() {
    if !rr_exists() { return; }
    let dir = tempfile::tempdir().unwrap();
    bin().args(["x", &iso("rock_ridge.iso"), "hello.txt",
                "-C", dir.path().to_str().unwrap()])
        .assert().success();
    let content = std::fs::read_to_string(dir.path().join("hello.txt")).unwrap();
    assert!(content.contains("hello from iso corpus"));
}

#[test]
fn x_stdout_multiple_files_errors() {
    if !rr_exists() { return; }
    // Extract-all to stdout is ambiguous -> error.
    bin().args(["x", &iso("rock_ridge.iso"), "--stdout"]).assert().failure();
}

#[test]
fn x_missing_path_errors() {
    if !rr_exists() { return; }
    bin().args(["x", &iso("rock_ridge.iso"), "nope.txt", "--stdout"]).assert().failure();
}

#[test]
fn e_flat_to_output_dir() {
    if !rr_exists() { return; }
    let dir = tempfile::tempdir().unwrap();
    bin().args(["e", &iso("rock_ridge.iso"), "subdir/deep.txt",
                "-C", dir.path().to_str().unwrap()])
        .assert().success();
    // Flat: stored as deep.txt, not subdir/deep.txt
    assert!(dir.path().join("deep.txt").exists());
}

// ── hexdump ───────────────────────────────────────────────────────────────────

#[test]
fn hexdump_default_lba() {
    if !rr_exists() { return; }
    bin().args(["hexdump", &iso("rock_ridge.iso")]).assert().success()
        .stdout(predicate::str::contains("CD001").or(predicate::str::contains("43 44 30 30 31")));
}

#[test]
fn hexdump_explicit_lba() {
    if !rr_exists() { return; }
    bin().args(["hexdump", &iso("rock_ridge.iso"), "--lba", "16"]).assert().success()
        .stdout(predicate::str::contains("Sector 16"));
}

// ── audit ─────────────────────────────────────────────────────────────────────

#[test]
fn audit_clean_iso() {
    if !rr_exists() { return; }
    bin().args(["audit", &iso("rock_ridge.iso")]).assert().success()
        .stdout(predicate::str::contains("Forensic Audit"))
        .stdout(predicate::str::contains("[PASS]"))
        .stdout(predicate::str::contains("Result:"));
}

// ── map ───────────────────────────────────────────────────────────────────────

#[test]
fn map_renders() {
    if !rr_exists() { return; }
    bin().args(["map", &iso("rock_ridge.iso")]).assert().success()
        .stdout(predicate::str::contains("Sector Map"))
        .stdout(predicate::str::contains("PVD"));
}

// ── timeline ──────────────────────────────────────────────────────────────────

#[test]
fn timeline_renders() {
    if !rr_exists() { return; }
    bin().args(["timeline", &iso("rock_ridge.iso")]).assert().success()
        .stdout(predicate::str::contains("TIMESTAMP"))
        .stdout(predicate::str::contains("hello.txt"));
}

// ── hashlist (all formats) ────────────────────────────────────────────────────

#[test]
fn hashlist_default_hashdeep() {
    if !rr_exists() { return; }
    bin().args(["hashlist", &iso("rock_ridge.iso")]).assert().success()
        .stdout(predicate::str::contains("%%%% HASHDEEP"));
}

#[test]
fn hashlist_csv() {
    if !rr_exists() { return; }
    bin().args(["hashlist", &iso("rock_ridge.iso"), "--format", "csv"]).assert().success()
        .stdout(predicate::str::contains("path,size,sha256"));
}

#[test]
fn hashlist_tsv() {
    if !rr_exists() { return; }
    bin().args(["hashlist", &iso("rock_ridge.iso"), "--format", "tsv"]).assert().success()
        .stdout(predicate::str::contains("sha256"));
}

#[test]
fn hashlist_mactime() {
    if !rr_exists() { return; }
    bin().args(["hashlist", &iso("rock_ridge.iso"), "--format", "mactime"]).assert().success()
        .stdout(predicate::str::contains("|"));
}

#[test]
fn hashlist_dfxml() {
    if !rr_exists() { return; }
    bin().args(["hashlist", &iso("rock_ridge.iso"), "--format", "dfxml"]).assert().success()
        .stdout(predicate::str::contains("<dfxml"))
        .stdout(predicate::str::contains("fileobject"));
}

// ── find ──────────────────────────────────────────────────────────────────────

#[test]
fn find_name_glob() {
    if !rr_exists() { return; }
    bin().args(["find", &iso("rock_ridge.iso"), "--name", "*.txt"]).assert().success()
        .stdout(predicate::str::contains("hello.txt"));
}

#[test]
fn find_type_dir() {
    if !rr_exists() { return; }
    bin().args(["find", &iso("rock_ridge.iso"), "--type", "d"]).assert().success()
        .stdout(predicate::str::contains("subdir"));
}

#[test]
fn find_min_size() {
    if !rr_exists() { return; }
    bin().args(["find", &iso("rock_ridge.iso"), "--type", "f", "--min-size", "1"])
        .assert().success();
}

#[test]
fn find_max_size() {
    if !rr_exists() { return; }
    bin().args(["find", &iso("rock_ridge.iso"), "--max-size", "1000000"]).assert().success();
}

// ── grep ──────────────────────────────────────────────────────────────────────

#[test]
fn grep_finds_content() {
    if !rr_exists() { return; }
    bin().args(["grep", &iso("rock_ridge.iso"), "rock"]).assert().success()
        .stdout(predicate::str::contains("rockridge.txt"));
}

#[test]
fn grep_ignore_case() {
    if !rr_exists() { return; }
    bin().args(["grep", &iso("rock_ridge.iso"), "ROCK", "-i"]).assert().success()
        .stdout(predicate::str::contains("rockridge.txt"));
}

#[test]
fn grep_include_glob() {
    if !rr_exists() { return; }
    bin().args(["grep", &iso("rock_ridge.iso"), "rock", "--include", "*.txt"])
        .assert().success();
}

#[test]
fn grep_no_match_empty() {
    if !rr_exists() { return; }
    bin().args(["grep", &iso("rock_ridge.iso"), "zzznotthereatall"]).assert().success()
        .stdout(predicate::str::is_empty());
}
