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

// ── extract (canonical + x/e aliases) ───────────────────────────────────────

#[test]
fn extract_to_stdout() {
    if !rr_exists() { return; }
    bin().args(["extract", &iso("rock_ridge.iso"), "hello.txt", "--stdout"])
        .assert().success()
        .stdout(predicate::str::contains("hello from iso corpus"));
}

#[test]
fn extract_flat_strips_path() {
    if !rr_exists() { return; }
    let dir = tempfile::tempdir().unwrap();
    bin().args(["extract", &iso("rock_ridge.iso"), "subdir/deep.txt", "--flat",
                "-C", dir.path().to_str().unwrap()])
        .assert().success();
    assert!(dir.path().join("deep.txt").exists());
}

#[test]
fn x_alias_to_stdout() {
    if !rr_exists() { return; }
    bin().args(["x", &iso("rock_ridge.iso"), "hello.txt", "--stdout"])
        .assert().success()
        .stdout(predicate::str::contains("hello from iso corpus"));
}

#[test]
fn x_alias_to_output_dir() {
    if !rr_exists() { return; }
    let dir = tempfile::tempdir().unwrap();
    bin().args(["x", &iso("rock_ridge.iso"), "hello.txt",
                "-C", dir.path().to_str().unwrap()])
        .assert().success();
    let content = std::fs::read_to_string(dir.path().join("hello.txt")).unwrap();
    assert!(content.contains("hello from iso corpus"));
}

#[test]
fn extract_stdout_multiple_files_errors() {
    if !rr_exists() { return; }
    bin().args(["extract", &iso("rock_ridge.iso"), "--stdout"]).assert().failure();
}

#[test]
fn extract_missing_path_errors() {
    if !rr_exists() { return; }
    bin().args(["extract", &iso("rock_ridge.iso"), "nope.txt", "--stdout"]).assert().failure();
}

#[test]
fn e_alias_flat_to_output_dir() {
    if !rr_exists() { return; }
    let dir = tempfile::tempdir().unwrap();
    bin().args(["e", &iso("rock_ridge.iso"), "subdir/deep.txt",
                "-C", dir.path().to_str().unwrap()])
        .assert().success();
    // `e` is shorthand for `extract --flat`: stored as deep.txt, not subdir/deep.txt
    assert!(dir.path().join("deep.txt").exists());
}

// ── hexdump ───────────────────────────────────────────────────────────────────

#[test]
fn dump_default_lba() {
    if !rr_exists() { return; }
    bin().args(["dump", &iso("rock_ridge.iso")]).assert().success()
        .stdout(predicate::str::contains("CD001").or(predicate::str::contains("43 44 30 30 31")));
}

#[test]
fn dump_explicit_lba() {
    if !rr_exists() { return; }
    bin().args(["dump", &iso("rock_ridge.iso"), "--lba", "16"]).assert().success()
        .stdout(predicate::str::contains("Sector 16"));
}

#[test]
fn hexdump_is_not_a_command() {
    // `dump` is the only name; there is no `hexdump` alias.
    bin().args(["hexdump", &iso("rock_ridge.iso")]).assert().failure();
}

#[test]
fn dump_raw_emits_binary_sector() {
    if !rr_exists() { return; }
    let out = bin().args(["dump", &iso("rock_ridge.iso"), "--lba", "16", "--raw"])
        .assert().success();
    let bytes = &out.get_output().stdout;
    assert_eq!(bytes.len(), 2048, "raw dump must be exactly one 2048-byte sector");
    assert_eq!(&bytes[0..6], &[0x01, b'C', b'D', b'0', b'0', b'1']);
}

// ── help / version flags (no redundant `help` subcommand) ─────────────────────

#[test]
fn no_help_subcommand() {
    // The auto-generated `help` subcommand is disabled; `iso9660 help` must
    // error because -h/--help cover it.
    bin().arg("help").assert().failure();
}

#[test]
fn short_help_and_version_flags() {
    bin().arg("-h").assert().success()
        .stdout(predicate::str::contains("Forensic inspection"));
    bin().arg("-V").assert().success()
        .stdout(predicate::str::contains("iso9660"));
}

// ── map ───────────────────────────────────────────────────────────────────────

#[test]
fn map_renders() {
    if !rr_exists() { return; }
    bin().args(["map", &iso("rock_ridge.iso")]).assert().success()
        .stdout(predicate::str::contains("Sector Map"))
        .stdout(predicate::str::contains("PVD"));
}

// ── forensic audit ──────────────────────────────────────────────────────────

#[test]
fn forensic_audit_clean_iso() {
    if !rr_exists() { return; }
    bin().args(["forensic", "audit", &iso("rock_ridge.iso")]).assert().success()
        .stdout(predicate::str::contains("Forensic Audit"))
        .stdout(predicate::str::contains("[PASS]"))
        .stdout(predicate::str::contains("Result:"));
}

// ── forensic timeline ─────────────────────────────────────────────────────────

#[test]
fn forensic_timeline_renders() {
    if !rr_exists() { return; }
    bin().args(["forensic", "timeline", &iso("rock_ridge.iso")]).assert().success()
        .stdout(predicate::str::contains("TIMESTAMP"))
        .stdout(predicate::str::contains("hello.txt"));
}

// ── forensic hash (all formats) ───────────────────────────────────────────────

#[test]
fn forensic_hash_default_hashdeep() {
    if !rr_exists() { return; }
    bin().args(["forensic", "hash", &iso("rock_ridge.iso")]).assert().success()
        .stdout(predicate::str::contains("%%%% HASHDEEP"));
}

#[test]
fn forensic_hash_csv() {
    if !rr_exists() { return; }
    bin().args(["forensic", "hash", &iso("rock_ridge.iso"), "--format", "csv"]).assert().success()
        .stdout(predicate::str::contains("path,size,sha256"));
}

#[test]
fn forensic_hash_tsv() {
    if !rr_exists() { return; }
    bin().args(["forensic", "hash", &iso("rock_ridge.iso"), "--format", "tsv"]).assert().success()
        .stdout(predicate::str::contains("sha256"));
}

#[test]
fn forensic_hash_mactime() {
    if !rr_exists() { return; }
    bin().args(["forensic", "hash", &iso("rock_ridge.iso"), "--format", "mactime"]).assert().success()
        .stdout(predicate::str::contains("|"));
}

#[test]
fn forensic_hash_dfxml() {
    if !rr_exists() { return; }
    bin().args(["forensic", "hash", &iso("rock_ridge.iso"), "--format", "dfxml"]).assert().success()
        .stdout(predicate::str::contains("<dfxml"))
        .stdout(predicate::str::contains("fileobject"));
}

// ── search (metadata mode = find) ─────────────────────────────────────────────

#[test]
fn search_name_glob() {
    if !rr_exists() { return; }
    bin().args(["search", &iso("rock_ridge.iso"), "--name", "*.txt"]).assert().success()
        .stdout(predicate::str::contains("hello.txt"));
}

#[test]
fn search_type_dir() {
    if !rr_exists() { return; }
    bin().args(["search", &iso("rock_ridge.iso"), "--type", "d"]).assert().success()
        .stdout(predicate::str::contains("subdir"));
}

#[test]
fn search_min_size() {
    if !rr_exists() { return; }
    bin().args(["search", &iso("rock_ridge.iso"), "--type", "f", "--min-size", "1"])
        .assert().success();
}

#[test]
fn search_max_size() {
    if !rr_exists() { return; }
    bin().args(["search", &iso("rock_ridge.iso"), "--max-size", "1000000"]).assert().success();
}

// ── search (content mode = grep) ──────────────────────────────────────────────

#[test]
fn search_content_finds_match() {
    if !rr_exists() { return; }
    bin().args(["search", &iso("rock_ridge.iso"), "--content", "rock"]).assert().success()
        .stdout(predicate::str::contains("rockridge.txt"));
}

#[test]
fn search_content_ignore_case() {
    if !rr_exists() { return; }
    bin().args(["search", &iso("rock_ridge.iso"), "--content", "ROCK", "-i"]).assert().success()
        .stdout(predicate::str::contains("rockridge.txt"));
}

#[test]
fn search_content_with_name_include() {
    if !rr_exists() { return; }
    bin().args(["search", &iso("rock_ridge.iso"), "--content", "rock", "--name", "*.txt"])
        .assert().success();
}

#[test]
fn search_content_no_match_empty() {
    if !rr_exists() { return; }
    bin().args(["search", &iso("rock_ridge.iso"), "--content", "zzznotthereatall"]).assert().success()
        .stdout(predicate::str::is_empty());
}

// ── search regex (--name-regex / --content-regex) ─────────────────────────────

#[test]
fn search_name_regex_anchored() {
    if !rr_exists() { return; }
    bin().args(["search", &iso("rock_ridge.iso"), "--name-regex", r"^hello\.txt$"])
        .assert().success()
        .stdout(predicate::str::contains("hello.txt"))
        .stdout(predicate::str::contains("rockridge.txt").not());
}

#[test]
fn search_content_regex_matches() {
    if !rr_exists() { return; }
    // `r.ck` matches "rock" via regex; the literal would not.
    bin().args(["search", &iso("rock_ridge.iso"), "--content-regex", "r.ck"])
        .assert().success()
        .stdout(predicate::str::contains("rockridge.txt"));
}

#[test]
fn search_content_regex_ignore_case() {
    if !rr_exists() { return; }
    bin().args(["search", &iso("rock_ridge.iso"), "--content-regex", "R.CK", "-i"])
        .assert().success()
        .stdout(predicate::str::contains("rockridge.txt"));
}

#[test]
fn search_invalid_regex_errors() {
    if !rr_exists() { return; }
    // Unbalanced bracket is an invalid regex -> friendly error, nonzero exit.
    bin().args(["search", &iso("rock_ridge.iso"), "--content-regex", "["])
        .assert().failure()
        .stderr(predicate::str::contains("invalid regex"));
}

#[test]
fn search_name_and_name_regex_conflict() {
    if !rr_exists() { return; }
    bin().args(["search", &iso("rock_ridge.iso"), "--name", "*.txt", "--name-regex", ".*"])
        .assert().failure();
}
