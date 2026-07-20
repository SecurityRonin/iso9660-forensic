#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Integration tests against committed ISO corpus.
//!
//! All fixtures are in `tests/data/` — provenance in `tests/data/README.md`.
//! Files are produced by independent tools (dfvfs reference corpus, xorriso,
//! hdiutil, exiftool project) so the parser cannot share blind spots with them.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use iso9660_forensic::IsoReader;

const DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data");

fn open(name: &str) -> IsoReader<BufReader<File>> {
    let path = format!("{DATA_DIR}/{name}");
    let f = File::open(Path::new(&path)).unwrap_or_else(|e| panic!("open {name}: {e}"));
    IsoReader::open(BufReader::new(f)).unwrap_or_else(|e| panic!("IsoReader::open {name}: {e}"))
}

// ── dfvfs_plain.iso — pure ISO 9660, no extensions (dfvfs corpus) ─────────────

#[test]
fn dfvfs_plain_opens() {
    let _ = open("dfvfs_plain.iso");
}

#[test]
fn dfvfs_plain_has_no_rock_ridge() {
    assert!(!open("dfvfs_plain.iso").has_rock_ridge());
}

#[test]
fn dfvfs_plain_has_no_joliet() {
    assert!(!open("dfvfs_plain.iso").has_joliet());
}

#[test]
fn dfvfs_plain_single_session() {
    assert_eq!(open("dfvfs_plain.iso").session_count(), 1);
}

#[test]
fn dfvfs_plain_root_dir_has_entries() {
    let mut r = open("dfvfs_plain.iso");
    let entries = r.read_root_dir().expect("read_root_dir");
    assert!(!entries.is_empty(), "dfvfs_plain.iso root dir must not be empty");
}

// ── rock_ridge.iso — ISO 9660 + Rock Ridge (xorriso -r) ──────────────────────

#[test]
fn rock_ridge_opens() {
    let _ = open("rock_ridge.iso");
}

#[test]
fn rock_ridge_detected_in_rock_ridge_iso() {
    assert!(open("rock_ridge.iso").has_rock_ridge(), "rock_ridge.iso must report has_rock_ridge()");
}

#[test]
fn rock_ridge_iso_has_no_joliet() {
    assert!(!open("rock_ridge.iso").has_joliet());
}

#[test]
fn rock_ridge_root_dir_has_entries() {
    let mut r = open("rock_ridge.iso");
    let entries = r.read_root_dir().expect("read_root_dir");
    assert!(!entries.is_empty());
}

// ── joliet.iso — ISO 9660 + Rock Ridge + Joliet (xorriso -J) ─────────────────

#[test]
fn joliet_opens() {
    let _ = open("joliet.iso");
}

#[test]
fn joliet_detected_in_joliet_iso() {
    assert!(open("joliet.iso").has_joliet(), "joliet.iso must report has_joliet()");
}

#[test]
fn joliet_iso_also_has_rock_ridge() {
    // xorriso adds RR by default; Joliet and RR are not mutually exclusive.
    assert!(open("joliet.iso").has_rock_ridge());
}

#[test]
fn joliet_root_dir_has_entries() {
    let mut r = open("joliet.iso");
    let entries = r.read_root_dir().expect("read_root_dir");
    assert!(!entries.is_empty());
}

// ── multisession.iso — 2-session (xorriso append) ────────────────────────────

#[test]
fn multisession_opens() {
    let _ = open("multisession.iso");
}

#[test]
fn multisession_has_multiple_sessions() {
    let r = open("multisession.iso");
    assert!(
        r.session_count() >= 2,
        "multisession.iso must have ≥2 sessions, got {}",
        r.session_count()
    );
}

#[test]
fn multisession_active_session_root_dir_readable() {
    let mut r = open("multisession.iso");
    let entries = r.read_root_dir().expect("read_root_dir on active session");
    assert!(!entries.is_empty());
}

// ── eltorito.iso — El Torito bootable (xorriso -b) ───────────────────────────

#[test]
fn eltorito_opens() {
    let _ = open("eltorito.iso");
}

#[test]
fn eltorito_has_boot_entries() {
    let mut r = open("eltorito.iso");
    let entries = r.boot_entries().expect("boot_entries");
    assert!(!entries.is_empty(), "eltorito.iso must have at least one boot entry");
}

#[test]
fn eltorito_first_entry_is_bootable() {
    let mut r = open("eltorito.iso");
    let entries = r.boot_entries().expect("boot_entries");
    assert!(entries[0].bootable, "first El Torito entry must be marked bootable");
}

// ── udf_bridge.iso — ISO 9660 + Joliet (the UDF side is read by udf-forensic) ─

#[test]
fn udf_bridge_opens() {
    let _ = open("udf_bridge.iso");
}

#[test]
fn udf_bridge_has_joliet() {
    assert!(open("udf_bridge.iso").has_joliet());
}

#[test]
fn udf_bridge_root_dir_readable() {
    let mut r = open("udf_bridge.iso");
    let entries = r.read_root_dir().expect("read_root_dir");
    assert!(!entries.is_empty());
}

// ── truncated.iso — 40 KB file but PVD claims 381 MB (exiftool corpus) ───────
//
// The metadata area (sectors 0–20) is intact; the file content sectors do not
// exist. IsoReader must open it and report the extensions correctly, and must
// never panic regardless of what read_root_dir returns.

#[test]
fn truncated_iso_opens_without_panic() {
    let path = format!("{DATA_DIR}/truncated.iso");
    let f = File::open(Path::new(&path)).expect("open truncated.iso");
    let result = IsoReader::open(BufReader::new(f));
    // open() may succeed or return an error — both are acceptable.
    // What is NOT acceptable is a panic.
    let _ = result;
}

#[test]
fn truncated_iso_joliet_detected_from_svd() {
    // The Joliet SVD lives in sector 18, well within the 40 KB file.
    let path = format!("{DATA_DIR}/truncated.iso");
    let f = File::open(Path::new(&path)).expect("open");
    if let Ok(reader) = IsoReader::open(BufReader::new(f)) {
        assert!(reader.has_joliet(), "truncated.iso has a Joliet SVD in the intact metadata area");
    }
    // If open() itself returns Err that is also acceptable for a truncated image.
}

#[test]
fn truncated_iso_read_root_dir_does_not_panic() {
    // The root dir records may or may not be readable in a 40 KB truncated image.
    // The only requirement is: no panic.
    let path = format!("{DATA_DIR}/truncated.iso");
    let f = File::open(Path::new(&path)).expect("open");
    if let Ok(mut reader) = IsoReader::open(BufReader::new(f)) {
        let _ = reader.read_root_dir(); // Ok or Err, never panic
    }
}

// ── iso9660_1999.iso — ISO 9660:1999 / Enhanced Volume Descriptor (xorriso -iso-level 4) ──
// The EVD shares the type-2 descriptor code with a Joliet SVD but carries
// version byte (BP 7) = 2 and no UCS-2 escape, so it must be distinguished.

#[test]
fn iso9660_1999_opens() {
    let _ = open("iso9660_1999.iso");
}

#[test]
fn iso9660_1999_has_enhanced_vd() {
    assert!(
        open("iso9660_1999.iso").has_enhanced_volume_descriptor(),
        "ISO 9660:1999 carries an Enhanced Volume Descriptor (type 2, version 2)"
    );
}

#[test]
fn iso9660_1999_is_not_joliet() {
    // An EVD has no Joliet UCS-2 escape sequence, so has_joliet() must be false.
    assert!(!open("iso9660_1999.iso").has_joliet());
}

#[test]
fn iso9660_1999_lists_files() {
    let mut r = open("iso9660_1999.iso");
    let root = r.read_root_dir().expect("read_root_dir");
    assert!(
        root.iter().any(|e| e.iso_name().eq_ignore_ascii_case("hello.txt")),
        "root must contain hello.txt: {:?}",
        root.iter().map(|e| e.iso_name()).collect::<Vec<_>>()
    );
}
