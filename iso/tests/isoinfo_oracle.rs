#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Real-artifact, independent-oracle validation against `isoinfo` (cdrtools).
//!
//! The other corpus tests (`real_images.rs`, `pvd_getters.rs`) parse real ISO
//! images but assert mostly *structural booleans* (`has_joliet`, `session_count`,
//! "root dir not empty") or "no null byte / year in range" — they never reconcile
//! the parsed Primary Volume Descriptor fields and the directory listing against an
//! **independent tool**. This test closes that gap: it parses a genuine published
//! ISO and asserts the parser's volume id, system id, volume size, logical block
//! size, extension flags, and root-directory listing equal `isoinfo -d` / `isoinfo
//! -l` output (cdrtools `isoinfo` 3.x).
//!
//! Fixture: `multi_extent_8k.iso` — a real published test image from the libcdio
//! project corpus (made with xorriso/libisofs 1.5.5), exercising an ISO 9660 file
//! that spans multiple extents. Download URL + MD5 + the verbatim isoinfo output
//! reconciled against are in `tests/data/README.md`.
//!
//! Asserted values are isoinfo's, not hand-picked constants:
//!   isoinfo -d  "Volume id: ISOIMAGE"            → volume_label() == "ISOIMAGE"
//!   isoinfo -d  "System id:" (empty)             → system_id() == ""
//!   isoinfo -d  "Volume size is: 60"             → volume_space_size() == 60
//!   isoinfo -d  "Logical block size is: 2048"    → logical_block_size() == 2048
//!   isoinfo -d  "NO Joliet present"              → has_joliet() == false
//!   isoinfo -d  "Rock Ridge signatures ... found"→ has_rock_ridge() == true
//!   isoinfo -l  root entry "MULTI_EXTENT_FILE.;1"→ root listing == ["MULTI_EXTENT_FILE."]
//!                                                   (parser strips the ;version suffix)

use std::io::Cursor;

use iso9660_forensic::IsoReader;

// Committed fixture; skip cleanly if a checkout lacks it.
const MULTI_EXTENT: &[u8] = include_bytes!("../../tests/data/multi_extent_8k.iso");

#[test]
fn real_iso_pvd_and_listing_equal_isoinfo_oracle() {
    if MULTI_EXTENT.is_empty() {
        eprintln!("skipping: multi_extent_8k.iso fixture absent");
        return;
    }
    let mut r = IsoReader::open(Cursor::new(MULTI_EXTENT)).expect("IsoReader::open");

    // ── isoinfo -d (Primary Volume Descriptor) ───────────────────────────────
    assert_eq!(r.volume_label(), "ISOIMAGE", "isoinfo Volume id");
    assert_eq!(r.system_id(), "", "isoinfo System id (empty)");
    assert_eq!(r.volume_space_size(), 60, "isoinfo Volume size");
    assert_eq!(r.logical_block_size(), 2048, "isoinfo Logical block size");
    assert!(!r.has_joliet(), "isoinfo reports NO Joliet present");
    assert!(r.has_rock_ridge(), "isoinfo reports Rock Ridge signatures found (RRIP_1991A)");

    // ── isoinfo -l (root directory listing) ──────────────────────────────────
    let entries = r.read_root_dir().expect("read_root_dir");
    let names: Vec<String> = entries.iter().map(|e| e.iso_name()).collect();
    assert_eq!(
        names,
        vec!["MULTI_EXTENT_FILE.".to_string()],
        "root listing must equal isoinfo -l (sans ;version): MULTI_EXTENT_FILE.;1"
    );
}
