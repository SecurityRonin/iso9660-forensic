mod helpers;

use iso9660_forensic::IsoReader;

// ── Core read tests ───────────────────────────────────────────────────────────

#[test]
fn volume_label_from_single_session_iso() {
    let cursor = helpers::build_iso("FORENSICS", vec![helpers::file("README.TXT", b"hello")]);
    let reader = IsoReader::open(cursor).expect("open failed");
    assert_eq!(reader.volume_label(), "FORENSICS");
}

#[test]
fn root_dir_lists_files() {
    let cursor = helpers::build_iso(
        "TEST",
        vec![
            helpers::file("ALPHA.TXT", b"aaa"),
            helpers::file("BETA.TXT", b"bbb"),
        ],
    );
    let mut reader = IsoReader::open(cursor).expect("open failed");
    let entries = reader.read_root_dir().expect("read_root_dir failed");
    let names: Vec<String> = entries.iter().map(|e| e.iso_name()).collect();
    assert!(
        names.iter().any(|n| n == "ALPHA.TXT"),
        "expected ALPHA.TXT, got {names:?}"
    );
    assert!(
        names.iter().any(|n| n == "BETA.TXT"),
        "expected BETA.TXT, got {names:?}"
    );
    assert_eq!(
        entries.len(),
        2,
        "expected exactly 2 entries, got {names:?}"
    );
}

#[test]
fn read_file_entry_returns_correct_bytes() {
    let payload = b"forensic evidence payload";
    let cursor = helpers::build_iso("EVIDENCE", vec![helpers::file("DATA.BIN", payload)]);
    let mut reader = IsoReader::open(cursor).expect("open failed");
    let entries = reader.read_root_dir().expect("read_root_dir failed");
    let entry = entries
        .into_iter()
        .find(|e| e.iso_name() == "DATA.BIN")
        .expect("DATA.BIN not found");
    let data = reader
        .read_file_entry(&entry)
        .expect("read_file_entry failed");
    assert_eq!(&data[..payload.len()], payload);
}

#[test]
fn find_entry_by_path() {
    let payload = b"nested content";
    let cursor = helpers::build_iso(
        "TREE",
        vec![helpers::dir(
            "SUBDIR",
            vec![helpers::file("LEAF.TXT", payload)],
        )],
    );
    let mut reader = IsoReader::open(cursor).expect("open failed");
    let entry = reader
        .find_entry("SUBDIR/LEAF.TXT")
        .expect("find_entry failed");
    let data = reader.read_file_entry(&entry).expect("read_file failed");
    assert_eq!(&data[..payload.len()], payload);
}

#[test]
fn find_entry_rejects_path_traversal() {
    let cursor = helpers::build_iso("SEC", vec![helpers::file("FILE.TXT", b"x")]);
    let mut reader = IsoReader::open(cursor).expect("open failed");
    let result = reader.find_entry("../etc/passwd");
    assert!(
        matches!(result, Err(iso9660_forensic::IsoError::PathTraversal)),
        "expected PathTraversal, got {result:?}"
    );
}

// ── Session detection ─────────────────────────────────────────────────────────

#[test]
fn single_session_iso_has_session_count_one() {
    let cursor = helpers::build_iso("SINGLE", vec![helpers::file("A.TXT", b"a")]);
    let reader = IsoReader::open(cursor).expect("open failed");
    assert_eq!(reader.session_count(), 1);
}

// ── Extension detection ───────────────────────────────────────────────────────

#[test]
fn rock_ridge_detected() {
    let cursor = helpers::build_rr_iso("RRTEST", vec![helpers::file("low.txt", b"rrip")]);
    let reader = IsoReader::open(cursor).expect("open failed");
    assert!(
        reader.has_rock_ridge(),
        "expected Rock Ridge to be detected"
    );
}

#[test]
fn plain_iso_has_no_rock_ridge() {
    let cursor = helpers::build_iso("PLAIN", vec![helpers::file("FILE.TXT", b"x")]);
    let reader = IsoReader::open(cursor).expect("open failed");
    assert!(
        !reader.has_rock_ridge(),
        "plain ISO should not have Rock Ridge"
    );
}

#[test]
fn joliet_detected() {
    let cursor = helpers::build_joliet_iso("JOLIET", vec![helpers::file("file.txt", b"j")]);
    let reader = IsoReader::open(cursor).expect("open failed");
    assert!(reader.has_joliet(), "expected Joliet SVD to be detected");
}

#[test]
fn plain_iso_has_no_joliet() {
    let cursor = helpers::build_iso("PLAIN", vec![helpers::file("FILE.TXT", b"x")]);
    let reader = IsoReader::open(cursor).expect("open failed");
    assert!(!reader.has_joliet(), "plain ISO should not have Joliet");
}

#[test]
fn rock_ridge_alternate_name_readable() {
    // hadris-iso Rock Ridge stores lowercase filenames as NM entries.
    let cursor = helpers::build_rr_iso("RRNAME", vec![helpers::file("lowercase.txt", b"rr")]);
    let mut reader = IsoReader::open(cursor).expect("open failed");
    let entries = reader.read_root_dir().expect("read_root_dir failed");
    // At least one entry should have a Rock Ridge alternate name.
    let has_rr_name = entries
        .iter()
        .any(|e| iso9660_forensic::rock_ridge::alternate_name(&e.system_use).is_some());
    assert!(
        has_rr_name,
        "expected at least one Rock Ridge NM entry in root dir"
    );
}

// ── El Torito ─────────────────────────────────────────────────────────────────

#[test]
fn el_torito_boot_entries_listed() {
    let cursor = helpers::build_bootable_iso("BOOTISO");
    let mut reader = IsoReader::open(cursor).expect("open failed");
    let entries = reader.boot_entries().expect("boot_entries failed");
    assert!(!entries.is_empty(), "expected at least one boot entry");
    assert!(
        entries[0].bootable,
        "expected first boot entry to be bootable"
    );
}

#[test]
fn non_bootable_iso_has_no_boot_entries() {
    let cursor = helpers::build_iso("NOBOOT", vec![helpers::file("FILE.TXT", b"x")]);
    let mut reader = IsoReader::open(cursor).expect("open failed");
    let entries = reader.boot_entries().expect("boot_entries failed");
    assert!(entries.is_empty(), "plain ISO should have no boot entries");
}
