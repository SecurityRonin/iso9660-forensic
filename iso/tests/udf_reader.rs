// Full UDF reader — integration tests.
// RED phase: these reference UdfFileEntry and IsoReader UDF methods that do not
// exist yet. They drive the implementation in iso/src/udf.rs and lib.rs.

use std::fs::File;
use iso9660_forensic::{IsoReader, udf::UdfFileEntry};

fn open_udf_bridge() -> IsoReader<File> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/udf_bridge.iso");
    let f = File::open(path).expect("udf_bridge.iso not found");
    IsoReader::open(f).expect("IsoReader::open failed")
}

// ── UDF detection (existing API, regression guard) ────────────────────────────

#[test]
fn udf_bridge_detected() {
    let reader = open_udf_bridge();
    assert!(reader.has_udf(), "udf_bridge.iso must have UDF recognition sequence");
}

// ── UDF traversal (new API) ───────────────────────────────────────────────────

#[test]
fn udf_root_dir_is_non_empty() {
    let mut reader = open_udf_bridge();
    let entries = reader
        .read_udf_root_dir()
        .expect("read_udf_root_dir failed");
    assert!(
        !entries.is_empty(),
        "UDF root directory should contain at least one entry"
    );
}

#[test]
fn udf_entries_have_non_empty_names() {
    let mut reader = open_udf_bridge();
    let entries = reader
        .read_udf_root_dir()
        .expect("read_udf_root_dir failed");
    for e in &entries {
        assert!(
            !e.name.is_empty(),
            "UDF entry should have a non-empty name"
        );
    }
}

#[test]
fn udf_entry_size_consistent() {
    let mut reader = open_udf_bridge();
    let entries = reader
        .read_udf_root_dir()
        .expect("read_udf_root_dir failed");
    // Directory entries have size 0 or represent their data extent; files have size > 0.
    // At minimum, every entry's size field must be readable without panic.
    for e in &entries {
        let _ = e.size;
    }
}

#[test]
fn udf_file_entry_readable() {
    let mut reader = open_udf_bridge();
    let entries = reader
        .read_udf_root_dir()
        .expect("read_udf_root_dir failed");
    // Find a non-directory entry with non-zero size and read it.
    let file_entry = entries.iter().find(|e| !e.is_dir && e.size > 0);
    if let Some(fe) = file_entry {
        let data = reader
            .read_udf_file(fe)
            .expect("read_udf_file failed");
        assert_eq!(
            data.len() as u64,
            fe.size,
            "read_udf_file returned {} bytes but entry size is {}",
            data.len(),
            fe.size
        );
    }
    // If there are no files, the test trivially passes — that's fine for a dir-only image.
}

#[test]
fn udf_dir_entry_traversable() {
    let mut reader = open_udf_bridge();
    let entries = reader
        .read_udf_root_dir()
        .expect("read_udf_root_dir failed");
    // If there's a directory, read it recursively one level.
    let dir_entry = entries.iter().find(|e| e.is_dir);
    if let Some(de) = dir_entry {
        let sub = reader
            .read_udf_dir(de)
            .expect("read_udf_dir of sub-directory failed");
        // May be empty (that's valid), but must not error.
        let _ = sub;
    }
}

// ── UdfFileEntry field checks ─────────────────────────────────────────────────

#[test]
fn udf_file_entry_struct_fields_accessible() {
    // Compile-time check: all UdfFileEntry fields exist and have the right types.
    let e = UdfFileEntry {
        name: "test.txt".to_string(),
        is_dir: false,
        size: 42,
        fe_lba: 100,
    };
    assert_eq!(e.name, "test.txt");
    assert!(!e.is_dir);
    assert_eq!(e.size, 42u64);
    assert_eq!(e.fe_lba, 100u32);
}
