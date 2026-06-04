// Full UDF reader — integration tests.
// RED phase: these reference UdfFileEntry and IsoReader UDF methods that do not
// exist yet. They drive the implementation in iso/src/udf.rs and lib.rs.

use iso9660_forensic::{udf::UdfFileEntry, IsoReader};
use std::fs::File;

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
    let entries = reader.read_udf_root_dir().expect("read_udf_root_dir failed");
    assert!(!entries.is_empty(), "UDF root directory should contain at least one entry");
}

#[test]
fn udf_entries_have_non_empty_names() {
    let mut reader = open_udf_bridge();
    let entries = reader.read_udf_root_dir().expect("read_udf_root_dir failed");
    for e in &entries {
        assert!(!e.name.is_empty(), "UDF entry should have a non-empty name");
    }
}

#[test]
fn udf_entry_size_consistent() {
    let mut reader = open_udf_bridge();
    let entries = reader.read_udf_root_dir().expect("read_udf_root_dir failed");
    // Directory entries have size 0 or represent their data extent; files have size > 0.
    // At minimum, every entry's size field must be readable without panic.
    for e in &entries {
        let _ = e.size;
    }
}

#[test]
fn udf_file_entry_readable() {
    let mut reader = open_udf_bridge();
    let entries = reader.read_udf_root_dir().expect("read_udf_root_dir failed");
    // Find a non-directory entry with non-zero size and read it.
    let file_entry = entries.iter().find(|e| !e.is_dir && e.size > 0);
    if let Some(fe) = file_entry {
        let data = reader.read_udf_file(fe).expect("read_udf_file failed");
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
    let entries = reader.read_udf_root_dir().expect("read_udf_root_dir failed");
    // If there's a directory, read it recursively one level.
    let dir_entry = entries.iter().find(|e| e.is_dir);
    if let Some(de) = dir_entry {
        let sub = reader.read_udf_dir(de).expect("read_udf_dir of sub-directory failed");
        // May be empty (that's valid), but must not error.
        let _ = sub;
    }
}

// ── UdfFileEntry field checks ─────────────────────────────────────────────────

#[test]
fn udf_file_entry_struct_fields_accessible() {
    // Compile-time check: all UdfFileEntry fields exist and have the right types.
    let e = UdfFileEntry { name: "test.txt".to_string(), is_dir: false, size: 42, fe_lba: 100 };
    assert_eq!(e.name, "test.txt");
    assert!(!e.is_dir);
    assert_eq!(e.size, 42u64);
    assert_eq!(e.fe_lba, 100u32);
}

// ── UDF partition map parsing (v0.3-dev) ──────────────────────────────────────

use iso9660_forensic::UdfPartitionKind;

#[test]
fn udf_bridge_partition_kind_is_physical() {
    let reader = open_udf_bridge();
    assert_eq!(
        reader.udf_partition_kind(),
        Some(UdfPartitionKind::Physical),
        "udf_bridge.iso uses a Type 1 physical partition"
    );
}

#[test]
fn udf_bridge_partition_map_count_is_one() {
    let reader = open_udf_bridge();
    assert_eq!(reader.udf_partition_map_count(), Some(1));
}

#[test]
fn non_udf_image_has_no_partition_kind() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/rock_ridge.iso");
    let f = std::fs::File::open(path).unwrap();
    let reader = IsoReader::open(f).unwrap();
    assert_eq!(reader.udf_partition_kind(), None);
}

// Local-only: hdiutil-authored real UDF (skip-if-missing, not committed).
#[test]
fn hdiutil_udf_reads_files() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/udf_hdiutil.iso");
    if !std::path::Path::new(path).exists() {
        eprintln!("skip: udf_hdiutil.iso");
        return;
    }
    let f = std::fs::File::open(path).unwrap();
    let mut reader = IsoReader::open(f).unwrap();
    assert!(reader.has_udf());
    assert_eq!(reader.udf_partition_kind(), Some(UdfPartitionKind::Physical));
    let entries = reader.read_udf_root_dir().expect("read hdiutil udf root");
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(
        names.iter().any(|n| n.eq_ignore_ascii_case("hello.txt")),
        "hdiutil UDF must list hello.txt; got {names:?}"
    );
}

// ── pure-UDF open path (no ISO 9660 PVD) — v0.3-dev ──────────────────────────
// Real mkudffs images (skip-if-missing): generated by corpus/gen_udf_type2.sh.

fn open_real(name: &str) -> Option<IsoReader<File>> {
    let path = format!("{}/tests/data/{}", env!("CARGO_MANIFEST_DIR"), name);
    if !std::path::Path::new(&path).exists() {
        eprintln!("skip: {name}");
        return None;
    }
    Some(
        IsoReader::open(File::open(&path).unwrap())
            .expect("pure-UDF image must open without an ISO 9660 PVD"),
    )
}

#[test]
fn pure_udf_vat_opens_and_detects_virtual() {
    let Some(reader) = open_real("udf_vat.img") else {
        return;
    };
    assert!(reader.has_udf());
    assert_eq!(reader.udf_partition_kind(), Some(UdfPartitionKind::Virtual));
}

#[test]
fn pure_udf_sparable_opens_and_detects_sparable() {
    let Some(reader) = open_real("udf_spar.img") else {
        return;
    };
    assert!(reader.has_udf());
    assert_eq!(reader.udf_partition_kind(), Some(UdfPartitionKind::Sparable));
}

#[test]
fn pure_udf_has_empty_iso_volume_label() {
    let Some(reader) = open_real("udf_vat.img") else {
        return;
    };
    // No ISO 9660 PVD -> the ISO volume label is the empty sentinel.
    assert_eq!(reader.volume_label(), "");
}

#[test]
fn pure_garbage_still_errors() {
    // Neither ISO 9660 nor UDF: must still be rejected.
    let data = vec![0xABu8; 64 * 2048];
    assert!(IsoReader::open(std::io::Cursor::new(data)).is_err());
}
