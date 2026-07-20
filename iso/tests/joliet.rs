#![allow(clippy::unwrap_used, clippy::expect_used)]

// Joliet (SVD) tree traversal: `walk_joliet` walks the supplementary directory
// tree. A well-formed hybrid disc's Joliet and primary trees describe the same
// files, so they share the same data extents.

use iso9660_forensic::IsoReader;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::BufReader;

fn open(name: &str) -> IsoReader<BufReader<File>> {
    let path = format!("{}/../tests/data/{}", env!("CARGO_MANIFEST_DIR"), name);
    IsoReader::open(BufReader::new(File::open(path).expect("open fixture")))
        .expect("IsoReader::open")
}

fn file_extents(entries: &[iso9660_forensic::WalkEntry]) -> BTreeSet<u32> {
    entries
        .iter()
        .filter(|e| !e.record.is_dir() && e.record.size > 0)
        .map(|e| e.record.lba)
        .collect()
}

#[test]
fn walk_joliet_shares_primary_data_extents() {
    let mut r = open("joliet.iso");
    let primary = file_extents(&r.walk().expect("walk"));
    let joliet = file_extents(&r.walk_joliet().expect("walk_joliet"));
    assert!(!joliet.is_empty(), "Joliet tree should list files");
    assert_eq!(joliet, primary, "Joliet and primary trees share data extents");
}

#[test]
fn walk_joliet_empty_without_svd() {
    // rock_ridge.iso has no Joliet SVD.
    let mut r = open("rock_ridge.iso");
    assert!(r.walk_joliet().expect("walk_joliet").is_empty());
}
