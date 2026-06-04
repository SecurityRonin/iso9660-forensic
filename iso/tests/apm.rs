// Apple Partition Map detection at the IsoReader level.
//
// The pure APM parser tests live in the `apm-forensic` crate; here we only
// verify IsoReader::apple_partition_map() integration, by splicing the real
// DDM + partition map into rock_ridge.iso's system area to form a hybrid.

use iso9660_forensic::IsoReader;
use std::io::Cursor;

fn real_map() -> Vec<u8> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/apm_map.bin");
    std::fs::read(path).expect("apm_map.bin fixture")
}

fn rr_iso() -> Option<Vec<u8>> {
    std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/rock_ridge.iso")).ok()
}

#[test]
fn reader_detects_apm_in_hybrid_iso() {
    let Some(mut iso) = rr_iso() else { return };
    let map = real_map();
    iso[0..2048].copy_from_slice(&map[0..2048]);
    let mut reader = IsoReader::open(Cursor::new(iso)).unwrap();
    let parsed = reader.apple_partition_map().unwrap().expect("APM detected");
    assert!(parsed.hfs_partition().is_some());
}

#[test]
fn reader_no_apm_in_plain_iso() {
    let Some(iso) = rr_iso() else { return };
    let mut reader = IsoReader::open(Cursor::new(iso)).unwrap();
    assert_eq!(reader.apple_partition_map().unwrap(), None);
}
