// Apple Partition Map (APM) detection tests.
//
// Validated against REAL data: tests/data/apm_map.bin is the first 2 KiB of an
// `hdiutil create -fs HFS+ -layout SPUD` image — a genuine Driver Descriptor
// Map ('ER') + partition map ('PM') as Apple writes it (block size 512, two
// entries: Apple_partition_map and Apple_HFS).

use iso9660_forensic::apm;
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
fn parses_real_apple_partition_map() {
    let map = apm::parse(&real_map()).expect("parse real APM");
    assert_eq!(map.block_size, 512);
    assert_eq!(map.partitions.len(), 2);
    assert_eq!(map.partitions[0].type_name, "Apple_partition_map");
    assert_eq!(map.partitions[1].type_name, "Apple_HFS");
    assert_eq!(map.partitions[1].name, "disk image");
    assert_eq!(map.partitions[1].start_block, 64);
}

#[test]
fn finds_hfs_partition() {
    let map = apm::parse(&real_map()).unwrap();
    let hfs = map.hfs_partition().expect("an Apple_HFS partition");
    assert_eq!(hfs.start_block, 64);
}

#[test]
fn non_apm_is_none() {
    assert!(apm::parse(&[0u8; 2048]).is_none());
    assert!(apm::parse(&[0u8; 8]).is_none()); // too short
}

#[test]
fn reader_detects_apm_in_hybrid_iso() {
    let Some(mut iso) = rr_iso() else { return };
    let map = real_map();
    // Splice the real DDM + partition map into the ISO system area (sectors
    // 0..16, before the PVD) — producing an APM/ISO hybrid Apple disc.
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
