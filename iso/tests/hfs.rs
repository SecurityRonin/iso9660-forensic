// HFS+ volume-header detection tests.
//
// Validated against a REAL HFS+ volume header: tests/data/hfs_plus_header.bin
// is the first 2 KiB of an `hdiutil create -fs HFS+ -volname FORENSICHFS
// -size 2m` image, so the volume header at offset 1024 is genuine Apple output
// (signature H+, version 4, blockSize 4096, totalBlocks 512 = 2 MiB).

use iso9660_forensic::hfs::{self, HfsKind};
use iso9660_forensic::IsoReader;
use std::io::Cursor;

fn real_header() -> Vec<u8> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/hfs_plus_header.bin");
    std::fs::read(path).expect("hfs_plus_header.bin fixture")
}

fn rr_iso() -> Option<Vec<u8>> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/rock_ridge.iso");
    std::fs::read(path).ok()
}

#[test]
fn parses_real_hfs_plus_volume_header() {
    let vol = hfs::parse(&real_header()).expect("parse real HFS+ header");
    assert_eq!(vol.kind, HfsKind::HfsPlus);
    assert_eq!(vol.version, 4);
    assert_eq!(vol.block_size, 4096);
    assert_eq!(vol.total_blocks, 512);
    assert_eq!(vol.volume_size(), 2 * 1024 * 1024);
}

#[test]
fn non_hfs_buffer_is_none() {
    assert!(hfs::parse(&[0u8; 2048]).is_none());
    assert!(hfs::parse(&[0u8; 100]).is_none()); // too short
}

#[test]
fn reader_detects_hfs_in_hybrid_iso() {
    let Some(mut iso) = rr_iso() else { return };
    // Splice the real HFS+ header into the ISO system area (bytes 1024..1536),
    // which sits before the PVD at sector 16 — producing an ISO/HFS hybrid.
    let header = real_header();
    iso[1024..1536].copy_from_slice(&header[1024..1536]);
    let mut reader = IsoReader::open(Cursor::new(iso)).unwrap();
    let vol = reader.hfs_volume().unwrap().expect("hybrid HFS+ detected");
    assert_eq!(vol.kind, HfsKind::HfsPlus);
    assert_eq!(vol.block_size, 4096);
}

#[test]
fn reader_no_hfs_in_plain_iso() {
    let Some(iso) = rr_iso() else { return };
    let mut reader = IsoReader::open(Cursor::new(iso)).unwrap();
    assert_eq!(reader.hfs_volume().unwrap(), None);
}
