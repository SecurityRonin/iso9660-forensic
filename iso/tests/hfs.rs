// HFS+ detection at the IsoReader level (Apple ISO/HFS hybrid discs).
//
// The pure HFS+ parser tests live in the `hfsplus-forensic` crate; here we only
// verify IsoReader::hfs_volume() integration. The HFS+ header fixture is spliced
// into rock_ridge.iso's system area to form a hybrid.

use iso9660_forensic::hfs::HfsKind;
use iso9660_forensic::IsoReader;
use std::io::Cursor;

fn real_header() -> Vec<u8> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/hfs_plus_header.bin");
    std::fs::read(path).expect("hfs_plus_header.bin fixture")
}

fn rr_iso() -> Option<Vec<u8>> {
    std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/rock_ridge.iso")).ok()
}

#[test]
fn reader_detects_hfs_in_hybrid_iso() {
    let Some(mut iso) = rr_iso() else { return };
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
