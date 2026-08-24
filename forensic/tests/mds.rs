#![allow(clippy::unwrap_used, clippy::expect_used)]

// Alcohol 120% MDS descriptor parser tests.
//
// Layout grounded in the libmirage reference parser (cdemu image-mds): an
// 88-byte header ("MEDIA DESCRIPTOR" + 0x01), little-endian throughout, with
// offsets to 24-byte session blocks, each pointing to 80-byte track blocks
// that carry the explicit sector size, .mdf start offset, and a link to an
// 8-byte extra block holding the track length in sectors.
// No real .mds sample was available; fixtures are built to the documented
// byte layout (doer-checker: real-sample validation pending).

use iso9660_forensic::mds::{self};
use iso9660_forensic::SectorMode;
use std::io::Cursor;

fn le16(v: u16) -> [u8; 2] {
    v.to_le_bytes()
}
fn le32(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

/// Build a minimal one-track MDS: header @0, session block @88, track block
/// @112, extra block @192.
fn build_mds(mode: u8, sector_size: u16, start_offset: u64, num_sectors: u32) -> Vec<u8> {
    let mut img = vec![0u8; 200];
    // Header (88 bytes).
    img[0..16].copy_from_slice(b"MEDIA DESCRIPTOR");
    img[16] = 0x01; // version
    img[18..20].copy_from_slice(&le16(0)); // medium_type = CD
    img[20..22].copy_from_slice(&le16(1)); // num_sessions
    img[80..84].copy_from_slice(&le32(88)); // sessions_blocks_offset
                                            // Session block (24 bytes) @88.
    let s = 88;
    img[s + 8..s + 10].copy_from_slice(&le16(1)); // session_number
    img[s + 10] = 1; // num_all_blocks
    img[s + 11] = 0; // num_nontrack_blocks
    img[s + 12..s + 14].copy_from_slice(&le16(1)); // first_track
    img[s + 14..s + 16].copy_from_slice(&le16(1)); // last_track
    img[s + 20..s + 24].copy_from_slice(&le32(112)); // tracks_blocks_offset
                                                     // Track block (80 bytes) @112.
    let t = 112;
    img[t] = mode; // mode
    img[t + 1] = 0; // subchannel
    img[t + 4] = 1; // point = track 1
    img[t + 12..t + 16].copy_from_slice(&le32(192)); // extra_offset
    img[t + 16..t + 18].copy_from_slice(&le16(sector_size)); // sector_size
    img[t + 36..t + 40].copy_from_slice(&le32(0)); // start_sector
    img[t + 40..t + 48].copy_from_slice(&start_offset.to_le_bytes()); // start_offset
                                                                      // Extra block (8 bytes) @192.
    let e = 192;
    img[e..e + 4].copy_from_slice(&le32(0)); // pregap
    img[e + 4..e + 8].copy_from_slice(&le32(num_sectors)); // length (sectors)
    img
}

#[test]
fn parses_single_track() {
    let img = build_mds(0x02, 2048, 0, 20);
    let mds = mds::parse(&mut Cursor::new(img)).expect("parse mds");
    assert_eq!(mds.track_count(), 1);
    let t = &mds.tracks[0];
    assert_eq!(t.point, 1);
    assert_eq!(t.mode, 0x02);
    assert_eq!(t.sector_size, 2048);
    assert_eq!(t.start_offset, 0);
    assert_eq!(t.num_sectors, 20);
    assert_eq!(t.sector_mode(), Some(SectorMode::Iso2048));
    assert_eq!(t.data_size(), 20 * 2048);
}

#[test]
fn data_track_is_first_filesystem_track() {
    let img = build_mds(0x02, 2352, 0, 100);
    let mds = mds::parse(&mut Cursor::new(img)).unwrap();
    let dt = mds.data_track().expect("data track");
    assert_eq!(dt.sector_mode(), Some(SectorMode::Raw2352)); // Mode 1, 2352
}

#[test]
fn sector_mode_mapping() {
    use mds::sector_mode_for;
    assert_eq!(sector_mode_for(0x02, 2048), Some(SectorMode::Iso2048));
    assert_eq!(sector_mode_for(0x04, 2048), Some(SectorMode::Iso2048)); // Mode2 Form1, bare
    assert_eq!(sector_mode_for(0x03, 2336), Some(SectorMode::Mode2_2336));
    assert_eq!(sector_mode_for(0x02, 2352), Some(SectorMode::Raw2352)); // Mode 1
    assert_eq!(sector_mode_for(0x04, 2352), Some(SectorMode::Raw2352Mode2)); // Mode 2
    assert_eq!(sector_mode_for(0x02, 2448), Some(SectorMode::Raw2448));
    assert_eq!(sector_mode_for(0x04, 2448), Some(SectorMode::Raw2448Mode2));
    assert_eq!(sector_mode_for(0x01, 2352), None); // audio
}

#[test]
fn bad_signature_errors() {
    let img = vec![0u8; 200];
    assert!(mds::parse(&mut Cursor::new(img)).is_err());
}

// ── REAL-DATA validation (doer-checker) ───────────────────────────────────────
// real_alcohol.mds is a genuine Alcohol 120% MediaDescriptor produced by Aaru
// (open-source, an independent oracle) converting our own rock_ridge ISO (raw
// 2352) — so it carries no third-party content. It exposed that real Alcohol
// uses TrackMode bytes 0xA9-0xED (Mode1 = 0xAA); Aaru and libmirage decode this
// identically (libmirage matches `mode & 0x0F` against `n`/`n+8`), so it is
// ground-truth, not a one-tool quirk.
#[test]
fn parses_real_alcohol_mds_mode1() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/real_alcohol.mds");
    let bytes = std::fs::read(path).expect("real_alcohol.mds fixture");
    let mds = mds::parse(&mut Cursor::new(bytes)).expect("parse real MDS");
    let t = mds.data_track().expect("a data track");
    assert_eq!(t.sector_size, 2352);
    assert_eq!(t.mode, 0xAA); // real Alcohol Mode1
                              // Mode1 @2352 -> Raw2352 (user data at offset 16), NOT Raw2352Mode2 (offset 24).
    assert_eq!(t.sector_mode(), Some(SectorMode::Raw2352));
}
