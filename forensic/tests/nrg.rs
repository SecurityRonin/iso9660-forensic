#![allow(clippy::unwrap_used, clippy::expect_used)]

// Nero NRG image parser tests.
//
// Layout grounded in the libmirage reference parser (cdemu image-nrg/parser.c):
//   footer: "NER5" + u64 BE trailer offset (v2, 12 bytes at EOF) or
//           "NERO" + u32 BE trailer offset (v1, 8 bytes at EOF);
//   chunks: [4-byte ID][u32 BE size][data], terminated by "END!";
//   ETN2 (32B)/ETNF (20B) TAO track entries; DAOX (42B)/DAOI (30B) DAO
//   entries after a 22-byte DAO header carrying the 13-char MCN.
// Synthetic fixtures cover the byte layout exhaustively; `parses_real_nero_nrg`
// additionally validates against a genuine Nero image (doer-checker).

use iso9660_forensic::nrg::{self, NrgVersion};
use iso9660_forensic::SectorMode;
use std::io::Cursor;

fn be32(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}
fn be64(v: u64) -> [u8; 8] {
    v.to_be_bytes()
}

/// Build a v2 (NER5) NRG with one DAOX data track of `data_len` bytes at
/// file offset 0, mode `mode_code`, MCN `mcn`, ISRC `isrc`.
fn build_nrg_v2_daox(data_len: u64, mode_code: u8, mcn: &[u8; 13], isrc: &[u8; 12]) -> Vec<u8> {
    let mut img = vec![0xAAu8; data_len as usize]; // track data area
    let trailer_offset = img.len() as u64;

    // DAOX chunk: 22-byte header (MCN at [0..13]) + 42-byte subblock.
    let mut dao = Vec::new();
    let mut header = [0u8; 22];
    header[0..13].copy_from_slice(mcn);
    dao.extend_from_slice(&header);
    let mut sub = Vec::new();
    sub.extend_from_slice(isrc); // isrc[0..12]
    sub.extend_from_slice(&(2048u16).to_be_bytes()); // sector_size [12..14]
    sub.push(mode_code); // mode_code [14]
    sub.extend_from_slice(&[0u8; 3]); // pad [15..18]
    sub.extend_from_slice(&be64(0)); // pregap_offset [18..26]
    sub.extend_from_slice(&be64(0)); // start_offset  [26..34]
    sub.extend_from_slice(&be64(data_len)); // end_offset [34..42]
    assert_eq!(sub.len(), 42);
    dao.extend_from_slice(&sub);

    img.extend_from_slice(b"DAOX");
    img.extend_from_slice(&be32(dao.len() as u32));
    img.extend_from_slice(&dao);
    img.extend_from_slice(b"END!");
    img.extend_from_slice(&be32(0));

    img.extend_from_slice(b"NER5");
    img.extend_from_slice(&be64(trailer_offset));
    img
}

/// Build a v1 (NERO) NRG with one ETNF track at file offset 0.
fn build_nrg_v1_etnf(data_len: u32, mode_code: u8, start_lba: u32) -> Vec<u8> {
    let mut img = vec![0xBBu8; data_len as usize];
    let trailer_offset = img.len() as u32;

    let mut sub = [0u8; 20];
    sub[0..4].copy_from_slice(&be32(0)); // offset
    sub[4..8].copy_from_slice(&be32(data_len)); // size
    sub[11] = mode_code; // mode @11
    sub[12..16].copy_from_slice(&be32(start_lba)); // sector @12

    img.extend_from_slice(b"ETNF");
    img.extend_from_slice(&be32(sub.len() as u32));
    img.extend_from_slice(&sub);
    img.extend_from_slice(b"END!");
    img.extend_from_slice(&be32(0));

    img.extend_from_slice(b"NERO");
    img.extend_from_slice(&be32(trailer_offset));
    img
}

#[test]
fn parses_v2_daox_track_and_mcn() {
    let img = build_nrg_v2_daox(40960, 0x00, b"1234567890123", b"USRC17607839");
    let nrg = nrg::parse(&mut Cursor::new(img)).expect("parse v2");
    assert_eq!(nrg.version, NrgVersion::V2);
    assert_eq!(nrg.catalog.as_deref(), Some("1234567890123"));
    assert_eq!(nrg.track_count(), 1);
    let t = &nrg.tracks[0];
    assert_eq!(t.mode_code, 0x00);
    assert_eq!(t.start_offset, 0);
    assert_eq!(t.size, 40960);
    assert_eq!(t.isrc.as_deref(), Some("USRC17607839"));
    assert_eq!(t.sector_mode(), Some(SectorMode::Iso2048));
}

#[test]
fn data_track_picks_first_filesystem_track() {
    let img = build_nrg_v2_daox(8192, 0x05, b"0000000000000", b"            ");
    let nrg = nrg::parse(&mut Cursor::new(img)).unwrap();
    let dt = nrg.data_track().expect("data track");
    assert_eq!(dt.sector_mode(), Some(SectorMode::Raw2352)); // mode 0x05
}

#[test]
fn parses_v1_etnf_track() {
    let img = build_nrg_v1_etnf(40960, 0x05, 0);
    let nrg = nrg::parse(&mut Cursor::new(img)).expect("parse v1");
    assert_eq!(nrg.version, NrgVersion::V1);
    assert_eq!(nrg.track_count(), 1);
    let t = &nrg.tracks[0];
    assert_eq!(t.start_offset, 0);
    assert_eq!(t.size, 40960);
    assert_eq!(t.mode_code, 0x05);
    assert_eq!(t.sector_mode(), Some(SectorMode::Raw2352));
    assert_eq!(t.isrc, None); // ETN entries carry no ISRC
    assert_eq!(nrg.catalog, None); // ETN carries no MCN
}

#[test]
fn mode_code_to_sector_mode() {
    use nrg::sector_mode_for;
    assert_eq!(sector_mode_for(0x00), Some(SectorMode::Iso2048));
    assert_eq!(sector_mode_for(0x02), Some(SectorMode::Iso2048));
    assert_eq!(sector_mode_for(0x03), Some(SectorMode::Mode2_2336));
    assert_eq!(sector_mode_for(0x05), Some(SectorMode::Raw2352));
    assert_eq!(sector_mode_for(0x06), Some(SectorMode::Raw2352Mode2));
    assert_eq!(sector_mode_for(0x07), None); // audio
    assert_eq!(sector_mode_for(0x0F), Some(SectorMode::Raw2448));
    assert_eq!(sector_mode_for(0x11), Some(SectorMode::Raw2448Mode2));
}

#[test]
fn not_an_nrg_errors() {
    let img = vec![0u8; 64];
    assert!(nrg::parse(&mut Cursor::new(img)).is_err());
}

// ── REAL-DATA validation (doer-checker) ───────────────────────────────────────
// real_nero.nrg is a genuine Nero (NER5/v2) audio-CD image — two audio tracks —
// from the public glepore70/pronom-research corpus (sample_files/n/nrg/p1.nrg).
// It carries audio content, so it is NOT committed (gitignored); fetch it with:
//   curl -L -o tests/data/real_nero.nrg \
//     https://raw.githubusercontent.com/glepore70/pronom-research/master/sample_files/n/nrg/p1.nrg
// Skips automatically when absent (as the UDF real-media tests do).
#[test]
fn parses_real_nero_nrg() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/real_nero.nrg");
    let Ok(bytes) = std::fs::read(path) else {
        eprintln!("skip: real_nero.nrg absent");
        return;
    };
    let nrg = nrg::parse(&mut std::io::Cursor::new(bytes)).expect("parse real NRG");
    assert_eq!(nrg.version, NrgVersion::V2);
    assert_eq!(nrg.track_count(), 2);
    // Both tracks are Red Book audio -> no filesystem data track.
    assert!(nrg.tracks.iter().all(|t| t.sector_mode().is_none()));
    assert!(nrg.data_track().is_none());
    assert_eq!(nrg.tracks[0].start_offset, 705_600);
    assert_eq!(nrg.tracks[0].size, 176_400);
}
