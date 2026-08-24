#![allow(clippy::unwrap_used, clippy::expect_used)]

// CD sector-mode detection and user-data extraction (ECMA-130 §14).
//
// Builds synthetic raw images for each physical layout and checks that
// SectorMode::detect picks the right variant and read_sector_data lands on
// the 2048-byte ISO user-data window at the correct offset.

use iso9660_forensic::sector::{read_sector_data, SectorMode};
use std::io::Cursor;

const SYNC: [u8; 12] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];

/// Build a raw image of `n` physical sectors of `phys` bytes each, writing a
/// PVD (0x01 "CD001" 0x01) into sector 16's user-data window at `data_off`,
/// with the sync pattern + mode byte set when `sync` is true.
fn build(phys: usize, data_off: usize, sync: bool, mode_byte: u8, n: usize) -> Vec<u8> {
    let mut img = vec![0u8; n * phys];
    for s in 0..n {
        let base = s * phys;
        if sync {
            img[base..base + 12].copy_from_slice(&SYNC);
            img[base + 15] = mode_byte;
        }
    }
    // PVD in sector 16's user data.
    let p = 16 * phys + data_off;
    img[p] = 0x01;
    img[p + 1..p + 6].copy_from_slice(b"CD001");
    img[p + 6] = 0x01;
    img
}

// ── data_offset / physical_size correctness ──────────────────────────────────

#[test]
fn mode2_form1_2352_offsets() {
    assert_eq!(SectorMode::Raw2352Mode2.physical_sector_size(), 2352);
    assert_eq!(SectorMode::Raw2352Mode2.data_offset(), 24);
}

#[test]
fn raw2448_offsets() {
    assert_eq!(SectorMode::Raw2448.physical_sector_size(), 2448);
    assert_eq!(SectorMode::Raw2448.data_offset(), 16);
}

#[test]
fn raw2448_mode2_offsets() {
    assert_eq!(SectorMode::Raw2448Mode2.physical_sector_size(), 2448);
    assert_eq!(SectorMode::Raw2448Mode2.data_offset(), 24);
}

#[test]
fn mode2_2336_offsets() {
    assert_eq!(SectorMode::Mode2_2336.physical_sector_size(), 2336);
    assert_eq!(SectorMode::Mode2_2336.data_offset(), 8);
}

// ── detection ────────────────────────────────────────────────────────────────

#[test]
fn detect_mode2_form1_2352() {
    let img = build(2352, 24, true, 0x02, 18);
    let mut cur = Cursor::new(img);
    assert_eq!(SectorMode::detect(&mut cur).unwrap(), SectorMode::Raw2352Mode2);
}

#[test]
fn detect_mode1_2352_still_works() {
    let img = build(2352, 16, true, 0x01, 18);
    let mut cur = Cursor::new(img);
    assert_eq!(SectorMode::detect(&mut cur).unwrap(), SectorMode::Raw2352);
}

#[test]
fn detect_raw2448_mode1() {
    let img = build(2448, 16, true, 0x01, 18);
    let mut cur = Cursor::new(img);
    assert_eq!(SectorMode::detect(&mut cur).unwrap(), SectorMode::Raw2448);
}

#[test]
fn detect_raw2448_mode2() {
    let img = build(2448, 24, true, 0x02, 18);
    let mut cur = Cursor::new(img);
    assert_eq!(SectorMode::detect(&mut cur).unwrap(), SectorMode::Raw2448Mode2);
}

#[test]
fn detect_mode2_2336() {
    let img = build(2336, 8, false, 0x00, 18);
    let mut cur = Cursor::new(img);
    assert_eq!(SectorMode::detect(&mut cur).unwrap(), SectorMode::Mode2_2336);
}

// ── reading lands on the right bytes ─────────────────────────────────────────

#[test]
fn read_mode2_form1_pvd() {
    let img = build(2352, 24, true, 0x02, 18);
    let mut cur = Cursor::new(img);
    let mode = SectorMode::detect(&mut cur).unwrap();
    let mut buf = [0u8; 6];
    read_sector_data(&mut cur, mode, 16, &mut buf).unwrap();
    assert_eq!(&buf, b"\x01CD001");
}
