// Multi-extent file reading (ECMA-119 §9.1.6).
//
// FILE_FLAG_MULTI_EXTENT = 0x80: when set, the entry is not the last extent
// of the file; consecutive same-name records with this flag form an extent
// chain terminated by a record with bit 7 clear.
//
// Spec: ECMA-119 4th ed §9.1.6.
// Refs: iso9660-rs (Poprdi) multi-extent; cdfs (az1/iso9660-rs) extent chain.

use iso9660_forensic::{dir::FILE_FLAG_MULTI_EXTENT, IsoReader};
use std::io::Cursor;

// ── minimal ISO builder ───────────────────────────────────────────────────────

/// Build a 22-sector ISO image with a 2-extent file "BIG":
///
/// - Sector 16: PVD  (root dir LBA=18, size=2048)
/// - Sector 17: VD Terminator
/// - Sector 18: Root directory
///   - dot (.) — no Rock Ridge needed
///   - dotdot (..)
///   - "BIG" extent 1: lba=20, size=2048, flags=0x80 (multi-extent)
///   - "BIG" extent 2: lba=21, size=2048, flags=0x00 (last extent)
/// - Sector 20: extent 1 data = [0xAA; 2048]
/// - Sector 21: extent 2 data = [0xBB; 2048]
fn make_iso_multi_extent() -> Vec<u8> {
    const S: usize = 2048;
    let mut img = vec![0u8; 22 * S];

    // ── PVD ──────────────────────────────────────────────────────────────────
    {
        let p = &mut img[16 * S..17 * S];
        p[0] = 0x01;
        p[1..6].copy_from_slice(b"CD001");
        p[6] = 0x01;
        p[80..84].copy_from_slice(&22u32.to_le_bytes());
        p[84..88].copy_from_slice(&22u32.to_be_bytes());
        p[128..130].copy_from_slice(&2048u16.to_le_bytes());
        p[130..132].copy_from_slice(&2048u16.to_be_bytes());
        p[132..136].copy_from_slice(&10u32.to_le_bytes());
        p[140..144].copy_from_slice(&1u32.to_le_bytes());
        p[148..152].copy_from_slice(&1u32.to_be_bytes());
        // Embedded root dir record at offset 156.
        p[156] = 34;
        p[158..162].copy_from_slice(&18u32.to_le_bytes()); // lba
        p[162..166].copy_from_slice(&18u32.to_be_bytes());
        p[166..170].copy_from_slice(&2048u32.to_le_bytes()); // size
        p[170..174].copy_from_slice(&2048u32.to_be_bytes());
        p[181] = 0x02; // directory flag
        p[188] = 1; // name_len (dot)
    }

    // ── VD Terminator ─────────────────────────────────────────────────────────
    {
        let t = &mut img[17 * S..18 * S];
        t[0] = 0xFF;
        t[1..6].copy_from_slice(b"CD001");
        t[6] = 0x01;
    }

    // ── Root directory (sector 18) ────────────────────────────────────────────
    {
        let d = &mut img[18 * S..19 * S];

        // dot at offset 0, record_len=34 (no Rock Ridge needed here)
        d[0] = 34;
        d[2..6].copy_from_slice(&18u32.to_le_bytes());
        d[10..14].copy_from_slice(&2048u32.to_le_bytes());
        d[25] = 0x02;
        d[32] = 1;
        // d[33] = 0x00 (dot)

        // dotdot at offset 34, record_len=34
        let o = 34;
        d[o] = 34;
        d[o + 2..o + 6].copy_from_slice(&18u32.to_le_bytes());
        d[o + 10..o + 14].copy_from_slice(&2048u32.to_le_bytes());
        d[o + 25] = 0x02;
        d[o + 32] = 1;
        d[o + 33] = 0x01; // dotdot

        // "BIG" extent 1 at offset 68: flags=0x80, lba=20, size=2048
        // name="BIG" (3 bytes, odd) → su_start=36, no system_use → record_len=36
        let o = 68;
        d[o] = 36;
        d[o + 2..o + 6].copy_from_slice(&20u32.to_le_bytes()); // lba
        d[o + 6..o + 10].copy_from_slice(&20u32.to_be_bytes());
        d[o + 10..o + 14].copy_from_slice(&2048u32.to_le_bytes()); // size
        d[o + 14..o + 18].copy_from_slice(&2048u32.to_be_bytes());
        d[o + 25] = 0x80; // FILE_FLAG_MULTI_EXTENT
        d[o + 32] = 3;
        d[o + 33..o + 36].copy_from_slice(b"BIG");

        // "BIG" extent 2 at offset 104: flags=0x00, lba=21, size=2048
        let o = 104;
        d[o] = 36;
        d[o + 2..o + 6].copy_from_slice(&21u32.to_le_bytes());
        d[o + 6..o + 10].copy_from_slice(&21u32.to_be_bytes());
        d[o + 10..o + 14].copy_from_slice(&2048u32.to_le_bytes());
        d[o + 14..o + 18].copy_from_slice(&2048u32.to_be_bytes());
        d[o + 25] = 0x00; // last extent
        d[o + 32] = 3;
        d[o + 33..o + 36].copy_from_slice(b"BIG");
    }

    // ── File data ─────────────────────────────────────────────────────────────
    img[20 * S..21 * S].fill(0xAA); // extent 1
    img[21 * S..22 * S].fill(0xBB); // extent 2

    img
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[test]
fn multi_extent_flag_constant_value() {
    assert_eq!(FILE_FLAG_MULTI_EXTENT, 0x80);
}

#[test]
fn read_dir_merges_multi_extent_into_one_record() {
    let img = make_iso_multi_extent();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let records = reader.read_root_dir().unwrap();

    // Merged: only one record for "BIG", not two.
    assert_eq!(records.len(), 1, "multi-extent records must be merged into one");
    assert_eq!(records[0].iso_name(), "BIG");
}

#[test]
fn multi_extent_file_read_returns_concatenated_data() {
    let img = make_iso_multi_extent();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let records = reader.read_root_dir().unwrap();
    let big = &records[0];

    let data = reader.read_file_entry(big).unwrap();
    assert_eq!(data.len(), 4096, "both extents = 2×2048 bytes");
    assert!(data[..2048].iter().all(|&b| b == 0xAA), "extent 1 = 0xAA");
    assert!(data[2048..].iter().all(|&b| b == 0xBB), "extent 2 = 0xBB");
}

#[test]
fn single_extent_file_unaffected() {
    // With no multi-extent file in the image, read_file_entry still works.
    let img = make_iso_multi_extent();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let records = reader.read_root_dir().unwrap();
    // "BIG" is the only entry — verify its name is correct.
    assert_eq!(records[0].iso_name(), "BIG");
    // extra_extents should have exactly 1 element (the second extent).
    assert_eq!(records[0].extra_extents.len(), 1);
    assert_eq!(records[0].extra_extents[0], (21, 2048));
}

#[test]
fn is_multi_extent_method() {
    let img = make_iso_multi_extent();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let records = reader.read_root_dir().unwrap();
    // Merged record's primary flags should NOT have 0x80 set
    // (we clear it after merging so callers see a normal file).
    assert!(!records[0].is_multi_extent(), "merged record's flags must have 0x80 cleared");
}
