#![allow(clippy::unwrap_used, clippy::expect_used)]

// IsoReader::find_path — path-based directory entry lookup.
//
// Spec: ECMA-119 §6.8.2 (directory structure); IEEE P1282 NM (alternate names).
// Refs: cdfs ISO9660::open(path) — splits "/" and walks directory tree.
//       ids1024/iso9660-rs ISODirectory::find(identifier) — case-insensitive match.

use iso9660_forensic::IsoReader;
use std::io::Cursor;

// ── helpers ───────────────────────────────────────────────────────────────────

/// Two-level ISO: root has subdir "SUB" (lba=20), which has file "FILE.TXT" (lba=22).
fn make_nested_iso() -> Vec<u8> {
    const S: usize = 2048;
    // Sectors: 0-15 unused, 16=PVD, 17=VDT, 18=root-dir, 19=sub-dir, 20=file
    let mut img = vec![0u8; 21 * S];

    // PVD at sector 16
    {
        let p = &mut img[16 * S..17 * S];
        p[0] = 0x01;
        p[1..6].copy_from_slice(b"CD001");
        p[6] = 0x01;
        p[80..84].copy_from_slice(&21u32.to_le_bytes());
        p[84..88].copy_from_slice(&21u32.to_be_bytes());
        p[128..130].copy_from_slice(&2048u16.to_le_bytes());
        p[130..132].copy_from_slice(&2048u16.to_be_bytes());
        p[132..136].copy_from_slice(&10u32.to_le_bytes());
        p[140..144].copy_from_slice(&1u32.to_le_bytes());
        p[148..152].copy_from_slice(&1u32.to_be_bytes());
        // Root dir record at offset 156: len=34, lba=18, size=2048
        p[156] = 34;
        p[158..162].copy_from_slice(&18u32.to_le_bytes());
        p[162..166].copy_from_slice(&18u32.to_be_bytes());
        p[166..170].copy_from_slice(&2048u32.to_le_bytes());
        p[170..174].copy_from_slice(&2048u32.to_be_bytes());
        p[181] = 0x02;
        p[188] = 1;
    }
    // VD Terminator at sector 17
    {
        let t = &mut img[17 * S..18 * S];
        t[0] = 0xFF;
        t[1..6].copy_from_slice(b"CD001");
        t[6] = 0x01;
    }
    // Root dir sector 18: dot, dotdot, "SUB" directory entry
    {
        let d = &mut img[18 * S..19 * S];
        // dot
        d[0] = 34;
        d[2..6].copy_from_slice(&18u32.to_le_bytes());
        d[10..14].copy_from_slice(&2048u32.to_le_bytes());
        d[25] = 0x02;
        d[32] = 1;
        // dotdot
        let o = 34;
        d[o] = 34;
        d[o + 2..o + 6].copy_from_slice(&18u32.to_le_bytes());
        d[o + 10..o + 14].copy_from_slice(&2048u32.to_le_bytes());
        d[o + 25] = 0x02;
        d[o + 32] = 1;
        d[o + 33] = 0x01;
        // "SUB" entry: name_len=3, record_len=36 (33+3 = 36, even — wait 36 is even OK)
        // Actually: 33 + 3 = 36. su_start = 33+3+(3%2==1?0:1) = 33+3+0 = 36. record_len = 36.
        let o = 68;
        d[o] = 36; // record_len=36
        d[o + 2..o + 6].copy_from_slice(&19u32.to_le_bytes()); // lba=19
        d[o + 6..o + 10].copy_from_slice(&19u32.to_be_bytes());
        d[o + 10..o + 14].copy_from_slice(&2048u32.to_le_bytes()); // size
        d[o + 14..o + 18].copy_from_slice(&2048u32.to_be_bytes());
        d[o + 25] = 0x02; // directory flag
        d[o + 32] = 3;
        d[o + 33..o + 36].copy_from_slice(b"SUB");
    }
    // Sub dir sector 19: dot, dotdot, "FILE.TXT" file entry
    {
        let d = &mut img[19 * S..20 * S];
        // dot
        d[0] = 34;
        d[2..6].copy_from_slice(&19u32.to_le_bytes());
        d[10..14].copy_from_slice(&2048u32.to_le_bytes());
        d[25] = 0x02;
        d[32] = 1;
        // dotdot
        let o = 34;
        d[o] = 34;
        d[o + 2..o + 6].copy_from_slice(&18u32.to_le_bytes());
        d[o + 10..o + 14].copy_from_slice(&2048u32.to_le_bytes());
        d[o + 25] = 0x02;
        d[o + 32] = 1;
        d[o + 33] = 0x01;
        // "FILE.TXT": name_len=8, su_start=33+8=41+(8%2==0?1:0)=42, record_len=42
        let o = 68;
        d[o] = 42; // record_len=42
        d[o + 2..o + 6].copy_from_slice(&20u32.to_le_bytes()); // lba=20
        d[o + 6..o + 10].copy_from_slice(&20u32.to_be_bytes());
        d[o + 10..o + 14].copy_from_slice(&100u32.to_le_bytes()); // size=100
        d[o + 14..o + 18].copy_from_slice(&100u32.to_be_bytes());
        d[o + 32] = 8;
        d[o + 33..o + 41].copy_from_slice(b"FILE.TXT");
    }
    // File data at sector 20
    img[20 * S..20 * S + 100].fill(0xAB);
    img
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[test]
fn find_path_root_file_not_found() {
    let img = make_nested_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let result = reader.find_path("MISSING.TXT").unwrap();
    assert!(result.is_none(), "nonexistent path must return None");
}

#[test]
fn find_path_subdir_entry() {
    let img = make_nested_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let entry = reader.find_path("SUB").unwrap().expect("SUB directory must be found");
    assert!(entry.is_dir(), "SUB must be a directory");
}

#[test]
fn find_path_nested_file() {
    let img = make_nested_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let entry = reader.find_path("SUB/FILE.TXT").unwrap().expect("SUB/FILE.TXT must be found");
    assert!(!entry.is_dir(), "FILE.TXT must be a file");
    assert_eq!(entry.size, 100);
}

#[test]
fn find_path_leading_slash_normalized() {
    let img = make_nested_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    // Leading slash must be handled identically to no leading slash.
    let a = reader.find_path("SUB/FILE.TXT").unwrap();
    let b = reader.find_path("/SUB/FILE.TXT").unwrap();
    assert!(a.is_some() && b.is_some());
    assert_eq!(a.unwrap().lba, b.unwrap().lba);
}

#[test]
fn find_path_case_insensitive() {
    let img = make_nested_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    // ISO 9660 names are uppercase; lookup must be case-insensitive.
    let entry = reader.find_path("sub/file.txt").unwrap();
    assert!(entry.is_some(), "lowercase lookup must match uppercase ISO name");
}
