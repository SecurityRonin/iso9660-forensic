// Recursive directory walk (ECMA-119 §6.8 directory traversal).
//
// Spec: ECMA-119 4th ed §6.8 (directory structure).
// Refs: iso9660-rs (Poprdi) IsoFs::walk(); cdfs (az1) DirWalker.
//
// IsoReader::walk() returns a Vec<WalkEntry> with the full path, DirRecord,
// and depth of every file and directory, in DFS pre-order.

use iso9660_forensic::IsoReader;
use std::io::Cursor;

// ── minimal ISO builder ───────────────────────────────────────────────────────

/// Build a 3-level ISO:
///
/// - /FILE.TXT       (file)
/// - /DIR/           (directory, LBA=20, size=2048)
/// - /DIR/CHILD.TXT  (file)
///
/// Sectors:
///   16 = PVD (root LBA=18)
///   17 = Terminator
///   18 = root dir
///   19 = padding
///   20 = /DIR/ directory sector
fn make_iso_tree() -> Vec<u8> {
    const S: usize = 2048;
    let mut img = vec![0u8; 21 * S];

    // ── PVD ──────────────────────────────────────────────────────────────────
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
        p[156] = 34;
        p[158..162].copy_from_slice(&18u32.to_le_bytes());
        p[162..166].copy_from_slice(&18u32.to_be_bytes());
        p[166..170].copy_from_slice(&2048u32.to_le_bytes());
        p[170..174].copy_from_slice(&2048u32.to_be_bytes());
        p[181] = 0x02;
        p[188] = 1;
    }

    // ── VD Terminator ─────────────────────────────────────────────────────────
    {
        let t = &mut img[17 * S..18 * S];
        t[0] = 0xFF;
        t[1..6].copy_from_slice(b"CD001");
        t[6] = 0x01;
    }

    // ── Sector 18: root directory ─────────────────────────────────────────────
    {
        let d = &mut img[18 * S..19 * S];

        // dot at 0 (34 bytes)
        d[0] = 34;
        d[2..6].copy_from_slice(&18u32.to_le_bytes());
        d[10..14].copy_from_slice(&2048u32.to_le_bytes());
        d[25] = 0x02;
        d[32] = 1;

        // dotdot at 34 (34 bytes)
        let o = 34;
        d[o] = 34;
        d[o + 2..o + 6].copy_from_slice(&18u32.to_le_bytes());
        d[o + 10..o + 14].copy_from_slice(&2048u32.to_le_bytes());
        d[o + 25] = 0x02;
        d[o + 32] = 1;
        d[o + 33] = 0x01;

        // "FILE.TXT" at 68: name=8 bytes (even), su_start=42, record_len=42
        let o = 68;
        d[o] = 42;
        // lba=0, size=0
        d[o + 32] = 8;
        d[o + 33..o + 41].copy_from_slice(b"FILE.TXT");
        // d[o+41] = alignment pad — zero

        // "DIR" at 110: name=3 bytes (odd), su_start=36, record_len=36
        let o = 110;
        d[o] = 36;
        d[o + 2..o + 6].copy_from_slice(&20u32.to_le_bytes()); // LBA=20
        d[o + 6..o + 10].copy_from_slice(&20u32.to_be_bytes());
        d[o + 10..o + 14].copy_from_slice(&2048u32.to_le_bytes()); // size=2048
        d[o + 14..o + 18].copy_from_slice(&2048u32.to_be_bytes());
        d[o + 25] = 0x02; // directory
        d[o + 32] = 3;
        d[o + 33..o + 36].copy_from_slice(b"DIR");
    }

    // ── Sector 20: /DIR/ directory ────────────────────────────────────────────
    {
        let d = &mut img[20 * S..21 * S];

        // dot at 0 (34 bytes)
        d[0] = 34;
        d[2..6].copy_from_slice(&20u32.to_le_bytes());
        d[10..14].copy_from_slice(&2048u32.to_le_bytes());
        d[25] = 0x02;
        d[32] = 1;

        // dotdot at 34 (pointing to root, LBA=18)
        let o = 34;
        d[o] = 34;
        d[o + 2..o + 6].copy_from_slice(&18u32.to_le_bytes());
        d[o + 10..o + 14].copy_from_slice(&2048u32.to_le_bytes());
        d[o + 25] = 0x02;
        d[o + 32] = 1;
        d[o + 33] = 0x01;

        // "CHILD.TXT" at 68: name=9 bytes (odd), su_start=42, record_len=42
        let o = 68;
        d[o] = 42;
        d[o + 32] = 9;
        d[o + 33..o + 42].copy_from_slice(b"CHILD.TXT");
    }

    img
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[test]
fn walk_returns_all_entries() {
    let img = make_iso_tree();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let entries = reader.walk().unwrap();

    let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    assert!(paths.contains(&"FILE.TXT"), "FILE.TXT must be in walk output");
    assert!(paths.contains(&"DIR"), "DIR must be in walk output");
    assert!(paths.contains(&"DIR/CHILD.TXT"), "DIR/CHILD.TXT must be in walk output");
    assert_eq!(entries.len(), 3, "exactly 3 entries");
}

#[test]
fn walk_entry_depth_correct() {
    let img = make_iso_tree();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let entries = reader.walk().unwrap();

    let file_txt = entries.iter().find(|e| e.path == "FILE.TXT").unwrap();
    let dir = entries.iter().find(|e| e.path == "DIR").unwrap();
    let child = entries.iter().find(|e| e.path == "DIR/CHILD.TXT").unwrap();

    assert_eq!(file_txt.depth, 0, "FILE.TXT depth=0");
    assert_eq!(dir.depth, 0, "DIR depth=0");
    assert_eq!(child.depth, 1, "CHILD.TXT depth=1");
}

#[test]
fn walk_entry_is_dir_flag() {
    let img = make_iso_tree();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let entries = reader.walk().unwrap();

    let dir_entry = entries.iter().find(|e| e.path == "DIR").unwrap();
    let file_entry = entries.iter().find(|e| e.path == "FILE.TXT").unwrap();
    assert!(dir_entry.record.is_dir(), "DIR must be marked as directory");
    assert!(!file_entry.record.is_dir(), "FILE.TXT must not be marked as directory");
}

#[test]
fn walk_struct_fields_accessible() {
    let img = make_iso_tree();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let entries = reader.walk().unwrap();
    let e = entries.first().unwrap();
    // Verify the public fields exist and are readable.
    let _: &str = &e.path;
    let _: usize = e.depth;
    let _ = &e.record;
}
