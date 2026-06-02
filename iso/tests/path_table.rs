// Path table parsing + Type-L vs Type-M cross-validation.
//
// Spec: ECMA-119 4th ed §8.4.19–§8.4.20 (L and M Path Tables).
// Refs: iso9660-rs (Poprdi) path_table.rs; cdfs PathTable parser.
//
// Path table record layout (ECMA-119 §9.4):
//   [0]      dir_id_len  (u8)
//   [1]      ext_attr_len (u8, always 0)
//   [2..6]   lba         (u32, LE in Type-L, BE in Type-M)
//   [6..8]   parent_dir_num (u16, LE in Type-L, BE in Type-M)
//   [8..]    dir_id      (dir_id_len bytes, padded to even with 0x00)

use iso9660_forensic::path_table::{parse_l_path_table, parse_m_path_table,
                                   validate_path_tables, PathTableEntry};

// ── builders ─────────────────────────────────────────────────────────────────

/// Build a minimal Type-L (little-endian) path table with 2 entries.
fn l_table_two_dirs() -> Vec<u8> {
    // Entry 1: root "\" — dir_id = 0x00, lba=18, parent=1
    // Entry 2: "DIR" — dir_id = b"DIR", lba=20, parent=1
    let mut buf = Vec::new();

    // Entry 1: root
    buf.push(1u8);          // dir_id_len
    buf.push(0u8);          // ext_attr_len
    buf.extend_from_slice(&18u32.to_le_bytes()); // lba LE
    buf.extend_from_slice(&1u16.to_le_bytes());  // parent_dir_num LE
    buf.push(0x00);         // dir_id (root sentinel)
    buf.push(0x00);         // pad to even

    // Entry 2: "DIR"
    buf.push(3u8);          // dir_id_len
    buf.push(0u8);
    buf.extend_from_slice(&20u32.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(b"DIR"); // dir_id (3 bytes, odd → pad)
    buf.push(0x00);         // padding

    buf
}

/// Same entries in Type-M (big-endian) format.
fn m_table_two_dirs() -> Vec<u8> {
    let mut buf = Vec::new();

    // Entry 1: root
    buf.push(1u8);
    buf.push(0u8);
    buf.extend_from_slice(&18u32.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.push(0x00);
    buf.push(0x00);

    // Entry 2: "DIR"
    buf.push(3u8);
    buf.push(0u8);
    buf.extend_from_slice(&20u32.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(b"DIR");
    buf.push(0x00);

    buf
}

// ── PathTableEntry struct tests ───────────────────────────────────────────────

#[test]
fn parse_l_table_entry_count() {
    let entries = parse_l_path_table(&l_table_two_dirs()).unwrap();
    assert_eq!(entries.len(), 2, "must parse 2 entries");
}

#[test]
fn parse_l_table_root_entry() {
    let entries = parse_l_path_table(&l_table_two_dirs()).unwrap();
    assert_eq!(entries[0].lba, 18);
    assert_eq!(entries[0].parent_dir_num, 1);
    assert_eq!(entries[0].dir_id, vec![0x00u8]);
}

#[test]
fn parse_l_table_dir_entry() {
    let entries = parse_l_path_table(&l_table_two_dirs()).unwrap();
    assert_eq!(entries[1].lba, 20);
    assert_eq!(entries[1].parent_dir_num, 1);
    assert_eq!(entries[1].dir_id, b"DIR");
}

#[test]
fn parse_m_table_matches_l_table() {
    let l = parse_l_path_table(&l_table_two_dirs()).unwrap();
    let m = parse_m_path_table(&m_table_two_dirs()).unwrap();
    assert_eq!(l.len(), m.len());
    for (le, me) in l.iter().zip(m.iter()) {
        assert_eq!(le.lba, me.lba, "LBA mismatch");
        assert_eq!(le.parent_dir_num, me.parent_dir_num, "parent mismatch");
        assert_eq!(le.dir_id, me.dir_id, "dir_id mismatch");
    }
}

#[test]
fn path_table_entry_struct_fields() {
    let e = PathTableEntry { lba: 42, parent_dir_num: 1, dir_id: b"TEST".to_vec() };
    assert_eq!(e.lba, 42);
    assert_eq!(e.parent_dir_num, 1);
    assert_eq!(e.dir_id, b"TEST");
}

// ── Cross-validation tests ────────────────────────────────────────────────────

#[test]
fn validate_matching_tables_ok() {
    let l = parse_l_path_table(&l_table_two_dirs()).unwrap();
    let m = parse_m_path_table(&m_table_two_dirs()).unwrap();
    let mismatches = validate_path_tables(&l, &m);
    assert!(mismatches.is_empty(), "matching tables must produce no mismatches");
}

#[test]
fn validate_detects_lba_mismatch() {
    let l_buf = l_table_two_dirs();
    let mut m_buf = m_table_two_dirs();
    // Corrupt the LBA of entry 2 in the M table.
    // Entry 2 starts at offset 10 (after 10-byte entry 1 padded).
    // LBA is at m_buf[10+2..10+6] in BE.
    m_buf[12..16].copy_from_slice(&99u32.to_be_bytes()); // wrong LBA
    let l = parse_l_path_table(&l_buf).unwrap();
    let m = parse_m_path_table(&m_buf).unwrap();
    let mismatches = validate_path_tables(&l, &m);
    assert!(!mismatches.is_empty(), "LBA mismatch must be detected");
    assert_eq!(mismatches[0].index, 1, "mismatch at entry index 1");
}

#[test]
fn validate_detects_length_mismatch() {
    let l = parse_l_path_table(&l_table_two_dirs()).unwrap();
    // M table with only 1 entry.
    let mut m_buf = Vec::new();
    m_buf.push(1u8); m_buf.push(0u8);
    m_buf.extend_from_slice(&18u32.to_be_bytes());
    m_buf.extend_from_slice(&1u16.to_be_bytes());
    m_buf.push(0x00); m_buf.push(0x00);
    let m = parse_m_path_table(&m_buf).unwrap();
    let mismatches = validate_path_tables(&l, &m);
    assert!(!mismatches.is_empty(), "count mismatch must be detected");
}
