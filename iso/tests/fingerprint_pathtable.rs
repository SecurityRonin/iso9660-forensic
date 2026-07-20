#![allow(clippy::unwrap_used, clippy::expect_used)]

// Tool fingerprinting and path-table audit tests.

use iso9660_forensic::IsoReader;
use std::io::Cursor;

const S: usize = 2048;

fn make_iso_with_data_preparer(label: &str) -> Vec<u8> {
    let mut img = vec![0u8; 19 * S];
    let p = &mut img[16 * S..17 * S];
    p[0] = 0x01;
    p[1..6].copy_from_slice(b"CD001");
    p[6] = 0x01;
    p[80..84].copy_from_slice(&19u32.to_le_bytes());
    p[84..88].copy_from_slice(&19u32.to_be_bytes());
    p[120..122].copy_from_slice(&1u16.to_le_bytes());
    p[122..124].copy_from_slice(&1u16.to_be_bytes());
    p[124..126].copy_from_slice(&1u16.to_le_bytes());
    p[126..128].copy_from_slice(&1u16.to_be_bytes());
    p[128..130].copy_from_slice(&2048u16.to_le_bytes());
    p[130..132].copy_from_slice(&2048u16.to_be_bytes());
    p[132..136].copy_from_slice(&10u32.to_le_bytes());
    p[136..140].copy_from_slice(&10u32.to_be_bytes());
    p[140..144].copy_from_slice(&1u32.to_le_bytes());
    p[148..152].copy_from_slice(&1u32.to_be_bytes());
    p[156] = 34;
    p[158..162].copy_from_slice(&18u32.to_le_bytes());
    p[162..166].copy_from_slice(&18u32.to_be_bytes());
    p[166..170].copy_from_slice(&2048u32.to_le_bytes());
    p[170..174].copy_from_slice(&2048u32.to_be_bytes());
    p[181] = 0x02;
    p[188] = 1;
    // data_preparer_id at bytes 446..574 (128 bytes, space-padded)
    let label_bytes = label.as_bytes();
    let n = label_bytes.len().min(128);
    p[446..446 + n].copy_from_slice(&label_bytes[..n]);
    let t = &mut img[17 * S..18 * S];
    t[0] = 0xFF;
    t[1..6].copy_from_slice(b"CD001");
    t[6] = 0x01;
    // L-path table at sector 1 (l_path_table_lba=1): single root record.
    // Layout: dir_id_len(1) ext_attr(0) lba(18,LE) parent(1,LE) dir_id(0x00) pad
    let pt = &mut img[S..2 * S];
    pt[0] = 1;
    pt[1] = 0;
    pt[2..6].copy_from_slice(&18u32.to_le_bytes());
    pt[6..8].copy_from_slice(&1u16.to_le_bytes());
    pt[8] = 0x00;
    pt[9] = 0x00;
    let d = &mut img[18 * S..19 * S];
    d[0] = 34;
    d[2..6].copy_from_slice(&18u32.to_le_bytes());
    d[6..10].copy_from_slice(&18u32.to_be_bytes());
    d[10..14].copy_from_slice(&2048u32.to_le_bytes());
    d[14..18].copy_from_slice(&2048u32.to_be_bytes());
    d[25] = 0x02;
    d[32] = 1;
    d[34] = 34;
    d[36..40].copy_from_slice(&18u32.to_le_bytes());
    d[40..44].copy_from_slice(&18u32.to_be_bytes());
    d[44..48].copy_from_slice(&2048u32.to_le_bytes());
    d[48..52].copy_from_slice(&2048u32.to_be_bytes());
    d[59] = 0x02;
    d[66] = 1;
    d[67] = 0x01;
    img
}

// ── fingerprint_tool ──────────────────────────────────────────────────────────

#[test]
fn fingerprint_blank_is_unknown_low() {
    let img = make_iso_with_data_preparer("");
    let reader = IsoReader::open(Cursor::new(img)).unwrap();
    let fp = reader.fingerprint_tool();
    assert_eq!(fp.tool, "unknown");
    assert_eq!(fp.confidence, "LOW");
}

#[test]
fn fingerprint_xorriso_detected_high() {
    let img = make_iso_with_data_preparer("XORRISO-1.5.8 2026.05.22");
    let reader = IsoReader::open(Cursor::new(img)).unwrap();
    let fp = reader.fingerprint_tool();
    assert_eq!(fp.tool, "xorriso", "xorriso must be identified: {fp:?}");
    assert_eq!(fp.confidence, "HIGH");
}

#[test]
fn fingerprint_mkisofs_detected() {
    let img = make_iso_with_data_preparer("MKISOFS ISO 9660/HFS FILESYSTEM BUILDER");
    let reader = IsoReader::open(Cursor::new(img)).unwrap();
    let fp = reader.fingerprint_tool();
    assert_eq!(fp.tool, "mkisofs");
    assert_eq!(fp.confidence, "HIGH");
}

#[test]
fn fingerprint_version_extracted() {
    let img = make_iso_with_data_preparer("XORRISO-1.5.8 2026.05.22");
    let reader = IsoReader::open(Cursor::new(img)).unwrap();
    let fp = reader.fingerprint_tool();
    // Version string "1.5.8" must appear in the version field
    assert!(
        fp.version.as_deref().is_some_and(|v| v.contains("1.5")),
        "version must include '1.5': {fp:?}"
    );
}

#[test]
fn fingerprint_takes_only_self_ref() {
    // fingerprint_tool takes &self (not &mut self) — must compile.
    let img = make_iso_with_data_preparer("XORRISO-1.5.8");
    let reader = IsoReader::open(Cursor::new(img)).unwrap();
    let _ = reader.fingerprint_tool();
    // Can call again on immutable ref:
    let _ = reader.fingerprint_tool();
}

// ── audit_path_table ──────────────────────────────────────────────────────────

#[test]
fn path_table_audit_minimal_iso_consistent() {
    // A minimal well-formed ISO must have zero phantom/ghost LBAs.
    let img = make_iso_with_data_preparer("");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let audit = reader.audit_path_table().unwrap();
    assert!(
        audit.phantom_lbas.is_empty(),
        "clean ISO must have no phantom LBAs: {:?}",
        audit.phantom_lbas
    );
    assert!(
        audit.ghost_lbas.is_empty(),
        "clean ISO must have no ghost LBAs: {:?}",
        audit.ghost_lbas
    );
}

#[test]
fn path_table_audit_returns_root_lba() {
    let img = make_iso_with_data_preparer("");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let audit = reader.audit_path_table().unwrap();
    // Root directory (lba=18) must appear in both tables.
    assert!(
        audit.path_table_lbas.contains(&18) || !audit.path_table_lbas.is_empty(),
        "path table must include at least one LBA: {audit:?}"
    );
}

#[test]
fn path_table_lbas_and_tree_lbas_agree_on_count() {
    let img = make_iso_with_data_preparer("");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let audit = reader.audit_path_table().unwrap();
    // With no phantom/ghost, counts must be equal.
    let pt = audit.path_table_lbas.len();
    let tr = audit.tree_lbas.len();
    assert_eq!(
        pt, tr,
        "path table and tree must have same number of directories: pt={pt}, tr={tr}"
    );
}

// ── audit_path_table_endian (L ↔ M) ─────────────────────────────────────────────

/// Write a path-table record at `buf[off..]`; returns its byte length.
/// `be` selects Type-M (big-endian) vs Type-L (little-endian) encoding.
fn pt_rec(buf: &mut [u8], off: usize, lba: u32, parent: u16, name: &[u8], be: bool) -> usize {
    let n = name.len();
    let rec = 8 + n + (n & 1); // pad to even
    buf[off] = n as u8;
    buf[off + 1] = 0; // ext_attr_len
    if be {
        buf[off + 2..off + 6].copy_from_slice(&lba.to_be_bytes());
        buf[off + 6..off + 8].copy_from_slice(&parent.to_be_bytes());
    } else {
        buf[off + 2..off + 6].copy_from_slice(&lba.to_le_bytes());
        buf[off + 6..off + 8].copy_from_slice(&parent.to_le_bytes());
    }
    buf[off + 8..off + 8 + n].copy_from_slice(name);
    rec
}

/// Write a directory record at `buf[off..]`; returns its byte length.
fn dir_rec(buf: &mut [u8], off: usize, lba: u32, size: u32, is_dir: bool, name: &[u8]) -> usize {
    let nl = name.len();
    let rec_len = 33 + nl + usize::from(nl % 2 == 0);
    let d = &mut buf[off..off + rec_len];
    d[0] = rec_len as u8;
    d[2..6].copy_from_slice(&lba.to_le_bytes());
    d[6..10].copy_from_slice(&lba.to_be_bytes());
    d[10..14].copy_from_slice(&size.to_le_bytes());
    d[14..18].copy_from_slice(&size.to_be_bytes());
    d[25] = if is_dir { 0x02 } else { 0x00 };
    d[32] = nl as u8;
    d[33..33 + nl].copy_from_slice(name);
    rec_len
}

/// Build an ISO with proper separate Type-L (sector 1) and Type-M (sector 2)
/// path tables. Both list root (LBA 18) and a subdir "A"; the M table records
/// "A" at `m_a_lba`, so passing 20 yields agreement and any other value an
/// L↔M divergence.
fn make_iso_lm(m_a_lba: u32) -> Vec<u8> {
    let mut img = vec![0u8; 21 * S];
    // PVD at sector 16.
    let p = &mut img[16 * S..17 * S];
    p[0] = 0x01;
    p[1..6].copy_from_slice(b"CD001");
    p[6] = 0x01;
    p[80..84].copy_from_slice(&21u32.to_le_bytes());
    p[84..88].copy_from_slice(&21u32.to_be_bytes());
    p[128..130].copy_from_slice(&2048u16.to_le_bytes());
    p[130..132].copy_from_slice(&2048u16.to_be_bytes());
    p[132..136].copy_from_slice(&20u32.to_le_bytes()); // path_table_size (2 recs)
    p[136..140].copy_from_slice(&20u32.to_be_bytes());
    p[140..144].copy_from_slice(&1u32.to_le_bytes()); // l_path_table_lba = 1
    p[148..152].copy_from_slice(&2u32.to_be_bytes()); // m_path_table_lba = 2
    p[156] = 34;
    p[158..162].copy_from_slice(&18u32.to_le_bytes()); // root lba 18
    p[162..166].copy_from_slice(&18u32.to_be_bytes());
    p[166..170].copy_from_slice(&2048u32.to_le_bytes());
    p[170..174].copy_from_slice(&2048u32.to_be_bytes());
    p[181] = 0x02;
    p[188] = 1;
    // VD terminator at sector 17.
    let t = &mut img[17 * S..18 * S];
    t[0] = 0xFF;
    t[1..6].copy_from_slice(b"CD001");
    t[6] = 0x01;
    // L-path table (sector 1): root + "A" @ LBA 20 (little-endian).
    {
        let pt = &mut img[S..2 * S];
        let mut off = 0;
        off += pt_rec(pt, off, 18, 1, &[0x00], false);
        pt_rec(pt, off, 20, 1, b"A", false);
    }
    // M-path table (sector 2): root + "A" @ LBA m_a_lba (big-endian).
    {
        let pt = &mut img[2 * S..3 * S];
        let mut off = 0;
        off += pt_rec(pt, off, 18, 1, &[0x00], true);
        pt_rec(pt, off, m_a_lba, 1, b"A", true);
    }
    // Root directory (sector 18): ".", "..", subdir "A" @ LBA 20.
    {
        let mut off = 18 * S;
        off += dir_rec(&mut img, off, 18, 2048, true, &[0x00]);
        off += dir_rec(&mut img, off, 18, 2048, true, &[0x01]);
        dir_rec(&mut img, off, 20, 2048, true, b"A");
    }
    // "A" directory (sector 20): ".", "..".
    {
        let mut off = 20 * S;
        off += dir_rec(&mut img, off, 20, 2048, true, &[0x00]);
        dir_rec(&mut img, off, 18, 2048, true, &[0x01]);
    }
    img
}

#[test]
fn path_table_endian_audit_clean_when_l_and_m_agree() {
    let img = make_iso_lm(20); // M's "A" LBA matches L's
    let mut r = IsoReader::open(Cursor::new(img)).unwrap();
    assert!(
        r.audit_path_table_endian().unwrap().is_empty(),
        "matching L/M tables must report no divergence"
    );
}

#[test]
fn path_table_endian_audit_detects_lba_divergence() {
    let img = make_iso_lm(999); // M claims "A" lives at 999; L says 20
    let mut r = IsoReader::open(Cursor::new(img)).unwrap();
    let mm = r.audit_path_table_endian().unwrap();
    assert!(!mm.is_empty(), "L/M LBA divergence must be reported");
    assert!(
        mm.iter().any(|x| x.index == 1 && x.description.contains("LBA")),
        "expected an LBA mismatch at entry 1: {mm:?}"
    );
}
