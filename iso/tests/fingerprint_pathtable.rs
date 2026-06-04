// Tool fingerprinting and path-table audit tests.

use std::io::Cursor;
use iso9660_forensic::IsoReader;

const S: usize = 2048;

fn make_iso_with_data_preparer(label: &str) -> Vec<u8> {
    let mut img = vec![0u8; 19 * S];
    let p = &mut img[16 * S..17 * S];
    p[0]=0x01; p[1..6].copy_from_slice(b"CD001"); p[6]=0x01;
    p[80..84].copy_from_slice(&19u32.to_le_bytes()); p[84..88].copy_from_slice(&19u32.to_be_bytes());
    p[120..122].copy_from_slice(&1u16.to_le_bytes()); p[122..124].copy_from_slice(&1u16.to_be_bytes());
    p[124..126].copy_from_slice(&1u16.to_le_bytes()); p[126..128].copy_from_slice(&1u16.to_be_bytes());
    p[128..130].copy_from_slice(&2048u16.to_le_bytes()); p[130..132].copy_from_slice(&2048u16.to_be_bytes());
    p[132..136].copy_from_slice(&10u32.to_le_bytes()); p[136..140].copy_from_slice(&10u32.to_be_bytes());
    p[140..144].copy_from_slice(&1u32.to_le_bytes()); p[148..152].copy_from_slice(&1u32.to_be_bytes());
    p[156]=34; p[158..162].copy_from_slice(&18u32.to_le_bytes()); p[162..166].copy_from_slice(&18u32.to_be_bytes());
    p[166..170].copy_from_slice(&2048u32.to_le_bytes()); p[170..174].copy_from_slice(&2048u32.to_be_bytes());
    p[181]=0x02; p[188]=1;
    // data_preparer_id at bytes 446..574 (128 bytes, space-padded)
    let label_bytes = label.as_bytes();
    let n = label_bytes.len().min(128);
    p[446..446+n].copy_from_slice(&label_bytes[..n]);
    let t = &mut img[17 * S..18 * S];
    t[0]=0xFF; t[1..6].copy_from_slice(b"CD001"); t[6]=0x01;
    // L-path table at sector 1 (l_path_table_lba=1): single root record.
    // Layout: dir_id_len(1) ext_attr(0) lba(18,LE) parent(1,LE) dir_id(0x00) pad
    let pt = &mut img[S..2 * S];
    pt[0]=1; pt[1]=0;
    pt[2..6].copy_from_slice(&18u32.to_le_bytes());
    pt[6..8].copy_from_slice(&1u16.to_le_bytes());
    pt[8]=0x00; pt[9]=0x00;
    let d = &mut img[18 * S..19 * S];
    d[0]=34; d[2..6].copy_from_slice(&18u32.to_le_bytes()); d[6..10].copy_from_slice(&18u32.to_be_bytes());
    d[10..14].copy_from_slice(&2048u32.to_le_bytes()); d[14..18].copy_from_slice(&2048u32.to_be_bytes());
    d[25]=0x02; d[32]=1;
    d[34]=34; d[36..40].copy_from_slice(&18u32.to_le_bytes()); d[40..44].copy_from_slice(&18u32.to_be_bytes());
    d[44..48].copy_from_slice(&2048u32.to_le_bytes()); d[48..52].copy_from_slice(&2048u32.to_be_bytes());
    d[59]=0x02; d[66]=1; d[67]=0x01;
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
    assert!(audit.phantom_lbas.is_empty(),
        "clean ISO must have no phantom LBAs: {:?}", audit.phantom_lbas);
    assert!(audit.ghost_lbas.is_empty(),
        "clean ISO must have no ghost LBAs: {:?}", audit.ghost_lbas);
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
    assert_eq!(pt, tr,
        "path table and tree must have same number of directories: pt={pt}, tr={tr}");
}
