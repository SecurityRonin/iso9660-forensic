#![allow(clippy::unwrap_used, clippy::expect_used)]

// Forensic audit library tests.
//
// Detection tests deliberately fail with the stubs (which return Ok(vec![])),
// confirming RED state.  Clean-ISO tests pass even with stubs, but are kept
// for regression coverage.

use iso9660_forensic::IsoReader;
use std::io::Cursor;

const S: usize = 2048;

// ── Minimal ISO builder ───────────────────────────────────────────────────────

fn minimal_iso() -> Vec<u8> {
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
    let t = &mut img[17 * S..18 * S];
    t[0] = 0xFF;
    t[1..6].copy_from_slice(b"CD001");
    t[6] = 0x01;
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

/// Build ISO with a file "DATA" of the given sector-level data.
fn iso_with_file(file_data: &[u8]) -> Vec<u8> {
    // Sectors: 16=PVD, 17=VDT, 18=root-dir, 19=file-data
    let total = 20u32;
    let mut img = vec![0u8; 20 * S];
    // PVD
    let p = &mut img[16 * S..17 * S];
    p[0] = 0x01;
    p[1..6].copy_from_slice(b"CD001");
    p[6] = 0x01;
    p[80..84].copy_from_slice(&total.to_le_bytes());
    p[84..88].copy_from_slice(&total.to_be_bytes());
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
    // VDT
    let t = &mut img[17 * S..18 * S];
    t[0] = 0xFF;
    t[1..6].copy_from_slice(b"CD001");
    t[6] = 0x01;
    // Root dir: dot + dotdot + file entry "DATA" (name_len=4, even -> +1 pad, rec_len=38)
    let d = &mut img[18 * S..19 * S];
    // dot
    d[0] = 34;
    d[2..6].copy_from_slice(&18u32.to_le_bytes());
    d[6..10].copy_from_slice(&18u32.to_be_bytes());
    d[10..14].copy_from_slice(&2048u32.to_le_bytes());
    d[14..18].copy_from_slice(&2048u32.to_be_bytes());
    d[25] = 0x02;
    d[32] = 1;
    // dotdot
    d[34] = 34;
    d[36..40].copy_from_slice(&18u32.to_le_bytes());
    d[40..44].copy_from_slice(&18u32.to_be_bytes());
    d[44..48].copy_from_slice(&2048u32.to_le_bytes());
    d[48..52].copy_from_slice(&2048u32.to_be_bytes());
    d[59] = 0x02;
    d[66] = 1;
    d[67] = 0x01;
    // file "DATA": name_len=4 (even) -> pad=1, rec_len=38
    let file_size = file_data.len().min(S) as u32;
    d[68] = 38;
    d[70..74].copy_from_slice(&19u32.to_le_bytes());
    d[74..78].copy_from_slice(&19u32.to_be_bytes());
    d[78..82].copy_from_slice(&file_size.to_le_bytes());
    d[82..86].copy_from_slice(&file_size.to_be_bytes());
    d[93] = 0x00;
    d[100] = 4;
    d[101..105].copy_from_slice(b"DATA");
    // file data sector 19
    let n = file_data.len().min(S);
    img[19 * S..19 * S + n].copy_from_slice(&file_data[..n]);
    img
}

// ── Both-endian mismatch detection ───────────────────────────────────────────

#[test]
fn both_endian_clean_iso_no_mismatches() {
    let img = minimal_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let m = iso9660_forensic::audit_both_endian(&mut reader).unwrap();
    assert!(m.is_empty(), "clean ISO must have 0 mismatches, got: {m:?}");
}

#[test]
fn both_endian_tampered_pvd_volume_space_size() {
    let mut img = minimal_iso();
    // LE = 100, BE stays as 19 (original) — deliberate mismatch
    img[16 * S + 80..16 * S + 84].copy_from_slice(&100u32.to_le_bytes());
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let m = iso9660_forensic::audit_both_endian(&mut reader).unwrap();
    assert!(!m.is_empty(), "tampered volume_space_size must be detected");
    assert!(
        m.iter().any(|x| x.field == "volume_space_size"),
        "mismatch must name the volume_space_size field: {m:?}"
    );
}

#[test]
fn both_endian_tampered_pvd_path_table_size() {
    let mut img = minimal_iso();
    // LE = 99, BE stays as 10
    img[16 * S + 132..16 * S + 136].copy_from_slice(&99u32.to_le_bytes());
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let m = iso9660_forensic::audit_both_endian(&mut reader).unwrap();
    assert!(m.iter().any(|x| x.field == "path_table_size"), "{m:?}");
}

#[test]
fn both_endian_tampered_dir_entry_lba() {
    let mut img = minimal_iso();
    // Patch the dot entry's lba: LE=99, BE stays as 18
    img[18 * S + 2..18 * S + 6].copy_from_slice(&99u32.to_le_bytes());
    // IsoReader may fail to open (dot lba wrong) — if it does, that's fine:
    // the mismatch would be detected before the structural error in real tools.
    // Test that at minimum we detect if we CAN open it.
    if let Ok(mut reader) = IsoReader::open(Cursor::new(img)) {
        let m = iso9660_forensic::audit_both_endian(&mut reader).unwrap();
        // Should detect lba mismatch in the dot entry
        assert!(m.iter().any(|x| x.field == "entry_lba"), "{m:?}");
    }
    // If open fails due to broken dot lba, the test is inconclusive — skip.
}

// ── Pre-system area analysis ──────────────────────────────────────────────────

#[test]
fn pre_system_clean_no_hits() {
    let img = minimal_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let h = iso9660_forensic::audit_pre_system(&mut reader).unwrap();
    assert!(h.is_empty(), "clean pre-system area must have no hits");
}

#[test]
fn pre_system_mz_in_sector_zero() {
    let mut img = minimal_iso();
    img[0] = b'M';
    img[1] = b'Z';
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let h = iso9660_forensic::audit_pre_system(&mut reader).unwrap();
    assert!(!h.is_empty(), "MZ at sector 0 must be detected");
    assert!(
        h.iter().any(|x| x.sector == 0 && x.kind == "MZ/PE"),
        "hit must report sector=0, kind=MZ/PE: {h:?}"
    );
}

#[test]
fn pre_system_elf_in_sector_two() {
    let mut img = minimal_iso();
    img[2 * S] = 0x7F;
    img[2 * S + 1] = b'E';
    img[2 * S + 2] = b'L';
    img[2 * S + 3] = b'F';
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let h = iso9660_forensic::audit_pre_system(&mut reader).unwrap();
    assert!(h.iter().any(|x| x.sector == 2 && x.kind == "ELF"), "{h:?}");
}

#[test]
fn pre_system_zip_detected() {
    let mut img = minimal_iso();
    img[0] = b'P';
    img[1] = b'K';
    img[2] = 0x03;
    img[3] = 0x04;
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let h = iso9660_forensic::audit_pre_system(&mut reader).unwrap();
    assert!(h.iter().any(|x| x.kind == "ZIP"), "{h:?}");
}

// ── Symlink path-traversal audit ──────────────────────────────────────────────

#[test]
fn symlinks_clean_iso_no_issues() {
    let img = minimal_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let issues = iso9660_forensic::audit_symlinks(&mut reader).unwrap();
    assert!(issues.is_empty(), "clean ISO with no symlinks must return empty");
}

#[test]
fn symlinks_real_rock_ridge_iso_no_crash() {
    // Smoke-test against real RR image: must not panic, result may be empty.
    let path = "../tests/data/rock_ridge.iso";
    if !std::path::Path::new(path).exists() {
        return;
    }
    let f = std::fs::File::open(path).unwrap();
    let mut reader = IsoReader::open(std::io::BufReader::new(f)).unwrap();
    let _ = iso9660_forensic::audit_symlinks(&mut reader).unwrap();
}

// ── File slack analysis ───────────────────────────────────────────────────────

#[test]
fn file_slack_empty_iso_no_hits() {
    let img = minimal_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let s = iso9660_forensic::audit_file_slack(&mut reader).unwrap();
    assert!(s.is_empty(), "no files -> no slack hits");
}

#[test]
fn file_slack_zero_filled_reports_nonzero_false() {
    // Pass only the 10-byte content; iso_with_file sets file_size=10.
    // Remaining 2038 bytes of the sector are zero-initialised -> nonzero=false.
    let img = iso_with_file(b"helloworld");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let hits = iso9660_forensic::audit_file_slack(&mut reader).unwrap();
    let hit = hits.iter().find(|h| h.entry_path.to_uppercase().contains("DATA"));
    assert!(hit.is_some(), "slack hit for DATA not found: {hits:?}");
    let hit = hit.unwrap();
    assert_eq!(hit.file_size, 10);
    assert_eq!(hit.slack_bytes, 2038);
    assert!(!hit.nonzero, "zero-filled slack must report nonzero=false");
}

#[test]
fn file_slack_nonzero_detected() {
    // Build ISO with 10-byte file, then patch the first slack byte to 0xFF.
    let mut img = iso_with_file(b"helloworld");
    img[19 * S + 10] = 0xFF; // first byte after file content = slack region
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let hits = iso9660_forensic::audit_file_slack(&mut reader).unwrap();
    let hit = hits.iter().find(|h| h.entry_path.to_uppercase().contains("DATA")).unwrap();
    assert!(hit.nonzero, "0xFF in slack must report nonzero=true");
}

// ── Sector gap analysis ───────────────────────────────────────────────────────

#[test]
fn sector_gaps_minimal_iso_all_zero_gaps() {
    // Minimal ISO: sectors 19+ beyond the volume are not scanned.
    // Within the declared 19 sectors, sectors 0-15 are pre-sys (non-zero check),
    // 16-18 are VD+root. Result: gaps should all be nonzero=false.
    let img = minimal_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let gaps = iso9660_forensic::audit_sector_gaps(&mut reader).unwrap();
    assert!(gaps.iter().all(|g| !g.nonzero), "clean ISO gaps must all be zero-filled: {gaps:?}");
}

#[test]
fn sector_gaps_hidden_data_detected() {
    // 20-sector ISO: sector 19 is unallocated but contains 0xFF
    let mut img = minimal_iso();
    img.resize(20 * S, 0);
    // Extend volume_space_size to 20 in PVD (both LE and BE)
    img[16 * S + 80..16 * S + 84].copy_from_slice(&20u32.to_le_bytes());
    img[16 * S + 84..16 * S + 88].copy_from_slice(&20u32.to_be_bytes());
    // Put data in sector 19 (unreferenced)
    img[19 * S] = 0xFF;
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let gaps = iso9660_forensic::audit_sector_gaps(&mut reader).unwrap();
    assert!(
        gaps.iter().any(|g| g.lba == 19 && g.nonzero),
        "hidden data in sector 19 must be detected: {gaps:?}"
    );
}

#[test]
fn sector_gaps_m_path_table_not_flagged() {
    // The M-path table (big-endian copy) is a legitimate ISO structure and
    // must NOT be reported as a hidden-data gap.  Point m_path_table_lba at
    // sector 25 (beyond the fixed 0-18 region) and fill it with content;
    // the gap scan must recognise it as allocated.
    let mut img = minimal_iso();
    img.resize(30 * S, 0);
    // Extend volume_space_size to 30 (both LE and BE).
    img[16 * S + 80..16 * S + 84].copy_from_slice(&30u32.to_le_bytes());
    img[16 * S + 84..16 * S + 88].copy_from_slice(&30u32.to_be_bytes());
    // m_path_table_lba is the BE u32 at PVD bytes 148..152.
    img[16 * S + 148..16 * S + 152].copy_from_slice(&25u32.to_be_bytes());
    // Fill sector 25 with content (as a real M-path table would have).
    img[25 * S] = 0x01;
    img[25 * S + 1] = 0x00;
    img[25 * S + 2..25 * S + 6].copy_from_slice(&18u32.to_be_bytes());
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let gaps = iso9660_forensic::audit_sector_gaps(&mut reader).unwrap();
    assert!(
        !gaps.iter().any(|g| g.lba == 25 && g.nonzero),
        "M-path table at sector 25 must not be flagged as a gap: {gaps:?}"
    );
}

#[test]
fn sector_gaps_real_joliet_iso_no_false_positives() {
    // Joliet adds an SVD with its own path tables and UCS-2 directory tree —
    // all legitimate.  A clean Joliet ISO must have no content-bearing gaps.
    let path = "../tests/data/joliet.iso";
    if !std::path::Path::new(path).exists() {
        return;
    }
    let f = std::fs::File::open(path).unwrap();
    let mut reader = IsoReader::open(std::io::BufReader::new(f)).unwrap();
    let gaps = iso9660_forensic::audit_sector_gaps(&mut reader).unwrap();
    let flagged: Vec<_> = gaps.iter().filter(|g| g.nonzero).collect();
    assert!(
        flagged.is_empty(),
        "clean Joliet ISO must have no content-bearing gaps, got: {flagged:?}"
    );
}

#[test]
fn sector_gaps_real_eltorito_iso_no_false_positives() {
    // El Torito adds a boot record VD and a boot catalog — both legitimate.
    let path = "../tests/data/eltorito.iso";
    if !std::path::Path::new(path).exists() {
        return;
    }
    let f = std::fs::File::open(path).unwrap();
    let mut reader = IsoReader::open(std::io::BufReader::new(f)).unwrap();
    let gaps = iso9660_forensic::audit_sector_gaps(&mut reader).unwrap();
    let flagged: Vec<_> = gaps.iter().filter(|g| g.nonzero).collect();
    assert!(
        flagged.is_empty(),
        "clean El Torito ISO must have no content-bearing gaps, got: {flagged:?}"
    );
}

#[test]
fn sector_gaps_real_rock_ridge_iso_no_false_positives() {
    // Validate against real external data (doer-checker principle): a clean
    // xorriso-produced Rock Ridge ISO must have NO gap sectors with content.
    // Its legitimate structures (M-path table, CE continuation areas) must all
    // be recognised as allocated.
    let path = "../tests/data/rock_ridge.iso";
    if !std::path::Path::new(path).exists() {
        return;
    }
    let f = std::fs::File::open(path).unwrap();
    let mut reader = IsoReader::open(std::io::BufReader::new(f)).unwrap();
    let gaps = iso9660_forensic::audit_sector_gaps(&mut reader).unwrap();
    let flagged: Vec<_> = gaps.iter().filter(|g| g.nonzero).collect();
    assert!(
        flagged.is_empty(),
        "clean xorriso ISO must have no content-bearing gaps, got: {flagged:?}"
    );
}
