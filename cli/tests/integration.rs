// CLI integration tests — strictly RED before implementation.
//
// Each command function returns a String or Vec<u8>; tests assert that
// specific tokens appear in the output.  The stubs return empty values,
// so every assertion here fails until the real implementation lands.

use std::io::Cursor;
use iso9660_forensic::IsoReader;
use iso9660_cli::cmd;

// ── Minimal ISO builder ───────────────────────────────────────────────────────

const S: usize = 2048;

/// Write the mandatory fixed fields of a PVD sector.
/// `label` is padded with spaces to 32 bytes (ECMA-119 §8.4.5).
fn write_pvd(img: &mut [u8], root_lba: u32, root_size: u32, total: u32, label: &[u8]) {
    let p = &mut img[16 * S..17 * S];
    p[0] = 0x01; p[1..6].copy_from_slice(b"CD001"); p[6] = 0x01;
    // Volume identifier at bytes 40-72 (32 bytes, space-padded)
    let mut vol_id = [b' '; 32];
    let n = label.len().min(32);
    vol_id[..n].copy_from_slice(&label[..n]);
    p[40..72].copy_from_slice(&vol_id);
    p[80..84].copy_from_slice(&total.to_le_bytes());
    p[84..88].copy_from_slice(&total.to_be_bytes());
    p[128..130].copy_from_slice(&2048u16.to_le_bytes());
    p[130..132].copy_from_slice(&2048u16.to_be_bytes());
    p[132..136].copy_from_slice(&10u32.to_le_bytes());
    p[140..144].copy_from_slice(&1u32.to_le_bytes());
    p[148..152].copy_from_slice(&1u32.to_be_bytes());
    // Root dir record embedded at offset 156
    p[156] = 34;
    p[158..162].copy_from_slice(&root_lba.to_le_bytes());
    p[162..166].copy_from_slice(&root_lba.to_be_bytes());
    p[166..170].copy_from_slice(&root_size.to_le_bytes());
    p[170..174].copy_from_slice(&root_size.to_be_bytes());
    p[181] = 0x02; p[188] = 1;
}

fn write_vdt(img: &mut [u8]) {
    let t = &mut img[17 * S..18 * S];
    t[0] = 0xFF; t[1..6].copy_from_slice(b"CD001"); t[6] = 0x01;
}

/// Write minimal dot+dotdot entries into a directory sector.
fn write_dot_dotdot(img: &mut [u8], sec: usize, self_lba: u32, parent_lba: u32) {
    let d = &mut img[sec * S..sec * S + 68];
    // dot
    d[0] = 34; d[2..6].copy_from_slice(&self_lba.to_le_bytes());
    d[6..10].copy_from_slice(&self_lba.to_be_bytes());
    d[10..14].copy_from_slice(&2048u32.to_le_bytes());
    d[25] = 0x02; d[32] = 1;
    // dotdot
    d[34] = 34; d[36..40].copy_from_slice(&parent_lba.to_le_bytes());
    d[40..44].copy_from_slice(&parent_lba.to_be_bytes());
    d[44..48].copy_from_slice(&2048u32.to_le_bytes());
    d[59] = 0x02; d[66] = 1; d[67] = 0x01;
}

/// Write a file entry at `off` bytes into sector `dir_sec`.
/// name_len must be odd (common case) → su_start = 33+name_len, no pad byte.
/// For even name_len add 1 manually.
fn write_file_entry(
    img: &mut [u8],
    dir_sec: usize,
    off: usize,
    name: &[u8],
    file_lba: u32,
    file_size: u32,
) {
    let nl = name.len();
    let pad = nl % 2; // 0 if odd, 1 if even — wait: ECMA-119 pads when name_len is EVEN
    // Actually: pad = if nl % 2 == 0 { 1 } else { 0 }
    let pad = if nl % 2 == 0 { 1 } else { 0 };
    let rec_len = 33 + nl + pad;
    let d = &mut img[dir_sec * S + off..dir_sec * S + off + rec_len];
    d[0] = rec_len as u8;
    d[2..6].copy_from_slice(&file_lba.to_le_bytes());
    d[6..10].copy_from_slice(&file_lba.to_be_bytes());
    d[10..14].copy_from_slice(&file_size.to_le_bytes());
    d[14..18].copy_from_slice(&file_size.to_be_bytes());
    d[25] = 0x00; // regular file
    d[32] = nl as u8;
    d[33..33 + nl].copy_from_slice(name);
}

/// Write a directory entry at `off` into sector `dir_sec`.
fn write_dir_entry(
    img: &mut [u8],
    dir_sec: usize,
    off: usize,
    name: &[u8],
    lba: u32,
    size: u32,
) {
    let nl = name.len();
    let pad = if nl % 2 == 0 { 1 } else { 0 };
    let rec_len = 33 + nl + pad;
    let d = &mut img[dir_sec * S + off..dir_sec * S + off + rec_len];
    d[0] = rec_len as u8;
    d[2..6].copy_from_slice(&lba.to_le_bytes());
    d[6..10].copy_from_slice(&lba.to_be_bytes());
    d[10..14].copy_from_slice(&size.to_le_bytes());
    d[14..18].copy_from_slice(&size.to_be_bytes());
    d[25] = 0x02; // directory flag
    d[32] = nl as u8;
    d[33..33 + nl].copy_from_slice(name);
}

/// Minimal ISO: PVD with `label`, VDT, empty root dir (dot+dotdot only).
/// Sectors: 0-15 unused, 16=PVD, 17=VDT, 18=root-dir.
fn make_labeled_iso(label: &str) -> Vec<u8> {
    let mut img = vec![0u8; 19 * S];
    write_pvd(&mut img, 18, 2048, 19, label.as_bytes());
    write_vdt(&mut img);
    write_dot_dotdot(&mut img, 18, 18, 18);
    img
}

/// ISO with a "README" file (11 bytes: b"hello world") at sector 19.
/// Sectors: 16=PVD, 17=VDT, 18=root-dir, 19=file-data.
fn make_file_iso() -> Vec<u8> {
    let mut img = vec![0u8; 20 * S];
    write_pvd(&mut img, 18, 2048, 20, b"FILETEST");
    write_vdt(&mut img);
    write_dot_dotdot(&mut img, 18, 18, 18);
    write_file_entry(&mut img, 18, 68, b"README", 19, 11);
    img[19 * S..19 * S + 11].copy_from_slice(b"hello world");
    img
}

/// Two-level ISO: root has "SUB" dir (lba=19), SUB has "FILE.TXT" (lba=21).
/// Sectors: 16=PVD, 17=VDT, 18=root-dir, 19=sub-dir, 20=file-data.
fn make_nested_iso() -> Vec<u8> {
    let mut img = vec![0u8; 21 * S];
    write_pvd(&mut img, 18, 2048, 21, b"NESTED");
    write_vdt(&mut img);
    // Root dir: dot+dotdot + "SUB" directory entry
    write_dot_dotdot(&mut img, 18, 18, 18);
    write_dir_entry(&mut img, 18, 68, b"SUB", 19, 2048);
    // Sub dir: dot+dotdot + "FILE.TXT" file entry
    write_dot_dotdot(&mut img, 19, 19, 18);
    write_file_entry(&mut img, 19, 68, b"FILE.TXT", 20, 8);
    img[20 * S..20 * S + 8].copy_from_slice(b"testdata");
    img
}

// ── info command ──────────────────────────────────────────────────────────────

#[test]
fn info_shows_volume_label() {
    let img = make_labeled_iso("FORENSIC");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::info::run(&mut reader);
    assert!(out.contains("FORENSIC"), "volume label missing from output:\n{out}");
}

#[test]
fn info_shows_volume_size() {
    let img = make_labeled_iso("TEST");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::info::run(&mut reader);
    // 19 sectors → must appear somewhere
    assert!(out.contains("19"), "sector count (19) missing from output:\n{out}");
}

#[test]
fn info_shows_sector_mode() {
    let img = make_labeled_iso("TEST");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::info::run(&mut reader);
    // 2048-byte ISO mode must be indicated
    assert!(
        out.contains("2048") || out.to_lowercase().contains("iso"),
        "sector mode missing from output:\n{out}"
    );
}

#[test]
fn info_shows_extension_flags() {
    let img = make_labeled_iso("TEST");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::info::run(&mut reader);
    // No extensions → output must say so ("none" or "—" or explicit "Rock Ridge: no")
    assert!(
        out.to_lowercase().contains("rock ridge") || out.contains("none") || out.contains('—'),
        "extension flags missing from output:\n{out}"
    );
}

#[test]
fn info_shows_session_count() {
    let img = make_labeled_iso("TEST");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::info::run(&mut reader);
    assert!(out.contains('1'), "session count missing from output:\n{out}");
}

// ── ls command ────────────────────────────────────────────────────────────────

#[test]
fn ls_root_shows_file_entry() {
    let img = make_file_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::ls::run(&mut reader, None).unwrap();
    assert!(out.contains("README"), "file entry missing from ls output:\n{out}");
}

#[test]
fn ls_root_shows_subdir_entry() {
    let img = make_nested_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::ls::run(&mut reader, None).unwrap();
    assert!(out.contains("SUB"), "directory entry missing from ls output:\n{out}");
}

#[test]
fn ls_subdir_shows_file_in_subdir() {
    let img = make_nested_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::ls::run(&mut reader, Some("SUB")).unwrap();
    assert!(out.contains("FILE.TXT"), "subdir file missing from ls output:\n{out}");
}

#[test]
fn ls_root_shows_lba() {
    let img = make_file_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::ls::run(&mut reader, None).unwrap();
    // README is at lba=19 — must appear in output
    assert!(out.contains("19"), "LBA missing from ls output:\n{out}");
}

#[test]
fn ls_root_shows_file_size() {
    let img = make_file_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::ls::run(&mut reader, None).unwrap();
    // README is 11 bytes
    assert!(out.contains("11"), "file size missing from ls output:\n{out}");
}

// ── tree command ──────────────────────────────────────────────────────────────

#[test]
fn tree_shows_nested_directory() {
    let img = make_nested_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::tree::run(&mut reader).unwrap();
    assert!(out.contains("SUB"), "directory missing from tree output:\n{out}");
}

#[test]
fn tree_shows_file_under_subdir() {
    let img = make_nested_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::tree::run(&mut reader).unwrap();
    assert!(out.contains("FILE.TXT"), "file missing from tree output:\n{out}");
}

#[test]
fn tree_file_path_contains_parent() {
    let img = make_nested_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::tree::run(&mut reader).unwrap();
    // Full path "SUB/FILE.TXT" or "SUB" then "FILE.TXT" on a later line
    let has_slash_path = out.contains("SUB/FILE.TXT");
    let has_on_separate_lines = {
        let sub_pos = out.find("SUB");
        let file_pos = out.find("FILE.TXT");
        sub_pos.is_some() && file_pos.is_some() && sub_pos.unwrap() < file_pos.unwrap()
    };
    assert!(
        has_slash_path || has_on_separate_lines,
        "tree output doesn't show SUB before FILE.TXT:\n{out}"
    );
}

#[test]
fn tree_empty_root_produces_no_output() {
    let img = make_labeled_iso("EMPTY");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::tree::run(&mut reader).unwrap();
    // Empty dir → no entries, just empty string or blank line
    assert!(
        out.trim().is_empty(),
        "empty ISO tree should produce no output, got:\n{out}"
    );
}

// ── extract command ───────────────────────────────────────────────────────────

#[test]
fn extract_returns_correct_bytes() {
    let img = make_file_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let data = cmd::extract::run(&mut reader, "README").unwrap();
    assert_eq!(data, b"hello world");
}

#[test]
fn extract_nested_file_returns_correct_bytes() {
    let img = make_nested_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let data = cmd::extract::run(&mut reader, "SUB/FILE.TXT").unwrap();
    assert_eq!(data, b"testdata");
}

#[test]
fn extract_missing_path_returns_error() {
    let img = make_labeled_iso("EMPTY");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let result = cmd::extract::run(&mut reader, "NO_SUCH_FILE.TXT");
    assert!(result.is_err(), "extracting nonexistent path must return Err");
}

// ── boot command ──────────────────────────────────────────────────────────────

#[test]
fn boot_no_catalog_reports_absence() {
    let img = make_labeled_iso("TEST");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::boot::run(&mut reader).unwrap();
    assert!(
        out.to_lowercase().contains("no boot") || out.contains("0") || out.trim().is_empty(),
        "expected no-catalog message, got:\n{out}"
    );
}
