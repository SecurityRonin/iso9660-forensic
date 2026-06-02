// CLI integration tests.
//
// Commands: info, ls [-R], x (extract with paths), e (extract flat).
// boot entries are a section of `info`; recursive listing is `ls -R`, not
// a separate `tree` subcommand.  `x`/`e` follow the dar/7z/tar convention.

use std::io::Cursor;
use iso9660_forensic::IsoReader;
use iso9660_cli::cmd;

// ── ISO builder helpers ───────────────────────────────────────────────────────

const S: usize = 2048;

fn write_pvd(img: &mut [u8], root_lba: u32, root_size: u32, total: u32, label: &[u8]) {
    let p = &mut img[16 * S..17 * S];
    p[0] = 0x01; p[1..6].copy_from_slice(b"CD001"); p[6] = 0x01;
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

fn write_dot_dotdot(img: &mut [u8], sec: usize, self_lba: u32, parent_lba: u32) {
    let d = &mut img[sec * S..sec * S + 68];
    d[0] = 34; d[2..6].copy_from_slice(&self_lba.to_le_bytes());
    d[6..10].copy_from_slice(&self_lba.to_be_bytes());
    d[10..14].copy_from_slice(&2048u32.to_le_bytes());
    d[25] = 0x02; d[32] = 1;
    d[34] = 34; d[36..40].copy_from_slice(&parent_lba.to_le_bytes());
    d[40..44].copy_from_slice(&parent_lba.to_be_bytes());
    d[44..48].copy_from_slice(&2048u32.to_le_bytes());
    d[59] = 0x02; d[66] = 1; d[67] = 0x01;
}

fn write_file_entry(img: &mut [u8], dir_sec: usize, off: usize, name: &[u8], lba: u32, size: u32) {
    let nl = name.len();
    let pad = if nl % 2 == 0 { 1 } else { 0 };
    let rec_len = 33 + nl + pad;
    let d = &mut img[dir_sec * S + off..dir_sec * S + off + rec_len];
    d[0] = rec_len as u8;
    d[2..6].copy_from_slice(&lba.to_le_bytes());
    d[6..10].copy_from_slice(&lba.to_be_bytes());
    d[10..14].copy_from_slice(&size.to_le_bytes());
    d[14..18].copy_from_slice(&size.to_be_bytes());
    d[25] = 0x00;
    d[32] = nl as u8;
    d[33..33 + nl].copy_from_slice(name);
}

fn write_dir_entry(img: &mut [u8], dir_sec: usize, off: usize, name: &[u8], lba: u32, size: u32) {
    let nl = name.len();
    let pad = if nl % 2 == 0 { 1 } else { 0 };
    let rec_len = 33 + nl + pad;
    let d = &mut img[dir_sec * S + off..dir_sec * S + off + rec_len];
    d[0] = rec_len as u8;
    d[2..6].copy_from_slice(&lba.to_le_bytes());
    d[6..10].copy_from_slice(&lba.to_be_bytes());
    d[10..14].copy_from_slice(&size.to_le_bytes());
    d[14..18].copy_from_slice(&size.to_be_bytes());
    d[25] = 0x02;
    d[32] = nl as u8;
    d[33..33 + nl].copy_from_slice(name);
}

/// Minimal ISO: just PVD + VDT + empty root dir.
fn make_labeled_iso(label: &str) -> Vec<u8> {
    let mut img = vec![0u8; 19 * S];
    write_pvd(&mut img, 18, 2048, 19, label.as_bytes());
    write_vdt(&mut img);
    write_dot_dotdot(&mut img, 18, 18, 18);
    img
}

/// Root-level file: "README" → b"hello world".
fn make_file_iso() -> Vec<u8> {
    let mut img = vec![0u8; 20 * S];
    write_pvd(&mut img, 18, 2048, 20, b"FILETEST");
    write_vdt(&mut img);
    write_dot_dotdot(&mut img, 18, 18, 18);
    write_file_entry(&mut img, 18, 68, b"README", 19, 11);
    img[19 * S..19 * S + 11].copy_from_slice(b"hello world");
    img
}

/// Two-level: root → "SUB/" → "FILE.TXT" (b"testdata").
fn make_nested_iso() -> Vec<u8> {
    let mut img = vec![0u8; 21 * S];
    write_pvd(&mut img, 18, 2048, 21, b"NESTED");
    write_vdt(&mut img);
    write_dot_dotdot(&mut img, 18, 18, 18);
    write_dir_entry(&mut img, 18, 68, b"SUB", 19, 2048);
    write_dot_dotdot(&mut img, 19, 19, 18);
    write_file_entry(&mut img, 19, 68, b"FILE.TXT", 20, 8);
    img[20 * S..20 * S + 8].copy_from_slice(b"testdata");
    img
}

/// Root has both a file "ROOT.TXT" and a subdir "SUB/" with "INNER.TXT".
fn make_mixed_iso() -> Vec<u8> {
    let mut img = vec![0u8; 22 * S];
    write_pvd(&mut img, 18, 2048, 22, b"MIXED");
    write_vdt(&mut img);
    write_dot_dotdot(&mut img, 18, 18, 18);
    write_file_entry(&mut img, 18, 68, b"ROOT.TXT", 20, 4);  // rec_len = 33+8+0 = 41 → 42 (even)
    write_dir_entry( &mut img, 18, 68 + 42, b"SUB", 19, 2048);
    write_dot_dotdot(&mut img, 19, 19, 18);
    write_file_entry(&mut img, 19, 68, b"INNER.TXT", 21, 5);
    img[20 * S..20 * S + 4].copy_from_slice(b"root");
    img[21 * S..21 * S + 5].copy_from_slice(b"inner");
    img
}

// ── info ──────────────────────────────────────────────────────────────────────

#[test]
fn info_shows_volume_label() {
    let img = make_labeled_iso("FORENSIC");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::info::run(&mut reader);
    assert!(out.contains("FORENSIC"), "volume label missing:\n{out}");
}

#[test]
fn info_shows_volume_size() {
    let img = make_labeled_iso("TEST");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::info::run(&mut reader);
    assert!(out.contains("19"), "sector count (19) missing:\n{out}");
}

#[test]
fn info_shows_sector_mode() {
    let img = make_labeled_iso("TEST");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::info::run(&mut reader);
    assert!(
        out.contains("2048") || out.to_lowercase().contains("iso"),
        "sector mode missing:\n{out}"
    );
}

#[test]
fn info_shows_extension_flags() {
    let img = make_labeled_iso("TEST");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::info::run(&mut reader);
    assert!(
        out.to_lowercase().contains("rock ridge") || out.contains("none") || out.contains('—'),
        "extension flags missing:\n{out}"
    );
}

#[test]
fn info_includes_boot_catalog_section() {
    // boot entries are metadata → must appear in info, not a separate command
    let img = make_labeled_iso("TEST");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::info::run(&mut reader);
    assert!(
        out.to_lowercase().contains("boot"),
        "boot catalog section missing from info:\n{out}"
    );
}

// ── ls (shallow) ──────────────────────────────────────────────────────────────

#[test]
fn ls_shallow_shows_root_file() {
    let img = make_file_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::ls::run(&mut reader, None, false).unwrap();
    assert!(out.contains("README"), "file entry missing:\n{out}");
}

#[test]
fn ls_shallow_shows_subdir() {
    let img = make_nested_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::ls::run(&mut reader, None, false).unwrap();
    assert!(out.contains("SUB"), "subdir missing:\n{out}");
}

#[test]
fn ls_shallow_does_not_recurse_into_subdir() {
    // ls without -R must NOT show FILE.TXT from inside SUB/
    let img = make_nested_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::ls::run(&mut reader, None, false).unwrap();
    assert!(!out.contains("FILE.TXT"), "shallow ls must not recurse into SUB:\n{out}");
}

#[test]
fn ls_path_lists_subdir_contents() {
    let img = make_nested_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::ls::run(&mut reader, Some("SUB"), false).unwrap();
    assert!(out.contains("FILE.TXT"), "FILE.TXT missing from ls SUB:\n{out}");
}

#[test]
fn ls_shows_lba_and_size() {
    let img = make_file_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::ls::run(&mut reader, None, false).unwrap();
    assert!(out.contains("19"), "lba=19 missing:\n{out}");
    assert!(out.contains("11"), "size=11 missing:\n{out}");
}

// ── ls -R (recursive / tree) ──────────────────────────────────────────────────

#[test]
fn ls_recursive_shows_nested_file() {
    let img = make_nested_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::ls::run(&mut reader, None, true).unwrap();
    assert!(out.contains("FILE.TXT"), "FILE.TXT missing from recursive ls:\n{out}");
}

#[test]
fn ls_recursive_shows_full_path() {
    let img = make_nested_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::ls::run(&mut reader, None, true).unwrap();
    // Either "SUB/FILE.TXT" or "SUB" appears before "FILE.TXT"
    let has_slash = out.contains("SUB/FILE.TXT");
    let sub_before = out.find("SUB").zip(out.find("FILE.TXT"))
        .is_some_and(|(s, f)| s < f);
    assert!(has_slash || sub_before, "recursive ls must show full paths:\n{out}");
}

#[test]
fn ls_recursive_empty_iso_no_file_lines() {
    let img = make_labeled_iso("EMPTY");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::ls::run(&mut reader, None, true).unwrap();
    assert!(out.trim().is_empty(), "empty ISO tree must be blank:\n{out}");
}

#[test]
fn ls_recursive_from_subdir_scoped() {
    // ls -R SUB/ must not show ROOT.TXT
    let img = make_mixed_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::ls::run(&mut reader, Some("SUB"), true).unwrap();
    assert!(out.contains("INNER.TXT"), "INNER.TXT missing:\n{out}");
    assert!(!out.contains("ROOT.TXT"), "ls -R SUB must not show root-level files:\n{out}");
}

// ── x — extract with paths ────────────────────────────────────────────────────

#[test]
fn x_single_file_returns_path_and_data() {
    let img = make_file_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let files = cmd::extract::run_x(&mut reader, Some("README")).unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].0, "README");
    assert_eq!(files[0].1, b"hello world");
}

#[test]
fn x_nested_file_preserves_path() {
    let img = make_nested_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let files = cmd::extract::run_x(&mut reader, Some("SUB/FILE.TXT")).unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].0, "SUB/FILE.TXT");
    assert_eq!(files[0].1, b"testdata");
}

#[test]
fn x_none_extracts_all_files_with_paths() {
    let img = make_nested_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let files = cmd::extract::run_x(&mut reader, None).unwrap();
    assert_eq!(files.len(), 1, "nested ISO has exactly 1 file");
    assert_eq!(files[0].0, "SUB/FILE.TXT");
}

#[test]
fn x_all_mixed_iso_returns_both_files() {
    let img = make_mixed_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let mut files = cmd::extract::run_x(&mut reader, None).unwrap();
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let paths: Vec<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
    assert!(paths.contains(&"ROOT.TXT"),  "ROOT.TXT missing: {paths:?}");
    assert!(paths.contains(&"SUB/INNER.TXT"), "SUB/INNER.TXT missing: {paths:?}");
}

#[test]
fn x_missing_path_returns_error() {
    let img = make_labeled_iso("EMPTY");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    assert!(cmd::extract::run_x(&mut reader, Some("NO_FILE")).is_err());
}

// ── e — extract flat (strip directory components) ─────────────────────────────

#[test]
fn e_single_file_strips_path() {
    let img = make_nested_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let files = cmd::extract::run_e(&mut reader, Some("SUB/FILE.TXT")).unwrap();
    assert_eq!(files.len(), 1);
    // path must be just the filename, no directory
    assert_eq!(files[0].0, "FILE.TXT", "e must strip SUB/ prefix");
    assert_eq!(files[0].1, b"testdata");
}

#[test]
fn e_all_files_flat() {
    let img = make_mixed_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let mut files = cmd::extract::run_e(&mut reader, None).unwrap();
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
    // No path separators in any name
    assert!(names.iter().all(|n| !n.contains('/')), "e must produce flat names: {names:?}");
    assert!(names.contains(&"ROOT.TXT"),  "ROOT.TXT missing: {names:?}");
    assert!(names.contains(&"INNER.TXT"), "INNER.TXT missing: {names:?}");
}

#[test]
fn e_data_matches_x_data() {
    // run_e and run_x must return the same bytes, only the path differs
    let img = make_nested_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let x_files = cmd::extract::run_x(&mut reader, None).unwrap();
    let e_files = cmd::extract::run_e(&mut reader, None).unwrap();
    assert_eq!(x_files.len(), e_files.len());
    for ((_, xdata), (_, edata)) in x_files.iter().zip(e_files.iter()) {
        assert_eq!(xdata, edata, "run_x and run_e must return identical bytes");
    }
}
