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

// ── ls formatting — ASCII-only fixed-width columns ───────────────────────────

#[test]
fn ls_output_is_pure_ascii() {
    let img = make_file_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::ls::run(&mut reader, None, false).unwrap();
    assert!(out.is_ascii(), "ls output must be pure ASCII (no box-drawing chars):\n{out}");
}

#[test]
fn ls_has_column_header_row() {
    let img = make_file_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::ls::run(&mut reader, None, false).unwrap();
    let first = out.lines().next().unwrap_or("");
    assert!(
        first.to_ascii_uppercase().contains("SIZE") && first.to_ascii_uppercase().contains("NAME"),
        "first line should be column header (SIZE, NAME):\n{out}"
    );
}

#[test]
fn ls_has_ascii_separator_after_header() {
    let img = make_file_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::ls::run(&mut reader, None, false).unwrap();
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines.len() >= 2, "need at least header + separator");
    let sep = lines[1];
    assert!(
        sep.chars().all(|c| c == '-' || c == ' '),
        "second line must be ASCII dash separator, got: {sep:?}"
    );
}

#[test]
fn ls_recursive_output_is_pure_ascii() {
    let img = make_nested_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::ls::run(&mut reader, None, true).unwrap();
    assert!(out.is_ascii(), "recursive ls must be pure ASCII:\n{out}");
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

// ── hexdump — sector hex dump, ASCII-only fixed-width columns ─────────────────
//
// Format (per-row, always 47 chars before newline):
//   XXXXXXXX  HH HH HH HH HH HH HH HH  | AAAAAAAA |
//   ^^^^^^^^  ^^^^^^^^^^^^^^^^^^^^^^^  ^  ^^^^^^^^  ^
//   8 addr    23 hex (padded)           |  8 ascii   |
//
// Rules enforced by tests:
//   - No Unicode box-drawing characters anywhere in output
//   - Separator line is pure '-' characters
//   - '|' appears at the same byte offset on every data line
//   - ASCII column between the two '|' is exactly 10 chars (" " + 8 + " ")

#[test]
fn hexdump_pvd_shows_cd001_magic() {
    // PVD at sector 16 starts: 01 43 44 30 30 31 ("CD001")
    let img = make_labeled_iso("HEXTEST");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::dump::run(&mut reader, 16).unwrap();
    assert!(
        out.contains("43 44 30 30 31"),
        "CD001 bytes (43 44 30 30 31) missing from hexdump of sector 16:\n{out}"
    );
}

#[test]
fn hexdump_output_is_pure_ascii() {
    let img = make_labeled_iso("TEST");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::dump::run(&mut reader, 16).unwrap();
    assert!(out.is_ascii(), "hexdump must be pure ASCII (no box-drawing):\n{out}");
}

#[test]
fn hexdump_separator_line_is_dashes() {
    let img = make_labeled_iso("TEST");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::dump::run(&mut reader, 16).unwrap();
    let sep = out.lines()
        .find(|l| l.chars().all(|c| c == '-') && l.len() > 4)
        .expect("no separator line of dashes found");
    assert!(sep.is_ascii() && !sep.is_empty());
}

#[test]
fn hexdump_pipe_at_consistent_column() {
    // Every hex-data line must have '|' at the same byte offset.
    let img = make_labeled_iso("TEST");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::dump::run(&mut reader, 16).unwrap();
    let positions: Vec<usize> = out
        .lines()
        .filter(|l| l.len() > 8 && l.starts_with(|c: char| c.is_ascii_hexdigit()))
        .filter_map(|l| l.find('|'))
        .collect();
    assert!(!positions.is_empty(), "no data lines with '|' found");
    assert!(
        positions.windows(2).all(|w| w[0] == w[1]),
        "pipe not at consistent column across lines: {positions:?}"
    );
}

#[test]
fn hexdump_ascii_column_is_ten_chars_wide() {
    // Between the two '|' separators: space + 8-char ASCII + space = 10 chars.
    let img = make_labeled_iso("TEST");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::dump::run(&mut reader, 16).unwrap();
    for line in out.lines().filter(|l| l.starts_with(|c: char| c.is_ascii_hexdigit())) {
        let parts: Vec<&str> = line.splitn(3, '|').collect();
        assert_eq!(parts.len(), 3, "expected 2 pipe chars in data line: {line:?}");
        assert_eq!(
            parts[1].len(), 10,
            "ASCII column must be 10 chars wide (space+8+space), got {}: {line:?}",
            parts[1].len()
        );
    }
}

#[test]
fn hexdump_shows_volume_label_in_ascii_column() {
    // PVD volume label "HEXTEST" at bytes 40-46 — should appear in ASCII sidebar.
    let img = make_labeled_iso("HEXTEST");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::dump::run(&mut reader, 16).unwrap();
    // "HEXTEST" is 7 chars; it must appear somewhere between pipe chars
    assert!(
        out.contains("HEXTEST"),
        "volume label 'HEXTEST' must appear in ASCII sidebar:\n{}",
        &out[..out.len().min(500)]
    );
}

#[test]
fn hexdump_raw_returns_full_sector_bytes() {
    // run_raw must return the verbatim 2048-byte sector payload.
    let img = make_labeled_iso("RAWTEST");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let bytes = cmd::dump::run_raw(&mut reader, 16).unwrap();
    assert_eq!(bytes.len(), 2048, "raw sector must be exactly 2048 bytes");
    // PVD sector begins with 0x01 "CD001" 0x01
    assert_eq!(&bytes[0..6], &[0x01, b'C', b'D', b'0', b'0', b'1']);
}

#[test]
fn hexdump_raw_matches_read_sector_raw() {
    use iso9660_forensic::IsoReader as R;
    let img = make_labeled_iso("RAWTEST");
    let mut reader = R::open(Cursor::new(img.clone())).unwrap();
    let via_cmd = cmd::dump::run_raw(&mut reader, 18).unwrap();
    let mut reader2 = R::open(Cursor::new(img)).unwrap();
    let via_lib = reader2.read_sector_raw(18).unwrap().to_vec();
    assert_eq!(via_cmd, via_lib, "run_raw must equal read_sector_raw");
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

// ── audit command ─────────────────────────────────────────────────────────────

#[test]
fn audit_report_contains_tool_section() {
    let img = make_labeled_iso("AUDIT");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::audit::run(&mut reader, "test.iso");
    assert!(out.contains("Tool:"), "audit report must have Tool section:\n{out}");
}

#[test]
fn audit_report_contains_both_endian_section() {
    let img = make_labeled_iso("AUDIT");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::audit::run(&mut reader, "test.iso");
    assert!(out.contains("Both-Endian"), "audit must check both-endian:\n{out}");
}

#[test]
fn audit_report_contains_result_line() {
    let img = make_labeled_iso("AUDIT");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::audit::run(&mut reader, "test.iso");
    assert!(out.contains("Result:"), "audit must have a Result line:\n{out}");
}

#[test]
fn audit_report_is_pure_ascii() {
    let img = make_nested_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::audit::run(&mut reader, "test.iso");
    assert!(out.is_ascii(), "audit report must be pure ASCII:\n{out}");
}

#[test]
fn audit_clean_iso_shows_pass() {
    let img = make_nested_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::audit::run(&mut reader, "test.iso");
    assert!(out.contains("[PASS]"), "clean ISO must show at least one [PASS]:\n{out}");
}

#[test]
fn audit_report_names_the_image() {
    let img = make_labeled_iso("AUDIT");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::audit::run(&mut reader, "evidence.iso");
    assert!(out.contains("evidence.iso"), "audit must name the image:\n{out}");
}

// ── map command ───────────────────────────────────────────────────────────────

#[test]
fn map_shows_presystem_area() {
    let img = make_labeled_iso("MAP");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::map::run(&mut reader).unwrap();
    assert!(
        out.to_lowercase().contains("pre-system") || out.to_lowercase().contains("presystem"),
        "map must show pre-system area:\n{out}"
    );
}

#[test]
fn map_shows_pvd_sector() {
    let img = make_labeled_iso("MAP");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::map::run(&mut reader).unwrap();
    assert!(out.contains("PVD"), "map must label the PVD sector:\n{out}");
}

#[test]
fn map_output_is_pure_ascii() {
    let img = make_nested_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::map::run(&mut reader).unwrap();
    assert!(out.is_ascii(), "map must be pure ASCII:\n{out}");
}

#[test]
fn map_has_separator_line() {
    let img = make_labeled_iso("MAP");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::map::run(&mut reader).unwrap();
    let has_sep = out.lines().any(|l| l.len() > 4 && l.chars().all(|c| c == '-'));
    assert!(has_sep, "map must have a dash separator line:\n{out}");
}

#[test]
fn map_shows_root_directory() {
    let img = make_nested_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::map::run(&mut reader).unwrap();
    assert!(
        out.to_lowercase().contains("directory") || out.to_lowercase().contains("root"),
        "map must show directory sectors:\n{out}"
    );
}

// ── timeline command ──────────────────────────────────────────────────────────

#[test]
fn timeline_has_header() {
    let img = make_file_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::timeline::run(&mut reader).unwrap();
    let up = out.to_ascii_uppercase();
    assert!(up.contains("TIMESTAMP") && up.contains("PATH"),
        "timeline must have TIMESTAMP and PATH header:\n{out}");
}

#[test]
fn timeline_is_pure_ascii() {
    let img = make_nested_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::timeline::run(&mut reader).unwrap();
    assert!(out.is_ascii(), "timeline must be pure ASCII:\n{out}");
}

#[test]
fn timeline_lists_file() {
    let img = make_file_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::timeline::run(&mut reader).unwrap();
    assert!(out.contains("README"), "timeline must list README:\n{out}");
}

// ── hashlist command ──────────────────────────────────────────────────────────

#[test]
fn hashlist_hashdeep_has_banner() {
    let img = make_file_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::hashlist::run(&mut reader, cmd::hashlist::HashFormat::Hashdeep).unwrap();
    assert!(out.contains("%%%%"), "hashdeep format must have %%%% banner:\n{out}");
}

#[test]
fn hashlist_hashdeep_has_known_hash() {
    // README = "hello world" -> sha256 b94d27b9...
    let img = make_file_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::hashlist::run(&mut reader, cmd::hashlist::HashFormat::Hashdeep).unwrap();
    assert!(
        out.contains("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"),
        "hashdeep must contain sha256 of 'hello world':\n{out}"
    );
}

#[test]
fn hashlist_csv_has_header() {
    let img = make_file_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::hashlist::run(&mut reader, cmd::hashlist::HashFormat::Csv).unwrap();
    assert!(out.starts_with("path,size,sha256"),
        "CSV must start with header row:\n{out}");
}

#[test]
fn hashlist_tsv_uses_tabs() {
    let img = make_file_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::hashlist::run(&mut reader, cmd::hashlist::HashFormat::Tsv).unwrap();
    assert!(out.contains('\t'), "TSV must contain tab characters:\n{out}");
}

#[test]
fn hashlist_mactime_has_pipes() {
    let img = make_file_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::hashlist::run(&mut reader, cmd::hashlist::HashFormat::Mactime).unwrap();
    // mactime body format is pipe-delimited
    assert!(out.contains('|'), "mactime must be pipe-delimited:\n{out}");
}

#[test]
fn hashlist_dfxml_is_xml() {
    let img = make_file_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::hashlist::run(&mut reader, cmd::hashlist::HashFormat::Dfxml).unwrap();
    assert!(out.contains("<?xml"), "DFXML must start with XML declaration:\n{out}");
    assert!(out.contains("<dfxml"), "DFXML must have a dfxml root element:\n{out}");
    assert!(out.contains("fileobject"), "DFXML must have fileobject records:\n{out}");
}

#[test]
fn hashlist_is_pure_ascii() {
    let img = make_nested_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::hashlist::run(&mut reader, cmd::hashlist::HashFormat::Csv).unwrap();
    assert!(out.is_ascii(), "hashlist must be pure ASCII:\n{out}");
}

// ── find command ──────────────────────────────────────────────────────────────

// ── find command (regex-only) ─────────────────────────────────────────────────

fn re(p: &str) -> regex::Regex {
    regex::Regex::new(p).unwrap()
}

#[test]
fn find_no_filter_lists_all_files() {
    let img = make_nested_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::find::run(&mut reader, None, None, None, None).unwrap();
    assert!(out.contains("FILE.TXT"), "find with no filter must list FILE.TXT:\n{out}");
}

#[test]
fn find_name_regex_matches() {
    let img = make_mixed_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::find::run(&mut reader, Some(&re(r"\.TXT$")), None, None, None).unwrap();
    assert!(out.contains("ROOT.TXT"), r"\.TXT$ must match ROOT.TXT:\n{out}");
    assert!(out.contains("INNER.TXT"), r"\.TXT$ must match INNER.TXT:\n{out}");
}

#[test]
fn find_name_regex_excludes_nonmatching() {
    let img = make_mixed_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::find::run(&mut reader, Some(&re(r"\.BIN$")), None, None, None).unwrap();
    assert!(!out.contains("ROOT.TXT"), r"\.BIN$ must not match .TXT files:\n{out}");
}

#[test]
fn find_name_regex_anchored_excludes() {
    // Anchored `^ROOT\.TXT$` matches ROOT.TXT but not INNER.TXT.
    let img = make_mixed_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::find::run(&mut reader, Some(&re(r"^ROOT\.TXT$")), None, None, None).unwrap();
    assert!(out.contains("ROOT.TXT"), "anchored regex must match ROOT.TXT:\n{out}");
    assert!(!out.contains("INNER.TXT"), "anchored regex must exclude INNER.TXT:\n{out}");
}

#[test]
fn find_name_regex_alternation() {
    let img = make_mixed_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::find::run(&mut reader, Some(&re(r"\.(TXT|BIN)$")), None, None, None).unwrap();
    assert!(out.contains("ROOT.TXT"), "alternation must match ROOT.TXT:\n{out}");
}

#[test]
fn find_type_d_returns_only_dirs() {
    let img = make_nested_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::find::run(&mut reader, None, Some('d'), None, None).unwrap();
    assert!(out.contains("SUB"), "find -type d must list SUB:\n{out}");
    assert!(!out.contains("FILE.TXT"), "find -type d must exclude files:\n{out}");
}

#[test]
fn find_type_f_returns_only_files() {
    let img = make_nested_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::find::run(&mut reader, None, Some('f'), None, None).unwrap();
    assert!(out.contains("FILE.TXT"), "find -type f must list FILE.TXT:\n{out}");
    // SUB is a dir — its name should not appear as a standalone match line
    assert!(!out.lines().any(|l| l.trim_end().ends_with("SUB")),
        "find -type f must exclude directory SUB:\n{out}");
}

#[test]
fn find_min_size_filters() {
    // README is 11 bytes; min_size=100 should exclude it.
    let img = make_file_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::find::run(&mut reader, None, Some('f'), Some(100), None).unwrap();
    assert!(!out.contains("README"), "min_size=100 must exclude 11-byte README:\n{out}");
}

#[test]
fn find_is_pure_ascii() {
    let img = make_nested_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::find::run(&mut reader, None, None, None, None).unwrap();
    assert!(out.is_ascii(), "find output must be pure ASCII:\n{out}");
}

// ── grep command (regex-only) ─────────────────────────────────────────────────

#[test]
fn grep_finds_matching_content() {
    // README contains "hello world".
    let img = make_file_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::grep::run(&mut reader, &re("hello"), None).unwrap();
    assert!(out.contains("README"), "grep must report the matching file:\n{out}");
    assert!(out.contains("hello"), "grep must show the matching content:\n{out}");
}

#[test]
fn grep_no_match_is_empty() {
    let img = make_file_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::grep::run(&mut reader, &re("zzznotpresent"), None).unwrap();
    assert!(out.trim().is_empty(), "grep with no match must be empty:\n{out}");
}

#[test]
fn grep_ignore_case_via_inline_flag() {
    // Case-insensitivity comes from the compiled regex, e.g. (?i).
    let img = make_file_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::grep::run(&mut reader, &re("(?i)HELLO"), None).unwrap();
    assert!(out.contains("README"), "(?i)HELLO must match 'hello':\n{out}");
}

#[test]
fn grep_case_sensitive_excludes() {
    let img = make_file_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::grep::run(&mut reader, &re("HELLO"), None).unwrap();
    assert!(out.trim().is_empty(), "case-sensitive 'HELLO' must not match 'hello':\n{out}");
}

#[test]
fn grep_regex_metachar_matches() {
    // `h.llo` matches "hello" via regex.
    let img = make_file_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::grep::run(&mut reader, &re("h.llo"), None).unwrap();
    assert!(out.contains("README"), "h.llo must match 'hello':\n{out}");
}

#[test]
fn grep_include_regex_filters_files() {
    // include regex limits which files are searched.
    let img = make_file_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    // Only search files whose basename matches "NOPE" -> README excluded.
    let out = cmd::grep::run(&mut reader, &re("hello"), Some(&re("^NOPE$"))).unwrap();
    assert!(out.trim().is_empty(), "include regex must exclude README:\n{out}");
}

#[test]
fn grep_is_pure_ascii() {
    let img = make_file_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::grep::run(&mut reader, &re("hello"), None).unwrap();
    assert!(out.is_ascii(), "grep output must be pure ASCII:\n{out}");
}

// ── forensic subchannel (v0.3-dev) ────────────────────────────────────────────

/// Interleave a 12-byte Q frame into a 96-byte subcode block (bit 6 = Q).
fn interleave_q(q: &[u8; 12]) -> [u8; 96] {
    let mut sub = [0u8; 96];
    for bit in 0..96 {
        let set = (q[bit / 8] >> (7 - (bit % 8))) & 1;
        sub[bit] = set << 6;
    }
    sub
}

/// Build a minimal openable 2448-byte (subchannel-bearing) image with the
/// given Q frames placed in the named sectors' subchannel areas.
fn build_2448(sectors: usize, frames: &[(usize, [u8; 12])]) -> Vec<u8> {
    const P: usize = 2448;
    const SYNC: [u8; 12] = [0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0];
    let mut img = vec![0u8; sectors * P];
    for s in 0..sectors {
        img[s * P..s * P + 12].copy_from_slice(&SYNC);
        img[s * P + 15] = 0x01;
    }
    let pvd = 16 * P + 16;
    img[pvd] = 0x01;
    img[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
    img[pvd + 6] = 0x01;
    let term = 17 * P + 16;
    img[term] = 0xFF;
    img[term + 1..term + 6].copy_from_slice(b"CD001");
    img[term + 6] = 0x01;
    for (sector, q) in frames {
        let off = sector * P + 2352;
        img[off..off + 96].copy_from_slice(&interleave_q(q));
    }
    img
}

#[test]
fn subchannel_reports_catalog_and_isrc() {
    // Q-mode 1 position (track 1), Q-mode 3 ISRC, Q-mode 2 catalog.
    const POS1: [u8; 12] = [0x41, 0x01, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x09, 0xD4];
    const ISRC: [u8; 12] = [0x43, 0x96, 0x38, 0x93, 0x04, 0x76, 0x07, 0x83, 0x90, 0x00, 0x6B, 0x86];
    const MCN: [u8; 12] = [0x42, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x30, 0x00, 0x00, 0x99, 0xCB];
    let img = build_2448(24, &[(18, POS1), (19, ISRC), (20, MCN)]);
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::subchannel::run(&mut reader).unwrap();
    assert!(out.contains("1234567890123"), "catalog: {out}");
    assert!(out.contains("USRC17607839"), "isrc: {out}");
    assert!(out.contains("Track  1"), "track label: {out}");
}

#[test]
fn subchannel_none_for_iso2048() {
    // A plain 2048-byte ISO has no subchannel; report so without erroring.
    let mut img = vec![0u8; 20 * S];
    write_pvd(&mut img, 18, S as u32, 20, b"NOSUB");
    write_vdt(&mut img);
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let out = cmd::subchannel::run(&mut reader).unwrap();
    assert!(out.to_lowercase().contains("no"), "expected a 'none' note: {out}");
}

#[test]
fn subchannel_run_sub_reads_external_sub_file() {
    // CloneCD .sub: 96 interleaved subcode bytes per sector, separate file.
    const POS1: [u8; 12] = [0x41, 0x01, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x09, 0xD4];
    const ISRC: [u8; 12] = [0x43, 0x96, 0x38, 0x93, 0x04, 0x76, 0x07, 0x83, 0x90, 0x00, 0x6B, 0x86];
    const MCN: [u8; 12] = [0x42, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x30, 0x00, 0x00, 0x99, 0xCB];
    let mut sub = Vec::new();
    for q in [POS1, ISRC, MCN] {
        sub.extend_from_slice(&interleave_q(&q));
    }
    let out = cmd::subchannel::run_sub(&sub);
    assert!(out.contains("1234567890123"), "catalog: {out}");
    assert!(out.contains("USRC17607839"), "isrc: {out}");
}
