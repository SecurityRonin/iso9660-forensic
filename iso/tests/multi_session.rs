// Multi-session disc access.
//
// Spec: ECMA-119 §6.8.2 (multiple sessions); Orange Book Part II (CD-R sessions).
// Refs: iso9660-rs (Poprdi) IsoFs::session_count; cdfs SessionIterator.
//
// A multi-session disc has multiple PVDs at different LBAs. The last session
// is the authoritative one; earlier sessions can still be accessed by index.

use std::io::Cursor;
use iso9660_forensic::IsoReader;

// ── in-memory multi-session ISO builder ───────────────────────────────────────

/// Build a 2-session ISO:
///
/// Session 0 (first): PVD at LBA 16, root dir at LBA 18, file "SESSION0.TXT"
/// Session 1 (last):  PVD at LBA 24, root dir at LBA 26, file "SESSION1.TXT"
///
/// Sector layout (30 sectors total):
///   16 = Session 0 PVD
///   17 = Session 0 Terminator
///   18 = Session 0 root dir
///   19-23 = padding
///   24 = Session 1 PVD
///   25 = Session 1 Terminator
///   26 = Session 1 root dir
fn make_two_session_iso() -> Vec<u8> {
    const S: usize = 2048;
    let mut img = vec![0u8; 30 * S];

    // Helper: write a minimal PVD sector at `pvd_offset` with `root_lba`.
    let write_pvd = |img: &mut Vec<u8>, pvd_lba: usize, root_lba: u32| {
        let p = &mut img[pvd_lba * S..(pvd_lba + 1) * S];
        p[0] = 0x01;
        p[1..6].copy_from_slice(b"CD001");
        p[6] = 0x01;
        p[80..84].copy_from_slice(&30u32.to_le_bytes());
        p[84..88].copy_from_slice(&30u32.to_be_bytes());
        p[128..130].copy_from_slice(&2048u16.to_le_bytes());
        p[130..132].copy_from_slice(&2048u16.to_be_bytes());
        p[132..136].copy_from_slice(&10u32.to_le_bytes());
        p[140..144].copy_from_slice(&1u32.to_le_bytes());
        p[148..152].copy_from_slice(&1u32.to_be_bytes());
        p[156] = 34;
        p[158..162].copy_from_slice(&root_lba.to_le_bytes());
        p[162..166].copy_from_slice(&root_lba.to_be_bytes());
        p[166..170].copy_from_slice(&2048u32.to_le_bytes());
        p[170..174].copy_from_slice(&2048u32.to_be_bytes());
        p[181] = 0x02;
        p[188] = 1;
    };

    let write_term = |img: &mut Vec<u8>, lba: usize| {
        let t = &mut img[lba * S..(lba + 1) * S];
        t[0] = 0xFF;
        t[1..6].copy_from_slice(b"CD001");
        t[6] = 0x01;
    };

    // Helper: write a root dir with one file entry.
    // name must be <= 7 bytes (odd length → no padding, so record_len = 33+len).
    let write_dir = |img: &mut Vec<u8>, dir_lba: usize, file_name: &[u8]| {
        let d = &mut img[dir_lba * S..(dir_lba + 1) * S];
        // dot
        d[0] = 34;
        d[2..6].copy_from_slice(&(dir_lba as u32).to_le_bytes());
        d[10..14].copy_from_slice(&2048u32.to_le_bytes());
        d[25] = 0x02; d[32] = 1;
        // dotdot
        let o = 34;
        d[o] = 34;
        d[o + 2..o + 6].copy_from_slice(&(dir_lba as u32).to_le_bytes());
        d[o + 10..o + 14].copy_from_slice(&2048u32.to_le_bytes());
        d[o + 25] = 0x02; d[o + 32] = 1; d[o + 33] = 0x01;
        // file entry
        let nl = file_name.len();
        let rec_len = 33 + nl + (if nl % 2 == 0 { 1 } else { 0 });
        let o = 68;
        d[o] = rec_len as u8;
        d[o + 32] = nl as u8;
        d[o + 33..o + 33 + nl].copy_from_slice(file_name);
    };

    write_pvd(&mut img, 16, 18);
    write_term(&mut img, 17);
    write_dir(&mut img, 18, b"SESSION0");

    write_pvd(&mut img, 24, 26);
    write_term(&mut img, 25);
    write_dir(&mut img, 26, b"SESSION1");

    img
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[test]
fn two_session_iso_detects_both() {
    let img = make_two_session_iso();
    let reader = IsoReader::open(Cursor::new(img)).unwrap();
    assert_eq!(reader.session_count(), 2, "must detect 2 sessions");
}

#[test]
fn read_session_root_dir_session0() {
    let img = make_two_session_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let records = reader.read_session_root_dir(0).unwrap();
    let names: Vec<String> = records.iter().map(|r| r.iso_name()).collect();
    assert!(names.contains(&"SESSION0".to_string()),
        "session 0 root dir must contain SESSION0, got: {names:?}");
    assert!(!names.contains(&"SESSION1".to_string()),
        "session 0 must NOT contain SESSION1");
}

#[test]
fn read_session_root_dir_session1() {
    let img = make_two_session_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let records = reader.read_session_root_dir(1).unwrap();
    let names: Vec<String> = records.iter().map(|r| r.iso_name()).collect();
    assert!(names.contains(&"SESSION1".to_string()),
        "session 1 root dir must contain SESSION1, got: {names:?}");
}

#[test]
fn read_session_out_of_bounds_returns_error() {
    let img = make_two_session_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    assert!(reader.read_session_root_dir(99).is_err(),
        "out-of-bounds session index must return an error");
}

#[test]
fn default_read_root_dir_uses_last_session() {
    let img = make_two_session_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let records = reader.read_root_dir().unwrap();
    let names: Vec<String> = records.iter().map(|r| r.iso_name()).collect();
    // Last session (idx=1) contains SESSION1.
    assert!(names.contains(&"SESSION1".to_string()),
        "default root dir must be the last session (SESSION1), got: {names:?}");
}
