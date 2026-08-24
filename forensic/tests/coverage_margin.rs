#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Targeted coverage-margin tests.
//!
//! These drive specific error and edge branches in the pure parser and the
//! streaming file reader that the end-to-end tests do not exercise on their
//! own. Each test constructs the minimal synthetic input that reaches one
//! branch and asserts the observable result, so the branch is genuinely
//! exercised rather than merely touched. No external fixtures are used.

use std::io::{self, Cursor, Read, Seek, SeekFrom};

use iso9660_forensic::IsoReader;

// ── shared: a minimal single-file ISO builder (LBA of DATA + size are args) ──

const S: usize = 2048;

/// Build a minimal 1-file ISO with a `DATA` entry at `data_lba` of `data_size`
/// bytes (payload 0x77). Mirrors the builder in `iso_file_reader.rs`.
fn iso_with_data(data_lba: u32, data_size: u32) -> Vec<u8> {
    let end_lba = (u64::from(data_lba) + u64::from(data_size).div_ceil(S as u64)).max(23) as usize;
    let mut img = vec![0u8; (end_lba + 1) * S];

    // PVD at sector 16.
    {
        let p = &mut img[16 * S..17 * S];
        p[0] = 0x01;
        p[1..6].copy_from_slice(b"CD001");
        p[6] = 0x01;
        p[80..84].copy_from_slice(&((end_lba + 1) as u32).to_le_bytes());
        p[84..88].copy_from_slice(&((end_lba + 1) as u32).to_be_bytes());
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
    // VD terminator at sector 17.
    {
        let t = &mut img[17 * S..18 * S];
        t[0] = 0xFF;
        t[1..6].copy_from_slice(b"CD001");
        t[6] = 0x01;
    }
    // Root dir at sector 18: dot, dotdot, then DATA.
    {
        let d = &mut img[18 * S..19 * S];
        d[0] = 34;
        d[2..6].copy_from_slice(&18u32.to_le_bytes());
        d[10..14].copy_from_slice(&2048u32.to_le_bytes());
        d[25] = 0x02;
        d[32] = 1;
        let o = 34;
        d[o] = 34;
        d[o + 2..o + 6].copy_from_slice(&18u32.to_le_bytes());
        d[o + 10..o + 14].copy_from_slice(&2048u32.to_le_bytes());
        d[o + 25] = 0x02;
        d[o + 32] = 1;
        d[o + 33] = 0x01;
        let o = 68;
        d[o] = 38;
        d[o + 2..o + 6].copy_from_slice(&data_lba.to_le_bytes());
        d[o + 6..o + 10].copy_from_slice(&data_lba.to_be_bytes());
        d[o + 10..o + 14].copy_from_slice(&data_size.to_le_bytes());
        d[o + 14..o + 18].copy_from_slice(&data_size.to_be_bytes());
        d[o + 32] = 4;
        d[o + 33..o + 37].copy_from_slice(b"DATA");
    }
    if data_size > 0 {
        let start = data_lba as usize * S;
        img[start..start + data_size as usize].fill(0x77);
    }
    img
}

fn open_data_file(img: Vec<u8>) -> iso9660_forensic::IsoFileReader<Cursor<Vec<u8>>> {
    let mut reader = IsoReader::open(Cursor::new(img)).expect("valid iso");
    let records = reader.read_root_dir().expect("root dir");
    let entry = records.iter().find(|r| r.iso_name() == "DATA").expect("DATA entry");
    reader.open_file(entry).expect("open file")
}

// ── session.rs: scan_pvd_lbas trailing-partial-sector break ──────────────────

#[test]
fn scan_pvd_lbas_breaks_on_trailing_partial_sector() {
    use iso9660_forensic::session::scan_pvd_lbas;

    // len leaves the final in-range sector's 7-byte window past the end, so the
    // loop hits `offset + 7 > image_bytes.len()` -> break.
    let img = vec![0u8; 17 * 2048 + 3];
    let lbas = scan_pvd_lbas(&img, 2048);
    assert!(lbas.is_empty());
}

// ── cue.rs: INDEX line applied to a track ───────────────────────────────────

#[test]
fn cue_index_line_pushes_index() {
    use iso9660_forensic::cue::parse;

    let sheet = parse("FILE \"img.bin\" BINARY\n  TRACK 01 MODE1/2048\n    INDEX 01 00:00:00\n");
    let file = sheet.files.first().expect("one file");
    let track = file.tracks.first().expect("one track");
    assert_eq!(track.indices.len(), 1);
    assert_eq!(track.indices[0].0, 1);
}

#[test]
fn cue_malformed_index_tokens_are_dropped() {
    use iso9660_forensic::cue::parse;

    // INDEX with two tokens present, but neither the number nor the MSF parses:
    // the outer `if let (Some, Some)` matches while the inner `if let (Ok, Some)`
    // fails, so no index is pushed.
    let sheet = parse("FILE \"img.bin\" BINARY\n  TRACK 01 MODE1/2048\n    INDEX zz not-an-msf\n");
    let track = &sheet.files[0].tracks[0];
    assert!(track.indices.is_empty());
}

// ── subq.rs: QData::Other frame is folded through summarize_q ────────────────

#[test]
fn summarize_q_ignores_other_adr() {
    use iso9660_forensic::subq::{summarize_q, Control, QData, QFrame, QSummary};

    let frame = QFrame { control: Control(0), adr: 5, data: QData::Other(5) };
    let summary = summarize_q(std::iter::once(frame));
    assert_eq!(summary, QSummary::default());
}

// ── el_torito.rs: boot-catalog early returns and truncated section entry ─────

#[test]
fn boot_catalog_too_short_returns_empty() {
    use iso9660_forensic::el_torito::parse_boot_catalog;
    assert!(parse_boot_catalog(&[0u8; 32]).is_empty());
}

#[test]
fn boot_catalog_bad_validation_entry_returns_empty() {
    use iso9660_forensic::el_torito::parse_boot_catalog;
    // 64 bytes but byte 0 != 0x01 -> empty.
    let cat = vec![0u8; 64];
    assert!(parse_boot_catalog(&cat).is_empty());
}

#[test]
fn boot_catalog_section_entry_truncated_breaks() {
    use iso9660_forensic::el_torito::parse_boot_catalog;

    // Validation entry + default entry + a section header claiming 2 entries but
    // with only one entry's worth of bytes -> inner `break`.
    let mut cat = vec![0u8; 32 + 32 + 32 + 32];
    cat[0] = 0x01;
    cat[30] = 0x55;
    cat[31] = 0xAA;
    cat[32] = 0x00; // default entry, non-bootable but recorded
    cat[64] = 0x91; // final section header
    cat[66] = 2; // count = 2 (LE u16)
    let entries = parse_boot_catalog(&cat);
    assert_eq!(entries.len(), 2);
}

// ── file_reader.rs: empty read, zero-size extent, past-end exhaustion ────────

#[test]
fn file_reader_empty_buffer_read_returns_zero() {
    let mut r = open_data_file(iso_with_data(20, 2048));
    assert_eq!(r.read(&mut []).expect("empty read ok"), 0);
}

#[test]
fn file_reader_zero_size_extent_yields_no_bytes() {
    // A zero-size DATA entry: ensure_buf hits `size == 0` and read yields none.
    let mut r = open_data_file(iso_with_data(20, 0));
    let mut out = [0u8; 16];
    assert_eq!(r.read(&mut out).expect("read ok"), 0);
}

#[test]
fn file_reader_read_past_end_and_exhaustion() {
    let mut r = open_data_file(iso_with_data(20, 2048));
    let mut all = Vec::new();
    r.read_to_end(&mut all).expect("read to end");
    assert_eq!(all.len(), 2048);
    let mut extra = [0u8; 8];
    assert_eq!(r.read(&mut extra).expect("post-eof read"), 0);
}

// ── sector.rs: mode1_ecc_valid too-short + hard I/O error propagation ────────

#[test]
fn mode1_ecc_valid_rejects_short_sector() {
    use iso9660_forensic::sector::mode1_ecc_valid;
    assert!(!mode1_ecc_valid(&[0u8; 100]));
}

/// A `Read + Seek` that returns a non-EOF error on every `read`, to drive the
/// `Err(e) => Err(e)` arms in `probe_cd001` / `has_sync_pattern`.
struct FailingReader {
    len: u64,
    pos: u64,
}

impl Read for FailingReader {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "boom"))
    }
}

impl Seek for FailingReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.pos = match pos {
            SeekFrom::Start(p) => p,
            SeekFrom::End(p) => (self.len as i64 + p) as u64,
            SeekFrom::Current(p) => (self.pos as i64 + p) as u64,
        };
        Ok(self.pos)
    }
}

#[test]
fn sector_probe_propagates_non_eof_error() {
    let reader = FailingReader { len: 64 * 2048, pos: 0 };
    let result = IsoReader::open(reader);
    assert!(result.is_err(), "hard I/O error must surface");
}

// ── mds.rs: sector_mode_for pure-function branches ──────────────────────────

#[test]
fn mds_sector_mode_for_audio_and_unknown() {
    use iso9660_forensic::mds::sector_mode_for;
    use iso9660_forensic::SectorMode;

    assert_eq!(sector_mode_for(0xA9, 2048), None);
    assert_eq!(sector_mode_for(0xA9, 2352), None);
    assert_eq!(sector_mode_for(0xA9, 2448), None);
    assert_eq!(sector_mode_for(0x04, 2352), Some(SectorMode::Raw2352Mode2));
    assert_eq!(sector_mode_for(0x02, 2448), Some(SectorMode::Raw2448));
    assert_eq!(sector_mode_for(0xAA, 999), None);
}
