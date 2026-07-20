#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Coverage-completion tests for the container-opener path (`open()`), driven
//! by real container files built into a tempdir.
//!
//! `open()` resolves an optical image path to a `Read + Seek` over its ISO 9660
//! data track. The repo's other `open` tests need gitignored sample images, so
//! the `.cue`/`.ccd`/`.nrg`/`.mds`/`.toc` resolution arms and their
//! `File`-typed reads sit uncovered on CI. Here each container is synthesized
//! around a real hadris-built ISO payload written to disk, so `open()` and the
//! `<File>` monomorphizations of the readers are genuinely exercised — the
//! opened stream is fed to `analyse()` and the volume label is asserted.

mod helpers;

use std::io::Write;

use helpers::{build_iso, file};
use iso9660_forensic::{analyse, open, IsoReader};

/// A real ISO payload (2048-byte sectors) whose volume label we can assert.
fn iso_bytes(label: &str) -> Vec<u8> {
    build_iso(label, vec![file("HELLO.TXT", b"hi")]).into_inner()
}

fn tmp() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

fn write(dir: &std::path::Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let p = dir.join(name);
    let mut f = std::fs::File::create(&p).expect("create");
    f.write_all(bytes).expect("write");
    p
}

/// Assert `open(path)` yields a stream whose ISO volume label matches.
fn assert_opens_to_label(path: &std::path::Path, label: &str) {
    let mut src = open(path).expect("open container");
    let a = analyse(&mut src).expect("analyse opened stream");
    assert_eq!(a.volume.volume_label.trim_end(), label, "{:?}", a.volume);
}

#[test]
fn open_plain_iso_from_disk() {
    let d = tmp();
    let p = write(d.path(), "disc.iso", &iso_bytes("PLAINISO"));
    assert_opens_to_label(&p, "PLAINISO");
}

#[test]
fn open_unknown_extension_falls_back_to_plain() {
    // An extension the matcher doesn't special-case -> open_plain.
    let d = tmp();
    let p = write(d.path(), "disc.dat", &iso_bytes("RAWDATA"));
    assert_opens_to_label(&p, "RAWDATA");
}

#[test]
fn open_cue_resolves_bin() {
    let d = tmp();
    write(d.path(), "disc.bin", &iso_bytes("CUEDISC"));
    // MODE1/2048 data track in disc.bin (2048-byte ISO sectors at offset 0).
    let cue = "FILE \"disc.bin\" BINARY\nTRACK 01 MODE1/2048\nINDEX 01 00:00:00\n";
    let p = write(d.path(), "disc.cue", cue.as_bytes());
    assert_opens_to_label(&p, "CUEDISC");
}

#[test]
fn open_cue_without_data_track_errors() {
    let d = tmp();
    write(d.path(), "audio.bin", &iso_bytes("X"));
    // Audio-only sheet -> no data track -> resolve_cue_bin returns Err.
    let cue = "FILE \"audio.bin\" BINARY\nTRACK 01 AUDIO\nINDEX 01 00:00:00\n";
    let p = write(d.path(), "audio.cue", cue.as_bytes());
    assert!(open(&p).is_err());
}

#[test]
fn open_ccd_resolves_img() {
    let d = tmp();
    // CloneCD .img stores full 2352 sectors; open() windows via a MODE-1 track
    // start LBA. Our ISO is 2048-byte; wrap it in a 2352-sector .img so the
    // CD001 probe at the raw-Mode-1 offset succeeds is out of scope — instead
    // assert the resolution arm: a .ccd whose sibling .img is present resolves,
    // and a missing .img errors.
    write(d.path(), "clone.img", &iso_bytes("CCDDISC"));
    let ccd = "[Disc]\nTocEntries=1\n[Entry 0]\nPoint=0x01\nPLBA=0\n[TRACK 1]\nMODE=0\n";
    let p = write(d.path(), "clone.ccd", ccd.as_bytes());
    // MODE=0 (audio) makes it a raw pass-through: open() resolves to the .img
    // and reads its bytes as a plain 2048 image (ISO at LBA 0).
    assert_opens_to_label(&p, "CCDDISC");
}

#[test]
fn open_ccd_without_img_errors() {
    let d = tmp();
    let ccd = "[Disc]\nTocEntries=0\n";
    let p = write(d.path(), "lonely.ccd", ccd.as_bytes());
    assert!(open(&p).is_err());
}

#[test]
fn open_nrg_windows_data_track() {
    // Build a v2 (NER5) NRG whose single DAOX track (mode 0x00 -> Iso2048) holds
    // the real ISO payload at file offset 0.
    let d = tmp();
    let payload = iso_bytes("NRGDISC");
    let nrg = build_nrg_v2_iso(&payload);
    let p = write(d.path(), "disc.nrg", &nrg);
    assert_opens_to_label(&p, "NRGDISC");
}

#[test]
fn open_nrg_without_data_track_errors() {
    let d = tmp();
    // An NRG with no chunks at all -> parse yields no data track -> Err.
    let nrg = build_nrg_empty();
    let p = write(d.path(), "empty.nrg", &nrg);
    assert!(open(&p).is_err());
}

#[test]
fn open_nrg_audio_only_errors() {
    // A parseable NRG whose only track is audio (mode 0x07): parse() succeeds
    // but data_track() is None -> open_nrg hits the "no data track" arm.
    let d = tmp();
    let nrg = build_nrg_v2_mode(&iso_bytes("AUDIO"), 0x07);
    let p = write(d.path(), "audio.nrg", &nrg);
    assert!(open(&p).is_err());
}

#[test]
fn open_mds_audio_only_errors() {
    // An MDS whose only track is audio (mode 0xA9 -> no SectorMode): parse()
    // succeeds but data_track() is None -> open_mds hits the "no data track" arm.
    let d = tmp();
    std::fs::write(d.path().join("audio.mdf"), iso_bytes("X")).unwrap();
    let mds = build_mds_mode(0xA9, 2352, 0, 10);
    let p = write(d.path(), "audio.mds", &mds);
    assert!(open(&p).is_err());
}

#[test]
fn open_toc_without_explicit_length_uses_available_bytes() {
    // A DATAFILE with a byte offset but NO MSF length -> open_toc takes the
    // `length_sectors == 0` else-arm (use all available bytes from the offset).
    let d = tmp();
    let payload = iso_bytes("TOCAVAIL");
    write(d.path(), "avail.bin", &payload);
    let toc = "CD_ROM\nTRACK MODE1\nDATAFILE \"avail.bin\" #0\n";
    let p = write(d.path(), "avail.toc", toc.as_bytes());
    assert_opens_to_label(&p, "TOCAVAIL");
}

#[test]
fn open_mds_windows_data_track_via_mdf() {
    let d = tmp();
    let payload = iso_bytes("MDSDISC");
    let num_sectors = (payload.len() / 2048) as u32;
    write(d.path(), "disc.mdf", &payload);
    let mds = build_mds_iso(2048, 0, num_sectors);
    let p = write(d.path(), "disc.mds", &mds);
    assert_opens_to_label(&p, "MDSDISC");
}

#[test]
fn open_toc_windows_data_track() {
    let d = tmp();
    let payload = iso_bytes("TOCDISC");
    write(d.path(), "data.bin", &payload);
    let num_sectors = payload.len() / 2048;
    // A CDRDAO .toc with a MODE1 data track pointing at data.bin from offset 0.
    let toc =
        format!("CD_ROM\nTRACK MODE1\nDATAFILE \"data.bin\" #0 {}\n", lba_to_msf(num_sectors));
    let p = write(d.path(), "disc.toc", toc.as_bytes());
    assert_opens_to_label(&p, "TOCDISC");
}

#[test]
fn open_toc_without_datafile_errors() {
    let d = tmp();
    // A data track with no DATAFILE line -> Err.
    let toc = "CD_ROM\nTRACK MODE1\n";
    let p = write(d.path(), "nofile.toc", toc.as_bytes());
    assert!(open(&p).is_err());
}

#[test]
fn open_toc_audio_only_errors() {
    let d = tmp();
    // An audio-only TOC has no filesystem data track -> the "no data track"
    // arm of open_toc.
    let toc = "CD_DA\nTRACK AUDIO\nAUDIOFILE \"a.wav\" 00:03:00\n";
    let p = write(d.path(), "audio.toc", toc.as_bytes());
    assert!(open(&p).is_err());
}

// --- IsoReader driven over an opened Box<dyn ReadSeek> and a File ----------

#[test]
fn iso_reader_over_boxed_opened_source_walks_and_audits() {
    // open() returns Box<dyn ReadSeek>; driving an IsoReader over it exercises
    // the walk/timeline/recover/audit methods' boxed-source monomorphizations.
    let d = tmp();
    let joliet = helpers::build_joliet_iso("BOXJOL", vec![file("A.TXT", b"a")]).into_inner();
    let p = write(d.path(), "boxed.iso", &joliet);

    let src = open(&p).expect("open");
    let mut reader = IsoReader::open(src).expect("IsoReader over boxed source");
    assert!(!reader.walk().expect("walk").is_empty());
    // Joliet is present, so walk_joliet returns entries too.
    let _ = reader.walk_joliet().expect("walk_joliet");
    let _ = reader.recover_lost_files().expect("recover");
    let _ = reader.audit_pre_system().expect("audit_pre_system");
    let _ = reader.timeline().expect("timeline");
}

#[test]
fn iso_reader_over_file_walks() {
    // A plain std::fs::File source drives the File-typed reader instantiations.
    let d = tmp();
    let p = write(d.path(), "file.iso", &iso_bytes("FILESRC"));
    let f = std::fs::File::open(&p).expect("open file");
    let mut reader = IsoReader::open(f).expect("IsoReader over File");
    assert!(!reader.walk().expect("walk").is_empty());
    let _ = reader.recover_lost_files().expect("recover");
}

// --- container builders ----------------------------------------------------

fn be32(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}
fn be64(v: u64) -> [u8; 8] {
    v.to_be_bytes()
}

/// Build a v2 NER5 NRG: `payload` as a single DAOX Mode-1 (0x00) data track at
/// file offset 0, then a DAOX chunk, END!, and the NER5 footer.
fn build_nrg_v2_iso(payload: &[u8]) -> Vec<u8> {
    build_nrg_v2_mode(payload, 0x00)
}

/// As [`build_nrg_v2_iso`] but with an explicit Nero mode code (0x00 -> Iso2048
/// data, 0x07 -> audio, etc.).
fn build_nrg_v2_mode(payload: &[u8], mode_code: u8) -> Vec<u8> {
    let mut img = payload.to_vec();
    let trailer_offset = img.len() as u64;

    // DAOX: 22-byte header (MCN at [0..13]) + one 42-byte subblock.
    let mut dao = vec![0u8; 22];
    let mut sub = Vec::new();
    sub.extend_from_slice(&[0u8; 12]); // isrc
    sub.extend_from_slice(&2048u16.to_be_bytes()); // sector_size
    sub.push(mode_code);
    sub.extend_from_slice(&[0u8; 3]); // pad
    sub.extend_from_slice(&be64(0)); // pregap_offset
    sub.extend_from_slice(&be64(0)); // start_offset
    sub.extend_from_slice(&be64(payload.len() as u64)); // end_offset
    assert_eq!(sub.len(), 42);
    dao.extend_from_slice(&sub);

    img.extend_from_slice(b"DAOX");
    img.extend_from_slice(&be32(dao.len() as u32));
    img.extend_from_slice(&dao);
    img.extend_from_slice(b"END!");
    img.extend_from_slice(&be32(0));
    img.extend_from_slice(b"NER5");
    img.extend_from_slice(&be64(trailer_offset));
    img
}

/// An NRG whose chunk list is empty (only END!): no tracks.
fn build_nrg_empty() -> Vec<u8> {
    let mut img = Vec::new();
    let trailer_offset = img.len() as u64;
    img.extend_from_slice(b"END!");
    img.extend_from_slice(&be32(0));
    img.extend_from_slice(b"NER5");
    img.extend_from_slice(&be64(trailer_offset));
    img
}

/// Build a minimal one-track MDS (header @0, session @88, track @112, extra
/// @192) whose data track windows an .mdf from `start_offset`.
fn build_mds_iso(sector_size: u16, start_offset: u64, num_sectors: u32) -> Vec<u8> {
    build_mds_mode(0x02, sector_size, start_offset, num_sectors)
}

/// As [`build_mds_iso`] but with an explicit Alcohol mode byte (0x02 -> Mode 1
/// data; a code with no [`iso9660_forensic::SectorMode`] maps to audio).
fn build_mds_mode(mode: u8, sector_size: u16, start_offset: u64, num_sectors: u32) -> Vec<u8> {
    let le16 = u16::to_le_bytes;
    let le32 = u32::to_le_bytes;
    let mut img = vec![0u8; 200];
    img[0..16].copy_from_slice(b"MEDIA DESCRIPTOR");
    img[16] = 0x01;
    img[18..20].copy_from_slice(&le16(0));
    img[20..22].copy_from_slice(&le16(1));
    img[80..84].copy_from_slice(&le32(88));
    let s = 88;
    img[s + 8..s + 10].copy_from_slice(&le16(1));
    img[s + 10] = 1;
    img[s + 11] = 0;
    img[s + 12..s + 14].copy_from_slice(&le16(1));
    img[s + 14..s + 16].copy_from_slice(&le16(1));
    img[s + 20..s + 24].copy_from_slice(&le32(112));
    let t = 112;
    img[t] = mode; // 0x02 = Mode 1 (2048) -> Iso2048; others map to audio
    img[t + 1] = 0;
    img[t + 4] = 1;
    img[t + 12..t + 16].copy_from_slice(&le32(192));
    img[t + 16..t + 18].copy_from_slice(&le16(sector_size));
    img[t + 36..t + 40].copy_from_slice(&le32(0));
    img[t + 40..t + 48].copy_from_slice(&start_offset.to_le_bytes());
    let e = 192;
    img[e..e + 4].copy_from_slice(&le32(0));
    img[e + 4..e + 8].copy_from_slice(&le32(num_sectors));
    img
}

/// Render an LBA count as an `MM:SS:FF` timecode (75 frames/second).
fn lba_to_msf(sectors: usize) -> String {
    let frames = sectors % 75;
    let total_seconds = sectors / 75;
    let seconds = total_seconds % 60;
    let minutes = total_seconds / 60;
    format!("{minutes:02}:{seconds:02}:{frames:02}")
}
