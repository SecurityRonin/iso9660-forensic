// CD subchannel Q decoding tests (ECMA-130 §22).
//
// 12-byte Q frames computed to spec: byte0 = control<<4 | adr, bytes 1-9
// q-data, bytes 10-11 = inverted-CCITT CRC (big-endian).

use iso9660_forensic::cue::Msf;
use iso9660_forensic::subq::{decode_q, q_crc_valid, Control, QData, QFrame, TrackNo};

// Mode 1: control=0x4 (data, no copy), adr=1, TNO01 IDX01, rel 00:02:00, abs 00:04:00.
const MODE1: [u8; 12] = [0x41, 0x01, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x09, 0xD4];
// Mode 2: control=0x4, adr=2, catalog 1234567890123.
const MODE2: [u8; 12] = [0x42, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x30, 0x00, 0x00, 0x99, 0xCB];

#[test]
fn control_flags() {
    let c = Control(0x4); // 0100 = data, no copy
    assert!(c.is_data());
    assert!(!c.copy_permitted());
    assert!(!c.four_channel());
    assert!(!c.pre_emphasis());

    let c = Control(0x6); // 0110 = data, copy permitted
    assert!(c.is_data());
    assert!(c.copy_permitted());

    let c = Control(0x0); // audio, no pre-emphasis
    assert!(!c.is_data());

    let c = Control(0x1); // audio with pre-emphasis
    assert!(c.pre_emphasis());
    assert!(!c.is_data());
}

#[test]
fn decode_mode1_position() {
    let q = decode_q(&MODE1).expect("decode mode 1");
    assert_eq!(q.adr, 1);
    assert!(q.control.is_data());
    assert_eq!(
        q.data,
        QData::Position {
            track: TrackNo::Track(1),
            index: 1,
            relative: Msf { minutes: 0, seconds: 2, frames: 0 },
            absolute: Msf { minutes: 0, seconds: 4, frames: 0 },
        }
    );
}

#[test]
fn decode_mode1_leadout() {
    // TNO = 0xAA marks the lead-out.
    let mut f = MODE1;
    f[1] = 0xAA;
    let q = decode_q(&f).unwrap();
    match q.data {
        QData::Position { track, .. } => assert_eq!(track, TrackNo::LeadOut),
        other => panic!("expected position, got {other:?}"),
    }
}

#[test]
fn decode_mode2_catalog() {
    let q = decode_q(&MODE2).expect("decode mode 2");
    assert_eq!(q.adr, 2);
    assert_eq!(q.data, QData::Catalog("1234567890123".to_string()));
}

#[test]
fn decode_mode3_isrc() {
    // ISRC "USRC17607839" (US-RC1-76-07839), control 0x4, adr 3.
    let frame: [u8; 12] = [0x43, 0x96, 0x38, 0x93, 0x04, 0x76, 0x07, 0x83, 0x90, 0x00, 0x6B, 0x86];
    let q = decode_q(&frame).expect("decode mode 3");
    assert_eq!(q.adr, 3);
    assert_eq!(q.data, QData::Isrc("USRC17607839".to_string()));
}

#[test]
fn decode_mode5_is_other() {
    let mut f = MODE1;
    f[0] = 0x45; // control 0x4, adr 5 (multi-session TOC) — not decoded
    let q = decode_q(&f).unwrap();
    assert_eq!(q.data, QData::Other(5));
}

#[test]
fn crc_valid_and_invalid() {
    assert!(q_crc_valid(&MODE1));
    assert!(q_crc_valid(&MODE2));
    let mut bad = MODE1;
    bad[11] ^= 0xFF; // corrupt CRC
    assert!(!q_crc_valid(&bad));
}

#[test]
fn short_frame_is_none() {
    assert!(decode_q(&[0x41, 0x01]).is_none());
    assert!(decode_q(&[]).is_none());
}

#[test]
fn frame_type_is_constructible() {
    // QFrame is a public type usable by callers.
    let q: QFrame = decode_q(&MODE1).unwrap();
    let _ = q.control;
}

// ── subchannel extraction (v0.3-dev) ──────────────────────────────────────────

/// Interleave a 12-byte Q frame into a 96-byte subcode block (bit 6 = Q).
fn interleave_q(q: &[u8; 12]) -> [u8; 96] {
    let mut sub = [0u8; 96];
    for bit in 0..96 {
        let byte = q[bit / 8];
        let set = (byte >> (7 - (bit % 8))) & 1;
        sub[bit] = set << 6; // bit 6 = Q channel
    }
    sub
}

#[test]
fn extract_q_roundtrips_mode1() {
    let sub = interleave_q(&MODE1);
    let q = iso9660_forensic::subq::extract_q(&sub).expect("extract");
    assert_eq!(q, MODE1);
}

#[test]
fn extract_then_decode_position() {
    let sub = interleave_q(&MODE2);
    let q = iso9660_forensic::subq::extract_q(&sub).unwrap();
    let frame = decode_q(&q).unwrap();
    assert_eq!(frame.data, QData::Catalog("1234567890123".to_string()));
}

#[test]
fn extract_q_ignores_other_channel_bits() {
    // Set all bits except Q (bit 6); extraction must still recover the Q frame.
    let mut sub = interleave_q(&MODE1);
    for b in &mut sub {
        *b |= 0b1011_1111; // everything but bit 6
    }
    let q = iso9660_forensic::subq::extract_q(&sub).expect("extract");
    assert_eq!(q, MODE1);
}

#[test]
fn extract_q_short_is_none() {
    assert!(iso9660_forensic::subq::extract_q(&[0u8; 95]).is_none());
}

#[test]
fn reader_read_subchannel_q_from_2448() {
    use std::io::Cursor;
    const P: usize = 2448;
    let mut img = vec![0u8; 20 * P];
    // Raw2448 Mode 1: sync + mode byte + CD001 at offset 16 of sector 16.
    const SYNC: [u8; 12] = [0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0];
    for s in 0..20 {
        img[s * P..s * P + 12].copy_from_slice(&SYNC);
        img[s * P + 15] = 0x01; // Mode 1
    }
    let pvd = 16 * P + 16;
    img[pvd] = 0x01;
    img[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
    img[pvd + 6] = 0x01;
    // Volume Descriptor Set Terminator (type 0xFF) at sector 17, so the VD
    // chain scan stops instead of reading past EOF.
    let term = 17 * P + 16;
    img[term] = 0xFF;
    img[term + 1..term + 6].copy_from_slice(b"CD001");
    img[term + 6] = 0x01;
    // Put a Q frame in sector 18's subchannel (offset 2352).
    let sub = interleave_q(&MODE1);
    let soff = 18 * P + 2352;
    img[soff..soff + 96].copy_from_slice(&sub);

    let mut reader = iso9660_forensic::IsoReader::open(Cursor::new(img)).unwrap();
    assert_eq!(reader.sector_mode(), iso9660_forensic::SectorMode::Raw2448);
    let q = reader.read_subchannel_q(18).unwrap().expect("subchannel present");
    let frame = decode_q(&q).unwrap();
    assert!(frame.control.is_data());
    assert_eq!(frame.adr, 1);
}

#[test]
fn reader_no_subchannel_for_iso2048() {
    // rock_ridge.iso is 2048-byte mode -> no subchannel.
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/rock_ridge.iso");
    let f = std::fs::File::open(path).unwrap();
    let mut reader = iso9660_forensic::IsoReader::open(f).unwrap();
    assert_eq!(reader.read_subchannel_q(16).unwrap(), None);
}

// ── disc-level Q summary (v0.3-dev) ───────────────────────────────────────────

#[test]
fn summarize_attributes_isrc_to_current_track() {
    use iso9660_forensic::subq::summarize_q;
    // Disc order: position(track 1), ISRC (-> track 1), position(track 2),
    // catalog (MCN). Q-mode 3 frames carry no track; the track is set by the
    // preceding Q-mode 1 position frame.
    let isrc: [u8; 12] = [0x43, 0x96, 0x38, 0x93, 0x04, 0x76, 0x07, 0x83, 0x90, 0x00, 0x6B, 0x86];
    let mut pos2 = MODE1;
    pos2[1] = 0x02; // TNO = track 2 (BCD)
    let frames = vec![
        decode_q(&MODE1).unwrap(),
        decode_q(&isrc).unwrap(),
        decode_q(&pos2).unwrap(),
        decode_q(&MODE2).unwrap(),
    ];
    let s = summarize_q(frames);
    assert_eq!(s.catalog.as_deref(), Some("1234567890123"));
    assert_eq!(s.isrcs.get(&1).map(String::as_str), Some("USRC17607839"));
    assert!(!s.isrcs.contains_key(&2)); // no ISRC seen during track 2
}

#[test]
fn summarize_empty_is_default() {
    use iso9660_forensic::subq::{summarize_q, QSummary};
    assert_eq!(summarize_q(std::iter::empty()), QSummary::default());
}

#[test]
fn summarize_leadout_does_not_become_a_track() {
    use iso9660_forensic::subq::summarize_q;
    // An ISRC frame appearing while the lead-out (TNO 0xAA) is current must not
    // be filed under a numbered track.
    let mut leadout = MODE1;
    leadout[1] = 0xAA;
    let isrc: [u8; 12] = [0x43, 0x96, 0x38, 0x93, 0x04, 0x76, 0x07, 0x83, 0x90, 0x00, 0x6B, 0x86];
    let frames = vec![decode_q(&leadout).unwrap(), decode_q(&isrc).unwrap()];
    let s = summarize_q(frames);
    assert!(s.isrcs.is_empty());
}

#[test]
fn reader_scan_subchannel_collects_summary() {
    use std::io::Cursor;
    const P: usize = 2448;
    let n = 24usize;
    let mut img = vec![0u8; n * P];
    const SYNC: [u8; 12] = [0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0];
    for s in 0..n {
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
    // Q frames across the program area (only CRC-valid frames are trusted).
    let isrc: [u8; 12] = [0x43, 0x96, 0x38, 0x93, 0x04, 0x76, 0x07, 0x83, 0x90, 0x00, 0x6B, 0x86];
    let put = |img: &mut [u8], sector: usize, q: &[u8; 12]| {
        let sub = interleave_q(q);
        let off = sector * P + 2352;
        img[off..off + 96].copy_from_slice(&sub);
    };
    put(&mut img, 18, &MODE1); // position: track 1
    put(&mut img, 19, &isrc); // ISRC -> track 1
    put(&mut img, 20, &MODE2); // catalog

    let mut reader = iso9660_forensic::IsoReader::open(Cursor::new(img)).unwrap();
    let s = reader.scan_subchannel_q().unwrap();
    assert_eq!(s.catalog.as_deref(), Some("1234567890123"));
    assert_eq!(s.isrcs.get(&1).map(String::as_str), Some("USRC17607839"));
}

#[test]
fn reader_scan_subchannel_empty_for_iso2048() {
    use iso9660_forensic::subq::QSummary;
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/rock_ridge.iso");
    let f = std::fs::File::open(path).unwrap();
    let mut reader = iso9660_forensic::IsoReader::open(f).unwrap();
    assert_eq!(reader.scan_subchannel_q().unwrap(), QSummary::default());
}

// ── CloneCD .sub file summary (v0.3-dev) ──────────────────────────────────────

#[test]
fn summarize_sub_collects_from_external_subchannel_file() {
    use iso9660_forensic::subq::summarize_sub;
    // A CloneCD .sub file: 96 interleaved subcode bytes per sector, stored in
    // a separate file rather than appended to each 2352-byte sector.
    let isrc: [u8; 12] = [0x43, 0x96, 0x38, 0x93, 0x04, 0x76, 0x07, 0x83, 0x90, 0x00, 0x6B, 0x86];
    let mut sub = Vec::new();
    sub.extend_from_slice(&[0u8; 96]); // blank sector (no valid Q)
    sub.extend_from_slice(&interleave_q(&MODE1)); // position: track 1
    sub.extend_from_slice(&interleave_q(&isrc)); // ISRC -> track 1
    sub.extend_from_slice(&interleave_q(&MODE2)); // catalog
    let s = summarize_sub(&sub);
    assert_eq!(s.catalog.as_deref(), Some("1234567890123"));
    assert_eq!(s.isrcs.get(&1).map(String::as_str), Some("USRC17607839"));
}

#[test]
fn summarize_sub_ignores_trailing_partial_block_and_empty() {
    use iso9660_forensic::subq::{summarize_sub, QSummary};
    assert_eq!(summarize_sub(&[]), QSummary::default());
    // 50 trailing bytes (< one 96-byte block) must be ignored, not panic.
    let mut sub = interleave_q(&MODE2).to_vec();
    sub.extend_from_slice(&[0u8; 50]);
    assert_eq!(summarize_sub(&sub).catalog.as_deref(), Some("1234567890123"));
}
