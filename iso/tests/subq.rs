// CD subchannel Q decoding tests (ECMA-130 §22).
//
// 12-byte Q frames computed to spec: byte0 = control<<4 | adr, bytes 1-9
// q-data, bytes 10-11 = inverted-CCITT CRC (big-endian).

use iso9660_forensic::cue::Msf;
use iso9660_forensic::subq::{decode_q, q_crc_valid, Control, QData, QFrame, TrackNo};

// Mode 1: control=0x4 (data, no copy), adr=1, TNO01 IDX01, rel 00:02:00, abs 00:04:00.
const MODE1: [u8; 12] = [
    0x41, 0x01, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x09, 0xD4,
];
// Mode 2: control=0x4, adr=2, catalog 1234567890123.
const MODE2: [u8; 12] = [
    0x42, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x30, 0x00, 0x00, 0x99, 0xCB,
];

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
fn decode_mode3_is_other() {
    let mut f = MODE1;
    f[0] = 0x43; // control 0x4, adr 3 (ISRC — not decoded here)
    let q = decode_q(&f).unwrap();
    assert_eq!(q.data, QData::Other(3));
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
