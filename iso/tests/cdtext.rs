// CD-Text decoding tests (MMC-3 Annex J).
//
// CRC primitive is checked against the external CRC-16/XMODEM vector
// (0x31C3 for "123456789") to ground it independently of the pack builder.
// Pack byte vectors are computed to spec (CRC = CCITT inverted, big-endian).

use iso9660_forensic::cdtext::{crc16_ccitt, decode, PackType};

#[test]
fn crc16_matches_external_xmodem_vector() {
    assert_eq!(crc16_ccitt(b"123456789"), 0x31C3);
    assert_eq!(crc16_ccitt(b""), 0x0000);
}

#[test]
fn pack_type_from_byte() {
    assert_eq!(PackType::from_byte(0x80), PackType::Title);
    assert_eq!(PackType::from_byte(0x81), PackType::Performer);
    assert_eq!(PackType::from_byte(0x8E), PackType::UpcEanIsrc);
    assert_eq!(PackType::from_byte(0x8F), PackType::SizeInfo);
    assert_eq!(PackType::from_byte(0x8A), PackType::Reserved(0x8A));
}

#[test]
fn decode_single_pack_album_and_track_title() {
    // One Title pack carrying "ALBUM\0SONG1\0" (12 bytes) + spec CRC 0x41D2.
    let pack: [u8; 18] = [
        0x80, 0x00, 0x00, 0x00, 0x41, 0x4C, 0x42, 0x55, 0x4D, 0x00, 0x53, 0x4F,
        0x4E, 0x47, 0x31, 0x00, 0x41, 0xD2,
    ];
    let ct = decode(&pack);
    assert_eq!(ct.album_title(), Some("ALBUM"));
    assert_eq!(ct.track_title(1), Some("SONG1"));
    assert_eq!(ct.track_title(2), None);
}

#[test]
fn decode_performer_spanning_two_packs() {
    // "BAND\0ARTIST ONE X\0" split across two 18-byte Performer packs.
    let blob: [u8; 36] = [
        0x81, 0x00, 0x00, 0x00, 0x42, 0x41, 0x4E, 0x44, 0x00, 0x41, 0x52, 0x54,
        0x49, 0x53, 0x54, 0x20, 0xEE, 0x45, 0x81, 0x01, 0x01, 0x00, 0x4F, 0x4E,
        0x45, 0x20, 0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x91, 0x13,
    ];
    let ct = decode(&blob);
    assert_eq!(ct.album_performer(), Some("BAND"));
    assert_eq!(ct.track_performer(1), Some("ARTIST ONE X"));
}

#[test]
fn decode_empty_blob() {
    assert!(decode(&[]).entries().is_empty());
    // A sub-pack-length tail is ignored.
    assert!(decode(&[0x80, 0x00, 0x00]).entries().is_empty());
}

#[test]
fn decode_ignores_non_text_packs() {
    // A SIZE_INFO (0x8F) pack carries binary block info, not text.
    let pack = [0x8Fu8; 18];
    let ct = decode(&pack);
    assert!(ct.album_title().is_none());
}
