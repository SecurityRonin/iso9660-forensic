#![allow(clippy::unwrap_used, clippy::expect_used)]

// Rock Ridge extended — PX uid/gid/nlink/ino, TF long-form, CE detection.
// Spec: IEEE P1282 RRIP §4.1.1 (PX), §4.1.6 (TF), §4.1.1 (CE).
// Reference impls compared: cdfs (git.sr.ht/~az1/iso9660-rs) + mkisofs-rs.

use iso9660_forensic::rock_ridge;

// ── builders ─────────────────────────────────────────────────────────────────

/// PX v1 entry (len=44): mode + nlink + uid + gid + ino, all both-endian u32.
fn px_v1(mode: u32, nlink: u32, uid: u32, gid: u32, ino: u32) -> Vec<u8> {
    let mut v = vec![b'P', b'X', 44u8, 1u8];
    for val in [mode, nlink, uid, gid, ino] {
        v.extend_from_slice(&val.to_le_bytes());
        v.extend_from_slice(&val.to_be_bytes());
    }
    v
}

/// PX v2 entry (len=36): mode + nlink + uid + gid only (no inode field).
fn px_v2(mode: u32, nlink: u32, uid: u32, gid: u32) -> Vec<u8> {
    let mut v = vec![b'P', b'X', 36u8, 1u8];
    for val in [mode, nlink, uid, gid] {
        v.extend_from_slice(&val.to_le_bytes());
        v.extend_from_slice(&val.to_be_bytes());
    }
    v
}

/// TF entry using 17-byte long-format timestamps (bit 7 of flags = 1).
fn tf_long(flags: u8, timestamps: &[[u8; 17]]) -> Vec<u8> {
    let body_len = timestamps.len() * 17;
    let len = 5 + body_len;
    let mut v = vec![b'T', b'F', len as u8, 1u8, flags | 0x80];
    for ts in timestamps {
        v.extend_from_slice(ts);
    }
    v
}

/// CE entry: both-endian lba, offset, len (each 8 bytes = LE u32 + BE u32).
fn ce(lba: u32, offset: u32, len: u32) -> Vec<u8> {
    let mut v = vec![b'C', b'E', 28u8, 1u8];
    for val in [lba, offset, len] {
        v.extend_from_slice(&val.to_le_bytes());
        v.extend_from_slice(&val.to_be_bytes());
    }
    v
}

// ── PX tests ─────────────────────────────────────────────────────────────────

#[test]
fn px_v1_all_fields() {
    let su = px_v1(0o100644, 2, 1000, 1001, 42);
    let a = rock_ridge::posix_attrs(&su).expect("must find PX");
    assert_eq!(a.mode, 0o100644);
    assert_eq!(a.nlink, 2);
    assert_eq!(a.uid, 1000);
    assert_eq!(a.gid, 1001);
    assert_eq!(a.ino, Some(42));
}

#[test]
fn px_v2_no_inode() {
    let su = px_v2(0o040755, 3, 0, 0);
    let a = rock_ridge::posix_attrs(&su).expect("must find PX v2");
    assert_eq!(a.mode, 0o040755);
    assert_eq!(a.nlink, 3);
    assert_eq!(a.ino, None);
}

#[test]
fn px_no_entry_returns_none() {
    assert!(rock_ridge::posix_attrs(b"NM\x06\x01\x00abc").is_none());
}

#[test]
fn posix_mode_backward_compat() {
    let su = px_v1(0o100755, 1, 0, 0, 0);
    assert_eq!(rock_ridge::posix_mode(&su), Some(0o100755));
}

#[test]
fn px_after_nm_entry() {
    // NM entry: sig(2)+len(1)+ver(1)+flags(1)+name(3) = 8 bytes, no trailing pad.
    let mut su = b"NM\x08\x01\x00abc".to_vec();
    su.extend(px_v1(0o100644, 1, 500, 500, 7));
    let a = rock_ridge::posix_attrs(&su).expect("must find PX after NM");
    assert_eq!(a.uid, 500);
}

// ── TF long-format tests ──────────────────────────────────────────────────────

// A valid 17-byte long timestamp: "20220101120000000\x00" (note: 17 bytes total)
const LONG_TS: [u8; 17] = *b"20220101120000000";

#[test]
fn tf_long_creation_only() {
    let su = tf_long(0x01, &[LONG_TS]); // bit 0 = CREATION
    let r = rock_ridge::timestamps_any(&su).expect("must parse long TF");
    assert!(r.creation.is_some(), "creation must be Some");
    assert!(r.modify.is_none());
}

#[test]
fn tf_long_modify_and_access() {
    let su = tf_long(0x06, &[LONG_TS, LONG_TS]); // bits 1+2 = MODIFY + ACCESS
    let r = rock_ridge::timestamps_any(&su).unwrap();
    assert!(r.creation.is_none());
    assert!(r.modify.is_some());
    assert!(r.access.is_some());
}

#[test]
fn tf_long_all_seven() {
    let su = tf_long(0x7F, &[LONG_TS; 7]);
    let r = rock_ridge::timestamps_any(&su).unwrap();
    assert!(r.creation.is_some());
    assert!(r.modify.is_some());
    assert!(r.access.is_some());
    assert!(r.attributes.is_some());
    assert!(r.backup.is_some());
    assert!(r.expiration.is_some());
    assert!(r.effective.is_some());
}

#[test]
fn tf_short_via_timestamps_any() {
    // Short 7-byte format must still work through timestamps_any()
    let ts7 = [0x7Au8, 1, 1, 0, 0, 0, 0];
    let mut su = vec![b'T', b'F', 12u8, 1u8, 0x01]; // bit 0 = CREATION, bit7=0 => short
    su.extend_from_slice(&ts7);
    let r = rock_ridge::timestamps_any(&su).unwrap();
    assert!(r.creation.is_some());
}

#[test]
fn tf_long_skipped_by_old_timestamps() {
    // Backward compat: old timestamps() returns None for long-format entries.
    let su = tf_long(0x01, &[LONG_TS]);
    assert!(rock_ridge::timestamps(&su).is_none());
}

// ── CE continuation area tests ────────────────────────────────────────────────

#[test]
fn ce_returns_lba_offset_len() {
    let su = ce(0x1234, 64, 128);
    let c = rock_ridge::continuation(&su).expect("must find CE");
    assert_eq!(c.lba, 0x1234);
    assert_eq!(c.offset, 64);
    assert_eq!(c.len, 128);
}

#[test]
fn ce_no_entry_returns_none() {
    assert!(rock_ridge::continuation(b"NM\x06\x01\x00abc").is_none());
}

#[test]
fn ce_after_nm_entry() {
    let mut su = b"NM\x08\x01\x00abc".to_vec();
    su.extend(ce(99, 0, 256));
    let c = rock_ridge::continuation(&su).unwrap();
    assert_eq!(c.lba, 99);
    assert_eq!(c.len, 256);
}

#[test]
fn ce_struct_fields_accessible() {
    let c = rock_ridge::ContinuationArea { lba: 1, offset: 2, len: 3 };
    assert_eq!(c.lba, 1);
    assert_eq!(c.offset, 2);
    assert_eq!(c.len, 3);
}
