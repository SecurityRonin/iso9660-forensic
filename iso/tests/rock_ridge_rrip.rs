// Rock Ridge RRIP — tests for TF, SL, CL, PL, RE extensions.
// These tests drive the implementation; they reference functions that must be
// added to iso9660_forensic::rock_ridge.

use iso9660_forensic::rock_ridge;

// ── Byte-sequence builders ────────────────────────────────────────────────────

/// Build a TF System Use entry with the given flags and 7-byte short timestamps.
fn tf_entry(flags: u8, ts_list: &[[u8; 7]]) -> Vec<u8> {
    let len = 5u8 + ts_list.len() as u8 * 7;
    let mut v = vec![b'T', b'F', len, 1u8, flags];
    for ts in ts_list {
        v.extend_from_slice(ts);
    }
    v
}

/// Build a single SL component record.
fn sl_comp(flags: u8, data: &[u8]) -> Vec<u8> {
    let mut v = vec![flags, data.len() as u8];
    v.extend_from_slice(data);
    v
}

/// Build an SL System Use entry from a list of component records.
fn sl_entry(sl_flags: u8, components: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = components.iter().flat_map(|c| c.iter().copied()).collect();
    let mut v = vec![b'S', b'L', (5 + body.len()) as u8, 1u8, sl_flags];
    v.extend(body);
    v
}

/// Build a CL or PL System Use entry encoding an LBA in both LE and BE.
fn loc_entry(sig: &[u8; 2], lba: u32) -> Vec<u8> {
    let mut v = vec![sig[0], sig[1], 12u8, 1u8];
    v.extend_from_slice(&lba.to_le_bytes());
    v.extend_from_slice(&lba.to_be_bytes());
    v
}

// ── TF (timestamps) ───────────────────────────────────────────────────────────

#[test]
fn tf_no_entry_returns_none() {
    assert!(rock_ridge::timestamps(b"NM\x06\x01\x00abc").is_none());
}

#[test]
fn tf_creation_only_short_format() {
    let ts = [0x7Au8, 1, 1, 0, 0, 0, 0]; // year=122 (2022), Jan 1, midnight, UTC
    let su = tf_entry(0x01, &[ts]);
    let result = rock_ridge::timestamps(&su).unwrap();
    assert_eq!(result.creation, Some(ts));
    assert_eq!(result.modify, None);
    assert_eq!(result.access, None);
}

#[test]
fn tf_creation_and_modify() {
    let c = [0x7Au8, 1, 1, 0, 0, 0, 0];
    let m = [0x7Au8, 6, 2, 12, 30, 0, 0];
    let su = tf_entry(0x03, &[c, m]); // bits 0+1: CREATION + MODIFY
    let result = rock_ridge::timestamps(&su).unwrap();
    assert_eq!(result.creation, Some(c));
    assert_eq!(result.modify, Some(m));
    assert_eq!(result.access, None);
}

#[test]
fn tf_modify_only() {
    let m = [0x7Au8, 6, 15, 9, 0, 0, 0];
    let su = tf_entry(0x02, &[m]); // bit 1: MODIFY
    let result = rock_ridge::timestamps(&su).unwrap();
    assert_eq!(result.creation, None);
    assert_eq!(result.modify, Some(m));
}

#[test]
fn tf_access_bit() {
    let a = [0x7Bu8, 3, 15, 9, 30, 0, 0];
    let su = tf_entry(0x04, &[a]); // bit 2: ACCESS
    let result = rock_ridge::timestamps(&su).unwrap();
    assert_eq!(result.creation, None);
    assert_eq!(result.modify, None);
    assert_eq!(result.access, Some(a));
}

#[test]
fn tf_all_seven_timestamps() {
    let ts = [0x7Au8, 1, 1, 0, 0, 0, 0];
    let su = tf_entry(0x7F, &[ts, ts, ts, ts, ts, ts, ts]); // bits 0-6 all set
    let result = rock_ridge::timestamps(&su).unwrap();
    assert_eq!(result.creation, Some(ts));
    assert_eq!(result.modify, Some(ts));
    assert_eq!(result.access, Some(ts));
    assert_eq!(result.attributes, Some(ts));
    assert_eq!(result.backup, Some(ts));
    assert_eq!(result.expiration, Some(ts));
    assert_eq!(result.effective, Some(ts));
}

#[test]
fn tf_long_format_entry_skipped() {
    // flags bit 7 set = long (17-byte) format — we do not parse it, return None
    let su = tf_entry(0x81, &[[0u8; 7]]); // bit 7 (LONG) + bit 0 (CREATION)
    assert!(rock_ridge::timestamps(&su).is_none());
}

// ── SL (symbolic link) ────────────────────────────────────────────────────────

#[test]
fn sl_no_entry_returns_none() {
    assert!(rock_ridge::symlink_target(b"NM\x06\x01\x00abc").is_none());
}

#[test]
fn sl_root_only() {
    // ROOT component with no identifier → "/"
    let su = sl_entry(0, &[sl_comp(0x08, b"")]);
    assert_eq!(rock_ridge::symlink_target(&su), Some("/".to_string()));
}

#[test]
fn sl_absolute_path() {
    // /etc/passwd
    let su = sl_entry(
        0,
        &[
            sl_comp(0x08, b""), // ROOT → "/"
            sl_comp(0x00, b"etc"),
            sl_comp(0x00, b"passwd"),
        ],
    );
    assert_eq!(
        rock_ridge::symlink_target(&su),
        Some("/etc/passwd".to_string())
    );
}

#[test]
fn sl_relative_path() {
    // lib/libc.so
    let su = sl_entry(0, &[sl_comp(0x00, b"lib"), sl_comp(0x00, b"libc.so")]);
    assert_eq!(
        rock_ridge::symlink_target(&su),
        Some("lib/libc.so".to_string())
    );
}

#[test]
fn sl_parent_relative() {
    // ../sibling
    let su = sl_entry(0, &[sl_comp(0x04, b""), sl_comp(0x00, b"sibling")]);
    assert_eq!(
        rock_ridge::symlink_target(&su),
        Some("../sibling".to_string())
    );
}

#[test]
fn sl_current_dir() {
    // ./foo
    let su = sl_entry(0, &[sl_comp(0x02, b""), sl_comp(0x00, b"foo")]);
    assert_eq!(rock_ridge::symlink_target(&su), Some("./foo".to_string()));
}

#[test]
fn sl_single_component() {
    // plain filename
    let su = sl_entry(0, &[sl_comp(0x00, b"target.txt")]);
    assert_eq!(
        rock_ridge::symlink_target(&su),
        Some("target.txt".to_string())
    );
}

// ── CL (child link) ───────────────────────────────────────────────────────────

#[test]
fn cl_returns_child_lba() {
    let su = loc_entry(b"CL", 0x0042_0000);
    assert_eq!(rock_ridge::child_link(&su), Some(0x0042_0000));
}

#[test]
fn cl_no_entry_returns_none() {
    assert!(rock_ridge::child_link(b"NM\x06\x01\x00abc").is_none());
}

// ── PL (parent link) ─────────────────────────────────────────────────────────

#[test]
fn pl_returns_parent_lba() {
    let su = loc_entry(b"PL", 0xABCD);
    assert_eq!(rock_ridge::parent_link(&su), Some(0xABCD));
}

#[test]
fn pl_no_entry_returns_none() {
    assert!(rock_ridge::parent_link(b"NM\x06\x01\x00abc").is_none());
}

// ── RE (relocated entry) ─────────────────────────────────────────────────────

#[test]
fn re_marker_detected() {
    assert!(rock_ridge::is_relocated(b"RE\x04\x01"));
}

#[test]
fn re_not_present() {
    assert!(!rock_ridge::is_relocated(b"NM\x06\x01\x00abc"));
}

#[test]
fn re_after_other_entries() {
    // NM entry: sig(2)+len(1)+ver(1)+flags(1)+name(3) = 8 bytes total, so len=8.
    let mut su = b"NM\x08\x01\x00abc".to_vec();
    su.extend_from_slice(b"RE\x04\x01");
    assert!(rock_ridge::is_relocated(&su));
}
