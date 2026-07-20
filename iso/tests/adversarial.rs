#![allow(clippy::unwrap_used, clippy::expect_used)]

// Adversarial and malformed-input tests — defence against fuzzing and
// malicious/corrupted ISO images.
//
// Spec: ECMA-119 §6 (Volume Space), §8.4 (PVD), §9 (Directory Records).
// Refs: libfuzzer corpus from real-world fuzz campaigns;
//       OSS-Fuzz issue tracker for iso/CD parsing bugs.
//
// Invariants every parser MUST uphold regardless of input:
//   (a) never panic — return Err or Option::None;
//   (b) never allocate more than MAX_DIR_SIZE bytes for a directory;
//   (c) never recurse deeper than MAX_WALK_DEPTH;
//   (d) never produce a name longer than MAX_NM_LEN bytes from NM entries.

use iso9660_forensic::{rock_ridge, IsoError, IsoReader};
use std::io::Cursor;

// ── minimal ISO builder ───────────────────────────────────────────────────────

const S: usize = 2048;

/// Fill the mandatory fixed fields of a PVD sector in-place.
fn write_pvd(img: &mut [u8], pvd_sec: usize, root_lba: u32, root_size: u32, total_secs: u32) {
    let p = &mut img[pvd_sec * S..(pvd_sec + 1) * S];
    p[0] = 0x01;
    p[1..6].copy_from_slice(b"CD001");
    p[6] = 0x01;
    p[80..84].copy_from_slice(&total_secs.to_le_bytes());
    p[84..88].copy_from_slice(&total_secs.to_be_bytes());
    p[128..130].copy_from_slice(&2048u16.to_le_bytes());
    p[130..132].copy_from_slice(&2048u16.to_be_bytes());
    p[132..136].copy_from_slice(&10u32.to_le_bytes());
    p[140..144].copy_from_slice(&1u32.to_le_bytes());
    p[148..152].copy_from_slice(&1u32.to_be_bytes());
    // Root dir record at offset 156
    p[156] = 34;
    p[158..162].copy_from_slice(&root_lba.to_le_bytes());
    p[162..166].copy_from_slice(&root_lba.to_be_bytes());
    p[166..170].copy_from_slice(&root_size.to_le_bytes());
    p[170..174].copy_from_slice(&root_size.to_be_bytes());
    p[181] = 0x02;
    p[188] = 1;
}

fn write_vdt(img: &mut [u8], sec: usize) {
    let t = &mut img[sec * S..(sec + 1) * S];
    t[0] = 0xFF;
    t[1..6].copy_from_slice(b"CD001");
    t[6] = 0x01;
}

/// Write a minimal dot+dotdot directory sector.
fn write_empty_dir(img: &mut [u8], sec: usize, self_lba: u32, parent_lba: u32) {
    let d = &mut img[sec * S..(sec + 1) * S];
    d[0] = 34;
    d[2..6].copy_from_slice(&self_lba.to_le_bytes());
    d[10..14].copy_from_slice(&2048u32.to_le_bytes());
    d[25] = 0x02;
    d[32] = 1;
    let o = 34;
    d[o] = 34;
    d[o + 2..o + 6].copy_from_slice(&parent_lba.to_le_bytes());
    d[o + 10..o + 14].copy_from_slice(&2048u32.to_le_bytes());
    d[o + 25] = 0x02;
    d[o + 32] = 1;
    d[o + 33] = 0x01;
}

/// Write a directory entry for a subdirectory into sector `dir_sec` at byte offset `off`.
fn write_dir_entry(
    img: &mut [u8],
    dir_sec: usize,
    off: usize,
    name: &[u8],
    lba: u32,
    size: u32,
    flags: u8,
) {
    // record_len = 33 + name.len() + pad (to even)
    let name_len = name.len();
    let rec_len = 33 + name_len + (name_len % 2);
    let d = &mut img[dir_sec * S + off..dir_sec * S + off + rec_len];
    d[0] = rec_len as u8;
    d[2..6].copy_from_slice(&lba.to_le_bytes());
    d[6..10].copy_from_slice(&lba.to_be_bytes());
    d[10..14].copy_from_slice(&size.to_le_bytes());
    d[14..18].copy_from_slice(&size.to_be_bytes());
    d[25] = flags;
    d[32] = name_len as u8;
    d[33..33 + name_len].copy_from_slice(name);
}

// ── Category 1: basic input rejection ────────────────────────────────────────

#[test]
fn empty_image_is_error() {
    let result = IsoReader::open(Cursor::new(Vec::<u8>::new()));
    assert!(result.is_err(), "empty image must be Err");
}

#[test]
fn all_zero_image_is_error() {
    let data = vec![0u8; 32 * S];
    let result = IsoReader::open(Cursor::new(data));
    assert!(result.is_err(), "all-zero image must be Err");
}

#[test]
fn truncated_at_pvd_is_error() {
    // Only 10 bytes — not even a full sector.
    let data = vec![0xABu8; 10];
    let result = IsoReader::open(Cursor::new(data));
    assert!(result.is_err(), "10-byte image must be Err");
}

#[test]
fn pvd_wrong_signature_is_error() {
    let mut img = vec![0u8; 18 * S];
    // Put "BADCD" instead of "CD001"
    img[16 * S] = 0x01;
    img[16 * S + 1..16 * S + 6].copy_from_slice(b"BADCD");
    let result = IsoReader::open(Cursor::new(img));
    assert!(result.is_err(), "wrong PVD signature must be Err");
}

// ── Category 2: resource-limit bounds ────────────────────────────────────────
// RED: IsoError::ResourceLimit does not yet exist → compile error.

#[test]
fn oversized_dir_allocation_is_resource_limit() {
    // Build an ISO where root_dir_size = u32::MAX (4 GB).
    // Without the size cap, read_dir would attempt a 4 GB allocation.
    let mut img = vec![0u8; 20 * S];
    write_pvd(&mut img, 16, 18, u32::MAX, 20);
    write_vdt(&mut img, 17);
    // Sector 18 is the "root dir" — parser must reject before reading it.

    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let result = reader.read_root_dir();
    assert!(
        matches!(result, Err(IsoError::ResourceLimit(_))),
        "4 GB dir size must return ResourceLimit, got {result:?}"
    );
}

#[test]
fn walk_cycle_terminates_gracefully() {
    // Directory at sector 19 contains a "LOOP" entry pointing back to itself.
    // Without cycle-safety, walk() would recurse infinitely → stack overflow.
    let mut img = vec![0u8; 20 * S];
    write_pvd(&mut img, 16, 18, 2048, 20);
    write_vdt(&mut img, 17);
    // Root dir: dot + dotdot + "LOOP" entry pointing to sector 19
    write_empty_dir(&mut img, 18, 18, 18);
    write_dir_entry(&mut img, 18, 68, b"LOOP", 19, 2048, 0x02); // dir flag
                                                                // Sector 19: self-referential — "LOOP" points back to sector 19
    write_empty_dir(&mut img, 19, 19, 18);
    write_dir_entry(&mut img, 19, 68, b"LOOP", 19, 2048, 0x02);

    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    // Cycle-safe: walk terminates (does not recurse to the depth limit or
    // stack-overflow) and lists the cyclic entry without re-descending it.
    let entries = reader.walk().expect("cyclic walk must terminate gracefully, not error");
    assert!(
        entries.iter().any(|e| e.path.contains("LOOP")),
        "cyclic entry must be listed: {entries:?}"
    );
}

// ── Category 3: SUSP / Rock Ridge malformed entries ──────────────────────────

#[test]
fn susp_len_zero_terminates() {
    // A SUSP entry with len=0 must not infinite-loop.
    let su = b"NM\x00\x01\x00hello";
    // alternate_name must return None (or whatever is valid after 0-len entry),
    // importantly it must terminate.
    let _ = rock_ridge::alternate_name(su);
}

#[test]
fn susp_truncated_entry_is_safe() {
    // Entry claims len=20 but only 6 bytes remain.
    let su = b"NM\x14\x01\x00he"; // len=20 but total only 7 bytes
    let _ = rock_ridge::alternate_name(su);
    let _ = rock_ridge::posix_attrs(su);
    let _ = rock_ridge::timestamps(su);
    let _ = rock_ridge::continuation(su);
}

#[test]
fn susp_nm_concatenation_length_capped() {
    // Build many NM entries with CONTINUE bit set (bit 0 of flags = 1).
    // Total name content = 200 entries × 200 bytes each = 40,000 bytes.
    // Must not produce a name string exceeding MAX_NM_LEN.
    let chunk = b"A".repeat(200);
    let mut su = Vec::new();
    for _ in 0..200 {
        // NM: sig(2) + len(1) + ver(1) + flags(1=CONTINUE) + name...
        let entry_len = (5 + chunk.len()) as u8;
        su.push(b'N');
        su.push(b'M');
        su.push(entry_len);
        su.push(1);
        su.push(0x01); // CONTINUE bit
        su.extend_from_slice(&chunk);
    }
    // Add a final NM with CONTINUE=0 to close the chain
    su.extend_from_slice(b"NM\x06\x01\x00Z");

    let name = rock_ridge::alternate_name(&su);
    if let Some(n) = name {
        assert!(
            n.len() <= rock_ridge::MAX_NM_LEN,
            "NM name length {} exceeds MAX_NM_LEN {}",
            n.len(),
            rock_ridge::MAX_NM_LEN
        );
    }
}

#[test]
fn ce_continuation_depth_bounded() {
    // A CE entry whose continuation area contains another CE (chain length = 2).
    // Currently we only follow one level, but this must not loop.
    // Just verify the CE pointer is extracted correctly and following it doesn't panic.
    let mut su = Vec::new();
    // CE entry: sig + len + ver + lba(BE+LE 8 bytes) + offset(8) + len(8) = 28 bytes
    su.extend_from_slice(b"CE\x1c\x01");
    su.extend_from_slice(&999u32.to_le_bytes()); // lba LE
    su.extend_from_slice(&999u32.to_be_bytes()); // lba BE
    su.extend_from_slice(&0u32.to_le_bytes()); // offset LE
    su.extend_from_slice(&0u32.to_be_bytes()); // offset BE
    su.extend_from_slice(&100u32.to_le_bytes()); // len LE
    su.extend_from_slice(&100u32.to_be_bytes()); // len BE
    let ca = rock_ridge::continuation(&su);
    assert!(ca.is_some());
    assert_eq!(ca.unwrap().lba, 999);
}

// ── Category 4: directory record edge cases ───────────────────────────────────

#[test]
fn dir_record_name_len_overflow_is_error() {
    use iso9660_forensic::dir::DirRecord;
    // A dir record that claims name_len overruns the record boundary.
    let mut rec = vec![0u8; 40];
    rec[0] = 40; // record_len = 40
    rec[32] = 30; // name_len = 30, but 33+30 = 63 > 40 → overflow
    let result = DirRecord::parse(&rec, 0);
    assert!(result.is_err(), "name overrun must be Err");
}

#[test]
fn dir_record_len_too_small_is_error() {
    use iso9660_forensic::dir::DirRecord;
    // record_len = 5, minimum is 33.
    let rec = [5u8, 0, 0, 0, 0, 0, 0, 0];
    let result = DirRecord::parse(&rec, 0);
    assert!(result.is_err(), "record_len < 33 must be Err");
}

#[test]
fn dir_record_len_extends_past_buffer_is_error() {
    use iso9660_forensic::dir::DirRecord;
    // record_len claims 100 bytes but buffer only has 50.
    let mut rec = vec![0u8; 50];
    rec[0] = 100;
    let result = DirRecord::parse(&rec, 0);
    assert!(result.is_err(), "record overrunning buffer must be Err");
}
