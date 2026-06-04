// Rock Ridge CE (Continuation Area) following.
//
// Spec: IEEE P1282 §4.1.1 (CE), RRIP-IEEE-P1282-draft-v1.12 §4.1.1.
// Refs: cdfs (sr.ht/~az1/iso9660-rs) — ContinuationArea; mkisofs — RRIP_CE.
//
// Tests verify that IsoReader::read_dir() follows CE pointers and appends
// the continuation bytes to each record's system_use field, so that
// downstream parsers (alternate_name, posix_attrs, …) see the full RRIP data.

use iso9660_forensic::{rock_ridge, IsoReader};
use std::io::Cursor;

// ── in-memory ISO builder ─────────────────────────────────────────────────────

/// Build a minimal valid 2048-byte-sector ISO image (21 sectors) where:
///
/// - Sector 16: PVD  (root dir at LBA 18, size 2048)
/// - Sector 17: VD Terminator
/// - Sector 18: Root directory
///   - dot (.) with SP Rock Ridge indicator
///   - dotdot (..)
///   - file "FILE" whose system_use contains only a CE pointer → sector 20 offset 0
/// - Sector 20: CE continuation area — NM entry "longname" (13 bytes)
fn make_iso_with_ce() -> Vec<u8> {
    const SECTOR: usize = 2048;
    let mut img = vec![0u8; 21 * SECTOR];

    // ── Sector 16: PVD ───────────────────────────────────────────────────────
    {
        let pvd = &mut img[16 * SECTOR..17 * SECTOR];
        pvd[0] = 0x01;
        pvd[1..6].copy_from_slice(b"CD001");
        pvd[6] = 0x01;
        pvd[80..84].copy_from_slice(&21u32.to_le_bytes()); // volume_space_size LE
        pvd[84..88].copy_from_slice(&21u32.to_be_bytes()); // volume_space_size BE
        pvd[128..130].copy_from_slice(&2048u16.to_le_bytes()); // block_size LE
        pvd[130..132].copy_from_slice(&2048u16.to_be_bytes()); // block_size BE
        pvd[132..136].copy_from_slice(&10u32.to_le_bytes()); // path_table_size LE
        pvd[140..144].copy_from_slice(&1u32.to_le_bytes()); // l_path_table_lba LE
        pvd[148..152].copy_from_slice(&1u32.to_be_bytes()); // m_path_table_lba BE
                                                            // Root directory record embedded in PVD at offset 156 (ECMA-119 §8.4.18).
        pvd[156] = 34; // record_len
        pvd[158..162].copy_from_slice(&18u32.to_le_bytes()); // lba LE
        pvd[162..166].copy_from_slice(&18u32.to_be_bytes()); // lba BE
        pvd[166..170].copy_from_slice(&2048u32.to_le_bytes()); // size LE
        pvd[170..174].copy_from_slice(&2048u32.to_be_bytes()); // size BE
        pvd[181] = 0x02; // flags: directory
        pvd[188] = 1; // name_len
                      // pvd[189] = 0x00 = dot — already zero
    }

    // ── Sector 17: VD Terminator ─────────────────────────────────────────────
    {
        let t = &mut img[17 * SECTOR..18 * SECTOR];
        t[0] = 0xFF;
        t[1..6].copy_from_slice(b"CD001");
        t[6] = 0x01;
    }

    // ── Sector 18: Root directory ─────────────────────────────────────────────
    {
        let dir = &mut img[18 * SECTOR..19 * SECTOR];

        // Entry 1 — dot (.) at offset 0, record_len=42.
        // name_len=1 (odd) → su_start=34; SP entry (7 bytes) at [34..41].
        dir[0] = 42;
        dir[2..6].copy_from_slice(&18u32.to_le_bytes());
        dir[10..14].copy_from_slice(&2048u32.to_le_bytes());
        dir[25] = 0x02; // directory
        dir[32] = 1; // name_len
                     // dir[33] = 0x00 (dot) — zero
                     // SP entry: "SP" + len=7 + ver=1 + 0xBE + 0xEF + skip=0
        dir[34] = b'S';
        dir[35] = b'P';
        dir[36] = 7;
        dir[37] = 1;
        dir[38] = 0xBE;
        dir[39] = 0xEF;
        dir[40] = 0;
        // dir[41] = 0 (pad to even record_len=42) — zero

        // Entry 2 — dotdot (..) at offset 42, record_len=34.
        let o = 42;
        dir[o] = 34;
        dir[o + 2..o + 6].copy_from_slice(&18u32.to_le_bytes());
        dir[o + 10..o + 14].copy_from_slice(&2048u32.to_le_bytes());
        dir[o + 25] = 0x02;
        dir[o + 32] = 1;
        dir[o + 33] = 0x01; // dotdot

        // Entry 3 — file "FILE" at offset 76, record_len=66.
        // name_len=4 (even) → su_start=38; CE entry (28 bytes) at [38..66].
        let o = 76;
        dir[o] = 66;
        // lba=0, size=0 (no file data needed for this test)
        dir[o + 32] = 4;
        dir[o + 33..o + 37].copy_from_slice(b"FILE");
        // dir[o+37] = 0 (alignment pad for even name_len) — zero
        // CE entry at [o+38..o+66]: sig + len + ver + lba_both + offset_both + len_both
        let ce = &mut dir[o + 38..o + 66];
        ce[0] = b'C';
        ce[1] = b'E';
        ce[2] = 28;
        ce[3] = 1;
        ce[4..8].copy_from_slice(&20u32.to_le_bytes()); // lba LE = 20
        ce[8..12].copy_from_slice(&20u32.to_be_bytes()); // lba BE
                                                         // offset LE/BE = 0 — already zero
        ce[20..24].copy_from_slice(&13u32.to_le_bytes()); // len LE = 13
        ce[24..28].copy_from_slice(&13u32.to_be_bytes()); // len BE
    }

    // ── Sector 20: CE continuation area ──────────────────────────────────────
    // NM entry for "longname": sig(2) + len(1) + ver(1) + flags(1) + name(8) = 13 bytes.
    {
        let nm = &mut img[20 * SECTOR..20 * SECTOR + 13];
        nm[0] = b'N';
        nm[1] = b'M';
        nm[2] = 13;
        nm[3] = 1;
        nm[4] = 0;
        nm[5..13].copy_from_slice(b"longname");
    }

    img
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[test]
fn ce_pointer_present_in_raw_system_use() {
    let img = make_iso_with_ce();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let records = reader.read_root_dir().unwrap();
    let file = records.iter().find(|r| r.iso_name() == "FILE").expect("FILE entry must exist");

    let ce = rock_ridge::continuation(&file.system_use)
        .expect("CE pointer must be present in system_use");
    assert_eq!(ce.lba, 20, "CE lba");
    assert_eq!(ce.offset, 0, "CE offset");
    assert_eq!(ce.len, 13, "CE len");
}

#[test]
fn ce_followed_nm_name_resolved() {
    let img = make_iso_with_ce();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let records = reader.read_root_dir().unwrap();
    let file = records.iter().find(|r| r.iso_name() == "FILE").expect("FILE entry must exist");

    let name = rock_ridge::alternate_name(&file.system_use);
    assert_eq!(
        name.as_deref(),
        Some("longname"),
        "alternate_name must resolve NM entry from CE continuation area"
    );
}

#[test]
fn ce_system_use_contains_both_ce_and_nm_after_follow() {
    let img = make_iso_with_ce();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let records = reader.read_root_dir().unwrap();
    let file = records.iter().find(|r| r.iso_name() == "FILE").expect("FILE entry must exist");

    // CE entry must still be present (we append, not replace).
    assert!(
        rock_ridge::continuation(&file.system_use).is_some(),
        "CE entry must remain in system_use after following"
    );
    // And NM entry must now also be reachable.
    assert!(
        rock_ridge::alternate_name(&file.system_use).is_some(),
        "NM entry from continuation area must now be in system_use"
    );
}

#[test]
fn record_without_ce_has_no_nm() {
    // The dot entry (skipped by parse_dir_records) is the only record with SP.
    // The dotdot entry has no Rock Ridge data at all.
    // If we had a second plain file with no CE, its name would still not be overridden.
    // Here we just verify the FILE entry's iso_name() is "FILE".
    let img = make_iso_with_ce();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let records = reader.read_root_dir().unwrap();
    assert_eq!(records.len(), 1, "only FILE entry (dot/dotdot filtered out)");
    assert_eq!(records[0].iso_name(), "FILE");
}
