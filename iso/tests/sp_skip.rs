#![allow(clippy::unwrap_used, clippy::expect_used)]

// SP System Use field skip (SUSP IEEE P1282 §5.3).
//
// The `SP` entry's LEN_SKP byte tells parsers how many bytes to skip at the
// beginning of the System Use Area for each directory record before SUSP
// entries begin. Both the Linux kernel (`s_rock_offset`) and illumos
// (`hsfs_rrip.h`) store and apply this value. We must too.
//
// When LEN_SKP > 0 and the pre-SUSP padding is zero-filled, every SUSP
// scanner breaks immediately at `len=0 < 3`, silently discarding all SUSP
// data for that record.

use iso9660_forensic::{rock_ridge, IsoReader};
use std::io::Cursor;

const S: usize = 2048;

// ── Unit tests for rock_ridge::sp_skip() ─────────────────────────────────────

#[test]
fn sp_skip_extracts_value_from_sp_entry() {
    // SP entry: sig(2) + len(1) + ver(1) + magic(2) + skip(1) = 7 bytes total.
    // skip byte at offset 6 of the entry (offset 4 past the two signature bytes).
    let su = [b'S', b'P', 7, 1, 0xBE, 0xEF, 4];
    assert_eq!(rock_ridge::sp_skip(&su), 4);
}

#[test]
fn sp_skip_returns_zero_when_no_sp_entry() {
    assert_eq!(rock_ridge::sp_skip(&[]), 0);
    assert_eq!(rock_ridge::sp_skip(b"NM\x06\x01\x00hello"), 0);
}

#[test]
fn sp_skip_returns_zero_when_magic_wrong() {
    // SP entry with wrong magic bytes — should be ignored.
    let su = [b'S', b'P', 7, 1, 0xDE, 0xAD, 9];
    assert_eq!(rock_ridge::sp_skip(&su), 0);
}

#[test]
fn sp_skip_reads_from_entry_embedded_in_longer_buffer() {
    // SP entry preceded by unrelated bytes (e.g., another SUSP entry).
    let mut su = Vec::new();
    // Fake PX entry (just to advance the scanner): 4 bytes
    su.extend_from_slice(&[b'P', b'X', 4, 1]);
    // SP entry with skip=2
    su.extend_from_slice(&[b'S', b'P', 7, 1, 0xBE, 0xEF, 2]);
    assert_eq!(rock_ridge::sp_skip(&su), 2);
}

// ── Integration test: sp_skip applied when opening an ISO ────────────────────

/// Build a minimal ISO where:
/// - Root "." entry has an SP entry with LEN_SKP=4.
/// - A file entry "FILE" has 4 zero bytes before its NM("hello") SUSP entry.
///
/// Without the skip fix, `alternate_name()` on the raw system_use breaks at
/// the first zero byte (len=0 < 3) and returns None.
/// With the fix, the reader trims 4 bytes and NM("hello") is parsed correctly.
fn make_sp_skip_iso() -> Vec<u8> {
    // Sectors: 0-15 unused, 16=PVD, 17=VDT, 18=root-dir, 19=file-data
    let mut img = vec![0u8; 20 * S];

    // ── PVD at sector 16 ──────────────────────────────────────────────────
    {
        let p = &mut img[16 * S..17 * S];
        p[0] = 0x01;
        p[1..6].copy_from_slice(b"CD001");
        p[6] = 0x01;
        // volume_space_size (both-endian 32-bit at 80/84)
        p[80..84].copy_from_slice(&20u32.to_le_bytes());
        p[84..88].copy_from_slice(&20u32.to_be_bytes());
        // logical_block_size (both-endian 16-bit at 128/130)
        p[128..130].copy_from_slice(&2048u16.to_le_bytes());
        p[130..132].copy_from_slice(&2048u16.to_be_bytes());
        // path_table_size (both-endian 32-bit at 132/136)
        p[132..136].copy_from_slice(&10u32.to_le_bytes());
        // L-path table LBA
        p[140..144].copy_from_slice(&1u32.to_le_bytes());
        p[148..152].copy_from_slice(&1u32.to_be_bytes());
        // Root dir record embedded in PVD at offset 156: len=34, lba=18, size=2048
        p[156] = 34;
        p[158..162].copy_from_slice(&18u32.to_le_bytes());
        p[162..166].copy_from_slice(&18u32.to_be_bytes());
        p[166..170].copy_from_slice(&2048u32.to_le_bytes());
        p[170..174].copy_from_slice(&2048u32.to_be_bytes());
        p[181] = 0x02;
        p[188] = 1;
    }

    // ── VD Terminator at sector 17 ────────────────────────────────────────
    {
        let t = &mut img[17 * S..18 * S];
        t[0] = 0xFF;
        t[1..6].copy_from_slice(b"CD001");
        t[6] = 0x01;
    }

    // ── Root dir sector 18 ────────────────────────────────────────────────
    // Layout (byte offsets within sector 18):
    //
    //   0: "." (dot) entry  — record_len=42
    //      [0]   = 42               (record_len)
    //      [2..6]= lba=18 LE        (self)
    //      [10..14]=size=2048 LE
    //      [14..18]=size=2048 BE
    //      [25]  = 0x02             (directory flag)
    //      [32]  = 1                (name_len, dot=\x00)
    //      [33]  = 0x00             (dot name byte)
    //      — System Use starts at 34 (name_len=1 is odd → no padding byte) —
    //      [34..41] = SP entry: b"SP" + len(7) + ver(1) + 0xBE + 0xEF + skip(4)
    //      [41]  = 0x00             (record-length padding to reach 42)
    //
    //  42: ".." (dotdot) entry — record_len=34
    //
    //  76: "FILE" file entry — record_len=52
    //      name_len=4 (even → +1 pad → su_start=38)
    //      [38..42] = 4 zero bytes  (SP skip region)
    //      [42..52] = NM("hello") entry (10 bytes)

    let d = &mut img[18 * S..19 * S];

    // "." dot entry (record_len=42)
    d[0] = 42;
    d[2..6].copy_from_slice(&18u32.to_le_bytes()); // lba LE
    d[6..10].copy_from_slice(&18u32.to_be_bytes()); // lba BE
    d[10..14].copy_from_slice(&2048u32.to_le_bytes()); // size LE
    d[14..18].copy_from_slice(&2048u32.to_be_bytes()); // size BE
    d[25] = 0x02; // directory flag
    d[32] = 1; // name_len=1
    d[33] = 0x00; // dot
                  // SP entry at system_use offset 0 (su_start=34 within record, so d[34..41])
    d[34] = b'S';
    d[35] = b'P';
    d[36] = 7;
    d[37] = 1;
    d[38] = 0xBE;
    d[39] = 0xEF;
    d[40] = 4; // skip=4
    d[41] = 0x00; // padding to reach record_len=42

    // ".." dotdot entry at offset 42 (record_len=34)
    d[42] = 34;
    d[44..48].copy_from_slice(&18u32.to_le_bytes());
    d[48..52].copy_from_slice(&18u32.to_be_bytes());
    d[52..56].copy_from_slice(&2048u32.to_le_bytes());
    d[56..60].copy_from_slice(&2048u32.to_be_bytes());
    d[67] = 0x02;
    d[74] = 1;
    d[75] = 0x01; // dotdot

    // "FILE" file entry at offset 76 (record_len=52)
    //   name_len=4 ("FILE"), su_start = 33+4+1 = 38 (even name_len → +1 pad)
    //   system_use: [0,0,0,0] (4-byte SP-skip padding) + NM("hello") (10 bytes)
    d[76] = 52; // record_len=52
    d[78..82].copy_from_slice(&19u32.to_le_bytes()); // lba=19
    d[82..86].copy_from_slice(&19u32.to_be_bytes());
    d[86..90].copy_from_slice(&5u32.to_le_bytes()); // size=5
    d[90..94].copy_from_slice(&5u32.to_be_bytes());
    d[101] = 0x00; // flags=0 (regular file)
    d[108] = 4; // name_len=4
    d[109..113].copy_from_slice(b"FILE");
    // d[113] = 0x00  (padding byte for even name_len — already zeroed)
    // su_start = 76+38 = 114 within sector, which is d[114..128]
    // [114..118] = 4 zero bytes (SP-skip padding region)
    d[114] = 0x00;
    d[115] = 0x00;
    d[116] = 0x00;
    d[117] = 0x00;
    // [118..128] = NM entry: sig(2)+len(1)+ver(1)+flags(1)+"hello"(5) = 10 bytes
    d[118] = b'N';
    d[119] = b'M';
    d[120] = 10;
    d[121] = 1;
    d[122] = 0;
    d[123] = b'h';
    d[124] = b'e';
    d[125] = b'l';
    d[126] = b'l';
    d[127] = b'o';

    // ── File data sector 19: 5 bytes ──────────────────────────────────────
    img[19 * S..19 * S + 5].copy_from_slice(b"hello");

    img
}

#[test]
fn sp_skip_applied_trimmed_system_use_yields_nm_name() {
    let img = make_sp_skip_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();

    // Rock Ridge should be detected because the "." entry has a valid SP entry.
    assert!(reader.has_rock_ridge(), "SP entry must trigger has_rock_ridge");

    let entries = reader.read_root_dir().unwrap();

    // Find the "FILE" entry (the non-dot/dotdot entry).
    let file_entry = entries
        .iter()
        .find(|e| !e.name_bytes.is_empty() && e.name_bytes[0] != 0x00 && e.name_bytes[0] != 0x01)
        .expect("FILE entry not found in root dir");

    // After SP skip is applied, alternate_name must return "hello" from the NM entry.
    let name = rock_ridge::alternate_name(&file_entry.system_use);
    assert_eq!(
        name.as_deref(),
        Some("hello"),
        "NM alternate name must be 'hello' after SP skip applied; \
         system_use (hex): {:02x?}",
        &file_entry.system_use,
    );
}

#[test]
fn sp_skip_zero_iso_unaffected() {
    // An ISO without an SP entry (no Rock Ridge) must still parse correctly
    // and sp_skip must default to 0 (no trimming).
    use std::io::Cursor;
    let mut img = vec![0u8; 20 * S];
    // PVD
    let p = &mut img[16 * S..17 * S];
    p[0] = 0x01;
    p[1..6].copy_from_slice(b"CD001");
    p[6] = 0x01;
    p[80..84].copy_from_slice(&20u32.to_le_bytes());
    p[84..88].copy_from_slice(&20u32.to_be_bytes());
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
    // VDT
    let t = &mut img[17 * S..18 * S];
    t[0] = 0xFF;
    t[1..6].copy_from_slice(b"CD001");
    t[6] = 0x01;
    // Root dir: dot + dotdot only
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

    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    assert!(!reader.has_rock_ridge(), "no SP entry → no Rock Ridge");
    let entries = reader.read_root_dir().unwrap();
    // parse_dir_records skips dot/dotdot — empty root dir has no file entries
    assert_eq!(entries.len(), 0);
}
