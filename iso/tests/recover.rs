#![allow(clippy::unwrap_used, clippy::expect_used)]

// Lost-file recovery: surface files inside orphaned directory extents that the
// path table references but the active directory tree cannot reach (IsoBuster's
// "find missing files and folders").

use iso9660_forensic::IsoReader;
use std::io::Cursor;

const S: usize = 2048;

/// Write a directory record at `img[off..]`.
fn dir_rec(img: &mut [u8], off: usize, lba: u32, size: u32, is_dir: bool, name: &[u8]) -> usize {
    let nl = name.len();
    let rec_len = 33 + nl + usize::from(nl % 2 == 0); // pad to even
    let d = &mut img[off..off + rec_len];
    d[0] = rec_len as u8;
    d[2..6].copy_from_slice(&lba.to_le_bytes());
    d[6..10].copy_from_slice(&lba.to_be_bytes());
    d[10..14].copy_from_slice(&size.to_le_bytes());
    d[14..18].copy_from_slice(&size.to_be_bytes());
    d[25] = if is_dir { 0x02 } else { 0x00 };
    d[32] = nl as u8;
    d[33..33 + nl].copy_from_slice(name);
    rec_len
}

/// Build an ISO whose path table references a phantom directory (LBA 20) not
/// linked from the root tree; that directory holds GHOST.TXT.
fn make_iso_with_phantom_dir() -> Vec<u8> {
    let mut img = vec![0u8; 22 * S];
    // PVD at sector 16.
    let p = &mut img[16 * S..17 * S];
    p[0] = 0x01;
    p[1..6].copy_from_slice(b"CD001");
    p[6] = 0x01;
    p[80..84].copy_from_slice(&22u32.to_le_bytes());
    p[84..88].copy_from_slice(&22u32.to_be_bytes());
    p[128..130].copy_from_slice(&2048u16.to_le_bytes());
    p[130..132].copy_from_slice(&2048u16.to_be_bytes());
    p[132..136].copy_from_slice(&22u32.to_le_bytes()); // path_table_size
    p[136..140].copy_from_slice(&22u32.to_be_bytes());
    p[140..144].copy_from_slice(&1u32.to_le_bytes()); // l_path_table_lba = 1
    p[156] = 34; // root dir record length
    p[158..162].copy_from_slice(&18u32.to_le_bytes()); // root lba 18
    p[162..166].copy_from_slice(&18u32.to_be_bytes());
    p[166..170].copy_from_slice(&2048u32.to_le_bytes()); // root size
    p[170..174].copy_from_slice(&2048u32.to_be_bytes());
    p[181] = 0x02;
    p[188] = 1;
    // VD terminator at sector 17.
    let t = &mut img[17 * S..18 * S];
    t[0] = 0xFF;
    t[1..6].copy_from_slice(b"CD001");
    t[6] = 0x01;
    // L-path table at sector 1: root (lba 18) + phantom "LOST" (lba 20).
    let pt = &mut img[S..2 * S];
    // entry 0: root — dir_id_len 1, ext 0, lba 18, parent 1, id 0x00, pad.
    pt[0] = 1;
    pt[2..6].copy_from_slice(&18u32.to_le_bytes());
    pt[6..8].copy_from_slice(&1u16.to_le_bytes());
    pt[8] = 0x00;
    // entry 1 @ offset 10: phantom — dir_id_len 4, lba 20, parent 1, id "LOST".
    pt[10] = 4;
    pt[12..16].copy_from_slice(&20u32.to_le_bytes());
    pt[16..18].copy_from_slice(&1u16.to_le_bytes());
    pt[18..22].copy_from_slice(b"LOST");
    // Root directory (sector 18): only "." and ".." (no link to sector 20).
    let mut off = 18 * S;
    off += dir_rec(&mut img, off, 18, 2048, true, &[0x00]);
    dir_rec(&mut img, off, 18, 2048, true, &[0x01]);
    // Phantom directory (sector 20): ".", "..", and GHOST.TXT (lba 21, 5 bytes).
    let mut off = 20 * S;
    off += dir_rec(&mut img, off, 20, 2048, true, &[0x00]);
    off += dir_rec(&mut img, off, 18, 2048, true, &[0x01]);
    dir_rec(&mut img, off, 21, 5, false, b"GHOST.TXT");
    // File data at sector 21.
    img[21 * S..21 * S + 5].copy_from_slice(b"ghost");
    img
}

#[test]
fn recovers_file_from_phantom_directory() {
    let img = make_iso_with_phantom_dir();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let lost = reader.recover_lost_files().unwrap();
    assert_eq!(lost.len(), 1, "expected one lost file: {lost:?}");
    assert_eq!(lost[0].name, "GHOST.TXT");
    assert_eq!(lost[0].lba, 21);
    assert_eq!(lost[0].size, 5);
    assert_eq!(lost[0].parent_lba, 20);
}

#[test]
fn no_lost_files_in_clean_iso() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/rock_ridge.iso");
    let f = std::fs::File::open(path).unwrap();
    let mut reader = IsoReader::open(f).unwrap();
    assert!(reader.recover_lost_files().unwrap().is_empty());
}
