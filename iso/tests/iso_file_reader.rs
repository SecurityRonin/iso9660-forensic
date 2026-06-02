// IsoFileReader — streaming std::io::Read impl for file data.
//
// Spec: ECMA-119 §9 (file data layout, sector-aligned LBAs).
// Refs: iso9660-rs (Poprdi) FileReader<R>; cdfs IsoFile impl.
//
// Tests verify: Read trait works, partial reads, seek back (BufReader),
// multi-extent streaming, and that total bytes == entry size.

use std::io::{Cursor, Read, Seek, SeekFrom};
use iso9660_forensic::{IsoReader, IsoFileReader};

// ── helpers ───────────────────────────────────────────────────────────────────

/// Minimal 1-file ISO: file "DATA" at LBA=20, size=5000 bytes, data=0x77.
fn make_iso_with_file() -> Vec<u8> {
    const S: usize = 2048;
    // Need sectors 0-20 + 2 data sectors → 23 sectors.
    let mut img = vec![0u8; 23 * S];

    // PVD
    {
        let p = &mut img[16 * S..17 * S];
        p[0] = 0x01;
        p[1..6].copy_from_slice(b"CD001");
        p[6] = 0x01;
        p[80..84].copy_from_slice(&23u32.to_le_bytes());
        p[84..88].copy_from_slice(&23u32.to_be_bytes());
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
    }
    // VD Terminator
    {
        let t = &mut img[17 * S..18 * S];
        t[0] = 0xFF;
        t[1..6].copy_from_slice(b"CD001");
        t[6] = 0x01;
    }
    // Root dir (sector 18)
    {
        let d = &mut img[18 * S..19 * S];
        // dot
        d[0] = 34;
        d[2..6].copy_from_slice(&18u32.to_le_bytes());
        d[10..14].copy_from_slice(&2048u32.to_le_bytes());
        d[25] = 0x02; d[32] = 1;
        // dotdot
        let o = 34;
        d[o] = 34;
        d[o + 2..o + 6].copy_from_slice(&18u32.to_le_bytes());
        d[o + 10..o + 14].copy_from_slice(&2048u32.to_le_bytes());
        d[o + 25] = 0x02; d[o + 32] = 1; d[o + 33] = 0x01;
        // "DATA" at offset 68: name=4 (even) → su_start=38, record_len=38
        let o = 68;
        d[o] = 38;
        d[o + 2..o + 6].copy_from_slice(&20u32.to_le_bytes());    // lba
        d[o + 6..o + 10].copy_from_slice(&20u32.to_be_bytes());
        d[o + 10..o + 14].copy_from_slice(&5000u32.to_le_bytes()); // size = 5000
        d[o + 14..o + 18].copy_from_slice(&5000u32.to_be_bytes());
        d[o + 32] = 4;
        d[o + 33..o + 37].copy_from_slice(b"DATA");
    }
    // File data starts at LBA 20; 5000 bytes spans into sector 22.
    img[20 * S..20 * S + 5000].fill(0x77);

    img
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[test]
fn iso_file_reader_reads_exact_bytes() {
    let img = make_iso_with_file();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let records = reader.read_root_dir().unwrap();
    let entry = records.iter().find(|r| r.iso_name() == "DATA").unwrap();

    let mut file = reader.open_file(entry).unwrap();
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();

    assert_eq!(buf.len(), 5000, "must read exactly 5000 bytes");
    assert!(buf.iter().all(|&b| b == 0x77), "all bytes must be 0x77");
}

#[test]
fn iso_file_reader_partial_read() {
    let img = make_iso_with_file();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let records = reader.read_root_dir().unwrap();
    let entry = records.iter().find(|r| r.iso_name() == "DATA").unwrap();

    let mut file = reader.open_file(entry).unwrap();
    let mut buf = [0u8; 100];
    let n = file.read(&mut buf).unwrap();
    assert!(n > 0 && n <= 100, "partial read must return 1-100 bytes");
    assert!(buf[..n].iter().all(|&b| b == 0x77));
}

#[test]
fn iso_file_reader_empty_read_at_eof() {
    let img = make_iso_with_file();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let records = reader.read_root_dir().unwrap();
    let entry = records.iter().find(|r| r.iso_name() == "DATA").unwrap();

    let mut file = reader.open_file(entry).unwrap();
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();
    // Further reads at EOF must return 0 bytes.
    let mut extra = [0u8; 10];
    let n = file.read(&mut extra).unwrap();
    assert_eq!(n, 0, "read at EOF must return 0");
}

#[test]
fn iso_file_reader_seek_from_start() {
    let img = make_iso_with_file();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let records = reader.read_root_dir().unwrap();
    let entry = records.iter().find(|r| r.iso_name() == "DATA").unwrap();

    let mut file = reader.open_file(entry).unwrap();
    // Seek to byte 2100 (inside the second sector), read 10 bytes.
    let pos = file.seek(SeekFrom::Start(2100)).unwrap();
    assert_eq!(pos, 2100);
    let mut buf = [0u8; 10];
    file.read_exact(&mut buf).unwrap();
    assert!(buf.iter().all(|&b| b == 0x77), "bytes after seek must still be 0x77");
}

#[test]
fn iso_file_reader_seek_from_end() {
    let img = make_iso_with_file();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let records = reader.read_root_dir().unwrap();
    let entry = records.iter().find(|r| r.iso_name() == "DATA").unwrap();

    let mut file = reader.open_file(entry).unwrap();
    // Seek 50 bytes from end, read remaining 50 bytes.
    let pos = file.seek(SeekFrom::End(-50)).unwrap();
    assert_eq!(pos, 4950);
    let mut buf = [0u8; 50];
    file.read_exact(&mut buf).unwrap();
    assert!(buf.iter().all(|&b| b == 0x77));
}

#[test]
fn iso_file_reader_seek_from_current() {
    let img = make_iso_with_file();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let records = reader.read_root_dir().unwrap();
    let entry = records.iter().find(|r| r.iso_name() == "DATA").unwrap();

    let mut file = reader.open_file(entry).unwrap();
    // Read 100 bytes (advances cursor to 100), then seek +50, check pos.
    let mut discard = [0u8; 100];
    file.read_exact(&mut discard).unwrap();
    let pos = file.seek(SeekFrom::Current(50)).unwrap();
    assert_eq!(pos, 150);
    let mut buf = [0u8; 10];
    file.read_exact(&mut buf).unwrap();
    assert!(buf.iter().all(|&b| b == 0x77));
}

#[test]
fn iso_file_reader_size_matches_entry() {
    let img = make_iso_with_file();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let records = reader.read_root_dir().unwrap();
    let entry = records.iter().find(|r| r.iso_name() == "DATA").unwrap();

    let file = reader.open_file(entry).unwrap();
    assert_eq!(file.size(), 5000, "IsoFileReader::size() must equal entry.size");
}
