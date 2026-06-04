// OffsetReader windowing adapter tests.
//
// Presents a bounded [base, base+len) window of an inner Read+Seek as if it
// were a standalone stream starting at 0 — used to open a container's data
// track (e.g. an NRG track at a byte offset) without copying it out.

use iso9660_forensic::offset::OffsetReader;
use std::io::{Cursor, Read, Seek, SeekFrom};

fn window() -> OffsetReader<Cursor<Vec<u8>>> {
    // Inner: 0..10; window = bytes [3, 7) => "3456".
    OffsetReader::new(Cursor::new(b"0123456789".to_vec()), 3, 4).unwrap()
}

#[test]
fn reads_only_the_window() {
    let mut r = window();
    let mut buf = Vec::new();
    r.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"3456");
}

#[test]
fn read_stops_at_window_end_not_inner_end() {
    let mut r = window();
    let mut buf = [0u8; 16];
    let n = r.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"3456");
    // A second read is EOF even though the inner stream has more bytes.
    assert_eq!(r.read(&mut buf).unwrap(), 0);
}

#[test]
fn seek_start_is_relative_to_window() {
    let mut r = window();
    r.seek(SeekFrom::Start(1)).unwrap();
    let mut buf = Vec::new();
    r.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"456");
}

#[test]
fn seek_end_is_relative_to_window_len() {
    let mut r = window();
    let pos = r.seek(SeekFrom::End(-1)).unwrap();
    assert_eq!(pos, 3);
    let mut one = [0u8; 1];
    r.read_exact(&mut one).unwrap();
    assert_eq!(&one, b"6");
}

#[test]
fn seek_current_and_position() {
    let mut r = window();
    r.seek(SeekFrom::Start(2)).unwrap();
    let pos = r.seek(SeekFrom::Current(1)).unwrap();
    assert_eq!(pos, 3);
    let mut one = [0u8; 1];
    r.read_exact(&mut one).unwrap();
    assert_eq!(&one, b"6");
}
