// DiscJuggler CDI detection tests.
//
// The CDI footer is well-defined (libmirage image-cdi): the last 4 bytes are
// the descriptor length (LE u32) and the 4 before that are the DiscJuggler
// version (0x80000004/5/6). The track-descriptor internals are undeciphered in
// the reference implementation, so this module does DETECTION only — it does
// not guess track layout.

use iso9660_forensic::cdi;
use std::io::Cursor;

/// Build a buffer ending in a valid CDI footer (version + descriptor length).
fn with_footer(body: usize, version: u32, length: u32) -> Vec<u8> {
    let mut v = vec![0u8; body];
    v.extend_from_slice(&version.to_le_bytes());
    v.extend_from_slice(&length.to_le_bytes());
    v
}

#[test]
fn detects_valid_cdi_footer() {
    let img = with_footer(2048, 0x8000_0006, 64);
    let info = cdi::detect(&mut Cursor::new(img)).expect("detect CDI");
    assert_eq!(info.version, 0x8000_0006);
    assert_eq!(info.descriptor_length, 64);
}

#[test]
fn rejects_non_cdi() {
    assert!(cdi::detect(&mut Cursor::new(vec![0u8; 2048])).is_none()); // version 0
    assert!(cdi::detect(&mut Cursor::new(vec![0u8; 4])).is_none()); // too short
                                                                    // Valid version but descriptor length larger than the file.
    let bad = with_footer(16, 0x8000_0006, 9_999_999);
    assert!(cdi::detect(&mut Cursor::new(bad)).is_none());
}

// Real DiscJuggler image (dc-load.cdi, GPL Dreamcast homebrew) — content-bearing
// and large, so gitignored; fetch with:
//   curl -L -o iso/tests/data/real_discjuggler.cdi \
//     https://raw.githubusercontent.com/Kochise/dreamcast-docs/master/LAN/ROMS/dc-load-ip-1.0.4-dj4/dc-load.cdi
#[test]
fn detects_real_discjuggler_image() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/real_discjuggler.cdi");
    let Ok(f) = std::fs::File::open(path) else {
        eprintln!("skip: real_discjuggler.cdi absent");
        return;
    };
    let info = cdi::detect(&mut std::io::BufReader::new(f)).expect("detect real CDI");
    assert_eq!(info.version, 0x8000_0006); // DiscJuggler 3.5
    assert_eq!(info.descriptor_length, 664);
}
