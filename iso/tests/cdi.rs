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
    // All known DiscJuggler versions (0x80000005 and 0x80000006 both seen in
    // real dreamcast-docs images; 0x80000004 is older DJ 3.00).
    for version in [0x8000_0004u32, 0x8000_0005, 0x8000_0006] {
        let img = with_footer(2048, version, 64);
        let info = cdi::detect(&mut Cursor::new(img)).expect("detect CDI");
        assert_eq!(info.version, version);
        assert_eq!(info.descriptor_length, 64);
    }
}

#[test]
fn rejects_non_cdi() {
    assert!(cdi::detect(&mut Cursor::new(vec![0u8; 2048])).is_none()); // version 0
    assert!(cdi::detect(&mut Cursor::new(vec![0u8; 4])).is_none()); // too short
                                                                    // Valid version but descriptor length larger than the file.
    let bad = with_footer(16, 0x8000_0006, 9_999_999);
    assert!(cdi::detect(&mut Cursor::new(bad)).is_none());
}

// Real DiscJuggler image (dc-load.cdi, Dreamcast homebrew) — content-bearing
// and large, so gitignored; fetch with:
//   curl -L -o tests/data/real_discjuggler.cdi \
//     https://raw.githubusercontent.com/Kochise/dreamcast-docs/master/LAN/ROMS/dc-load-ip-1.0.4-dj4/dc-load.cdi
// Detection was manually cross-validated against 3 real dreamcast-docs CDIs
// spanning two versions: dc-load.cdi + dcload-serial (0x80000006) and
// image.cdi (0x80000005); all detected correctly.
#[test]
fn detects_real_discjuggler_image() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/real_discjuggler.cdi");
    let Ok(f) = std::fs::File::open(path) else {
        eprintln!("skip: real_discjuggler.cdi absent");
        return;
    };
    let info = cdi::detect(&mut std::io::BufReader::new(f)).expect("detect real CDI");
    assert_eq!(info.version, 0x8000_0006); // DiscJuggler 3.5
    assert_eq!(info.descriptor_length, 664);
}

// CDI track decode, validated against the real dc-load.cdi (gitignored; see
// fetch URL above). The full geometry asserted here is the byte-exact output of
// `aaru image info dc-load.cdi` (independent oracle):
//
//   Track  Type             Bps   Raw bps  Pregap  Start   End
//   1      CdMode2Formless  2336  2352     150     0       79
//   2      CdMode2Formless  2336  2352     150     11330   11781
//
// The port was additionally cross-validated locally against two further real
// CDIs that exercise the Audio (2352/2352) and Mode2 readMode-1 (2336/2336)
// paths and the open-session terminator; all matched Aaru exactly. A third
// image (image.cdi) has a malformed descriptor (zero sessions) that both Aaru
// and this decoder correctly decline.
#[test]
fn decodes_real_discjuggler_tracks() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/real_discjuggler.cdi");
    let Ok(f) = std::fs::File::open(path) else {
        eprintln!("skip: real_discjuggler.cdi absent");
        return;
    };
    let tracks = cdi::tracks(&mut std::io::BufReader::new(f)).expect("decode CDI tracks");
    assert_eq!(tracks.len(), 2, "Aaru reports 2 tracks: {tracks:?}");
    assert!(tracks.iter().all(|t| t.kind == cdi::CdiTrackKind::Mode2Formless), "{tracks:?}");
    assert!(tracks.iter().all(|t| t.bytes_per_sector == 2336), "{tracks:?}");
    assert!(tracks.iter().all(|t| t.raw_bytes_per_sector == 2352), "{tracks:?}");

    assert_eq!(tracks[0].start_sector, 0);
    assert_eq!(tracks[0].end_sector(), 79);
    assert_eq!(tracks[1].start_sector, 11330);
    assert_eq!(tracks[1].end_sector(), 11781);
}
