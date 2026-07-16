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

// ── synthetic descriptor: exercises the track-table walk without the fixture ─
//
// The real-image tests above are gitignored/env-gated, so the descriptor walk
// (`parse_descriptor`/`parse_track`/`decode_mode`) is otherwise unexercised in a
// clean clone. This builder emits one session + one Mode-2-formless track using
// the exact field layout ported in `cdi.rs`, then a terminating open-session
// header so the session loop's trailing pass ends via the header break.

/// A valid 15-byte DiscJuggler session header carrying `track_count`.
fn session_header(track_count: u8) -> [u8; 15] {
    let mut h = [0u8; 15];
    h[1] = track_count; // byte 1 = track count (unconstrained)
    h[9] = 0x01;
    h[13] = 0xFF;
    h[14] = 0xFF;
    h
}

/// One track record with `filename` length 0, `n_indices` index longwords, and
/// `n_cdtext` CD-Text groups (each 18 length-prefixed packs, emitted here as
/// single-payload-byte packs), geometry `start_sector` / `track_len`, and the
/// given `track_mode` / `read_mode`.
fn track_record_full(
    start_sector: u32,
    track_len: u32,
    track_mode: u32,
    read_mode: u32,
    n_indices: u16,
    n_cdtext: u32,
) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(&[0u8; 16]); // skip unknown
    r.push(0); // filename length = 0
    r.extend_from_slice(&[0u8; 29]); // skip unknown
    r.extend_from_slice(&0u16.to_le_bytes()); // medium type
    r.extend_from_slice(&n_indices.to_le_bytes()); // maxI indices
    r.extend_from_slice(&vec![0u8; usize::from(n_indices) * 4]); // index longwords
    r.extend_from_slice(&n_cdtext.to_le_bytes()); // maxC CD-Text groups
    for _ in 0..n_cdtext {
        for _ in 0..18 {
            r.push(1); // pack length = 1
            r.push(0); // one payload byte
        }
    }
    r.extend_from_slice(&[0u8; 2]); // skip unknown
    r.extend_from_slice(&track_mode.to_le_bytes()); // trackMode
    r.extend_from_slice(&[0u8; 4]); // skip unknown
    r.extend_from_slice(&1u32.to_le_bytes()); // session seq
    r.extend_from_slice(&1u32.to_le_bytes()); // track seq
    r.extend_from_slice(&start_sector.to_le_bytes());
    r.extend_from_slice(&track_len.to_le_bytes());
    r.extend_from_slice(&[0u8; 16]); // skip unknown
    r.extend_from_slice(&read_mode.to_le_bytes()); // readMode
    r.extend_from_slice(&[0u8; 4]); // track ctl
    r.extend_from_slice(&[0u8; 9]); // skip unknown
    r.extend_from_slice(&[0u8; 12]); // ISRC
    r.extend_from_slice(&0u32.to_le_bytes()); // isrc valid
    r.extend_from_slice(&[0u8; 87]); // skip unknown
    r.push(0); // session type
    r.extend_from_slice(&[0u8; 5]); // skip unknown
    r.push(0); // track follows
    r.extend_from_slice(&[0u8; 2]); // padding before end address (advance is +2)
    r.extend_from_slice(&0u32.to_le_bytes()); // end address
    r
}

/// The common no-indices / no-CD-Text track record.
fn track_record(start_sector: u32, track_len: u32, track_mode: u32, read_mode: u32) -> Vec<u8> {
    track_record_full(start_sector, track_len, track_mode, read_mode, 0, 0)
}

/// Wrap a descriptor in a CDI image and decode its tracks. `tracks()` reads the
/// descriptor from `size - descriptor_length`, so the footer's 8 bytes are part
/// of that length.
fn decode_descriptor(descriptor: &[u8]) -> Option<Vec<cdi::CdiTrack>> {
    let dsc_len = (descriptor.len() + 8) as u32;
    let mut img = vec![0u8; 4096];
    img.extend_from_slice(descriptor);
    img.extend_from_slice(&0x8000_0006u32.to_le_bytes());
    img.extend_from_slice(&dsc_len.to_le_bytes());
    cdi::tracks(&mut Cursor::new(img))
}

#[test]
fn decodes_synthetic_discjuggler_descriptor() {
    // max_s = 1, one real session (1 track), then a terminating open session.
    let mut descriptor = vec![1u8]; // max_s
    descriptor.extend_from_slice(&session_header(1));
    descriptor.extend_from_slice(&track_record(0, 229, 2, 1)); // Mode2Formless, 2336
    descriptor.extend_from_slice(&session_header(0)); // terminating open session

    let tracks = decode_descriptor(&descriptor).expect("decode synthetic CDI tracks");
    assert_eq!(tracks.len(), 1, "{tracks:?}");
    let t = &tracks[0];
    assert_eq!(t.kind, cdi::CdiTrackKind::Mode2Formless);
    assert_eq!(t.bytes_per_sector, 2336);
    assert_eq!(t.raw_bytes_per_sector, 2336);
    assert_eq!(t.start_sector, 0);
    // start_sector == 0 -> track_len -= 150.
    assert_eq!(t.length_sectors, 229 - 150);
}

/// Build a one-session, one-track descriptor with the given geometry/modes.
fn one_track_descriptor(start: u32, len: u32, track_mode: u32, read_mode: u32) -> Vec<u8> {
    let mut d = vec![1u8]; // max_s
    d.extend_from_slice(&session_header(1));
    d.extend_from_slice(&track_record(start, len, track_mode, read_mode));
    d.extend_from_slice(&session_header(0)); // terminating open session
    d
}

#[test]
fn decodes_synthetic_audio_track() {
    // Audio (trackMode 0, readMode 2 -> 2352/2352) with a non-zero start sector,
    // so the `start_sector != 0` normalisation branch (-150) is taken.
    let tracks = decode_descriptor(&one_track_descriptor(300, 500, 0, 2)).expect("audio");
    assert_eq!(tracks.len(), 1, "{tracks:?}");
    assert_eq!(tracks[0].kind, cdi::CdiTrackKind::Audio);
    assert_eq!(tracks[0].bytes_per_sector, 2352);
    assert_eq!(tracks[0].raw_bytes_per_sector, 2352);
    assert_eq!(tracks[0].start_sector, 300 - 150);
    assert_eq!(tracks[0].length_sectors, 500);
}

#[test]
fn decodes_synthetic_mode1_track() {
    // Mode 1 (trackMode 1, readMode 0 -> 2048/2048).
    let tracks = decode_descriptor(&one_track_descriptor(1000, 400, 1, 0)).expect("mode1");
    assert_eq!(tracks.len(), 1, "{tracks:?}");
    assert_eq!(tracks[0].kind, cdi::CdiTrackKind::Mode1);
    assert_eq!(tracks[0].bytes_per_sector, 2048);
    assert_eq!(tracks[0].raw_bytes_per_sector, 2048);
    assert_eq!(tracks[0].start_sector, 1000 - 150);
}

#[test]
fn synthetic_unknown_track_mode_declines() {
    // trackMode 7 is unmapped -> decode_mode returns None -> tracks() yields None.
    assert!(decode_descriptor(&one_track_descriptor(0, 100, 7, 2)).is_none());
}

#[test]
fn synthetic_track_with_indices_and_cdtext() {
    // Two index longwords and one CD-Text group (18 length-prefixed packs) drive
    // the index-skip and the CD-Text pack loop in parse_track.
    let mut d = vec![1u8];
    d.extend_from_slice(&session_header(1));
    d.extend_from_slice(&track_record_full(0, 300, 2, 1, 2, 1));
    d.extend_from_slice(&session_header(0));
    let tracks = decode_descriptor(&d).expect("indices + cdtext");
    assert_eq!(tracks.len(), 1, "{tracks:?}");
    assert_eq!(tracks[0].kind, cdi::CdiTrackKind::Mode2Formless);
}

#[test]
fn synthetic_invalid_read_modes_decline() {
    // Each kind with a readMode outside its accepted set -> decode_mode's None
    // fallback arm -> tracks() yields None.
    assert!(decode_descriptor(&one_track_descriptor(0, 100, 0, 0)).is_none()); // Audio, rm 0
    assert!(decode_descriptor(&one_track_descriptor(0, 100, 1, 9)).is_none()); // Mode1, rm 9
    assert!(decode_descriptor(&one_track_descriptor(0, 100, 2, 9)).is_none()); // Mode2, rm 9
}
