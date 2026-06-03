// CD TOC + disc identification tests.
//
// Golden vectors from the MusicBrainz "Disc ID Calculation" worked example
// (6-track audio CD): track frame offsets [150, 15363, 32314, 46592, 63414,
// 80489], lead-out 95462. MusicBrainz disc ID is published as
// "49HHV7Eb8UKF3aQiNmu1GR8vKTY-"; the freedb ID is cross-checked at 0x3404f606.

use iso9660_forensic::cdtoc::Toc;

fn example_toc() -> Toc {
    Toc {
        first_track: 1,
        track_frames: vec![150, 15363, 32314, 46592, 63414, 80489],
        leadout_frame: 95462,
    }
}

#[test]
fn musicbrainz_id_matches_published_example() {
    assert_eq!(example_toc().musicbrainz_id(), "49HHV7Eb8UKF3aQiNmu1GR8vKTY-");
}

#[test]
fn musicbrainz_id_is_28_chars() {
    assert_eq!(example_toc().musicbrainz_id().len(), 28);
}

#[test]
fn freedb_id_matches_cross_checked_value() {
    assert_eq!(example_toc().freedb_id(), 0x3404_f606);
    assert_eq!(example_toc().freedb_id_hex(), "3404f606");
}

#[test]
fn track_geometry() {
    let toc = example_toc();
    assert_eq!(toc.track_count(), 6);
    assert_eq!(toc.first_track, 1);
    assert_eq!(toc.last_track(), 6);
    // track 1 length = 15363 - 150 = 15213
    assert_eq!(toc.track_length_frames(0), Some(15213));
    // last track length = leadout - last offset = 95462 - 80489 = 14973
    assert_eq!(toc.track_length_frames(5), Some(14973));
    assert_eq!(toc.track_length_frames(6), None);
}

#[test]
fn single_track_toc() {
    // A one-track data disc still produces stable IDs.
    let toc = Toc { first_track: 1, track_frames: vec![150], leadout_frame: 5000 };
    assert_eq!(toc.track_count(), 1);
    assert_eq!(toc.musicbrainz_id().len(), 28);
    assert_ne!(toc.freedb_id(), 0);
}

// ── Toc::from_cue (v0.3-dev) ──────────────────────────────────────────────────

use iso9660_forensic::cue;

#[test]
fn toc_from_cue_audio_disc_ids() {
    let sheet = cue::parse(
        "FILE \"audio.bin\" BINARY\n\
         \x20 TRACK 01 AUDIO\n    INDEX 01 00:00:00\n\
         \x20 TRACK 02 AUDIO\n    INDEX 01 03:00:00\n",
    );
    // 03:00:00 = (3*60)*75 = 13500 frames; total disc = 20000 frames.
    let toc = Toc::from_cue(&sheet, 20000).expect("toc from cue");
    assert_eq!(toc.first_track, 1);
    assert_eq!(toc.track_count(), 2);
    assert_eq!(toc.track_frames, vec![150, 13650]);
    assert_eq!(toc.leadout_frame, 20150);
    assert_eq!(toc.musicbrainz_id(), "WMACBQwb0kczYVuWM7lyfPJbl8s-");
    assert_eq!(toc.freedb_id_hex(), "0d010a02");
}

#[test]
fn toc_from_cue_empty_is_none() {
    let sheet = cue::parse("REM empty\n");
    assert!(Toc::from_cue(&sheet, 1000).is_none());
}
