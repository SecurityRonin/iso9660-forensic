// CUE sheet parser tests.

use iso9660_forensic::cue::{parse, Msf, TrackMode};
use iso9660_forensic::sector::SectorMode;

const SHEET: &str = r#"FILE "image.bin" BINARY
  TRACK 01 MODE1/2352
    INDEX 01 00:00:00
  TRACK 02 AUDIO
    INDEX 00 03:00:00
    INDEX 01 03:02:00
"#;

#[test]
fn parses_single_file() {
    let cue = parse(SHEET);
    assert_eq!(cue.files.len(), 1);
    assert_eq!(cue.files[0].name, "image.bin");
    assert_eq!(cue.files[0].format, "BINARY");
}

#[test]
fn parses_tracks_and_modes() {
    let cue = parse(SHEET);
    let tracks = &cue.files[0].tracks;
    assert_eq!(tracks.len(), 2);
    assert_eq!(tracks[0].number, 1);
    assert_eq!(tracks[0].mode, TrackMode::Mode1_2352);
    assert_eq!(tracks[1].number, 2);
    assert_eq!(tracks[1].mode, TrackMode::Audio);
}

#[test]
fn parses_indices() {
    let cue = parse(SHEET);
    let t2 = &cue.files[0].tracks[1];
    assert_eq!(t2.indices.len(), 2);
    assert_eq!(t2.indices[0], (0, Msf { minutes: 3, seconds: 0, frames: 0 }));
    assert_eq!(t2.indices[1].0, 1);
    // 3:02:00 -> (3*60+2)*75 + 0 = 13650
    assert_eq!(t2.indices[1].1.to_lba(), 13_650);
}

#[test]
fn data_track_picks_mode1() {
    let cue = parse(SHEET);
    let (file, track) = cue.data_track().expect("a data track must be found");
    assert_eq!(file, "image.bin");
    assert_eq!(track.number, 1);
    assert_eq!(track.mode.sector_mode(), Some(SectorMode::Raw2352));
}

#[test]
fn mode_token_mapping() {
    let s = parse(
        "FILE \"a.bin\" BINARY\n  TRACK 01 MODE2/2352\n    INDEX 01 00:00:00\n",
    );
    assert_eq!(s.files[0].tracks[0].mode, TrackMode::Mode2_2352);
    assert_eq!(
        s.files[0].tracks[0].mode.sector_mode(),
        Some(SectorMode::Raw2352Mode2)
    );

    let s = parse("FILE \"a.iso\" BINARY\n  TRACK 01 MODE1/2048\n    INDEX 01 00:00:00\n");
    assert_eq!(s.files[0].tracks[0].mode, TrackMode::Mode1_2048);
    assert_eq!(s.files[0].tracks[0].mode.sector_mode(), Some(SectorMode::Iso2048));
}

#[test]
fn audio_only_has_no_data_track() {
    let s = parse("FILE \"a.bin\" BINARY\n  TRACK 01 AUDIO\n    INDEX 01 00:00:00\n");
    assert!(s.data_track().is_none());
    assert!(!s.files[0].tracks[0].mode.is_data());
}

#[test]
fn multi_file_cue() {
    let s = parse(
        "FILE \"t1.bin\" BINARY\n  TRACK 01 AUDIO\n    INDEX 01 00:00:00\n\
         FILE \"t2.bin\" BINARY\n  TRACK 02 MODE1/2048\n    INDEX 01 00:00:00\n",
    );
    assert_eq!(s.files.len(), 2);
    let (file, _t) = s.data_track().unwrap();
    assert_eq!(file, "t2.bin"); // data track lives in the second file
}

#[test]
fn empty_or_garbage_is_empty() {
    assert!(parse("").files.is_empty());
    assert!(parse("REM this is a comment\nnonsense line\n").files.is_empty());
}
