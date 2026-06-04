// CloneCD .ccd control-file parser tests.
//
// Field set and TOC semantics grounded in the libmirage reference parser
// (cdemu image-ccd/parser.c): [Disc] CATALOG, [Entry N] Point/TrackNo/PLBA/
// PMin..PFrame, [TRACK N] MODE/ISRC. Point 0xA0=first track, 0xA1=last,
// 0xA2=lead-out, 0x01-0x63=track starts.

use iso9660_forensic::ccd::{self, CcdMode};
use iso9660_forensic::SectorMode;

// A mixed-mode disc: track 1 = Mode 1 data, track 2 = audio with an ISRC.
const SAMPLE: &str = "\
[CloneCD]
Version=3
[Disc]
TocEntries=5
Sessions=1
DataTracksScrambled=0
CDTextLength=0
CATALOG=1234567890123
[Session 1]
PreGapMode=2
PreGapSubC=1
[Entry 0]
Session=1
Point=0xa0
ADR=0x01
Control=0x04
TrackNo=0
AMin=0
ASec=0
AFrame=0
ALBA=-150
Zero=0
PMin=1
PSec=0
PFrame=0
PLBA=0
[Entry 1]
Session=1
Point=0xa1
ADR=0x01
Control=0x04
TrackNo=0
PMin=2
PSec=0
PFrame=0
PLBA=0
[Entry 2]
Session=1
Point=0xa2
ADR=0x01
Control=0x04
TrackNo=0
PMin=10
PSec=32
PFrame=0
PLBA=47250
[Entry 3]
Session=1
Point=0x01
ADR=0x01
Control=0x04
TrackNo=1
AMin=0
ASec=2
AFrame=0
ALBA=0
Zero=0
PMin=0
PSec=2
PFrame=0
PLBA=0
[Entry 4]
Session=1
Point=0x02
ADR=0x01
Control=0x00
TrackNo=2
AMin=5
ASec=2
AFrame=0
ALBA=22500
Zero=0
PMin=5
PSec=2
PFrame=0
PLBA=22500
[TRACK 1]
MODE=1
INDEX 1=0
[TRACK 2]
MODE=0
INDEX 1=22500
ISRC=USRC17607839
";

#[test]
fn parses_catalog_and_track_range() {
    let toc = ccd::parse(SAMPLE);
    assert_eq!(toc.catalog.as_deref(), Some("1234567890123"));
    assert_eq!(toc.first_track, 1);
    assert_eq!(toc.last_track, 2);
    assert_eq!(toc.leadout_lba, 47250);
    assert_eq!(toc.track_count(), 2);
}

#[test]
fn parses_track_modes_starts_and_isrc() {
    let toc = ccd::parse(SAMPLE);
    let t1 = &toc.tracks[0];
    assert_eq!(t1.number, 1);
    assert_eq!(t1.mode, CcdMode::Mode1);
    assert_eq!(t1.start_lba, 0);
    assert_eq!(t1.isrc, None);

    let t2 = &toc.tracks[1];
    assert_eq!(t2.number, 2);
    assert_eq!(t2.mode, CcdMode::Audio);
    assert_eq!(t2.start_lba, 22500);
    assert_eq!(t2.isrc.as_deref(), Some("USRC17607839"));
}

#[test]
fn data_track_is_first_filesystem_track() {
    let toc = ccd::parse(SAMPLE);
    let dt = toc.data_track().expect("a data track");
    assert_eq!(dt.number, 1);
    assert_eq!(dt.mode.sector_mode(), Some(SectorMode::Raw2352));
}

#[test]
fn mode_value_mapping() {
    assert_eq!(CcdMode::from_value(0), CcdMode::Audio);
    assert_eq!(CcdMode::from_value(1), CcdMode::Mode1);
    assert_eq!(CcdMode::from_value(2), CcdMode::Mode2);
    assert_eq!(CcdMode::from_value(7), CcdMode::Other(7));
    assert_eq!(CcdMode::Mode2.sector_mode(), Some(SectorMode::Raw2352Mode2));
    assert!(CcdMode::Audio.sector_mode().is_none());
    assert!(CcdMode::Mode1.is_data());
    assert!(!CcdMode::Audio.is_data());
}

#[test]
fn start_lba_falls_back_to_msf_when_no_plba() {
    // Same disc but drop PLBA from the track-2 entry; start must derive from
    // the absolute PMin:PSec:PFrame (lead-in 150 frames removed).
    let text = SAMPLE.replace("PLBA=22500\n", "");
    let toc = ccd::parse(&text);
    let t2 = toc.tracks.iter().find(|t| t.number == 2).unwrap();
    // 5:02:00 -> (5*60+2)*75 = 22650 frames; minus 150 lead-in = 22500.
    assert_eq!(t2.start_lba, 22500);
}

#[test]
fn missing_catalog_is_none_and_unknown_lines_ignored() {
    let text = "[CloneCD]\nVersion=3\n[Disc]\nSessions=1\nFrobnicate=yes\n";
    let toc = ccd::parse(text);
    assert_eq!(toc.catalog, None);
    assert_eq!(toc.track_count(), 0);
}

#[test]
fn empty_input_is_default() {
    let toc = ccd::parse("");
    assert_eq!(toc, iso9660_forensic::ccd::CcdToc::default());
}
