#![allow(clippy::unwrap_used, clippy::expect_used)]

// CDRDAO `.toc` parser tests.
//
// real_cdrdao.toc is a genuine CDRDAO TOC produced by Aaru (an independent
// oracle) converting our own rock_ridge ISO (reframed to raw 2352), so it
// carries no third-party content. Aaru's `image info` on it reports a single
// MODE1_RAW track, 188 sectors (start 0, end 187), data offset 0 — this test
// requires the parser to agree.

use iso9660_forensic::toc;
use iso9660_forensic::SectorMode;

fn real() -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/real_cdrdao.toc");
    std::fs::read_to_string(path).expect("real_cdrdao.toc fixture")
}

#[test]
fn parses_real_cdrdao_toc() {
    let sheet = toc::parse(&real());
    assert_eq!(sheet.disc_type.as_deref(), Some("CD_ROM"));
    assert_eq!(sheet.tracks.len(), 1, "{sheet:?}");
    let t = &sheet.tracks[0];
    assert_eq!(t.number, 1);
    assert_eq!(t.mode, toc::TocMode::Mode1Raw);
    assert_eq!(t.datafile.as_deref(), Some("real_cdrdao.bin"));
    assert_eq!(t.file_offset, 0);
    assert_eq!(t.length_sectors, 188); // 00:02:38 = 2*75 + 38
}

#[test]
fn real_data_track_maps_to_raw2352() {
    let sheet = toc::parse(&real());
    let dt = sheet.data_track().expect("data track");
    assert_eq!(dt.mode.sector_mode(), Some(SectorMode::Raw2352)); // MODE1_RAW
}

#[test]
fn mode_token_mapping() {
    use toc::TocMode;
    assert_eq!(TocMode::Mode1.sector_mode(), Some(SectorMode::Iso2048));
    assert_eq!(TocMode::Mode1Raw.sector_mode(), Some(SectorMode::Raw2352));
    assert_eq!(TocMode::Mode2.sector_mode(), Some(SectorMode::Mode2_2336));
    assert_eq!(TocMode::Mode2Raw.sector_mode(), Some(SectorMode::Raw2352Mode2));
    assert_eq!(TocMode::Mode2Form1.sector_mode(), Some(SectorMode::Iso2048));
    assert_eq!(TocMode::Mode2Form2.sector_mode(), None); // 2324 user bytes
    assert_eq!(TocMode::Audio.sector_mode(), None);
}

#[test]
fn audio_disc_has_no_data_track() {
    // A CD_DA disc with two audio tracks (no DATAFILE byte offsets needed).
    let txt = "CD_DA\n\nTRACK AUDIO\nAUDIOFILE \"a.bin\" 0 03:00:00\n\
               TRACK AUDIO\nAUDIOFILE \"a.bin\" 03:00:00 03:00:00\n";
    let sheet = toc::parse(txt);
    assert_eq!(sheet.tracks.len(), 2, "{sheet:?}");
    assert!(sheet.tracks.iter().all(|t| t.mode == toc::TocMode::Audio));
    assert!(sheet.data_track().is_none());
}
