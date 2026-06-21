// `open(path)` — resolve an optical image (raw .iso or a .cue/.ccd/.nrg/.mds/.toc
// container) to a Read+Seek over its ISO 9660 data track. This is the entry point
// a higher-level tool (disk4n6) uses to feed `analyse`/`IsoReader`.

use iso9660_forensic::{analyse, open};

const DATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data");

#[test]
fn open_raw_iso() {
    let mut src = open(format!("{DATA}/rock_ridge.iso")).expect("open raw iso");
    let a = analyse(&mut src).expect("analyse");
    assert!(
        a.volume.data_preparer_id.to_ascii_uppercase().contains("XORRISO"),
        "{:?}",
        a.volume.data_preparer_id
    );
}

#[test]
fn open_cdrdao_toc_resolves_data_track() {
    // real_cdrdao.toc -> real_cdrdao.bin (raw 2352, windowed to the data track).
    let mut src = open(format!("{DATA}/real_cdrdao.toc")).expect("open toc");
    let a = analyse(&mut src).expect("analyse via toc");
    // The reframed ISO inside is our rock_ridge content.
    assert!(a.volume.data_preparer_id.to_ascii_uppercase().contains("XORRISO"), "{:?}", a.volume);
}

#[test]
fn open_missing_file_errors() {
    assert!(open("/nonexistent/nowhere.iso").is_err());
}
