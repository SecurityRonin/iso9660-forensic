//! UDF presence detection: an ISO carries UDF when its Volume Recognition
//! Sequence (sector 16+) holds an NSR02/NSR03 descriptor.

mod helpers;

use helpers::build_iso;
use iso9660_forensic::IsoReader;
use std::fs::File;

#[test]
fn udf_bridge_iso_reports_udf_present() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/udf_bridge.iso");
    let r = IsoReader::open(File::open(path).unwrap()).unwrap();
    assert!(r.has_udf(), "udf_bridge.iso carries a UDF NSR descriptor");
}

#[test]
fn plain_iso9660_reports_no_udf() {
    let r = IsoReader::open(build_iso("PLAIN", vec![])).unwrap();
    assert!(!r.has_udf(), "a plain ISO 9660 image has no UDF VRS");
}
