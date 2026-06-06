// Forensic analyzer contract (`iso9660_forensic::analyse`) — mirrors the
// gpt-forensic `analyse() -> Analysis { anomalies, ... }` pattern so a
// disk-forensic orchestrator can report on an ISO uniformly.
//
// Validated against the project's own xorriso-built rock_ridge.iso (real data):
// a clean image yields the volume/provenance summary and no anomalies; a
// byte-tampered both-endian copy is flagged.

use iso9660_forensic::analyse;
use iso9660_forensic::findings::{AnomalyKind, Severity};
use std::io::Cursor;

const DATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data");

fn rr() -> Vec<u8> {
    std::fs::read(format!("{DATA}/rock_ridge.iso")).expect("rock_ridge.iso fixture")
}

#[test]
fn clean_iso_reports_provenance_and_no_anomalies() {
    let mut c = Cursor::new(rr());
    let a = analyse(&mut c).expect("analyse");
    // No structural anomalies on a clean, tool-produced image.
    assert!(a.max_severity().is_none(), "unexpected anomalies: {:?}", a.anomalies);
    // Provenance / authoring-tool fingerprint is captured.
    assert!(
        a.volume.data_preparer_id.to_ascii_uppercase().contains("XORRISO"),
        "data preparer should fingerprint the mastering tool: {:?}",
        a.volume.data_preparer_id
    );
    assert!(a.volume.has_rock_ridge);
    assert_eq!(a.volume.session_count, 1);
}

#[test]
fn both_endian_mismatch_is_flagged() {
    // Corrupt ONLY the big-endian copy of the PVD's Volume Space Size
    // (sector offset 84; the LE copy is at 80). PVD is at LBA 16 in a 2048 ISO.
    let mut bytes = rr();
    bytes[16 * 2048 + 84] ^= 0xFF;
    let mut c = Cursor::new(bytes);
    let a = analyse(&mut c).expect("analyse");

    let f = a
        .anomalies
        .iter()
        .find(|x| matches!(x.kind, AnomalyKind::BothEndianMismatch { .. }))
        .expect("both-endian mismatch should be flagged");
    assert!(
        matches!(&f.kind, AnomalyKind::BothEndianMismatch { field, .. } if *field == "volume_space_size"),
        "wrong field: {:?}",
        f.kind
    );
    assert!(f.severity >= Severity::High, "both-endian mismatch is a strong tamper signal");
    assert_eq!(f.code, "ISO-PVD-ENDIAN");
    assert!(a.max_severity().is_some());
}
