// Forensic analyzer contract (`iso9660_forensic::analyse`) — mirrors the
// gpt-forensic `analyse() -> Analysis { anomalies, ... }` pattern so a
// disk-forensic orchestrator can report on an ISO uniformly.
//
// Validated against the project's own xorriso-built rock_ridge.iso (real data):
// a clean image yields the volume/provenance summary and no anomalies; a
// byte-tampered both-endian copy is flagged.

use iso9660_forensic::analyse;
use iso9660_forensic::findings::{AnomalyKind, Severity};
use iso9660_forensic::IsoReader;
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
        .find(|x| x.code == "ISO-BOTH-ENDIAN")
        .expect("both-endian mismatch should be flagged");
    match &f.kind {
        AnomalyKind::BothEndianMismatch { context, field, .. } => {
            assert_eq!(field.as_str(), "volume_space_size", "{:?}", f.kind);
            assert_eq!(context.as_str(), "PVD");
        }
        other => panic!("expected BothEndianMismatch: {other:?}"),
    }
    assert!(f.severity >= Severity::High, "both-endian mismatch is a strong tamper signal");
    assert!(a.max_severity().is_some());
}

#[test]
fn trailing_payload_past_volume_is_flagged() {
    // Append a non-zero payload past the ISO's declared end (polyglot / hidden
    // archive technique).
    let mut bytes = rr();
    let payload = b"HIDDEN PAYLOAD APPENDED PAST THE ISO END";
    bytes.extend_from_slice(payload);
    let mut c = Cursor::new(bytes);
    let a = analyse(&mut c).expect("analyse");

    let f = a
        .anomalies
        .iter()
        .find(|x| x.code == "ISO-TRAILING-DATA")
        .expect("trailing payload should be flagged");
    match &f.kind {
        AnomalyKind::TrailingData { trailing_bytes, .. } => {
            assert_eq!(*trailing_bytes, payload.len() as u64, "{:?}", f.kind);
        }
        other => panic!("wrong kind: {other:?}"),
    }
    assert!(f.severity >= Severity::Medium);
}

#[test]
fn nonzero_file_slack_is_flagged() {
    // rock_ridge.iso has zero-filled slack (xorriso). Locate a file with slack
    // via the reader, then plant a non-zero byte in its final-sector slack —
    // simulating leaked mastering-host buffer content.
    let mut bytes = rr();
    let (lba, size) = {
        let mut r = IsoReader::open(Cursor::new(bytes.clone())).expect("open");
        let slacks = r.audit_file_slack().expect("slack audit");
        let s = slacks.iter().find(|s| s.slack_bytes > 0).expect("a file with slack");
        (s.lba, s.file_size)
    };
    let sectors = (u64::from(size)).div_ceil(2048);
    let last_lba = u64::from(lba) + sectors - 1;
    let data_end = (size % 2048) as usize; // first slack byte in the last sector
    bytes[last_lba as usize * 2048 + data_end] = 0xAA; // 2048-mode ISO

    let a = analyse(&mut Cursor::new(bytes)).expect("analyse");
    let f = a
        .anomalies
        .iter()
        .find(|x| x.code == "ISO-SLACK-DATA")
        .expect("non-zero slack should be flagged");
    assert!(matches!(f.kind, AnomalyKind::SlackData { .. }), "{:?}", f.kind);
}

#[test]
fn zero_padding_is_not_flagged_as_trailing() {
    // Benign zero padding past the volume must NOT be reported.
    let mut bytes = rr();
    bytes.extend_from_slice(&[0u8; 4096]);
    let mut c = Cursor::new(bytes);
    let a = analyse(&mut c).expect("analyse");
    assert!(
        a.anomalies.iter().all(|x| x.code != "ISO-TRAILING-DATA"),
        "zero padding must not be flagged: {:?}",
        a.anomalies
    );
}
