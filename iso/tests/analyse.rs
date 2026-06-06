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
fn pre_system_area_payload_is_flagged() {
    // Embed a PE ("MZ") magic in the reserved system area (sector 0, before the
    // PVD) — a classic place to stash a payload. rock_ridge.iso zeroes it.
    let mut bytes = rr();
    bytes[0] = b'M';
    bytes[1] = b'Z';
    let a = analyse(&mut Cursor::new(bytes)).expect("analyse");
    let f = a
        .anomalies
        .iter()
        .find(|x| x.code == "ISO-PRESYS-DATA")
        .expect("pre-system payload should be flagged");
    match &f.kind {
        AnomalyKind::PreSystemData { sector, kind } => {
            assert_eq!(*sector, 0);
            assert_eq!(kind.as_str(), "MZ/PE");
        }
        other => panic!("wrong kind: {other:?}"),
    }
    assert!(f.severity >= Severity::Medium, "recognized executable magic is notable");
}

#[test]
fn symlink_traversal_and_absolute_are_flagged() {
    // symlinks.iso (xorriso -R) contains abs_link -> /etc/passwd and
    // trav_link -> ../../../escape/target.
    let img = std::fs::read(format!("{DATA}/symlinks.iso")).expect("symlinks.iso fixture");
    let a = analyse(&mut Cursor::new(img)).expect("analyse");
    let sl: Vec<_> = a.anomalies.iter().filter(|x| x.code == "ISO-SYMLINK").collect();
    assert_eq!(sl.len(), 2, "expected two symlink findings: {:?}", a.anomalies);

    let trav = sl
        .iter()
        .find(|f| matches!(&f.kind, AnomalyKind::SymlinkAnomaly { issue, .. } if issue.as_str() == "path-traversal"))
        .expect("path-traversal symlink");
    assert!(trav.severity >= Severity::High, "traversal is an escape attempt");

    let abs = sl
        .iter()
        .find(|f| matches!(&f.kind, AnomalyKind::SymlinkAnomaly { issue, .. } if issue.as_str() == "absolute"))
        .expect("absolute symlink");
    assert!(abs.severity <= Severity::Medium, "absolute is usually a path leak, not escape");
}

#[test]
fn orphaned_lost_file_is_flagged() {
    // phantom.iso: the path table references directory "LOST" (LBA 20) holding
    // GHOST.TXT, but the active tree never links it — recoverable hidden/deleted
    // content.
    let img = std::fs::read(format!("{DATA}/phantom.iso")).expect("phantom.iso fixture");
    let a = analyse(&mut Cursor::new(img)).expect("analyse");
    let f = a
        .anomalies
        .iter()
        .find(|x| x.code == "ISO-ORPHAN-FILE")
        .expect("orphaned file should be flagged");
    match &f.kind {
        AnomalyKind::OrphanedFile { name, parent_lba, .. } => {
            assert_eq!(name.as_str(), "GHOST.TXT", "{:?}", f.kind);
            assert_eq!(*parent_lba, 20);
        }
        other => panic!("wrong kind: {other:?}"),
    }
    assert!(f.severity >= Severity::Medium);
}

#[test]
fn file_recorded_after_volume_is_flagged() {
    // Backdate the PVD volume creation year to 1990 (digits at sector offset
    // 813). rock_ridge's files are recorded in 2026 — now "after" the volume,
    // consistent with a post-mastering addition or a backdated volume.
    let mut bytes = rr();
    let pvd = 16 * 2048;
    bytes[pvd + 813..pvd + 817].copy_from_slice(b"1990");
    let a = analyse(&mut Cursor::new(bytes)).expect("analyse");

    // sanity: the volume now reads as 1990
    assert!(a.volume.creation_time.as_deref().unwrap_or("").starts_with("1990"));

    let f = a
        .anomalies
        .iter()
        .find(|x| x.code == "ISO-TIME-AFTER-VOL")
        .expect("file-after-volume should be flagged");
    assert!(matches!(f.kind, AnomalyKind::FileAfterVolume { .. }), "{:?}", f.kind);
    assert!(f.severity >= Severity::Medium);
}

#[test]
fn mixed_timezones_are_flagged() {
    // rock_ridge is uniformly GMT+0. Shift the volume creation GMT offset (PVD
    // tz byte at sector offset 829) so timestamps span two distinct UTC offsets.
    let mut bytes = rr();
    bytes[16 * 2048 + 829] = 4; // +1 hour (15-min units)
    let a = analyse(&mut Cursor::new(bytes)).expect("analyse");
    let f = a
        .anomalies
        .iter()
        .find(|x| x.code == "ISO-MIXED-TZ")
        .expect("mixed timezones should be flagged");
    match &f.kind {
        AnomalyKind::MixedTimezones { offsets } => assert!(offsets.len() >= 2, "{offsets:?}"),
        other => panic!("wrong kind: {other:?}"),
    }
}

#[test]
fn implausible_volume_date_is_flagged() {
    // Backdate the volume creation year to 1970 — impossible for an optical
    // volume (pre-CD-ROM), unlike a file's preserved old mtime.
    let mut bytes = rr();
    bytes[16 * 2048 + 813..16 * 2048 + 817].copy_from_slice(b"1970");
    let a = analyse(&mut Cursor::new(bytes)).expect("analyse");
    let f = a
        .anomalies
        .iter()
        .find(|x| x.code == "ISO-TIME-IMPLAUSIBLE")
        .expect("implausible volume date should be flagged");
    match &f.kind {
        AnomalyKind::ImplausibleVolumeDate { which, year } => {
            assert_eq!(*year, 1970);
            assert_eq!(which.as_str(), "creation");
        }
        other => panic!("wrong kind: {other:?}"),
    }
    assert!(f.severity >= Severity::Medium);
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
