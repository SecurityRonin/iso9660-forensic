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
fn implausible_future_volume_date_is_flagged() {
    // Forward-date the volume creation year to 2200 — no optical disc
    // legitimately claims a year past the far-future ceiling, so this is
    // consistent with a corrupt or falsified date.
    let mut bytes = rr();
    bytes[16 * 2048 + 813..16 * 2048 + 817].copy_from_slice(b"2200");
    let a = analyse(&mut Cursor::new(bytes)).expect("analyse");
    let f = a
        .anomalies
        .iter()
        .find(|x| x.code == "ISO-TIME-IMPLAUSIBLE")
        .expect("implausible future volume date should be flagged");
    match &f.kind {
        AnomalyKind::ImplausibleVolumeDate { which, year } => {
            assert_eq!(*year, 2200);
            assert_eq!(which.as_str(), "creation");
        }
        other => panic!("wrong kind: {other:?}"),
    }
    assert!(f.severity >= Severity::Medium);
}

#[test]
fn reserved_pvd_field_data_is_flagged() {
    // The PVD's reserved tail (offsets 1395..2048) must be zero per ECMA-119.
    // Plant a byte there — consistent with a tool fingerprint or stashed data.
    let mut bytes = rr();
    bytes[16 * 2048 + 1500] = 0x42;
    let a = analyse(&mut Cursor::new(bytes)).expect("analyse");
    let f = a
        .anomalies
        .iter()
        .find(|x| x.code == "ISO-RESERVED-DATA")
        .expect("non-zero reserved field should be flagged");
    match &f.kind {
        AnomalyKind::ReservedFieldData { region, nonzero_bytes, .. } => {
            assert_eq!(region.as_str(), "reserved tail", "{:?}", f.kind);
            assert_eq!(*nonzero_bytes, 1);
        }
        other => panic!("wrong kind: {other:?}"),
    }
    assert!(f.severity >= Severity::Low);
}

#[test]
fn joliet_primary_divergence_is_flagged() {
    // joliet.iso is a hybrid (shared data extents). Repoint one file's extent in
    // the Joliet tree so it no longer matches the primary — a file visible to one
    // OS view but not the other.
    let mut bytes = std::fs::read(format!("{DATA}/joliet.iso")).expect("joliet.iso fixture");
    // Locate the SVD (the sole type-2 descriptor) and its Joliet root dir LBA.
    let svd = (16..24)
        .map(|l| l * 2048)
        .find(|&o| &bytes[o + 1..o + 6] == b"CD001" && bytes[o] == 2)
        .expect("SVD");
    let root_lba = u32::from_le_bytes(bytes[svd + 158..svd + 162].try_into().unwrap()) as usize;
    // Find the first file (non-dir) record in the Joliet root and repoint it.
    let ro = root_lba * 2048;
    let mut off = 0usize;
    let file_off = loop {
        let len = bytes[ro + off] as usize;
        assert!(len != 0, "no file record in Joliet root");
        if bytes[ro + off + 25] & 0x02 == 0 {
            break ro + off;
        }
        off += len;
    };
    bytes[file_off + 2..file_off + 6].copy_from_slice(&9000u32.to_le_bytes());
    bytes[file_off + 6..file_off + 10].copy_from_slice(&9000u32.to_be_bytes());

    let a = analyse(&mut Cursor::new(bytes)).expect("analyse");
    let f = a
        .anomalies
        .iter()
        .find(|x| x.code == "ISO-TREE-DIVERGENCE")
        .expect("Joliet/primary divergence should be flagged");
    assert!(matches!(f.kind, AnomalyKind::TreeDivergence { .. }), "{:?}", f.kind);
    assert!(f.severity >= Severity::High, "OS-targeted concealment is a strong signal");
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

#[test]
fn phantom_directory_divergence_is_flagged() {
    // phantom.iso: directory "LOST" (LBA 20) is listed in the path table but is
    // unreachable from the directory tree. Beyond the recoverable file inside it
    // (ISO-ORPHAN-FILE), the structural divergence of the directory itself is a
    // distinct finding.
    let img = std::fs::read(format!("{DATA}/phantom.iso")).expect("phantom.iso fixture");
    let a = analyse(&mut Cursor::new(img)).expect("analyse");
    let f = a
        .anomalies
        .iter()
        .find(|x| x.code == "ISO-PATHTABLE-DIVERGENCE")
        .expect("path-table divergence should be flagged");
    match &f.kind {
        AnomalyKind::PathTableDivergence { direction, lba } => {
            assert_eq!(direction.as_str(), "phantom", "{:?}", f.kind);
            assert_eq!(*lba, 20);
        }
        other => panic!("wrong kind: {other:?}"),
    }
    // A path-table-only dir is the recoverable / deleted-folder case.
    assert_eq!(f.severity, Severity::Medium);
}

#[test]
fn ghost_directory_divergence_is_flagged() {
    // A directory reachable in the tree but ABSENT from the path table — the
    // mandatory path-table index was edited to omit a directory that still
    // exists, consistent with concealment from path-table-based navigation.
    let img = make_iso_with_ghost_dir();
    let a = analyse(&mut Cursor::new(img)).expect("analyse");
    let f = a
        .anomalies
        .iter()
        .find(|x| x.code == "ISO-PATHTABLE-DIVERGENCE")
        .expect("ghost path-table divergence should be flagged");
    match &f.kind {
        AnomalyKind::PathTableDivergence { direction, lba } => {
            assert_eq!(direction.as_str(), "ghost", "{:?}", f.kind);
            assert_eq!(*lba, 20);
        }
        other => panic!("wrong kind: {other:?}"),
    }
    // A directory hidden from the path table is a stronger concealment signal.
    assert!(f.severity >= Severity::High);
}

#[test]
fn path_table_endian_divergence_is_flagged() {
    // rock_ridge.iso stores its path table twice (L little-endian @ LBA 21,
    // M big-endian @ LBA 22). Corrupt the M copy's record of SUBDIR's extent
    // LBA (entry 1, BE bytes at table offset 12) so the two redundant indexes
    // disagree — consistent with editing one copy to create an OS-specific view.
    let mut bytes = rr();
    bytes[22 * 2048 + 12] = 0xFF;
    let a = analyse(&mut Cursor::new(bytes)).expect("analyse");
    let f = a
        .anomalies
        .iter()
        .find(|x| x.code == "ISO-PATHTABLE-ENDIAN")
        .expect("L/M path-table divergence should be flagged");
    match &f.kind {
        AnomalyKind::PathTableEndianDivergence { index, description } => {
            assert_eq!(*index, 1, "{:?}", f.kind);
            assert!(description.contains("LBA"), "{description}");
        }
        other => panic!("wrong kind: {other:?}"),
    }
    // A both-endian redundancy disagreement is a strong tamper/corruption signal.
    assert!(f.severity >= Severity::High);
}

/// Write a directory record at `img[off..]`; returns its byte length.
fn dir_rec(img: &mut [u8], off: usize, lba: u32, size: u32, is_dir: bool, name: &[u8]) -> usize {
    let nl = name.len();
    let rec_len = 33 + nl + usize::from(nl % 2 == 0); // pad to even
    let d = &mut img[off..off + rec_len];
    d[0] = rec_len as u8;
    d[2..6].copy_from_slice(&lba.to_le_bytes());
    d[6..10].copy_from_slice(&lba.to_be_bytes());
    d[10..14].copy_from_slice(&size.to_le_bytes());
    d[14..18].copy_from_slice(&size.to_be_bytes());
    d[25] = if is_dir { 0x02 } else { 0x00 };
    d[32] = nl as u8;
    d[33..33 + nl].copy_from_slice(name);
    rec_len
}

/// Build an ISO whose directory tree links a subdirectory "SECRET" (LBA 20)
/// that the L-path table never lists — a ghost directory.
fn make_iso_with_ghost_dir() -> Vec<u8> {
    const S: usize = 2048;
    let mut img = vec![0u8; 22 * S];
    // PVD at sector 16.
    let p = &mut img[16 * S..17 * S];
    p[0] = 0x01;
    p[1..6].copy_from_slice(b"CD001");
    p[6] = 0x01;
    p[80..84].copy_from_slice(&22u32.to_le_bytes());
    p[84..88].copy_from_slice(&22u32.to_be_bytes());
    p[128..130].copy_from_slice(&2048u16.to_le_bytes());
    p[130..132].copy_from_slice(&2048u16.to_be_bytes());
    p[132..136].copy_from_slice(&10u32.to_le_bytes()); // path_table_size: root only
    p[136..140].copy_from_slice(&10u32.to_be_bytes());
    p[140..144].copy_from_slice(&1u32.to_le_bytes()); // l_path_table_lba = 1
    p[156] = 34; // root dir record length
    p[158..162].copy_from_slice(&18u32.to_le_bytes()); // root lba 18
    p[162..166].copy_from_slice(&18u32.to_be_bytes());
    p[166..170].copy_from_slice(&2048u32.to_le_bytes()); // root size
    p[170..174].copy_from_slice(&2048u32.to_be_bytes());
    p[181] = 0x02;
    p[188] = 1;
    // VD terminator at sector 17.
    let t = &mut img[17 * S..18 * S];
    t[0] = 0xFF;
    t[1..6].copy_from_slice(b"CD001");
    t[6] = 0x01;
    // L-path table at sector 1: ONLY root (lba 18) — SECRET is omitted.
    let pt = &mut img[S..2 * S];
    pt[0] = 1; // dir_id_len 1
    pt[2..6].copy_from_slice(&18u32.to_le_bytes());
    pt[6..8].copy_from_slice(&1u16.to_le_bytes()); // parent 1
    pt[8] = 0x00; // id 0x00, pad
                  // Root directory (sector 18): ".", "..", and subdir "SECRET" (lba 20).
    let mut off = 18 * S;
    off += dir_rec(&mut img, off, 18, 2048, true, &[0x00]);
    off += dir_rec(&mut img, off, 18, 2048, true, &[0x01]);
    dir_rec(&mut img, off, 20, 2048, true, b"SECRET");
    // SECRET directory (sector 20): only "." and "..".
    let mut off = 20 * S;
    off += dir_rec(&mut img, off, 20, 2048, true, &[0x00]);
    dir_rec(&mut img, off, 18, 2048, true, &[0x01]);
    img
}

#[test]
fn out_of_bounds_extent_is_flagged() {
    // A file whose data extent points far past the image end — consistent with
    // truncation, corruption, or a dangling reference to removed content.
    let img = make_iso_with_oob_file(2048);
    let a = analyse(&mut Cursor::new(img)).expect("analyse");
    let f = a
        .anomalies
        .iter()
        .find(|x| x.code == "ISO-OOB-EXTENT")
        .expect("out-of-bounds extent should be flagged");
    match &f.kind {
        AnomalyKind::OutOfBoundsExtent { entry_path, lba, .. } => {
            assert!(entry_path.contains("BIG"), "{:?}", f.kind);
            assert_eq!(*lba, 9999);
        }
        other => panic!("wrong kind: {other:?}"),
    }
    // A referenced extent outside the image is a strong corruption/tamper signal.
    assert!(f.severity >= Severity::High);
}

#[test]
fn out_of_bounds_file_does_not_crash_slack_audit() {
    // A non-sector-multiple size forces the slack audit to read the file's final
    // sector — which is past the image end. analyse() must DEGRADE GRACEFULLY
    // (skip the unreadable slack, still report the out-of-bounds extent) rather
    // than erroring out on a genuinely corrupt/truncated image.
    let img = make_iso_with_oob_file(3000);
    let a = analyse(&mut Cursor::new(img)).expect("analyse must not error on an unreadable extent");
    assert!(
        a.anomalies.iter().any(|x| x.code == "ISO-OOB-EXTENT"),
        "corrupt extent must still be reported: {:?}",
        a.anomalies
    );
}

#[test]
fn out_of_bounds_directory_does_not_crash_walk() {
    // A subdirectory whose extent is past the image must not crash traversal:
    // walk() lists the entry but does not descend into the unreadable subtree,
    // and analyse() reports the out-of-bounds extent rather than erroring.
    let img = make_iso_with_oob_dir();
    // Direct walk() must succeed and still list the OOB directory entry.
    let mut r = IsoReader::open(Cursor::new(img.clone())).expect("open");
    let entries = r.walk().expect("walk must not error on an unreadable subtree");
    assert!(entries.iter().any(|e| e.path.contains("SECRET")), "OOB dir must still be listed");
    // analyse() must report it rather than erroring out.
    let a =
        analyse(&mut Cursor::new(img)).expect("analyse must not error on an unreadable subtree");
    assert!(
        a.anomalies.iter().any(|x| x.code == "ISO-OOB-EXTENT"),
        "out-of-bounds directory must be reported: {:?}",
        a.anomalies
    );
}

#[test]
fn el_torito_boot_provenance_is_captured() {
    // eltorito.iso has one bootable X86 (BIOS) entry whose boot image is at
    // LBA 34. The provenance summary must surface boot capability + location.
    let img = std::fs::read(format!("{DATA}/eltorito.iso")).expect("eltorito.iso fixture");
    let a = analyse(&mut Cursor::new(img)).expect("analyse");
    assert_eq!(a.volume.boot_entries.len(), 1, "{:?}", a.volume.boot_entries);
    let b = &a.volume.boot_entries[0];
    assert!(b.bootable);
    assert_eq!(b.load_lba, 34);
    assert!(
        b.platform.to_ascii_uppercase().contains("X86")
            || b.platform.to_ascii_uppercase().contains("BIOS"),
        "platform: {}",
        b.platform
    );
}

#[test]
fn non_bootable_iso_has_no_boot_entries() {
    // rock_ridge.iso is not bootable.
    let a = analyse(&mut Cursor::new(rr())).expect("analyse");
    assert!(a.volume.boot_entries.is_empty(), "{:?}", a.volume.boot_entries);
}

#[test]
fn overlapping_extents_are_flagged() {
    // Two files whose data extents partially overlap (share a sector without
    // being identical) — consistent with corruption or one file concealed in
    // another's allocated space. Benign identical-extent dedup is excluded.
    let img = make_iso_with_overlapping_files();
    let a = analyse(&mut Cursor::new(img)).expect("analyse");
    let f = a
        .anomalies
        .iter()
        .find(|x| x.code == "ISO-OVERLAP-EXTENT")
        .expect("overlapping extents should be flagged");
    match &f.kind {
        AnomalyKind::OverlappingExtents { path, overlaps_path, .. } => {
            assert!(path.contains("FILEB") && overlaps_path.contains("FILEA"), "{:?}", f.kind);
        }
        other => panic!("wrong kind: {other:?}"),
    }
    assert!(f.severity >= Severity::High);
}

/// Build an ISO with two files whose extents partially overlap: FILEA spans
/// sectors 19-20 and FILEB spans 20-21 (sharing sector 20, but not identical).
fn make_iso_with_overlapping_files() -> Vec<u8> {
    const S: usize = 2048;
    let mut img = vec![0u8; 22 * S];
    let p = &mut img[16 * S..17 * S];
    p[0] = 0x01;
    p[1..6].copy_from_slice(b"CD001");
    p[6] = 0x01;
    p[80..84].copy_from_slice(&22u32.to_le_bytes());
    p[84..88].copy_from_slice(&22u32.to_be_bytes());
    p[128..130].copy_from_slice(&2048u16.to_le_bytes());
    p[130..132].copy_from_slice(&2048u16.to_be_bytes());
    p[132..136].copy_from_slice(&10u32.to_le_bytes());
    p[136..140].copy_from_slice(&10u32.to_be_bytes());
    p[140..144].copy_from_slice(&1u32.to_le_bytes()); // l_path_table_lba = 1
    p[156] = 34;
    p[158..162].copy_from_slice(&18u32.to_le_bytes());
    p[162..166].copy_from_slice(&18u32.to_be_bytes());
    p[166..170].copy_from_slice(&2048u32.to_le_bytes());
    p[170..174].copy_from_slice(&2048u32.to_be_bytes());
    p[181] = 0x02;
    p[188] = 1;
    let t = &mut img[17 * S..18 * S];
    t[0] = 0xFF;
    t[1..6].copy_from_slice(b"CD001");
    t[6] = 0x01;
    {
        let pt = &mut img[S..2 * S];
        pt[0] = 1;
        pt[2..6].copy_from_slice(&18u32.to_le_bytes());
        pt[6..8].copy_from_slice(&1u16.to_le_bytes());
        pt[8] = 0x00;
    }
    // Root directory (sector 18): ".", "..", FILEA (lba 19, 4096B), FILEB (lba 20, 4096B).
    let mut off = 18 * S;
    off += dir_rec(&mut img, off, 18, 2048, true, &[0x00]);
    off += dir_rec(&mut img, off, 18, 2048, true, &[0x01]);
    off += dir_rec(&mut img, off, 19, 4096, false, b"FILEA");
    dir_rec(&mut img, off, 20, 4096, false, b"FILEB");
    img
}

/// Build a minimal ISO whose root links a subdirectory "SECRET" with an extent
/// LBA (9999) far beyond the 19-sector image — the subtree is unreadable.
fn make_iso_with_oob_dir() -> Vec<u8> {
    const S: usize = 2048;
    let mut img = vec![0u8; 19 * S];
    // PVD at sector 16.
    let p = &mut img[16 * S..17 * S];
    p[0] = 0x01;
    p[1..6].copy_from_slice(b"CD001");
    p[6] = 0x01;
    p[80..84].copy_from_slice(&19u32.to_le_bytes());
    p[84..88].copy_from_slice(&19u32.to_be_bytes());
    p[128..130].copy_from_slice(&2048u16.to_le_bytes());
    p[130..132].copy_from_slice(&2048u16.to_be_bytes());
    p[132..136].copy_from_slice(&10u32.to_le_bytes()); // path_table_size (root only)
    p[136..140].copy_from_slice(&10u32.to_be_bytes());
    p[140..144].copy_from_slice(&1u32.to_le_bytes()); // l_path_table_lba = 1
                                                      // m_path_table_lba left 0 → L/M endian audit skips
    p[156] = 34;
    p[158..162].copy_from_slice(&18u32.to_le_bytes()); // root lba 18
    p[162..166].copy_from_slice(&18u32.to_be_bytes());
    p[166..170].copy_from_slice(&2048u32.to_le_bytes());
    p[170..174].copy_from_slice(&2048u32.to_be_bytes());
    p[181] = 0x02;
    p[188] = 1;
    // VD terminator at sector 17.
    let t = &mut img[17 * S..18 * S];
    t[0] = 0xFF;
    t[1..6].copy_from_slice(b"CD001");
    t[6] = 0x01;
    // L-path table (sector 1): root only.
    {
        let pt = &mut img[S..2 * S];
        pt[0] = 1;
        pt[2..6].copy_from_slice(&18u32.to_le_bytes());
        pt[6..8].copy_from_slice(&1u16.to_le_bytes());
        pt[8] = 0x00;
    }
    // Root directory (sector 18): ".", "..", subdir "SECRET" @ LBA 9999 (OOB).
    let mut off = 18 * S;
    off += dir_rec(&mut img, off, 18, 2048, true, &[0x00]);
    off += dir_rec(&mut img, off, 18, 2048, true, &[0x01]);
    dir_rec(&mut img, off, 9999, 2048, true, b"SECRET");
    img
}

/// Build a minimal ISO whose root holds a file "BIG.TXT" with an extent LBA
/// (9999) far beyond the 19-sector image, of the given `size`. A size that is
/// an exact sector multiple keeps the slack audit from reading the unreadable
/// extent; a non-multiple size forces that read.
fn make_iso_with_oob_file(size: u32) -> Vec<u8> {
    const S: usize = 2048;
    let mut img = vec![0u8; 19 * S];
    // PVD at sector 16.
    let p = &mut img[16 * S..17 * S];
    p[0] = 0x01;
    p[1..6].copy_from_slice(b"CD001");
    p[6] = 0x01;
    p[80..84].copy_from_slice(&19u32.to_le_bytes());
    p[84..88].copy_from_slice(&19u32.to_be_bytes());
    p[128..130].copy_from_slice(&2048u16.to_le_bytes());
    p[130..132].copy_from_slice(&2048u16.to_be_bytes());
    p[132..136].copy_from_slice(&10u32.to_le_bytes()); // path_table_size (root only)
    p[136..140].copy_from_slice(&10u32.to_be_bytes());
    p[140..144].copy_from_slice(&1u32.to_le_bytes()); // l_path_table_lba = 1
                                                      // m_path_table_lba left 0 → L/M endian audit skips
    p[156] = 34;
    p[158..162].copy_from_slice(&18u32.to_le_bytes()); // root lba 18
    p[162..166].copy_from_slice(&18u32.to_be_bytes());
    p[166..170].copy_from_slice(&2048u32.to_le_bytes());
    p[170..174].copy_from_slice(&2048u32.to_be_bytes());
    p[181] = 0x02;
    p[188] = 1;
    // VD terminator at sector 17.
    let t = &mut img[17 * S..18 * S];
    t[0] = 0xFF;
    t[1..6].copy_from_slice(b"CD001");
    t[6] = 0x01;
    // L-path table (sector 1): root only.
    {
        let pt = &mut img[S..2 * S];
        pt[0] = 1;
        pt[2..6].copy_from_slice(&18u32.to_le_bytes());
        pt[6..8].copy_from_slice(&1u16.to_le_bytes());
        pt[8] = 0x00;
    }
    // Root directory (sector 18): ".", "..", file "BIG.TXT" @ LBA 9999 (OOB).
    let mut off = 18 * S;
    off += dir_rec(&mut img, off, 18, 2048, true, &[0x00]);
    off += dir_rec(&mut img, off, 18, 2048, true, &[0x01]);
    dir_rec(&mut img, off, 9999, size, false, b"BIG.TXT");
    img
}
