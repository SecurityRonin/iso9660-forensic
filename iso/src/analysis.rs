//! Forensic analyzer entry point: [`analyse`].
//!
//! Mirrors the sibling partition crates' `analyse(reader) -> Analysis`
//! contract (`gpt-forensic`, `mbr-forensic`, `apm-forensic`) so a disk-forensic
//! orchestrator can report on an ISO 9660 volume uniformly alongside the
//! partition and other filesystem layers. It returns a [`IsoVolumeInfo`]
//! provenance summary (authoring-tool fingerprints, timestamps, extension flags)
//! plus a list of structural [`Anomaly`]s.
//!
//! This is a batch *analysis* surface, distinct from the navigation/mount
//! surface ([`IsoReader`]); both share the same parser underneath.

use std::io::{Read, Seek, SeekFrom};

use crate::findings::{Anomaly, AnomalyKind, Severity};
use crate::pvd::IsoDateTime;
use crate::{IsoError, IsoReader};

/// Options controlling [`analyse_with_options`]. Currently empty; reserved for
/// future toggles (slack carving, full directory-record redundancy walk, …).
#[derive(Debug, Clone, Copy, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct AnalyseOptions {}

/// Volume provenance summary — the authoring/context "breadcrumbs" a forensic
/// report leads with. All fields are observations from the active session's PVD.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct IsoVolumeInfo {
    pub volume_label: String,
    pub system_id: String,
    pub volume_set_id: String,
    pub publisher_id: String,
    /// Data preparer — usually the mastering tool's signature/version.
    pub data_preparer_id: String,
    pub application_id: String,
    /// Volume creation time, `YYYY-MM-DD HH:MM:SS`, if present.
    pub creation_time: Option<String>,
    /// Volume modification time, `YYYY-MM-DD HH:MM:SS`, if present.
    pub modification_time: Option<String>,
    /// Detected sector mode (e.g. `Iso2048`, `Raw2352`).
    pub sector_mode: String,
    /// Number of PVD sessions detected.
    pub session_count: usize,
    pub has_rock_ridge: bool,
    pub has_joliet: bool,
    pub has_enhanced_volume_descriptor: bool,
}

/// Result of a forensic analysis of an ISO 9660 volume.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct IsoAnalysis {
    /// Provenance / volume summary from the active PVD.
    pub volume: IsoVolumeInfo,
    /// Structural anomalies, in discovery order.
    pub anomalies: Vec<Anomaly>,
}

impl IsoAnalysis {
    /// The highest severity among all anomalies, or `None` when clean.
    #[must_use]
    pub fn max_severity(&self) -> Option<Severity> {
        self.anomalies.iter().map(|a| a.severity).max()
    }
}

/// Forensically analyse an ISO 9660 image.
///
/// # Errors
/// Returns [`IsoError`] if the image is not a readable ISO 9660 volume.
pub fn analyse<R: Read + Seek>(reader: &mut R) -> Result<IsoAnalysis, IsoError> {
    analyse_with_options(reader, AnalyseOptions::default())
}

/// Like [`analyse`], with explicit [`AnalyseOptions`].
///
/// # Errors
/// Returns [`IsoError`] if the image is not a readable ISO 9660 volume.
pub fn analyse_with_options<R: Read + Seek>(
    reader: &mut R,
    _opts: AnalyseOptions,
) -> Result<IsoAnalysis, IsoError> {
    // Total image size, for the trailing-data check below.
    let image_bytes = reader.seek(SeekFrom::End(0))?;
    reader.seek(SeekFrom::Start(0))?;

    // Gather the volume summary, both-endian mismatches, and the geometry needed
    // for the trailing-data check, then drop the IsoReader so we can re-read raw
    // bytes past the volume end.
    let (
        volume,
        declared_sectors,
        phys,
        be_mismatches,
        slack_hits,
        presys_hits,
        symlink_issues,
        lost_files,
        time_anomalies,
    ) = {
        let mut iso = IsoReader::open(&mut *reader)?;
        let volume = IsoVolumeInfo {
            volume_label: iso.volume_label().to_string(),
            system_id: iso.system_id().to_string(),
            volume_set_id: iso.volume_set_id().to_string(),
            publisher_id: iso.publisher_id().to_string(),
            data_preparer_id: iso.data_preparer_id().to_string(),
            application_id: iso.application_id().to_string(),
            creation_time: iso.volume_creation_time().map(fmt_dt),
            modification_time: iso.volume_modification_time().map(fmt_dt),
            sector_mode: format!("{:?}", iso.sector_mode()),
            session_count: iso.session_count(),
            has_rock_ridge: iso.has_rock_ridge(),
            has_joliet: iso.has_joliet(),
            has_enhanced_volume_descriptor: iso.has_enhanced_volume_descriptor(),
        };
        let be = iso.audit_both_endian()?;
        let slack: Vec<_> = iso.audit_file_slack()?.into_iter().filter(|s| s.nonzero).collect();
        let presys = iso.audit_pre_system()?;
        let symlinks = iso.audit_symlinks()?;
        let lost = iso.recover_lost_files()?;

        // Files recorded after the volume creation date (post-mastering add /
        // backdated volume). Compared as UTC instants so timezone offsets don't
        // cause false ordering.
        // Volume dates before the optical era are impossible for the volume
        // itself (year 0 = unset, skipped). 1985 ≈ first CD-ROMs.
        const OPTICAL_ERA_FLOOR: u16 = 1985;
        let mut time_anoms: Vec<Anomaly> = Vec::new();
        for (which, t) in [
            ("creation", iso.volume_creation_time().cloned()),
            ("modification", iso.volume_modification_time().cloned()),
        ] {
            if let Some(dt) = t {
                if (1..OPTICAL_ERA_FLOOR).contains(&dt.year) {
                    time_anoms.push(Anomaly::new(AnomalyKind::ImplausibleVolumeDate {
                        which: which.to_string(),
                        year: dt.year,
                    }));
                }
            }
        }
        if let Some(vt) = iso.volume_creation_time().cloned() {
            let vkey = utc_key(&vt);
            let mut tz_offsets = std::collections::BTreeSet::new();
            tz_offsets.insert(vt.tz_offset_15min);
            for e in iso.walk()? {
                if e.record.is_dir() {
                    continue;
                }
                if let Some(ft) = &e.record.recorded {
                    tz_offsets.insert(ft.tz_offset_15min);
                    if utc_key(ft) > vkey {
                        time_anoms.push(Anomaly::new(AnomalyKind::FileAfterVolume {
                            entry_path: e.path,
                            file_time: fmt_dt(ft),
                            volume_time: fmt_dt(&vt),
                        }));
                    }
                }
            }
            if tz_offsets.len() > 1 {
                time_anoms.push(Anomaly::new(AnomalyKind::MixedTimezones {
                    offsets: tz_offsets.into_iter().collect(),
                }));
            }
        }

        // Joliet ↔ primary divergence: on a hybrid disc both trees describe the
        // same files (shared data extents). A file extent in only one tree is
        // consistent with concealment from one OS's view.
        if iso.has_joliet() {
            let extents =
                |entries: Vec<crate::WalkEntry>| -> std::collections::BTreeMap<u32, String> {
                    entries
                        .into_iter()
                        .filter(|e| !e.record.is_dir() && e.record.size > 0)
                        .map(|e| (e.record.lba, e.path))
                        .collect()
                };
            let primary = extents(iso.walk()?);
            let joliet = extents(iso.walk_joliet()?);
            for (lba, path) in &primary {
                if !joliet.contains_key(lba) {
                    time_anoms.push(Anomaly::new(AnomalyKind::TreeDivergence {
                        tree: "primary-only".to_string(),
                        lba: *lba,
                        path: path.clone(),
                    }));
                }
            }
            for (lba, path) in &joliet {
                if !primary.contains_key(lba) {
                    time_anoms.push(Anomaly::new(AnomalyKind::TreeDivergence {
                        tree: "joliet-only".to_string(),
                        lba: *lba,
                        path: path.clone(),
                    }));
                }
            }
        }

        (
            volume,
            u64::from(iso.volume_space_size()),
            iso.sector_mode().physical_sector_size(),
            be,
            slack,
            presys,
            symlinks,
            lost,
            time_anoms,
        )
    };

    let mut anomalies = Vec::new();

    // Both-endian redundancy: reuse the (tested) audit, which reconciles the PVD
    // and directory-record both-endian copies, and map each mismatch to a
    // unified [`Anomaly`].
    for m in be_mismatches {
        anomalies.push(Anomaly::new(AnomalyKind::BothEndianMismatch {
            context: m.context,
            field: m.field,
            byte_offset: m.byte_offset,
            le: m.le_val,
            be: m.be_val,
        }));
    }

    // Non-zero file slack: leaked buffer/RAM fragments past a file's data.
    for s in slack_hits {
        anomalies.push(Anomaly::new(AnomalyKind::SlackData {
            entry_path: s.entry_path,
            lba: s.lba,
            slack_bytes: s.slack_bytes,
        }));
    }

    // Pre-system area (sectors 0–15) non-zero data.
    for p in presys_hits {
        anomalies.push(Anomaly::new(AnomalyKind::PreSystemData {
            sector: p.sector,
            kind: p.kind.to_string(),
        }));
    }

    // Rock Ridge symlink targets that escape the volume or leak host paths.
    for s in symlink_issues {
        anomalies.push(Anomaly::new(AnomalyKind::SymlinkAnomaly {
            entry_path: s.entry_path,
            target: s.target,
            issue: s.issue.to_string(),
        }));
    }

    // Files in orphaned directory extents (path-table dirs unreachable from the tree).
    for l in lost_files {
        anomalies.push(Anomaly::new(AnomalyKind::OrphanedFile {
            name: l.name,
            lba: l.lba,
            size: l.size,
            parent_lba: l.parent_lba,
        }));
    }

    // Files recorded after the volume creation date (built inside the scope above).
    anomalies.extend(time_anomalies);

    // Trailing data: bytes past the declared volume end. Only flagged when the
    // trailing region is non-zero (benign zero padding is ignored).
    let declared_bytes = declared_sectors.saturating_mul(phys);
    if image_bytes > declared_bytes && trailing_has_nonzero(reader, declared_bytes, image_bytes)? {
        anomalies.push(Anomaly::new(AnomalyKind::TrailingData {
            declared_bytes,
            image_bytes,
            trailing_bytes: image_bytes - declared_bytes,
        }));
    }

    Ok(IsoAnalysis { volume, anomalies })
}

/// True if the byte range `[start, end)` contains any non-zero byte.
fn trailing_has_nonzero<R: Read + Seek>(
    reader: &mut R,
    start: u64,
    end: u64,
) -> Result<bool, IsoError> {
    reader.seek(SeekFrom::Start(start))?;
    let mut remaining = end - start;
    let mut buf = [0u8; 65536];
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        reader.read_exact(&mut buf[..want])?;
        if buf[..want].iter().any(|&b| b != 0) {
            return Ok(true);
        }
        remaining -= want as u64;
    }
    Ok(false)
}

/// A comparable UTC-seconds key for an [`IsoDateTime`], normalising the stored
/// `tz_offset_15min` so two timestamps in different zones order correctly.
/// Uses Howard Hinnant's days-from-civil algorithm (proleptic Gregorian).
fn utc_key(dt: &IsoDateTime) -> i64 {
    let y = i64::from(dt.year);
    let m = i64::from(dt.month.max(1));
    let d = i64::from(dt.day.max(1));
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468; // days since 1970-01-01
    let local = days * 86_400
        + i64::from(dt.hour) * 3600
        + i64::from(dt.minute) * 60
        + i64::from(dt.second);
    // Stored times are local; subtract the GMT offset (15-minute units) to get UTC.
    local - i64::from(dt.tz_offset_15min) * 15 * 60
}

fn fmt_dt(dt: &IsoDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second
    )
}
