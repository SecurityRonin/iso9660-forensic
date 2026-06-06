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
    let (volume, declared_sectors, phys, be_mismatches) = {
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
        (volume, u64::from(iso.volume_space_size()), iso.sector_mode().physical_sector_size(), be)
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

fn fmt_dt(dt: &IsoDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second
    )
}
