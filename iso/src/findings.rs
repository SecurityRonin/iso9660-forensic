//! ISO 9660 forensic findings: severity, anomaly classification, and the
//! analysis result.
//!
//! Mirrors the sibling partition crates (`gpt-forensic` / `mbr-forensic` /
//! `apm-forensic`): every anomaly's severity, stable machine-readable code, and
//! human-readable note are *derived* from its [`AnomalyKind`], so they cannot
//! drift. A disk-forensic orchestrator can aggregate these uniformly with the
//! findings from the partition and other filesystem layers.

use core::fmt;

/// Severity of an ISO 9660 forensic finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum Severity {
    /// Informational — provenance/context, not suspicious on its own.
    Info,
    /// Low — minor irregularity with a common benign explanation.
    Low,
    /// Medium — notable irregularity worth examiner attention.
    Medium,
    /// High — strong indicator of tampering or concealment.
    High,
    /// Critical — structural contradiction; the image cannot be trusted as-is.
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        })
    }
}

/// Classification of an ISO 9660 forensic anomaly.
///
/// Each variant carries the evidence needed to reproduce the observation. The
/// `benign` / suspicious framing lives in [`AnomalyKind::note`]: an anomaly is
/// an *observation*, never an assertion of intent.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum AnomalyKind {
    /// A both-endian numeric field's little-endian and big-endian copies
    /// disagree — ECMA-119 stores them redundantly, so a mismatch is a strong
    /// tamper/corruption signal (an editor updated one copy but not the other).
    BothEndianMismatch {
        /// Where the field lives (e.g. `PVD`, or a directory record path).
        context: String,
        /// ECMA-119 field name (e.g. `volume_space_size`, `entry_lba`).
        field: String,
        /// Absolute byte offset of the field in the image.
        byte_offset: u64,
        /// Value read from the little-endian copy.
        le: u64,
        /// Value read from the big-endian copy.
        be: u64,
    },

    /// Non-zero data in the reserved system area (logical sectors 0–15, before
    /// the ISO 9660 PVD). Consistent with legitimate boot code (isohybrid MBR /
    /// APM on a hybrid disc) when opaque, or with a stashed payload when it
    /// carries a recognizable file magic.
    PreSystemData {
        /// System-area sector (0–15) holding the data.
        sector: u8,
        /// Detected content type: `non-zero`, `MZ/PE`, `ELF`, `ZIP`, `PDF`, `7z`.
        kind: String,
    },

    /// A file's final-sector slack (the unused tail after its data, since files
    /// occupy whole 2048-byte sectors) contains non-zero bytes — data the ISO
    /// 9660 structures do not account for. Consistent with leaked buffer/RAM
    /// fragments from the mastering host (often benign: the tool simply did not
    /// zero-fill) or, rarely, deliberately hidden bytes.
    SlackData {
        /// Path of the file whose slack is non-zero.
        entry_path: String,
        /// LBA of the file's data extent.
        lba: u32,
        /// Number of slack bytes in the file's final sector.
        slack_bytes: u32,
    },

    /// The image extends past the volume's declared end (`volume_space_size`)
    /// and the trailing region contains non-zero bytes — data exists where the
    /// ISO 9660 structures account for none. Consistent with an appended payload
    /// (polyglot file, hidden archive) or a wrapping container; benign zero
    /// padding is *not* reported.
    TrailingData {
        /// Declared volume size in bytes (`volume_space_size` × physical sector).
        declared_bytes: u64,
        /// Total image size in bytes.
        image_bytes: u64,
        /// Non-accounted bytes past the declared volume end.
        trailing_bytes: u64,
    },
}

impl AnomalyKind {
    /// Severity assigned to this kind — the single source of truth.
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self {
            AnomalyKind::BothEndianMismatch { .. } => Severity::High,
            AnomalyKind::TrailingData { .. } => Severity::Medium,
            AnomalyKind::SlackData { .. } => Severity::Low,
            // Opaque bytes can be legitimate boot code; a recognizable
            // executable/archive magic in the reserved area is more notable.
            AnomalyKind::PreSystemData { kind, .. } => {
                if kind == "non-zero" {
                    Severity::Low
                } else {
                    Severity::Medium
                }
            }
        }
    }

    /// Stable machine-readable code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            AnomalyKind::BothEndianMismatch { .. } => "ISO-BOTH-ENDIAN",
            AnomalyKind::TrailingData { .. } => "ISO-TRAILING-DATA",
            AnomalyKind::SlackData { .. } => "ISO-SLACK-DATA",
            AnomalyKind::PreSystemData { .. } => "ISO-PRESYS-DATA",
        }
    }

    /// Human-readable description (observation, not a conclusion).
    #[must_use]
    pub fn note(&self) -> String {
        match self {
            AnomalyKind::BothEndianMismatch { context, field, le, be, byte_offset } => format!(
                "{context} field `{field}` (byte {byte_offset}): little-endian copy ({le}) disagrees \
                 with its big-endian copy ({be}) — ECMA-119 stores both redundantly; a mismatch is \
                 consistent with editing one copy (tampering) or with single-bit corruption"
            ),
            AnomalyKind::TrailingData { declared_bytes, image_bytes, trailing_bytes } => format!(
                "image is {image_bytes} bytes but the volume declares only {declared_bytes} — \
                 {trailing_bytes} non-zero bytes past the volume end are unaccounted for by the ISO \
                 9660 structures; consistent with an appended payload (polyglot / hidden archive) or \
                 a wrapping container"
            ),
            AnomalyKind::SlackData { entry_path, lba, slack_bytes } => format!(
                "file `{entry_path}` (LBA {lba}) has {slack_bytes} non-zero slack bytes in its final \
                 sector — data unaccounted for by the file size; consistent with buffer/RAM fragments \
                 leaked by the mastering host (often benign: not zero-filled) or hidden bytes"
            ),
            AnomalyKind::PreSystemData { sector, kind } => format!(
                "reserved system-area sector {sector} (before the PVD) holds {kind} data — consistent \
                 with legitimate boot code (isohybrid MBR / Apple driver) when opaque, or with a \
                 stashed payload when it carries a file magic"
            ),
        }
    }
}

/// A single ISO 9660 anomaly with derived severity/code/note.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Anomaly {
    /// Severity, derived from `kind`.
    pub severity: Severity,
    /// Stable machine-readable code, derived from `kind`.
    pub code: &'static str,
    /// The classified anomaly with its evidence.
    pub kind: AnomalyKind,
    /// Human-readable note, derived from `kind`.
    pub note: String,
}

impl Anomaly {
    /// Build an [`Anomaly`], deriving severity/code/note from `kind` so they
    /// cannot drift from the classification.
    #[must_use]
    pub fn new(kind: AnomalyKind) -> Self {
        Anomaly { severity: kind.severity(), code: kind.code(), note: kind.note(), kind }
    }
}

impl fmt::Display for Anomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.severity, self.code, self.note)
    }
}
