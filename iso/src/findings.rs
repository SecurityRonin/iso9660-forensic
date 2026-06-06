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

    /// A file whose recording datetime is later than the volume's creation date
    /// — impossible in a single mastering pass (files predate the finalized
    /// volume). Consistent with a file added after mastering or a backdated
    /// volume-creation date.
    FileAfterVolume {
        /// Path of the offending file.
        entry_path: String,
        /// The file's recording datetime (`YYYY-MM-DD HH:MM:SS`).
        file_time: String,
        /// The volume creation datetime (`YYYY-MM-DD HH:MM:SS`).
        volume_time: String,
    },

    /// A file's data extent appears in only one of the two directory trees
    /// (primary ISO 9660 vs Joliet) on a hybrid disc. Both trees normally
    /// describe the same files, so an extent in one only is consistent with a
    /// file deliberately hidden from one OS's view.
    TreeDivergence {
        /// Which tree the extent is unique to: `primary-only` or `joliet-only`.
        tree: String,
        /// Data extent LBA seen in only that tree.
        lba: u32,
        /// Path of the entry in that tree (Joliet paths are raw, not decoded).
        path: String,
    },

    /// A directory present in only one of ISO 9660's two redundant directory
    /// indexes — the path table or the walked directory tree. `phantom` =
    /// path-table-only (unreachable from the tree); `ghost` = tree-only (absent
    /// from the path table). Either is consistent with one index being edited.
    PathTableDivergence {
        /// `phantom` (path-table-only) or `ghost` (tree-only).
        direction: String,
        /// LBA of the directory extent unique to one index.
        lba: u32,
    },

    /// The Type-L (little-endian) and Type-M (big-endian) path tables — ISO
    /// 9660's two redundant byte-order copies of the directory index — disagree
    /// on an entry. Consistent with editing one copy (tools differ on which
    /// table they trust, yielding an OS-specific view) or with corruption.
    PathTableEndianDivergence {
        /// 0-based index of the diverging path-table entry.
        index: usize,
        /// Description of the discrepancy (field, L value, M value).
        description: String,
    },

    /// A file with a document/media extension whose content begins with an
    /// executable magic (PE/ELF/Mach-O). A document extension never legitimately
    /// holds an executable, so this is consistent with a disguised or dropped
    /// payload. (Detection is the ISO-layer magic only; deep executable analysis
    /// belongs to a dedicated PE/ELF analyzer.)
    DisguisedExecutable {
        /// Path of the disguised file.
        entry_path: String,
        /// Detected executable format: `PE`, `ELF`, or `Mach-O`.
        format: String,
        /// The misleading filename extension (lowercase).
        claimed_ext: String,
    },

    /// Raw 2352-byte Mode-1 sectors whose stored EDC does not match the EDC
    /// computed over their data. A genuine optical dump carries valid EDC;
    /// invalid or zero EDC is consistent with a synthesized/repackaged image
    /// (not a faithful drive dump) or with data tampered without recomputing it.
    EdcInvalid {
        /// Mode-1 sectors whose EDC was checked.
        sectors_checked: u32,
        /// Of those, how many had a mismatching EDC.
        sectors_invalid: u32,
        /// LBA of the first sector with an invalid EDC.
        first_invalid_lba: u32,
    },

    /// The same file (matched by data extent) is named differently in the
    /// Rock Ridge (Unix) and Joliet (Windows) long-name namespaces. The two
    /// should agree; a divergence presents a different filename to different
    /// operating systems, consistent with concealment. The ISO 9660 8.3 short
    /// name is reported as evidence but is legitimately mangled, so it never
    /// triggers this on its own.
    NameDivergence {
        /// Data extent LBA the names share.
        lba: u32,
        /// ISO 9660 8.3 name (evidence; may be mangled).
        iso_name: String,
        /// Joliet (UCS-2) decoded name.
        joliet_name: String,
        /// Rock Ridge `NM` POSIX name.
        rock_ridge_name: String,
    },

    /// A directory whose extent is one of its own ancestors — a directory
    /// cycle. Consistent with corruption or a deliberate structure that makes
    /// naive recursive tools loop forever (a denial-of-service vector).
    DirectoryCycle {
        /// Path of the directory entry that closes the loop.
        entry_path: String,
        /// The ancestor extent LBA it points back to.
        lba: u32,
    },

    /// Two entries whose data extents partially overlap (share sectors without
    /// being an identical extent). Distinct files occupy distinct extents, so a
    /// partial overlap is consistent with corruption or with one file concealed
    /// inside another's allocated space. Identical-extent deduplication (a common
    /// benign optimisation) is excluded.
    OverlappingExtents {
        /// Path of the entry.
        path: String,
        /// Its extent start LBA.
        lba: u32,
        /// Path of the entry it overlaps.
        overlaps_path: String,
        /// That entry's extent start LBA.
        overlaps_lba: u32,
    },

    /// A PVD field that ECMA-119 mandates be zero holds non-zero bytes.
    /// Consistent with a proprietary mastering-tool fingerprint (often benign)
    /// or with data deliberately stashed in unused structure (steganography).
    ReservedFieldData {
        /// Human-readable name of the reserved region.
        region: String,
        /// Byte offset of the region within the PVD sector.
        pvd_offset: u32,
        /// Count of non-zero bytes found in the region.
        nonzero_bytes: u32,
    },

    /// A file present in an earlier session but no longer referenced by the
    /// active session's tree (or pointing to a different extent there). The
    /// earlier extent is still readable — recoverable content consistent with a
    /// deletion or a replaced multisession write.
    SupersededFile {
        /// Path of the file in the earlier session.
        entry_path: String,
        /// Index of the earlier session holding it (0 = oldest).
        session: usize,
        /// Extent LBA in that earlier session (the recoverable data).
        lba: u32,
        /// `deleted` (absent from the active tree) or `replaced` (active points
        /// to a different extent).
        status: String,
    },

    /// A file or directory whose data extent points beyond the readable image.
    /// The referenced sectors cannot be read; consistent with image truncation,
    /// corruption of the extent pointer, or a dangling reference to content that
    /// was removed or never present.
    OutOfBoundsExtent {
        /// Path of the entry whose extent is out of bounds.
        entry_path: String,
        /// Extent start LBA (sector index).
        lba: u32,
        /// Declared extent size in bytes.
        size: u32,
        /// Total sectors the image actually holds.
        image_sectors: u32,
    },

    /// A volume creation/modification date before the optical era (year < 1985)
    /// — impossible for the volume itself (unlike a file's preserved old mtime).
    /// Consistent with a falsified, zeroed, or epoch-leaked volume date.
    ImplausibleVolumeDate {
        /// `creation` or `modification`.
        which: String,
        /// The implausible year.
        year: u16,
    },

    /// The volume's timestamps use more than one distinct UTC offset —
    /// consistent with files gathered across multiple timezones or hosts, or a
    /// finalization host in a different zone than the source files.
    MixedTimezones {
        /// Distinct GMT offsets seen (15-minute units, signed).
        offsets: Vec<i8>,
    },

    /// A file living in a directory that the path table references but the
    /// active directory tree cannot reach — recoverable content the normal view
    /// hides. Consistent with deletion, an interrupted/replaced write
    /// (multisession), or deliberate concealment.
    OrphanedFile {
        /// File name within the orphaned directory.
        name: String,
        /// LBA of the file's data extent.
        lba: u32,
        /// File size in bytes.
        size: u32,
        /// LBA of the orphaned (unreachable) directory extent.
        parent_lba: u32,
    },

    /// A Rock Ridge symbolic link whose target escapes the volume (`..`
    /// traversal) or is absolute. Traversal is an extraction/escape hazard;
    /// an absolute target leaks the source host's directory layout.
    SymlinkAnomaly {
        /// Path of the symlink entry.
        entry_path: String,
        /// Resolved link target.
        target: String,
        /// `path-traversal` or `absolute`.
        issue: String,
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
            AnomalyKind::OrphanedFile { .. } => Severity::Medium,
            AnomalyKind::FileAfterVolume { .. } => Severity::Medium,
            AnomalyKind::MixedTimezones { .. } => Severity::Low,
            AnomalyKind::ImplausibleVolumeDate { .. } => Severity::Medium,
            AnomalyKind::TreeDivergence { .. } => Severity::High,
            // A ghost dir (tree-only) means the mandatory path-table index was
            // edited to omit it — stronger than a phantom (recoverable) dir.
            AnomalyKind::PathTableDivergence { direction, .. } => {
                if direction == "ghost" {
                    Severity::High
                } else {
                    Severity::Medium
                }
            }
            AnomalyKind::PathTableEndianDivergence { .. } => Severity::High,
            AnomalyKind::OutOfBoundsExtent { .. } => Severity::High,
            AnomalyKind::SupersededFile { .. } => Severity::Medium,
            AnomalyKind::ReservedFieldData { .. } => Severity::Low,
            AnomalyKind::OverlappingExtents { .. } => Severity::High,
            AnomalyKind::DirectoryCycle { .. } => Severity::High,
            AnomalyKind::NameDivergence { .. } => Severity::High,
            AnomalyKind::EdcInvalid { .. } => Severity::Medium,
            AnomalyKind::DisguisedExecutable { .. } => Severity::High,
            // Traversal can escape extraction; an absolute target merely leaks a path.
            AnomalyKind::SymlinkAnomaly { issue, .. } => {
                if issue == "path-traversal" {
                    Severity::High
                } else {
                    Severity::Low
                }
            }
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
            AnomalyKind::SymlinkAnomaly { .. } => "ISO-SYMLINK",
            AnomalyKind::OrphanedFile { .. } => "ISO-ORPHAN-FILE",
            AnomalyKind::FileAfterVolume { .. } => "ISO-TIME-AFTER-VOL",
            AnomalyKind::MixedTimezones { .. } => "ISO-MIXED-TZ",
            AnomalyKind::ImplausibleVolumeDate { .. } => "ISO-TIME-IMPLAUSIBLE",
            AnomalyKind::TreeDivergence { .. } => "ISO-TREE-DIVERGENCE",
            AnomalyKind::PathTableDivergence { .. } => "ISO-PATHTABLE-DIVERGENCE",
            AnomalyKind::PathTableEndianDivergence { .. } => "ISO-PATHTABLE-ENDIAN",
            AnomalyKind::OutOfBoundsExtent { .. } => "ISO-OOB-EXTENT",
            AnomalyKind::SupersededFile { .. } => "ISO-SUPERSEDED-FILE",
            AnomalyKind::ReservedFieldData { .. } => "ISO-RESERVED-DATA",
            AnomalyKind::OverlappingExtents { .. } => "ISO-OVERLAP-EXTENT",
            AnomalyKind::DirectoryCycle { .. } => "ISO-DIR-CYCLE",
            AnomalyKind::NameDivergence { .. } => "ISO-NAME-DIVERGENCE",
            AnomalyKind::EdcInvalid { .. } => "ISO-EDC-INVALID",
            AnomalyKind::DisguisedExecutable { .. } => "ISO-DISGUISED-EXEC",
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
            AnomalyKind::TreeDivergence { tree, lba, path } => format!(
                "data extent LBA {lba} (`{path}`) appears in the {tree} directory tree only — the \
                 primary and Joliet trees normally describe the same files, so this is consistent \
                 with a file hidden from one OS's view"
            ),
            AnomalyKind::PathTableEndianDivergence { index, description } => format!(
                "path-table entry {index}: {description} — ECMA-119 stores the path table in both \
                 little- and big-endian (Type-L and Type-M) and the two copies must be identical; \
                 a disagreement is consistent with editing one copy (an OS-specific view, since \
                 tools differ on which table they trust) or with corruption"
            ),
            AnomalyKind::DisguisedExecutable { entry_path, format, claimed_ext } => format!(
                "file `{entry_path}` has a `.{claimed_ext}` extension but its content begins with a \
                 {format} executable magic — a document/media extension never legitimately holds an \
                 executable; consistent with a disguised or dropped payload (deep analysis: hand to \
                 a dedicated PE/ELF analyzer)"
            ),
            AnomalyKind::EdcInvalid { sectors_checked, sectors_invalid, first_invalid_lba } => format!(
                "{sectors_invalid} of {sectors_checked} raw Mode-1 sectors have an EDC that does \
                 not match their data (first at LBA {first_invalid_lba}) — a genuine optical dump \
                 carries valid EDC, so this is consistent with a synthesized/repackaged image (not \
                 a faithful drive dump) or with data tampered without recomputing the EDC"
            ),
            AnomalyKind::NameDivergence { lba, iso_name, joliet_name, rock_ridge_name } => format!(
                "file at LBA {lba} is named `{rock_ridge_name}` via Rock Ridge (Unix) but \
                 `{joliet_name}` via Joliet (Windows) — the long-name namespaces describe the same \
                 file and should agree; a divergence presents a different filename per OS, \
                 consistent with concealment (ISO 9660 short name: `{iso_name}`)"
            ),
            AnomalyKind::DirectoryCycle { entry_path, lba } => format!(
                "directory `{entry_path}` points back to ancestor extent LBA {lba} — a directory \
                 cycle; consistent with corruption or a structure crafted to make naive recursive \
                 tools loop indefinitely (a denial-of-service vector)"
            ),
            AnomalyKind::OverlappingExtents { path, lba, overlaps_path, overlaps_lba } => format!(
                "file `{path}` (LBA {lba}) shares sectors with `{overlaps_path}` (LBA \
                 {overlaps_lba}) — distinct files must occupy distinct extents, so a partial \
                 overlap is consistent with corruption or with one file concealed inside another's \
                 allocated space"
            ),
            AnomalyKind::ReservedFieldData { region, pvd_offset, nonzero_bytes } => format!(
                "PVD reserved field {region} (offset {pvd_offset}) holds {nonzero_bytes} non-zero \
                 byte(s) — ECMA-119 mandates this field be zero; consistent with a proprietary \
                 mastering-tool fingerprint (often benign) or with data stashed in unused structure"
            ),
            AnomalyKind::SupersededFile { entry_path, session, lba, status } => format!(
                "file `{entry_path}` exists in earlier session {session} (extent LBA {lba}) but is \
                 {status} in the active session — multisession discs append a new tree per session, \
                 so the earlier extent remains readable; recoverable content consistent with a \
                 deletion or a replaced write"
            ),
            AnomalyKind::OutOfBoundsExtent { entry_path, lba, size, image_sectors } => format!(
                "`{entry_path}` extent starts at LBA {lba} ({size} bytes) but the image holds only \
                 {image_sectors} sectors — the extent points past readable data; consistent with \
                 image truncation, corruption of the extent pointer, or a dangling reference to \
                 content that was removed or never written"
            ),
            AnomalyKind::PathTableDivergence { direction, lba } => {
                if direction == "ghost" {
                    format!(
                        "directory extent LBA {lba} is reachable in the directory tree but absent \
                         from the path table — the path table must index every directory, so its \
                         omission is consistent with editing the path table to hide the directory \
                         from path-table-based navigation"
                    )
                } else {
                    format!(
                        "directory extent LBA {lba} is listed in the path table but is unreachable \
                         from the directory tree — consistent with an unlinked, superseded, or \
                         hidden folder; its contents may be recoverable"
                    )
                }
            }
            AnomalyKind::ImplausibleVolumeDate { which, year } => {
                let era = if *year < 1985 {
                    "before the optical era (< 1985)"
                } else {
                    "implausibly far in the future (> 2100)"
                };
                format!(
                    "volume {which} date is year {year}, {era} — impossible for the volume; \
                     consistent with a falsified, zeroed, epoch-leaked, or corrupt date"
                )
            }
            AnomalyKind::MixedTimezones { offsets } => {
                let hours: Vec<String> =
                    offsets.iter().map(|o| format!("UTC{:+}", f64::from(*o) / 4.0)).collect();
                format!(
                    "volume timestamps span {} distinct UTC offsets ({}) — consistent with files \
                     gathered across multiple timezones/hosts or finalized in a different zone",
                    offsets.len(),
                    hours.join(", ")
                )
            }
            AnomalyKind::FileAfterVolume { entry_path, file_time, volume_time } => format!(
                "file `{entry_path}` was recorded {file_time}, after the volume creation date \
                 {volume_time} — files normally predate volume finalization; consistent with a \
                 post-mastering addition or a backdated volume date"
            ),
            AnomalyKind::OrphanedFile { name, lba, size, parent_lba } => format!(
                "file `{name}` ({size} bytes at LBA {lba}) lives in directory extent LBA {parent_lba}, \
                 referenced by the path table but unreachable from the active tree — recoverable \
                 content consistent with deletion, a replaced multisession write, or concealment"
            ),
            AnomalyKind::SymlinkAnomaly { entry_path, target, issue } => format!(
                "symlink `{entry_path}` -> `{target}` ({issue}) — a `..` target can escape the \
                 extraction root; an absolute target leaks the source host's directory layout"
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
