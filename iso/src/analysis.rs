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

/// One El Torito boot entry, summarised for the provenance report.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct BootRecord {
    /// Boot platform (e.g. `X86`, `EFI`, `Mac`, `Other`).
    pub platform: String,
    /// Whether the entry is marked bootable.
    pub bootable: bool,
    /// LBA of the boot image (for carving / hashing).
    pub load_lba: u32,
    /// Boot image length in virtual 512-byte sectors.
    pub sectors: u16,
}

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
    /// El Torito boot entries (empty if not bootable).
    pub boot_entries: Vec<BootRecord>,
    /// Distinct Rock Ridge `PX` owner UIDs across the tree (authoring account
    /// intel; empty without Rock Ridge), sorted ascending.
    pub rock_ridge_uids: Vec<u32>,
    /// Distinct Rock Ridge `PX` owner GIDs across the tree, sorted ascending.
    pub rock_ridge_gids: Vec<u32>,
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
        pt_divergence,
        pt_endian,
        time_anomalies,
    ) = {
        let mut iso = IsoReader::open(&mut *reader)?;
        // El Torito boot provenance (empty when not bootable). Computed before
        // the volume literal so its &mut borrow doesn't overlap the &self getters.
        let boot_entries: Vec<BootRecord> = iso
            .boot_entries()?
            .iter()
            .map(|b| BootRecord {
                platform: format!("{:?}", b.platform),
                bootable: b.bootable,
                load_lba: b.lba,
                sectors: b.sector_count,
            })
            .collect();
        let mut volume = IsoVolumeInfo {
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
            boot_entries,
            rock_ridge_uids: Vec::new(),
            rock_ridge_gids: Vec::new(),
        };

        // Rock Ridge PX owner identity: distinct uid/gid that authored the tree.
        {
            let mut uids = std::collections::BTreeSet::new();
            let mut gids = std::collections::BTreeSet::new();
            for e in iso.walk()? {
                if let Some(px) = crate::rock_ridge::posix_attrs(&e.record.system_use) {
                    uids.insert(px.uid);
                    gids.insert(px.gid);
                }
            }
            volume.rock_ridge_uids = uids.into_iter().collect();
            volume.rock_ridge_gids = gids.into_iter().collect();
        }
        let be = iso.audit_both_endian()?;
        let slack: Vec<_> = iso.audit_file_slack()?.into_iter().filter(|s| s.nonzero).collect();
        let presys = iso.audit_pre_system()?;
        let symlinks = iso.audit_symlinks()?;
        let lost = iso.recover_lost_files()?;

        // Path table vs directory tree: the path table is ISO 9660's redundant
        // flattened directory index and must agree with the walked tree. A
        // `phantom` dir is in the table but unreachable; a `ghost` dir is in the
        // tree but missing from the table — either is a one-sided edit.
        let pt = iso.audit_path_table()?;
        let pt_div: Vec<(String, u32)> = pt
            .phantom_lbas
            .iter()
            .map(|&lba| ("phantom".to_string(), lba))
            .chain(pt.ghost_lbas.iter().map(|&lba| ("ghost".to_string(), lba)))
            .collect();

        // L-path-table (little-endian) vs M-path-table (big-endian): the two
        // redundant copies of the directory index must be identical.
        let pt_endian = iso.audit_path_table_endian()?;

        // Non-zero PVD reserved fields (ECMA-119 mandates zero) — a tool
        // fingerprint or data stashed in unused structure.
        let mut pvd_reserved: Vec<Anomaly> = Vec::new();
        {
            let pvd_lba = *iso.session_pvd_lbas.last().unwrap_or(&16);
            let raw = iso.read_sector_raw(pvd_lba)?;
            for (region, start, end) in [
                ("byte 7 (unused)", 7usize, 8usize),
                ("byte 882 (unused)", 882, 883),
                ("reserved tail", 1395, 2048),
            ] {
                let nz = raw[start..end].iter().filter(|&&b| b != 0).count();
                if nz > 0 {
                    pvd_reserved.push(Anomaly::new(AnomalyKind::ReservedFieldData {
                        region: region.to_string(),
                        pvd_offset: start as u32,
                        nonzero_bytes: nz as u32,
                    }));
                }
            }
        }

        // Three-namespace name divergence: a file's Rock Ridge (Unix) and Joliet
        // (Windows) long names must agree. The ISO 8.3 short name is evidence
        // only (legitimately mangled). Matched by shared data extent LBA.
        let mut name_div: Vec<Anomaly> = Vec::new();
        if iso.has_joliet() {
            let norm = |s: &str| -> String {
                let s = s.trim();
                s.rsplit_once(';').map_or(s, |(a, _)| a).to_ascii_lowercase()
            };
            let mut prim: std::collections::HashMap<u32, (String, String)> =
                std::collections::HashMap::new();
            for e in iso.walk()? {
                if e.record.is_dir() {
                    continue;
                }
                if let Some(rr) = crate::rock_ridge::alternate_name(&e.record.system_use) {
                    prim.entry(e.record.lba).or_insert((e.record.iso_name(), rr));
                }
            }
            for e in iso.walk_joliet()? {
                if e.record.is_dir() {
                    continue;
                }
                let jol = e.record.joliet_name();
                if let Some((iso_n, rr)) = prim.get(&e.record.lba) {
                    if norm(rr) != norm(&jol) {
                        name_div.push(Anomaly::new(AnomalyKind::NameDivergence {
                            lba: e.record.lba,
                            iso_name: iso_n.clone(),
                            joliet_name: jol,
                            rock_ridge_name: rr.clone(),
                        }));
                    }
                }
            }
        }

        // Disguised executables: a file with a document/media extension whose
        // content begins with an executable magic (concealment). ISO-layer magic
        // check only; deep analysis is a dedicated PE/ELF analyzer's job.
        let mut disguised: Vec<Anomaly> = Vec::new();
        {
            const DOC_EXTS: &[&str] = &[
                "txt", "doc", "docx", "pdf", "jpg", "jpeg", "png", "gif", "csv", "xml", "html",
                "htm", "md", "rtf", "log", "json", "bmp", "tif", "tiff",
            ];
            for e in iso.walk()? {
                if e.record.is_dir() || e.record.size < 4 {
                    continue;
                }
                let lower = e.path.to_ascii_lowercase();
                let Some(ext) = lower.rsplit('.').next().filter(|_| lower.contains('.')) else {
                    continue;
                };
                if !DOC_EXTS.contains(&ext) {
                    continue;
                }
                let Ok(hdr) = iso.read_sector_raw(u64::from(e.record.lba)) else {
                    continue;
                };
                if let Some(format) = exe_magic(&hdr) {
                    disguised.push(Anomaly::new(AnomalyKind::DisguisedExecutable {
                        entry_path: e.path,
                        format: format.to_string(),
                        claimed_ext: ext.to_string(),
                    }));
                }
            }
        }

        // Directory cycles: a directory whose extent is one of its own
        // ancestors. Detected from the (cycle-safe) walk output by checking each
        // directory against the extent LBAs of its path ancestors.
        let mut dir_cycles: Vec<Anomaly> = Vec::new();
        {
            let entries = iso.walk()?;
            let mut dir_lba: std::collections::HashMap<String, u32> =
                std::collections::HashMap::new();
            dir_lba.insert(String::new(), iso.pvd.root_dir_lba);
            for e in &entries {
                if e.record.is_dir() {
                    dir_lba.insert(e.path.clone(), e.record.lba);
                }
            }
            for e in &entries {
                if !e.record.is_dir() {
                    continue;
                }
                let parts: Vec<&str> = e.path.split('/').collect();
                // Proper ancestors only (exclude the entry's own full path).
                let cycles_back = (0..parts.len()).any(|i| {
                    let anc = parts[..i].join("/");
                    dir_lba.get(&anc) == Some(&e.record.lba)
                });
                if cycles_back {
                    dir_cycles.push(Anomaly::new(AnomalyKind::DirectoryCycle {
                        entry_path: e.path.clone(),
                        lba: e.record.lba,
                    }));
                }
            }
        }

        // Overlapping extents: distinct files must occupy distinct extents. A
        // partial overlap (intersecting, not identical) is consistent with
        // corruption or concealment; identical-extent dedup is benign and
        // excluded. Running-coverage sweep keeps this O(n log n).
        let mut overlaps: Vec<Anomaly> = Vec::new();
        {
            let mut exts: Vec<(u32, u32, String)> = iso
                .walk()?
                .into_iter()
                .filter(|e| !e.record.is_dir() && e.record.size > 0)
                .map(|e| {
                    let start = e.record.lba;
                    let sectors =
                        u32::try_from(u64::from(e.record.size).div_ceil(2048)).unwrap_or(u32::MAX);
                    (start, start.saturating_add(sectors), e.path)
                })
                .collect();
            exts.sort();
            let mut cover: Option<(u32, u32, String)> = None;
            for (start, end, path) in exts {
                if let Some((cs, ce, cpath)) = cover.as_ref() {
                    if start < *ce && !(start == *cs && end == *ce) {
                        overlaps.push(Anomaly::new(AnomalyKind::OverlappingExtents {
                            path: path.clone(),
                            lba: start,
                            overlaps_path: cpath.clone(),
                            overlaps_lba: *cs,
                        }));
                    }
                }
                if cover.as_ref().is_none_or(|(_, ce, _)| end > *ce) {
                    cover = Some((start, end, path));
                }
            }
        }

        // Superseded content across sessions: a file present in an earlier
        // session but no longer referenced by the active tree (or pointing to a
        // different extent) remains readable from that earlier session.
        let mut superseded: Vec<Anomaly> = Vec::new();
        let session_n = iso.session_count();
        if session_n > 1 {
            let active: std::collections::HashMap<String, u32> = iso
                .walk()?
                .into_iter()
                .filter(|e| !e.record.is_dir())
                .map(|e| (e.path, e.record.lba))
                .collect();
            for idx in 0..session_n - 1 {
                for e in iso.walk_session(idx)? {
                    if e.record.is_dir() {
                        continue;
                    }
                    let status = match active.get(&e.path) {
                        None => "deleted",
                        Some(&l) if l != e.record.lba => "replaced",
                        Some(_) => continue, // still live at the same extent
                    };
                    superseded.push(Anomaly::new(AnomalyKind::SupersededFile {
                        entry_path: e.path,
                        session: idx,
                        lba: e.record.lba,
                        status: status.to_string(),
                    }));
                }
            }
        }

        // Out-of-bounds extents: an entry whose data extent points past the
        // readable image (truncation, corruption, or a dangling reference).
        let image_sectors = image_bytes / iso.sector_mode().physical_sector_size();
        let mut oob_anoms: Vec<Anomaly> = Vec::new();
        for e in iso.walk()? {
            if e.record.size == 0 {
                continue;
            }
            let end = u64::from(e.record.lba) + u64::from(e.record.size).div_ceil(2048);
            if u64::from(e.record.lba) >= image_sectors || end > image_sectors {
                oob_anoms.push(Anomaly::new(AnomalyKind::OutOfBoundsExtent {
                    entry_path: e.path,
                    lba: e.record.lba,
                    size: e.record.size,
                    image_sectors: u32::try_from(image_sectors).unwrap_or(u32::MAX),
                }));
            }
        }

        // Files recorded after the volume creation date (post-mastering add /
        // backdated volume). Compared as UTC instants so timezone offsets don't
        // cause false ordering.
        // Volume dates outside the optical era are impossible for the volume
        // itself (year 0 = unset, skipped). 1985 ≈ first CD-ROMs; nothing
        // legitimately claims a year past the far-future ceiling.
        const OPTICAL_ERA_FLOOR: u16 = 1985;
        const OPTICAL_ERA_CEILING: u16 = 2100;
        let mut time_anoms: Vec<Anomaly> = Vec::new();
        for (which, t) in [
            ("creation", iso.volume_creation_time().cloned()),
            ("modification", iso.volume_modification_time().cloned()),
        ] {
            if let Some(dt) = t {
                if (1..OPTICAL_ERA_FLOOR).contains(&dt.year) || dt.year > OPTICAL_ERA_CEILING {
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
            pt_div,
            pt_endian,
            {
                time_anoms.extend(oob_anoms);
                time_anoms.extend(superseded);
                time_anoms.extend(pvd_reserved);
                time_anoms.extend(overlaps);
                time_anoms.extend(dir_cycles);
                time_anoms.extend(name_div);
                time_anoms.extend(disguised);
                time_anoms
            },
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

    // Path table vs directory tree divergence: a directory present in only one
    // of the two redundant indexes (phantom = path-table-only, ghost = tree-only).
    for (direction, lba) in pt_divergence {
        anomalies.push(Anomaly::new(AnomalyKind::PathTableDivergence { direction, lba }));
    }

    // L/M path-table both-endian divergence: the two redundant byte-order copies
    // of the directory index disagree on an entry's content.
    for m in pt_endian {
        anomalies.push(Anomaly::new(AnomalyKind::PathTableEndianDivergence {
            index: m.index,
            description: m.description,
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

    // EDC integrity (raw 2352 Mode-1 sectors only): a genuine optical dump
    // carries valid EDC; zero/invalid EDC indicates a synthesized image or
    // tampered data. Skipped for 2048-byte ISO images (no EDC field).
    if phys >= 2352 {
        let total = image_bytes / phys;
        let mut sec = vec![0u8; 2352];
        let mut checked = 0u32;
        let mut invalid = 0u32;
        let mut first_invalid = 0u32;
        for lba in 0..total {
            reader.seek(SeekFrom::Start(lba * phys))?;
            if reader.read_exact(&mut sec).is_err() {
                break;
            }
            let sync_ok = sec[0] == 0 && sec[1..11].iter().all(|&b| b == 0xFF) && sec[11] == 0;
            if !sync_ok || sec[15] != 1 {
                continue; // not a Mode-1 sector with EDC
            }
            checked += 1;
            let stored = u32::from_le_bytes([sec[2064], sec[2065], sec[2066], sec[2067]]);
            if crate::sector::cd_edc(&sec[0..2064]) != stored {
                if invalid == 0 {
                    first_invalid = u32::try_from(lba).unwrap_or(u32::MAX);
                }
                invalid += 1;
            }
        }
        if invalid > 0 {
            anomalies.push(Anomaly::new(AnomalyKind::EdcInvalid {
                sectors_checked: checked,
                sectors_invalid: invalid,
                first_invalid_lba: first_invalid,
            }));
        }
    }

    Ok(IsoAnalysis { volume, anomalies })
}

/// True if the byte range `[start, end)` contains any non-zero byte.
/// Identify an executable file format from its leading magic bytes, or `None`.
fn exe_magic(header: &[u8]) -> Option<&'static str> {
    if header.len() < 4 {
        return None;
    }
    if header[0] == 0x4D && header[1] == 0x5A {
        return Some("PE"); // "MZ" (DOS/PE)
    }
    if header[0] == 0x7F && &header[1..4] == b"ELF" {
        return Some("ELF");
    }
    let be = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    // Mach-O 32/64-bit (both byte orders) and universal ("fat") binaries.
    if matches!(be, 0xFEED_FACE | 0xFEED_FACF | 0xCEFA_EDFE | 0xCFFA_EDFE | 0xCAFE_BABE) {
        return Some("Mach-O");
    }
    None
}

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
