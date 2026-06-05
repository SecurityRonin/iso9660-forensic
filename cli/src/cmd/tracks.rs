//! `tracks` — print a container descriptor's table of contents.
//!
//! Surfaces the track layout parsed from a CUE / CCD / NRG / MDS / CDI / CDRDAO
//! TOC / BlindWrite (B5T/B6T) container — the same parsers used to locate the
//! data track when opening — giving an IsoBuster-style view of modes, start
//! positions, sizes, ISRCs, and the disc MCN. (BlindWrite is detection-only.)

use std::fmt::Write as _;
use std::path::Path;

use anyhow::{bail, Context, Result};
use iso9660_forensic::{bw5, ccd, cdi, cdtext, cue, mds, nrg, toc, SectorMode};

/// Placeholder for a column with no value for this container.
const DASH: &str = "-";

/// Render the track table for a container descriptor, dispatched by extension.
pub fn run(path: &Path) -> Result<String> {
    let ext = path.extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase);
    match ext.as_deref() {
        Some("cue") => tracks_cue(path),
        Some("ccd") => tracks_ccd(path),
        Some("nrg") => tracks_nrg(path),
        Some("mds") => tracks_mds(path),
        Some("cdi") => tracks_cdi(path),
        Some("toc") => tracks_toc(path),
        Some(e @ ("b5t" | "b6t")) => tracks_bw5(path, e),
        _ => bail!(
            "no track table for this file; supported containers: \
             .cue .ccd .nrg .mds .cdi .toc .b5t .b6t"
        ),
    }
}

fn tracks_toc(path: &Path) -> Result<String> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read CDRDAO TOC {}", path.display()))?;
    let sheet = toc::parse(&text);
    let container =
        format!("CDRDAO TOC{}", sheet.disc_type.map(|d| format!(" ({d})")).unwrap_or_default());
    let mut out = String::new();
    header(&mut out, &container, None);
    for t in &sheet.tracks {
        let size = u64::from(t.length_sectors)
            * t.mode.sector_mode().map_or(2352, SectorMode::physical_sector_size);
        let _ = writeln!(
            out,
            "{:>5}  {:<15}  {:>11}  {size:>6}  {}",
            t.number,
            format!("{:?}", t.mode),
            t.file_offset,
            DASH
        );
    }
    Ok(out)
}

/// BlindWrite 5/6/7 TOCs are detection-only: the track layout is undecoded
/// pending a real sample to validate a decoder against (see the `bw5` module).
fn tracks_bw5(path: &Path, ext: &str) -> Result<String> {
    let mut f =
        std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    bw5::detect(&mut f)
        .ok_or_else(|| anyhow::anyhow!("not a BlindWrite TOC: {}", path.display()))?;
    let version = if ext == "b6t" { "6/7" } else { "5" };
    Ok(format!(
        "Container: BlindWrite {version} TOC ({ext})\n\
         Note: identified by signature; track layout not decoded (no public sample \
         to validate a decoder against — detection only).\n"
    ))
}

/// DiscJuggler images: decode the descriptor's track table when it is
/// well-formed, otherwise fall back to a detection-only note.
fn tracks_cdi(path: &Path) -> Result<String> {
    let mut f =
        std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let info = cdi::detect(&mut f)
        .ok_or_else(|| anyhow::anyhow!("not a DiscJuggler image: {}", path.display()))?;
    let container = format!("DiscJuggler CDI (version {:#010x})", info.version);

    let Some(tracks) = cdi::tracks(&mut f) else {
        return Ok(format!(
            "Container: {container}\n\
             Descriptor: {} bytes\n\
             Note: track table not decodable (malformed descriptor); detection only.\n",
            info.descriptor_length
        ));
    };

    let mut out = String::new();
    header(&mut out, &container, None);
    for t in &tracks {
        let size = u64::from(t.length_sectors) * u64::from(t.raw_bytes_per_sector);
        let _ = writeln!(
            out,
            "{:>5}  {:<15}  {:>11}  {size:>6}  {}",
            t.sequence,
            format!("{:?}", t.kind),
            t.start_sector,
            DASH
        );
    }
    Ok(out)
}

fn header(out: &mut String, container: &str, mcn: Option<&str>) {
    let _ = writeln!(out, "Container: {container}");
    if let Some(m) = mcn {
        let _ = writeln!(out, "MCN:       {m}");
    }
    let _ = writeln!(out, "Track  Mode             Start          Size  ISRC");
    let _ = writeln!(out, "-----  ---------------  -----------  ------  ------------");
}

fn tracks_cue(path: &Path) -> Result<String> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read CUE sheet {}", path.display()))?;
    let sheet = cue::parse(&text);
    let mut out = String::new();
    header(&mut out, "BIN/CUE", None);
    for file in &sheet.files {
        for t in &file.tracks {
            let start = t.indices.last().map_or(0, |(_, msf)| msf.to_lba());
            let _ = writeln!(
                out,
                "{:>5}  {:<15}  {start:>11}  {:>6}  {}",
                t.number,
                format!("{:?}", t.mode),
                DASH,
                DASH
            );
        }
    }
    Ok(out)
}

fn tracks_ccd(path: &Path) -> Result<String> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read CCD control file {}", path.display()))?;
    let toc = ccd::parse(&text);
    let mut out = String::new();
    header(&mut out, "CloneCD", toc.catalog.as_deref());
    for t in &toc.tracks {
        let _ = writeln!(
            out,
            "{:>5}  {:<15}  {:>11}  {:>6}  {}",
            t.number,
            format!("{:?}", t.mode),
            t.start_lba,
            DASH,
            t.isrc.as_deref().unwrap_or(DASH)
        );
    }
    if !toc.cdtext.is_empty() {
        let ct = cdtext::decode(&toc.cdtext);
        if let Some(title) = ct.album_title() {
            let _ = writeln!(out, "\nCD-Text album: {title}");
        }
        if let Some(performer) = ct.album_performer() {
            let _ = writeln!(out, "CD-Text performer: {performer}");
        }
        for t in &toc.tracks {
            if let Some(title) = ct.track_title(t.number) {
                let _ = writeln!(out, "  track {} title: {title}", t.number);
            }
        }
    }
    Ok(out)
}

fn tracks_nrg(path: &Path) -> Result<String> {
    let mut f =
        std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let image =
        nrg::parse(&mut f).with_context(|| format!("not an NRG image: {}", path.display()))?;
    let version = format!("NRG {:?}", image.version);
    let mut out = String::new();
    header(&mut out, &version, image.catalog.as_deref());
    for t in &image.tracks {
        let mode = t.sector_mode().map_or_else(|| "audio".to_string(), |m| format!("{m:?}"));
        let _ = writeln!(
            out,
            "{:>5}  {:<15}  {:>11}  {:>6}  {}",
            t.number,
            mode,
            t.start_offset,
            t.size,
            t.isrc.as_deref().unwrap_or("-")
        );
    }
    Ok(out)
}

fn tracks_mds(path: &Path) -> Result<String> {
    let mut f =
        std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let image =
        mds::parse(&mut f).with_context(|| format!("not an MDS descriptor: {}", path.display()))?;
    let mut out = String::new();
    header(&mut out, "Alcohol MDS", None);
    for t in &image.tracks {
        let mode = t.sector_mode().map_or_else(|| "audio".to_string(), |m| format!("{m:?}"));
        let _ = writeln!(
            out,
            "{:>5}  {:<15}  {:>11}  {:>6}  {}",
            t.point,
            mode,
            t.start_sector,
            t.data_size(),
            DASH
        );
    }
    Ok(out)
}
