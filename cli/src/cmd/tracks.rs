//! `tracks` — print a container descriptor's table of contents.
//!
//! Surfaces the track layout parsed from a CUE/CCD/NRG/MDS container (the same
//! parsers used to locate the data track when opening), giving an IsoBuster-style
//! view of modes, start positions, sizes, ISRCs, and the disc MCN.

use std::fmt::Write as _;
use std::path::Path;

use anyhow::{bail, Context, Result};
use iso9660_forensic::{ccd, cue, mds, nrg};

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
        _ => bail!("no track table for this file; supported containers: .cue .ccd .nrg .mds"),
    }
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
