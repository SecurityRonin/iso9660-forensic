//! Resolve an optical image *path* to a byte source over its ISO 9660 data
//! track.
//!
//! An optical image arrives in several container shapes: a raw `.iso`, a `.cue`
//! sheet pointing at a `.bin`, a `CloneCD` `.ccd` pointing at an `.img`, or a
//! Nero `.nrg` / Alcohol `.mds` / CDRDAO `.toc` whose data track sits at a byte
//! offset inside a larger file. [`open`] hides those differences: it returns a
//! `Read + Seek` positioned to read the ISO 9660 volume, ready for
//! [`crate::analyse`] or [`crate::IsoReader`]. A higher-level tool composes this
//! with its own evidence-container layer (E01/VMDK/…) for non-optical inputs.

use std::fs::File;
use std::io::{BufReader, Read, Seek};
use std::path::Path;

use crate::offset::OffsetReader;
use crate::sector::SectorMode;
use crate::{cue, mds, nrg, toc, IsoError};

/// A seekable byte source, type-erased so the different container resolutions
/// (plain file, offset-windowed track) unify behind one return type.
pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}

/// Open an optical image by path, resolving its container to a `Read + Seek`
/// over the ISO 9660 data track.
///
/// Resolves `.cue`→`.bin` and `.ccd`→`.img` (same-basename data file), and
/// windows the data track of `.nrg` / `.mds` / `.toc`. Any other extension is
/// opened as a raw image.
pub fn open<P: AsRef<Path>>(path: P) -> Result<Box<dyn ReadSeek>, IsoError> {
    let path = path.as_ref();
    let ext = path.extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase);
    match ext.as_deref() {
        Some("nrg") => open_nrg(path),
        Some("mds") => open_mds(path),
        Some("toc") => open_toc(path),
        Some("cue") => open_plain(&resolve_cue_bin(path)?),
        Some("ccd") => open_plain(&resolve_ccd_img(path)?),
        _ => open_plain(path),
    }
}

fn open_plain(path: &Path) -> Result<Box<dyn ReadSeek>, IsoError> {
    Ok(Box::new(BufReader::new(File::open(path)?)))
}

/// Window a Nero `.nrg` to its first data track.
fn open_nrg(path: &Path) -> Result<Box<dyn ReadSeek>, IsoError> {
    let mut f = File::open(path)?;
    let image = nrg::parse(&mut f)?;
    let track = image.data_track().ok_or_else(|| {
        IsoError::BadDescriptor(format!("no data track in NRG {}", path.display()))
    })?;
    Ok(Box::new(OffsetReader::new(BufReader::new(f), track.start_offset, track.size)?))
}

/// Window an Alcohol `.mds`'s sibling `.mdf` to its first data track.
fn open_mds(path: &Path) -> Result<Box<dyn ReadSeek>, IsoError> {
    let mut desc = File::open(path)?;
    let image = mds::parse(&mut desc)?;
    let track = image.data_track().ok_or_else(|| {
        IsoError::BadDescriptor(format!("no data track in MDS {}", path.display()))
    })?;
    let mdf = File::open(path.with_extension("mdf"))?;
    Ok(Box::new(OffsetReader::new(BufReader::new(mdf), track.start_offset, track.data_size())?))
}

/// Window a CDRDAO `.toc`'s data file to its first data track.
fn open_toc(path: &Path) -> Result<Box<dyn ReadSeek>, IsoError> {
    let text = std::fs::read_to_string(path)?;
    let sheet = toc::parse(&text);
    let track = sheet.data_track().ok_or_else(|| {
        IsoError::BadDescriptor(format!("no data track in TOC {}", path.display()))
    })?;
    let datafile = track.datafile.as_deref().ok_or_else(|| {
        IsoError::BadDescriptor(format!("TOC data track has no DATAFILE: {}", path.display()))
    })?;
    let data_path = path.parent().unwrap_or_else(|| Path::new(".")).join(datafile);
    let f = File::open(&data_path)?;
    let file_len = f.metadata().map_or(0, |m| m.len());
    let avail = file_len.saturating_sub(track.file_offset);
    let sector_size = track.mode.sector_mode().map_or(2352, SectorMode::physical_sector_size);
    let len = if track.length_sectors > 0 {
        (u64::from(track.length_sectors) * sector_size).min(avail)
    } else {
        avail
    };
    Ok(Box::new(OffsetReader::new(BufReader::new(f), track.file_offset, len)?))
}

/// Resolve a CUE sheet to the `.bin` holding its first data track.
fn resolve_cue_bin(path: &Path) -> Result<std::path::PathBuf, IsoError> {
    let text = std::fs::read_to_string(path)?;
    let sheet = cue::parse(&text);
    let (file_name, _track) = sheet.data_track().ok_or_else(|| {
        IsoError::BadDescriptor(format!("no data track in CUE sheet {}", path.display()))
    })?;
    Ok(path.parent().unwrap_or_else(|| Path::new(".")).join(file_name))
}

/// Resolve a `CloneCD` `.ccd` to its same-basename `.img`.
fn resolve_ccd_img(path: &Path) -> Result<std::path::PathBuf, IsoError> {
    let img = path.with_extension("img");
    if img.is_file() {
        Ok(img)
    } else {
        Err(IsoError::BadDescriptor(format!(
            "no .img alongside CloneCD control file {}",
            path.display()
        )))
    }
}
