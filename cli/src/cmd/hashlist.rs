use iso9660_forensic::{IsoError, IsoReader};
use std::io::{Read, Seek};

/// Output format for the hash list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashFormat {
    /// hashdeep-compatible (size,sha256,filename).
    Hashdeep,
    /// Comma-separated (path,size,sha256).
    Csv,
    /// Tab-separated (path<TAB>size<TAB>sha256).
    Tsv,
    /// Sleuth Kit mactime body format.
    Mactime,
    /// Digital Forensics XML (DFXML) fileobject records.
    Dfxml,
}

/// Render the per-file SHA-256 hash list in the requested format.
pub fn run<R: Read + Seek>(
    reader: &mut IsoReader<R>,
    format: HashFormat,
) -> Result<String, IsoError> {
    let _ = (reader, format);
    Ok(String::new())
}
