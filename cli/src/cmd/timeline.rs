use iso9660_forensic::{IsoError, IsoReader};
use std::io::{Read, Seek};

/// Render a chronological timeline of files as a fixed-width ASCII table.
pub fn run<R: Read + Seek>(reader: &mut IsoReader<R>) -> Result<String, IsoError> {
    let _ = reader;
    Ok(String::new())
}
