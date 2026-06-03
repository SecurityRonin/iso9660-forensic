use iso9660_forensic::{IsoError, IsoReader};
use std::io::{Read, Seek};

/// Find entries by name glob, type, and size range. One path per line.
pub fn run<R: Read + Seek>(
    reader: &mut IsoReader<R>,
    name_glob: Option<&str>,
    file_type: Option<char>,
    min_size: Option<u32>,
    max_size: Option<u32>,
) -> Result<String, IsoError> {
    let _ = (reader, name_glob, file_type, min_size, max_size);
    Ok(String::new())
}
