use iso9660_forensic::{IsoError, IsoReader};
use std::io::{Read, Seek};

/// Search file contents for a literal pattern.
///
/// Text files report `path:lineno: line`; binary files report
/// `path: binary match at offset N`.
pub fn run<R: Read + Seek>(
    reader: &mut IsoReader<R>,
    pattern: &str,
    include_glob: Option<&str>,
    ignore_case: bool,
) -> Result<String, IsoError> {
    let _ = (reader, pattern, include_glob, ignore_case);
    Ok(String::new())
}
