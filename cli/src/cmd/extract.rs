use iso9660_forensic::{IsoError, IsoReader};
use std::io::{Read, Seek};

pub fn run<R: Read + Seek>(reader: &mut IsoReader<R>, path: &str) -> Result<Vec<u8>, IsoError> {
    let _ = (reader, path);
    Ok(Vec::new())
}
