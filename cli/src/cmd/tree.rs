use iso9660_forensic::{IsoError, IsoReader};
use std::io::{Read, Seek};

pub fn run<R: Read + Seek>(reader: &mut IsoReader<R>) -> Result<String, IsoError> {
    let _ = reader;
    Ok(String::new())
}
