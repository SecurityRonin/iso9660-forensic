use iso9660_forensic::{IsoError, IsoReader};
use std::io::{Read, Seek};

pub fn run<R: Read + Seek>(reader: &mut IsoReader<R>, lba: u64) -> Result<String, IsoError> {
    let _ = (reader, lba);
    Ok(String::new())
}
