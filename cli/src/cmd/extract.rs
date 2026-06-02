use iso9660_forensic::{IsoError, IsoReader};
use std::io::{Read, Seek};

pub fn run<R: Read + Seek>(reader: &mut IsoReader<R>, path: &str) -> Result<Vec<u8>, IsoError> {
    let entry = reader.find_entry(path)?;
    reader.read_file_entry(&entry)
}
