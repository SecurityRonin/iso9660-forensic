use iso9660_forensic::{IsoError, IsoReader};
use std::io::{Read, Seek};

pub fn run<R: Read + Seek>(reader: &mut IsoReader<R>) -> Result<String, IsoError> {
    let entries = reader.walk()?;
    let mut out = String::new();
    for e in &entries {
        if e.record.is_dir() {
            out.push_str(&format!("{}/\n", e.path));
        } else {
            out.push_str(&format!("{}\n", e.path));
        }
    }
    Ok(out)
}
