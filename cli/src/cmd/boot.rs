use iso9660_forensic::{IsoError, IsoReader};
use std::io::{Read, Seek};

pub fn run<R: Read + Seek>(reader: &mut IsoReader<R>) -> Result<String, IsoError> {
    let entries = reader.boot_entries()?;
    if entries.is_empty() {
        return Ok("No boot catalog\n".to_owned());
    }
    let mut out = format!("El Torito Boot Entries: {}\n", entries.len());
    for (i, e) in entries.iter().enumerate() {
        out.push_str(&format!(
            "  [{:>2}] bootable={:<5}  lba={}\n",
            i + 1,
            e.bootable,
            e.lba,
        ));
    }
    Ok(out)
}
