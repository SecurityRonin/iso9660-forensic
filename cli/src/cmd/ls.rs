use iso9660_forensic::{rock_ridge, IsoError, IsoReader};
use std::io::{Read, Seek};

pub fn run<R: Read + Seek>(
    reader: &mut IsoReader<R>,
    path: Option<&str>,
) -> Result<String, IsoError> {
    let entries = match path {
        None => reader.read_root_dir()?,
        Some(p) => {
            let dir = reader.find_entry(p)?;
            if !dir.is_dir() {
                return Err(IsoError::NotFound(format!("{p} is not a directory")));
            }
            reader.read_dir(dir.lba, dir.size)?
        }
    };

    let mut out = String::new();
    for e in &entries {
        let type_ch = if e.is_dir() { 'd' } else { '-' };
        let iso_name = e.iso_name();
        let rr_name  = rock_ridge::alternate_name(&e.system_use);
        let display  = rr_name.as_deref().unwrap_or(&iso_name);
        let suffix   = if e.is_dir() { "/" } else { "" };
        out.push_str(&format!(
            "{type_ch}  {:>10}  lba={:<6}  {display}{suffix}\n",
            e.size, e.lba
        ));
    }
    Ok(out)
}
