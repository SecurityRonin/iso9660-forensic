use iso9660_forensic::{rock_ridge, IsoError, IsoReader};
use std::io::{Read, Seek};

/// List directory entries.
///
/// `path`  — directory to list; `None` = root.
/// `tree`  — when true, recurse and show full paths (equivalent to `-R`).
pub fn run<R: Read + Seek>(
    reader: &mut IsoReader<R>,
    path: Option<&str>,
    tree: bool,
) -> Result<String, IsoError> {
    if tree {
        return run_recursive(reader, path);
    }

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

    // Fixed-width ASCII table — no Unicode box-drawing.
    // Columns: T=1  SIZE=right-10  LBA=right-6  NAME=variable
    let mut out = String::from("T        SIZE     LBA  NAME\n");
    out.push_str("-  ----------  ------  ----\n");
    for e in &entries {
        let type_ch = if e.is_dir() { 'd' } else { '-' };
        let iso_name = e.iso_name();
        let rr_name = rock_ridge::alternate_name(&e.system_use);
        let display = rr_name.as_deref().unwrap_or(&iso_name);
        let suffix = if e.is_dir() { "/" } else { "" };
        out.push_str(&format!("{type_ch}  {:>10}  {:>6}  {display}{suffix}\n", e.size, e.lba));
    }
    Ok(out)
}

fn run_recursive<R: Read + Seek>(
    reader: &mut IsoReader<R>,
    path: Option<&str>,
) -> Result<String, IsoError> {
    let all = reader.walk()?;

    let prefix = path.map(|p| p.trim_matches('/').to_ascii_uppercase());

    let mut out = String::new();
    for e in &all {
        if let Some(ref pfx) = prefix {
            if !e.path.to_ascii_uppercase().starts_with(pfx.as_str()) {
                continue;
            }
        }
        if e.record.is_dir() {
            out.push_str(&format!("{}/\n", e.path));
        } else {
            out.push_str(&format!("{}\n", e.path));
        }
    }
    Ok(out)
}
