//! `forensic recover` — list files recovered from orphaned directory extents.
//!
//! Surfaces [`IsoReader::recover_lost_files`]: files inside directories the
//! path table references but the active tree cannot reach.

use std::fmt::Write as _;
use std::io::{Read, Seek};

use iso9660_forensic::{IsoError, IsoReader};

pub fn run<R: Read + Seek>(reader: &mut IsoReader<R>) -> Result<String, IsoError> {
    let lost = reader.recover_lost_files()?;
    let mut out = String::new();
    if lost.is_empty() {
        out.push_str("No lost files found (no orphaned directory extents).\n");
        return Ok(out);
    }
    let _ = writeln!(out, "Recovered {} lost file(s):", lost.len());
    out.push_str("       LBA        SIZE  NAME (orphan dir LBA)\n");
    out.push_str("----------  ----------  ----\n");
    for f in &lost {
        let _ = writeln!(out, "{:>10}  {:>10}  {} ({})", f.lba, f.size, f.name, f.parent_lba);
    }
    Ok(out)
}
