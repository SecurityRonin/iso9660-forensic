use iso9660_forensic::{IsoError, IsoReader};
use std::io::{Read, Seek};

/// Render a chronological timeline of files as a fixed-width ASCII table.
///
/// Sorted by Rock Ridge modification timestamp (entries without a timestamp
/// last).  Anomalies (e.g. epoch dates) are appended in brackets.
pub fn run<R: Read + Seek>(reader: &mut IsoReader<R>) -> Result<String, IsoError> {
    let entries = reader.timeline()?;

    let mut out = String::from("TYPE       SIZE  TIMESTAMP            PATH\n");
    out.push_str(        "----  ---------  -------------------  ----\n");
    for e in &entries {
        let ty = if e.is_dir { "dir " } else { "file" };
        let ts = match e.modify_ts {
            Some(t) => format_ts(&t),
            None => " ".repeat(19),
        };
        let anomaly = match &e.anomaly {
            Some(a) => format!(" [{a}]"),
            None => String::new(),
        };
        out.push_str(&format!(
            "{ty}  {:>9}  {ts}  {}{anomaly}\n",
            e.size, e.path
        ));
    }
    Ok(out)
}

/// Format a 7-byte short Rock Ridge timestamp as ISO 8601 (no timezone).
fn format_ts(t: &[u8; 7]) -> String {
    let year = 1900u32 + t[0] as u32;
    format!(
        "{year:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        t[1], t[2], t[3], t[4], t[5]
    )
}
