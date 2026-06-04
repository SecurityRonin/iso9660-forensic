use iso9660_forensic::{IsoError, IsoReader};
use regex::Regex;
use std::io::{Read, Seek};

/// Search file contents with a pre-compiled regex.
///
/// Text files report `path:lineno: line`; files containing NUL bytes are
/// treated as binary and report `path: binary match at offset N`.
/// `include` (a regex on the basename), when `Some`, limits the search to
/// matching files.  Case sensitivity is whatever the regexes were compiled
/// with.
pub fn run<R: Read + Seek>(
    reader: &mut IsoReader<R>,
    content: &Regex,
    include: Option<&Regex>,
) -> Result<String, IsoError> {
    let entries = reader.walk()?;

    // Collect matching file records first to avoid borrowing reader twice.
    let targets: Vec<_> = entries
        .into_iter()
        .filter(|e| !e.record.is_dir())
        .filter(|e| match include {
            None => true,
            Some(re) => {
                let base = e.path.rsplit('/').next().unwrap_or(&e.path);
                re.is_match(base)
            }
        })
        .collect();

    let mut out = String::new();
    for e in &targets {
        let data = reader.read_file_entry(&e.record)?;
        let is_binary = data.contains(&0u8);

        if is_binary {
            // Search the lossy-decoded string; report the first match offset.
            let lossy = String::from_utf8_lossy(&data);
            if let Some(m) = content.find(&lossy) {
                out.push_str(&format!("{}: binary match at offset {}\n", e.path, m.start()));
            }
            continue;
        }

        // Text: search line by line (split on 0x0A).
        for (i, line) in data.split(|&b| b == b'\n').enumerate() {
            let text = String::from_utf8_lossy(line);
            if content.is_match(&text) {
                out.push_str(&format!("{}:{}: {}\n", e.path, i + 1, text.trim_end_matches('\r')));
            }
        }
    }
    Ok(out)
}
