use iso9660_forensic::{IsoError, IsoReader};
use regex::Regex;
use std::io::{Read, Seek};

/// Find entries by name regex, type, and size range. One path per line.
///
/// - `name`: a pre-compiled regex matched (unanchored) against the basename.
///   Case sensitivity is whatever the regex was compiled with.
/// - `file_type`: `'f'` files only, `'d'` directories only, `None` for both.
/// - `min_size` / `max_size`: inclusive byte bounds (applied to files).
pub fn run<R: Read + Seek>(
    reader: &mut IsoReader<R>,
    name: Option<&Regex>,
    file_type: Option<char>,
    min_size: Option<u32>,
    max_size: Option<u32>,
) -> Result<String, IsoError> {
    let entries = reader.walk()?;
    let mut out = String::new();
    for e in &entries {
        let is_dir = e.record.is_dir();

        if let Some(t) = file_type {
            match t {
                'f' if is_dir => continue,
                'd' if !is_dir => continue,
                _ => {}
            }
        }

        if let Some(re) = name {
            let base = e.path.rsplit('/').next().unwrap_or(&e.path);
            if !re.is_match(base) {
                continue;
            }
        }

        // Size filters apply to files (directories have no meaningful size here).
        if !is_dir {
            if let Some(mn) = min_size {
                if e.record.size < mn {
                    continue;
                }
            }
            if let Some(mx) = max_size {
                if e.record.size > mx {
                    continue;
                }
            }
        } else if min_size.is_some() || max_size.is_some() {
            // A size filter excludes directories.
            continue;
        }

        // Paths from walk() already carry Rock Ridge names where present.
        out.push_str(&e.path);
        out.push('\n');
    }
    Ok(out)
}
