use crate::glob::glob_match;
use iso9660_forensic::{IsoError, IsoReader};
use regex::Regex;
use std::io::{Read, Seek};

/// Find entries by name (glob or regex), type, and size range. One path per line.
///
/// - `name_glob`: `*` wildcard matched case-insensitively against the basename.
/// - `name_regex`: a pre-compiled regex matched against the basename (case
///   sensitivity is whatever the regex was compiled with).  Takes precedence
///   over `name_glob` when both are supplied.
/// - `file_type`: `'f'` files only, `'d'` directories only, `None` for both.
/// - `min_size` / `max_size`: inclusive byte bounds (applied to files).
pub fn run<R: Read + Seek>(
    reader: &mut IsoReader<R>,
    name_glob: Option<&str>,
    name_regex: Option<&Regex>,
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

        let base = e.path.rsplit('/').next().unwrap_or(&e.path);
        // RED stub: name_regex not yet honored.
        let _ = name_regex;
        if let Some(g) = name_glob {
            if !glob_match(&g.to_ascii_uppercase(), &base.to_ascii_uppercase()) {
                continue;
            }
        }

        // Size filters apply to files (directories have no meaningful size here).
        if !is_dir {
            if let Some(mn) = min_size {
                if e.record.size < mn { continue; }
            }
            if let Some(mx) = max_size {
                if e.record.size > mx { continue; }
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
