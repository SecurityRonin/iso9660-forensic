use crate::glob::glob_match;
use iso9660_forensic::{IsoError, IsoReader};
use regex::Regex;
use std::io::{Read, Seek};

/// Search file contents for a literal pattern or a pre-compiled regex.
///
/// Text files report `path:lineno: line`; files containing NUL bytes are
/// treated as binary and report `path: binary match at offset N`.
/// When `regex` is `Some`, it takes precedence over the literal `pattern`
/// (and `ignore_case`, which is baked into the compiled regex).
/// `include_glob` (with `*`) limits the search to matching basenames.
pub fn run<R: Read + Seek>(
    reader: &mut IsoReader<R>,
    pattern: &str,
    regex: Option<&Regex>,
    include_glob: Option<&str>,
    ignore_case: bool,
) -> Result<String, IsoError> {
    let entries = reader.walk()?;
    let needle = if ignore_case { pattern.to_ascii_lowercase() } else { pattern.to_owned() };

    // Collect matching file records first to avoid borrowing reader twice.
    let targets: Vec<_> = entries
        .into_iter()
        .filter(|e| !e.record.is_dir())
        .filter(|e| match include_glob {
            None => true,
            Some(g) => {
                let base = e.path.rsplit('/').next().unwrap_or(&e.path);
                glob_match(&g.to_ascii_uppercase(), &base.to_ascii_uppercase())
            }
        })
        .collect();

    let mut out = String::new();
    for e in &targets {
        let data = reader.read_file_entry(&e.record)?;
        let is_binary = data.contains(&0u8);

        if is_binary {
            // Binary: report the byte offset of the first match.  For regex we
            // search the lossy-decoded string and map back to a byte offset.
            let hit = match regex {
                Some(re) => {
                    let lossy = String::from_utf8_lossy(&data);
                    re.find(&lossy).map(|m| m.start())
                }
                None => find_bytes(&data, pattern.as_bytes(), ignore_case),
            };
            if let Some(off) = hit {
                out.push_str(&format!("{}: binary match at offset {off}\n", e.path));
            }
            continue;
        }

        // Text: search line by line (split on 0x0A).
        for (i, line) in data.split(|&b| b == b'\n').enumerate() {
            let text = String::from_utf8_lossy(line);
            let matched = match regex {
                // The compiled regex already carries any case-insensitivity.
                Some(re) => re.is_match(&text),
                None => {
                    let hay = if ignore_case { text.to_ascii_lowercase() } else { text.to_string() };
                    hay.contains(&needle)
                }
            };
            if matched {
                out.push_str(&format!(
                    "{}:{}: {}\n",
                    e.path,
                    i + 1,
                    text.trim_end_matches('\r')
                ));
            }
        }
    }
    Ok(out)
}

/// Find the first offset of `needle` in `hay`, optionally case-insensitively.
fn find_bytes(hay: &[u8], needle: &[u8], ignore_case: bool) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    let eq = |a: u8, b: u8| {
        if ignore_case { a.eq_ignore_ascii_case(&b) } else { a == b }
    };
    (0..=hay.len() - needle.len())
        .find(|&i| hay[i..i + needle.len()].iter().zip(needle).all(|(&a, &b)| eq(a, b)))
}
