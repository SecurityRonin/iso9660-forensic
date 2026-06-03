use iso9660_forensic::{IsoError, IsoReader};
use std::io::{Read, Seek};

/// Search file contents for a literal pattern.
///
/// Text files report `path:lineno: line`; files containing NUL bytes are
/// treated as binary and report `path: binary match at offset N`.
/// `include_glob` (with `*`) limits the search to matching basenames.
pub fn run<R: Read + Seek>(
    reader: &mut IsoReader<R>,
    pattern: &str,
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
            if let Some(off) = find_bytes(&data, pattern.as_bytes(), ignore_case) {
                out.push_str(&format!("{}: binary match at offset {off}\n", e.path));
            }
            continue;
        }

        // Text: search line by line (split on 0x0A).
        for (i, line) in data.split(|&b| b == b'\n').enumerate() {
            let text = String::from_utf8_lossy(line);
            let hay = if ignore_case { text.to_ascii_lowercase() } else { text.to_string() };
            if hay.contains(&needle) {
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

/// Minimal `*`-only glob matcher (case-normalised inputs).
fn glob_match(pat: &str, text: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None, 0usize);
    while ti < t.len() {
        if pi < p.len() && p[pi] == t[ti] {
            pi += 1; ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi); mark = ti; pi += 1;
        } else if let Some(s) = star {
            pi = s + 1; mark += 1; ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' { pi += 1; }
    pi == p.len()
}
