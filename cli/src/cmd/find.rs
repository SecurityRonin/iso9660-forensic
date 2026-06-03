use iso9660_forensic::{IsoError, IsoReader};
use std::io::{Read, Seek};

/// Find entries by name glob, type, and size range. One path per line.
///
/// - `name_glob`: `*` wildcard matched case-insensitively against the basename.
/// - `file_type`: `'f'` files only, `'d'` directories only, `None` for both.
/// - `min_size` / `max_size`: inclusive byte bounds (applied to files).
pub fn run<R: Read + Seek>(
    reader: &mut IsoReader<R>,
    name_glob: Option<&str>,
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

        if let Some(g) = name_glob {
            let base = e.path.rsplit('/').next().unwrap_or(&e.path);
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

/// Minimal glob matcher supporting only the `*` wildcard (matches any run,
/// including empty).  Both arguments should already be case-normalised.
fn glob_match(pat: &str, text: &str) -> bool {
    // Classic two-pointer wildcard match with backtracking.
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == t[ti]) {
            pi += 1; ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}
