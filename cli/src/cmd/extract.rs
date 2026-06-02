use iso9660_forensic::{IsoError, IsoReader};
use std::io::{Read, Seek};

/// Extract files preserving their full archive paths.
///
/// Returns `Vec<(archive_path, bytes)>`.
/// - `src = None`  — extract every file in the image.
/// - `src = Some(path)` — extract a single file, or every file under a directory.
pub fn run_x<R: Read + Seek>(
    reader: &mut IsoReader<R>,
    src: Option<&str>,
) -> Result<Vec<(String, Vec<u8>)>, IsoError> {
    match src {
        None => extract_all(reader),
        Some(path) => {
            let entry = reader.find_entry(path)?;
            if entry.is_dir() {
                // Walk entire tree, keep entries whose path starts with this dir.
                let prefix = path.trim_matches('/').to_ascii_uppercase();
                let all = reader.walk()?;
                let mut result = Vec::new();
                for e in all {
                    let ep = e.path.to_ascii_uppercase();
                    if !e.record.is_dir() && ep.starts_with(&prefix) {
                        let data = reader.read_file_entry(&e.record)?;
                        result.push((e.path, data));
                    }
                }
                Ok(result)
            } else {
                let data = reader.read_file_entry(&entry)?;
                Ok(vec![(path.to_string(), data)])
            }
        }
    }
}

/// Extract files flat — strip all directory components from paths.
///
/// Delegates to [`run_x`] for data, then maps each path to its basename.
pub fn run_e<R: Read + Seek>(
    reader: &mut IsoReader<R>,
    src: Option<&str>,
) -> Result<Vec<(String, Vec<u8>)>, IsoError> {
    let files = run_x(reader, src)?;
    Ok(files
        .into_iter()
        .map(|(path, data)| {
            let name = path
                .rsplit('/')
                .next()
                .unwrap_or(&path)
                .to_string();
            (name, data)
        })
        .collect())
}

fn extract_all<R: Read + Seek>(
    reader: &mut IsoReader<R>,
) -> Result<Vec<(String, Vec<u8>)>, IsoError> {
    let all = reader.walk()?;
    let mut result = Vec::new();
    for e in all {
        if !e.record.is_dir() {
            let data = reader.read_file_entry(&e.record)?;
            result.push((e.path, data));
        }
    }
    Ok(result)
}
