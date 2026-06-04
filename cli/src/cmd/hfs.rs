//! `hfs` — browse and extract files from an Apple HFS+ volume.
//!
//! Operates on the raw image bytes (a hybrid disc's HFS+ volume shares the
//! image), reusing the `iso9660_forensic::hfs` catalog reader. Lists the root
//! directory (or the whole tree with `-R`) and extracts a file by path.

use std::fmt::Write as _;
use std::path::Path;

use anyhow::{bail, Context, Result};
use iso9660_forensic::hfs;

/// Read the whole image so the HFS+ catalog (located by byte offset) is in scope.
fn read_image(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))
}

/// List the HFS+ root directory, or the whole tree when `recursive`.
pub fn list(path: &Path, recursive: bool) -> Result<String> {
    let bytes = read_image(path)?;
    let mut out = String::from("TYPE   CNID        PATH\n----   ----------  ----\n");
    if recursive {
        let entries = hfs::walk(&bytes)
            .ok_or_else(|| anyhow::anyhow!("no HFS+ volume in {}", path.display()))?;
        for e in &entries {
            let ty = if e.is_dir { "dir " } else { "file" };
            let _ = writeln!(out, "{ty}   {:>10}  {}", e.cnid, e.path);
        }
    } else {
        let entries = hfs::list_root(&bytes)
            .ok_or_else(|| anyhow::anyhow!("no HFS+ volume in {}", path.display()))?;
        for e in &entries {
            let ty = if e.is_dir { "dir " } else { "file" };
            let _ = writeln!(out, "{ty}   {:>10}  {}", e.cnid, e.name);
        }
    }
    Ok(out)
}

/// Extract a file by its `/`-joined path (root files use the bare name).
pub fn extract(path: &Path, name: &str) -> Result<Vec<u8>> {
    let bytes = read_image(path)?;
    let entries =
        hfs::walk(&bytes).ok_or_else(|| anyhow::anyhow!("no HFS+ volume in {}", path.display()))?;
    let entry = entries
        .iter()
        .find(|e| e.path == name)
        .ok_or_else(|| anyhow::anyhow!("no HFS+ entry at path {name:?}"))?;
    if entry.is_dir {
        bail!("{name:?} is a directory, not a file");
    }
    hfs::read_file(&bytes, entry.cnid)
        .ok_or_else(|| anyhow::anyhow!("could not read HFS+ file {name:?}"))
}
