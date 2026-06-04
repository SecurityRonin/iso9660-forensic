//! `hfs` — browse and extract files from an Apple HFS+ volume.
//!
//! Operates on the raw image bytes (a hybrid disc's HFS+ volume shares the
//! image), reusing the `iso9660_forensic::hfs` catalog reader. Lists the root
//! directory or extracts a named root file's data fork.

use std::fmt::Write as _;
use std::path::Path;

use anyhow::{bail, Context, Result};
use iso9660_forensic::hfs;

/// Read the whole image so the HFS+ catalog (located by byte offset) is in scope.
fn read_image(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))
}

/// List the HFS+ root directory as a fixed-width table.
pub fn list(path: &Path) -> Result<String> {
    let bytes = read_image(path)?;
    let entries = hfs::list_root(&bytes)
        .ok_or_else(|| anyhow::anyhow!("no HFS+ volume in {}", path.display()))?;
    let mut out = String::from("TYPE   CNID        NAME\n----   ----------  ----\n");
    for e in &entries {
        let ty = if e.is_dir { "dir " } else { "file" };
        let _ = writeln!(out, "{ty}   {:>10}  {}", e.cnid, e.name);
    }
    Ok(out)
}

/// Extract a named root-level file's contents.
pub fn extract(path: &Path, name: &str) -> Result<Vec<u8>> {
    let bytes = read_image(path)?;
    let entries = hfs::list_root(&bytes)
        .ok_or_else(|| anyhow::anyhow!("no HFS+ volume in {}", path.display()))?;
    let entry = entries
        .iter()
        .find(|e| e.name == name)
        .ok_or_else(|| anyhow::anyhow!("no HFS+ file named {name:?} in root"))?;
    if entry.is_dir {
        bail!("{name:?} is a directory, not a file");
    }
    hfs::read_file(&bytes, entry.cnid)
        .ok_or_else(|| anyhow::anyhow!("could not read HFS+ file {name:?}"))
}
