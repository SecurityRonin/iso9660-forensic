use iso9660_forensic::{IsoError, IsoReader};
use std::io::{Read, Seek};

/// Render a sector-by-sector map of the image as a fixed-width ASCII table.
///
/// Sectors are classified by reference (VDs, path table, directories, file
/// data, boot catalog) and consecutive same-type sectors are collapsed into
/// ranges.  Anything unreferenced is reported as "Unallocated".
pub fn run<R: Read + Seek>(reader: &mut IsoReader<R>) -> Result<String, IsoError> {
    let total = reader.volume_space_size().max(19);
    let mut labels: Vec<&'static str> = vec!["Unallocated"; total as usize];

    // Pre-system area: sectors 0-15.
    for l in labels.iter_mut().take(16.min(total as usize)) {
        *l = "Pre-system area";
    }

    // Volume descriptors: scan from sector 16 until the terminator.
    for lba in 16..total {
        let raw = reader.read_sector_raw(lba as u64)?;
        if &raw[1..6] != b"CD001" {
            break;
        }
        let label = match raw[0] {
            0x00 => "Boot record",
            0x01 => "PVD",
            0x02 => "SVD/Joliet",
            0xFF => "VD Terminator",
            _ => "Volume descriptor",
        };
        if (lba as usize) < labels.len() {
            labels[lba as usize] = label;
        }
        if raw[0] == 0xFF {
            break;
        }
    }

    // Path table sectors.
    let pt_lba = reader.l_path_table_lba();
    let pt_sectors = (reader.path_table_size() as usize).div_ceil(2048).max(1);
    for i in 0..pt_sectors {
        let s = pt_lba as usize + i;
        if s < labels.len() && labels[s] == "Unallocated" {
            labels[s] = "Path table";
        }
    }

    // Root directory LBA from the PVD root record (bytes 158..162).
    let pvd = reader.read_sector_raw(16)?;
    let root_lba = u32::from_le_bytes(pvd[158..162].try_into().unwrap());
    if (root_lba as usize) < labels.len() {
        labels[root_lba as usize] = "Root directory";
    }

    // Directories and file data from the tree walk.
    let entries = reader.walk()?;
    for e in &entries {
        let lba = e.record.lba as usize;
        if e.record.is_dir() {
            if lba < labels.len() && labels[lba] == "Unallocated" {
                labels[lba] = "Directory";
            }
        } else {
            let sectors = (e.record.size as u64).div_ceil(2048).max(1) as usize;
            for s in lba..(lba + sectors) {
                if s < labels.len() && labels[s] == "Unallocated" {
                    labels[s] = "File data";
                }
            }
        }
    }

    // Boot catalog image sectors.
    if let Ok(boot) = reader.boot_entries() {
        for b in &boot {
            let s = b.lba as usize;
            if s < labels.len() && labels[s] == "Unallocated" {
                labels[s] = "Boot image";
            }
        }
    }

    // ── Render: collapse consecutive runs of identical labels ──
    let bytes = total as u64 * 2048;
    let mut out = format!("Sector Map: {total} sectors  {bytes} bytes\n");
    out.push_str(&"-".repeat(80));
    out.push('\n');
    out.push_str("  Sector  Type                 Size\n");
    out.push_str("--------  -------------------  ----------\n");

    let mut i = 0usize;
    while i < labels.len() {
        let start = i;
        let label = labels[i];
        while i < labels.len() && labels[i] == label {
            i += 1;
        }
        let end = i - 1;
        let count = (end - start + 1) as u64;
        let range =
            if start == end { format!("{start:>8}") } else { format!("{start:>4}-{end:<3}") };
        out.push_str(&format!("{range}  {label:<19}  {:>10}\n", count * 2048));
    }
    Ok(out)
}
