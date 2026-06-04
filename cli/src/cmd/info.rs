use iso9660_forensic::{sector::SectorMode, IsoReader, UdfPartitionKind};
use std::io::{Read, Seek};

pub fn run<R: Read + Seek>(reader: &mut IsoReader<R>) -> String {
    let mut exts: Vec<&str> = Vec::new();
    if reader.has_rock_ridge() {
        exts.push("Rock Ridge");
    }
    if reader.has_joliet() {
        exts.push("Joliet");
    }
    if reader.has_udf() {
        exts.push("UDF");
    }
    let ext_str = if exts.is_empty() { "none".to_owned() } else { exts.join(", ") };

    let mode_str = match reader.sector_mode() {
        SectorMode::Iso2048 => "ISO 9660 / 2048-byte sectors",
        SectorMode::Raw2352 => "Raw CD-ROM / 2352-byte sectors (Mode 1)",
        SectorMode::Raw2352Mode2 => "Raw CD-ROM / 2352-byte sectors (Mode 2 Form 1)",
        SectorMode::Raw2448 => "Raw CD-ROM / 2448-byte sectors (Mode 1 + subchannel)",
        SectorMode::Raw2448Mode2 => "Raw CD-ROM / 2448-byte sectors (Mode 2 Form 1 + subchannel)",
        SectorMode::Mode2_2336 => "Raw CD-ROM / 2336-byte sectors (Mode 2)",
    };

    let sectors = reader.volume_space_size();
    let bytes = sectors as u64 * 2048;

    let mut out = String::new();
    out.push_str(&format!("Volume Label:     {}\n", reader.volume_label()));
    out.push_str(&format!("System ID:        {}\n", reader.system_id()));
    out.push_str(&format!("Volume Set:       {}\n", reader.volume_set_id()));
    out.push_str(&format!("Publisher:        {}\n", reader.publisher_id()));
    out.push_str(&format!("Data Preparer:    {}\n", reader.data_preparer_id()));
    out.push_str(&format!("Application:      {}\n", reader.application_id()));
    out.push_str(&format!("Volume Size:      {sectors} sectors ({bytes} bytes)\n"));
    out.push_str(&format!("Sector Mode:      {mode_str}\n"));
    out.push_str(&format!("Sessions:         {}\n", reader.session_count()));
    out.push_str(&format!("Extensions:       {ext_str}\n"));

    if let Some(t) = reader.volume_creation_time() {
        out.push_str(&format!("Created:          {t:?}\n"));
    }
    if let Some(label) = reader.joliet_label() {
        out.push_str(&format!("Joliet Label:     {label}\n"));
    }

    if reader.has_udf() {
        let kind = match reader.udf_partition_kind() {
            Some(UdfPartitionKind::Physical) => "Physical (Type 1)",
            Some(UdfPartitionKind::Virtual) => {
                "Virtual / VAT (Type 2 — advanced, not fully resolved)"
            }
            Some(UdfPartitionKind::Sparable) => "Sparable (Type 2 — advanced, not fully resolved)",
            Some(UdfPartitionKind::Metadata) => "Metadata (Type 2 — advanced, not fully resolved)",
            Some(UdfPartitionKind::Unknown) => "Unknown",
            None => "n/a",
        };
        let maps = reader.udf_partition_map_count().unwrap_or(0);
        out.push_str(&format!("UDF Partition:    {kind} ({maps} map(s))\n"));
    }

    // Apple HFS+ hybrid: report a co-resident HFS/HFSX volume if present.
    if let Ok(Some(vol)) = reader.hfs_volume() {
        let kind = match vol.kind {
            iso9660_forensic::hfs::HfsKind::HfsPlus => "HFS+",
            iso9660_forensic::hfs::HfsKind::Hfsx => "HFSX",
        };
        out.push_str(&format!(
            "Apple HFS:        {kind} hybrid ({} bytes, {}-byte blocks)\n",
            vol.volume_size(),
            vol.block_size
        ));
    }

    // Boot catalog section — always present so callers can rely on it.
    match reader.boot_entries() {
        Ok(entries) if entries.is_empty() => {
            out.push_str("Boot Catalog:     none\n");
        }
        Ok(entries) => {
            out.push_str(&format!(
                "Boot Catalog:     {} entr{}\n",
                entries.len(),
                if entries.len() == 1 { "y" } else { "ies" }
            ));
            for (i, e) in entries.iter().enumerate() {
                out.push_str(&format!(
                    "  [{:>2}] bootable={:<5}  lba={}\n",
                    i + 1,
                    e.bootable,
                    e.lba
                ));
            }
        }
        Err(_) => {
            out.push_str("Boot Catalog:     (unreadable)\n");
        }
    }

    out
}
