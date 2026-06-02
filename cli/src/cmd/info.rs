use iso9660_forensic::{sector::SectorMode, IsoReader};
use std::io::{Read, Seek};

pub fn run<R: Read + Seek>(reader: &mut IsoReader<R>) -> String {
    let mut exts: Vec<&str> = Vec::new();
    if reader.has_rock_ridge() { exts.push("Rock Ridge"); }
    if reader.has_joliet()     { exts.push("Joliet"); }
    if reader.has_udf()        { exts.push("UDF"); }
    let ext_str = if exts.is_empty() { "none".to_owned() } else { exts.join(", ") };

    let mode_str = match reader.sector_mode() {
        SectorMode::Iso2048  => "ISO 9660 / 2048-byte sectors",
        SectorMode::Raw2352  => "Raw CD-ROM / 2352-byte sectors",
    };

    let sectors = reader.volume_space_size();
    let bytes   = sectors as u64 * 2048;

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

    out
}
