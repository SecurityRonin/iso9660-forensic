use iso9660_forensic::{IsoError, IsoReader};
use std::io::{Read, Seek};

/// Hex dump one logical sector.
///
/// Output format — pure ASCII, fixed-width columns, pipe separators:
///
///   Sector 16  (file offset 0x00008000)  2048 bytes
///   ------------------------------------------------------------------------
///   00000000  01 43 44 30 30 31 01 00  | .CD001.. |
///   00000008  20 20 20 20 20 20 20 20  |          |
///   ...
///
/// Every data line is exactly 47 chars before the newline:
///   8 (addr) + 2 + 23 (hex, always padded) + 2 + 1 (|) + 1 + 8 (ascii) + 1 + 1 (|)
pub fn run<R: Read + Seek>(reader: &mut IsoReader<R>, lba: u64) -> Result<String, IsoError> {
    let sector = reader.read_sector_raw(lba)?;
    let file_offset = reader.sector_mode().user_data_pos(lba);

    let mut out = String::new();
    out.push_str(&format!(
        "Sector {lba}  (file offset 0x{file_offset:08X})  2048 bytes\n"
    ));
    out.push_str(&"-".repeat(72));
    out.push('\n');

    for (row, chunk) in sector.chunks(8).enumerate() {
        let addr = row * 8;

        // Hex column: "HH HH HH HH HH HH HH HH" — always 23 chars wide.
        // 8 bytes = 7×"HH " + "HH" = 23 chars.  Fewer bytes: pad with spaces.
        let hex: String = chunk
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ");

        // ASCII column: printable graphic chars as-is, all others as '.'.
        // Always 8 chars wide (padded with spaces for short rows).
        let ascii: String = chunk
            .iter()
            .map(|b| if b.is_ascii_graphic() { *b as char } else { '.' })
            .collect();

        // Format: XXXXXXXX  <hex:23>  | <ascii:8> |
        out.push_str(&format!(
            "{addr:08X}  {hex:<23}  | {ascii:<8} |\n"
        ));
    }
    Ok(out)
}
