//! UDF (Universal Disk Format) — detection and file-entry traversal.
//!
//! UDF bridge discs carry both ISO 9660 and UDF structures on the same sectors.
//! The UDF recognition sequence starts at sector 16: each Volume Structure
//! Descriptor is 2048 bytes with a 5-byte identifier at bytes 1-5.
//!
//! Identifiers: "BEA01" (Extended Area Descriptor), "NSR02" or "NSR03"
//! (OSTA CS0 UDF mark), "TEA01" (Terminating Extended Area Descriptor).
//! NSR02/NSR03 presence is the definitive UDF indicator.
//!
//! # Full UDF traversal
//!
//! Descriptor chain: AVDP (LBA 256) → VDS → Partition Descriptor (partition
//! start LBA) + Logical Volume Descriptor (FSD location) → File Set Descriptor
//! (root dir FE LBA) → File Entry → File Identifier Descriptors.
//!
//! All physical LBAs satisfy: `phys_lba = partition_start + logical_block_num`.

use std::io::{Read, Seek, SeekFrom};

// ── ECMA-167 / UDF tag identifiers ───────────────────────────────────────────

const TAG_AVDP: u16 = 2;
const TAG_PD: u16 = 5;
const TAG_LVD: u16 = 6;
const TAG_TERM: u16 = 8;
const TAG_FSD: u16 = 256;
const TAG_FID: u16 = 257;
const TAG_FE: u16 = 260;
/// Some UDF implementations (e.g. older genisoimage) write 261 for File Entry.
const TAG_FE_ALT: u16 = 261;
const TAG_EFE: u16 = 266;

// FID File Characteristics bits
const FC_DIRECTORY: u8 = 0x02;
const FC_PARENT: u8 = 0x08;

// ICB allocation type (FE flags bits 0-2)
const ALLOC_SHORT: u16 = 0;
const ALLOC_LONG: u16 = 1;
const ALLOC_INLINE: u16 = 3;

// Extent type bits 30-31 of extent_length field
const EXTENT_RECORDED: u32 = 0x0000_0000; // 0b00 in bits 30-31

// ── Public types ──────────────────────────────────────────────────────────────

/// A single entry returned by UDF directory traversal.
#[derive(Debug, Clone)]
pub struct UdfFileEntry {
    /// Decoded filename (OSTA CS0: UTF-8 or UTF-16BE).
    pub name: String,
    /// True if this entry is a directory.
    pub is_dir: bool,
    /// File size in bytes (Information Length from FE).
    pub size: u64,
    /// Physical LBA of the File Entry descriptor sector.
    pub fe_lba: u32,
}

// ── Internal UDF state ────────────────────────────────────────────────────────

pub(crate) struct UdfState {
    pub partition_start: u32,
    pub root_fe_lba: u32,
}

// ── UDF detection (existing public API) ──────────────────────────────────────

/// True if the image has a UDF recognition sequence (NSR02 or NSR03).
///
/// Scans volume structure descriptors starting at LBA 16, up to LBA 32.
pub fn detect_udf<R: Read + Seek>(reader: &mut R) -> bool {
    let mut buf = [0u8; 6];
    for lba in 16u64..32 {
        let pos = lba * 2048 + 1;
        if reader.seek(SeekFrom::Start(pos)).is_err() {
            break;
        }
        if reader.read_exact(&mut buf).is_err() {
            break;
        }
        let id = &buf[..5];
        if id == b"NSR02" || id == b"NSR03" {
            return true;
        }
        if id == b"TEA01" {
            break;
        }
    }
    false
}

// ── UDF traversal (new internal API) ─────────────────────────────────────────

/// Try to parse the AVDP → VDS → FSD chain, returning state needed for
/// directory traversal. Returns `None` if the image lacks a valid UDF structure.
pub(crate) fn parse_udf_state<R: Read + Seek>(reader: &mut R) -> Option<UdfState> {
    let (vds_loc, vds_len) = read_avdp(reader)?;
    let (partition_start, fsd_lba) = read_vds(reader, vds_loc, vds_len)?;
    let root_fe_lba = read_fsd(reader, fsd_lba, partition_start)?;
    Some(UdfState { partition_start, root_fe_lba })
}

/// Read all non-parent File Identifier Descriptors from the directory whose
/// File Entry resides at `dir_fe_lba`, returning one `UdfFileEntry` per child.
pub(crate) fn read_dir_at_lba<R: Read + Seek>(
    reader: &mut R,
    partition_start: u32,
    dir_fe_lba: u32,
) -> Option<Vec<UdfFileEntry>> {
    let dir_data = read_fe_data(reader, partition_start, dir_fe_lba)?;
    Some(parse_fids(reader, partition_start, &dir_data))
}

/// Read the data extent of the File Entry at `fe_lba`.
pub(crate) fn read_fe_data<R: Read + Seek>(
    reader: &mut R,
    partition_start: u32,
    fe_lba: u32,
) -> Option<Vec<u8>> {
    let mut sector = [0u8; 2048];
    seek_read(reader, fe_lba as u64 * 2048, &mut sector)?;

    let tag_ident = u16::from_le_bytes([sector[0], sector[1]]);
    let is_efe = tag_ident == TAG_EFE;
    if tag_ident != TAG_FE && tag_ident != TAG_FE_ALT && !is_efe {
        return None;
    }

    let icb_flags = u16::from_le_bytes([sector[34], sector[35]]);
    let alloc_type = icb_flags & 0x0007;
    let info_len = u64::from_le_bytes(sector[56..64].try_into().unwrap());

    // EFE has an additional ObjectSize (8 bytes) field before L_EA / L_AD.
    let (ea_off, ad_off, header) = if is_efe {
        (176usize, 180usize, 184usize)
    } else {
        (168usize, 172usize, 176usize)
    };

    if ad_off + 4 > sector.len() {
        return None;
    }
    let ea_len = u32::from_le_bytes(sector[ea_off..ea_off + 4].try_into().unwrap()) as usize;
    let ad_len = u32::from_le_bytes(sector[ad_off..ad_off + 4].try_into().unwrap()) as usize;

    let ad_start = header + ea_len;
    let ad_end = ad_start + ad_len;
    if ad_end > sector.len() {
        return None;
    }
    let ad_area = sector[ad_start..ad_end].to_vec();

    match alloc_type {
        ALLOC_INLINE => Some(ad_area[..info_len.min(ad_area.len() as u64) as usize].to_vec()),
        ALLOC_SHORT => read_extents_short(reader, partition_start, &ad_area, info_len),
        ALLOC_LONG => read_extents_long(reader, partition_start, &ad_area, info_len),
        _ => None,
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Parse AVDP at LBA 256. Returns (vds_location, vds_length).
fn read_avdp<R: Read + Seek>(reader: &mut R) -> Option<(u32, u32)> {
    let mut sector = [0u8; 2048];
    seek_read(reader, 256 * 2048, &mut sector)?;
    if u16::from_le_bytes([sector[0], sector[1]]) != TAG_AVDP {
        return None;
    }
    let vds_len = u32::from_le_bytes(sector[16..20].try_into().unwrap());
    let vds_loc = u32::from_le_bytes(sector[20..24].try_into().unwrap());
    Some((vds_loc, vds_len))
}

/// Scan VDS to find PD (partition start) and LVD (FSD location).
/// Returns (partition_start_lba, fsd_physical_lba).
fn read_vds<R: Read + Seek>(
    reader: &mut R,
    vds_loc: u32,
    vds_len: u32,
) -> Option<(u32, u32)> {
    let sectors = (vds_len as usize).div_ceil(2048);
    let mut partition_start: Option<u32> = None;
    let mut fsd_lbn: Option<u32> = None;

    for i in 0..sectors {
        let mut sector = [0u8; 2048];
        seek_read(reader, (vds_loc as u64 + i as u64) * 2048, &mut sector)?;
        let tag_ident = u16::from_le_bytes([sector[0], sector[1]]);
        match tag_ident {
            TAG_PD => {
                // Partition Starting Location at offset 188
                let psl = u32::from_le_bytes(sector[188..192].try_into().unwrap());
                partition_start = Some(psl);
            }
            TAG_LVD => {
                // LV Contents Use long_ad at offset 248:
                //   extent_length [248..252], logical_block_num [252..256]
                let lbn = u32::from_le_bytes(sector[252..256].try_into().unwrap());
                fsd_lbn = Some(lbn);
            }
            TAG_TERM | 0 => break,
            _ => {}
        }
    }

    let ps = partition_start?;
    let fsd = fsd_lbn?;
    Some((ps, ps + fsd))
}

/// Parse FSD at `fsd_lba` to find the root directory FE logical block number.
fn read_fsd<R: Read + Seek>(
    reader: &mut R,
    fsd_lba: u32,
    partition_start: u32,
) -> Option<u32> {
    let mut sector = [0u8; 2048];
    seek_read(reader, fsd_lba as u64 * 2048, &mut sector)?;
    if u16::from_le_bytes([sector[0], sector[1]]) != TAG_FSD {
        return None;
    }
    // FSD field sizes (ECMA-167 Table 20):
    //   Tag(16) + RecordingDate(12) + Interchange/Charset fields(28) +
    //   LV Ident CharSet(64) + LV Identifier(128) + FS CharSet(64) +
    //   FS Identifier(32) + Copyright FI(32) + Abstract FI(32) = 408 bytes.
    // Root Directory ICB (long_ad) starts at offset 400:
    //   extent_length [400..404], logical_block_num [404..408]
    let lbn = u32::from_le_bytes(sector[404..408].try_into().unwrap());
    Some(partition_start + lbn)
}

/// Detect whether FIDs in this directory data use a standard 16-byte ECMA-167 tag
/// or an extended 18-byte tag written by some UDF tools.
///
/// Some implementations append 2 extra bytes after the standard tag before the
/// FID body, making all field offsets shift by 2. Detection heuristic: read the
/// ICB logical block number at both candidate positions and use whichever gives a
/// plausible value (< 65536, fitting discs up to ~128 GB).
fn detect_fid_tag_size(data: &[u8]) -> usize {
    let mut off = 0;
    while off + 28 <= data.len() {
        let ti = u16::from_le_bytes([data[off], data[off + 1]]);
        if ti == TAG_FID {
            let lbn16 = if off + 26 <= data.len() {
                u32::from_le_bytes(data[off + 22..off + 26].try_into().unwrap())
            } else {
                u32::MAX
            };
            let lbn18 = if off + 28 <= data.len() {
                u32::from_le_bytes(data[off + 24..off + 28].try_into().unwrap())
            } else {
                u32::MAX
            };
            if lbn16 < 0x10000 {
                return 16;
            }
            if lbn18 < 0x10000 {
                return 18;
            }
            return 16; // can't determine; fall back to standard
        }
        off += 4;
    }
    16
}

/// Parse File Identifier Descriptors from raw directory data.
fn parse_fids<R: Read + Seek>(
    reader: &mut R,
    partition_start: u32,
    data: &[u8],
) -> Vec<UdfFileEntry> {
    // Some UDF tools write an extra 2 bytes after the standard 16-byte tag.
    // tag_size is 16 (standard) or 18 (extended); body fields follow at tag_size.
    let tag_size = detect_fid_tag_size(data);
    let min_fid = tag_size + 20; // tag + chars(1)+L_FI(1)+ICB(16)+L_IU(2)

    let mut entries = Vec::new();
    let mut off = 0;

    while off + min_fid <= data.len() {
        let tag_ident = u16::from_le_bytes([data[off], data[off + 1]]);
        if tag_ident != TAG_FID {
            // Advance 4 bytes to stay aligned; skip padding or unknown tags.
            off += 4;
            continue;
        }

        // CRC_len (at tag[10..12]) gives the true body extent from byte 16.
        let crc_len = u16::from_le_bytes([data[off + 10], data[off + 11]]) as usize;
        let fid_advance = ((16 + crc_len + 3) & !3).max(min_fid);
        if off + fid_advance > data.len() {
            break;
        }

        let file_chars = data[off + tag_size];
        let file_id_len = data[off + tag_size + 1] as usize;
        // ICB long_ad: extent_length at body[2..6], lbn at body[6..10]
        let icb_lbn = if off + tag_size + 10 <= data.len() {
            u32::from_le_bytes(
                data[off + tag_size + 6..off + tag_size + 10].try_into().unwrap(),
            )
        } else {
            off += fid_advance.max(4);
            continue;
        };
        let impl_use_len = if off + tag_size + 20 <= data.len() {
            u16::from_le_bytes([data[off + tag_size + 18], data[off + tag_size + 19]]) as usize
        } else {
            off += fid_advance.max(4);
            continue;
        };

        if file_chars & FC_PARENT == 0 {
            let is_dir = file_chars & FC_DIRECTORY != 0;
            let fe_lba = partition_start + icb_lbn;

            let id_start = off + tag_size + 20 + impl_use_len;
            let id_end = (id_start + file_id_len).min(data.len());
            let name = if id_end > id_start {
                decode_osta_cs0(&data[id_start..id_end])
            } else {
                String::new()
            };

            // Read the FE to get the canonical file size.
            let size = read_fe_info_len(reader, fe_lba).unwrap_or(0);

            entries.push(UdfFileEntry { name, is_dir, size, fe_lba });
        }

        off += fid_advance.max(4);
    }
    entries
}

/// Read the Information Length (file size) from a File Entry at `fe_lba`.
fn read_fe_info_len<R: Read + Seek>(reader: &mut R, fe_lba: u32) -> Option<u64> {
    let mut sector = [0u8; 2048];
    seek_read(reader, fe_lba as u64 * 2048, &mut sector)?;
    let tag_ident = u16::from_le_bytes([sector[0], sector[1]]);
    if tag_ident != TAG_FE && tag_ident != TAG_FE_ALT && tag_ident != TAG_EFE {
        return None;
    }
    Some(u64::from_le_bytes(sector[56..64].try_into().unwrap()))
}

/// Collect data from short allocation descriptors (8 bytes each).
fn read_extents_short<R: Read + Seek>(
    reader: &mut R,
    partition_start: u32,
    ad_area: &[u8],
    total_len: u64,
) -> Option<Vec<u8>> {
    let mut data = Vec::new();
    let mut pos = 0;
    while pos + 8 <= ad_area.len() && (data.len() as u64) < total_len {
        let len_raw = u32::from_le_bytes(ad_area[pos..pos + 4].try_into().unwrap());
        let ext_pos = u32::from_le_bytes(ad_area[pos + 4..pos + 8].try_into().unwrap());
        let ext_type = len_raw >> 30;
        let ext_len = (len_raw & 0x3FFF_FFFF) as usize;
        if ext_type == (EXTENT_RECORDED >> 30) && ext_len > 0 {
            let phys = (partition_start as u64 + ext_pos as u64) * 2048;
            read_extent(reader, phys, ext_len, total_len, &mut data)?;
        }
        pos += 8;
    }
    data.truncate(total_len as usize);
    Some(data)
}

/// Collect data from long allocation descriptors (16 bytes each).
fn read_extents_long<R: Read + Seek>(
    reader: &mut R,
    partition_start: u32,
    ad_area: &[u8],
    total_len: u64,
) -> Option<Vec<u8>> {
    let mut data = Vec::new();
    let mut pos = 0;
    while pos + 16 <= ad_area.len() && (data.len() as u64) < total_len {
        let len_raw = u32::from_le_bytes(ad_area[pos..pos + 4].try_into().unwrap());
        let lbn = u32::from_le_bytes(ad_area[pos + 4..pos + 8].try_into().unwrap());
        let ext_type = len_raw >> 30;
        let ext_len = (len_raw & 0x3FFF_FFFF) as usize;
        if ext_type == (EXTENT_RECORDED >> 30) && ext_len > 0 {
            let phys = (partition_start as u64 + lbn as u64) * 2048;
            read_extent(reader, phys, ext_len, total_len, &mut data)?;
        }
        pos += 16;
    }
    data.truncate(total_len as usize);
    Some(data)
}

/// Read `ext_len` bytes from `byte_pos`, appending to `data` up to `total_len`.
fn read_extent<R: Read + Seek>(
    reader: &mut R,
    byte_pos: u64,
    ext_len: usize,
    total_len: u64,
    data: &mut Vec<u8>,
) -> Option<()> {
    let sectors = ext_len.div_ceil(2048);
    for i in 0..sectors {
        let mut sector = [0u8; 2048];
        seek_read(reader, byte_pos + i as u64 * 2048, &mut sector)?;
        let already = data.len() as u64;
        let remaining = total_len.saturating_sub(already) as usize;
        let sector_bytes = (ext_len - i * 2048).min(2048);
        let take = sector_bytes.min(remaining);
        data.extend_from_slice(&sector[..take]);
    }
    Some(())
}

/// Decode an OSTA CS0 encoded identifier: first byte is compression ID
/// (8 = UTF-8, 16 = UTF-16BE), remainder is character data.
fn decode_osta_cs0(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let comp_id = bytes[0];
    let payload = &bytes[1..];
    match comp_id {
        8 => String::from_utf8_lossy(payload).into_owned(),
        16 => {
            let pairs: Vec<u16> = payload
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&pairs)
        }
        _ => String::from_utf8_lossy(payload).into_owned(),
    }
}

/// Seek to `byte_pos` and read exactly `buf.len()` bytes; returns `None` on any error.
fn seek_read<R: Read + Seek>(reader: &mut R, byte_pos: u64, buf: &mut [u8]) -> Option<()> {
    reader.seek(SeekFrom::Start(byte_pos)).ok()?;
    reader.read_exact(buf).ok()?;
    Some(())
}
