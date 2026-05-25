//! UDF (Universal Disk Format) detection.
//!
//! UDF bridge discs carry both ISO 9660 and UDF structures on the same sectors.
//! The UDF recognition sequence starts at sector 16: each Volume Structure
//! Descriptor is 2048 bytes with a 5-byte identifier at bytes 1-5.
//!
//! Identifiers: "BEA01" (Extended Area Descriptor), "NSR02" or "NSR03"
//! (OSTA CS0 UDF mark), "TEA01" (Terminating Extended Area Descriptor).
//! NSR02/NSR03 presence is the definitive UDF indicator.

use std::io::{Read, Seek, SeekFrom};

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
        // TEA01 = end of recognition sequence
        if id == b"TEA01" {
            break;
        }
    }
    false
}
