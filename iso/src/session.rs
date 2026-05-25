//! Multi-session ISO support.
//!
//! Multi-session CDs write each session to a new track. The last session's
//! PVD chain is the authoritative one (it extends the previous sessions).
//! In ISO image files, sessions are concatenated: a naive reader that stops
//! at sector 16's PVD misses everything added in later sessions.
//!
//! Detection strategy: scan the image for all valid PVD signatures at
//! multiples of `scan_step` sectors. Report all sessions found; the
//! last one is the active session.

/// Scan for all LBAs where a valid ISO 9660 PVD exists.
///
/// Reads every `step` sectors and looks for the `\x01CD001` PVD signature.
/// Returns a sorted list of PVD LBAs (ascending).
///
/// `step` of 16 covers typical session gaps (~75 sectors, but exact alignment
/// is not guaranteed for arbitrary images). A step of 1 is exhaustive but slow.
pub fn scan_pvd_lbas(image_bytes: &[u8], sector_size: usize) -> Vec<u64> {
    let mut lbas = Vec::new();
    let total_sectors = image_bytes.len() / sector_size;

    for lba in 16..total_sectors {
        let offset = lba * sector_size;
        if offset + 7 > image_bytes.len() {
            break;
        }
        let sector = &image_bytes[offset..offset + 7];
        if sector[0] == 0x01 && &sector[1..6] == b"CD001" && sector[6] == 0x01 {
            lbas.push(lba as u64);
        }
    }
    lbas
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_finds_single_session() {
        // A 17-sector zero image with a fake PVD signature at sector 16.
        let mut img = vec![0u8; 17 * 2048];
        img[16 * 2048] = 0x01;
        img[16 * 2048 + 1..16 * 2048 + 6].copy_from_slice(b"CD001");
        img[16 * 2048 + 6] = 0x01;

        let lbas = scan_pvd_lbas(&img, 2048);
        assert_eq!(lbas, vec![16u64]);
    }

    #[test]
    fn scan_finds_two_sessions() {
        // Two PVDs: at sector 16 and sector 48.
        let mut img = vec![0u8; 49 * 2048];
        for &lba in &[16usize, 48usize] {
            img[lba * 2048] = 0x01;
            img[lba * 2048 + 1..lba * 2048 + 6].copy_from_slice(b"CD001");
            img[lba * 2048 + 6] = 0x01;
        }
        let lbas = scan_pvd_lbas(&img, 2048);
        assert_eq!(lbas, vec![16u64, 48u64]);
    }
}
