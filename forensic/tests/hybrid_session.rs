#![allow(clippy::unwrap_used, clippy::expect_used)]

use iso9660_forensic::IsoReader;
use std::io::Cursor;

const SECTOR: usize = 2048;

fn write_pvd(image: &mut [u8], lba: usize, root_lba: u32, volume_sectors: u32) {
    let pvd = &mut image[lba * SECTOR..(lba + 1) * SECTOR];
    pvd[0] = 0x01;
    pvd[1..6].copy_from_slice(b"CD001");
    pvd[6] = 0x01;
    pvd[80..84].copy_from_slice(&volume_sectors.to_le_bytes());
    pvd[84..88].copy_from_slice(&volume_sectors.to_be_bytes());
    pvd[128..130].copy_from_slice(&(SECTOR as u16).to_le_bytes());
    pvd[130..132].copy_from_slice(&(SECTOR as u16).to_be_bytes());
    pvd[132..136].copy_from_slice(&10u32.to_le_bytes());
    pvd[140..144].copy_from_slice(&1u32.to_le_bytes());
    pvd[148..152].copy_from_slice(&1u32.to_be_bytes());
    pvd[156] = 34;
    pvd[158..162].copy_from_slice(&root_lba.to_le_bytes());
    pvd[162..166].copy_from_slice(&root_lba.to_be_bytes());
    pvd[166..170].copy_from_slice(&(SECTOR as u32).to_le_bytes());
    pvd[170..174].copy_from_slice(&(SECTOR as u32).to_be_bytes());
    pvd[181] = 0x02;
    pvd[188] = 1;
}

fn write_terminator(image: &mut [u8], lba: usize) {
    let terminator = &mut image[lba * SECTOR..(lba + 1) * SECTOR];
    terminator[0] = 0xff;
    terminator[1..6].copy_from_slice(b"CD001");
    terminator[6] = 0x01;
}

fn write_root(image: &mut [u8], lba: usize, file_lba: usize, file_name: &[u8]) {
    let root = &mut image[lba * SECTOR..(lba + 1) * SECTOR];
    for (offset, parent_lba) in [(0, lba), (34, lba)] {
        root[offset] = 34;
        root[offset + 2..offset + 6].copy_from_slice(&(parent_lba as u32).to_le_bytes());
        root[offset + 10..offset + 14].copy_from_slice(&(SECTOR as u32).to_le_bytes());
        root[offset + 25] = 0x02;
        root[offset + 32] = 1;
        if offset == 34 {
            root[offset + 33] = 0x01;
        }
    }

    let offset = 68;
    let record_len = 33 + file_name.len() + usize::from(file_name.len() % 2 == 0);
    root[offset] = record_len as u8;
    root[offset + 2..offset + 6].copy_from_slice(&(file_lba as u32).to_le_bytes());
    root[offset + 10..offset + 14].copy_from_slice(&13u32.to_le_bytes());
    root[offset + 32] = file_name.len() as u8;
    root[offset + 33..offset + 33 + file_name.len()].copy_from_slice(file_name);
}

/// The image contains a valid ISO descriptor chain at LBA 16 and a second
/// descriptor chain at LBA 32 whose root pointer targets file data, not a
/// directory. This mirrors the Fedora/Ubuntu hybrid layout that triggered the
/// false-positive session selection.
fn hybrid_iso_with_decoy_session() -> Vec<u8> {
    let mut image = vec![0u8; 64 * SECTOR];

    write_pvd(&mut image, 16, 18, 64);
    write_terminator(&mut image, 17);
    write_root(&mut image, 18, 20, b"PAYLOAD.BIN");
    image[20 * SECTOR..20 * SECTOR + 13].copy_from_slice(b"valid payload");

    write_pvd(&mut image, 32, 57, 64);
    write_terminator(&mut image, 33);
    image[57 * SECTOR..57 * SECTOR + 16].copy_from_slice(&[
        0x7c, 0x00, 0xa9, 0x07, 0x00, 0x00, 0x00, 0x00, 0x07, 0xa9, 0xd8, 0x06, 0x00, 0x00, 0x00,
        0x00,
    ]);

    image
}

#[test]
fn ignores_hybrid_decoy_session_and_extracts_file() {
    let mut reader = IsoReader::open(Cursor::new(hybrid_iso_with_decoy_session()))
        .expect("hybrid ISO should open");

    assert_eq!(reader.session_count(), 1, "only the structurally valid session is active");
    assert_eq!(reader.root_dir_lba(), 18, "the decoy PVD must not replace the real PVD");

    let entry = reader.find_entry("PAYLOAD.BIN").expect("payload should be listed");
    assert_eq!(
        reader.read_file_entry(&entry).expect("payload should be extracted"),
        b"valid payload"
    );
}
