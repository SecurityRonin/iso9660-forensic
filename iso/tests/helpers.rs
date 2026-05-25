//! Test helpers: build synthetic ISO images using hadris-iso as the oracle.

use std::io::Cursor;
use std::sync::Arc;

use hadris_iso::joliet::JolietLevel;
use hadris_iso::read::PathSeparator;
use hadris_iso::write::options::{CreationFeatures, FormatOptions};
use hadris_iso::write::{File as IsoFile, InputFiles, IsoImageWriter};

pub type IsoCursor = Cursor<Vec<u8>>;

fn base_options(label: &str) -> FormatOptions {
    FormatOptions {
        volume_name: label.to_string(),
        system_id: None,
        volume_set_id: None,
        publisher_id: None,
        preparer_id: None,
        application_id: None,
        sector_size: 2048,
        path_separator: PathSeparator::ForwardSlash,
        features: CreationFeatures::default(),
        strict_charset: false,
    }
}

/// Build a plain ISO with the given label and files.
pub fn build_iso(label: &str, files: Vec<IsoFile>) -> IsoCursor {
    let input = InputFiles {
        path_separator: PathSeparator::ForwardSlash,
        files,
    };
    let opts = base_options(label);
    let mut buf = Cursor::new(vec![0u8; 8 * 1024 * 1024]);
    IsoImageWriter::format_new(&mut buf, input, opts).expect("hadris-iso write failed");
    Cursor::new(buf.into_inner())
}

/// Build an ISO with Rock Ridge extensions.
pub fn build_rr_iso(label: &str, files: Vec<IsoFile>) -> IsoCursor {
    let input = InputFiles {
        path_separator: PathSeparator::ForwardSlash,
        files,
    };
    let mut opts = base_options(label);
    opts.features = CreationFeatures::with_rock_ridge();
    let mut buf = Cursor::new(vec![0u8; 8 * 1024 * 1024]);
    IsoImageWriter::format_new(&mut buf, input, opts).expect("hadris-iso write failed");
    Cursor::new(buf.into_inner())
}

/// Build an ISO with Joliet extensions.
pub fn build_joliet_iso(label: &str, files: Vec<IsoFile>) -> IsoCursor {
    let input = InputFiles {
        path_separator: PathSeparator::ForwardSlash,
        files,
    };
    let mut opts = base_options(label);
    opts.features = CreationFeatures::with_joliet(JolietLevel::Level3);
    let mut buf = Cursor::new(vec![0u8; 8 * 1024 * 1024]);
    IsoImageWriter::format_new(&mut buf, input, opts).expect("hadris-iso write failed");
    Cursor::new(buf.into_inner())
}

/// Build an ISO with an El Torito boot image.
pub fn build_bootable_iso(label: &str) -> IsoCursor {
    use hadris_iso::boot::EmulationType;
    use hadris_iso::boot::options::{BootEntryOptions, BootOptions};

    let boot_image = vec![0xEB, 0xFE, 0x90]; // minimal x86 bootstrap stub
    let files = InputFiles {
        path_separator: PathSeparator::ForwardSlash,
        files: vec![IsoFile::File {
            name: Arc::new("BOOT.BIN".to_string()),
            contents: boot_image,
        }],
    };
    let mut opts = base_options(label);
    opts.features = CreationFeatures {
        el_torito: Some(BootOptions {
            write_boot_catalog: true,
            default: BootEntryOptions {
                boot_image_path: "BOOT.BIN".to_string(),
                load_size: Some(std::num::NonZeroU16::new(4).unwrap()),
                boot_info_table: false,
                grub2_boot_info: false,
                emulation: EmulationType::NoEmulation,
            },
            entries: vec![],
        }),
        ..CreationFeatures::default()
    };
    let mut buf = Cursor::new(vec![0u8; 8 * 1024 * 1024]);
    IsoImageWriter::format_new(&mut buf, files, opts).expect("hadris-iso bootable write failed");
    Cursor::new(buf.into_inner())
}

pub fn file(name: &str, contents: &[u8]) -> IsoFile {
    IsoFile::File {
        name: Arc::new(name.to_string()),
        contents: contents.to_vec(),
    }
}

pub fn dir(name: &str, children: Vec<IsoFile>) -> IsoFile {
    IsoFile::Directory {
        name: Arc::new(name.to_string()),
        children,
    }
}
