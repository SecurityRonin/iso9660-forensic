use std::fs::File;
use iso9660_forensic::{IsoReader, pvd::IsoDateTime};

fn open_udf() -> IsoReader<File> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/udf_bridge.iso");
    IsoReader::open(File::open(path).unwrap()).unwrap()
}

#[test]
fn pvd_string_fields_contain_no_null_bytes() {
    let r = open_udf();
    for (name, s) in [
        ("system_id", r.system_id()),
        ("volume_set_id", r.volume_set_id()),
        ("publisher_id", r.publisher_id()),
        ("data_preparer_id", r.data_preparer_id()),
        ("application_id", r.application_id()),
        ("copyright_file_id", r.copyright_file_id()),
        ("abstract_file_id", r.abstract_file_id()),
        ("bibliographic_file_id", r.bibliographic_file_id()),
    ] {
        assert!(!s.contains('\0'), "{name} contains NUL: {s:?}");
    }
}

#[test]
fn pvd_volume_space_size_positive() {
    assert!(open_udf().volume_space_size() > 0);
}

#[test]
fn pvd_logical_block_size_is_2048() {
    assert_eq!(open_udf().logical_block_size(), 2048);
}

#[test]
fn pvd_path_table_lbas_nonzero() {
    let r = open_udf();
    assert!(r.l_path_table_lba() > 0, "L-path LBA must be nonzero");
    assert!(r.m_path_table_lba() > 0, "M-path LBA must be nonzero");
}

#[test]
fn pvd_path_table_size_positive() {
    assert!(open_udf().path_table_size() > 0);
}

#[test]
fn pvd_creation_time_parseable() {
    let r = open_udf();
    let dt = r.volume_creation_time().expect("creation time must be Some");
    assert!(dt.year >= 2000 && dt.year <= 2100, "year={}", dt.year);
    assert!((1..=12).contains(&dt.month), "month={}", dt.month);
    assert!((1..=31).contains(&dt.day), "day={}", dt.day);
}

#[test]
fn pvd_application_id_accessible() {
    // Just verify the field is accessible and contains no null bytes.
    let s = open_udf().application_id().to_string();
    assert!(!s.contains('\0'), "application_id contains NUL: {s:?}");
}

#[test]
fn iso_datetime_struct_fields() {
    let dt = IsoDateTime {
        year: 2024, month: 6, day: 15,
        hour: 12, minute: 30, second: 0,
        centisecond: 0, tz_offset_15min: 0,
    };
    assert_eq!(dt.year, 2024);
    assert_eq!(dt.month, 6);
    assert_eq!(dt.day, 15);
}

#[test]
fn pvd_volume_space_consistent() {
    let r = open_udf();
    let total = r.volume_space_size() as u64 * r.logical_block_size() as u64;
    assert!(total > 0);
}

#[test]
fn pvd_volume_space_size_field_accessible() {
    // volume_space_size is also on PrimaryVolumeDescriptor directly (unchanged)
    let r = open_udf();
    assert!(r.volume_space_size() > 0);
}
