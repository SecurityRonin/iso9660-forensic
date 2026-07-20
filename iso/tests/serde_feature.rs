#![allow(clippy::unwrap_used, clippy::expect_used)]

// Serde feature — optional Serialize/Deserialize derives on all public structs.
//
// Run with: cargo test --features serde --test serde_feature
//
// Spec: serde 1.x (https://serde.rs).
// Refs: iso9660-rs (Poprdi) serde feature; cdfs (az1) serde derives.

#[cfg(feature = "serde")]
mod tests {
    use iso9660_forensic::el_torito::{BootInfoTable, BootPlatform};
    use iso9660_forensic::findings::{Anomaly, AnomalyKind};
    use iso9660_forensic::path_table::{PathTableEntry, PathTableMismatch};
    use iso9660_forensic::pvd::IsoDateTime;
    use iso9660_forensic::rock_ridge::{ContinuationArea, PosixAttrs};

    fn round_trip<T>(value: &T) -> T
    where
        T: serde::Serialize + for<'de> serde::Deserialize<'de> + std::fmt::Debug + PartialEq,
    {
        let json = serde_json::to_string(value).expect("serialize");
        serde_json::from_str(&json).expect("deserialize")
    }

    #[test]
    fn iso_datetime_round_trip() {
        let dt = IsoDateTime {
            year: 2024,
            month: 6,
            day: 15,
            hour: 12,
            minute: 30,
            second: 0,
            centisecond: 50,
            tz_offset_15min: 4,
        };
        assert_eq!(round_trip(&dt), dt);
    }

    #[test]
    fn boot_platform_round_trip() {
        for p in [
            BootPlatform::X86,
            BootPlatform::PowerPC,
            BootPlatform::Mac,
            BootPlatform::EFI,
            BootPlatform::Other(0x42),
        ] {
            assert_eq!(round_trip(&p), p);
        }
    }

    #[test]
    fn boot_info_table_round_trip() {
        let b =
            BootInfoTable { pvd_lba: 16, boot_file_lba: 42, boot_file_len: 8192, checksum: 0xDEAD };
        assert_eq!(round_trip(&b), b);
    }

    #[test]
    fn path_table_entry_round_trip() {
        let e = PathTableEntry { lba: 100, parent_dir_num: 1, dir_id: b"DIR".to_vec() };
        assert_eq!(round_trip(&e), e);
    }

    #[test]
    fn path_table_mismatch_round_trip() {
        let m = PathTableMismatch { index: 2, description: "LBA mismatch".to_string() };
        assert_eq!(round_trip(&m), m);
    }

    #[test]
    fn posix_attrs_round_trip() {
        let a = PosixAttrs { mode: 0o100644, nlink: 1, uid: 1000, gid: 1000, ino: Some(42) };
        assert_eq!(round_trip(&a), a);
    }

    #[test]
    fn continuation_area_round_trip() {
        let c = ContinuationArea { lba: 25, offset: 64, len: 128 };
        assert_eq!(round_trip(&c), c);
    }

    // Forensic findings derive Serialize (only) — verify the analyzer output
    // serializes with its stable code, evidence, and severity.
    #[test]
    fn anomaly_serializes() {
        let a = Anomaly::new(AnomalyKind::BothEndianMismatch {
            context: "PVD".to_string(),
            field: "volume_space_size".to_string(),
            byte_offset: 32_852,
            le: 188,
            be: 999,
        });
        let json = serde_json::to_string(&a).expect("serialize anomaly");
        assert!(json.contains("ISO-BOTH-ENDIAN"), "{json}");
        assert!(json.contains("volume_space_size"), "{json}");
        assert!(json.contains("High"), "{json}"); // Severity serializes as its variant name
    }
}

// If serde feature is disabled, ensure this file compiles with no-ops.
#[cfg(not(feature = "serde"))]
#[test]
fn serde_feature_not_enabled() {
    // This test always passes — it exists so cargo test doesn't fail with
    // "no tests found" when serde is not enabled.
}
