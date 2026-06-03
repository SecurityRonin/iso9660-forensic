use iso9660_forensic::IsoReader;
use std::io::{Read, Seek};

/// Run the full forensic audit suite and produce an ASCII report.
pub fn run<R: Read + Seek>(reader: &mut IsoReader<R>, image_name: &str) -> String {
    let _ = (reader, image_name);
    String::new()
}
