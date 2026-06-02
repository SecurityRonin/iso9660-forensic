use iso9660_forensic::IsoReader;
use std::io::{Read, Seek};

pub fn run<R: Read + Seek>(reader: &mut IsoReader<R>) -> String {
    let _ = reader;
    String::new()
}
