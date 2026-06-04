use iso9660_forensic::{IsoError, IsoReader};
use std::io::{Read, Seek};

/// Output format for the hash list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashFormat {
    /// hashdeep-compatible (size,sha256,filename).
    Hashdeep,
    /// Comma-separated (path,size,sha256).
    Csv,
    /// Tab-separated (path<TAB>size<TAB>sha256).
    Tsv,
    /// Sleuth Kit mactime body format (pipe-delimited).
    Mactime,
    /// Digital Forensics XML (DFXML) fileobject records.
    Dfxml,
}

/// Render the per-file SHA-256 hash list in the requested format.
pub fn run<R: Read + Seek>(
    reader: &mut IsoReader<R>,
    format: HashFormat,
) -> Result<String, IsoError> {
    let files = reader.hashlist()?;
    let out = match format {
        HashFormat::Hashdeep => {
            let mut s = String::from("%%%% HASHDEEP-1.0\n%%%% size,sha256,filename\n");
            for f in &files {
                s.push_str(&format!("{},{},{}\n", f.size, f.sha256_hex, f.path));
            }
            s
        }
        HashFormat::Csv => {
            let mut s = String::from("path,size,sha256\n");
            for f in &files {
                s.push_str(&format!("{},{},{}\n", f.path, f.size, f.sha256_hex));
            }
            s
        }
        HashFormat::Tsv => {
            let mut s = String::from("path\tsize\tsha256\n");
            for f in &files {
                s.push_str(&format!("{}\t{}\t{}\n", f.path, f.size, f.sha256_hex));
            }
            s
        }
        HashFormat::Mactime => {
            // Sleuth Kit body format:
            //   MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
            // No reliable timestamp/inode source here, so use 0; the sha256
            // is carried in the name field comment for traceability.
            let mut s = String::new();
            for f in &files {
                s.push_str(&format!(
                    "0|{} (sha256:{})|0|0|0|0|{}|0|0|0|0\n",
                    f.path, f.sha256_hex, f.size
                ));
            }
            s
        }
        HashFormat::Dfxml => {
            let mut s = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
            s.push_str("<dfxml version=\"1.0\">\n");
            for f in &files {
                s.push_str("  <fileobject>\n");
                s.push_str(&format!("    <filename>{}</filename>\n", xml_escape(&f.path)));
                s.push_str(&format!("    <filesize>{}</filesize>\n", f.size));
                s.push_str(&format!(
                    "    <hashdigest type=\"sha256\">{}</hashdigest>\n",
                    f.sha256_hex
                ));
                s.push_str("  </fileobject>\n");
            }
            s.push_str("</dfxml>\n");
            s
        }
    };
    Ok(out)
}

/// Minimal XML text escaping for filenames.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}
