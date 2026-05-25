use thiserror::Error;

#[derive(Debug, Error)]
pub enum IsoError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("not an ISO image: missing CD001 signature at sector 16")]
    NotAnIso,
    #[error("unsupported sector size: expected 2048 or 2352, detected {0}")]
    UnsupportedSectorSize(u64),
    #[error("volume descriptor parse error: {0}")]
    BadDescriptor(String),
    #[error("directory record parse error: {0}")]
    BadDirRecord(String),
    #[error("file not found: {0}")]
    NotFound(String),
    #[error("path traversal outside root")]
    PathTraversal,
}
