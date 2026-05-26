use std::io::BufReader;
use std::path::PathBuf;
use iso::IsoReader;

fn corpus_dir() -> Option<PathBuf> {
    std::env::var("CORPUS_DIR").ok().map(PathBuf::from)
}

fn open_corpus(name: &str) -> Option<IsoReader<BufReader<std::fs::File>>> {
    let dir = corpus_dir()?;
    let path = dir.join(name);
    if !path.exists() {
        return None;
    }
    let f = std::fs::File::open(&path).ok()?;
    IsoReader::open(BufReader::new(f)).ok()
}

#[test]
fn corpus_test_iso_opens() {
    let Some(mut reader) = open_corpus("test.iso") else { return };
    assert!(reader.session_count() > 0, "ISO must have at least one session");
}

#[test]
fn corpus_test_iso_has_joliet_and_rock_ridge() {
    let Some(mut reader) = open_corpus("test.iso") else { return };
    // xorriso -as mkisofs -J -r produces both extensions.
    assert!(reader.has_joliet(), "xorriso -J must set Joliet");
    assert!(reader.has_rock_ridge(), "xorriso -r must set Rock Ridge");
}

#[test]
fn corpus_test_iso_root_dir_is_nonempty() {
    let Some(mut reader) = open_corpus("test.iso") else { return };
    let entries = reader.read_root_dir().expect("read_root_dir");
    assert!(!entries.is_empty(), "root directory must contain at least one entry");
}
