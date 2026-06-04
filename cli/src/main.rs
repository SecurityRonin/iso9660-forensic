use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use iso9660_cli::cmd;
use iso9660_cli::cmd::hashlist::HashFormat;
use iso9660_forensic::IsoReader;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Write};
use std::path::PathBuf;

/// clap-facing mirror of [`HashFormat`] so the enum can derive `ValueEnum`
/// without coupling the library command module to clap.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum HashFmt {
    Hashdeep,
    Csv,
    Tsv,
    Mactime,
    Dfxml,
}

impl From<HashFmt> for HashFormat {
    fn from(f: HashFmt) -> Self {
        match f {
            HashFmt::Hashdeep => HashFormat::Hashdeep,
            HashFmt::Csv => HashFormat::Csv,
            HashFmt::Tsv => HashFormat::Tsv,
            HashFmt::Mactime => HashFormat::Mactime,
            HashFmt::Dfxml => HashFormat::Dfxml,
        }
    }
}

#[derive(Parser)]
#[command(
    name = "iso9660",
    about = "Forensic inspection of ISO 9660 / Rock Ridge / Joliet disc images",
    version,
    // -h/--help and -V/--version cover everything; drop the redundant
    // auto-generated `help` subcommand from the command list.
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show PVD metadata, extension flags, and El Torito boot catalog
    Info { image: PathBuf },

    /// List directory entries  [-R recurses the full tree]
    Ls {
        image: PathBuf,
        /// Directory path within the image (default: root)
        path: Option<String>,
        /// Recurse into subdirectories (like ls -R)
        #[arg(short = 'R', long = "tree")]
        tree: bool,
    },

    /// Extract files from the image  (alias: `x`; --flat = `e`)
    #[command(visible_alias = "x")]
    Extract {
        image: PathBuf,
        /// File or directory to extract (default: everything)
        src: Option<String>,
        /// Strip directory components, writing all files into one flat level
        #[arg(long)]
        flat: bool,
        /// Write extracted files under this directory (default: current dir)
        #[arg(short = 'C', long = "output-dir")]
        output_dir: Option<PathBuf>,
        /// Write a single extracted file to stdout instead of disk
        #[arg(long)]
        stdout: bool,
    },

    /// Extract files flat — shorthand for `extract --flat`  (dar/7z `e` convention)
    #[command(name = "e")]
    ExtractFlat {
        image: PathBuf,
        /// File or directory to extract (default: everything)
        src: Option<String>,
        /// Write extracted files under this directory (default: current dir)
        #[arg(short = 'C', long = "output-dir")]
        output_dir: Option<PathBuf>,
        /// Write a single extracted file to stdout instead of disk
        #[arg(long)]
        stdout: bool,
    },

    /// Search the tree by name/type/size (metadata) or by --content (grep).
    ///
    /// `--name` and `--content` are regular expressions (a plain string is a
    /// valid regex that matches itself).  Both are case-sensitive unless `-i`
    /// is given or the pattern carries an inline `(?i)` flag.  Note: shell
    /// globs like `*.txt` are not regexes — use `.*\.txt` instead.
    Search {
        image: PathBuf,
        /// Regex matched against the basename (e.g. '\.txt$', 'report-\d+').
        /// In content mode this restricts which files are searched.
        #[arg(long)]
        name: Option<String>,
        /// Entry type: f = files, d = directories  (metadata mode only)
        #[arg(long = "type")]
        file_type: Option<char>,
        /// Minimum file size in bytes, inclusive  (metadata mode only)
        #[arg(long)]
        min_size: Option<u32>,
        /// Maximum file size in bytes, inclusive  (metadata mode only)
        #[arg(long)]
        max_size: Option<u32>,
        /// Search file *contents* with this regex (grep mode)
        #[arg(long)]
        content: Option<String>,
        /// Case-insensitive matching for --name and --content
        #[arg(short = 'i', long)]
        ignore_case: bool,
    },

    /// Dump a logical sector — annotated hex by default, raw bytes with --raw
    Dump {
        image: PathBuf,
        /// Logical block address (sector number) to dump
        #[arg(long, default_value_t = 16)]
        lba: u64,
        /// Emit the raw 2048-byte sector to stdout instead of annotated hex
        #[arg(long)]
        raw: bool,
    },

    /// Render a sector-by-sector map of the image
    Map { image: PathBuf },

    /// List the disc's tracks from a container descriptor (.cue/.ccd/.nrg/.mds)
    Tracks { image: PathBuf },

    /// Forensic analysis: integrity audit, timeline, and hashing
    Forensic {
        #[command(subcommand)]
        cmd: ForensicCmd,
    },
}

#[derive(Subcommand)]
enum ForensicCmd {
    /// Run the full audit suite (both-endian, pre-system, slack, gaps, ...)
    Audit { image: PathBuf },

    /// Show a chronological timeline of files (Rock Ridge timestamps)
    Timeline { image: PathBuf },

    /// Compute SHA-256 for every file (hashdeep/csv/tsv/mactime/dfxml)
    Hash {
        image: PathBuf,
        /// Output format
        #[arg(long, value_enum, default_value_t = HashFmt::Hashdeep)]
        format: HashFmt,
    },

    /// Compute whole-disc identity fingerprints (freedb + MusicBrainz) from a
    /// CUE sheet — for matching an audio / mixed-mode CD to a known release
    Discid {
        /// Path to a .cue sheet describing the disc's tracks
        cue: PathBuf,
    },

    /// Report Q-subchannel identifiers (Media Catalog Number + per-track ISRC)
    /// from a 2448-byte subchannel-bearing image
    Subchannel { image: PathBuf },

    /// Recover lost files from orphaned directory extents (path-table dirs the
    /// active tree can't reach)
    Recover { image: PathBuf },
}

/// Any seekable byte source the reader can open, erased to one type so the
/// different container paths (plain file, offset-windowed NRG track) unify.
trait ReadSeek: io::Read + io::Seek {}
impl<T: io::Read + io::Seek> ReadSeek for T {}

fn open_reader(image: &PathBuf) -> Result<IsoReader<Box<dyn ReadSeek>>> {
    // Sidecar descriptors resolve to the data file holding the sectors:
    // a `.cue` to its data track's `.bin`, a CloneCD `.ccd` to its `.img`.
    // A Nero `.nrg` embeds the track inside a single file, so it is windowed
    // to the data track's byte range instead of being opened whole.
    let ext = image.extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase);
    if ext.as_deref() == Some("nrg") {
        return open_nrg(image);
    }
    if ext.as_deref() == Some("mds") {
        return open_mds(image);
    }
    let target = match ext.as_deref() {
        Some("cue") => resolve_cue_bin(image)?,
        Some("ccd") => resolve_ccd_img(image)?,
        _ => image.clone(),
    };
    let f = File::open(&target).with_context(|| format!("cannot open {}", target.display()))?;
    let source: Box<dyn ReadSeek> = Box::new(BufReader::new(f));
    IsoReader::open(source).with_context(|| format!("not a valid ISO image: {}", target.display()))
}

/// Open a Nero `.nrg` image by parsing its TOC, locating the first data track,
/// and windowing the file to that track's byte range.
fn open_nrg(path: &std::path::Path) -> Result<IsoReader<Box<dyn ReadSeek>>> {
    use iso9660_forensic::nrg;
    use iso9660_forensic::offset::OffsetReader;

    let mut f = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let image =
        nrg::parse(&mut f).with_context(|| format!("not an NRG image: {}", path.display()))?;
    let track = image
        .data_track()
        .ok_or_else(|| anyhow::anyhow!("no data track in NRG image {}", path.display()))?;
    let window = OffsetReader::new(BufReader::new(f), track.start_offset, track.size)
        .with_context(|| format!("cannot window NRG data track in {}", path.display()))?;
    let source: Box<dyn ReadSeek> = Box::new(window);
    IsoReader::open(source).with_context(|| format!("not a valid ISO image: {}", path.display()))
}

/// Open an Alcohol 120% `.mds` image by parsing the descriptor, locating the
/// first data track, and windowing the sibling `.mdf` to that track's range.
fn open_mds(path: &std::path::Path) -> Result<IsoReader<Box<dyn ReadSeek>>> {
    use iso9660_forensic::mds;
    use iso9660_forensic::offset::OffsetReader;

    let mut desc = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let image = mds::parse(&mut desc)
        .with_context(|| format!("not an MDS descriptor: {}", path.display()))?;
    let track = image
        .data_track()
        .ok_or_else(|| anyhow::anyhow!("no data track in MDS image {}", path.display()))?;
    let mdf_path = path.with_extension("mdf");
    let mdf = File::open(&mdf_path)
        .with_context(|| format!("cannot open MDF data file {}", mdf_path.display()))?;
    let window = OffsetReader::new(BufReader::new(mdf), track.start_offset, track.data_size())
        .with_context(|| format!("cannot window MDF data track in {}", mdf_path.display()))?;
    let source: Box<dyn ReadSeek> = Box::new(window);
    IsoReader::open(source)
        .with_context(|| format!("not a valid ISO image: {}", mdf_path.display()))
}

/// Resolve a CloneCD `.ccd` control file to its `.img` data file (same
/// basename), mirroring how a `.cue` resolves to its `.bin`.
fn resolve_ccd_img(ccd_path: &std::path::Path) -> Result<PathBuf> {
    let img = ccd_path.with_extension("img");
    if img.is_file() {
        Ok(img)
    } else {
        anyhow::bail!("no .img alongside CloneCD control file {}", ccd_path.display())
    }
}

/// Resolve a CUE sheet to the `.bin` file holding its first data track.
fn resolve_cue_bin(cue_path: &PathBuf) -> Result<PathBuf> {
    let text = std::fs::read_to_string(cue_path)
        .with_context(|| format!("cannot read CUE sheet {}", cue_path.display()))?;
    let sheet = iso9660_forensic::cue::parse(&text);
    let (file_name, _track) = sheet
        .data_track()
        .ok_or_else(|| anyhow::anyhow!("no data track in CUE sheet {}", cue_path.display()))?;
    // Resolve the FILE name relative to the CUE sheet's directory.
    let dir = cue_path.parent().unwrap_or_else(|| std::path::Path::new("."));
    Ok(dir.join(file_name))
}

fn write_files(files: Vec<(String, Vec<u8>)>, output_dir: &std::path::Path) -> Result<()> {
    for (path, data) in files {
        let dest = output_dir.join(&path);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
        let mut f =
            File::create(&dest).with_context(|| format!("cannot create {}", dest.display()))?;
        BufWriter::new(&mut f)
            .write_all(&data)
            .with_context(|| format!("write failed: {}", dest.display()))?;
    }
    Ok(())
}

fn run_extract(
    image: &PathBuf,
    src: Option<String>,
    flat: bool,
    output_dir: Option<PathBuf>,
    stdout: bool,
) -> Result<()> {
    let mut reader = open_reader(image)?;
    let files = if flat {
        cmd::extract::run_e(&mut reader, src.as_deref()).context("extract failed")?
    } else {
        cmd::extract::run_x(&mut reader, src.as_deref()).context("extract failed")?
    };

    if stdout {
        // Writing to stdout only makes sense for a single file.
        if files.len() != 1 {
            anyhow::bail!("--stdout requires exactly one file; got {}", files.len());
        }
        io::stdout().write_all(&files[0].1).context("stdout write failed")?;
    } else {
        let dir = output_dir.unwrap_or_else(|| PathBuf::from("."));
        write_files(files, &dir)?;
    }
    Ok(())
}

struct SearchArgs {
    name: Option<String>,
    file_type: Option<char>,
    min_size: Option<u32>,
    max_size: Option<u32>,
    content: Option<String>,
    ignore_case: bool,
}

/// Compile a regex pattern, optionally forcing case-insensitivity.
fn compile_regex(pattern: &str, ignore_case: bool) -> Result<regex::Regex> {
    regex::RegexBuilder::new(pattern)
        .case_insensitive(ignore_case)
        .build()
        .with_context(|| format!("invalid regex: {pattern}"))
}

fn run_search(image: &PathBuf, a: SearchArgs) -> Result<()> {
    let mut reader = open_reader(image)?;

    let name_re = match &a.name {
        Some(p) => Some(compile_regex(p, a.ignore_case)?),
        None => None,
    };

    let out = if let Some(pattern) = &a.content {
        // Content mode (grep); --name regex restricts which files are searched.
        let content_re = compile_regex(pattern, a.ignore_case)?;
        cmd::grep::run(&mut reader, &content_re, name_re.as_ref()).context("search failed")?
    } else {
        // Metadata mode (find).
        cmd::find::run(&mut reader, name_re.as_ref(), a.file_type, a.min_size, a.max_size)
            .context("search failed")?
    };
    print!("{out}");
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Info { image } => {
            let mut reader = open_reader(&image)?;
            print!("{}", cmd::info::run(&mut reader));
        }

        Command::Ls { image, path, tree } => {
            let mut reader = open_reader(&image)?;
            let out = cmd::ls::run(&mut reader, path.as_deref(), tree).context("ls failed")?;
            print!("{out}");
        }

        Command::Extract { image, src, flat, output_dir, stdout } => {
            run_extract(&image, src, flat, output_dir, stdout)?;
        }

        Command::ExtractFlat { image, src, output_dir, stdout } => {
            run_extract(&image, src, true, output_dir, stdout)?;
        }

        Command::Search { image, name, file_type, min_size, max_size, content, ignore_case } => {
            run_search(
                &image,
                SearchArgs { name, file_type, min_size, max_size, content, ignore_case },
            )?;
        }

        Command::Dump { image, lba, raw } => {
            let mut reader = open_reader(&image)?;
            if raw {
                let bytes = cmd::dump::run_raw(&mut reader, lba).context("dump failed")?;
                io::stdout().write_all(&bytes).context("stdout write failed")?;
            } else {
                let out = cmd::dump::run(&mut reader, lba).context("dump failed")?;
                print!("{out}");
            }
        }

        Command::Map { image } => {
            let mut reader = open_reader(&image)?;
            let out = cmd::map::run(&mut reader).context("map failed")?;
            print!("{out}");
        }

        Command::Tracks { image } => {
            let out = cmd::tracks::run(&image).context("tracks failed")?;
            print!("{out}");
        }

        Command::Forensic { cmd } => match cmd {
            ForensicCmd::Audit { image } => {
                let mut reader = open_reader(&image)?;
                let name = image.file_name().and_then(|n| n.to_str()).unwrap_or("image.iso");
                print!("{}", cmd::audit::run(&mut reader, name));
            }
            ForensicCmd::Timeline { image } => {
                let mut reader = open_reader(&image)?;
                let out = cmd::timeline::run(&mut reader).context("timeline failed")?;
                print!("{out}");
            }
            ForensicCmd::Hash { image, format } => {
                let mut reader = open_reader(&image)?;
                let out = cmd::hashlist::run(&mut reader, format.into()).context("hash failed")?;
                print!("{out}");
            }
            ForensicCmd::Discid { cue } => {
                let text = std::fs::read_to_string(&cue)
                    .with_context(|| format!("cannot read CUE sheet {}", cue.display()))?;
                let sheet = iso9660_forensic::cue::parse(&text);
                // Total disc length = the (first) .bin size in 2352-byte CD frames.
                let file =
                    sheet.files.first().ok_or_else(|| anyhow::anyhow!("no FILE in CUE sheet"))?;
                let dir = cue.parent().unwrap_or_else(|| std::path::Path::new("."));
                let bin = dir.join(&file.name);
                let bytes = std::fs::metadata(&bin)
                    .with_context(|| format!("cannot stat {}", bin.display()))?
                    .len();
                let total_frames = (bytes / 2352) as u32;
                let out = cmd::discid::run(&sheet, total_frames).context("discid failed")?;
                print!("{out}");
            }
            ForensicCmd::Recover { image } => {
                let mut reader = open_reader(&image)?;
                let out = cmd::recover::run(&mut reader).context("recover failed")?;
                print!("{out}");
            }
            ForensicCmd::Subchannel { image } => {
                // CloneCD stores subchannel in a sibling .sub file; prefer it
                // over an in-stream 2448 scan when present (a .ccd/.img need
                // not be an openable ISO for this).
                let sub_path = image.with_extension("sub");
                if sub_path.is_file() {
                    let bytes = std::fs::read(&sub_path)
                        .with_context(|| format!("cannot read {}", sub_path.display()))?;
                    print!("{}", cmd::subchannel::run_sub(&bytes));
                } else {
                    let mut reader = open_reader(&image)?;
                    let out = cmd::subchannel::run(&mut reader).context("subchannel failed")?;
                    print!("{out}");
                }
            }
        },
    }
    Ok(())
}
