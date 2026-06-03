use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use iso9660_forensic::IsoReader;
use iso9660_cli::cmd;
use iso9660_cli::cmd::hashlist::HashFormat;
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
    about = "Forensic inspection of ISO 9660 / Rock Ridge / UDF disc images",
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
    Info {
        image: PathBuf,
    },

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

    /// Search the tree by metadata (--name/--type/--size) or content (--content)
    Search {
        image: PathBuf,
        /// Glob pattern matched against the basename (e.g. "*.txt").
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
        /// Search file *contents* for this literal pattern (grep mode)
        #[arg(long)]
        content: Option<String>,
        /// Case-insensitive content search
        #[arg(short = 'i', long)]
        ignore_case: bool,
    },

    /// Dump a logical sector — annotated hex by default, raw bytes with --raw
    #[command(visible_alias = "hexdump")]
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
    Map {
        image: PathBuf,
    },

    /// Forensic analysis: integrity audit, timeline, and hashing
    Forensic {
        #[command(subcommand)]
        cmd: ForensicCmd,
    },
}

#[derive(Subcommand)]
enum ForensicCmd {
    /// Run the full audit suite (both-endian, pre-system, slack, gaps, ...)
    Audit {
        image: PathBuf,
    },

    /// Show a chronological timeline of files (Rock Ridge timestamps)
    Timeline {
        image: PathBuf,
    },

    /// Compute SHA-256 for every file (hashdeep/csv/tsv/mactime/dfxml)
    Hash {
        image: PathBuf,
        /// Output format
        #[arg(long, value_enum, default_value_t = HashFmt::Hashdeep)]
        format: HashFmt,
    },
}

fn open_reader(image: &PathBuf) -> Result<IsoReader<BufReader<File>>> {
    let f = File::open(image)
        .with_context(|| format!("cannot open {}", image.display()))?;
    IsoReader::open(BufReader::new(f))
        .with_context(|| format!("not a valid ISO image: {}", image.display()))
}

fn write_files(
    files: Vec<(String, Vec<u8>)>,
    output_dir: &std::path::Path,
) -> Result<()> {
    for (path, data) in files {
        let dest = output_dir.join(&path);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
        let mut f = File::create(&dest)
            .with_context(|| format!("cannot create {}", dest.display()))?;
        BufWriter::new(&mut f).write_all(&data)
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

fn run_search(
    image: &PathBuf,
    name: Option<String>,
    file_type: Option<char>,
    min_size: Option<u32>,
    max_size: Option<u32>,
    content: Option<String>,
    ignore_case: bool,
) -> Result<()> {
    let mut reader = open_reader(image)?;
    let out = match content {
        // Content mode == grep; --name doubles as the include glob.
        Some(pattern) => cmd::grep::run(&mut reader, &pattern, name.as_deref(), ignore_case)
            .context("search failed")?,
        // Metadata mode == find.
        None => cmd::find::run(&mut reader, name.as_deref(), file_type, min_size, max_size)
            .context("search failed")?,
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
            run_search(&image, name, file_type, min_size, max_size, content, ignore_case)?;
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
                let out = cmd::hashlist::run(&mut reader, format.into())
                    .context("hash failed")?;
                print!("{out}");
            }
        },
    }
    Ok(())
}
