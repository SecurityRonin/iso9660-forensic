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
    version
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

    /// Extract files preserving their full archive paths  (dar/7z `x` convention)
    #[command(name = "x")]
    Extract {
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

    /// Hex dump a logical sector — ASCII-only fixed-width columns
    Hexdump {
        image: PathBuf,
        /// Logical block address (sector number) to dump
        #[arg(long, default_value_t = 16)]
        lba: u64,
    },

    /// Run the full forensic audit suite (both-endian, pre-system, slack, gaps, ...)
    Audit {
        image: PathBuf,
    },

    /// Render a sector-by-sector map of the image
    Map {
        image: PathBuf,
    },

    /// Show a chronological timeline of files (Rock Ridge timestamps)
    Timeline {
        image: PathBuf,
    },

    /// Compute SHA-256 for every file in the image
    Hashlist {
        image: PathBuf,
        /// Output format
        #[arg(long, value_enum, default_value_t = HashFmt::Hashdeep)]
        format: HashFmt,
    },

    /// Extract files flat — strip all directory path components  (dar/7z `e` convention)
    #[command(name = "e")]
    ExtractFlat {
        image: PathBuf,
        /// File or directory to extract (default: everything)
        src: Option<String>,
        /// Write extracted files into this directory (default: current dir)
        #[arg(short = 'C', long = "output-dir")]
        output_dir: Option<PathBuf>,
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Info { image } => {
            let mut reader = open_reader(&image)?;
            print!("{}", cmd::info::run(&mut reader));
        }

        Command::Ls { image, path, tree } => {
            let mut reader = open_reader(&image)?;
            let out = cmd::ls::run(&mut reader, path.as_deref(), tree)
                .context("ls failed")?;
            print!("{out}");
        }

        Command::Extract { image, src, output_dir, stdout } => {
            let mut reader = open_reader(&image)?;
            let files = cmd::extract::run_x(&mut reader, src.as_deref())
                .context("extract failed")?;

            if stdout {
                // Only valid for a single file.
                if files.len() != 1 {
                    anyhow::bail!(
                        "--stdout requires exactly one file; got {}",
                        files.len()
                    );
                }
                io::stdout().write_all(&files[0].1).context("stdout write failed")?;
            } else {
                let dir = output_dir.unwrap_or_else(|| PathBuf::from("."));
                write_files(files, &dir)?;
            }
        }

        Command::Hexdump { image, lba } => {
            let mut reader = open_reader(&image)?;
            let out = cmd::hexdump::run(&mut reader, lba)
                .context("hexdump failed")?;
            print!("{out}");
        }

        Command::Audit { image } => {
            let mut reader = open_reader(&image)?;
            let name = image.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("image.iso");
            print!("{}", cmd::audit::run(&mut reader, name));
        }

        Command::Map { image } => {
            let mut reader = open_reader(&image)?;
            let out = cmd::map::run(&mut reader).context("map failed")?;
            print!("{out}");
        }

        Command::Timeline { image } => {
            let mut reader = open_reader(&image)?;
            let out = cmd::timeline::run(&mut reader).context("timeline failed")?;
            print!("{out}");
        }

        Command::Hashlist { image, format } => {
            let mut reader = open_reader(&image)?;
            let out = cmd::hashlist::run(&mut reader, format.into())
                .context("hashlist failed")?;
            print!("{out}");
        }

        Command::ExtractFlat { image, src, output_dir } => {
            let mut reader = open_reader(&image)?;
            let files = cmd::extract::run_e(&mut reader, src.as_deref())
                .context("extract-flat failed")?;
            let dir = output_dir.unwrap_or_else(|| PathBuf::from("."));
            write_files(files, &dir)?;
        }
    }
    Ok(())
}
