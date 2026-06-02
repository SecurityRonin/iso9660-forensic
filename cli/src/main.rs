use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use iso9660_forensic::IsoReader;
use iso9660_cli::cmd;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Write};
use std::path::PathBuf;

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
    /// Show PVD metadata and extension flags
    Info {
        /// Path to the ISO image file
        image: PathBuf,
    },

    /// List directory entries
    Ls {
        /// Path to the ISO image file
        image: PathBuf,
        /// Path within the image to list (default: root)
        path: Option<String>,
    },

    /// Walk the full directory tree
    Tree {
        /// Path to the ISO image file
        image: PathBuf,
    },

    /// Extract a file to stdout or a local path
    Extract {
        /// Path to the ISO image file
        image: PathBuf,
        /// Path to the file inside the image
        src: String,
        /// Write extracted data to this file instead of stdout
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Show El Torito boot catalog entries
    Boot {
        /// Path to the ISO image file
        image: PathBuf,
    },
}

fn open_reader(image: &PathBuf) -> Result<IsoReader<BufReader<File>>> {
    let f = File::open(image)
        .with_context(|| format!("cannot open {}", image.display()))?;
    IsoReader::open(BufReader::new(f))
        .with_context(|| format!("not a valid ISO image: {}", image.display()))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Info { image } => {
            let mut reader = open_reader(&image)?;
            print!("{}", cmd::info::run(&mut reader));
        }

        Command::Ls { image, path } => {
            let mut reader = open_reader(&image)?;
            let out = cmd::ls::run(&mut reader, path.as_deref())
                .with_context(|| "ls failed")?;
            print!("{out}");
        }

        Command::Tree { image } => {
            let mut reader = open_reader(&image)?;
            let out = cmd::tree::run(&mut reader)
                .with_context(|| "tree failed")?;
            print!("{out}");
        }

        Command::Extract { image, src, output } => {
            let mut reader = open_reader(&image)?;
            let data = cmd::extract::run(&mut reader, &src)
                .with_context(|| format!("extract '{src}' failed"))?;
            match output {
                Some(path) => {
                    let f = File::create(&path)
                        .with_context(|| format!("cannot create {}", path.display()))?;
                    BufWriter::new(f).write_all(&data)
                        .with_context(|| "write failed")?;
                }
                None => {
                    io::stdout().write_all(&data)
                        .with_context(|| "stdout write failed")?;
                }
            }
        }

        Command::Boot { image } => {
            let mut reader = open_reader(&image)?;
            let out = cmd::boot::run(&mut reader)
                .with_context(|| "boot failed")?;
            print!("{out}");
        }
    }
    Ok(())
}
