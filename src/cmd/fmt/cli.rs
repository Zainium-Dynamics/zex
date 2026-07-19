use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "zex fmt", about = "Zainium Secure Package Format Tool")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Create a secure .zex package from a directory
    Pack {
        directory: PathBuf,

        #[arg(short = 'v', long = "version")]
        version: String,

        #[arg(long, default_value = "")]
        description: String,

        #[arg(long, value_delimiter = ',', default_value = "")]
        features: Vec<String>,

        #[arg(long, default_value_t = false)]
        report: bool,

        /// Also emit a `.zex.locked` maintainer-review artifact
        /// (full source + 5 empty approval slots).
        #[arg(long, default_value_t = false)]
        locked: bool,

        /// Union-layer root used to render absolute paths in the
        /// install receipt .toml (rarely needs changing).
        #[arg(long, default_value = "/overlayer/zexlib")]
        install_root: String,

        #[arg(short = 'o', long = "output")]
        output: Option<PathBuf>,
    },

    /// Extract a .zex package
    Unpack {
        file: PathBuf,

        #[arg(short = 'o', long = "output")]
        output: Option<PathBuf>,

        #[arg(long, default_value_t = false)]
        verify_only: bool,
    },

    /// Verify signature and integrity of a .zex package
    Verify { file: PathBuf },

    /// Show detailed package information
    Inspect { file: PathBuf },

    /// Fill a maintainer review slot in a .zex.locked artifact
    Review {
        /// Path to the .zex.locked file
        locked_file: PathBuf,

        /// Slot number (1–5)
        #[arg(long, value_parser = clap::value_parser!(u8).range(1..=5))]
        slot: u8,

        /// Reviewer identifier (e.g. "alice@zainium.org")
        #[arg(long)]
        reviewer: String,

        /// Review decision
        #[arg(long, value_enum)]
        status: ReviewStatusArg,

        /// Optional notes
        #[arg(long, default_value = "")]
        notes: String,
    },

    /// Generate a real Ed25519 signing keypair for Tier 1 (.zex) packages
    Keygen {
        /// Directory to write signing.key + trust.pub into (default: cwd)
        #[arg(short = 'o', long = "output-dir")]
        output_dir: Option<PathBuf>,

        /// Overwrite existing key files if present
        #[arg(long, default_value_t = false)]
        force: bool,
    },
}

#[derive(clap::ValueEnum, Clone, Copy)]
pub enum ReviewStatusArg {
    Approved,
    ChangesRequested,
    Rejected,
}
