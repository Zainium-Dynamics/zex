//! elevate zex inspect <package>
//!
//! Deep inspection of an installed package:
//!   • Version, status, libc target, origin tier
//!   • All installed file locations (from receipt)
//!   • Shared library dependencies (readelf -d)
//!   • Symlinks created by this package
//!   • Disk usage breakdown

use clap::Parser;

use super::inspect;

#[derive(Parser, Debug)]
#[command(
    name = "inspect",
    about = "Deep inspection of an installed package",
    version,
    override_usage = "elevate zex inspect <PACKAGE>"
)]
struct Cli {
    /// Package to inspect.
    package: String,
}

pub async fn run(raw_args: Vec<String>) {
    let cli = Cli::parse_from(&raw_args);
    if let Err(e) = inspect::run(&cli.package).await {
        eprintln!("\n \x1b[91mError:\x1b[0m {e}\n");
        std::process::exit(1);
    }
}
