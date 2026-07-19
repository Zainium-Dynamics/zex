use clap::{Parser, Subcommand};
use std::sync::{Arc, Mutex};

use super::syscore;
use super::userland;

pub struct GlobalConfig {
    pub dry_run: bool,
    pub verbose: bool,
}

lazy_static::lazy_static! {
    pub static ref GLOBAL_CONFIG: Arc<Mutex<GlobalConfig>> = Arc::new(Mutex::new(GlobalConfig {
        dry_run: false,
        verbose: false,
    }));
}

fn set_global_config(dry_run: bool, verbose: bool) {
    let mut config = GLOBAL_CONFIG.lock().unwrap();
    config.dry_run = dry_run;
    config.verbose = verbose;
}

#[derive(Parser)]
#[command(
    name = "upgrade",
    about = "Zainium System Upgrader",
    override_usage = "elevate zex <syshub|uland> --u"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(short, long, global = true)]
    verbose: bool,

    #[arg(short, long, global = true)]
    dry_run: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Upgrade Syshub core and Zaisys engine natively
    Syshub {
        #[arg(short = 'u', long = "upgrade", alias = "u", help = "Perform upgrade")]
        u: bool,
    },
    /// Upgrade Userland packages across all tiers
    Uland {
        #[arg(short = 'u', long = "upgrade", alias = "u", help = "Perform upgrade")]
        u: bool,
    },
}

fn print_root_required() {
    const RED: &str = "\x1b[91m";
    const GREEN: &str = "\x1b[92m";
    const PURPLE: &str = "\x1b[95m";
    const RESET: &str = "\x1b[0m";

    eprintln!("\n{RED}✗ {PURPLE}Root (elevate) privileges required.{RESET}");
    eprintln!(
        "{GREEN}  This operation modifies system files and requires elevated privileges.{RESET}"
    );
    eprintln!("\n{GREEN}  Run with: {PURPLE}elevate zex syshub --u{RESET} or {PURPLE}elevate zex uland --u{RESET}\n");
}

pub async fn run(raw_args: Vec<String>) -> anyhow::Result<()> {
    if !nix::unistd::geteuid().is_root() {
        print_root_required();
        std::process::exit(1);
    }

    // Handle dummy 'upgrade' arg if passed by zex wrapper
    let mut args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "upgrade" {
        args.remove(1);
    }
    
    let cli = Cli::parse_from(args);
    set_global_config(cli.dry_run, cli.verbose);

    if cli.dry_run {
        println!(" DRY RUN MODE — No changes will be made\n");
    }

    match cli.command {
        Commands::Syshub { u } => {
            if u {
                if let Err(e) = syscore::execute().await {
                    eprintln!("✗ Syshub upgrade failed: {}", e);
                    std::process::exit(1);
                }
            } else {
                println!("Missing --u flag for syshub upgrade.");
            }
        }
        Commands::Uland { u } => {
            if u {
                if let Err(e) = userland::execute().await {
                    eprintln!("✗ Userland upgrade failed: {}", e);
                    std::process::exit(1);
                }
            } else {
                println!("Missing --u flag for uland upgrade.");
            }
        }
    }

    Ok(())
}
