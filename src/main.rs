//! main.rs — Zex multicall binary dispatcher.
//!
//! BusyBox-style: ONE binary, many commands.
//!
//! Detection order:
//!   1. argv[0] contains "zex-<cmd>" → run <cmd>
//!   2. argv[1] is a known command   → run <cmd> with argv[2..] as args
//!
//! Install layout:
//!   /overlayer/syshub/bin/zex              ← single ELF
//!   /overlayer/syshub/bin/zex-install      → zex  (symlink)
//!   /overlayer/syshub/bin/zex-upgrade      → zex
//!   /overlayer/syshub/drivers/system/*     → zex  (symlinks for driver compat)

mod aliases;
mod archive_safety;
mod cmd;
mod extract;
mod http_client;
mod immutable;
mod local_install;
mod pinning;
mod sandbox;
mod setuid;
mod steps;
mod syshub_pending;
mod triggers;
mod trust;
mod zex_codec;

use std::{env, process::exit};

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

#[cfg(unix)]
unsafe extern "C" {
    fn geteuid() -> u32;
}
#[cfg(unix)]
unsafe fn libc_geteuid() -> u32 {
    unsafe { geteuid() }
}

// ── Help ──────────────────────────────────────────────────────────────────────

fn print_help() {
    const G: &str = "\x1b[92m";
    const B: &str = "\x1b[96m";
    const Y: &str = "\x1b[93m";
    const D: &str = "\x1b[2m";
    const R: &str = "\x1b[0m";
    const BOLD: &str = "\x1b[1m";

    println!();
    println!("  {BOLD}{B}zex{R} — {BOLD}Zainium eXecutor & Package Manager{R}");
    println!();
    println!("  {BOLD}Usage:{R}  elevate zex <command> [options]");
    println!();
    println!("  {Y}Package Management:{R}");
    println!("    {G}install{R} {D}<pkg>...{R}       Install packages");
    let repos: Vec<String> = cmd::install::main::repository_names()
        .into_iter()
        .filter(|n| !n.contains('-'))
        .map(|n| format!("--{n}"))
        .collect();
    if !repos.is_empty() {
        println!(
            "    {G}install{R} {D}--<repo> <pkg>{R}  Install from one repository: {D}{}{R}",
            repos.join(" ")
        );
    }
    println!("    {G}reinstall{R} {D}<pkg>...{R}     Download and reinstall, even when unchanged");
    println!("    {G}remove{R}  {D}<pkg>...{R}       Remove packages");
    println!("    {G}update{R}              Full system update (userland + syshub)");
    println!("    {G}uland --u{R}          Upgrade userland packages");
    println!("    {G}syshub --u{R}         Upgrade immutable core");
    println!("    {G}search{R}  {D}<query>{R}       Search repositories");
    println!("    {G}refresh{R}             Refresh indexes of all 4 tiers");
    println!("    {G}rollback{R} {D}<tx_id>{R}      Revert a transaction");
    println!();
    println!("  {Y}Inspection:{R}");
    println!("    {G}doctor{R}              System health audit");
    println!("    {G}doctor --fix{R}        Auto-repair issues");
    println!("    {G}depends{R} {D}<pkg>{R}         Dependency tree");
    println!("    {G}why{R}     {D}<pkg>{R}         Reverse dependencies");
    println!("    {G}inspect{R} {D}<pkg>{R}         Deep package inspection");
    println!("    {G}sweep{R}               Clean cache and orphaned files");
    println!();
    println!("  {Y}Pinning:{R}");
    println!("    {G}pin{R}     {D}<pkg>{R}         Lock package version");
    println!("    {G}unpin{R}   {D}<pkg>{R}         Release version lock");
    println!("    {G}pins{R}                List all pinned packages");
    println!();
    println!("  {Y}Local Packages:{R}");
    println!(
        "    {G}local-install{R} {D}<file>{R}  Install local .zex/.apk/.xbps {D}(short: -i){R}"
    );
    println!("    {G}extract{R} {D}<file>{R}        Extract package contents {D}(short: -e){R}");
    println!();
    println!("  Zainium OS — {B}archive.zainiumdynamics.tech{R}");
    println!();
}

// ── Async runtime ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let all_args: Vec<String> = env::args().collect();
    if all_args.is_empty() {
        exit(1);
    }

    // Detect argv[0] for symlink dispatch (zex-install, zex-remove, …)
    let argv0 = std::path::Path::new(&all_args[0])
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("zex");

    let (command, cmd_args): (&str, Vec<String>) = if let Some(cmd) = argv0.strip_prefix("zex-") {
        // Symlink dispatch: argv[0] = "zex-install", args = argv[1..]
        (cmd, all_args[1..].to_vec())
    } else {
        // Normal dispatch: argv[1] = command, args = argv[2..]
        if all_args.len() < 2 {
            print_help();
            exit(0);
        }
        (all_args[1].as_str(), all_args[2..].to_vec())
    };

    // Build args vector the driver sees: [command, ...user_args]
    // This lets Clap see argv[0] = command name for error messages
    let mut driver_args = vec![command.to_string()];
    driver_args.extend(cmd_args.clone());

    // ── Dispatch ─────────────────────────────────────────────────────────────
    let result: anyhow::Result<()> = match command {
        // ── Built-ins (no driver binary needed) ──────────────────────────────
        "-h" | "--help" | "help" => {
            print_help();
            exit(0);
        }

        "-V" | "--version" | "version" => {
            println!("zex {}", env!("CARGO_PKG_VERSION"));
            exit(0);
        }

        "-e" | "--extract" | "extract" => {
            if cmd_args.is_empty() {
                eprintln!("Usage: zex extract <file> [--output <dir>]");
                exit(1);
            }
            extract::run(&cmd_args).map_err(|e| anyhow::anyhow!(e))
        }

        "-i" | "--local-install" | "local-install" => {
            if cmd_args.is_empty() {
                eprintln!(
                    "Usage: elevate zex local-install <file> [--dry-run] [--root <path>] [--force]"
                );
                exit(1);
            }
            #[cfg(unix)]
            {
                let dry = cmd_args.iter().any(|a| a == "--dry-run");
                let custom = cmd_args.iter().any(|a| a == "--root");
                if !dry && !custom && unsafe { libc_geteuid() } != 0 {
                    eprintln!("  ✗ Root required. Run: elevate zex local-install <file>");
                    exit(1);
                }
            }
            local_install::run(&cmd_args).map_err(|e| anyhow::anyhow!(e))
        }

        // ── Pin / Unpin (built-in) ────────────────────────────────────────────
        "pin" => {
            if cmd_args.is_empty() {
                eprintln!("Usage: elevate zex pin <package> [--reason <text>]");
                exit(1);
            }
            let mut pkgs: Vec<&str> = Vec::new();
            let mut reason: Option<&str> = None;
            let mut i = 0;
            while i < cmd_args.len() {
                if cmd_args[i] == "--reason" {
                    i += 1;
                    if i < cmd_args.len() {
                        reason = Some(&cmd_args[i]);
                    }
                } else {
                    pkgs.push(&cmd_args[i]);
                }
                i += 1;
            }
            let mut err = None;
            for p in &pkgs {
                if let Err(e) = pinning::pin(p, reason) {
                    err = Some(e);
                    break;
                }
            }
            err.map(Err).unwrap_or(Ok(()))
        }

        "unpin" => {
            if cmd_args.is_empty() {
                eprintln!("Usage: elevate zex unpin <package>");
                exit(1);
            }
            let mut err = None;
            for p in &cmd_args {
                if let Err(e) = pinning::unpin(p) {
                    err = Some(e);
                    break;
                }
            }
            err.map(Err).unwrap_or(Ok(()))
        }

        "pins" | "list-pins" => {
            pinning::print_pins(&pinning::load_pinned());
            Ok(())
        }

        // ── Driver commands (now compiled into this binary) ───────────────────
        "install" => {
            cmd::install::run(driver_args).await;
            Ok(())
        }
        "reinstall" => {
            if cmd_args.is_empty() {
                eprintln!("Usage: elevate zex reinstall <package>...");
                exit(1);
            }
            let mut args = vec!["install".to_string(), "--reinstall".to_string()];
            args.extend(cmd_args.clone());
            cmd::install::run(args).await;
            Ok(())
        }
        "remove" => {
            cmd::remove::run(driver_args).await;
            Ok(())
        }
        "search" => {
            cmd::search::run(driver_args).await;
            Ok(())
        }
        "refresh" => cmd::refresh::run(driver_args).await,
        "doctor" => {
            cmd::doctor::run(driver_args);
            Ok(())
        }
        "rollback" => {
            cmd::rollback::run(driver_args);
            Ok(())
        }
        "sweep" => cmd::sweep::run(driver_args).await,
        "inspect" => {
            cmd::inspect::run(driver_args).await;
            Ok(())
        }
        "depends" => {
            cmd::depends::run(driver_args);
            Ok(())
        }
        "why" => {
            cmd::why::run(driver_args);
            Ok(())
        }
        "history" => cmd::history::run(driver_args),
        "update" => cmd::update::run(driver_args).await,

        // ── Upgrade: exactly two commands (syshub | uland) — no bare `upgrade` ─
        "syshub" | "uland" => {
            let mut up_args = vec!["upgrade".to_string()];
            match command {
                "syshub" => {
                    up_args.push("syshub".into());
                    up_args.push("--u".into());
                }
                "uland" => {
                    up_args.push("uland".into());
                    up_args.push("--u".into());
                }
                _ => unreachable!(),
            }
            cmd::upgrade::run(up_args).await
        }

        // ── Unknown ───────────────────────────────────────────────────────────
        other => {
            eprintln!(
                "\n \x1b[91mError:\x1b[0m Unknown command '{other}'.\n\
                 Type 'zex' for help.\n"
            );
            exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("\n \x1b[91mError:\x1b[0m {e}\n");
        exit(1);
    }
}
