use super::audit;
use super::backend::{self, PackageBackend};
use super::common::{PackageMeta, RunOpts, confirm_removal};
use crate::cmd::install::theme::{self, Tone};
use futures::stream::{self, StreamExt};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::sync::Arc;

const STEP_WIDTH: usize = 52;

enum RemovalOutcome {
    Removed(PackageMeta, PackageBackend),
    NotFound(String),
    DryRun(PackageMeta, PackageBackend),
}

pub async fn remove(names: &[String], opts: &RunOpts) {
    let count = names.len();

    let mut valid_names = Vec::new();
    let mut blocked_names = Vec::new();
    for name in names {
        if crate::cmd::install::backend::is_in_syshub(name) {
            blocked_names.push(name.clone());
        } else {
            valid_names.push(name.clone());
        }
    }

    if !blocked_names.is_empty() {
        let blocked = blocked_names.join(", ");
        println!(
            "\n{}",
            theme::line(&[
                (Tone::Red, "✗ "),
                (
                    Tone::Purple,
                    &format!(
                        "Cannot remove [{}], they are locked inside the immutable Syshub.",
                        blocked
                    )
                )
            ])
        );
        if valid_names.is_empty() {
            return;
        }
    }

    let targets = valid_names.join(", ");
    println!(
        "\n{}",
        theme::line(&[(Tone::Green, "→ Targets: "), (Tone::Purple, &targets)])
    );

    if !confirm_removal(&valid_names, opts) {
        println!(
            "\n{}",
            theme::line(&[(Tone::Red, "✗ "), (Tone::Purple, "Aborted.")])
        );
        println!();
        return;
    }
    println!();

    if opts.dry_run {
        print_dry_run_table(&valid_names, opts).await;
        return;
    }

    println!(
        "{}",
        theme::line(&[(Tone::Green, "Starting "), (Tone::Purple, "removal...")])
    );

    let mp = Arc::new(MultiProgress::new());
    let bar = mp.add(ProgressBar::new(count as u64));
    bar.set_style(
        ProgressStyle::with_template("  [{bar:50}] {pos}/{len} packages  {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("██░"),
    );
    bar.set_message("removing...");

    let bar_clone = bar.clone();
    let opts_arc = Arc::new(opts.clone());

    let outcomes: Vec<RemovalOutcome> = stream::iter(valid_names.to_owned())
        .map(|name| {
            let opts_ref = Arc::clone(&opts_arc);
            let bar_ref = bar_clone.clone();
            async move {
                let outcome = remove_one_pkg(&name, &opts_ref).await;
                bar_ref.inc(1);
                outcome
            }
        })
        .buffer_unordered(5)
        .collect()
        .await;

    bar.finish_with_message("done");
    println!();

    let mut removed: Vec<(PackageMeta, PackageBackend)> = Vec::new();
    let mut not_found: Vec<String> = Vec::new();

    for outcome in outcomes {
        match outcome {
            RemovalOutcome::Removed(meta, be) => {
                print_pkg_steps(&meta.display_name);
                removed.push((meta, be));
            }
            RemovalOutcome::NotFound(name) => {
                println!(
                    "  {}",
                    theme::line(&[
                        (Tone::Red, "⚠ "),
                        (
                            Tone::Purple,
                            &format!("'{}' is not installed — skipping.", name)
                        )
                    ])
                );
                not_found.push(name);
            }
            RemovalOutcome::DryRun(meta, be) => {
                removed.push((meta, be));
            }
        }
    }

    for (meta, be) in &removed {
        audit::log_removal(
            &meta.display_name.to_lowercase(),
            &meta.version,
            be.label(),
            meta.size_mb,
            false,
        )
        .await;

        super::stats::Stats::record_removal(meta.size_mb).await;
    }

    if removed.is_empty() {
        println!(
            "\n{}",
            theme::line(&[
                (Tone::Red, "✗ "),
                (Tone::Purple, "No packages were removed.")
            ])
        );
        println!();
        return;
    }

    let pkg_list: String = removed
        .iter()
        .map(|(m, _)| m.display_name.as_str())
        .collect::<Vec<_>>()
        .join(", ");

    let summary = format!("completed successfully ✓ ({} packages)", removed.len());

    println!(
        "\n{}",
        theme::line(&[(Tone::Green, "Removal "), (Tone::Purple, &summary)])
    );
    println!(
        "\n{}",
        theme::line(&[(Tone::Green, "Removal "), (Tone::Purple, "Summary:")])
    );
    println!(
        "{}",
        theme::kv_line(20, "Packages removed", Tone::Purple, &pkg_list)
    );
    let total_mb: f64 = removed.iter().map(|(m, _)| m.size_mb).sum();
    println!(
        "{}\n",
        theme::kv_line(
            20,
            "Total space freed",
            Tone::Blue,
            &format!("~{:.1} MB", total_mb)
        )
    );
}

async fn remove_one_pkg(name: &str, opts: &RunOpts) -> RemovalOutcome {
    let Some(pkg_backend) = backend::find_backend(name).await else {
        return RemovalOutcome::NotFound(name.to_string());
    };

    let meta = super::common::query_package(name).await.unwrap_or_else(|| {
        let display = capitalise(name);
        PackageMeta {
            name: name.to_string(),
            display_name: display,
            version: "unknown".to_string(),
            size_mb: 0.0,
            origin: "unknown".into(),
        }
    });

    if opts.dry_run {
        return RemovalOutcome::DryRun(meta, pkg_backend);
    }

    pkg_backend.execute_removal(name, opts.recursive).await;

    RemovalOutcome::Removed(meta, pkg_backend)
}

fn print_pkg_steps(display_name: &str) {
    let steps = "Scanning • Cleaning • Registry";
    let used = 2 + display_name.len() + 5 + steps.len() + 1;
    let dots = STEP_WIDTH.saturating_sub(used).max(3);
    println!(
        "  {}   {} {}{} {}",
        theme::paint(Tone::Purple, display_name),
        theme::paint(Tone::Green, "→"),
        theme::paint(Tone::Black, steps),
        theme::paint(Tone::Black, &".".repeat(dots)),
        theme::paint(Tone::Green, "✓")
    );
}

async fn print_dry_run_table(names: &[String], _opts: &RunOpts) {
    println!(
        "{}",
        theme::line(&[
            (Tone::Red, "⚠ "),
            (Tone::Purple, "DRY RUN — no changes will be made")
        ])
    );
    println!();

    let mut total_mb = 0.0_f64;

    for name in names {
        let be = backend::find_backend(name).await;
        let meta = super::common::query_package(name).await;

        match (be, meta) {
            (Some(backend), Some(m)) => {
                println!(
                    "{}",
                    theme::line(&[
                        (Tone::Green, "  • "),
                        (Tone::Purple, &m.display_name),
                        (
                            Tone::Black,
                            &format!(
                                " (v{})  [{}]  ~{} MB",
                                m.version,
                                backend.label(),
                                m.size_mb
                            )
                        )
                    ])
                );
                total_mb += m.size_mb;
            }
            _ => {
                println!(
                    "{}",
                    theme::line(&[
                        (Tone::Red, "  • "),
                        (Tone::Purple, name),
                        (Tone::Black, " — not installed")
                    ])
                );
            }
        }
    }

    println!();
    println!(
        "{}",
        theme::kv_line(
            20,
            "Total would free",
            Tone::Blue,
            &format!("~{:.1} MB", total_mb)
        )
    );
    println!(
        "\n{}",
        theme::line(&[
            (Tone::Green, "  Remove "),
            (Tone::Purple, "--dry-run"),
            (Tone::Black, " to perform the actual removal.")
        ])
    );
    println!();
}

fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => s.to_string(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}
