//! Install/remove hot-path micro-benchmarks.

use std::hint::black_box;
use std::path::Path;

fn main() {
    let iterations = 10_000usize;

    let start = std::time::Instant::now();
    for i in 0..iterations {
        let p = Path::new("usr/bin/vim");
        let _ = black_box(zex::archive_safety::sanitize_archive_path(p).unwrap());
        black_box(i);
    }
    println!(
        "sanitize_archive_path: {} ops in {:?}",
        iterations,
        start.elapsed()
    );

    let start = std::time::Instant::now();
    for i in 0..iterations {
        let _ = black_box(zex::cmd::upgrade::vercmp::is_upgrade("1.0.0", "1.0.1"));
        black_box(i);
    }
    println!(
        "vercmp is_upgrade: {} ops in {:?}",
        iterations,
        start.elapsed()
    );

    let start = std::time::Instant::now();
    for i in 0..1_000 {
        let _ = black_box(zex::cmd::install::union::build_sync_event());
        black_box(i);
    }
    println!("union sync event: 1000 ops in {:?}", start.elapsed());
}
