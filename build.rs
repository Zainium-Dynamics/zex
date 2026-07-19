//! build.rs — Generate shell completions at build time.
//!
//! Output: completions/{zex.bash, zex.zsh, _zex.fish}
//! Install via install-symlinks.sh to /overlayer/syshub/share/completions/

use std::{env, fs, path::PathBuf};

fn main() {
    // Only regenerate when CLI changes
    println!("cargo:rerun-if-changed=src/main.rs");
    println!("cargo:rerun-if-changed=src/cmd/install/main.rs");
    println!("cargo:rerun-if-changed=src/cmd/remove/main.rs");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let comp_dir = PathBuf::from("completions");
    fs::create_dir_all(&comp_dir).ok();

    // We generate completions via a standalone script at install time
    // to avoid circular build deps. The build.rs just creates the dir.
    println!("cargo:warning=Run 'cargo run --bin gen-completions' after build to generate shell completions");
}
