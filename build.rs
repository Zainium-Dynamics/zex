//! build.rs — Generate shell completions at build time.
//!
//! Output: completions/{zex.bash, zex.zsh, _zex.fish}
//! Install via install-symlinks.sh to /overlayer/syshub/share/completions/

use std::{fs, path::PathBuf};

fn main() {
    // Only regenerate when CLI changes
    println!("cargo:rerun-if-changed=src/main.rs");
    println!("cargo:rerun-if-changed=src/cmd/install/main.rs");
    println!("cargo:rerun-if-changed=src/cmd/remove/main.rs");

    let comp_dir = PathBuf::from("completions");
    fs::create_dir_all(&comp_dir).ok();

    // the completions in completions/ are kept in the repo; build.rs only creates the dir
}
