//! build.rs: Generate shell completions at build time.

use std::{fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=src/main.rs");
    println!("cargo:rerun-if-changed=src/cmd/install/main.rs");
    println!("cargo:rerun-if-changed=src/cmd/remove/main.rs");

    let comp_dir = PathBuf::from("completions");
    fs::create_dir_all(&comp_dir).ok();

}
