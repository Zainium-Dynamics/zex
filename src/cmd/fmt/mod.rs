//! cmd/fmt — zex fmt: secure package builder and verifier.
//!
//! Sub-commands:
//!   zex fmt pack <dir> --version <v>    — build a .zex package
//!   zex fmt unpack <file>               — extract a .zex package
//!   zex fmt verify <file>               — verify signature + integrity
//!   zex fmt inspect <file>              — show embedded security report
//!   zex fmt review <.zex.locked> ...    — fill maintainer review slot

pub mod cli;
pub mod core;
pub mod error;
pub mod security;
pub mod ui;
pub mod utils;
pub mod main;

pub use main::run;
