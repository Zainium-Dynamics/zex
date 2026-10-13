//! cmd/mod.rs — all zex sub-command modules.
//! Each module exposes:
//!   pub async fn run(raw_args: Vec<String>) — for async commands
//!   pub fn run(raw_args: Vec<String>)       — for sync commands

pub mod depends;
pub mod doctor;
pub mod history;
pub mod inspect;
pub mod install;
pub mod refresh;
pub mod remove;
pub mod rollback;
pub mod search;
pub mod sweep;
pub mod update;
pub mod upgrade;
pub mod why;
