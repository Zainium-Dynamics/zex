//! cmd/mod.rs — all zex sub-command modules.
//! Each module exposes:
//!   pub async fn run(raw_args: Vec<String>) — for async commands
//!   pub fn run(raw_args: Vec<String>)       — for sync commands

pub mod install;
pub mod upgrade;
pub mod remove;
pub mod search;
pub mod doctor;
pub mod rollback;
pub mod update;
pub mod sweep;
pub mod inspect;
pub mod depends;
pub mod why;
pub mod fmt;
pub mod history;
