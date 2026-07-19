pub mod common;
pub mod backend;
pub mod parallel;
pub mod persist_cache;
pub mod cache;
pub mod daemon;
// cmd/remove/mod.rs — re-exports the remove driver entry point
pub mod audit;
pub mod preflight;
pub mod single;
pub mod stats;
pub mod ui;
pub mod main;

pub use main::run;
