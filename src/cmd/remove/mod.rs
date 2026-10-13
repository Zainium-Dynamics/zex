pub mod backend;
pub mod cache;
pub mod common;
pub mod daemon;
pub mod parallel;
pub mod persist_cache;
// cmd/remove/mod.rs — re-exports the remove driver entry point
pub mod audit;
pub mod main;
pub mod preflight;
pub mod single;
pub mod stats;
pub mod ui;

pub use main::run;
