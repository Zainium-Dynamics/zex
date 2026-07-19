// cmd/search/mod.rs — re-exports the search driver entry point
pub mod config;
pub mod models;
pub mod probers;
pub mod suggest;
pub mod ui;
pub mod main;

pub use main::run;
