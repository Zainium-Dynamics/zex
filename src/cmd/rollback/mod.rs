// cmd/rollback/mod.rs — re-exports the rollback driver entry point
pub mod main;
pub mod transaction;
pub mod ui;

pub use main::run;
