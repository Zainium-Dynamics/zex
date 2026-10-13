// cmd/update/mod.rs — re-exports the update driver entry point
pub mod apply;
pub mod diff;
pub mod main;
pub mod ui;
pub mod vercmp;

pub use main::run;
