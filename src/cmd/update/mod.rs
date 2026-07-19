// cmd/update/mod.rs — re-exports the update driver entry point
pub mod diff;
pub mod apply;
pub mod ui;
pub mod vercmp;
pub mod main;

pub use main::run;
