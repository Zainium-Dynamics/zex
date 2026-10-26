// cmd/upgrade/mod.rs — re-exports the upgrade driver entry point
pub mod audit;
pub mod benchmark;
pub mod checksum;
pub mod esp;
pub mod kernel;
pub mod main;
pub mod swap;
pub mod syscore;
pub mod transaction;
pub mod ui;
pub mod userland;
pub mod vercmp;

pub use main::run;
