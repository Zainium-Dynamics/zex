// cmd/upgrade/mod.rs — re-exports the upgrade driver entry point
pub mod audit;
pub mod benchmark;
pub mod checksum;
pub mod swap;
pub mod transaction;
pub mod ui;
pub mod vercmp;
pub mod syscore;
pub mod userland;
pub mod main;

pub use main::run;
