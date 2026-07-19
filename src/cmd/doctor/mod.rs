// cmd/doctor/mod.rs — re-exports the doctor driver entry point
pub mod audit;
pub mod fix;
pub mod layout;
pub mod ui;
pub mod main;

pub use main::run;
