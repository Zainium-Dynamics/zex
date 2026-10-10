//! lib.rs — Zex library exports.
//! The cmd modules are exposed here for internal cross-module use.

pub mod aliases;
pub mod archive_safety;
pub mod cmd;
pub mod executable;
pub mod extract;
pub mod http_client;
pub mod immutable;
pub mod local_install;
pub mod pinning;
pub mod sandbox;
pub mod syshub_pending;
pub mod triggers;
pub mod trust;
pub mod zex_codec;
