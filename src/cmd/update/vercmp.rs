//! vercmp.rs — version comparison for update driver: the same rules as `cmd::upgrade::vercmp`.

pub fn is_upgrade(local: &str, remote: &str) -> bool {
    crate::cmd::upgrade::vercmp::is_upgrade(local, remote)
}
