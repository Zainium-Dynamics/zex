//! Landlock LSM rules for post-install script confinement.

use std::path::Path;

use anyhow::{Context, Result};
use landlock::{
    path_beneath_rules, Access, ABI, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr,
};

const SYSHUB_BIN: &str = "/overlayer/syshub/bin";
const UNION_ROOT: &str = "/overlayer/zexlib/union";
const SYSHUB_ETC: &str = "/overlayer/syshub/etc";

/// Restrict the current thread to read/execute syshub + read/write union + store path.
pub fn restrict_postinst(store_path: &Path) -> Result<()> {
    let abi = ABI::V3;
    let store = store_path
        .canonicalize()
        .unwrap_or_else(|_| store_path.to_path_buf());
    let store_str = store.to_string_lossy().to_string();

    Ruleset::default()
        .handle_access(<AccessFs as Access>::from_all(abi))
        .context("landlock handle_access")?
        .create()
        .context("landlock create")?
        .add_rules(path_beneath_rules(
            [SYSHUB_BIN, SYSHUB_ETC],
            AccessFs::from_read(abi),
        ))?
        .add_rules(path_beneath_rules(
            [UNION_ROOT, store_str.as_str()],
            <AccessFs as Access>::from_all(abi),
        ))?
        .restrict_self()
        .context("landlock restrict_self")?;

    Ok(())
}