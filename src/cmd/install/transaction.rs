use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cmd::install::registry::PkgRecord;

/// Snapshots the pre-operation state of a whole package batch (a main
/// package plus every dependency being installed alongside it) as ONE
/// transaction, so a failure partway through can roll back everything
/// that already succeeded: not just the single package that happened to
/// fail. Returns the transaction id for use with `rollback::rollback_userland`.
pub fn create_snapshot(pkgs: &[String], op: &str) -> std::io::Result<String> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let tx_id = format!("tx-{}", ts);
    let tx_dir = PathBuf::from(format!("/overlayer/zexlib/transactions/{}", tx_id));
    fs::create_dir_all(&tx_dir)?;

    let backup_name = if op == "install" {
        ""
    } else {
        "backup.tar.zst"
    };
    let target_label = pkgs.join(",");

    let mut existing: Vec<(String, PkgRecord)> = Vec::new();
    for pkg in pkgs {
        let live_receipt =
            PathBuf::from(format!("/overlayer/zexlib/registry/installed/{}.toml", pkg));
        if let Some(record) = fs::read_to_string(&live_receipt)
            .ok()
            .and_then(|raw| toml::from_str::<PkgRecord>(&raw).ok())
        {
            fs::copy(&live_receipt, tx_dir.join(format!("{}.toml", pkg)))?;
            existing.push((pkg.clone(), record));
        }
    }
    let version = existing
        .first()
        .map(|(_, r)| r.version.clone())
        .unwrap_or_default();

    let packages_list = pkgs
        .iter()
        .map(|p| format!("\"{p}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let state_toml = format!(
        "transaction_id = \"{}\"\ntimestamp = \"{}\"\noperation = \"{}\"\ntarget_package = \"{}\"\nbackup_archive = \"{}\"\nversion = \"{}\"\npackages = [{}]\n",
        tx_id, ts, op, target_label, backup_name, version, packages_list
    );
    fs::write(tx_dir.join("state.toml"), state_toml)?;

    let live_pkgs = PathBuf::from("/overlayer/zexlib/registry/packages.toml");
    if live_pkgs.exists() {
        fs::copy(&live_pkgs, tx_dir.join("packages.toml"))?;
    }

    if op == "remove" || op == "upgrade" {
        let all_files: Vec<String> = existing
            .iter()
            .flat_map(|(_, r)| r.installed_files.clone())
            .collect();
        if !all_files.is_empty() {
            create_tar_backup(&all_files, &tx_dir.join("backup.tar.zst"))?;
        }
    }

    let _ = prune_transactions(3);

    Ok(tx_id)
}

fn create_tar_backup(paths: &[String], dest: &Path) -> std::io::Result<()> {
    let file = fs::File::create(dest)?;
    let enc = zstd::stream::write::Encoder::new(file, 3)?.auto_finish();
    let mut builder = tar::Builder::new(enc);

    for path_str in paths {
        let p = Path::new(path_str);
        if p.exists() && p.is_file() {
            let tar_path = p.strip_prefix("/").unwrap_or(p);
            let mut f = fs::File::open(p)?;
            builder.append_file(tar_path, &mut f)?;
        }
    }
    builder.finish()?;
    Ok(())
}

pub fn prune_transactions(keep_count: usize) -> std::io::Result<()> {
    let tx_dir = Path::new("/overlayer/zexlib/transactions");
    if !tx_dir.exists() {
        return Ok(());
    }

    let mut transactions = Vec::new();
    for entry in fs::read_dir(tx_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            transactions.push(entry.path());
        }
    }

    transactions.sort();

    if transactions.len() > keep_count {
        let to_remove = transactions.len() - keep_count;
        for i in 0..to_remove {
            let _ = fs::remove_dir_all(&transactions[i]);
        }
    }
    Ok(())
}
