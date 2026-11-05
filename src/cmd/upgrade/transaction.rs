//! Transactional rollback engine.

use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// One checkpointed file: records its pre-update state.
///
/// Serializable: this is written to disk as an on-disk journal entry (see
/// `Transaction::checkpoint`) so a crash that kills the process before
/// `commit`/`rollback` runs still leaves enough information on disk for
/// `Transaction::recover_stale` to finish the rollback on the next run —
/// the in-memory `Vec<Checkpoint>` alone is lost the instant the process dies.
#[derive(Debug, Serialize, Deserialize)]
struct Checkpoint {
    /// The live path that will be (or was) modified.
    target: PathBuf,
    /// What it was before modification.
    state: PreState,
}

#[derive(Debug, Serialize, Deserialize)]
enum PreState {
    /// File did not exist: rollback = delete it
    DidNotExist,
    /// File was a regular file: content backed up to this temp path
    BackedUp(PathBuf),
    /// File was a symlink pointing to this target
    Symlink(PathBuf),
    /// Directory too large to backup in full (modules): directory path noted
    LargeDir(PathBuf),
}

/// Writes `contents` to `path` crash-safely: write to a sibling temp file,
/// fsync it, rename over the destination, then fsync the containing
/// directory so the rename itself is durable across a power loss.
fn write_atomic(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow!("path has no parent: {:?}", path))?;
    fs::create_dir_all(dir)?;
    let tmp_path = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("journal"),
        std::process::id()
    ));
    {
        let mut f = fs::File::create(&tmp_path)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    fs::rename(&tmp_path, path)?;
    if let Ok(dir_file) = fs::File::open(dir) {
        let _ = dir_file.sync_all();
    }
    Ok(())
}

pub struct Transaction {
    checkpoints: Vec<Checkpoint>,
    backup_root: PathBuf,
    #[allow(dead_code)]
    step_log: Vec<String>,
    checkpoint_seq: u64,
}

/// Marker file name recording a transaction's on-disk state: "in_progress"
/// from creation until `commit()` atomically flips it to "committed" as its
/// very first action (before any cleanup). `recover_stale` uses this to
/// tell a genuinely-interrupted transaction (still "in_progress": the
/// owning process died) apart from one that crashed merely while deleting
/// its own already-committed backup files (which must NOT be rolled back).
const STATE_FILE: &str = "STATE";
const STATE_IN_PROGRESS: &str = "in_progress";
const STATE_COMMITTED: &str = "committed";

impl Transaction {
    /// Create a new transaction. `backup_root` is where backup copies are stored.
    #[allow(dead_code)]
    pub fn with_path(staging_dir: &Path) -> anyhow::Result<Self> {
        Self::new(staging_dir)
    }

    /// Create a new transaction. `backup_root` is where backup copies are stored.
    pub fn new(staging_dir: &Path) -> anyhow::Result<Self> {
        let backup_root = staging_dir.join(format!("rollback-{}", std::process::id()));
        fs::create_dir_all(&backup_root)?;
        fs::create_dir_all(backup_root.join("checkpoints"))?;
        write_atomic(&backup_root.join(STATE_FILE), STATE_IN_PROGRESS.as_bytes())?;
        Ok(Self {
            checkpoints: Vec::new(),
            backup_root,
            step_log: Vec::new(),
            checkpoint_seq: 0,
        })
    }

    /// Snapshot the current state of `path` before it is modified.
    ///
    /// Call this BEFORE any write/rename/delete that touches `path`.
    /// If `path` does not exist yet, records `DidNotExist` so rollback deletes it.
    ///
    /// Persists the checkpoint to an on-disk journal entry *before*
    /// returning: a crash right after this call still leaves enough on
    /// disk for `recover_stale` to finish the rollback later; the
    /// in-memory `checkpoints` vec alone would be lost the instant this
    /// process dies.
    pub fn checkpoint(&mut self, path: &Path) -> anyhow::Result<()> {
        let state = if !path.exists() && !path.is_symlink() {
            PreState::DidNotExist
        } else if path.is_symlink() {
            let target = fs::read_link(path)?;
            PreState::Symlink(target)
        } else if path.is_file() {
            let backup_name = path_to_backup_name(path);
            let backup_path = self.backup_root.join(&backup_name);
            if let Some(p) = backup_path.parent() {
                fs::create_dir_all(p)?;
            }
            fs::copy(path, &backup_path)
                .map_err(|e| anyhow!("Failed to backup {:?} for rollback: {}", path, e))?;
            PreState::BackedUp(backup_path)
        } else if path.is_dir() {
            let backup_dir = self.backup_root.join(path_to_backup_name(path));
            if path.exists() {
                if let Some(p) = backup_dir.parent() {
                    fs::create_dir_all(p)?;
                }
                fs::rename(path, &backup_dir)
                    .map_err(|e| anyhow!("Failed to backup dir {:?}: {}", path, e))?;
                fs::create_dir_all(path)?;
            }
            PreState::LargeDir(backup_dir)
        } else {
            PreState::DidNotExist
        };

        let checkpoint = Checkpoint {
            target: path.to_path_buf(),
            state,
        };
        let journal_path = self
            .backup_root
            .join("checkpoints")
            .join(format!("{:06}.json", self.checkpoint_seq));
        let journal_json = serde_json::to_vec(&checkpoint)
            .map_err(|e| anyhow!("failed to serialize checkpoint journal entry: {}", e))?;
        write_atomic(&journal_path, &journal_json)?;
        self.checkpoint_seq += 1;

        self.step_log
            .push(format!("checkpoint: {:?}", checkpoint.target));
        self.checkpoints.push(checkpoint);
        Ok(())
    }

    /// Log that a step completed successfully.
    #[allow(dead_code)]
    pub fn step_ok(&mut self, step: &str) {
        self.step_log.push(format!("step_ok: {}", step));
    }

    /// Commit: all steps succeeded. Delete all backup copies.
    pub fn commit(self) {
        let _ = write_atomic(
            &self.backup_root.join(STATE_FILE),
            STATE_COMMITTED.as_bytes(),
        );
        for cp in &self.checkpoints {
            match &cp.state {
                PreState::BackedUp(bp) => {
                    let _ = fs::remove_file(bp);
                }
                PreState::LargeDir(bp) => {
                    let _ = fs::remove_dir_all(bp);
                }
                _ => {}
            }
        }
        let _ = fs::remove_dir_all(&self.backup_root);
    }

    /// Rollback: at least one step failed. Restore ALL checkpoints IN REVERSE ORDER.
    ///
    /// After rollback, the system is identical to its pre-update state.
    pub fn rollback(self) -> anyhow::Result<()> {
        let mut errors: Vec<String> = Vec::new();

        for cp in self.checkpoints.into_iter().rev() {
            if let Err(e) = restore_checkpoint(cp) {
                errors.push(e.to_string());
            }
        }

        let _ = fs::remove_dir_all(&self.backup_root);

        if errors.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(
                "Rollback completed with {} restoration error(s):\n{}",
                errors.len(),
                errors.join("\n")
            ))
        }
    }

    /// Crash recovery: finds and finishes any transaction left behind by a
    /// process that died (SIGKILL, power loss, OOM) before it could call
    /// `commit()` or `rollback()` on itself: the normal in-process error
    /// handling those two provide is no help there, since the `Transaction`
    /// value and its in-memory checkpoint list die with the process. Scans
    /// `staging_dir` for `rollback-<pid>` directories from *previous* runs:
    /// ones marked "committed" just get their leftover directory deleted;
    /// ones still "in_progress" get their on-disk checkpoint journal
    /// replayed in reverse, restoring every file to its pre-transaction
    /// state: exactly what `rollback()` would have done had the owning
    /// process lived long enough to call it.
    ///
    /// Safe to call unconditionally at the start of every syshub/userland
    /// upgrade: a clean prior run leaves nothing to recover, and this never
    /// touches a `rollback-<pid>` directory belonging to the *current*
    /// process (that can't exist yet: `Transaction::new` hasn't run).
    pub fn recover_stale(staging_dir: &Path) -> Vec<String> {
        let mut recovered = Vec::new();
        let Ok(entries) = fs::read_dir(staging_dir) else {
            return recovered;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let is_rollback_dir = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("rollback-"));
            if !is_rollback_dir || !path.is_dir() {
                continue;
            }

            let state = fs::read_to_string(path.join(STATE_FILE)).unwrap_or_default();
            if state.trim() == STATE_COMMITTED {
                let _ = fs::remove_dir_all(&path);
                continue;
            }

            let checkpoints_dir = path.join("checkpoints");
            let mut journal_files: Vec<PathBuf> = fs::read_dir(&checkpoints_dir)
                .map(|d| d.flatten().map(|e| e.path()).collect())
                .unwrap_or_default();
            journal_files.sort();

            for journal_path in journal_files.into_iter().rev() {
                let Ok(raw) = fs::read_to_string(&journal_path) else {
                    continue;
                };
                let Ok(cp) = serde_json::from_str::<Checkpoint>(&raw) else {
                    continue;
                };
                let target_display = cp.target.display().to_string();
                match restore_checkpoint(cp) {
                    Ok(()) => recovered.push(target_display),
                    Err(e) => log::warn!(
                        "crash recovery: failed to restore {}: {}",
                        target_display,
                        e
                    ),
                }
            }

            let _ = fs::remove_dir_all(&path);
        }

        recovered
    }

    /// Returns all logged steps (for audit log).
    #[allow(dead_code)]
    pub fn step_log(&self) -> &[String] {
        &self.step_log
    }
}

fn restore_checkpoint(cp: Checkpoint) -> anyhow::Result<()> {
    match cp.state {
        PreState::DidNotExist => {
            if cp.target.exists() || cp.target.is_symlink() {
                if cp.target.is_dir() {
                    fs::remove_dir_all(&cp.target).map_err(|e| {
                        anyhow!("Rollback: failed to delete {:?}: {}", cp.target, e)
                    })?;
                } else {
                    fs::remove_file(&cp.target).map_err(|e| {
                        anyhow!("Rollback: failed to delete {:?}: {}", cp.target, e)
                    })?;
                }
            }
        }
        PreState::BackedUp(backup_path) => {
            if let Some(p) = cp.target.parent() {
                let _ = fs::create_dir_all(p);
            }
            fs::rename(&backup_path, &cp.target)
                .or_else(|_| {
                    fs::copy(&backup_path, &cp.target)?;
                    fs::remove_file(&backup_path)?;
                    Ok::<(), std::io::Error>(())
                })
                .map_err(|e| anyhow!("Rollback: failed to restore {:?}: {}", cp.target, e))?;
        }
        PreState::Symlink(original_target) => {
            if cp.target.exists() || cp.target.is_symlink() {
                fs::remove_file(&cp.target).map_err(|e| {
                    anyhow!("Rollback: failed to remove symlink {:?}: {}", cp.target, e)
                })?;
            }
            std::os::unix::fs::symlink(&original_target, &cp.target).map_err(|e| {
                anyhow!("Rollback: failed to restore symlink {:?}: {}", cp.target, e)
            })?;
        }
        PreState::LargeDir(backup_dir) => {
            if cp.target.exists() {
                fs::remove_dir_all(&cp.target).map_err(|e| {
                    anyhow!("Rollback: failed to remove new dir {:?}: {}", cp.target, e)
                })?;
            }
            if backup_dir.exists() {
                fs::rename(&backup_dir, &cp.target).map_err(|e| {
                    anyhow!("Rollback: failed to restore dir {:?}: {}", cp.target, e)
                })?;
            }
        }
    }
    Ok(())
}

/// Convert a path to a flat backup filename (replaces `/` with `__`).
fn path_to_backup_name(path: &Path) -> String {
    path.to_string_lossy()
        .trim_start_matches('/')
        .replace('/', "__")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each test gets its own unique temp directory so parallel tests don't collide.
    fn tmp_dir(test_name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("zai_tx_{}_{}", test_name, std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn rollback_restores_existing_file() {
        let root = tmp_dir("restore_file");
        let target = root.join("testfile");
        let stage = root.join("stage");
        fs::create_dir_all(&stage).unwrap();

        fs::write(&target, b"ORIGINAL").unwrap();

        let mut tx = Transaction::new(&stage).unwrap();
        tx.checkpoint(&target).unwrap();

        fs::write(&target, b"NEW CONTENT").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"NEW CONTENT");

        tx.rollback().unwrap();

        assert_eq!(fs::read(&target).unwrap(), b"ORIGINAL");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rollback_deletes_newly_created_file() {
        let root = tmp_dir("delete_new");
        let target = root.join("newfile");
        let stage = root.join("stage");
        fs::create_dir_all(&stage).unwrap();

        assert!(!target.exists());

        let mut tx = Transaction::new(&stage).unwrap();
        tx.checkpoint(&target).unwrap();

        fs::write(&target, b"CREATED BY UPDATE").unwrap();
        assert!(target.exists());

        tx.rollback().unwrap();

        assert!(!target.exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn commit_removes_backup_copies() {
        let root = tmp_dir("commit_backup");
        let target = root.join("commitfile");
        let stage = root.join("stage");
        fs::create_dir_all(&stage).unwrap();

        fs::write(&target, b"ORIGINAL").unwrap();

        let mut tx = Transaction::new(&stage).unwrap();
        let backup_root = tx.backup_root.clone();
        tx.checkpoint(&target).unwrap();

        assert!(backup_root.exists());

        fs::write(&target, b"UPDATED").unwrap();

        tx.commit();

        assert!(!backup_root.exists());
        assert_eq!(fs::read(&target).unwrap(), b"UPDATED");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rollback_runs_in_reverse_order() {
        let root = tmp_dir("reverse_order");
        let file_a = root.join("a");
        let file_b = root.join("b");
        let stage = root.join("stage");
        fs::create_dir_all(&stage).unwrap();

        fs::write(&file_a, b"A-ORIGINAL").unwrap();
        fs::write(&file_b, b"B-ORIGINAL").unwrap();

        let mut tx = Transaction::new(&stage).unwrap();
        tx.checkpoint(&file_a).unwrap();
        tx.checkpoint(&file_b).unwrap();

        fs::write(&file_a, b"A-NEW").unwrap();
        fs::write(&file_b, b"B-NEW").unwrap();

        tx.rollback().unwrap();

        assert_eq!(fs::read(&file_a).unwrap(), b"A-ORIGINAL");
        assert_eq!(fs::read(&file_b).unwrap(), b"B-ORIGINAL");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn recover_stale_restores_interrupted_transaction() {
        let root = tmp_dir("recover_interrupted");
        let target = root.join("critical-file");
        let stage = root.join("stage");
        fs::create_dir_all(&stage).unwrap();
        fs::write(&target, b"ORIGINAL").unwrap();

        {
            let mut tx = Transaction::new(&stage).unwrap();
            tx.checkpoint(&target).unwrap();
            fs::write(&target, b"HALF-UPGRADED").unwrap();
        }
        assert_eq!(fs::read(&target).unwrap(), b"HALF-UPGRADED");

        let recovered = Transaction::recover_stale(&stage);
        assert_eq!(recovered.len(), 1);
        assert_eq!(fs::read(&target).unwrap(), b"ORIGINAL");

        let leftover = fs::read_dir(&stage).unwrap().flatten().count();
        assert_eq!(leftover, 0);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn recover_stale_ignores_already_committed_transaction() {
        let root = tmp_dir("recover_committed");
        let target = root.join("already-upgraded-file");
        let stage = root.join("stage");
        fs::create_dir_all(&stage).unwrap();
        fs::write(&target, b"NEW VERSION").unwrap();

        let backup_root = stage.join("rollback-999999");
        fs::create_dir_all(backup_root.join("checkpoints")).unwrap();
        fs::write(backup_root.join(STATE_FILE), STATE_COMMITTED).unwrap();

        let recovered = Transaction::recover_stale(&stage);
        assert!(recovered.is_empty());
        assert_eq!(fs::read(&target).unwrap(), b"NEW VERSION");
        assert!(!backup_root.exists());

        let _ = fs::remove_dir_all(&root);
    }
}
