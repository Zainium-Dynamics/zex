use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

pub struct ActivationPlan {
    /// Pairs of (staged_path, final_path)
    pub moves: Vec<(PathBuf, PathBuf)>,
}

impl ActivationPlan {
    pub fn new() -> Self {
        Self {
            moves: Vec::new(),
        }
    }

    pub fn add(&mut self, staged_path: PathBuf, final_path: PathBuf) {
        self.moves.push((staged_path, final_path));
    }

    /// Place every file; on the first failure, remove what this plan already placed.
    pub fn commit(&self) -> Result<()> {
        let mut placed: Vec<&PathBuf> = Vec::new();
        for (staged_path, final_path) in &self.moves {
            if let Err(e) = place(staged_path, final_path) {
                for p in placed.iter().rev() {
                    let _ = fs::remove_file(p);
                }
                return Err(e.context("transaction rolled back"));
            }
            placed.push(final_path);
        }
        Ok(())
    }
}

/// Write next to the target, then rename over it: the swap is atomic and a running
/// program keeps its old copy. Staging may sit on another filesystem than the target.
fn place(staged: &Path, target: &Path) -> Result<()> {
    let name = target.file_name().unwrap_or_default().to_string_lossy();
    let tmp = target.with_file_name(format!(".{name}.zexnew"));
    let _ = fs::remove_file(&tmp);

    let meta = fs::symlink_metadata(staged).with_context(|| format!("stat {}", staged.display()))?;
    if meta.file_type().is_symlink() {
        let link = fs::read_link(staged)?;
        std::os::unix::fs::symlink(&link, &tmp).with_context(|| format!("symlink {}", tmp.display()))?;
    } else if fs::rename(staged, &tmp).is_err() {
        fs::copy(staged, &tmp).with_context(|| format!("copy {} -> {}", staged.display(), tmp.display()))?;
    }

    // a directory can't be renamed over; an old file or link can (once it isn't immutable)
    let _ = crate::immutable::try_clear_immutable(target);
    if fs::symlink_metadata(target).map(|m| m.is_dir()).unwrap_or(false) {
        let _ = fs::remove_file(&tmp);
        anyhow::bail!("{} is a directory", target.display());
    }
    fs::rename(&tmp, target).with_context(|| {
        let _ = fs::remove_file(&tmp);
        format!("place {}", target.display())
    })
}
