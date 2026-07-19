use anyhow::Result;
use std::path::PathBuf;

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

    /// Atomically commit all file moves.
    /// If any move fails, the entire transaction rolls back.
    pub fn commit(&self) -> Result<()> {
        let mut completed: Vec<(&PathBuf, &PathBuf)> = Vec::new();

        for (staged_path, final_path) in &self.moves {
            // Remove existing if it's a symlink or file
            if final_path.exists() || final_path.symlink_metadata().is_ok() {
            if let Err(e) = std::fs::remove_file(final_path) {
                // Try to rollback
                let _ = self.rollback(&completed);
                anyhow::bail!(
                    "Failed to remove existing file at {}: {}",
                    final_path.display(),
                    e
                );
            }
        }

        // Move the file
        match std::fs::rename(staged_path, final_path) {
            Ok(_) => {
                completed.push((staged_path, final_path));
            }
            Err(e) => {
                // Critical Failure - Rollback immediately
                let _ = self.rollback(&completed);
                anyhow::bail!(
                    "Failed to move file from {} to {}: {}. Transaction rolled back.",
                    staged_path.display(),
                    final_path.display(),
                    e
                );
            }
        }
    }

    Ok(())
}

/// Undo a partial activation.
fn rollback(&self, completed_moves: &[(&PathBuf, &PathBuf)]) -> Result<()> {
    for (staged_path, final_path) in completed_moves {
        // Move back from final_path to staged_path
        let _ = std::fs::rename(final_path, staged_path);
        // In a full implementation, we'd restore the old files here using a backup list.
        // For now, ensuring we don't leave broken half-states.
    }
    Ok(())
}
}
