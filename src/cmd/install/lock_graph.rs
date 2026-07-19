use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::backend::BackendConfig;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockedPackage {
    pub name: String,
    pub version: String,
    pub format: String,
    pub source_url: String,
    pub sha256: String,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockGraph {
    pub schema_version: u32,
    pub packages: Vec<LockedPackage>,
}

impl LockGraph {
    pub fn new(mut packages: Vec<LockedPackage>) -> Self {
        normalize_packages(&mut packages);
        Self {
            schema_version: 1,
            packages,
        }
    }

    pub fn canonical_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn graph_hash_hex(&self) -> Result<String, serde_json::Error> {
        let canonical = self.canonical_json()?;
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        Ok(format!("{:x}", hasher.finalize()))
    }
}

fn atomic_write(path: &Path, content: &str) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)?;
        f.write_all(content.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(tmp, path)?;
    Ok(())
}

pub fn persist_for_txn(
    config: &BackendConfig,
    txn_id: &str,
    graph: &LockGraph,
) -> Result<PathBuf, anyhow::Error> {
    let dir = PathBuf::from(&config.cache_dir).join("lock-graphs");
    std::fs::create_dir_all(&dir)?;

    let file_path = dir.join(format!("{}.lock.json", txn_id));
    let canonical = graph.canonical_json()?;
    atomic_write(&file_path, &canonical)?;

    Ok(file_path)
}

fn normalize_packages(packages: &mut [LockedPackage]) {
    for pkg in packages.iter_mut() {
        pkg.dependencies.sort();
        pkg.dependencies.dedup();
    }

    packages.sort_by(|a, b| {
        (
            a.name.as_str(),
            a.version.as_str(),
            a.format.as_str(),
            a.source_url.as_str(),
            a.sha256.as_str(),
        )
            .cmp(&(
                b.name.as_str(),
                b.version.as_str(),
                b.format.as_str(),
                b.source_url.as_str(),
                b.sha256.as_str(),
            ))
    });
}

#[cfg(test)]
mod tests {
    use super::{LockGraph, LockedPackage};

    fn pkg(name: &str, deps: &[&str]) -> LockedPackage {
        LockedPackage {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            format: "deb".to_string(),
            source_url: format!("https://mirror.example/{name}.deb"),
            sha256: format!("sha-{name}"),
            dependencies: deps.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    #[test]
    fn produces_stable_hash_independent_of_input_order() {
        let g1 = LockGraph::new(vec![pkg("beta", &["z", "a"]), pkg("alpha", &["c", "b"])]);
        let g2 = LockGraph::new(vec![pkg("alpha", &["b", "c"]), pkg("beta", &["a", "z"])]);

        let h1 = g1.graph_hash_hex().expect("hash should generate");
        let h2 = g2.graph_hash_hex().expect("hash should generate");
        assert_eq!(h1, h2);
    }

    #[test]
    fn canonical_json_is_stable_for_repeated_calls() {
        let g = LockGraph::new(vec![pkg("alpha", &["dep2", "dep1", "dep1"])]);
        let j1 = g.canonical_json().expect("json should serialize");
        let j2 = g.canonical_json().expect("json should serialize");
        assert_eq!(j1, j2);

        let parsed: LockGraph = serde_json::from_str(&j1).expect("json should parse");
        assert_eq!(parsed.packages.len(), 1);
        assert_eq!(parsed.packages[0].dependencies, vec!["dep1", "dep2"]);
    }
}
