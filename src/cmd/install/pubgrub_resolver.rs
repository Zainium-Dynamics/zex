use anyhow::Result;
use pubgrub::error::PubGrubError;
use pubgrub::range::Range;
use pubgrub::report::Reporter;
use pubgrub::solver::{Dependencies, DependencyProvider, resolve};
use pubgrub::type_aliases::Map;
use pubgrub::version::SemanticVersion;
use std::borrow::Borrow;
use std::collections::HashMap;
use std::str::FromStr;

/// Package source tier for priority-based resolution scoring.
#[derive(Debug, Clone, PartialEq)]
pub enum PackageTier {
    Zainium,
    Alpine,
    Chimera,
    Void,
}

pub type ZexVersion = SemanticVersion;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ZexPackage {
    pub real_name: String,
}

impl std::fmt::Display for ZexPackage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.real_name)
    }
}

/// Represents the global state for the PubGrub solver to query.
/// This would be backed by the PackageRegistry/Database in a full implementation.
use std::cell::RefCell;
use std::sync::Arc;

pub struct ZexDependencyProvider {
    pub client: Arc<reqwest::Client>,
    pub config: Arc<super::backend::BackendConfig>,
    pub mm: Arc<super::backend::MetadataManager>,

    // Dynamic Caches
    pub available_versions: RefCell<HashMap<ZexPackage, Vec<ZexVersion>>>,
    pub dependencies:
        RefCell<HashMap<(ZexPackage, ZexVersion), Dependencies<ZexPackage, ZexVersion>>>,
    pub tiers: RefCell<HashMap<(ZexPackage, ZexVersion), PackageTier>>,
}

impl ZexDependencyProvider {
    pub fn new(
        client: Arc<reqwest::Client>,
        config: Arc<super::backend::BackendConfig>,
        mm: Arc<super::backend::MetadataManager>,
    ) -> Self {
        Self {
            client,
            config,
            mm,
            available_versions: RefCell::new(HashMap::new()),
            dependencies: RefCell::new(HashMap::new()),
            tiers: RefCell::new(HashMap::new()),
        }
    }

    fn fetch_package(&self, pkg_name: &str) {
        // Only fetch if we haven't already
        let real_pkg = ZexPackage {
            real_name: pkg_name.to_string(),
        };
        if self.available_versions.borrow().contains_key(&real_pkg) {
            return;
        }

        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                super::resolver::resolve(pkg_name, &self.client, &self.config, &self.mm).await
            })
        });

        match result {
            Ok(info) => {
                // Parse version
                let ver = pubgrub::version::SemanticVersion::from_str(&info.version)
                    .unwrap_or_else(|_| {
                        pubgrub::version::SemanticVersion::from_str("1.0.0").unwrap()
                    });

                // Add to available versions
                self.available_versions
                    .borrow_mut()
                    .insert(real_pkg.clone(), vec![ver.clone()]);

                // Add to tiers
                let tier = match info.format {
                    super::backend::PackageFormat::Zex => PackageTier::Zainium,
                    super::backend::PackageFormat::Apk => PackageTier::Alpine,
                    super::backend::PackageFormat::Xbps => PackageTier::Void,
                    super::backend::PackageFormat::Adb => PackageTier::Chimera,
                };
                self.tiers
                    .borrow_mut()
                    .insert((real_pkg.clone(), ver.clone()), tier);

                // Add dependencies
                let mut deps = pubgrub::type_aliases::Map::default();
                for dep_name in &info.depends {
                    let dep_pkg = ZexPackage {
                        real_name: dep_name.clone(),
                    };
                    deps.insert(dep_pkg, pubgrub::range::Range::any());
                }

                self.dependencies
                    .borrow_mut()
                    .insert((real_pkg, ver), Dependencies::Known(deps));
            }
            Err(e) => {
                log::debug!("Failed to resolve dependency '{}': {}", pkg_name, e);
                self.available_versions
                    .borrow_mut()
                    .insert(real_pkg.clone(), vec![]);
            }
        }
    }
}

impl DependencyProvider<ZexPackage, ZexVersion> for ZexDependencyProvider {
    fn choose_package_version<T: Borrow<ZexPackage>, U: Borrow<Range<ZexVersion>>>(
        &self,
        potential_packages: impl Iterator<Item = (T, U)>,
    ) -> Result<(T, Option<ZexVersion>), Box<dyn std::error::Error>> {
        let mut best_idx = 0;
        let mut best_ver = None;
        let mut highest_tier = None;
        let mut pkgs: Vec<_> = potential_packages.collect();

        for (i, (pkg, range)) in pkgs.iter().enumerate() {
            let p = pkg.borrow();
            let r = range.borrow();

            self.fetch_package(&p.real_name);

            if let Some(versions) = self.available_versions.borrow().get(p) {
                for v in versions {
                    if r.contains(v) {
                        let tier_map = self.tiers.borrow();
                        let tier = tier_map
                            .get(&(p.clone(), v.clone()))
                            .unwrap_or(&PackageTier::Void);

                        let tier_score = match tier {
                            PackageTier::Zainium => 100,
                            PackageTier::Alpine => 75,
                            PackageTier::Chimera => 50,
                            PackageTier::Void => 25,
                        };

                        let current_best_score = match highest_tier {
                            Some(PackageTier::Zainium) => 100,
                            Some(PackageTier::Alpine) => 75,
                            Some(PackageTier::Chimera) => 50,
                            Some(PackageTier::Void) => 25,
                            None => 0,
                        };

                        if best_ver.is_none() || tier_score > current_best_score {
                            best_idx = i;
                            best_ver = Some(v.clone());
                            highest_tier = Some(tier.clone());
                        }
                        break;
                    }
                }
            }
        }

        let (best_pkg, _) = pkgs.swap_remove(best_idx);
        Ok((best_pkg, best_ver))
    }

    fn get_dependencies(
        &self,
        package: &ZexPackage,
        version: &ZexVersion,
    ) -> Result<Dependencies<ZexPackage, ZexVersion>, Box<dyn std::error::Error>> {
        self.fetch_package(&package.real_name);

        match self
            .dependencies
            .borrow()
            .get(&(package.clone(), version.clone()))
        {
            Some(deps) => Ok(deps.clone()),
            None => Ok(Dependencies::Unknown),
        }
    }
}

/// Solves the dependency graph.
/// Zainium Core pins can be fed in via the 'root' package dependencies.
pub fn solve_dependencies(
    provider: &ZexDependencyProvider,
    root_pkg: ZexPackage,
    root_ver: ZexVersion,
) -> Result<Map<ZexPackage, ZexVersion>> {
    match resolve(provider, root_pkg.clone(), root_ver) {
        Ok(lock) => Ok(lock),
        Err(PubGrubError::NoSolution(derivation_tree)) => {
            // Zainium Tier Supremacy rejection
            anyhow::bail!(
                "Dependency Hell Averted: No solution exists that satisfies the requirements without violating a Zainium Core pin.\n\nConflict Details:\n{}",
                pubgrub::report::DefaultStringReporter::report(&derivation_tree)
            );
        }
        Err(e) => anyhow::bail!("PubGrub resolution failed: {:?}", e),
    }
}
