//! depends.rs: Dependency resolution engine for the Zex install driver.

use anyhow::Result;
use std::collections::{HashMap, HashSet, VecDeque};

use super::backend::{BackendConfig, MetadataManager, PackageInfo};
use crate::cmd::upgrade::vercmp::Version;

/// A fully resolved dependency plan ready for download + install.
#[derive(Debug)]
pub struct DepPlan {
    /// Deps to install, in topological order (leaves first).
    pub packages: Vec<PackageInfo>,
    /// Deps that were skipped because they're already installed.
    pub already_installed: Vec<String>,
    /// (dependency_token, provider_name) pairs for deps skipped because
    /// syshub already provides them: either file-detected or explicitly
    /// blocked (`blocked.rs`): surfaced separately from
    /// `already_installed` so the UI can say *why* instead of silently
    /// dropping the dependency with no explanation.
    pub syshub_provided: Vec<(String, String)>,
    /// Deps that couldn't be resolved (virtual packages, etc.)
    pub unresolvable: Vec<String>,
    /// Total download size of all deps in bytes.
    pub total_size: u64,
    /// (package_being_installed, already_installed_package) pairs that
    /// declared themselves incompatible with each other: checked
    /// bidirectionally, since real indexes only declare it from one side.
    pub conflicts: Vec<(String, String)>,
    /// (package_name, reason) pairs for dependency tokens carrying a
    /// version constraint (e.g. "libfoo>=2.0") whose resolved candidate
    /// violates it: either a freshly-resolved transitive dep, or an
    /// already-installed direct dep whose installed version doesn't satisfy
    /// what the root package actually requires.
    pub version_conflicts: Vec<(String, String)>,
    /// (dependency_name, preferred_mirror_id, actual_mirror_used) for every
    /// dependency that couldn't be satisfied from the *same* mirror the
    /// root package itself came from and had to fall back to a different
    /// one: surfaced as a warning, not an error, since a real cross-tier
    /// dependency is sometimes genuinely correct (e.g. a shared library
    /// only one tier packages), but silently substituting tiers is exactly
    /// the "dependency hell" this makes visible instead of hidden.
    pub cross_tier_fallbacks: Vec<(String, String, String)>,
}

/// Checks whether `resolved_version` satisfies the version constraint
/// embedded in `token` (e.g. "vim-common>=9.2.0747-r0"). Returns `None` if
/// the token carries no constraint, or if it does and it's satisfied.
/// Whether a dependency token (which may carry an embedded version
/// constraint, e.g. "vim-common=9.2.0747-r0") refers to a package that's
/// already installed or provided by Syshub. Matching must strip the
/// constraint first: `installed_set`/`is_in_syshub` only know bare names,
/// so an exact-string match against a versioned token would always miss.
fn dep_already_present(token: &str, installed_set: &HashSet<String>) -> bool {
    let base = super::apk::strip_constraint(token).to_ascii_lowercase();
    installed_set.contains(&base)
        || super::blocked::provided_by(&base).is_some()
        || super::backend::is_in_syshub(&base)
        || library_dir(token).is_some()
}

/// For a library dependency ("so:libpcre2-8.so.0"), the loader directory that
/// already has it: whatever package put it there, so a repository's own copy
/// is never installed over the base's.
fn library_dir(token: &str) -> Option<&'static str> {
    let lib = super::apk::strip_constraint(token).trim();
    let lib = lib
        .strip_prefix("so:")
        .or_else(|| lib.strip_prefix("SO:"))?;
    super::libcheck::system_dir_of(lib)
}

/// If `token` is skipped because syshub (not zex's own registry) already
/// provides it: either file-detected (`is_in_syshub`) or explicitly
/// hand-listed (`blocked::provided_by`, for cases with no file-level
/// overlap to detect, e.g. `coreutils` vs Zainium's own `userutils`) —
/// returns what provides it, for a "provided by the immutable base"
/// message instead of silently dropping the dependency with no
/// explanation at all.
fn syshub_provider(token: &str, installed_set: &HashSet<String>) -> Option<String> {
    let base = super::apk::strip_constraint(token).to_ascii_lowercase();
    if installed_set.contains(&base) {
        return None;
    }
    if let Some(provider) = super::blocked::provided_by(&base) {
        return Some(provider.to_string());
    }
    if super::backend::is_in_syshub(&base) {
        return Some(base);
    }
    if library_dir(token).is_some_and(|d| d.starts_with("/overlayer/syshub")) {
        return Some(base.trim_start_matches("so:").to_string());
    }
    None
}

fn check_version_constraint(token: &str, resolved_version: &str) -> Option<String> {
    let (op, required) = super::apk::parse_constraint(token)?;
    use super::apk::ConstraintOp::*;

    let ok = if op == Fuzzy {
        resolved_version.starts_with(required)
    } else {
        let actual = Version::parse(resolved_version);
        let required_v = Version::parse(required);
        match op {
            Ge => actual >= required_v,
            Le => actual <= required_v,
            Gt => actual > required_v,
            Lt => actual < required_v,
            Eq => actual == required_v,
            Fuzzy => unreachable!(),
        }
    };

    if ok {
        None
    } else {
        Some(format!(
            "requires {token} but resolved version is {resolved_version}"
        ))
    }
}

/// Checks `candidates` (the root package plus every resolved dependency)
/// against everything currently installed for genuine conflicts, in both
/// directions: a candidate can declare "!other-pkg" itself, or something
/// already installed can declare a conflict with a candidate.
fn check_conflicts(candidates: &[&PackageInfo]) -> Vec<(String, String)> {
    let installed = super::registry::load_all();
    let mut out = Vec::new();

    for cand in candidates {
        for c in &cand.conflicts {
            let base = super::apk::strip_constraint(c).to_ascii_lowercase();
            if installed.iter().any(|r| r.name.eq_ignore_ascii_case(&base)) {
                out.push((cand.name.clone(), base));
            }
        }
    }
    for rec in &installed {
        for c in &rec.conflicts {
            let base = super::apk::strip_constraint(c).to_ascii_lowercase();
            for cand in candidates {
                if cand.name.eq_ignore_ascii_case(&base) {
                    out.push((rec.name.clone(), cand.name.clone()));
                }
            }
        }
    }
    out
}

/// Resolve all transitive dependencies for a package dynamically.
pub async fn resolve_dependencies(
    root: &PackageInfo,
    client: &reqwest::Client,
    config: &BackendConfig,
    mm: &MetadataManager,
) -> Result<DepPlan> {
    if root.depends.is_empty() {
        return Ok(DepPlan {
            packages: Vec::new(),
            already_installed: Vec::new(),
            syshub_provided: Vec::new(),
            unresolvable: Vec::new(),
            total_size: 0,
            conflicts: check_conflicts(&[root]),
            version_conflicts: Vec::new(),
            cross_tier_fallbacks: Vec::new(),
        });
    }

    let installed_set = get_installed_packages().await;

    let mut resolved: HashMap<String, PackageInfo> = HashMap::new();
    let mut unresolvable: Vec<String> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    let mut version_conflicts: Vec<(String, String)> = Vec::new();
    let mut cross_tier_fallbacks: Vec<(String, String, String)> = Vec::new();
    let preferred_mirror = root.source_mirror.as_deref();

    for dep in &root.depends {
        if !dep_already_present(dep, &installed_set) && !visited.contains(dep) && dep != &root.name
        {
            queue.push_back(dep.clone());
            visited.insert(dep.clone());
        }
    }

    while !queue.is_empty() {
        let wave: Vec<String> = queue.drain(..).collect();
        let wave_results = futures_util::future::join_all(wave.iter().map(|dep_name| {
            super::resolver::resolve_preferring(dep_name, client, config, mm, preferred_mirror)
        }))
        .await;

        for (dep_name, result) in wave.into_iter().zip(wave_results) {
            if resolved.contains_key(&dep_name) {
                continue;
            }

            match result {
                Ok(super::resolver::ResolvedWithAffinity {
                    info,
                    fell_back_from,
                }) => {
                    if let Some(preferred) = fell_back_from {
                        if let Some(actual) = &info.source_mirror {
                            cross_tier_fallbacks.push((
                                info.name.clone(),
                                preferred,
                                actual.clone(),
                            ));
                        }
                    }

                    if let Some(reason) = check_version_constraint(&dep_name, &info.version) {
                        version_conflicts.push((info.name.clone(), reason));
                    }

                    if resolved.values().any(|r: &PackageInfo| r.name == info.name) {
                        continue;
                    }
                    let sub_deps = info.depends.clone();
                    resolved.insert(dep_name.clone(), info);

                    for sub_dep in sub_deps {
                        if !dep_already_present(&sub_dep, &installed_set)
                            && !visited.contains(&sub_dep)
                            && &sub_dep != &root.name
                        {
                            queue.push_back(sub_dep.clone());
                            visited.insert(sub_dep.clone());
                        }
                    }
                }
                Err(super::resolver::ResolveError::NotFound(_)) => {
                    unresolvable.push(dep_name);
                }
                Err(e) => {
                    log::warn!("dependency '{}' hit infra error: {}", dep_name, e);
                    unresolvable.push(dep_name);
                }
            }
        }
    }

    let sorted = topological_sort(&resolved, &installed_set);

    let total_size: u64 = sorted.iter().map(|p| p.size).sum();
    let already_installed: Vec<String> = root
        .depends
        .iter()
        .filter(|d| dep_already_present(d, &installed_set))
        .cloned()
        .collect();
    let syshub_provided: Vec<(String, String)> = root
        .depends
        .iter()
        .filter_map(|d| syshub_provider(d, &installed_set).map(|provider| (d.clone(), provider)))
        .collect();

    for dep_token in &already_installed {
        let base = super::apk::strip_constraint(dep_token);
        if let Some(rec) = super::registry::lookup(base) {
            if let Some(reason) = check_version_constraint(dep_token, &rec.version) {
                version_conflicts.push((rec.name.clone(), reason));
            }
        }
    }

    let mut candidates: Vec<&PackageInfo> = vec![root];
    candidates.extend(sorted.iter());
    let conflicts = check_conflicts(&candidates);

    Ok(DepPlan {
        packages: sorted,
        already_installed,
        syshub_provided,
        unresolvable,
        total_size,
        conflicts,
        version_conflicts,
        cross_tier_fallbacks,
    })
}

/// Get the set of packages already installed BY ZEX.
///
/// Only packages that Zex itself installed (tracked in the TOML registry)
/// are considered "installed" for dependency resolution purposes.
async fn get_installed_packages() -> HashSet<String> {
    super::registry::get_installed_set()
}

/// Sort resolved packages so that dependencies are installed before dependants.
fn topological_sort(
    resolved: &HashMap<String, PackageInfo>,
    installed: &HashSet<String>,
) -> Vec<PackageInfo> {
    let names: HashSet<&String> = resolved.keys().collect();

    let key_by_name: HashMap<String, &String> = resolved
        .iter()
        .map(|(key, info)| (info.name.to_ascii_lowercase(), key))
        .collect();

    let mut in_degree: HashMap<&String, usize> = HashMap::new();
    let mut adj: HashMap<&String, Vec<&String>> = HashMap::new();

    for name in &names {
        in_degree.entry(name).or_insert(0);
        adj.entry(name).or_insert_with(Vec::new);
    }

    for (name, info) in resolved {
        for dep in &info.depends {
            if dep_already_present(dep, installed) {
                continue;
            }
            let base = super::apk::strip_constraint(dep).to_ascii_lowercase();
            if let Some(&dep_key) = key_by_name.get(&base) {
                if dep_key != name {
                    adj.entry(dep_key).or_insert_with(Vec::new).push(name);
                    *in_degree.entry(name).or_insert(0) += 1;
                }
            }
        }
    }

    let mut queue: VecDeque<&String> = VecDeque::new();
    for (name, degree) in &in_degree {
        if *degree == 0 {
            queue.push_back(name);
        }
    }

    let mut sorted: Vec<PackageInfo> = Vec::new();
    let mut visited_count = 0;

    while let Some(name) = queue.pop_front() {
        if let Some(info) = resolved.get(name) {
            sorted.push(info.clone());
        }
        visited_count += 1;

        if let Some(dependants) = adj.get(name) {
            for dep in dependants {
                if let Some(d) = in_degree.get_mut(dep) {
                    *d -= 1;
                    if *d == 0 {
                        queue.push_back(dep);
                    }
                }
            }
        }
    }

    if visited_count < names.len() {
        for (name, info) in resolved {
            if !sorted.iter().any(|p| p.name == *name) {
                sorted.push(info.clone());
            }
        }
    }

    sorted
}
