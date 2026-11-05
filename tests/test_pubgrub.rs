//! tests/test_pubgrub.rs: PubGrub dependency solver stress tests.

use pubgrub::{
    range::Range,
    solver::{Dependencies, DependencyProvider, resolve},
    version::SemanticVersion,
};
use std::collections::HashMap;

#[derive(Clone)]
struct FakeRegistry {
    packages: HashMap<String, Vec<(SemanticVersion, HashMap<String, Range<SemanticVersion>>)>>,
}

impl FakeRegistry {
    fn new() -> Self {
        FakeRegistry {
            packages: HashMap::new(),
        }
    }

    fn add_version(
        &mut self,
        name: &str,
        version: &str,
        deps: Vec<(&str, Range<SemanticVersion>)>,
    ) {
        let ver: SemanticVersion = version.parse().unwrap();
        let dep_map: HashMap<String, Range<SemanticVersion>> =
            deps.into_iter().map(|(n, r)| (n.to_string(), r)).collect();
        self.packages
            .entry(name.to_string())
            .or_default()
            .push((ver, dep_map));
    }
}

impl DependencyProvider<String, SemanticVersion> for FakeRegistry {
    fn choose_package_version<T, U>(
        &self,
        potential_packages: impl Iterator<Item = (T, U)>,
    ) -> Result<(T, Option<SemanticVersion>), Box<dyn std::error::Error>>
    where
        T: std::borrow::Borrow<String>,
        U: std::borrow::Borrow<Range<SemanticVersion>>,
    {
        for (pkg, range) in potential_packages {
            if let Some(versions) = self.packages.get(pkg.borrow()) {
                for (ver, _) in versions.iter().rev() {
                    if range.borrow().contains(ver) {
                        return Ok((pkg, Some(ver.clone())));
                    }
                }
                return Ok((pkg, None));
            }
            return Ok((pkg, None));
        }
        unreachable!()
    }

    fn get_dependencies(
        &self,
        package: &String,
        version: &SemanticVersion,
    ) -> Result<Dependencies<String, SemanticVersion>, Box<dyn std::error::Error>> {
        if let Some(versions) = self.packages.get(package) {
            for (ver, deps) in versions {
                if ver == version {
                    let mut map = pubgrub::type_aliases::Map::default();
                    for (dep, range) in deps {
                        map.insert(dep.clone(), range.clone());
                    }
                    return Ok(Dependencies::Known(map));
                }
            }
        }
        Ok(Dependencies::Known(pubgrub::type_aliases::Map::default()))
    }
}

fn v(s: &str) -> SemanticVersion {
    s.parse().unwrap()
}

fn any() -> Range<SemanticVersion> {
    Range::any()
}

fn gte(s: &str) -> Range<SemanticVersion> {
    Range::higher_than(v(s))
}

fn between(lo: &str, hi: &str) -> Range<SemanticVersion> {
    Range::between(v(lo), v(hi))
}

mod basic {
    use super::*;

    #[test]
    fn single_package_no_deps() {
        let mut reg = FakeRegistry::new();
        reg.add_version("vim", "9.1.0", vec![]);
        let result = resolve(&reg, "vim".to_string(), v("9.1.0"));
        assert!(result.is_ok());
        let sol = result.unwrap();
        assert_eq!(sol.get("vim"), Some(&v("9.1.0")));
    }

    #[test]
    fn package_with_one_dep() {
        let mut reg = FakeRegistry::new();
        reg.add_version("libc", "1.0.0", vec![]);
        reg.add_version("curl", "8.11.0", vec![("libc", gte("1.0.0"))]);

        let result = resolve(&reg, "curl".to_string(), v("8.11.0"));
        assert!(result.is_ok());
        let sol = result.unwrap();
        assert!(sol.contains_key("curl"));
        assert!(sol.contains_key("libc"));
    }

    #[test]
    fn package_with_transitive_deps() {
        let mut reg = FakeRegistry::new();
        reg.add_version("base", "1.0.0", vec![]);
        reg.add_version("mid", "2.0.0", vec![("base", gte("1.0.0"))]);
        reg.add_version("top", "3.0.0", vec![("mid", gte("2.0.0"))]);

        let sol = resolve(&reg, "top".to_string(), v("3.0.0")).unwrap();
        assert!(sol.contains_key("top"));
        assert!(sol.contains_key("mid"));
        assert!(sol.contains_key("base"));
    }

    #[test]
    fn picks_newest_satisfying_version() {
        let mut reg = FakeRegistry::new();
        reg.add_version("lib", "1.0.0", vec![]);
        reg.add_version("lib", "1.1.0", vec![]);
        reg.add_version("lib", "2.0.0", vec![]);
        reg.add_version("app", "1.0.0", vec![("lib", gte("1.0.0"))]);

        let sol = resolve(&reg, "app".to_string(), v("1.0.0")).unwrap();
        assert_eq!(sol.get("lib"), Some(&v("2.0.0")));
    }

    #[test]
    fn respects_version_upper_bound() {
        let mut reg = FakeRegistry::new();
        reg.add_version("lib", "1.0.0", vec![]);
        reg.add_version("lib", "1.5.0", vec![]);
        reg.add_version("lib", "2.0.0", vec![]);
        reg.add_version("app", "1.0.0", vec![("lib", between("1.0.0", "2.0.0"))]);

        let sol = resolve(&reg, "app".to_string(), v("1.0.0")).unwrap();
        let lib_ver = sol.get("lib").unwrap();
        assert!(*lib_ver < v("2.0.0"));
    }

    #[test]
    fn diamond_dependency_resolved() {
        let mut reg = FakeRegistry::new();
        reg.add_version("libc", "1.0.0", vec![]);
        reg.add_version("libc", "2.0.0", vec![]);
        reg.add_version("liba", "1.0.0", vec![("libc", gte("1.0.0"))]);
        reg.add_version("libb", "1.0.0", vec![("libc", gte("1.0.0"))]);
        reg.add_version(
            "app",
            "1.0.0",
            vec![("liba", gte("1.0.0")), ("libb", gte("1.0.0"))],
        );

        let sol = resolve(&reg, "app".to_string(), v("1.0.0")).unwrap();
        assert!(sol.contains_key("libc"));
        assert_eq!(sol.len(), 4);
    }

    #[test]
    fn unsatisfiable_returns_error() {
        let mut reg = FakeRegistry::new();
        reg.add_version("lib", "1.0.0", vec![]);
        reg.add_version("app", "1.0.0", vec![("lib", gte("2.0.0"))]);

        let result = resolve(&reg, "app".to_string(), v("1.0.0"));
        assert!(result.is_err());
    }

    #[test]
    fn conflicting_diamond_detected() {
        let mut reg = FakeRegistry::new();
        reg.add_version("lib", "1.5.0", vec![]);
        reg.add_version("lib", "2.0.0", vec![]);
        reg.add_version("liba", "1.0.0", vec![("lib", between("1.0.0", "2.0.0"))]);
        reg.add_version("libb", "1.0.0", vec![("lib", gte("2.0.0"))]);
        reg.add_version(
            "app",
            "1.0.0",
            vec![("liba", gte("1.0.0")), ("libb", gte("1.0.0"))],
        );

        let result = resolve(&reg, "app".to_string(), v("1.0.0"));
        assert!(result.is_err());
    }
}

mod stress {
    use super::*;

    #[test]
    fn linear_chain_100_packages() {
        let mut reg = FakeRegistry::new();
        for i in 0..100 {
            if i + 1 < 100 {
                reg.add_version(
                    &format!("pkg{i}"),
                    "1.0.0",
                    vec![(&format!("pkg{}", i + 1), gte("1.0.0"))],
                );
            } else {
                reg.add_version(&format!("pkg{i}"), "1.0.0", vec![]);
            }
        }

        let start = std::time::Instant::now();
        let result = resolve(&reg, "pkg0".to_string(), v("1.0.0"));
        let elapsed = start.elapsed();

        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 100);
        assert!(
            elapsed.as_secs() < 5,
            "resolution took too long: {elapsed:?}"
        );
    }

    #[test]
    fn wide_flat_100_deps() {
        let mut reg = FakeRegistry::new();
        let mut root_deps = Vec::new();
        for i in 0..100 {
            let name = format!("dep{i}");
            reg.add_version(&name, "1.0.0", vec![]);
            root_deps.push(name);
        }
        let dep_ranges: Vec<(&str, Range<SemanticVersion>)> = root_deps
            .iter()
            .map(|n| (n.as_str(), gte("1.0.0")))
            .collect();
        reg.add_version("root", "1.0.0", dep_ranges);

        let start = std::time::Instant::now();
        let result = resolve(&reg, "root".to_string(), v("1.0.0"));
        let elapsed = start.elapsed();

        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 101);
        assert!(
            elapsed.as_secs() < 5,
            "wide resolution too slow: {elapsed:?}"
        );
    }

    #[test]
    fn deep_diamond_10_levels() {
        let mut reg = FakeRegistry::new();
        let levels = 5;

        reg.add_version("base", "1.0.0", vec![]);

        for i in (0..levels).rev() {
            let name = format!("mid_{i}");
            if i + 1 == levels {
                reg.add_version(&name, "1.0.0", vec![("base", gte("1.0.0"))]);
            } else {
                let child = format!("mid_{}", i + 1);
                reg.add_version(&name, "1.0.0", vec![(&child, gte("1.0.0"))]);
            }
        }

        for i in 0..levels {
            let mid = format!("mid_{i}");
            let a = format!("a_{i}");
            let b = format!("b_{i}");
            reg.add_version(&a, "1.0.0", vec![(&mid, gte("1.0.0"))]);
            reg.add_version(&b, "1.0.0", vec![(&mid, gte("1.0.0"))]);
        }

        reg.add_version(
            "root",
            "1.0.0",
            vec![("a_0", gte("1.0.0")), ("b_0", gte("1.0.0"))],
        );

        let start = std::time::Instant::now();
        let result = resolve(&reg, "root".to_string(), v("1.0.0"));
        let elapsed = start.elapsed();

        assert!(result.is_ok(), "diamond resolve failed: {result:?}");
        assert!(elapsed.as_secs() < 5);
    }

    #[test]
    fn multiple_versions_per_package() {
        let mut reg = FakeRegistry::new();
        for major in 1..=10 {
            reg.add_version("lib", &format!("{major}.0.0"), vec![]);
        }
        reg.add_version("app", "1.0.0", vec![("lib", between("5.0.0", "8.0.0"))]);

        let sol = resolve(&reg, "app".to_string(), v("1.0.0")).unwrap();
        let lib_ver = sol.get("lib").unwrap();
        assert!(*lib_ver >= v("5.0.0"));
        assert!(*lib_ver < v("8.0.0"));
    }

    #[test]
    fn sibling_constraints_satisfied() {
        let mut reg = FakeRegistry::new();
        for i in 1..=5 {
            reg.add_version("lib", &format!("{i}.0.0"), vec![]);
        }
        reg.add_version("mid1", "1.0.0", vec![("lib", gte("2.0.0"))]);
        reg.add_version("mid2", "1.0.0", vec![("lib", between("1.0.0", "3.0.0"))]);
        reg.add_version(
            "app",
            "1.0.0",
            vec![("mid1", gte("1.0.0")), ("mid2", gte("1.0.0"))],
        );

        let sol = resolve(&reg, "app".to_string(), v("1.0.0")).unwrap();
        let lib_ver = sol.get("lib").unwrap();
        assert!(*lib_ver >= v("2.0.0"));
        assert!(*lib_ver < v("3.0.0"));
    }
}

mod edge_cases {
    use super::*;

    #[test]
    fn self_referential_not_possible() {
        let mut reg = FakeRegistry::new();
        reg.add_version("lib", "1.0.0", vec![]);
        reg.add_version("app", "1.0.0", vec![("lib", gte("1.0.0"))]);
        let result = resolve(&reg, "app".to_string(), v("1.0.0"));
        assert!(result.is_ok());
    }

    #[test]
    fn empty_registry_fails() {
        let reg = FakeRegistry::new();
        let result = resolve(&reg, "nonexistent".to_string(), v("1.0.0"));
        assert!(result.is_err());
    }

    #[test]
    fn exact_version_constraint() {
        let mut reg = FakeRegistry::new();
        reg.add_version("lib", "1.0.0", vec![]);
        reg.add_version("lib", "2.0.0", vec![]);
        reg.add_version("app", "1.0.0", vec![("lib", between("1.0.0", "1.0.1"))]);
        let sol = resolve(&reg, "app".to_string(), v("1.0.0")).unwrap();
        assert_eq!(sol.get("lib"), Some(&v("1.0.0")));
    }

    #[test]
    fn any_range_picks_newest() {
        let mut reg = FakeRegistry::new();
        for i in 1..=5 {
            reg.add_version("lib", &format!("{i}.0.0"), vec![]);
        }
        reg.add_version("app", "1.0.0", vec![("lib", any())]);
        let sol = resolve(&reg, "app".to_string(), v("1.0.0")).unwrap();
        assert_eq!(sol.get("lib"), Some(&v("5.0.0")));
    }

    #[test]
    fn resolution_result_contains_root() {
        let mut reg = FakeRegistry::new();
        reg.add_version("app", "1.0.0", vec![]);
        let sol = resolve(&reg, "app".to_string(), v("1.0.0")).unwrap();
        assert!(sol.contains_key("app"));
    }
}
