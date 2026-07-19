//! aliases.rs — Command name to driver binary resolution.
//!
//! [`resolve`] maps a command name (e.g. `"install"`) to a [`Route`]
//! containing the list of candidate binary paths to try in order and any
//! internal arguments to prepend (e.g. `["syshub", "--u"]` for the
//! `"syshub"` alias of the upgrade driver).
//!
//! # Multicall dispatch
//!
//! Because `zex` is a multicall binary, not all commands go through the
//! alias table — `pin`, `unpin`, `pins`, `-i`, `-e`, `help`, and `version`
//! are handled as built-ins directly in `main.rs`. The alias table covers
//! only the 11 driver commands that exec a sub-binary or call `cmd::*::run`.

pub struct Route {
    pub binary_candidates: Vec<String>,
    pub internal_args: Vec<String>,
}

fn driver(name: &str) -> Vec<String> {
    vec![
        format!("/overlayer/syshub/drivers/system/{}", name),
        format!("/overlayer/syshub/bin/zex-{}", name),
    ]
}

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|&s| s.to_string()).collect()
}

pub fn resolve(command: &str) -> Option<Route> {
    match command {
        "install" => Some(Route {
            binary_candidates: driver("install"),
            internal_args: args(&["--install"]),
        }),
        "refresh" => Some(Route {
            binary_candidates: driver("update"),
            internal_args: args(&[]),
        }),
        "update" => Some(Route {
            binary_candidates: driver("update"),
            internal_args: args(&[]),
        }),
        "remove" => Some(Route {
            binary_candidates: driver("remove"),
            internal_args: args(&[]),
        }),
        // Upgrade has exactly two entry points — never a bare `upgrade` command.
        "syshub" => Some(Route {
            binary_candidates: driver("upgrade"),
            internal_args: args(&["syshub", "--u"]),
        }),
        "uland" => Some(Route {
            binary_candidates: driver("upgrade"),
            internal_args: args(&["uland", "--u"]),
        }),
        "search" => Some(Route {
            binary_candidates: driver("search"),
            internal_args: args(&[]),
        }),
        "sweep" => Some(Route {
            binary_candidates: driver("sweep"),
            internal_args: args(&[]),
        }),
        "rollback" => Some(Route {
            binary_candidates: driver("rollback"),
            internal_args: args(&[]),
        }),
        "doctor" => Some(Route {
            binary_candidates: driver("doctor"),
            internal_args: args(&[]),
        }),
        "depends" => Some(Route {
            binary_candidates: driver("depends"),
            internal_args: args(&[]),
        }),
        "why" => Some(Route {
            binary_candidates: driver("why"),
            internal_args: args(&[]),
        }),
        "inspect" => Some(Route {
            binary_candidates: driver("inspect"),
            internal_args: args(&[]),
        }),
        _ => None,
    }
}
