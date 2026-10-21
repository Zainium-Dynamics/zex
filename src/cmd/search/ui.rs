//! ui.rs — Terminal UI for the search driver.
//! Same palette as install/upgrade/remove drivers.

use super::models::SearchResult;

pub const G: &str = "\x1b[92m";
pub const P: &str = "\x1b[95m";
pub const B: &str = "\x1b[96m";
pub const Y: &str = "\x1b[93m";
pub const R: &str = "\x1b[91m";
pub const DIM: &str = "\x1b[2m";
pub const RST: &str = "\x1b[0m";

const INST_BADGE: &str = "\x1b[92m[installed]\x1b[0m";

pub fn print_searching() {
    println!("\n {G}Searching repositories...{RST}\n");
}

pub fn print_results_header(query: &str) {
    println!(" {G}Results for:{RST} {P}{query}{RST}\n");
}

pub fn print_result_row(r: &SearchResult) {
    let origin_col = r.origin.color();
    let origin_lbl = r.origin.label();

    // Column widths matching spec:
    //   name 22, version 14, origin 16, [installed]/blank 14, description
    let installed = if r.installed { INST_BADGE } else { "" };
    let installed_pad = if r.installed { "" } else { "              " }; // 14 spaces

    println!(
        "  {DIM}•{RST} {P}{name:<22}{RST} {B}{ver:<14}{RST} {origin_col}{orig:<16}{RST} \
         {installed}{installed_pad}{DIM}{desc}{RST}",
        name = r.name,
        ver = r.version,
        orig = origin_lbl,
        desc = r.description,
    );
}

pub fn print_found_count(n: usize) {
    println!(
        "\n{G}Found {n} result{}{RST}\n",
        if n == 1 { "" } else { "s" }
    );
}

pub fn print_not_found(query: &str, suggestions: &[String]) {
    println!("\n{R}No results found for{RST} {P}'{query}'{RST}\n");
    if !suggestions.is_empty() {
        println!("{G}Similar suggestions:{RST}");
        for s in suggestions {
            println!("  {DIM}•{RST} {P}{s}{RST}");
        }
        println!(
            "\n{DIM}Try searching with:{RST} {P}zex search {sug}{RST}\n",
            sug = suggestions.first().map(String::as_str).unwrap_or(query)
        );
    }
}

pub fn print_error(msg: &str) {
    println!("\n {R}Error:{RST} {msg}\n");
}
