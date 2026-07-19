//! display.rs — Terminal output for zex fmt.
//! Uses the standard Zainium ANSI palette — no external crates.

const G:   &str = "\x1b[92m";   // green  — success
const P:   &str = "\x1b[95m";   // purple — package name
const B:   &str = "\x1b[96m";   // blue   — values
const Y:   &str = "\x1b[93m";   // yellow — warnings
const R:   &str = "\x1b[91m";   // red    — errors
const DIM: &str = "\x1b[2m";
const BLD: &str = "\x1b[1m";
const RST: &str = "\x1b[0m";

pub fn title(msg: &str) {
    println!("\n {BLD}{G}zex fmt{RST} {G}— {msg}{RST}");
}

pub fn step(msg: &str) {
    println!("\n {G}→{RST} {msg}");
}

pub fn kv(key: &str, value: &str) {
    println!("  {DIM}{key:<20}{RST} : {B}{value}{RST}");
}

pub fn ok_kv(key: &str, value: &str) {
    println!("  {DIM}{key:<20}{RST} : {G}✓{RST}  {value}");
}

pub fn fail_kv(key: &str, value: &str) {
    println!("  {DIM}{key:<20}{RST} : {R}✗{RST}  {value}");
}

pub fn warn_kv(key: &str, value: &str) {
    println!("  {DIM}{key:<20}{RST} : {Y}⚠{RST}  {value}");
}

pub fn success(msg: &str) {
    println!("\n {G}✓ {BLD}{msg}{RST}\n");
}

pub fn error(msg: &str) {
    eprintln!("\n {R}✗ Error:{RST} {msg}\n");
}

pub fn section(msg: &str) {
    println!("\n{G}{msg}{RST}");
}
