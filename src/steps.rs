//! Step lines that follow the real work: a step shows as running (spinner) while its

use std::sync::Mutex;
use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};

struct Running {
    pb: ProgressBar,
    done: String,
    failed: String,
}

static RUNNING: Mutex<Option<Running>> = Mutex::new(None);

/// Ends the running step as done, then shows `running` until the next step, `finish` or `fail`.
pub fn start(running: String, done: String, failed: String) {
    finish();
    let pb = ProgressBar::new_spinner();
    let template = format!(
        "{}{{spinner}}",
        running.replace('{', "{{").replace('}', "}}")
    );
    pb.set_style(
        ProgressStyle::with_template(&template)
            .unwrap_or_else(|_| ProgressStyle::default_spinner())
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", " "]),
    );
    pb.enable_steady_tick(Duration::from_millis(80));
    *RUNNING.lock().unwrap_or_else(|e| e.into_inner()) = Some(Running { pb, done, failed });
}

/// Prints the running step as done.
pub fn finish() {
    end(true);
}

/// Prints the running step as failed.
pub fn fail() {
    end(false);
}

fn end(ok: bool) {
    let Some(r) = RUNNING.lock().unwrap_or_else(|e| e.into_inner()).take() else {
        return;
    };
    r.pb.finish_and_clear();
    println!("{}", if ok { r.done } else { r.failed });
}

/// Ends the running step when dropped: done after `ok()`, failed on an early return.
pub struct Guard {
    ok: bool,
}

impl Guard {
    pub fn new() -> Self {
        Guard { ok: false }
    }

    pub fn ok(mut self) {
        self.ok = true;
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        end(self.ok);
    }
}

const G: &str = "\x1b[92m";
const R: &str = "\x1b[91m";
const DIM: &str = "\x1b[2m";
const RST: &str = "\x1b[0m";

/// Starts a step in zex's usual layout: "  {head} ......... [██████] {word}".
/// `head` is the coloured label as the command prints it, `dots` the filler length.
pub fn start_bar(head: &str, dots: usize, bar_w: usize, word: &str) {
    let dots = ".".repeat(dots);
    let filled = "\u{2588}".repeat(bar_w);
    let empty = "\u{2591}".repeat(bar_w);
    start(
        format!("  {head} {DIM}{dots}{RST} {DIM}[{empty}]{RST} "),
        format!("  {head} {DIM}{dots}{RST} {G}[{filled}]{RST} {G}{word}{RST}"),
        format!("  {head} {DIM}{dots}{RST} {R}[{empty}]{RST} {R}failed{RST}"),
    );
}
