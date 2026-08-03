//! Two-tier verbose progress output.
//!
//! Long, looping operations (`__type`-walk, `brute`, audit probes) can run for a
//! while; under `--verbose` the user wants to see what's happening without the
//! scrollback filling with one line per request. This module separates two
//! kinds of output:
//!
//! * [`transient`] — a live, in-place status line (carriage-return, overwrites
//!   itself) for high-frequency "currently doing X" updates. It is only emitted
//!   when stderr is an interactive terminal, so piped/redirected output and
//!   `--format json`/`markdown` stay clean.
//! * [`persistent`] — a normal line the user should be able to read later in
//!   scrollback (phase changes, warnings, summaries). It first clears any
//!   pending transient line so the two don't collide.
//!
//! Everything goes to **stderr**, never stdout, so structured output on stdout
//! is never corrupted.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};

/// Tracks whether a transient line is currently on screen and needs clearing
/// before the next persistent write.
static DIRTY: AtomicBool = AtomicBool::new(false);

/// Whether in-place updates make sense (stderr is a real terminal).
fn interactive() -> bool {
    std::io::stderr().is_terminal()
}

/// Emit/refresh a transient, in-place status line on stderr. No-op when stderr
/// is not a TTY. Keep the message to a single line (no `\n`).
pub fn transient(msg: &str) {
    if !interactive() {
        return;
    }
    // `\r` returns to column 0; `\x1b[2K` erases the whole line so a shorter
    // message doesn't leave trailing characters from a longer previous one.
    eprint!("\r\x1b[2K{}", msg);
    let _ = std::io::stderr().flush();
    DIRTY.store(true, Ordering::Relaxed);
}

/// Erase the current transient line, if any. Safe to call unconditionally.
pub fn clear() {
    if interactive() && DIRTY.swap(false, Ordering::Relaxed) {
        eprint!("\r\x1b[2K");
        let _ = std::io::stderr().flush();
    }
}

/// Write a persistent line to stderr, first clearing any transient line so they
/// don't overwrite each other. Use for information worth keeping in scrollback.
pub fn persistent(msg: &str) {
    clear();
    eprintln!("{}", msg);
}
