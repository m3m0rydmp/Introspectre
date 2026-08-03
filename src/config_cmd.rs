//! The `config` subcommand: view and edit tool settings in `config.toml`.
//!
//! Settings live in `config.toml` (the same file the analysis loads), so this
//! command just reads/edits that file. `set` uses `toml_edit`, which preserves
//! existing formatting and comments, and creates the file (and any parent
//! tables) if they don't exist yet.

use std::path::{Path, PathBuf};

use colored::Colorize;
use toml_edit::{value, DocumentMut, Item, Table};

use crate::cli::ConfigAction;

/// Resolve which config file to operate on: an explicit `--config <path>` wins,
/// otherwise `./config.toml` in the current directory.
fn resolve_path(explicit: Option<&Path>) -> PathBuf {
    match explicit {
        Some(p) => p.to_path_buf(),
        None => PathBuf::from("config.toml"),
    }
}

/// Parse a CLI string value into the most specific TOML type: integer, boolean,
/// then fall back to a string.
fn parse_value(raw: &str) -> Item {
    if let Ok(i) = raw.parse::<i64>() {
        value(i)
    } else if let Ok(b) = raw.parse::<bool>() {
        value(b)
    } else {
        value(raw)
    }
}

pub fn run(action: &ConfigAction, explicit_config: Option<&Path>) -> i32 {
    let path = resolve_path(explicit_config);
    match action {
        ConfigAction::Path => {
            println!("{}", path.display());
            0
        }
        ConfigAction::Show => {
            match std::fs::read_to_string(&path) {
                Ok(content) => {
                    println!("  {} {}\n", "config:".bright_black(), path.display().to_string().bright_white());
                    println!("{}", content);
                    0
                }
                Err(_) => {
                    println!(
                        "  {} No config file at {} — the tool is using built-in defaults. Create one with `{}`.",
                        "!".yellow().bold(),
                        path.display(),
                        "config set <key> <value>".bright_white()
                    );
                    0
                }
            }
        }
        ConfigAction::Get { key } => {
            let content = std::fs::read_to_string(&path).unwrap_or_default();
            let doc = match content.parse::<DocumentMut>() {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("  {} Failed to parse {}: {}", "✗".red().bold(), path.display(), e);
                    return 1;
                }
            };
            match lookup(&doc, key) {
                Some(v) => {
                    println!("{}", v);
                    0
                }
                None => {
                    eprintln!("  {} `{}` is not set in {}.", "!".yellow().bold(), key, path.display());
                    1
                }
            }
        }
        ConfigAction::Set { key, value: raw } => {
            let existing = std::fs::read_to_string(&path).unwrap_or_default();
            let mut doc = match existing.parse::<DocumentMut>() {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("  {} Failed to parse {}: {}", "✗".red().bold(), path.display(), e);
                    return 1;
                }
            };
            if let Err(e) = set_key(&mut doc, key, parse_value(raw)) {
                eprintln!("  {} {}", "✗".red().bold(), e);
                return 1;
            }
            if let Err(e) = std::fs::write(&path, doc.to_string()) {
                eprintln!("  {} Failed to write {}: {}", "✗".red().bold(), path.display(), e);
                return 1;
            }
            println!(
                "  {} Set {} = {} in {}",
                "✓".green().bold(),
                key.bright_white(),
                raw.bright_white(),
                path.display()
            );
            0
        }
    }
}

/// Read the value at a dotted key path as a display string, if present.
fn lookup(doc: &DocumentMut, key: &str) -> Option<String> {
    let mut item: &Item = doc.as_item();
    for part in key.split('.') {
        item = item.as_table_like()?.get(part)?;
    }
    item.as_value().map(|v| v.to_string().trim().to_string())
}

/// Set the value at a dotted key path, creating intermediate tables as needed.
fn set_key(doc: &mut DocumentMut, key: &str, val: Item) -> Result<(), String> {
    let parts: Vec<&str> = key.split('.').filter(|p| !p.is_empty()).collect();
    if parts.is_empty() {
        return Err("empty config key".to_string());
    }
    let mut tbl: &mut Table = doc.as_table_mut();
    for part in &parts[..parts.len() - 1] {
        let entry = tbl
            .entry(part)
            .or_insert_with(|| Item::Table(Table::new()));
        tbl = entry
            .as_table_mut()
            .ok_or_else(|| format!("`{}` is not a table", part))?;
    }
    tbl[parts[parts.len() - 1]] = val;
    Ok(())
}
