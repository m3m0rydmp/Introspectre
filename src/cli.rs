use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

use crate::transport::Transport;
use crate::types::Severity;

#[derive(Parser)]
#[command(
    name = "introspectre",
    about = "GraphQL Security Analyzer — introspection-based vulnerability scanner",
    version,
    long_about = "Analyzes GraphQL schemas (from a live endpoint or a JSON file) and reports security issues: exposed sensitive fields, missing auth directives, circular type references, large attack surfaces, deprecated fields, and more."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Purge the ENTIRE cache database (all targets, cached scans, and learned seeds)
    /// after a confirmation prompt. Global maintenance action — no subcommand needed.
    #[arg(long, default_value_t = false)]
    pub purge_db: bool,

    /// Path to TOML config file
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    /// Merge additional words from file into patterns: <type>=<path> (repeatable)
    #[arg(long, global = true, value_name = "TYPE=PATH")]
    pub wordlist: Vec<String>,

    /// Output format: text (default) or json
    #[arg(long, default_value = "text", global = true)]
    pub format: OutputFormat,

    /// Max affected entries shown per finding in text/markdown output (0 = no limit)
    #[arg(long, default_value_t = 30, global = true)]
    pub max_affected: usize,

    /// Show only findings at or above this level: low | medium | high
    #[arg(long, global = true)]
    pub min_severity: Option<Severity>,

    /// Optional bearer token used for authenticated introspection requests
    #[arg(short = 't', long, global = true)]
    pub token: Option<String>,

    /// Custom User-Agent string for all requests
    #[arg(long, global = true)]
    pub user_agent: Option<String>,

    /// Stealth mode: uses a common browser User-Agent to bypass simple filters
    #[arg(long, global = true, default_value_t = false)]
    pub stealth: bool,

    /// Reuse a browser session by sending a raw Cookie header on every request.
    /// Paste the cookies from a browser session that already passed the bot-wall
    /// challenge, e.g. --challenge-cookie "_px3=...; __cf_bm=...". Needed for
    /// endpoints behind bot-management WAFs (PerimeterX, Cloudflare, Akamai, …).
    /// For ordinary session/auth headers (`Authorization: Bearer ...`, a signed
    /// `Cookie: ...`) use `-H`/`--header "Name=Value"` instead.
    #[arg(long = "challenge-cookie", global = true, value_name = "STRING")]
    pub cookie: Option<String>,

    /// Clear this target's cached scan before running, forcing a fresh fetch.
    /// (scan/brute reuse the last cached schema by default to avoid re-requesting.)
    #[arg(long, global = true, default_value_t = false)]
    pub purge_cache: bool,

    /// Skip GraphQL server-framework fingerprinting (a few extra recon requests).
    #[arg(long, global = true, default_value_t = false)]
    pub no_fingerprint: bool,

    /// Use a local schema JSON file for auditing a live URL (when introspection is disabled)
    #[arg(long, global = true, value_name = "FILE")]
    pub use_schema: Option<PathBuf>,

    /// Serve an interactive attack-surface graph on a local web server
    /// (127.0.0.1 only). Runs in the foreground until Ctrl+C; opens your browser.
    #[arg(long, global = true, default_value_t = false)]
    pub visualize: bool,

    /// Preferred port for the --visualize server (default 7878; falls back to a
    /// free port if busy).
    #[arg(long, global = true, value_name = "PORT")]
    pub port: Option<u16>,

    /// Path to a traffic file (HAR or Burp XML) to learn valid data values from
    #[arg(long, global = true, value_name = "FILE")]
    pub seed_traffic: Option<PathBuf>,

    /// Path to a JSON file containing seed values for specific types/fields
    /// Example: { "UserID": "\"user-123\"", "Email": "\"test@example.com\"" }
    #[arg(long, global = true, value_name = "FILE")]
    pub seeds: Option<PathBuf>,

    /// Show verbose details in text output (includes PoC blocks when available)
    #[arg(long, default_value_t = false, global = true)]
    pub verbose: bool,

    /// GraphQL transport: auto (detect), post-json, get, form, graphql
    #[arg(long, global = true, default_value = "auto")]
    pub transport: Transport,

    /// Comma-separated probe ids to skip (e.g. sql-injection,ssrf)
    #[arg(long, global = true, value_delimiter = ',')]
    pub skip: Vec<String>,

    /// Comma-separated probe ids to run exclusively (overrides --skip default set)
    #[arg(long, global = true, value_delimiter = ',')]
    pub only: Vec<String>,

    /// Skip all DoS-class probes (alias amplification, batching, complexity, nested-list expansion)
    #[arg(long, global = true, default_value_t = false)]
    pub no_dos: bool,

    /// Print the probes/payloads that would run, without sending any requests
    #[arg(long, global = true, default_value_t = false)]
    pub dry_run: bool,

    /// Always exit 0, even when High/Medium findings are present. Suppresses the CI
    /// "findings gate" so interactive or chained runs aren't treated as a failed command.
    #[arg(long, global = true, default_value_t = false)]
    pub exit_zero: bool,

    /// Out-of-band collaborator domain/URL (Burp Collaborator / interactsh / `*.oast.fun`). When set,
    /// the SSRF probe fires payloads with per-target subdomain markers; a DNS/HTTP hit in your
    /// collaborator confirms blind SSRF. Example: --oob-url abc123.oast.fun
    #[arg(long, global = true, value_name = "DOMAIN")]
    pub oob_url: Option<String>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Fetch schema via live introspection query
    Scan {
        /// GraphQL endpoint URL
        url: String,

        /// Extra request headers as key=value pairs (repeatable)
        /// Example: --header "Authorization=Bearer token"
        #[arg(short = 'H', long = "header", value_name = "KEY=VALUE")]
        headers: Vec<String>,

        /// Timeout in seconds for the HTTP request
        #[arg(long, default_value_t = 15)]
        timeout: u64,

        /// Safety mode: passive analysis only, no active exploit payload probes.
        /// Defaults to true; pass `--static-only false` to enable active probing.
        #[arg(long, action = clap::ArgAction::Set, default_value_t = true)]
        static_only: bool,

        /// Client-side delay before issuing requests (milliseconds)
        #[arg(long, default_value_t = 750)]
        rate_limit_ms: u64,

        /// Automatically adjust delay/concurrency based on server response latency
        #[arg(long, default_value_t = false)]
        dynamic_throttling: bool,

        /// Discover which root fields are protected vs public using unauthenticated knock probes
        #[arg(long, action = clap::ArgAction::Set, default_value_t = true)]
        discover_auth: bool,

        /// Run a lightweight GraphQL endpoint probe before introspection
        #[arg(long, action = clap::ArgAction::Set, default_value_t = true)]
        probe_first: bool,

        /// Only run endpoint probing (no introspection or vulnerability analysis)
        #[arg(long, default_value_t = false)]
        probe_only: bool,
    },

    /// Active probing audit flow using schema-derived possibilities
    Audit {
        /// GraphQL endpoint URL
        url: String,

        /// Extra request headers as key=value pairs (repeatable)
        /// Example: --header "Authorization=Bearer token"
        #[arg(short = 'H', long = "header", value_name = "KEY=VALUE")]
        headers: Vec<String>,

        /// Timeout in seconds for each HTTP request
        #[arg(long, default_value_t = 15)]
        timeout: u64,

        /// Client-side delay before issuing requests (milliseconds)
        #[arg(long, default_value_t = 750)]
        rate_limit_ms: u64,

        /// Automatically adjust delay based on server response latency
        #[arg(long, default_value_t = false)]
        dynamic_throttling: bool,

        /// Level of query obfuscation to test WAF resilience (0-3)
        #[arg(long, default_value_t = 0)]
        evasion: u8,

        /// Enable the injection-class probes (SQL/NoSQL injection, OS command injection, SSRF, XSS)
        /// for this run, overriding config. They are off by default because they send
        /// exploit-style payloads. (Naming any of them in --only also enables them.)
        #[arg(long, default_value_t = false)]
        injection: bool,

        /// Auto-chain: on a confirmed SQL injection, attempt to extract credentials
        /// (best-effort UNION dump of a users table) and feed any recovered username/password
        /// into later probes as seeds, so auth-gated sinks can be reached without --seeds.
        /// Aggressive (exfiltrates data); implies --injection.
        #[arg(long, default_value_t = false)]
        chain: bool,

        /// Enable batching of safe probes (verbose disclosure, unauthenticated access) into single requests
        #[arg(long, default_value_t = false)]
        batch_probes: bool,

        /// Maximum number of operations per batched request (only when --batch-probes is enabled)
        #[arg(long, default_value_t = 5)]
        batch_size: u32,

        /// Custom possibility IDs for IDOR probing (comma-separated or repeatable)
        #[arg(long, value_delimiter = ',')]
        idor_payloads: Vec<String>,

        /// Restrict active probing to these types or root fields (repeatable / comma-separated).
        /// Match a whole type ("User") or a specific root field ("Query.user").
        #[arg(long, value_delimiter = ',')]
        focus: Vec<String>,

        /// Cap the number of targets each fan-out probe tests (0 = unlimited).
        /// Large schemas auto-cap to a safe default unless this is set.
        #[arg(long)]
        max_targets: Option<usize>,

        /// Global cap on the total number of active requests the fan-out probes may send
        /// (0 = unlimited). The audit stops probing once the budget is reached.
        #[arg(long)]
        max_requests: Option<usize>,
    },

    /// Brute-force schema reconstruction when introspection is fully disabled
    Brute {
        /// GraphQL endpoint URL
        url: String,

        /// Extra request headers as key=value pairs (repeatable)
        /// Example: --header "Authorization=Bearer token"
        #[arg(short = 'H', long = "header", value_name = "KEY=VALUE")]
        headers: Vec<String>,

        /// Timeout in seconds for each HTTP request
        #[arg(long, default_value_t = 15)]
        timeout: u64,

        /// Path to a custom wordlist of field names
        #[arg(short = 'w', long = "words")]
        words: Option<PathBuf>,

        /// Concurrency limit for brute-force probes
        #[arg(short = 'c', long, default_value_t = 10)]
        concurrency: usize,

        /// Automatically adjust concurrency based on server response latency
        #[arg(long, default_value_t = false)]
        dynamic_throttling: bool,

        /// Client-side delay before issuing requests (milliseconds)
        #[arg(long, default_value_t = 100)]
        rate_limit_ms: u64,
    },

    /// Analyze a schema already saved to a JSON file
    File {
        /// Path to the introspection JSON file
        path: PathBuf,
    },

    /// View or edit tool settings in config.toml
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum ConfigAction {
    /// Set a setting, e.g. `config set audit.max_type_walk_types 5000`
    Set {
        /// Dotted key path, e.g. audit.max_type_walk_types
        key: String,
        /// New value (parsed as int/bool where possible, else string)
        value: String,
    },
    /// Print a setting's current value, e.g. `config get audit.max_type_walk_types`
    Get {
        /// Dotted key path
        key: String,
    },
    /// Print the resolved config file path and its contents
    Show,
    /// Print the config file path that would be used
    Path,
}

#[derive(ValueEnum, Clone, Debug, PartialEq)]
pub enum OutputFormat {
    Text,
    Json,
    Markdown,
}
