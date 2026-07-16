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
    pub command: Commands,

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

    /// Use a local schema JSON file for auditing a live URL (when introspection is disabled)
    #[arg(long, global = true, value_name = "FILE")]
    pub use_schema: Option<PathBuf>,

    /// Generate an interactive actionable visualization HTML report.
    /// Optionally specify the output path (defaults to introspectre-visual.html).
    #[arg(long, global = true, value_name = "PATH", num_args = 0..=1, default_missing_value = "introspectre-visual.html")]
    pub visualize: Option<PathBuf>,

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

        /// Enable batching of safe probes (verbose disclosure, unauthenticated access) into single requests
        #[arg(long, default_value_t = false)]
        batch_probes: bool,

        /// Maximum number of operations per batched request (only when --batch-probes is enabled)
        #[arg(long, default_value_t = 5)]
        batch_size: u32,

        /// Custom possibility IDs for IDOR probing (comma-separated or repeatable)
        #[arg(long, value_delimiter = ',')]
        idor_payloads: Vec<String>,
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
}

#[derive(ValueEnum, Clone, Debug, PartialEq)]
pub enum OutputFormat {
    Text,
    Json,
    Markdown,
}
