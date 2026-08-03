//! Local visualizer web server.
//!
//! `--visualize` no longer writes a static HTML file. Instead it starts a small
//! [`axum`] server, bound **strictly to `127.0.0.1`**, that serves the frontend
//! (embedded at compile time with [`rust_embed`]) and exposes the analysis result
//! as JSON at `GET /api/schema`. The frontend fetches that endpoint on load. The
//! server runs in the foreground and stays alive until the user presses Ctrl+C.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    extract::{Path as AxumPath, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use colored::Colorize;
use rust_embed::RustEmbed;
use tokio::net::TcpListener;

use crate::config::PatternConfig;
use crate::report_visual::build_payload;
use crate::types::{Finding, GqlSchema, ReportMeta, SchemaStats};

/// The frontend assets (index.html, app.js, app.css, vendor/*.js), embedded into
/// the binary so the server is fully self-contained and needs no filesystem.
#[derive(RustEmbed)]
#[folder = "src/webui/"]
struct WebAsset;

/// Preferred port. On collision we scan a small range and finally fall back to an
/// OS-assigned ephemeral port, so two concurrent visualizers never clash.
const DEFAULT_PORT: u16 = 7878;
const PORT_SCAN: u16 = 16;

#[derive(Clone)]
struct AppState {
    /// The `/api/schema` body (current run), serialized once at startup and shared with every
    /// request handler.
    payload: Arc<String>,
    /// Path to `introspectre.db`, so the target switcher can reconstruct other cached targets.
    db_path: PathBuf,
    /// Detection patterns, needed to re-run passive analysis when switching targets.
    patterns: PatternConfig,
    /// The current run's endpoint URL, so `/api/targets` can flag which one is live.
    current_url: String,
}

/// Build the payload, bind a local listener, open the browser, and serve until
/// Ctrl+C. Returns once the server has shut down gracefully.
pub async fn serve_visualizer(
    schema: &GqlSchema,
    findings: &[Finding],
    meta: &ReportMeta,
    stats: &SchemaStats,
    seeds: &[crate::traffic::TrafficSeed],
    port: Option<u16>,
    db_path: PathBuf,
    patterns: PatternConfig,
) -> Result<(), String> {
    let payload = build_payload(schema, findings, meta, stats, seeds);
    let payload_str = serde_json::to_string(&payload).map_err(|e| e.to_string())?;
    let state = AppState {
        payload: Arc::new(payload_str),
        db_path,
        patterns,
        current_url: meta.source.clone(),
    };

    let listener = bind_listener(port).await?;
    let bound_port = listener
        .local_addr()
        .map_err(|e| format!("could not read the bound address: {}", e))?
        .port();
    let url = format!("http://127.0.0.1:{}/", bound_port);

    let app = Router::new()
        .route("/", get(index_handler))
        .route("/api/schema", get(schema_handler))
        .route("/api/targets", get(targets_handler))
        .route("/api/targets/:id/schema", get(target_schema_handler))
        .route("/assets/*path", get(asset_handler))
        .with_state(state);

    eprintln!();
    eprintln!(
        "  {} {}",
        "▶ Visualizer serving at".green().bold(),
        url.bright_white().underline()
    );
    eprintln!(
        "    {}",
        "Bound to 127.0.0.1 (local only). Press Ctrl+C to stop.".dimmed()
    );

    open_browser(&url);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| format!("server error: {}", e))?;

    eprintln!("  {}", "Visualizer stopped.".dimmed());
    Ok(())
}

/// Bind a TCP listener on `127.0.0.1` only. An explicit `--port` is honored (and
/// its failure is fatal); otherwise try [`DEFAULT_PORT`], then the next
/// [`PORT_SCAN`] ports, then an ephemeral port.
async fn bind_listener(port: Option<u16>) -> Result<TcpListener, String> {
    let host = Ipv4Addr::LOCALHOST;

    if let Some(p) = port {
        return TcpListener::bind(SocketAddr::from((host, p)))
            .await
            .map_err(|e| format!("could not bind 127.0.0.1:{}: {}", p, e));
    }

    for p in DEFAULT_PORT..DEFAULT_PORT.saturating_add(PORT_SCAN) {
        if let Ok(listener) = TcpListener::bind(SocketAddr::from((host, p))).await {
            if p != DEFAULT_PORT {
                eprintln!(
                    "  {} port {} was busy; using {}.",
                    "•".dimmed(),
                    DEFAULT_PORT,
                    p
                );
            }
            return Ok(listener);
        }
    }

    TcpListener::bind(SocketAddr::from((host, 0)))
        .await
        .map_err(|e| format!("could not bind an ephemeral 127.0.0.1 port: {}", e))
}

async fn index_handler() -> Response {
    serve_embedded("index.html")
}

async fn schema_handler(State(state): State<AppState>) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        (*state.payload).clone(),
    )
        .into_response()
}

async fn asset_handler(AxumPath(path): AxumPath<String>) -> Response {
    serve_embedded(&path)
}

/// `GET /api/targets` — list every target with a cached scan in `introspectre.db`, flagging the
/// one currently being served. The DB read is quick but blocking, so it runs on a blocking thread.
async fn targets_handler(State(state): State<AppState>) -> Response {
    let db_path = state.db_path.clone();
    let current = state.current_url.clone();
    let rows = tokio::task::spawn_blocking(move || {
        crate::db::ProjectDatabase::new(&db_path)
            .and_then(|db| db.list_projects_with_scans())
            .unwrap_or_default()
    })
    .await
    .unwrap_or_default();

    let targets: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|(id, name, url, ts)| {
            serde_json::json!({
                "id": id,
                "name": name,
                "url": url,
                "scannedAt": ts,
                "current": url == current,
            })
        })
        .collect();
    Json(targets).into_response()
}

/// `GET /api/targets/:id/schema` — reconstruct a cached target's full visualization payload from
/// its stored schema (re-running passive analysis), without any network request or re-scan.
async fn target_schema_handler(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<i64>,
) -> Response {
    let db_path = state.db_path.clone();
    let patterns = state.patterns.clone();
    let result = tokio::task::spawn_blocking(move || reconstruct_target(&db_path, &patterns, id))
        .await
        .ok()
        .flatten();

    match result {
        Some(body) => (
            [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
            body,
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "unknown or unreadable target").into_response(),
    }
}

/// Rebuild a target's `/api/schema` payload from the cached scan: parse the stored schema, re-run
/// passive analysis + heuristic scoring, replay the cached fingerprint and learned seeds, and emit
/// the same JSON shape the live target produces. Returns `None` on any missing/parse failure.
fn reconstruct_target(db_path: &PathBuf, patterns: &PatternConfig, id: i64) -> Option<String> {
    let db = crate::db::ProjectDatabase::new(db_path).ok()?;
    let (_name, url) = db.get_project(id).ok()??;
    let (schema_json, _ts, fp_json) = db.get_latest_scan(id).ok()??;
    let schema: GqlSchema = serde_json::from_str(&schema_json).ok()?;

    let (mut findings, stats) = crate::analysis::analyze(&schema, patterns, None);
    let server_fingerprint = fp_json
        .and_then(|j| serde_json::from_str::<crate::fingerprint::ServerFingerprint>(&j).ok());
    let meta = ReportMeta {
        source: url,
        offline: true,
        static_only: true,
        reconstructed: false,
        auth_discovery_performed: false,
        auth_discovery: None,
        server_fingerprint,
    };
    crate::analysis::scoring::apply_heuristics(&mut findings, &meta);
    let seeds = db.get_seeds(id).unwrap_or_default();

    let payload = build_payload(&schema, &findings, &meta, &stats, &seeds);
    serde_json::to_string(&payload).ok()
}

/// Look up an embedded asset by its path (relative to `src/webui/`) and return it
/// with an appropriate content type, or 404 if absent.
fn serve_embedded(path: &str) -> Response {
    match WebAsset::get(path) {
        Some(content) => (
            [(header::CONTENT_TYPE, mime_for(path))],
            content.data.into_owned(),
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

fn mime_for(path: &str) -> &'static str {
    if path.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if path.ends_with(".js") {
        "text/javascript; charset=utf-8"
    } else if path.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if path.ends_with(".json") {
        "application/json; charset=utf-8"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else if path.ends_with(".woff2") {
        "font/woff2"
    } else {
        "application/octet-stream"
    }
}

/// Completes when the user presses Ctrl+C, triggering axum's graceful shutdown.
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    eprintln!();
    eprintln!("  {}", "Shutting down…".dimmed());
}

/// Best-effort attempt to open the default browser at `url`. Under WSL the native
/// opener can't reach the Windows browser, so prefer `wslview`/`explorer.exe`.
/// Any failure just prints the URL for the user to open manually — never fatal.
fn open_browser(url: &str) {
    if is_wsl() {
        if std::process::Command::new("wslview").arg(url).spawn().is_ok() {
            return;
        }
        if std::process::Command::new("explorer.exe").arg(url).spawn().is_ok() {
            return;
        }
        print_manual(url);
        return;
    }

    if open::that(url).is_err() {
        print_manual(url);
    }
}

fn print_manual(url: &str) {
    eprintln!("    {} {}", "Open manually:".yellow(), url.bright_white());
}

fn is_wsl() -> bool {
    std::fs::read_to_string("/proc/version")
        .map(|v| {
            let v = v.to_lowercase();
            v.contains("microsoft") || v.contains("wsl")
        })
        .unwrap_or(false)
}
