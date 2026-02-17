//! Sentinel WASM sidecar — Unix socket listener.
//!
//! Accepts JSON requests over a Unix domain socket, dispatches to the
//! Wasmtime sandbox engine for isolated WASM execution, and returns
//! JSON responses with leak detection and fuel metering.

mod capabilities;
mod config;
mod host_functions;
mod http_client;
mod leak_detector;
mod protocol;
mod registry;
mod sandbox;

use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::Mutex;

use config::SidecarConfig;
use leak_detector::LeakDetector;
use protocol::{Request, Response};
use registry::ToolRegistry;
use sandbox::SandboxEngine;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let socket_path = std::env::var("SENTINEL_SIDECAR_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp/sentinel-sidecar.sock"));

    // Load configuration
    let config = SidecarConfig::from_env();

    // Build leak detector (Aho-Corasick automaton compiled once at startup)
    let leak_detector = Arc::new(Mutex::new(LeakDetector::new()));

    // Load tool registry from tool directory
    let registry = Arc::new(
        ToolRegistry::load(&config.tool_dir)
            .unwrap_or_else(|e| {
                eprintln!("sidecar: warning: failed to load registry: {e}");
                ToolRegistry::new()
            })
    );
    eprintln!("sidecar: {} tool(s) registered", registry.len());

    // Create sandbox engine
    let engine = Arc::new(
        SandboxEngine::new(&config)
            .expect("failed to create sandbox engine")
    );

    // Remove stale socket file if it exists
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }

    let listener = UnixListener::bind(&socket_path)?;
    eprintln!("sidecar: listening on {}", socket_path.display());

    // Graceful shutdown on SIGTERM
    let socket_path_cleanup = socket_path.clone();
    tokio::spawn(async move {
        if let Ok(()) = tokio::signal::ctrl_c().await {
            eprintln!("sidecar: shutting down");
            let _ = std::fs::remove_file(&socket_path_cleanup);
            std::process::exit(0);
        }
    });

    loop {
        let (stream, _addr) = listener.accept().await?;
        let engine = engine.clone();
        let registry = registry.clone();
        let leak_detector = leak_detector.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, &engine, &registry, &leak_detector).await {
                eprintln!("sidecar: connection error: {e}");
            }
        });
    }
}

/// Handle a single client connection — read newline-delimited JSON requests,
/// process each one via the sandbox engine, and write back JSON responses.
async fn handle_connection(
    stream: tokio::net::UnixStream,
    engine: &SandboxEngine,
    registry: &ToolRegistry,
    leak_detector: &Mutex<LeakDetector>,
) -> std::io::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(req) => {
                let mut detector = leak_detector.lock().await;
                engine.execute(&req, registry, &mut detector).await
            }
            Err(e) => Response::error(format!("invalid request: {e}")),
        };

        let mut out = serde_json::to_string(&response).unwrap_or_default();
        out.push('\n');
        writer.write_all(out.as_bytes()).await?;
    }

    Ok(())
}
