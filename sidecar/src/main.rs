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

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use config::SidecarConfig;
use leak_detector::LeakDetector;
use protocol::{Request, Response};
use registry::ToolRegistry;
use sandbox::SandboxEngine;

/// How long to wait for in-flight connections to finish before force-stopping.
const DRAIN_TIMEOUT_SECS: u64 = 10;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let socket_path = std::env::var("SENTINEL_SIDECAR_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp/sentinel-sidecar.sock"));

    // Load configuration
    let config = SidecarConfig::from_env();

    // Build leak detector (Aho-Corasick automaton compiled once at startup,
    // shared immutably — no Mutex needed, U7/RACE-1)
    let leak_detector = Arc::new(LeakDetector::new());

    // Create Wasmtime engine first — shared by registry (module compilation)
    // and sandbox (execution). Engine is Send + Sync.
    let mut engine_config = wasmtime::Config::new();
    engine_config.consume_fuel(true);
    engine_config.epoch_interruption(true);
    let wasm_engine = wasmtime::Engine::new(&engine_config)
        .expect("failed to create Wasmtime engine");

    // Load tool registry with pre-compiled WASM modules
    let registry = Arc::new(
        ToolRegistry::load(&config.tool_dir, &wasm_engine)
            .unwrap_or_else(|e| {
                eprintln!("sidecar: warning: failed to load registry: {e}");
                ToolRegistry::new()
            })
    );
    eprintln!("sidecar: {} tool(s) registered", registry.len());

    // Shared child PID registry for shell process cleanup on shutdown (LEAK-1)
    let active_children: Arc<std::sync::Mutex<HashSet<u32>>> =
        Arc::new(std::sync::Mutex::new(HashSet::new()));

    // Create sandbox engine, reusing the same Wasmtime engine
    let engine = Arc::new(
        SandboxEngine::from_engine(wasm_engine, &config, active_children.clone())
            .expect("failed to create sandbox engine")
    );

    // Remove stale socket file if it exists
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }

    let listener = UnixListener::bind(&socket_path)?;
    eprintln!("sidecar: listening on {}", socket_path.display());

    // Shutdown signal handler — listens for both SIGINT and SIGTERM (SHUT-1)
    let shutdown = Arc::new(tokio::sync::Notify::new());
    {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            let mut sigterm = tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::terminate(),
            )
            .expect("failed to register SIGTERM handler");

            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    eprintln!("sidecar: received SIGINT");
                }
                _ = sigterm.recv() => {
                    eprintln!("sidecar: received SIGTERM");
                }
            }
            shutdown.notify_waiters();
        });
    }

    // Accept loop with graceful shutdown and request draining (SHUT-2)
    let mut tasks = tokio::task::JoinSet::new();

    // Signal readiness to the Python supervisor. start_sidecar() waits for
    // this exact line before returning, guaranteeing the accept loop is live.
    eprintln!("READY");

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, _addr) = result?;
                let engine = engine.clone();
                let registry = registry.clone();
                let leak_detector = leak_detector.clone();

                tasks.spawn(async move {
                    if let Err(e) = handle_connection(stream, &engine, &registry, &leak_detector).await {
                        eprintln!("sidecar: connection error: {e}");
                    }
                });
            }
            _ = shutdown.notified() => {
                break;
            }
        }

        // Reap completed tasks without blocking
        while tasks.try_join_next().is_some() {}
    }

    // Drain: wait for in-flight connections to complete with timeout
    let inflight = tasks.len();
    if inflight > 0 {
        eprintln!("sidecar: draining {inflight} in-flight connection(s)");
        let drain_timeout = tokio::time::Duration::from_secs(DRAIN_TIMEOUT_SECS);
        match tokio::time::timeout(drain_timeout, async {
            while tasks.join_next().await.is_some() {}
        })
        .await
        {
            Ok(()) => eprintln!("sidecar: all connections drained"),
            Err(_) => {
                eprintln!(
                    "sidecar: drain timeout ({DRAIN_TIMEOUT_SECS}s), aborting {} remaining task(s)",
                    tasks.len()
                );
                tasks.abort_all();
            }
        }
    }

    // Kill any remaining shell child processes (LEAK-1)
    {
        let children = active_children.lock().unwrap_or_else(|e| e.into_inner());
        if !children.is_empty() {
            eprintln!(
                "sidecar: killing {} orphaned shell process(es)",
                children.len()
            );
            #[cfg(unix)]
            for &pid in children.iter() {
                // Kill the process group (same pattern as shell_exec timeout)
                unsafe {
                    extern "C" {
                        fn kill(pid: i32, sig: i32) -> i32;
                    }
                    let result = kill(-(pid as i32), 9); // SIGKILL process group
                    if result != 0 {
                        eprintln!(
                            "sidecar: failed to kill child pgid {pid} (may have already exited)"
                        );
                    }
                }
            }
        }
    }

    // Clean up socket file
    let _ = std::fs::remove_file(&socket_path);
    eprintln!("sidecar: shutdown complete");

    Ok(())
}

/// Maximum request line length (2 MiB). Rejects oversized lines to prevent OOM.
const MAX_REQUEST_LINE: usize = 2 * 1024 * 1024;

/// Handle a single client connection — read newline-delimited JSON requests,
/// process each one via the sandbox engine, and write back JSON responses.
async fn handle_connection(
    stream: tokio::net::UnixStream,
    engine: &SandboxEngine,
    registry: &ToolRegistry,
    leak_detector: &LeakDetector,
) -> std::io::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);

    loop {
        let response = match read_bounded_line(&mut buf_reader, MAX_REQUEST_LINE).await {
            Ok(None) => break, // EOF
            Ok(Some(line)) => match serde_json::from_str::<Request>(&line) {
                Ok(req) => {
                    eprintln!(
                        "sidecar: [request_id={}] executing tool={}",
                        req.request_id, req.tool_name
                    );
                    let resp = engine.execute(&req, registry, leak_detector).await;
                    eprintln!(
                        "sidecar: [request_id={}] tool={} success={}",
                        req.request_id, req.tool_name, resp.success
                    );
                    resp
                }
                Err(e) => Response::error(format!("invalid request: {e}")),
            },
            Err(_) => {
                // Line exceeds limit — send error and close connection
                let err = Response::error("request too large (max 2 MiB)".to_string());
                let mut out = serde_json::to_string(&err).unwrap_or_default();
                out.push('\n');
                writer.write_all(out.as_bytes()).await?;
                break;
            }
        };

        let mut out = serde_json::to_string(&response).unwrap_or_default();
        out.push('\n');
        writer.write_all(out.as_bytes()).await?;
    }

    Ok(())
}

/// Read a newline-terminated line, rejecting lines that exceed `max_bytes`.
/// Returns `Ok(None)` on EOF, `Ok(Some(line))` on success, `Err` on oversize.
async fn read_bounded_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max_bytes: usize,
) -> std::io::Result<Option<String>> {
    let mut buf = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return if buf.is_empty() {
                Ok(None)
            } else {
                Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
            };
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            buf.extend_from_slice(&available[..pos]);
            reader.consume(pos + 1);
            return Ok(Some(String::from_utf8_lossy(&buf).into_owned()));
        }
        let len = available.len();
        buf.extend_from_slice(available);
        reader.consume(len);
        if buf.len() > max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request line exceeds maximum length",
            ));
        }
    }
}
