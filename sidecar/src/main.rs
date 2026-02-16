//! Sentinel WASM sidecar — Unix socket listener.
//!
//! Accepts JSON requests over a Unix domain socket, dispatches to the
//! sandbox engine, and returns JSON responses. Currently a skeleton
//! that echoes requests back — actual WASM execution comes in Phase 4.

mod capabilities;
mod config;
mod protocol;
mod registry;
mod sandbox;

use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use protocol::{Request, Response};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let socket_path = std::env::var("SENTINEL_SIDECAR_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp/sentinel-sidecar.sock"));

    // Remove stale socket file if it exists
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }

    let listener = UnixListener::bind(&socket_path)?;
    eprintln!("sidecar: listening on {}", socket_path.display());

    loop {
        let (stream, _addr) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream).await {
                eprintln!("sidecar: connection error: {e}");
            }
        });
    }
}

/// Handle a single client connection — read newline-delimited JSON requests,
/// process each one, and write back JSON responses.
async fn handle_connection(stream: tokio::net::UnixStream) -> std::io::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(req) => process_request(req),
            Err(e) => Response::error(format!("invalid request: {e}")),
        };

        let mut out = serde_json::to_string(&response).unwrap_or_default();
        out.push('\n');
        writer.write_all(out.as_bytes()).await?;
    }

    Ok(())
}

/// Process a request — currently returns a stub response.
/// Real WASM execution will be wired in Phase 4.
fn process_request(req: Request) -> Response {
    let _engine = sandbox::SandboxEngine::new(&config::SidecarConfig::default());
    let _meta = registry::ToolRegistry::new().lookup(&req.tool_name);

    Response::success(format!(
        "stub: tool={} would execute with {} arg(s)",
        req.tool_name,
        req.args.as_object().map_or(0, |m| m.len()),
    ))
}
