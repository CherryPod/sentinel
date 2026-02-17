//! Host function dispatcher for WASM tool sandbox.
//!
//! Provides the `host_call(op, len) -> i32` import that guest WASM modules
//! call to perform privileged operations. Each operation is gated by the
//! tool's granted capabilities.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use wasmtime::{Caller, Extern};

use crate::capabilities::{Capability, CapabilitySet};
use crate::http_client::{self, HttpConfig};

/// State stored in each Wasmtime Store, accessible to host functions.
pub struct HostState {
    /// Capabilities granted for this execution.
    pub capabilities: CapabilitySet,
    /// Credentials available for this execution (name → value).
    pub credentials: HashMap<String, String>,
    /// Directories the tool is allowed to read/write.
    pub allowed_paths: Vec<String>,
    /// HTTP URL allowlist for this execution.
    pub http_allowlist: Vec<String>,
    /// HTTP client configuration.
    pub http_config: HttpConfig,
    /// Shell command timeout in milliseconds (reserved for per-command timeout).
    #[allow(dead_code)]
    pub shell_timeout_ms: u64,
    /// Shell command max output size in bytes.
    pub shell_max_output_bytes: u64,
    /// WASI context (stored here for Wasmtime lifecycle).
    pub wasi_ctx: wasmtime_wasi::p1::WasiP1Ctx,
}

/// Dispatch a host_call from the guest. Reads request JSON from the guest's
/// IO_BUFFER, executes the operation (with capability check), writes the
/// response JSON back, and returns the response length.
///
/// Returns negative on error:
///   -1 = unknown op
///   -2 = capability denied
///   -3 = operation error
///   -4 = buffer I/O error
pub fn host_call_dispatch(mut caller: Caller<'_, HostState>, op: i32, req_len: i32) -> i32 {
    // Get the IO buffer pointer from the guest's exported function
    let io_buffer_ptr = match get_io_buffer_ptr(&mut caller) {
        Ok(ptr) => ptr,
        Err(_) => return -4,
    };

    // Read request JSON from guest memory
    let request_json = match read_from_guest(&mut caller, io_buffer_ptr, req_len as usize) {
        Ok(json) => json,
        Err(_) => return -4,
    };

    let request: serde_json::Value = match serde_json::from_slice(&request_json) {
        Ok(v) => v,
        Err(_) => return -4,
    };

    // Dispatch based on operation code
    let result = match op {
        1 => handle_read_file(caller.data(), &request),
        2 => handle_write_file(caller.data(), &request),
        3 => handle_shell_exec(caller.data(), &request),
        4 => handle_http_fetch(caller.data(), &request),
        5 => handle_get_credential(caller.data(), &request),
        _ => return -1,
    };

    match result {
        Ok(response) => {
            let response_bytes = match serde_json::to_vec(&response) {
                Ok(b) => b,
                Err(_) => return -3,
            };
            // Write response back to guest IO_BUFFER
            match write_to_guest(&mut caller, io_buffer_ptr, &response_bytes) {
                Ok(()) => response_bytes.len() as i32,
                Err(_) => -4,
            }
        }
        Err(_e) => -3,
    }
}

/// Get the IO_BUFFER pointer from the guest's exported `get_io_buffer` function.
fn get_io_buffer_ptr(caller: &mut Caller<'_, HostState>) -> Result<u32> {
    let get_buf = caller
        .get_export("get_io_buffer")
        .and_then(|e| match e {
            Extern::Func(f) => Some(f),
            _ => None,
        })
        .context("guest missing get_io_buffer export")?;

    let mut results = [wasmtime::Val::I32(0)];
    get_buf
        .call(&mut *caller, &[], &mut results)
        .context("get_io_buffer call failed")?;

    match results[0] {
        wasmtime::Val::I32(ptr) => Ok(ptr as u32),
        _ => bail!("get_io_buffer returned non-i32"),
    }
}

/// Read bytes from guest linear memory at the given offset.
fn read_from_guest(caller: &mut Caller<'_, HostState>, offset: u32, len: usize) -> Result<Vec<u8>> {
    let memory = caller
        .get_export("memory")
        .and_then(|e| e.into_memory())
        .context("guest missing memory export")?;

    let data = memory.data(&*caller);
    let start = offset as usize;
    let end = start + len;
    if end > data.len() {
        bail!("read out of bounds: {end} > {}", data.len());
    }
    Ok(data[start..end].to_vec())
}

/// Write bytes to guest linear memory at the given offset.
fn write_to_guest(caller: &mut Caller<'_, HostState>, offset: u32, bytes: &[u8]) -> Result<()> {
    let memory = caller
        .get_export("memory")
        .and_then(|e| e.into_memory())
        .context("guest missing memory export")?;

    let data = memory.data_mut(&mut *caller);
    let start = offset as usize;
    let end = start + bytes.len();
    if end > data.len() {
        bail!("write out of bounds: {end} > {}", data.len());
    }
    data[start..end].copy_from_slice(bytes);
    Ok(())
}

/// Validate a path is under one of the allowed directories.
/// Rejects path traversal (../ sequences).
fn validate_path(path_str: &str, allowed_paths: &[String]) -> Result<PathBuf> {
    let path = Path::new(path_str);

    // Reject non-absolute paths
    if !path.is_absolute() {
        bail!("path must be absolute: {path_str}");
    }

    // Canonicalize to resolve symlinks and .. components.
    // For write operations the file may not exist yet, so canonicalize
    // the parent directory and append the filename.
    let canonical = if path.exists() {
        path.canonicalize()
            .with_context(|| format!("failed to canonicalize {path_str}"))?
    } else {
        let parent = path
            .parent()
            .with_context(|| format!("path has no parent: {path_str}"))?;
        if !parent.exists() {
            bail!("parent directory does not exist: {}", parent.display());
        }
        let canon_parent = parent
            .canonicalize()
            .with_context(|| format!("failed to canonicalize parent {}", parent.display()))?;
        let filename = path
            .file_name()
            .with_context(|| format!("path has no filename: {path_str}"))?;
        canon_parent.join(filename)
    };

    // Check against allowed directories
    let canonical_str = canonical.to_string_lossy();
    let allowed = allowed_paths.iter().any(|allowed| {
        canonical_str.starts_with(allowed)
    });

    if !allowed {
        bail!(
            "path '{}' (resolved: '{}') not under allowed directories: {:?}",
            path_str,
            canonical_str,
            allowed_paths
        );
    }

    Ok(canonical)
}

// ── Host function handlers ──────────────────────────────────────────────

fn handle_read_file(state: &HostState, request: &serde_json::Value) -> Result<serde_json::Value> {
    if !state.capabilities.has(&Capability::ReadFile) {
        bail!("capability denied: ReadFile");
    }

    let path_str = request["path"]
        .as_str()
        .context("missing 'path' in request")?;
    let path = validate_path(path_str, &state.allowed_paths)?;

    let content =
        std::fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let bytes = content.len();

    Ok(serde_json::json!({
        "content": content,
        "bytes": bytes,
    }))
}

fn handle_write_file(state: &HostState, request: &serde_json::Value) -> Result<serde_json::Value> {
    if !state.capabilities.has(&Capability::WriteFile) {
        bail!("capability denied: WriteFile");
    }

    let path_str = request["path"]
        .as_str()
        .context("missing 'path' in request")?;
    let content = request["content"]
        .as_str()
        .context("missing 'content' in request")?;
    let path = validate_path(path_str, &state.allowed_paths)?;

    // Create parent directories if needed
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create parent dirs for {}", path.display()))?;
    }

    std::fs::write(&path, content)
        .with_context(|| format!("failed to write {}", path.display()))?;

    Ok(serde_json::json!({
        "written": content.len(),
    }))
}

fn handle_shell_exec(state: &HostState, request: &serde_json::Value) -> Result<serde_json::Value> {
    if !state.capabilities.has(&Capability::ShellExec) {
        bail!("capability denied: ShellExec");
    }

    let command = request["command"]
        .as_str()
        .context("missing 'command' in request")?;

    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .output();

    match output {
        Ok(out) => {
            let mut stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let mut stderr = String::from_utf8_lossy(&out.stderr).to_string();

            // Truncate to max output size
            let max = state.shell_max_output_bytes as usize;
            if stdout.len() > max {
                stdout.truncate(max);
                stdout.push_str("\n[truncated]");
            }
            if stderr.len() > max {
                stderr.truncate(max);
                stderr.push_str("\n[truncated]");
            }

            Ok(serde_json::json!({
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": out.status.code().unwrap_or(-1),
            }))
        }
        Err(e) => {
            bail!("command execution failed: {e}");
        }
    }
}

fn handle_http_fetch(
    state: &HostState,
    request: &serde_json::Value,
) -> Result<serde_json::Value> {
    if !state.capabilities.has(&Capability::HttpRequest) {
        bail!("capability denied: HttpRequest");
    }

    let url = request["url"]
        .as_str()
        .context("missing 'url' in request")?;
    let method = request["method"].as_str().unwrap_or("GET");

    let headers: Vec<(String, String)> = request["headers"]
        .as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    let body = request["body"].as_str();

    let response = http_client::fetch(url, method, &headers, body, &state.http_allowlist, &state.http_config)
        .map_err(|e| anyhow::anyhow!(e))?;

    Ok(serde_json::json!({
        "status": response.status,
        "body": response.body,
        "headers": response.headers,
    }))
}

fn handle_get_credential(
    state: &HostState,
    request: &serde_json::Value,
) -> Result<serde_json::Value> {
    if !state.capabilities.has(&Capability::UseCredential) {
        bail!("capability denied: UseCredential");
    }

    let name = request["name"]
        .as_str()
        .context("missing 'name' in request")?;

    let value = state
        .credentials
        .get(name)
        .with_context(|| format!("credential '{name}' not available"))?;

    Ok(serde_json::json!({
        "name": name,
        "value": value,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_path_rejects_relative() {
        let result = validate_path("relative/path.txt", &["/workspace".into()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_path_rejects_outside_allowed() {
        let result = validate_path("/etc/shadow", &["/workspace".into()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_path_allows_workspace() {
        // Create a temp dir to test with
        let tmp = std::env::temp_dir().join("sentinel_test_validate");
        std::fs::create_dir_all(&tmp).unwrap();
        let test_file = tmp.join("test.txt");
        std::fs::write(&test_file, "test").unwrap();

        let tmp_str = tmp.to_string_lossy().to_string();
        let result = validate_path(&test_file.to_string_lossy(), &[tmp_str]);
        assert!(result.is_ok());

        std::fs::remove_dir_all(&tmp).ok();
    }
}
