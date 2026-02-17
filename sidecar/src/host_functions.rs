//! Host function dispatcher for WASM tool sandbox.
//!
//! Provides the `host_call(op, len) -> i32` import that guest WASM modules
//! call to perform privileged operations. Each operation is gated by the
//! tool's granted capabilities.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

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
    /// Shell command timeout in milliseconds.
    pub shell_timeout_ms: u64,
    /// Shell command max output size in bytes.
    pub shell_max_output_bytes: u64,
    /// Active shell child PIDs — shared with shutdown handler for cleanup.
    pub active_children: Arc<Mutex<HashSet<u32>>>,
    /// WASI context (stored here for Wasmtime lifecycle).
    pub wasi_ctx: wasmtime_wasi::p1::WasiP1Ctx,
    /// WASM memory limits — enforced via Store::limiter() (BH3-063).
    pub store_limits: wasmtime::StoreLimits,
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

    // O-003: Validate req_len before casting to usize — negative i32 would wrap.
    // 1 MiB cap is an intentional safety bound for IO_BUFFER — matches WASM
    // linear memory constraints and prevents guest from claiming excessive reads.
    if req_len < 0 || req_len > 1_048_576 {
        return -4;
    }

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
        1 => handle_read_file(&caller.data(), &request),
        2 => handle_write_file(&caller.data(), &request),
        3 => handle_shell_exec(&caller.data(), &request),
        4 => handle_http_fetch(&caller.data(), &request),
        5 => handle_get_credential(&caller.data(), &request),
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
                // O-004: Safe i32 conversion — prevent overflow on large responses
                Ok(()) => i32::try_from(response_bytes.len()).unwrap_or(i32::MAX),
                Err(_) => -4,
            }
        }
        Err(e) => {
            // Write error message to IO buffer so the guest can read it.
            // Return -(1000 + msg_len) to signal "operation error with message".
            let err_msg = e.to_string();
            let err_bytes = err_msg.as_bytes();
            match write_to_guest(&mut caller, io_buffer_ptr, err_bytes) {
                Ok(()) => {
                    let msg_len = err_bytes.len().min((i32::MAX as usize) - 1000);
                    -(1000 + msg_len as i32)
                }
                Err(_) => -3, // fallback if buffer write fails
            }
        }
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

    // Check against allowed directories (O-002: require path boundary after prefix)
    let canonical_str = canonical.to_string_lossy();
    let allowed = allowed_paths.iter().any(|dir| {
        // Exact match or path starts with dir + "/" separator
        // Prevents /workspace-evil from matching allowed path /workspace
        canonical_str == dir.as_str()
            || canonical_str.starts_with(&format!("{}/", dir.trim_end_matches('/')))
    });

    if !allowed {
        // O-010: Don't leak resolved path or allowed directories list in error
        // messages — these are internal implementation details.
        bail!("path '{}' is not under an allowed directory", path_str);
    }

    Ok(canonical)
}

// ── Host function handlers ──────────────────────────────────────────────

/// Maximum file size that read_file will load (1 MiB).
const MAX_READ_FILE_BYTES: u64 = 1_048_576;

fn handle_read_file(state: &HostState, request: &serde_json::Value) -> Result<serde_json::Value> {
    if !state.capabilities.has(&Capability::ReadFile) {
        bail!("capability denied: ReadFile");
    }

    let path_str = request["path"]
        .as_str()
        .context("missing 'path' in request")?;
    let path = validate_path(path_str, &state.allowed_paths)?;

    let meta = std::fs::metadata(&path)
        .with_context(|| format!("failed to stat {}", path.display()))?;
    if meta.len() > MAX_READ_FILE_BYTES {
        bail!(
            "file too large: {} bytes (max {})",
            meta.len(),
            MAX_READ_FILE_BYTES
        );
    }

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

    // BH3-064: Re-validate after create_dir_all to prevent TOCTOU symlink race.
    // An attacker could create a symlink between initial validation and write,
    // causing the write to land outside the sandbox.
    let final_path = validate_path(path_str, &state.allowed_paths)?;

    std::fs::write(&final_path, content)
        .with_context(|| format!("failed to write {}", final_path.display()))?;

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

    use std::io::Read as _;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    #[cfg(unix)]
    use std::os::unix::process::CommandExt;

    let mut cmd = Command::new("sh");
    cmd.arg("-c")
        .arg(command)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Put child in its own process group so we can kill the whole tree on timeout
    #[cfg(unix)]
    cmd.process_group(0);

    let mut child = cmd.spawn().context("failed to spawn shell")?;

    // Register child PID for cleanup on shutdown (LEAK-1)
    let child_pid = child.id();
    state.active_children.lock().unwrap_or_else(|e| e.into_inner()).insert(child_pid);

    let timeout = Duration::from_millis(state.shell_timeout_ms);

    // Read stdout/stderr in background threads to prevent pipe buffer deadlock
    // (OS pipe buffer ~64KB — if child fills it and we're not reading, both block)
    let mut stdout_pipe = child.stdout.take().context("missing stdout pipe")?;
    let mut stderr_pipe = child.stderr.take().context("missing stderr pipe")?;

    let stdout_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        stdout_pipe.read_to_end(&mut buf).ok();
        buf
    });
    let stderr_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        stderr_pipe.read_to_end(&mut buf).ok();
        buf
    });

    // Poll for process exit with timeout.
    // BH3-065: Exponential backoff (10ms → 200ms cap) instead of fixed 50ms sleep.
    // Short commands complete faster, long commands waste less CPU.
    let start = Instant::now();
    let mut poll_interval_ms = 10u64;
    let timed_out = loop {
        match child.try_wait().context("failed to check child status")? {
            Some(_) => break false,
            None if start.elapsed() >= timeout => {
                // Kill the entire process group (not just the shell) to ensure
                // child processes are also terminated and pipes close promptly
                #[cfg(unix)]
                {
                    extern "C" {
                        fn kill(pid: i32, sig: i32) -> i32;
                    }
                    let pgid = child.id() as i32;
                    unsafe {
                        kill(-pgid, 9); // SIGKILL the process group
                    }
                }
                #[cfg(not(unix))]
                {
                    let _ = child.kill();
                }
                let _ = child.wait(); // Reap zombie
                break true;
            }
            None => {
                std::thread::sleep(Duration::from_millis(poll_interval_ms));
                poll_interval_ms = (poll_interval_ms * 2).min(200);
            }
        }
    };

    // Deregister child PID — process has exited or been killed
    state.active_children.lock().unwrap_or_else(|e| e.into_inner()).remove(&child_pid);

    // Collect output from reader threads (pipes close on process exit/kill)
    let stdout_raw = stdout_thread.join().unwrap_or_default();
    let stderr_raw = stderr_thread.join().unwrap_or_default();

    let exit_code = if timed_out {
        -1
    } else {
        child.wait()?.code().unwrap_or(-1)
    };

    let mut stdout = String::from_utf8_lossy(&stdout_raw).to_string();
    let mut stderr = String::from_utf8_lossy(&stderr_raw).to_string();

    // Truncate to max output size (char-boundary safe to avoid panic on
    // multi-byte chars from from_utf8_lossy replacement U+FFFD = 3 bytes)
    let max = state.shell_max_output_bytes as usize;
    if stdout.len() > max {
        let mut trunc = max;
        while trunc > 0 && !stdout.is_char_boundary(trunc) {
            trunc -= 1;
        }
        stdout.truncate(trunc);
        stdout.push_str("\n[truncated]");
    }
    if stderr.len() > max {
        let mut trunc = max;
        while trunc > 0 && !stderr.is_char_boundary(trunc) {
            trunc -= 1;
        }
        stderr.truncate(trunc);
        stderr.push_str("\n[truncated]");
    }

    Ok(serde_json::json!({
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": exit_code,
        "timed_out": timed_out,
    }))
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

    #[test]
    fn test_validate_path_rejects_prefix_bypass() {
        // O-002: /workspace-evil must NOT match allowed path /workspace
        let tmp = std::env::temp_dir().join("sentinel_test_ws");
        let evil = std::env::temp_dir().join("sentinel_test_ws-evil");
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::create_dir_all(&evil).unwrap();
        let evil_file = evil.join("steal.txt");
        std::fs::write(&evil_file, "secret").unwrap();

        let result = validate_path(
            &evil_file.to_string_lossy(),
            &[tmp.to_string_lossy().to_string()],
        );
        assert!(result.is_err(), "prefix bypass should be rejected");

        std::fs::remove_dir_all(&tmp).ok();
        std::fs::remove_dir_all(&evil).ok();
    }

    #[test]
    fn test_read_file_rejects_oversized() {
        let tmp = std::env::temp_dir().join("sentinel_test_readlimit");
        std::fs::create_dir_all(&tmp).unwrap();
        let big_file = tmp.join("big.txt");
        // Create a file just over the 1 MiB limit
        let data = vec![b'A'; (MAX_READ_FILE_BYTES as usize) + 1];
        std::fs::write(&big_file, &data).unwrap();

        let state = HostState {
            capabilities: {
                let mut cs = CapabilitySet::new();
                cs.grant(Capability::ReadFile);
                cs
            },
            credentials: HashMap::new(),
            allowed_paths: vec![tmp.to_string_lossy().to_string()],
            http_allowlist: vec![],
            http_config: HttpConfig::default(),
            shell_timeout_ms: 5000,
            shell_max_output_bytes: 65536,
            active_children: Arc::new(Mutex::new(HashSet::new())),
            wasi_ctx: wasmtime_wasi::WasiCtxBuilder::new().build_p1(),
            store_limits: wasmtime::StoreLimitsBuilder::new().build(),
        };

        let request = serde_json::json!({ "path": big_file.to_string_lossy().to_string() });
        let result = handle_read_file(&state, &request);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("file too large"), "error was: {err_msg}");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_read_file_allows_small_file() {
        let tmp = std::env::temp_dir().join("sentinel_test_readok");
        std::fs::create_dir_all(&tmp).unwrap();
        let small_file = tmp.join("small.txt");
        std::fs::write(&small_file, "hello world").unwrap();

        let state = HostState {
            capabilities: {
                let mut cs = CapabilitySet::new();
                cs.grant(Capability::ReadFile);
                cs
            },
            credentials: HashMap::new(),
            allowed_paths: vec![tmp.to_string_lossy().to_string()],
            http_allowlist: vec![],
            http_config: HttpConfig::default(),
            shell_timeout_ms: 5000,
            shell_max_output_bytes: 65536,
            active_children: Arc::new(Mutex::new(HashSet::new())),
            wasi_ctx: wasmtime_wasi::WasiCtxBuilder::new().build_p1(),
            store_limits: wasmtime::StoreLimitsBuilder::new().build(),
        };

        let request = serde_json::json!({ "path": small_file.to_string_lossy().to_string() });
        let result = handle_read_file(&state, &request);
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response["content"], "hello world");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_shell_exec_respects_timeout() {
        let state = HostState {
            capabilities: {
                let mut cs = CapabilitySet::new();
                cs.grant(Capability::ShellExec);
                cs
            },
            credentials: HashMap::new(),
            allowed_paths: vec![],
            http_allowlist: vec![],
            http_config: HttpConfig::default(),
            shell_timeout_ms: 500, // 0.5 seconds
            shell_max_output_bytes: 65536,
            active_children: Arc::new(Mutex::new(HashSet::new())),
            wasi_ctx: wasmtime_wasi::WasiCtxBuilder::new().build_p1(),
            store_limits: wasmtime::StoreLimitsBuilder::new().build(),
        };

        let request = serde_json::json!({ "command": "sleep 30" });
        let start = std::time::Instant::now();
        let result = handle_shell_exec(&state, &request);
        let elapsed = start.elapsed();

        assert!(result.is_ok(), "timeout should return Ok with timed_out flag");
        let response = result.unwrap();
        assert_eq!(response["timed_out"], true);
        assert_eq!(response["exit_code"], -1);
        // Should complete well before the 30s sleep
        assert!(elapsed.as_secs() < 5, "elapsed: {:?}", elapsed);
    }

    #[test]
    fn test_shell_exec_normal_completion() {
        let state = HostState {
            capabilities: {
                let mut cs = CapabilitySet::new();
                cs.grant(Capability::ShellExec);
                cs
            },
            credentials: HashMap::new(),
            allowed_paths: vec![],
            http_allowlist: vec![],
            http_config: HttpConfig::default(),
            shell_timeout_ms: 5000,
            shell_max_output_bytes: 65536,
            active_children: Arc::new(Mutex::new(HashSet::new())),
            wasi_ctx: wasmtime_wasi::WasiCtxBuilder::new().build_p1(),
            store_limits: wasmtime::StoreLimitsBuilder::new().build(),
        };

        let request = serde_json::json!({ "command": "echo hello" });
        let result = handle_shell_exec(&state, &request);
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response["stdout"], "hello\n");
        assert_eq!(response["exit_code"], 0);
        assert_eq!(response["timed_out"], false);
    }
}
