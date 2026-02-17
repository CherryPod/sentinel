//! Shared guest-side helpers for Sentinel WASM tools.
//!
//! Provides the IO_BUFFER for host function communication, the host_call
//! import, and a safe `call_host()` wrapper that handles JSON serialization.

use std::cell::UnsafeCell;
use serde::{Deserialize, Serialize};

/// 1 MiB shared buffer for host function I/O.
/// Guest writes request JSON here, calls host_call, then reads response JSON back.
const IO_BUFFER_SIZE: usize = 1024 * 1024;

/// Wrapper to avoid `static mut` deprecation warnings.
/// Safety: WASM is single-threaded, so UnsafeCell is fine here.
#[repr(transparent)]
struct IoBuffer(UnsafeCell<[u8; IO_BUFFER_SIZE]>);
unsafe impl Sync for IoBuffer {}

static IO_BUFFER: IoBuffer = IoBuffer(UnsafeCell::new([0u8; IO_BUFFER_SIZE]));

/// Exported function for the host to locate the IO buffer in guest memory.
#[no_mangle]
pub extern "C" fn get_io_buffer() -> *mut u8 {
    IO_BUFFER.0.get() as *mut u8
}

// Import from the "sentinel" host namespace.
// `op` is the operation code, `len` is the request JSON length in IO_BUFFER.
// Returns response length (positive) or error code (negative).
extern "C" {
    #[link_name = "host_call"]
    fn _host_call(op: i32, len: i32) -> i32;
}

/// Operation codes for host function dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Op {
    ReadFile = 1,
    WriteFile = 2,
    ShellExec = 3,
    HttpFetch = 4,
    GetCredential = 5,
}

/// Error returned by host function calls.
#[derive(Debug)]
pub enum HostError {
    /// Request too large for IO_BUFFER.
    RequestTooLarge(usize),
    /// Host returned a negative error code.
    HostError(i32),
    /// Failed to serialize request JSON.
    SerializeError(String),
    /// Failed to deserialize response JSON.
    DeserializeError(String),
}

impl std::fmt::Display for HostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RequestTooLarge(size) => {
                write!(f, "request too large: {size} bytes (max {IO_BUFFER_SIZE})")
            }
            Self::HostError(code) => write!(f, "host error code: {code}"),
            Self::SerializeError(e) => write!(f, "serialize error: {e}"),
            Self::DeserializeError(e) => write!(f, "deserialize error: {e}"),
        }
    }
}

impl std::error::Error for HostError {}

/// Safe wrapper around the host_call import.
///
/// Serializes `request` as JSON into IO_BUFFER, calls the host with the
/// given operation code, then deserializes the JSON response from IO_BUFFER.
pub fn call_host(op: Op, request: &serde_json::Value) -> Result<serde_json::Value, HostError> {
    let req_bytes =
        serde_json::to_vec(request).map_err(|e| HostError::SerializeError(e.to_string()))?;

    if req_bytes.len() > IO_BUFFER_SIZE {
        return Err(HostError::RequestTooLarge(req_bytes.len()));
    }

    // Write request to the shared buffer and call host
    let buf_ptr = IO_BUFFER.0.get() as *mut u8;
    let resp_len = unsafe {
        std::ptr::copy_nonoverlapping(req_bytes.as_ptr(), buf_ptr, req_bytes.len());
        _host_call(op as i32, req_bytes.len() as i32)
    };

    if resp_len < 0 {
        return Err(HostError::HostError(resp_len));
    }

    // Read response from the shared buffer
    let resp_bytes = unsafe {
        std::slice::from_raw_parts(buf_ptr as *const u8, resp_len as usize)
    };
    serde_json::from_slice(resp_bytes).map_err(|e| HostError::DeserializeError(e.to_string()))
}

/// Read stdin fully into a string (for reading tool arguments).
pub fn read_stdin() -> Result<String, std::io::Error> {
    use std::io::Read;
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    Ok(buf)
}

/// Convenience: parse stdin as a JSON value of type T.
pub fn parse_args<T: for<'de> Deserialize<'de>>() -> Result<T, String> {
    let input = read_stdin().map_err(|e| format!("failed to read stdin: {e}"))?;
    serde_json::from_str(&input).map_err(|e| format!("failed to parse args: {e}"))
}

/// Convenience: write a JSON result to stdout.
pub fn write_result<T: Serialize>(result: &T) -> Result<(), String> {
    let json = serde_json::to_string(result).map_err(|e| format!("failed to serialize result: {e}"))?;
    print!("{json}");
    Ok(())
}
