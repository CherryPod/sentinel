//! JSON request/response types for the sidecar protocol.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A tool execution request from the Python controller.
#[derive(Debug, Deserialize)]
pub struct Request {
    /// Unique request ID for correlation.
    #[allow(dead_code)]
    pub request_id: String,
    /// Name of the tool to execute (e.g. "file_read", "shell_exec").
    pub tool_name: String,
    /// Tool arguments as a JSON object.
    pub args: serde_json::Value,
    /// Capabilities granted for this execution.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Per-request timeout override in milliseconds.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Per-execution credential map (name → value).
    #[serde(default)]
    pub credentials: HashMap<String, String>,
    /// Per-execution URL allowlist for HTTP fetch operations.
    #[serde(default)]
    pub http_allowlist: Option<Vec<String>>,
}

/// A tool execution response back to the Python controller.
#[derive(Debug, Serialize)]
pub struct Response {
    /// Whether the execution succeeded.
    pub success: bool,
    /// Result content (on success) or error message (on failure).
    pub result: String,
    /// Optional structured output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    /// Whether the leak detector found credential patterns in output.
    #[serde(default)]
    pub leaked: bool,
    /// Fuel consumed by the WASM execution (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fuel_consumed: Option<u64>,
}

impl Response {
    pub fn success(result: String) -> Self {
        Self {
            success: true,
            result,
            data: None,
            leaked: false,
            fuel_consumed: None,
        }
    }

    pub fn success_with_data(result: String, data: serde_json::Value) -> Self {
        Self {
            success: true,
            result,
            data: Some(data),
            leaked: false,
            fuel_consumed: None,
        }
    }

    pub fn error(message: String) -> Self {
        Self {
            success: false,
            result: message,
            data: None,
            leaked: false,
            fuel_consumed: None,
        }
    }
}
