//! JSON request/response types for the sidecar protocol.

use serde::{Deserialize, Serialize};

/// A tool execution request from the Python controller.
#[derive(Debug, Deserialize)]
pub struct Request {
    /// Unique request ID for correlation.
    pub request_id: String,
    /// Name of the tool to execute (e.g. "file_read", "shell").
    pub tool_name: String,
    /// Tool arguments as a JSON object.
    pub args: serde_json::Value,
    /// Capabilities granted for this execution.
    #[serde(default)]
    pub capabilities: Vec<String>,
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
}

impl Response {
    pub fn success(result: String) -> Self {
        Self {
            success: true,
            result,
            data: None,
        }
    }

    pub fn error(message: String) -> Self {
        Self {
            success: false,
            result: message,
            data: None,
        }
    }
}
