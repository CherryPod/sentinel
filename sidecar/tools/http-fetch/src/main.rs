//! WASM tool: HTTP fetch via host function with SSRF protection.
//!
//! Reads JSON args from stdin: {"url": "...", "method": "GET", "headers": {...}, "body": "..."}
//! Optionally calls Op::GetCredential if auth_credential is specified.
//! Calls Op::HttpFetch host function.
//! Writes JSON result to stdout: {"status": N, "body": "...", "headers": {...}}

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tool_common::{call_host, Op};

#[derive(Deserialize)]
struct Args {
    url: String,
    #[serde(default = "default_method")]
    method: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    body: Option<String>,
    /// Optional credential name to inject as Authorization header.
    #[serde(default)]
    auth_credential: Option<String>,
}

fn default_method() -> String {
    "GET".to_string()
}

#[derive(Serialize)]
struct Result {
    status: u16,
    body: String,
    headers: HashMap<String, String>,
}

fn main() {
    let mut args: Args = match tool_common::parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("http_fetch: {e}");
            std::process::exit(1);
        }
    };

    // If auth_credential is specified, fetch it via host function and add to headers
    if let Some(cred_name) = &args.auth_credential {
        let cred_request = serde_json::json!({"name": cred_name});
        match call_host(Op::GetCredential, &cred_request) {
            Ok(response) => {
                if let Some(value) = response["value"].as_str() {
                    args.headers
                        .insert("Authorization".to_string(), value.to_string());
                }
            }
            Err(e) => {
                eprintln!("http_fetch: credential fetch failed: {e}");
                std::process::exit(1);
            }
        }
    }

    let request = serde_json::json!({
        "url": args.url,
        "method": args.method,
        "headers": args.headers,
        "body": args.body,
    });

    match call_host(Op::HttpFetch, &request) {
        Ok(response) => {
            let result = Result {
                status: response["status"].as_u64().unwrap_or(0) as u16,
                body: response["body"].as_str().unwrap_or("").to_string(),
                headers: response["headers"]
                    .as_object()
                    .map(|m| {
                        m.iter()
                            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                            .collect()
                    })
                    .unwrap_or_default(),
            };
            if let Err(e) = tool_common::write_result(&result) {
                eprintln!("http_fetch: {e}");
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("http_fetch: host call failed: {e}");
            std::process::exit(1);
        }
    }
}
