//! WASM tool: read file contents via host function.
//!
//! Reads JSON args from stdin: {"path": "..."}
//! Calls Op::ReadFile host function.
//! Writes JSON result to stdout: {"content": "...", "bytes": N}

use serde::{Deserialize, Serialize};
use tool_common::{call_host, Op};

#[derive(Deserialize)]
struct Args {
    path: String,
}

#[derive(Serialize)]
struct Result {
    content: String,
    bytes: usize,
}

fn main() {
    let args: Args = match tool_common::parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("file_read: {e}");
            std::process::exit(1);
        }
    };

    let request = serde_json::json!({"path": args.path});

    match call_host(Op::ReadFile, &request) {
        Ok(response) => {
            let content = response["content"].as_str().unwrap_or("");
            let bytes = content.len();
            let result = Result {
                content: content.to_string(),
                bytes,
            };
            if let Err(e) = tool_common::write_result(&result) {
                eprintln!("file_read: {e}");
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("file_read: host call failed: {e}");
            std::process::exit(1);
        }
    }
}
