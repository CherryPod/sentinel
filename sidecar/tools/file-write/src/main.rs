//! WASM tool: write file contents via host function.
//!
//! Reads JSON args from stdin: {"path": "...", "content": "..."}
//! Calls Op::WriteFile host function.
//! Writes JSON result to stdout: {"written": N}

use serde::{Deserialize, Serialize};
use tool_common::{call_host, Op};

#[derive(Deserialize)]
struct Args {
    path: String,
    content: String,
}

#[derive(Serialize)]
struct Result {
    written: usize,
}

fn main() {
    let args: Args = match tool_common::parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("file_write: {e}");
            std::process::exit(1);
        }
    };

    let request = serde_json::json!({
        "path": args.path,
        "content": args.content,
    });

    match call_host(Op::WriteFile, &request) {
        Ok(response) => {
            let written = response["written"].as_u64().unwrap_or(0) as usize;
            let result = Result { written };
            if let Err(e) = tool_common::write_result(&result) {
                eprintln!("file_write: {e}");
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("file_write: host call failed: {e}");
            std::process::exit(1);
        }
    }
}
