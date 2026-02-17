//! WASM tool: execute shell commands via host function.
//!
//! Reads JSON args from stdin: {"command": "..."}
//! Calls Op::ShellExec host function.
//! Writes JSON result to stdout: {"stdout": "...", "stderr": "...", "exit_code": N}

use serde::{Deserialize, Serialize};
use tool_common::{call_host, Op};

#[derive(Deserialize)]
struct Args {
    command: String,
}

#[derive(Serialize)]
struct Result {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

fn main() {
    let args: Args = match tool_common::parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("shell_exec: {e}");
            std::process::exit(1);
        }
    };

    let request = serde_json::json!({"command": args.command});

    match call_host(Op::ShellExec, &request) {
        Ok(response) => {
            let result = Result {
                stdout: response["stdout"].as_str().unwrap_or("").to_string(),
                stderr: response["stderr"].as_str().unwrap_or("").to_string(),
                exit_code: response["exit_code"].as_i64().unwrap_or(-1) as i32,
            };
            if let Err(e) = tool_common::write_result(&result) {
                eprintln!("shell_exec: {e}");
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("shell_exec: host call failed: {e}");
            std::process::exit(1);
        }
    }
}
