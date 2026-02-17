//! Wasmtime sandbox engine.
//!
//! Manages WASM execution with per-invocation isolation: fresh Store with
//! fuel metering, memory caps, epoch-based timeouts, and capability-gated
//! host functions. WASM modules execute in spawn_blocking (CPU-bound).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use wasmtime::*;
use wasmtime_wasi::WasiCtxBuilder;
use wasmtime_wasi::p2::pipe::{MemoryInputPipe, MemoryOutputPipe};

use crate::capabilities::CapabilitySet;
use crate::config::SidecarConfig;
use crate::host_functions::{self, HostState};
use crate::http_client::HttpConfig;
use crate::leak_detector::{CredentialScanner, LeakDetector};
use crate::protocol::{Request, Response};
use crate::registry::ToolRegistry;

/// The sandbox engine creates isolated WASM instances for each tool execution.
pub struct SandboxEngine {
    /// Pre-configured Wasmtime engine (shared, thread-safe).
    engine: Engine,
    /// Resource limits from config.
    config: Arc<SidecarConfig>,
    /// Shared registry of active shell child PIDs for cleanup on shutdown.
    active_children: Arc<std::sync::Mutex<HashSet<u32>>>,
}

impl SandboxEngine {
    /// Create a new sandbox engine with fuel metering and epoch interruption.
    pub fn new(config: &SidecarConfig, active_children: Arc<std::sync::Mutex<HashSet<u32>>>) -> Result<Self> {
        let mut engine_config = Config::new();
        engine_config.consume_fuel(true);
        engine_config.epoch_interruption(true);

        let engine = Engine::new(&engine_config)
            .context("failed to create Wasmtime engine")?;

        Ok(Self {
            engine,
            config: Arc::new(config.clone()),
            active_children,
        })
    }

    /// Create a sandbox engine from an existing Wasmtime engine.
    /// Use this when the engine was created externally (e.g. shared with ToolRegistry
    /// for pre-compiling WASM modules at startup).
    pub fn from_engine(engine: Engine, config: &SidecarConfig, active_children: Arc<std::sync::Mutex<HashSet<u32>>>) -> Result<Self> {
        Ok(Self {
            engine,
            config: Arc::new(config.clone()),
            active_children,
        })
    }

    /// Get a reference to the engine (needed for epoch ticker).
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Execute a tool request inside an isolated WASM sandbox.
    ///
    /// 1. Look up tool in registry, verify capabilities
    /// 2. Create fresh Store with fuel + epoch deadline
    /// 3. Load WASM module, link host functions + WASI
    /// 4. Pipe args JSON to stdin, capture stdout
    /// 5. Execute, collect result, run leak detection
    pub async fn execute(
        &self,
        request: &Request,
        registry: &ToolRegistry,
        leak_detector: &LeakDetector,
    ) -> Response {
        // Handle health check requests
        if request.tool_name == "_health" {
            return Response::success("ok".to_string());
        }

        // Look up tool in registry
        let tool_meta = match registry.lookup(&request.tool_name) {
            Some(meta) => meta,
            None => {
                return Response::error(format!("unknown tool: {}", request.tool_name));
            }
        };

        // Verify all required capabilities are granted
        let granted = CapabilitySet::from_strings(&request.capabilities);
        for required in &tool_meta.required_capabilities {
            if !granted.has(required) {
                return Response::error(format!(
                    "capability denied: tool '{}' requires '{}' but it was not granted",
                    request.tool_name,
                    required.as_str()
                ));
            }
        }

        // Build per-invocation credential scanner (U7/RACE-2: no shared mutable state)
        let cred_values: Vec<String> = request.credentials.values().cloned().collect();
        let cred_scanner = CredentialScanner::new(cred_values);

        // Use pre-compiled module from registry (compiled once at startup)
        let module = tool_meta.module.clone();
        let args_json = request.args.to_string();
        // O-005: Cap timeout to configured max to prevent epoch ticker thread
        // from running indefinitely with malicious timeout values from requests.
        let timeout_ms = request.timeout_ms.unwrap_or(
            tool_meta.timeout_ms.unwrap_or(self.config.timeout_ms)
        ).min(self.config.max_timeout_ms);
        let http_allowlist = request.http_allowlist.clone()
            .or_else(|| tool_meta.http_allowlist.clone())
            .unwrap_or_default();

        let engine = self.engine.clone();
        let config = self.config.clone();
        let capabilities = CapabilitySet::from_strings(&request.capabilities);
        let credentials = request.credentials.clone();
        let max_fuel = config.max_fuel;
        let active_children = self.active_children.clone();

        // Run WASM execution in a blocking task (WASM is synchronous/CPU-bound)
        let result = tokio::task::spawn_blocking(move || {
            execute_wasm_sync(
                &engine,
                &module,
                &args_json,
                capabilities,
                credentials,
                &config.allowed_paths,
                http_allowlist,
                &config,
                max_fuel,
                timeout_ms,
                active_children,
            )
        })
        .await;

        match result {
            Ok(Ok((stdout, fuel_consumed))) => {
                // Run leak detection on output (shared base + per-invocation creds)
                let leaked = leak_detector.has_leaks(&stdout, cred_scanner.as_ref());
                let output = if leaked {
                    leak_detector.redact(&stdout, cred_scanner.as_ref())
                } else {
                    stdout
                };

                // Parse output as JSON if possible, otherwise return as string
                let data = serde_json::from_str::<serde_json::Value>(&output).ok();
                let mut response = match &data {
                    Some(d) => Response::success_with_data("ok".to_string(), d.clone()),
                    None => Response::success(output),
                };
                response.leaked = leaked;
                response.fuel_consumed = Some(fuel_consumed);
                response
            }
            Ok(Err(e)) => Response::error(format!("execution failed: {e}")),
            Err(e) => Response::error(format!("task panic: {e}")),
        }
    }
}

/// Synchronous WASM execution — runs inside spawn_blocking.
///
/// Returns (stdout_output, fuel_consumed) on success.
fn execute_wasm_sync(
    engine: &Engine,
    module: &Module,
    args_json: &str,
    capabilities: CapabilitySet,
    credentials: HashMap<String, String>,
    allowed_paths: &[String],
    http_allowlist: Vec<String>,
    config: &SidecarConfig,
    max_fuel: u64,
    timeout_ms: u64,
    active_children: Arc<std::sync::Mutex<HashSet<u32>>>,
) -> Result<(String, u64)> {
    // Create WASI context with stdin (args) and captured stdout
    let stdin_data = args_json.as_bytes().to_vec();
    let stdout_buf = MemoryOutputPipe::new(config.stdout_max_bytes);

    let wasi_ctx = WasiCtxBuilder::new()
        .stdin(MemoryInputPipe::new(stdin_data))
        .stdout(stdout_buf.clone())
        // 64 KiB stderr buffer — intentionally small; stderr is diagnostic only
        .stderr(MemoryOutputPipe::new(64 * 1024))
        .build_p1();

    // Create host state
    let host_state = HostState {
        capabilities,
        credentials,
        allowed_paths: allowed_paths.to_vec(),
        http_allowlist,
        http_config: HttpConfig {
            timeout_ms: config.http_default_timeout_ms,
            max_response_bytes: config.http_max_response_bytes,
            allow_http: false,
            dns_timeout_s: config.dns_timeout_s,
        },
        shell_timeout_ms: config.shell_timeout_ms,
        shell_max_output_bytes: config.shell_max_output_bytes,
        active_children,
        wasi_ctx,
        // BH3-063: Enforce max_memory_bytes on WASM linear memory growth
        store_limits: StoreLimitsBuilder::new()
            .memory_size(config.max_memory_bytes as usize)
            .build(),
    };

    // Create a fresh Store with fuel budget and memory limit (BH3-063)
    let mut store = Store::new(engine, host_state);
    store.set_fuel(max_fuel).context("failed to set fuel")?;
    store.epoch_deadline_trap();
    store.set_epoch_deadline(1);

    // Enforce max_memory_bytes via StoreLimits (BH3-063: was configured but never enforced).
    // The limiter closure returns a &mut StoreLimits from HostState.
    store.limiter(|state| &mut state.store_limits);

    // Module is pre-compiled at startup — see registry.rs

    // Create linker and add WASI + host functions
    let mut linker = Linker::<HostState>::new(engine);

    // Add WASI preview 1 imports
    wasmtime_wasi::p1::add_to_linker_sync(&mut linker, |state: &mut HostState| {
        &mut state.wasi_ctx
    })
    .context("failed to add WASI imports")?;

    // Add the sentinel host_call function
    linker
        .func_wrap(
            "sentinel",
            "host_call",
            |caller: Caller<'_, HostState>, op: i32, len: i32| -> i32 {
                host_functions::host_call_dispatch(caller, op, len)
            },
        )
        .context("failed to link host_call")?;

    // Start epoch ticker thread for timeout enforcement.
    // 500ms epoch tick — fast enough for responsive timeouts, low enough overhead.
    let engine_clone = engine.clone();
    let epoch_interval_ms = 500u64;
    let total_epochs = (timeout_ms + epoch_interval_ms - 1) / epoch_interval_ms;
    let ticker = std::thread::spawn(move || {
        for _ in 0..total_epochs {
            std::thread::sleep(std::time::Duration::from_millis(epoch_interval_ms));
            engine_clone.increment_epoch();
        }
    });

    // Instantiate and run
    let instance = linker
        .instantiate(&mut store, &module)
        .context("failed to instantiate WASM module")?;

    let start = instance
        .get_typed_func::<(), ()>(&mut store, "_start")
        .context("WASM module missing _start export")?;

    let exec_result = start.call(&mut store, ());

    // O-006: Log if ticker thread panicked instead of silently ignoring
    if let Err(e) = ticker.join() {
        eprintln!("epoch ticker thread panicked: {:?}", e);
    }

    // Check execution result
    match exec_result {
        Ok(()) => {}
        Err(e) => {
            // Check if it was a fuel exhaustion or epoch interrupt
            let msg = e.to_string();
            if msg.contains("fuel") {
                bail!("fuel exhausted: tool exceeded instruction budget ({max_fuel} fuel units)");
            } else if msg.contains("epoch") {
                bail!("timeout: tool exceeded {timeout_ms}ms deadline");
            } else {
                bail!("WASM trap: {e}");
            }
        }
    }

    // Calculate fuel consumed
    let fuel_remaining = store.get_fuel().unwrap_or(0);
    let fuel_consumed = max_fuel.saturating_sub(fuel_remaining);

    // Collect stdout — binary output unsupported (JSON response requires
    // UTF-8 strings). Lossy conversion is intentional.
    let stdout_bytes = stdout_buf.contents();
    let stdout = String::from_utf8_lossy(&stdout_bytes).to_string();

    Ok((stdout, fuel_consumed))
}
