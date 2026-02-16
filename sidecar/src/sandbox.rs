//! Wasmtime sandbox engine stub.
//!
//! Phase 4 will add: fresh Wasmtime instance per execution, fuel metering,
//! memory caps, epoch-based timeouts, and WASI capability injection.

use crate::config::SidecarConfig;

/// The sandbox engine that will manage Wasmtime instances.
pub struct SandboxEngine {
    _max_memory_bytes: u64,
    _max_fuel: u64,
    _timeout_ms: u64,
}

impl SandboxEngine {
    pub fn new(config: &SidecarConfig) -> Self {
        Self {
            _max_memory_bytes: config.max_memory_bytes,
            _max_fuel: config.max_fuel,
            _timeout_ms: config.timeout_ms,
        }
    }
}
