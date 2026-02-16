//! Capability model stub.
//!
//! Phase 4 will implement: ReadFile, WriteFile, HttpRequest, UseCredential,
//! InvokeTool — each granted per-execution and enforced by the sandbox.

/// A capability that can be granted to a tool execution.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Capability {
    ReadFile,
    WriteFile,
    HttpRequest,
    UseCredential,
    InvokeTool,
}

impl Capability {
    /// Parse a capability from its string name.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "read_file" => Some(Self::ReadFile),
            "write_file" => Some(Self::WriteFile),
            "http_request" => Some(Self::HttpRequest),
            "use_credential" => Some(Self::UseCredential),
            "invoke_tool" => Some(Self::InvokeTool),
            _ => None,
        }
    }
}

/// A set of capabilities granted for a single tool execution.
#[derive(Debug, Default)]
pub struct CapabilitySet {
    caps: std::collections::HashSet<Capability>,
}

impl CapabilitySet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn grant(&mut self, cap: Capability) {
        self.caps.insert(cap);
    }

    pub fn has(&self, cap: &Capability) -> bool {
        self.caps.contains(cap)
    }
}
