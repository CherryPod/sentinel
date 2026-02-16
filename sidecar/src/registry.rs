//! Tool metadata registry stub.
//!
//! Phase 4 will populate this with WASM module paths, required capabilities,
//! and argument schemas for each registered tool.

/// Metadata about a registered tool.
#[derive(Debug)]
pub struct ToolMeta {
    pub name: String,
    pub description: String,
    pub required_capabilities: Vec<String>,
}

/// Registry of available tools and their metadata.
pub struct ToolRegistry {
    tools: Vec<ToolMeta>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self { tools: Vec::new() }
    }

    /// Look up a tool by name. Returns None if not registered.
    pub fn lookup(&self, name: &str) -> Option<&ToolMeta> {
        self.tools.iter().find(|t| t.name == name)
    }
}
