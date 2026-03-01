//! Tool metadata registry.
//!
//! Loads tool definitions from .toml files in the tool directory. Each tool
//! specifies its WASM module path, required capabilities, and optional config.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::capabilities::Capability;

/// Metadata about a registered tool, loaded from tool.toml.
#[derive(Debug)]
pub struct ToolMeta {
    /// Tool name (e.g. "file_read").
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Path to the compiled .wasm file.
    pub wasm_path: PathBuf,
    /// Capabilities required by this tool.
    pub required_capabilities: Vec<Capability>,
    /// Per-tool timeout override in milliseconds.
    pub timeout_ms: Option<u64>,
    /// HTTP URL allowlist (for http_fetch tools).
    pub http_allowlist: Option<Vec<String>>,
}

/// TOML structure for tool.toml files.
#[derive(serde::Deserialize)]
struct ToolToml {
    name: String,
    description: String,
    wasm: String,
    capabilities: Vec<String>,
    #[serde(default)]
    timeout_ms: Option<u64>,
    #[serde(default)]
    http_allowlist: Option<Vec<String>>,
}

/// Registry of available tools and their metadata.
pub struct ToolRegistry {
    tools: HashMap<String, ToolMeta>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
        }
    }

    /// Load all tool.toml files from a directory.
    /// Each .toml file defines one tool. The WASM file path is resolved
    /// relative to the tool directory.
    pub fn load(tool_dir: &Path) -> anyhow::Result<Self> {
        let mut registry = Self::new();

        if !tool_dir.exists() {
            eprintln!("sidecar: tool directory {} does not exist, starting with empty registry", tool_dir.display());
            return Ok(registry);
        }

        let entries = std::fs::read_dir(tool_dir)
            .map_err(|e| anyhow::anyhow!("failed to read tool dir {}: {e}", tool_dir.display()))?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("toml") {
                match Self::load_tool_toml(&path, tool_dir) {
                    Ok(meta) => {
                        eprintln!("sidecar: loaded tool '{}' from {}", meta.name, path.display());
                        registry.tools.insert(meta.name.clone(), meta);
                    }
                    Err(e) => {
                        eprintln!("sidecar: failed to load {}: {e}", path.display());
                    }
                }
            }
        }

        Ok(registry)
    }

    /// Parse a single tool.toml file into ToolMeta.
    fn load_tool_toml(toml_path: &Path, tool_dir: &Path) -> anyhow::Result<ToolMeta> {
        let content = std::fs::read_to_string(toml_path)
            .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", toml_path.display()))?;

        let parsed: ToolToml = toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("failed to parse {}: {e}", toml_path.display()))?;

        let wasm_path = tool_dir.join(&parsed.wasm);

        let required_capabilities: Vec<Capability> = parsed
            .capabilities
            .iter()
            .filter_map(|s| Capability::from_str(s))
            .collect();

        Ok(ToolMeta {
            name: parsed.name,
            description: parsed.description,
            wasm_path,
            required_capabilities,
            timeout_ms: parsed.timeout_ms,
            http_allowlist: parsed.http_allowlist,
        })
    }

    /// Look up a tool by name. Returns None if not registered.
    pub fn lookup(&self, name: &str) -> Option<&ToolMeta> {
        self.tools.get(name)
    }

    /// Register a tool programmatically (used for built-in tools).
    pub fn register(&mut self, meta: ToolMeta) {
        self.tools.insert(meta.name.clone(), meta);
    }

    /// Get the number of registered tools.
    pub fn len(&self) -> usize {
        self.tools.len()
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }
}
