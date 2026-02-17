//! Capability model for the WASM tool sandbox.
//!
//! Deny-by-default: each tool execution gets an explicit set of capabilities.
//! Host functions check capabilities before performing any privileged operation.

/// A capability that can be granted to a tool execution.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Capability {
    ReadFile,
    WriteFile,
    HttpRequest,
    UseCredential,
    InvokeTool,
    ShellExec,
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
            "shell_exec" => Some(Self::ShellExec),
            _ => None,
        }
    }

    /// Return the string name for this capability.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ReadFile => "read_file",
            Self::WriteFile => "write_file",
            Self::HttpRequest => "http_request",
            Self::UseCredential => "use_credential",
            Self::InvokeTool => "invoke_tool",
            Self::ShellExec => "shell_exec",
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

    /// Build a CapabilitySet from string names. Unknown names are silently ignored.
    pub fn from_strings(names: &[String]) -> Self {
        let mut set = Self::new();
        for name in names {
            if let Some(cap) = Capability::from_str(name) {
                set.grant(cap);
            }
        }
        set
    }

    pub fn grant(&mut self, cap: Capability) {
        self.caps.insert(cap);
    }

    pub fn has(&self, cap: &Capability) -> bool {
        self.caps.contains(cap)
    }

    /// Check that all required capabilities are granted.
    #[allow(dead_code)]
    pub fn requires_all(&self, required: &[Capability]) -> bool {
        required.iter().all(|cap| self.has(cap))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_str() {
        assert_eq!(Capability::from_str("read_file"), Some(Capability::ReadFile));
        assert_eq!(Capability::from_str("shell_exec"), Some(Capability::ShellExec));
        assert_eq!(Capability::from_str("unknown"), None);
    }

    #[test]
    fn test_from_strings() {
        let set = CapabilitySet::from_strings(&[
            "read_file".into(),
            "write_file".into(),
            "bogus".into(),
        ]);
        assert!(set.has(&Capability::ReadFile));
        assert!(set.has(&Capability::WriteFile));
        assert!(!set.has(&Capability::ShellExec));
    }

    #[test]
    fn test_requires_all() {
        let set = CapabilitySet::from_strings(&["read_file".into(), "write_file".into()]);
        assert!(set.requires_all(&[Capability::ReadFile, Capability::WriteFile]));
        assert!(!set.requires_all(&[Capability::ReadFile, Capability::ShellExec]));
    }
}
