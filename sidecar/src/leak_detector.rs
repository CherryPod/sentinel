//! Aho-Corasick credential pattern scanner.
//!
//! Scans tool output for leaked credentials using a pre-compiled multi-pattern
//! automaton. O(n) scan time regardless of pattern count.
//!
//! Architecture: The built-in pattern automaton is immutable after construction
//! and shared across all connections via Arc (no Mutex needed). Per-request
//! credential patterns get their own short-lived CredentialScanner, created per
//! invocation and discarded after use. This eliminates Mutex serialization
//! (U7/RACE-1) and credential cross-contamination (U7/RACE-2).

use aho_corasick::AhoCorasick;

/// A matched leak pattern with its location and name.
#[derive(Debug, Clone)]
pub struct LeakMatch {
    /// Name of the pattern that matched (e.g. "aws_access_key").
    pub pattern_name: String,
    /// Start byte offset in the scanned text.
    pub start: usize,
    /// End byte offset in the scanned text.
    pub end: usize,
}

/// Pattern definition: a name and the literal string to search for.
struct PatternDef {
    name: &'static str,
    pattern: &'static str,
}

/// Built-in leak detection patterns covering common credential formats.
/// O-008: Only detects literal patterns, not base64/hex encoded secrets.
/// Encoding detection would require decoding all output, adding latency
/// and false positives. The Python-side pipeline scans for encoded patterns.
const BUILTIN_PATTERNS: &[PatternDef] = &[
    // AWS access keys
    PatternDef { name: "aws_access_key", pattern: "AKIA" },
    PatternDef { name: "aws_temp_key", pattern: "ASIA" },
    // GitHub tokens
    PatternDef { name: "github_pat", pattern: "ghp_" },
    PatternDef { name: "github_oauth", pattern: "gho_" },
    PatternDef { name: "github_user", pattern: "ghu_" },
    PatternDef { name: "github_server", pattern: "ghs_" },
    PatternDef { name: "github_refresh", pattern: "ghr_" },
    // Slack tokens
    PatternDef { name: "slack_bot", pattern: "xoxb-" },
    PatternDef { name: "slack_user", pattern: "xoxp-" },
    PatternDef { name: "slack_app", pattern: "xoxa-" },
    PatternDef { name: "slack_refresh", pattern: "xoxr-" },
    // OpenAI (coarse first-pass; Python-side scanner handles full regex+entropy disambiguation)
    PatternDef { name: "openai_key", pattern: "sk-proj-" },
    // Stripe
    PatternDef { name: "stripe_secret", pattern: "sk_live_" },
    PatternDef { name: "stripe_public", pattern: "pk_live_" },
    // PEM private keys
    PatternDef { name: "pem_rsa", pattern: "-----BEGIN RSA PRIVATE KEY-----" },
    PatternDef { name: "pem_ec", pattern: "-----BEGIN EC PRIVATE KEY-----" },
    PatternDef { name: "pem_generic", pattern: "-----BEGIN PRIVATE KEY-----" },
    // JWT bearer tokens
    PatternDef { name: "bearer_jwt", pattern: "Bearer ey" },
    // GitLab PAT (BH3-013)
    PatternDef { name: "gitlab_pat", pattern: "glpat-" },
    // Google API key (BH3-013)
    PatternDef { name: "google_api_key", pattern: "AIza" },
    // SendGrid API key (BH3-013)
    PatternDef { name: "sendgrid_api_key", pattern: "SG." },
    // DigitalOcean PAT (BH3-013)
    PatternDef { name: "digitalocean_pat", pattern: "dop_v1_" },
    // Vercel tokens (BH3-013)
    PatternDef { name: "vercel_token_vcp", pattern: "vcp_" },
    PatternDef { name: "vercel_token_vci", pattern: "vci_" },
    PatternDef { name: "vercel_token_vca", pattern: "vca_" },
    PatternDef { name: "vercel_token_vcr", pattern: "vcr_" },
    PatternDef { name: "vercel_token_vck", pattern: "vck_" },
    // Telegram bot token prefix (BH3-013 — coarse, Python-side scanner has full regex)
    // Telegram tokens look like "123456:AA..." — prefix match not practical,
    // so we match the ":AA" segment that's always present after the bot ID.
    PatternDef { name: "telegram_bot_token", pattern: ":AA" },
    // HuggingFace token (BH3-013)
    PatternDef { name: "huggingface_token", pattern: "hf_" },
    // npm access token (BH3-013)
    PatternDef { name: "npm_access_token", pattern: "npm_" },
    // PyPI upload token (BH3-013)
    PatternDef { name: "pypi_upload_token", pattern: "pypi-AgEIcHlwaS5vcmc" },
    // HashiCorp Vault token (BH3-013)
    PatternDef { name: "hashicorp_vault_token", pattern: "hvs." },
    // age secret key (BH3-013)
    PatternDef { name: "age_secret_key", pattern: "AGE-SECRET-KEY-" },
    // Grafana service account token (BH3-013)
    PatternDef { name: "grafana_service_token", pattern: "glsa_" },
    // Discord bot token segment (BH3-013 — coarse first-pass)
    // Not a simple prefix — Python-side scanner handles full regex
    // OpenVPN static key (BH3-013)
    PatternDef { name: "openvpn_static_key", pattern: "-----BEGIN OpenVPN Static key V1-----" },
    // Generic credential assignments
    PatternDef { name: "generic_password", pattern: "password=" },
    PatternDef { name: "generic_secret", pattern: "secret=" },
    PatternDef { name: "generic_token", pattern: "token=" },
    PatternDef { name: "generic_api_key", pattern: "api_key=" },
];

/// Per-invocation credential scanner for request-specific credential values.
/// Created fresh for each execution and discarded after — no cross-request
/// contamination possible.
pub struct CredentialScanner {
    cred_automaton: AhoCorasick,
}

impl CredentialScanner {
    /// Build a credential scanner from per-request credential values.
    /// Returns None if no non-empty values are provided.
    pub fn new(values: Vec<String>) -> Option<Self> {
        let non_empty: Vec<String> = values.into_iter().filter(|v| !v.is_empty()).collect();
        if non_empty.is_empty() {
            return None;
        }
        AhoCorasick::new(&non_empty).ok().map(|ac| Self { cred_automaton: ac })
    }

    /// Check if text contains any credential values.
    pub fn has_leaks(&self, text: &str) -> bool {
        self.cred_automaton.is_match(text)
    }

    /// Find all credential matches in text.
    pub fn scan(&self, text: &str) -> Vec<LeakMatch> {
        self.cred_automaton
            .find_iter(text)
            .map(|mat| LeakMatch {
                pattern_name: "injected_credential".to_string(),
                start: mat.start(),
                end: mat.end(),
            })
            .collect()
    }
}

/// Pre-compiled leak detector using Aho-Corasick automaton.
/// O-012: The automaton is built once at sidecar startup (main.rs) and shared
/// immutably across all connections via Arc — no Mutex needed.
pub struct LeakDetector {
    automaton: AhoCorasick,
    /// Pattern names in the same order as automaton patterns.
    pattern_names: Vec<String>,
}

impl LeakDetector {
    /// Create a new leak detector with built-in patterns.
    pub fn new() -> Self {
        let patterns: Vec<&str> = BUILTIN_PATTERNS.iter().map(|p| p.pattern).collect();
        let names: Vec<String> = BUILTIN_PATTERNS.iter().map(|p| p.name.to_string()).collect();

        let automaton = AhoCorasick::new(&patterns)
            .expect("failed to build Aho-Corasick automaton");

        Self {
            automaton,
            pattern_names: names,
        }
    }

    /// Quick check: does the text contain any leak patterns?
    /// Checks both built-in patterns and optional per-request credentials.
    pub fn has_leaks(&self, text: &str, creds: Option<&CredentialScanner>) -> bool {
        if self.automaton.is_match(text) {
            return true;
        }
        if let Some(cs) = creds {
            if cs.has_leaks(text) {
                return true;
            }
        }
        false
    }

    /// Scan text and return all leak matches from both built-in patterns and
    /// optional per-request credentials.
    pub fn scan(&self, text: &str, creds: Option<&CredentialScanner>) -> Vec<LeakMatch> {
        let mut matches = Vec::new();

        // Check built-in patterns
        for mat in self.automaton.find_iter(text) {
            matches.push(LeakMatch {
                pattern_name: self.pattern_names[mat.pattern().as_usize()].clone(),
                start: mat.start(),
                end: mat.end(),
            });
        }

        // Check per-request credential values
        if let Some(cs) = creds {
            matches.extend(cs.scan(text));
        }

        matches
    }

    /// Redact all detected leaks in the text, replacing matches with
    /// `[REDACTED:pattern_name]`.
    pub fn redact(&self, text: &str, creds: Option<&CredentialScanner>) -> String {
        let mut leaks = self.scan(text, creds);
        if leaks.is_empty() {
            return text.to_string();
        }

        // Sort by start position descending so replacements don't shift offsets
        leaks.sort_by(|a, b| b.start.cmp(&a.start));

        let mut result = text.to_string();
        for leak in &leaks {
            let replacement = format!("[REDACTED:{}]", leak.pattern_name);
            result.replace_range(leak.start..leak.end, &replacement);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detects_aws_key() {
        let detector = LeakDetector::new();
        assert!(detector.has_leaks("my key is AKIAIOSFODNN7EXAMPLE", None));
        let matches = detector.scan("AKIAIOSFODNN7EXAMPLE", None);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern_name, "aws_access_key");
    }

    #[test]
    fn test_detects_github_pat() {
        let detector = LeakDetector::new();
        assert!(detector.has_leaks("token: ghp_abcdefg123456", None));
        let matches = detector.scan("ghp_test", None);
        assert_eq!(matches[0].pattern_name, "github_pat");
    }

    #[test]
    fn test_detects_slack_bot() {
        let detector = LeakDetector::new();
        assert!(detector.has_leaks("SLACK_TOKEN=xoxb-123-456", None));
    }

    #[test]
    fn test_detects_pem_header() {
        let detector = LeakDetector::new();
        assert!(detector.has_leaks("-----BEGIN RSA PRIVATE KEY-----\nMIIE...", None));
    }

    #[test]
    fn test_detects_bearer_jwt() {
        let detector = LeakDetector::new();
        assert!(detector.has_leaks("Authorization: Bearer eyJhbGciOiJ...", None));
    }

    #[test]
    fn test_detects_generic_patterns() {
        let detector = LeakDetector::new();
        assert!(detector.has_leaks("password=hunter2", None));
        assert!(detector.has_leaks("api_key=abc123", None));
    }

    #[test]
    fn test_clean_text_no_leaks() {
        let detector = LeakDetector::new();
        assert!(!detector.has_leaks("Hello, this is normal text with no secrets.", None));
    }

    #[test]
    fn test_redaction() {
        let detector = LeakDetector::new();
        let redacted = detector.redact("key is AKIAIOSFODNN7EXAMPLE here", None);
        assert!(redacted.contains("[REDACTED:aws_access_key]"));
        assert!(!redacted.contains("AKIA"));
    }

    #[test]
    fn test_credential_value_detection() {
        let detector = LeakDetector::new();
        let creds = CredentialScanner::new(vec!["my-secret-value-12345".to_string()]);
        assert!(detector.has_leaks("output contains my-secret-value-12345 here", creds.as_ref()));
        let matches = detector.scan("has my-secret-value-12345", creds.as_ref());
        assert_eq!(matches[0].pattern_name, "injected_credential");
    }

    #[test]
    fn test_credential_value_redaction() {
        let detector = LeakDetector::new();
        let creds = CredentialScanner::new(vec!["supersecret".to_string()]);
        let redacted = detector.redact("the value is supersecret!", creds.as_ref());
        assert!(redacted.contains("[REDACTED:injected_credential]"));
        assert!(!redacted.contains("supersecret"));
    }

    #[test]
    fn test_multiple_matches() {
        let detector = LeakDetector::new();
        let text = "AKIATEST and ghp_test and xoxb-123";
        let matches = detector.scan(text, None);
        assert!(matches.len() >= 3);
    }

    #[test]
    fn test_empty_credential_values() {
        let creds = CredentialScanner::new(vec!["".to_string()]);
        assert!(creds.is_none());
        // has_leaks with None creds should not panic or match everything
        let detector = LeakDetector::new();
        assert!(!detector.has_leaks("normal text", None));
    }

    #[test]
    fn test_credential_scanner_isolation() {
        // Verify that separate CredentialScanners don't share state
        let detector = LeakDetector::new();

        let creds_a = CredentialScanner::new(vec!["secret_a".to_string()]);
        let creds_b = CredentialScanner::new(vec!["secret_b".to_string()]);

        // Each scanner only detects its own credentials
        assert!(detector.has_leaks("contains secret_a", creds_a.as_ref()));
        assert!(!detector.has_leaks("contains secret_a", creds_b.as_ref()));
        assert!(detector.has_leaks("contains secret_b", creds_b.as_ref()));
        assert!(!detector.has_leaks("contains secret_b", creds_a.as_ref()));
    }
}
