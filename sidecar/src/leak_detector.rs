//! Aho-Corasick credential pattern scanner.
//!
//! Scans tool output for leaked credentials using a pre-compiled multi-pattern
//! automaton. O(n) scan time regardless of pattern count.

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
    // OpenAI
    PatternDef { name: "openai_key", pattern: "sk-" },
    // Stripe
    PatternDef { name: "stripe_secret", pattern: "sk_live_" },
    PatternDef { name: "stripe_public", pattern: "pk_live_" },
    // PEM private keys
    PatternDef { name: "pem_rsa", pattern: "-----BEGIN RSA PRIVATE KEY-----" },
    PatternDef { name: "pem_ec", pattern: "-----BEGIN EC PRIVATE KEY-----" },
    PatternDef { name: "pem_generic", pattern: "-----BEGIN PRIVATE KEY-----" },
    // JWT bearer tokens
    PatternDef { name: "bearer_jwt", pattern: "Bearer ey" },
    // Generic credential assignments
    PatternDef { name: "generic_password", pattern: "password=" },
    PatternDef { name: "generic_secret", pattern: "secret=" },
    PatternDef { name: "generic_token", pattern: "token=" },
    PatternDef { name: "generic_api_key", pattern: "api_key=" },
];

/// Pre-compiled leak detector using Aho-Corasick automaton.
pub struct LeakDetector {
    automaton: AhoCorasick,
    /// Pattern names in the same order as automaton patterns.
    pattern_names: Vec<String>,
    /// Additional credential values to scan for (injected per-execution).
    credential_values: Vec<String>,
    /// Aho-Corasick for credential values (rebuilt per-execution if needed).
    cred_automaton: Option<AhoCorasick>,
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
            credential_values: Vec::new(),
            cred_automaton: None,
        }
    }

    /// Add credential values to scan for (call before scanning output).
    /// These are the actual injected credential values that must not leak.
    pub fn set_credential_values(&mut self, values: Vec<String>) {
        // Only build automaton for non-empty values
        let non_empty: Vec<String> = values.into_iter().filter(|v| !v.is_empty()).collect();
        if !non_empty.is_empty() {
            self.cred_automaton = AhoCorasick::new(&non_empty).ok();
        } else {
            self.cred_automaton = None;
        }
        self.credential_values = non_empty;
    }

    /// Quick check: does the text contain any leak patterns?
    pub fn has_leaks(&self, text: &str) -> bool {
        if self.automaton.is_match(text) {
            return true;
        }
        if let Some(ref cred_ac) = self.cred_automaton {
            if cred_ac.is_match(text) {
                return true;
            }
        }
        false
    }

    /// Scan text and return all leak matches.
    pub fn scan(&self, text: &str) -> Vec<LeakMatch> {
        let mut matches = Vec::new();

        // Check built-in patterns
        for mat in self.automaton.find_iter(text) {
            matches.push(LeakMatch {
                pattern_name: self.pattern_names[mat.pattern().as_usize()].clone(),
                start: mat.start(),
                end: mat.end(),
            });
        }

        // Check injected credential values
        if let Some(ref cred_ac) = self.cred_automaton {
            for mat in cred_ac.find_iter(text) {
                matches.push(LeakMatch {
                    pattern_name: "injected_credential".to_string(),
                    start: mat.start(),
                    end: mat.end(),
                });
            }
        }

        matches
    }

    /// Redact all detected leaks in the text, replacing matches with
    /// `[REDACTED:pattern_name]`.
    pub fn redact(&self, text: &str) -> String {
        let mut leaks = self.scan(text);
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
        assert!(detector.has_leaks("my key is AKIAIOSFODNN7EXAMPLE"));
        let matches = detector.scan("AKIAIOSFODNN7EXAMPLE");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern_name, "aws_access_key");
    }

    #[test]
    fn test_detects_github_pat() {
        let detector = LeakDetector::new();
        assert!(detector.has_leaks("token: ghp_abcdefg123456"));
        let matches = detector.scan("ghp_test");
        assert_eq!(matches[0].pattern_name, "github_pat");
    }

    #[test]
    fn test_detects_slack_bot() {
        let detector = LeakDetector::new();
        assert!(detector.has_leaks("SLACK_TOKEN=xoxb-123-456"));
    }

    #[test]
    fn test_detects_pem_header() {
        let detector = LeakDetector::new();
        assert!(detector.has_leaks("-----BEGIN RSA PRIVATE KEY-----\nMIIE..."));
    }

    #[test]
    fn test_detects_bearer_jwt() {
        let detector = LeakDetector::new();
        assert!(detector.has_leaks("Authorization: Bearer eyJhbGciOiJ..."));
    }

    #[test]
    fn test_detects_generic_patterns() {
        let detector = LeakDetector::new();
        assert!(detector.has_leaks("password=hunter2"));
        assert!(detector.has_leaks("api_key=abc123"));
    }

    #[test]
    fn test_clean_text_no_leaks() {
        let detector = LeakDetector::new();
        assert!(!detector.has_leaks("Hello, this is normal text with no secrets."));
    }

    #[test]
    fn test_redaction() {
        let detector = LeakDetector::new();
        let redacted = detector.redact("key is AKIAIOSFODNN7EXAMPLE here");
        assert!(redacted.contains("[REDACTED:aws_access_key]"));
        assert!(!redacted.contains("AKIA"));
    }

    #[test]
    fn test_credential_value_detection() {
        let mut detector = LeakDetector::new();
        detector.set_credential_values(vec!["my-secret-value-12345".to_string()]);
        assert!(detector.has_leaks("output contains my-secret-value-12345 here"));
        let matches = detector.scan("has my-secret-value-12345");
        assert_eq!(matches[0].pattern_name, "injected_credential");
    }

    #[test]
    fn test_credential_value_redaction() {
        let mut detector = LeakDetector::new();
        detector.set_credential_values(vec!["supersecret".to_string()]);
        let redacted = detector.redact("the value is supersecret!");
        assert!(redacted.contains("[REDACTED:injected_credential]"));
        assert!(!redacted.contains("supersecret"));
    }

    #[test]
    fn test_multiple_matches() {
        let detector = LeakDetector::new();
        let text = "AKIATEST and ghp_test and xoxb-123";
        let matches = detector.scan(text);
        assert!(matches.len() >= 3);
    }

    #[test]
    fn test_empty_credential_values() {
        let mut detector = LeakDetector::new();
        detector.set_credential_values(vec!["".to_string()]);
        // Should not panic or match everything
        assert!(!detector.has_leaks("normal text"));
    }
}
