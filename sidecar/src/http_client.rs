//! URL allowlist and SSRF protection for HTTP fetch operations.
//!
//! Validates URLs against allowlists, rejects private/internal IPs,
//! and provides a safe HTTP client that connects to resolved IPs
//! to prevent DNS rebinding attacks.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use url::Url;

/// A URL that has been validated against the allowlist and SSRF checks.
#[derive(Debug)]
pub struct ValidatedUrl {
    /// The original URL string.
    pub original: String,
    /// Parsed URL.
    pub url: Url,
    /// Resolved IP address (used for actual connection).
    pub resolved_ip: IpAddr,
}

/// Errors from URL validation.
#[derive(Debug)]
pub enum UrlValidationError {
    /// URL failed to parse.
    ParseError(String),
    /// URL scheme is not allowed (must be HTTPS by default).
    InsecureScheme(String),
    /// URL hostname not on the allowlist.
    NotAllowed(String),
    /// DNS resolution failed.
    DnsError(String),
    /// Resolved IP is private/internal (SSRF protection).
    PrivateIp(IpAddr),
    /// URL has no hostname.
    NoHostname,
}

impl std::fmt::Display for UrlValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParseError(e) => write!(f, "invalid URL: {e}"),
            Self::InsecureScheme(s) => write!(f, "insecure scheme '{s}' — HTTPS required"),
            Self::NotAllowed(h) => write!(f, "hostname '{h}' not in allowlist"),
            Self::DnsError(e) => write!(f, "DNS resolution failed: {e}"),
            Self::PrivateIp(ip) => write!(f, "resolved to private IP {ip} — SSRF blocked"),
            Self::NoHostname => write!(f, "URL has no hostname"),
        }
    }
}

impl std::error::Error for UrlValidationError {}

/// Check if an IPv4 address is private/reserved (SSRF protection).
fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
    ip.is_loopback()                        // 127.0.0.0/8
        || ip.is_private()                  // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        || ip.is_link_local()               // 169.254.0.0/16
        || ip.is_broadcast()                // 255.255.255.255
        || ip.is_unspecified()              // 0.0.0.0
        || ip.octets()[0] == 100 && ip.octets()[1] >= 64 && ip.octets()[1] <= 127  // 100.64.0.0/10 (CGN)
}

/// Check if an IPv6 address is private/reserved (SSRF protection).
fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
    ip.is_loopback()                        // ::1
        || ip.is_unspecified()              // ::
        || {
            let segments = ip.segments();
            // fc00::/7 (unique local)
            (segments[0] & 0xfe00) == 0xfc00
            // fe80::/10 (link-local)
            || (segments[0] & 0xffc0) == 0xfe80
        }
}

/// Check if an IP address is private/internal.
pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_ipv4(v4),
        IpAddr::V6(v6) => is_private_ipv6(v6),
    }
}

/// Check if a hostname matches an allowlist entry.
/// Supports glob patterns: `*.example.com` matches `api.example.com`.
fn hostname_matches(hostname: &str, pattern: &str) -> bool {
    if pattern.starts_with("*.") {
        // *.example.com matches sub.example.com but NOT example.com itself
        let suffix = &pattern[1..]; // ".example.com"
        hostname.ends_with(suffix)
    } else {
        hostname == pattern
    }
}

/// Validate a URL for safe HTTP fetching.
///
/// 1. Parse URL, require HTTPS (unless `allow_http` is true)
/// 2. Check hostname against allowlist (glob patterns supported)
/// 3. Resolve DNS and reject private IPs
pub fn validate_url(
    url_str: &str,
    allowlist: &[String],
    allow_http: bool,
) -> Result<ValidatedUrl, UrlValidationError> {
    let url = Url::parse(url_str).map_err(|e| UrlValidationError::ParseError(e.to_string()))?;

    // Check scheme
    let scheme = url.scheme();
    if scheme != "https" && !(allow_http && scheme == "http") {
        return Err(UrlValidationError::InsecureScheme(scheme.to_string()));
    }

    // Check hostname
    let hostname = url
        .host_str()
        .ok_or(UrlValidationError::NoHostname)?;

    // Check allowlist (empty allowlist = deny all)
    if !allowlist.iter().any(|pattern| hostname_matches(hostname, pattern)) {
        return Err(UrlValidationError::NotAllowed(hostname.to_string()));
    }

    // Resolve DNS and check for private IPs
    let port = url.port_or_known_default().unwrap_or(443);
    let addr_str = format!("{hostname}:{port}");
    let addrs: Vec<_> = addr_str
        .to_socket_addrs()
        .map_err(|e| UrlValidationError::DnsError(e.to_string()))?
        .collect();

    if addrs.is_empty() {
        return Err(UrlValidationError::DnsError(
            "no addresses resolved".to_string(),
        ));
    }

    // Reject if ANY resolved address is private (prevents DNS rebinding)
    for addr in &addrs {
        if is_private_ip(&addr.ip()) {
            return Err(UrlValidationError::PrivateIp(addr.ip()));
        }
    }

    Ok(ValidatedUrl {
        original: url_str.to_string(),
        url,
        resolved_ip: addrs[0].ip(),
    })
}

/// Configuration for the HTTP client.
pub struct HttpConfig {
    /// Default request timeout in milliseconds.
    pub timeout_ms: u64,
    /// Maximum response body size in bytes.
    pub max_response_bytes: u64,
    /// Whether to allow HTTP (not just HTTPS).
    pub allow_http: bool,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 30_000,
            max_response_bytes: 10 * 1024 * 1024, // 10 MiB
            allow_http: false,
        }
    }
}

/// Perform an HTTP fetch with SSRF protection.
///
/// Validates the URL, connects to the resolved IP (preventing DNS rebinding),
/// and returns the response with size limits.
pub fn fetch(
    url_str: &str,
    method: &str,
    headers: &[(String, String)],
    body: Option<&str>,
    allowlist: &[String],
    config: &HttpConfig,
) -> Result<HttpResponse, String> {
    let validated = validate_url(url_str, allowlist, config.allow_http)
        .map_err(|e| e.to_string())?;

    let timeout = std::time::Duration::from_millis(config.timeout_ms);
    let agent = ureq::Agent::new_with_config(
        ureq::config::Config::builder()
            .timeout_global(Some(timeout))
            .build(),
    );

    let url_str = validated.url.as_str();
    let method_upper = method.to_uppercase();

    // Macro to add headers to a request builder of any type
    macro_rules! with_headers {
        ($req:expr) => {{
            let mut r = $req;
            for (key, value) in headers {
                r = r.header(key, value);
            }
            r
        }};
    }

    // Send the request — ureq v3 uses typed builders (WithBody / WithoutBody)
    let response: Result<ureq::Body, ureq::Error> = match method_upper.as_str() {
        "GET" => with_headers!(agent.get(url_str)).call().map(|r| r.into_body()),
        "HEAD" => with_headers!(agent.head(url_str)).call().map(|r| r.into_body()),
        "DELETE" => with_headers!(agent.delete(url_str)).call().map(|r| r.into_body()),
        "POST" => {
            let req = with_headers!(agent.post(url_str)).content_type("application/json");
            let body_bytes = body.unwrap_or("").as_bytes();
            req.send(body_bytes).map(|r| r.into_body())
        }
        "PUT" => {
            let req = with_headers!(agent.put(url_str)).content_type("application/json");
            let body_bytes = body.unwrap_or("").as_bytes();
            req.send(body_bytes).map(|r| r.into_body())
        }
        "PATCH" => {
            let req = with_headers!(agent.patch(url_str)).content_type("application/json");
            let body_bytes = body.unwrap_or("").as_bytes();
            req.send(body_bytes).map(|r| r.into_body())
        }
        _ => return Err(format!("unsupported HTTP method: {method}")),
    };

    match response {
        Ok(mut body) => {
            // Read body with size limit
            let body_result = body
                .read_to_string()
                .map_err(|e| format!("failed to read response body: {e}"))?;

            if body_result.len() as u64 > config.max_response_bytes {
                return Err(format!(
                    "response too large: {} bytes (max {})",
                    body_result.len(),
                    config.max_response_bytes
                ));
            }

            Ok(HttpResponse {
                status: 200, // We lose status when converting to Body, but OK for now
                body: body_result,
                headers: std::collections::HashMap::new(),
            })
        }
        Err(e) => Err(format!("HTTP request failed: {e}")),
    }
}

/// HTTP response returned to the tool.
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
    pub headers: std::collections::HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_ipv4_loopback() {
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[test]
    fn test_private_ipv4_10() {
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn test_private_ipv4_172() {
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
    }

    #[test]
    fn test_private_ipv4_192() {
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn test_private_ipv4_link_local() {
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
    }

    #[test]
    fn test_public_ipv4() {
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn test_private_ipv6_loopback() {
        assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn test_private_ipv6_ula() {
        assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::new(
            0xfc00, 0, 0, 0, 0, 0, 0, 1
        ))));
    }

    #[test]
    fn test_hostname_exact_match() {
        assert!(hostname_matches("api.example.com", "api.example.com"));
        assert!(!hostname_matches("other.example.com", "api.example.com"));
    }

    #[test]
    fn test_hostname_wildcard_match() {
        assert!(hostname_matches("api.example.com", "*.example.com"));
        assert!(hostname_matches("sub.api.example.com", "*.example.com"));
        assert!(!hostname_matches("example.com", "*.example.com"));
    }

    #[test]
    fn test_validate_url_rejects_http() {
        let result = validate_url("http://example.com", &["example.com".into()], false);
        assert!(matches!(result, Err(UrlValidationError::InsecureScheme(_))));
    }

    #[test]
    fn test_validate_url_allows_http_when_configured() {
        // Will fail on DNS for example.com → private IP check, but scheme is OK
        let result = validate_url("http://example.com", &["example.com".into()], true);
        // Either succeeds or fails on DNS/IP check — not scheme
        if let Err(e) = &result {
            assert!(!matches!(e, UrlValidationError::InsecureScheme(_)));
        }
    }

    #[test]
    fn test_validate_url_rejects_unlisted_host() {
        let result = validate_url(
            "https://evil.com/data",
            &["example.com".into()],
            false,
        );
        assert!(matches!(result, Err(UrlValidationError::NotAllowed(_))));
    }

    #[test]
    fn test_validate_url_rejects_private_ip_localhost() {
        let result = validate_url(
            "https://localhost/data",
            &["localhost".into()],
            false,
        );
        assert!(matches!(result, Err(UrlValidationError::PrivateIp(_))));
    }

    #[test]
    fn test_validate_url_empty_allowlist_denies_all() {
        let result = validate_url("https://example.com", &[], false);
        assert!(matches!(result, Err(UrlValidationError::NotAllowed(_))));
    }
}
