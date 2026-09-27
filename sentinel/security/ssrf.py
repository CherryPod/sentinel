"""SSRF policy primitives for Python-side URL validation.

Ported from ``sidecar/src/http_client.rs:62-222``. Ships **policy** only:
URL parsing + scheme check + host canonicalisation + allowlist membership
+ private/loopback/link-local/CGN IP rejection + DNS resolve-then-check.

Does NOT own transport — callers keep their own httpx/requests/aiohttp
wiring. Shared client factories + pin-connect DNS-rebind closure remain
deferred to umbrella Q12-U1.

Two entry points:
    - ``parse_and_check_syntactic`` — no DNS. Suitable for credential PUT.
    - ``resolve_and_check_private`` — DNS + private-IP reject. Suitable
      for immediately before the outbound call (use-time).

On reject: raise ``UrlValidationError`` with a ``category`` string that
matches the Rust-side shape.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import logging
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

import idna

logger = logging.getLogger(__name__)


# ── Constants ────────────────────────────────────────────────────────

# Carrier-grade NAT (RFC 6598). Not covered by ``ipaddress.is_private``;
# Rust side blocks explicitly at ``sidecar/src/http_client.rs:69``.
_CGN_NET = ipaddress.ip_network("100.64.0.0/10")

# Scheme allow-list. HTTP requires explicit opt-in via ``allow_http=True``.
_SUPPORTED_SCHEMES = frozenset({"http", "https"})

# Default ports (for URLs with no explicit port).
_DEFAULT_PORTS = {"http": 80, "https": 443}

# Allowlist "match anything" sentinel — explicit full-allow for rollback.
_ALL_SENTINEL = "*"

# Default DNS resolve timeout. Callers may override.
_DNS_TIMEOUT_DEFAULT_S = 5.0


# ── Exception ────────────────────────────────────────────────────────


class UrlValidationError(Exception):
    """Raised when a URL fails SSRF policy validation.

    ``category`` is a short stable string matching the Rust-side enum
    (``parse_error``, ``insecure_scheme``, ``not_allowed``, ``dns_error``,
    ``dns_timeout``, ``private_ip``, ``no_hostname``).  Callers typically
    log ``category`` (not ``reason``) as a structured field.
    """

    def __init__(
        self,
        reason: str,
        *,
        category: str,
        host: str = "",
        resolved_ip: str = "",
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.category = category
        self.host = host
        self.resolved_ip = resolved_ip


# ── Data classes ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class ParsedUrl:
    """Result of syntactic validation. ``host`` is canonicalised."""

    scheme: str
    host: str
    port: int
    # If the host is an IP literal (including numeric aliases like
    # ``2130706433``), the parsed address. ``None`` for DNS hostnames.
    literal_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None


@dataclass(frozen=True)
class ResolvedUrl:
    """Result of DNS resolution + private-IP reject."""

    parsed: ParsedUrl
    resolved_ips: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]


# ── Allowlist parsing ────────────────────────────────────────────────


def _parse_allowlist(raw: str) -> tuple[str, ...]:
    """Split a comma-separated allowlist string into entries.

    Matches the repo convention used by ``matrix_allowed_senders`` and
    similar settings: split on comma, strip whitespace, filter empty.
    """
    if not raw:
        return ()
    return tuple(entry.strip() for entry in raw.split(",") if entry.strip())


def _hostname_matches(host: str, allowlist: tuple[str, ...]) -> bool:
    """Check ``host`` against the allowlist using Rust-shape rules.

    - Empty allowlist → no host matches (deny-all).
    - ``"*"`` sentinel entry → match anything (explicit full-allow for rollback).
    - Exact literal match: ``foo.example.com`` matches ``foo.example.com``.
    - Suffix glob ``*.example.com``: matches ``example.com`` itself plus
      any subdomain (``a.example.com``). Dot-boundary enforced — does NOT
      match ``evil-example.com``.
    """
    if not allowlist:
        return False
    host_lc = host.lower()
    for entry in allowlist:
        if entry == _ALL_SENTINEL:
            return True
        entry_lc = entry.lower()
        if entry_lc.startswith("*."):
            suffix = entry_lc[2:]
            # ``*.example.com`` matches ``example.com`` and ``a.example.com``.
            if host_lc == suffix or host_lc.endswith("." + suffix):
                return True
        elif host_lc == entry_lc:
            return True
    return False


# ── Host canonicalisation ────────────────────────────────────────────


def _canonicalise_host(raw_host: str) -> str:
    """Lowercase + strip trailing dot + IDNA A-label normalise (UTS-46 nontransitional).

    ``urllib.parse.urlparse`` returns the hostname mostly lowercased but leaves
    Unicode homographs intact and preserves trailing dots. Both are SSRF bypass
    vectors against naive allowlist membership.

    Uses third-party ``idna.encode(uts46=True, transitional=False)`` to match
    the IDNA profile modern HTTP transport libraries (urllib3, httpx) use. The
    stdlib ``encode("idna")`` codec implements RFC 3490 IDNA 2003 which diverges
    from UTS-46 nontransitional on the deviation characters (ß, final sigma,
    ZWJ/ZWNJ): the validator and the transport would otherwise see different
    DNS names for the same input. See `docs/hardening/cleanup-pass-2026-04-25/
    fixes/C65-q12-fl4-trust-boundary-bypass-design-fix.md` for the bypass
    rationale and `_get_caldav_client` for the matching transport-side fix.

    IP literals (IPv4 dotted, IPv6 with brackets stripped by ``urlparse``) bypass
    IDNA — UTS-46 strict-rejects U+003A. Numeric IPv4 alias forms (e.g.
    ``2130706433``, ``0x7f000001``) are not strict-IP-parseable and pass through
    ``idna.encode`` unchanged; ``_parse_literal_ip`` downstream classifies them.

    Raises ``UrlValidationError(category='parse_error')`` on invalid IDNA.
    """
    logger.debug(
        "_canonicalise_host called",
        extra={
            "event": "security.ssrf._canonicalise_host",
            "raw_host_type": type(raw_host).__name__,
        },
    )  # auto:entry
    host = raw_host.lower()
    if host.endswith(".") and len(host) > 1:
        host = host[:-1]

    # IP literal short-circuit: IDNA does not apply to strict-parseable IPs.
    # Covers IPv6 (urlparse strips brackets, host carries colons) and dotted
    # IPv4 (IDNA-passes-through but the explicit return makes intent obvious).
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    try:
        # UTS-46 nontransitional: matches modern HTTP transport-library IDNA.
        # ``idna.IDNAError`` inherits from ``UnicodeError``, so the existing
        # except clause catches both stdlib codec errors and idna-package errors.
        host = idna.encode(host, uts46=True, transitional=False).decode("ascii")
    except UnicodeError as exc:
        raise UrlValidationError(
            f"invalid IDNA hostname: {exc}",
            category="parse_error",
            host=raw_host,
        ) from exc
    return host


def _parse_literal_ip(
    host: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Detect IP literals including numeric IPv4 aliases.

    Handles dotted-quad IPv4, bracket-stripped IPv6, and the historical
    IPv4 alias forms (integer, hex, octal, shorthand) that
    ``ipaddress.ip_address`` rejects but ``socket.getaddrinfo`` accepts.

    Returns ``None`` for DNS hostnames.
    """
    # First try strict dotted-quad / IPv6 parsing.
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    # Then try BSD-style IPv4 aliases via the system resolver's inet_aton.
    # ``inet_aton`` does NOT do DNS — purely numeric parsing — so no egress.
    try:
        packed = socket.inet_aton(host)
    except OSError:
        # Non-error: ``host`` is a DNS name, not a numeric IP literal.
        # This is the normal discriminator between IP and hostname paths,
        # not a fault — debug-level only.
        logger.debug(
            "security.ssrf._parse_literal_ip.not_numeric",
            extra={"event": "security.ssrf._parse_literal_ip.not_numeric"},
        )
        return None
    canonical = socket.inet_ntoa(packed)
    return ipaddress.IPv4Address(canonical)


def _classify_private(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> str | None:
    """Return a reject-reason category if ``ip`` is disallowed, else None.

    IPv4-mapped IPv6 (``::ffff:x.x.x.x``) is unwrapped before classification
    so ``::ffff:127.0.0.1`` is treated as IPv4 loopback (not just ``is_private``).
    CGN (``100.64.0.0/10``) is checked explicitly because Python's
    ``ip.is_private`` does NOT cover it.
    """
    # Unwrap IPv4-mapped IPv6 before category dispatch.
    logger.debug(
        "_classify_private called",
        extra={
            "event": "security.ssrf._classify_private",
            "ip_type": type(ip).__name__,
        },
    )  # auto:entry
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback:
        return "private_ip"
    if ip.is_link_local:
        return "private_ip"
    if ip.is_multicast:
        return "private_ip"
    if ip.is_unspecified:
        return "private_ip"
    if ip.is_reserved:
        return "private_ip"
    if ip.is_private:
        return "private_ip"
    if isinstance(ip, ipaddress.IPv4Address) and ip in _CGN_NET:
        return "private_ip"
    return None


# ── Public API: syntactic check ──────────────────────────────────────


def parse_and_check_syntactic(
    url_str: str,
    *,
    allow_http: bool = False,
    allowlist: tuple[str, ...] = (),
) -> ParsedUrl:
    """Parse ``url_str`` and enforce scheme + literal-IP + allowlist policy.

    Runs at credential PUT time. No DNS — intentionally decoupled from
    resolver liveness.

    Raises ``UrlValidationError`` on any policy breach.
    """
    logger.debug(
        "security.ssrf.validate_syntactic",
        extra={
            "event": "security.ssrf.validate_syntactic",
            "url_length": len(url_str),
            "allow_http": allow_http,
            "allowlist_size": len(allowlist),
        },
    )

    try:
        parsed = urlparse(url_str)
    except ValueError as exc:
        logger.info(
            "security.ssrf.reject",
            extra={
                "event": "security.ssrf.reject",
                "reason": "parse_error",
                "stage": "syntactic",
            },
        )
        raise UrlValidationError(
            f"URL parse failed: {exc}",
            category="parse_error",
        ) from exc

    scheme = (parsed.scheme or "").lower()
    if scheme not in _SUPPORTED_SCHEMES:
        logger.info(
            "security.ssrf.reject",
            extra={
                "event": "security.ssrf.reject",
                "reason": "insecure_scheme",
                "stage": "syntactic",
                "scheme": scheme or "<empty>",
            },
        )
        raise UrlValidationError(
            f"scheme {scheme!r} not supported (expected https or http)",
            category="insecure_scheme",
        )
    logger.debug(
        "parse_and_check_syntactic: scheme_not_in_SUPPORTED_SCHEMES_passed",
        extra={
            "event": "security.ssrf.reject.passed",
            "reason": "scheme_not_in_SUPPORTED_SCHEMES_passed",
        },
    )  # auto:neg
    if scheme == "http" and not allow_http:
        logger.info(
            "security.ssrf.reject",
            extra={
                "event": "security.ssrf.reject",
                "reason": "insecure_scheme",
                "stage": "syntactic",
                "scheme": scheme,
            },
        )
        raise UrlValidationError(
            "http scheme requires allow_http=True (default https-only)",
            category="insecure_scheme",
        )
    logger.debug(
        "parse_and_check_syntactic: scheme_eq_http_passed",
        extra={
            "event": "security.ssrf.reject.passed",
            "reason": "scheme_eq_http_passed",
        },
    )  # auto:neg

    raw_host = parsed.hostname or ""
    if not raw_host:
        logger.info(
            "security.ssrf.reject",
            extra={
                "event": "security.ssrf.reject",
                "reason": "no_hostname",
                "stage": "syntactic",
            },
        )
        raise UrlValidationError(
            "URL missing hostname",
            category="no_hostname",
        )

    host = _canonicalise_host(raw_host)
    literal_ip = _parse_literal_ip(host)

    if literal_ip is not None:
        # Literal IP (including numeric aliases). Run private-range check
        # at PUT time — no DNS needed for opaque-string IP aliases.
        reject = _classify_private(literal_ip)
        if reject is not None:
            logger.info(
                "security.ssrf.reject",
                extra={
                    "event": "security.ssrf.reject",
                    "reason": reject,
                    "stage": "syntactic",
                    "host": host,
                    "ip_family": "v4"
                    if isinstance(literal_ip, ipaddress.IPv4Address)
                    else "v6",
                },
            )
            raise UrlValidationError(
                f"host {host!r} is a private/reserved IP literal",
                category=reject,
                host=host,
                resolved_ip=str(literal_ip),
            )
        # Public literal IP — still enforce allowlist (operator must opt in).
        if not _hostname_matches(host, allowlist):
            logger.info(
                "security.ssrf.reject",
                extra={
                    "event": "security.ssrf.reject",
                    "reason": "not_allowed",
                    "stage": "syntactic",
                    "host": host,
                },
            )
            raise UrlValidationError(
                f"host {host!r} not in allowlist",
                category="not_allowed",
                host=host,
            )
    else:
        # DNS hostname — enforce allowlist membership (deny-all when empty).
        if not _hostname_matches(host, allowlist):
            logger.info(
                "security.ssrf.reject",
                extra={
                    "event": "security.ssrf.reject",
                    "reason": "not_allowed",
                    "stage": "syntactic",
                    "host": host,
                },
            )
            raise UrlValidationError(
                f"host {host!r} not in allowlist",
                category="not_allowed",
                host=host,
            )

    # Q12-F1 Cx-1: urllib.parse.urlparse lazily validates port on attribute
    # access; out-of-range / non-integer / negative ports raise raw ValueError
    # which would escape to a 500 on the auth PUT path + skip audit emission.
    # Wrap the read and translate to structured parse_error.
    try:
        explicit_port = parsed.port
    except ValueError as exc:
        logger.info(
            "security.ssrf.reject",
            extra={
                "event": "security.ssrf.reject",
                "reason": "parse_error",
                "stage": "syntactic",
                "detail": "invalid_port",
            },
        )
        raise UrlValidationError(
            f"URL has invalid port: {exc}",
            category="parse_error",
        ) from exc
    port = explicit_port or _DEFAULT_PORTS[scheme]
    logger.info(
        "security.ssrf.validated_syntactic",
        extra={
            "event": "security.ssrf.validated_syntactic",
            "host": host,
            "scheme": scheme,
            "port": port,
            "literal_ip": literal_ip is not None,
        },
    )
    return ParsedUrl(scheme=scheme, host=host, port=port, literal_ip=literal_ip)


# ── Public API: DNS resolve + private-IP check ───────────────────────


def _resolve_host(
    host: str,
    port: int,
    *,
    dns_timeout_s: float,
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    """Resolve ``host`` via the system resolver with a hard timeout.

    ``socket.getaddrinfo`` has no timeout parameter, so we run it in a
    dedicated worker thread and enforce the timeout via ``future.result``.
    On timeout the worker thread is abandoned (best-effort), but since the
    resolver itself will usually finish shortly after and we never reuse
    the executor, this is acceptable for our per-call pattern.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        fut = executor.submit(
            socket.getaddrinfo,
            host,
            port,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )
        try:
            infos = fut.result(timeout=dns_timeout_s)
        except concurrent.futures.TimeoutError as exc:
            raise UrlValidationError(
                f"DNS resolution for {host!r} exceeded {dns_timeout_s}s",
                category="dns_timeout",
                host=host,
            ) from exc
        except socket.gaierror as exc:
            raise UrlValidationError(
                f"DNS resolution for {host!r} failed: {exc}",
                category="dns_error",
                host=host,
            ) from exc

    results: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for info in infos:
        sockaddr = info[4]
        ip_str = sockaddr[0]
        try:
            results.append(ipaddress.ip_address(ip_str))
        except ValueError:
            # getaddrinfo can sometimes emit scoped IPv6 (e.g. fe80::1%eth0).
            # Strip the zone id and retry; if still invalid, skip this entry.
            # Recoverable path — debug-level only, not an error.
            logger.debug(
                "security.ssrf._resolve_host.scoped_ipv6",
                extra={"event": "security.ssrf._resolve_host.scoped_ipv6"},
            )
            unscoped = ip_str.split("%", 1)[0]
            try:
                results.append(ipaddress.ip_address(unscoped))
            except ValueError:
                continue
    return tuple(results)


def resolve_and_check_private(
    parsed: ParsedUrl,
    *,
    dns_timeout_s: float = _DNS_TIMEOUT_DEFAULT_S,
    private_host_allowlist: tuple[str, ...] = (),
) -> ResolvedUrl:
    """Resolve ``parsed`` via DNS and reject any private/reserved address.

    If the hostname (or any resolved IP string) is in
    ``private_host_allowlist``, the private-IP reject is bypassed — for
    operator-declared internal hosts only (self-hosted NAS case).

    Raises ``UrlValidationError`` on DNS failure, DNS timeout, or
    private-IP hit.
    """
    logger.debug(
        "security.ssrf.validate_resolve",
        extra={
            "event": "security.ssrf.validate_resolve",
            "host": parsed.host,
            "scheme": parsed.scheme,
            "port": parsed.port,
            "allowlist_size": len(private_host_allowlist),
        },
    )

    # Literal IPs do not need DNS resolution; ``parse_and_check_syntactic``
    # already vetted their private-range classification.
    if parsed.literal_ip is not None:
        logger.info(
            "security.ssrf.validated_resolve",
            extra={
                "event": "security.ssrf.validated_resolve",
                "host": parsed.host,
                "resolved_ips": 1,
                "literal": True,
            },
        )
        return ResolvedUrl(parsed=parsed, resolved_ips=(parsed.literal_ip,))

    resolved_ips = _resolve_host(parsed.host, parsed.port, dns_timeout_s=dns_timeout_s)
    if not resolved_ips:
        logger.info(
            "security.ssrf.reject",
            extra={
                "event": "security.ssrf.reject",
                "reason": "dns_error",
                "stage": "resolve",
                "host": parsed.host,
            },
        )
        raise UrlValidationError(
            f"DNS returned no addresses for {parsed.host!r}",
            category="dns_error",
            host=parsed.host,
        )

    host_on_allowlist = _hostname_matches(parsed.host, private_host_allowlist)

    for ip in resolved_ips:
        reject = _classify_private(ip)
        if reject is None:
            continue
        ip_str = str(ip)
        # Operator-declared internal host? Allow the private-IP result.
        if host_on_allowlist or ip_str in private_host_allowlist:
            logger.info(
                "security.ssrf.private_host_allowlist_hit",
                extra={
                    "event": "security.ssrf.private_host_allowlist_hit",
                    "host": parsed.host,
                    "resolved_ip": ip_str,
                },
            )
            continue
        logger.info(
            "security.ssrf.reject",
            extra={
                "event": "security.ssrf.reject",
                "reason": reject,
                "stage": "resolve",
                "host": parsed.host,
                "resolved_ip": ip_str,
            },
        )
        raise UrlValidationError(
            f"host {parsed.host!r} resolved to private address {ip_str}",
            category=reject,
            host=parsed.host,
            resolved_ip=ip_str,
        )

    logger.info(
        "security.ssrf.validated_resolve",
        extra={
            "event": "security.ssrf.validated_resolve",
            "host": parsed.host,
            "resolved_ips": len(resolved_ips),
            "literal": False,
        },
    )
    return ResolvedUrl(parsed=parsed, resolved_ips=resolved_ips)


__all__ = [
    "ParsedUrl",
    "ResolvedUrl",
    "UrlValidationError",
    "_parse_allowlist",
    "parse_and_check_syntactic",
    "resolve_and_check_private",
]
