"""Suppression handler: URI parsing.

Suppresses credential matches in URIs that point to loopback hosts,
example domains, compose service names (without passwords), or contain
example credential markers.

Extracted from ``CredentialScanner.scan`` URI suppression logic
(scanner.py:177-275).
"""

from __future__ import annotations

import logging
import urllib.parse

from sentinel.security._scan_context import ScanContext, ScanMatch

logger = logging.getLogger(__name__)

# Credential-portion markers — safe as substring match on full URI
# because they match userinfo (user:pass@), not the hostname.
_EXAMPLE_URI_CREDENTIALS = (
    "user:pass@",
    "user:password@",
    "username:password@",
    "your-password",
    "<password>",
    "changeme",
)

# Loopback hostnames — unconditionally safe to suppress.
# Real production URIs never point to loopback addresses.
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "0.0.0.0", "::1"})

# Common Compose/Kubernetes service names used as hostnames in dev configs.
# Safe to suppress only when there is NO password in the URI.
_COMPOSE_SERVICE_HOSTS = frozenset(
    {
        "db",
        "redis",
        "postgres",
        "mysql",
        "mongo",
        "rabbitmq",
        "memcached",
    }
)

# Example domains checked via proper hostname parsing (not substring).
_EXAMPLE_URI_DOMAINS = frozenset({"example.com", "example.org", "example.net"})


class UriParsingHandler:
    """Suppress credential matches in example/loopback/compose URIs."""

    handler_id: str = "uri_parsing"

    def evaluate(
        self,
        match: ScanMatch,
        context: ScanContext,
        params: dict | None = None,
    ) -> bool:
        """Return True if the match should be suppressed.

        Checks 4 conditions: example credentials, loopback host,
        compose service (no password), example domain.
        """
        logger.debug(
            "Evaluating URI parsing",
            extra={
                "event": "security.suppression.uri_parsing.evaluate",
                "rule_id": match.rule_id,
                "offset": match.offset,
            },
        )

        matched_text = match.matched_text

        # Check 1: credential-portion placeholders (substring on full URI)
        if any(s in matched_text for s in _EXAMPLE_URI_CREDENTIALS):
            logger.debug(
                "URI parsing: example credential in URI",
                extra={
                    "event": "security.suppression.uri_parsing.suppressed",
                    "reason": "example_uri_credential",
                },
            )
            return True

        # Check 2-4: parse the URI for hostname checks
        try:
            parsed = urllib.parse.urlparse(matched_text)
            host = (parsed.hostname or "").lower()

            # Check 2: loopback addresses — unconditionally safe
            if host in _LOOPBACK_HOSTS:
                logger.debug(
                    "URI parsing: loopback host",
                    extra={
                        "event": "security.suppression.uri_parsing.suppressed",
                        "reason": "loopback_host",
                        "host": host,
                    },
                )
                return True

            # Check 3: compose service names — suppress only when no password
            if host in _COMPOSE_SERVICE_HOSTS and not parsed.password:
                logger.debug(
                    "URI parsing: compose service host (no password)",
                    extra={
                        "event": "security.suppression.uri_parsing.suppressed",
                        "reason": "compose_service_host",
                        "host": host,
                    },
                )
                return True

            # Check 4: example domains (exact or subdomain match)
            if host in _EXAMPLE_URI_DOMAINS or any(
                host.endswith("." + d) for d in _EXAMPLE_URI_DOMAINS
            ):
                logger.debug(
                    "URI parsing: example domain",
                    extra={
                        "event": "security.suppression.uri_parsing.suppressed",
                        "reason": "example_domain",
                        "host": host,
                    },
                )
                return True

        except ValueError:
            # Malformed URI — don't suppress (fail-closed).
            # Parse errors on untrusted input are expected — log at DEBUG.
            logger.debug(
                "URI parsing: parse error on matched text",
                extra={
                    "event": "security.suppression.uri_parsing.parse_error",
                    "error_category": "parse_error",
                    "text_length": len(matched_text),
                },
            )

        return False
