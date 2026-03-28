import base64
import codecs
import html
import logging
import re
import urllib.parse

from sentinel.core.models import ScanMatch, ScanResult
from sentinel.security.context_classifier import CODE_FENCE_RE as _CODE_FENCE_RE
from sentinel.security.homoglyph import normalise_homoglyphs

logger = logging.getLogger(__name__)


class CredentialScanner:
    """Regex-based scanner for credentials and secrets in text."""

    # URI-format pattern names eligible for example-URI suppression.
    # API keys, PATs, JWTs are never allowlisted.
    _URI_PATTERN_NAMES = {"mongodb_uri", "postgres_uri", "redis_uri", "mysql_uri"}

    # Credential-portion markers — safe as substring match on full URI
    # because they match userinfo (user:pass@), not the hostname.
    _EXAMPLE_URI_CREDENTIALS = [
        "user:pass@", "user:password@", "username:password@",
        "your-password", "<password>", "changeme",
    ]

    # Loopback hostnames — unconditionally safe to suppress regardless of
    # credentials. Real production URIs never point to loopback addresses.
    # Must be checked via parsed hostname, not substring: "evil.localhost.com"
    # contains "localhost" as a substring but its hostname is NOT localhost.
    _LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "0.0.0.0", "::1"})

    # Common Compose/Kubernetes service names used as hostnames in dev configs.
    # Safe to suppress only when there is NO password in the URI — a URI like
    # "redis://redis:6379" has no password (the ":6379" is the port, not a
    # credential), but "mysql+pymysql://admin:s3cret@db:3306/app" does have a
    # real password and must be flagged regardless of the service-name host.
    _COMPOSE_SERVICE_HOSTS = frozenset({
        "db", "redis", "postgres", "mysql", "mongo",
        "rabbitmq", "memcached",
    })

    # Example domains checked via proper hostname parsing (not substring),
    # so "evil-example.com" doesn't match "example.com".
    _EXAMPLE_URI_DOMAINS = frozenset({"example.com", "example.org", "example.net"})

    # Pattern names eligible for placeholder-value suppression.
    # These match KEY=VALUE formats where the value might be a placeholder
    # in documentation, .env.example files, or tutorials.
    _SECRET_ASSIGNMENT_NAMES = {
        "generic_secret_assignment", "aws_secret_access_key", "wireguard_key",
    }

    # Values (case-insensitive) that indicate a placeholder, not a real secret.
    # Checked via starts-with against the matched value portion.
    # "changeme" matches "changeme" and "changeme123" but NOT
    # "realpasswordchangeme".  This prevents false suppression of real
    # credentials that happen to contain a placeholder word as a substring
    # (e.g. "password123secure" is NOT suppressed).
    _PLACEHOLDER_PREFIXES = (
        "changeme", "replace", "placeholder", "example", "todo",
        "xxxxxxxx", "change_me", "replace_me",
        "fakekey", "dummy", "sample",
        "your-", "your_", "<replace", "<your",
        "insert-", "insert_", "put-your", "put_your", "fill-in",
    )
    # Some well-known example credentials put the placeholder word at the
    # end (e.g. AWS's "wJalrXUt...EXAMPLEKEY").  Suffix matching uses a
    # restricted set to minimise false negatives.
    _PLACEHOLDER_SUFFIXES = (
        "examplekey", "placeholder", "replace_me", "change_me",
    )
    # Values that suppress ONLY as exact matches (case-insensitive).
    # These are genuine placeholders when used alone but are prefixes of
    # real secrets when followed by more characters.
    # "password123" is included because it's a universally-recognised dummy.
    _PLACEHOLDER_EXACT = frozenset({
        "password", "password123", "secret12", "12345678", "test1234",
    })

    def __init__(self, patterns: list[dict]):
        self._patterns: list[tuple[str, re.Pattern]] = []
        for entry in patterns:
            name = entry["name"]
            raw = entry["pattern"]
            # Finding #13: reject patterns with empty names — an empty name
            # makes log output and allowlist lookups ambiguous.
            if not name or not name.strip():
                raise ValueError(f"Credential pattern has empty name: {entry}")
            if not raw or not raw.strip():
                raise ValueError(f"Credential pattern '{name}' has empty regex")
            # Finding #14: validate regex syntax at init rather than deferring
            # the error until the first scan call, which makes failures harder
            # to trace back to the misconfigured pattern entry.
            try:
                compiled = re.compile(raw)
            except re.error as exc:
                raise ValueError(
                    f"Credential pattern '{name}' has invalid regex: {exc}"
                ) from exc
            self._patterns.append((name, compiled))

    def scan(self, text: str) -> ScanResult:
        # R14: Normalise homoglyphs (including zero-width chars) before
        # pattern matching to prevent evasion via invisible characters
        text = normalise_homoglyphs(text)
        matches = []
        for name, pattern in self._patterns:
            for match in pattern.finditer(text):
                matched_text = match.group()

                # Suppress example URIs — real credentials don't use
                # localhost, example.com, or placeholder passwords.
                if name in self._URI_PATTERN_NAMES:
                    # Check 1: credential-portion placeholders (substring on full URI).
                    # These match userinfo (user:pass@) so substring is safe here.
                    if any(s in matched_text for s in self._EXAMPLE_URI_CREDENTIALS):
                        logger.debug("scanner=credential action=suppress pattern=%s reason=example_uri_credential text=%.80s", name, matched_text)
                        continue
                    # Check 2: hostname — parse and check against known example/local
                    # hosts. Substring matching is intentionally avoided here: a URI
                    # like "postgres://x:secret@evil.localhost.com/db" contains
                    # "localhost" as a substring but its hostname is NOT localhost.
                    try:
                        parsed = urllib.parse.urlparse(matched_text)
                        host = (parsed.hostname or "").lower()
                        # Loopback addresses: unconditionally safe to suppress.
                        # Real production credentials never point to loopback.
                        if host in self._LOOPBACK_HOSTS:
                            logger.debug("scanner=credential action=suppress pattern=%s reason=loopback_host host=%s text=%.80s", name, host, matched_text)
                            continue
                        # Compose service names: suppress only when there is no
                        # real password. A URI without userinfo credentials (no @,
                        # or an empty password field) is a dev/compose reference.
                        # If a password is present, the URI must be flagged.
                        if host in self._COMPOSE_SERVICE_HOSTS and not parsed.password:
                            logger.debug("scanner=credential action=suppress pattern=%s reason=compose_service_host host=%s text=%.80s", name, host, matched_text)
                            continue
                        # Exact or subdomain match for well-known example domains.
                        if host in self._EXAMPLE_URI_DOMAINS or any(
                            host.endswith("." + d) for d in self._EXAMPLE_URI_DOMAINS
                        ):
                            logger.debug("scanner=credential action=suppress pattern=%s reason=example_domain host=%s text=%.80s", name, host, matched_text)
                            continue
                    except Exception as exc:
                        # Finding #12: log instead of silently swallowing the
                        # error.  A parse failure on an unusual URI scheme or
                        # malformed match is worth recording for diagnostics
                        # while still allowing the scan to continue.
                        logger.debug(
                            "scanner=credential action=parse_error pattern=%s error=%s text=%.80s",
                            name, exc, matched_text,
                        )

                # Suppress placeholder values in secret assignments —
                # .env.example, tutorials, and templates use dummy values.
                if name in self._SECRET_ASSIGNMENT_NAMES:
                    # Extract the value portion (after = or :)
                    value_part = re.split(r"[=:]+", matched_text, maxsplit=1)[-1]
                    value_lower = value_part.strip("'\"").lower()
                    if (value_lower in self._PLACEHOLDER_EXACT
                            or value_lower.startswith(self._PLACEHOLDER_PREFIXES)
                            or value_lower.endswith(self._PLACEHOLDER_SUFFIXES)):
                        logger.debug("scanner=credential action=suppress pattern=%s reason=placeholder value=%.40s text=%.80s", name, value_lower, matched_text)
                        continue

                matches.append(
                    ScanMatch(
                        pattern_name=name,
                        matched_text=matched_text,
                        position=match.start(),
                    )
                )
                logger.debug("scanner=credential action=flag pattern=%s text=%.80s", name, matched_text)
        # Defence-in-depth: detect /etc/shadow file content format
        matches.extend(self._check_shadow_content(text))
        return ScanResult(
            found=len(matches) > 0,
            matches=matches,
            scanner_name="credential_scanner",
        )

    # Known system account names that appear in /etc/shadow.
    # Includes standard Debian/Ubuntu accounts and common Alpine/RHEL service
    # accounts (nginx, postgres, mysql, redis, etc.) so that a single-line
    # shadow dump for any of these is recognised without requiring 2+ lines.
    _SHADOW_SYSTEM_ACCOUNTS = frozenset({
        "root", "daemon", "bin", "sys", "sync", "games", "man", "lp",
        "mail", "news", "uucp", "proxy", "www-data", "backup", "list",
        "irc", "gnats", "nobody", "systemd-network", "systemd-resolve",
        "messagebus", "systemd-timesync", "syslog", "sshd", "_apt",
        "tss", "uuidd", "systemd-oom", "tcpdump", "avahi-autoipd",
        "usbmux", "dnsmasq", "kernoops", "avahi", "cups-pk-helper",
        "rtkit", "whoopsie", "sssd", "speech-dispatcher", "fwupd-refresh",
        "nm-openvpn", "saned", "colord", "geoclue", "gnome-initial-setup",
        "hplip", "gdm", "polkitd",
        # Common Alpine / RHEL service accounts (#17)
        "nginx", "postgres", "mysql", "redis", "node", "git",
        "docker", "www", "apache", "named", "ntp",
    })

    # Regex: username:hash_or_marker:7 colon-separated numeric fields
    _SHADOW_LINE_RE = re.compile(
        r"^([a-z_][a-z0-9_-]*(?:\$[a-z_][a-z0-9_-]*)?):[^\s:]*(?::\d*){7}$",
        re.MULTILINE,
    )

    def _check_shadow_content(self, text: str) -> list[ScanMatch]:
        """Detect /etc/shadow file content by its 9-field colon format.

        Two-tier detection:
        - 2+ matching lines → always flag (bulk shadow dump)
        - 1 matching line → flag only if username is a known system account
        """
        hits = list(self._SHADOW_LINE_RE.finditer(text))
        if not hits:
            return []
        if len(hits) >= 2:
            logger.debug("scanner=credential action=flag pattern=shadow_file_content lines=%d", len(hits))
            return [
                ScanMatch(
                    pattern_name="shadow_file_content",
                    matched_text=m.group(),
                    position=m.start(),
                )
                for m in hits
            ]
        # Single match — only flag known system accounts
        m = hits[0]
        username = m.group(1)
        if username in self._SHADOW_SYSTEM_ACCOUNTS:
            logger.debug("scanner=credential action=flag pattern=shadow_file_content lines=%d", 1)
            return [
                ScanMatch(
                    pattern_name="shadow_file_content",
                    matched_text=m.group(),
                    position=m.start(),
                )
            ]
        return []


class SensitivePathScanner:
    """Substring-based scanner for sensitive path references in text."""

    # Shell command prefixes that indicate operational context.
    # Used to recognise shell lines inside non-shell-tagged code blocks and
    # outside code blocks entirely. For blocks tagged as shell (see
    # _SHELL_LANG_TAGS below), every line is treated as shell context without
    # needing a prefix match.
    _SHELL_PREFIXES = re.compile(
        r"^\s*(?:\$|#|sudo|"
        r"cat|rm|chmod|chown|ls|cp|mv|mkdir|touch|head|tail|less|more|nano|vi|vim|"
        r"source|scp|grep|curl|wget|tar|ssh|bash|sh|zsh|"
        r"python[23]?|perl|ruby|node|"
        r"powershell|pwsh|php|"
        r"find|xargs|sed|awk|sort|uniq|tee|"
        r"socat|telnet|openssl|nc|ncat|netcat"
        r")\s",
        re.IGNORECASE,
    )

    # Language tags treated as shell — ALL lines in these blocks are
    # operational context, not just lines matching _SHELL_PREFIXES.
    # A ```bash block is shell by definition; we should not rely on
    # prefix-matching individual lines to recognise that.
    _SHELL_LANG_TAGS: frozenset[str] = frozenset({
        "bash", "sh", "zsh", "shell", "console", "terminal",
        "powershell", "ps1", "pwsh", "bat", "cmd",
    })

    # Patterns that are safe to skip inside fenced code blocks.
    # These paths commonly appear in legitimate infrastructure, monitoring,
    # and configuration code (Terraform, Ansible, Containerfiles, system
    # health scripts, etc.). They remain flagged in shell command lines,
    # standalone path lines, and input scanning — only code blocks are relaxed.
    _CODE_BLOCK_SAFE: frozenset[str] = frozenset({
        "/etc/passwd",   # world-readable, common in user management (Ansible, Containerfiles)
        "/proc/",        # monitoring, cgroups, system info
        "/sys/",         # sysfs, cgroups, hardware info
        ".config/",      # standard XDG config directory
        ".local/share/", # standard XDG data directory
        # .env was removed from _CODE_BLOCK_SAFE (findings #3, #31): it must be
        # flagged in ALL code contexts (including non-shell code blocks like Python
        # load_dotenv patterns). The gitignore-style listing exemption
        # (_is_ignore_file_content / _surrounding_is_ignore_listing) still
        # suppresses .env in .gitignore-type contexts independently.
    })

    # Regex for lines that look like ignore-file entries:
    # comments (#...), negations (!path), glob patterns, paths with
    # slashes/dots/stars/brackets — but NOT code syntax (parens, quotes,
    # semicolons, spaces in the middle).
    _IGNORE_ENTRY_RE = re.compile(r"^(?:#.*|!?[a-zA-Z0-9.*_/\[\]{}\-\\]+/?)$")

    def __init__(self, patterns: list[str]):
        # Finding #30: reject empty/whitespace-only patterns at init so that
        # misconfigured policy files produce a clear warning rather than
        # silently matching every position in scanned text.
        self._patterns = [p for p in patterns if p and p.strip()]
        if len(self._patterns) != len(patterns):
            logger.warning(
                "scanner=path action=init_warning removed_empty_patterns=%d",
                len(patterns) - len(self._patterns),
            )

    @staticmethod
    def _is_boundary_match(text: str, pattern: str, pos: int) -> bool:
        """Check that the match at *pos* isn't a substring of a longer word.

        Patterns ending with ``/`` (e.g. ``.ssh/``, ``/proc/``) are
        boundary-safe by definition.  For patterns without a trailing
        slash (e.g. ``.env``, ``wallet.dat``), the character immediately
        after the match must **not** be alphabetic — otherwise the match
        is part of a longer token (``environment``, ``os.environ``) and
        should be ignored.

        Finding #27 — leading boundary: if the pattern doesn't start with
        ``/``, the character immediately *before* the match must not be
        alphanumeric.  This prevents ``.env`` from matching inside tokens
        like ``X.env`` while still allowing ``/path/.env`` (``/`` before
        the dot) and ``.env`` at the very start of the string (pos == 0).
        """
        # Leading boundary check (finding #27)
        if pos > 0 and not pattern.startswith("/"):
            before = text[pos - 1]
            if before.isalnum():
                return False
        # Trailing boundary check
        if pattern.endswith("/"):
            return True
        end = pos + len(pattern)
        if end < len(text) and text[end].isalpha():
            return False
        return True

    # Regex for comma-separated items that look like file patterns
    # (globs, dotfiles, paths) — NOT code syntax.
    _FILE_PATTERN_ITEM_RE = re.compile(
        r"^[a-zA-Z0-9.*_/\[\]{}\-\\]+/?$"
    )

    @staticmethod
    def _is_in_ignore_listing(text: str, pos: int) -> bool:
        """Check if a .env match is part of a comma-separated file-pattern list.

        Returns True for prose contexts like:
            "Include entries for: venv/, __pycache__/, .env, *.pyc, dist/"
        where .env is clearly an ignore-pattern reference, not a file access.

        Conservative: requires >=3 file-pattern-like items on the same line.
        """
        line_start = text.rfind("\n", 0, pos) + 1
        line_end = text.find("\n", pos)
        if line_end == -1:
            line_end = len(text)
        line = text[line_start:line_end]

        # Split by commas and strip whitespace / trailing "and"
        items = [
            item.strip().removeprefix("and ").strip()
            for item in line.split(",")
        ]
        if len(items) < 3:
            return False

        # Count items that look like file patterns (globs, dotfiles, paths)
        pattern_like = sum(
            1 for item in items
            if SensitivePathScanner._FILE_PATTERN_ITEM_RE.match(item)
            and len(item) < 30
        )
        return pattern_like >= 3

    def scan(self, text: str) -> ScanResult:
        # R12: Normalise homoglyphs before pattern matching to catch
        # Cyrillic/accented evasion (e.g. /еtc/ѕhadow → /etc/shadow)
        text = normalise_homoglyphs(text)
        matches = []
        for pattern in self._patterns:
            idx = 0
            while True:
                pos = text.find(pattern, idx)
                if pos == -1:
                    break
                idx = pos + 1
                if not self._is_boundary_match(text, pattern, pos):
                    continue

                # .env in a comma-separated list of file patterns (e.g.
                # gitignore entries in prose) is a listing, not an access
                # attempt.  Only applies to .env — other sensitive paths
                # like /etc/shadow don't appear in ignore listings.
                if pattern == ".env" and self._is_in_ignore_listing(text, pos):
                    logger.debug("scanner=path action=suppress pattern=%s reason=ignore_listing pos=%d", pattern, pos)
                    continue

                matches.append(
                    ScanMatch(
                        pattern_name="sensitive_path",
                        matched_text=pattern,
                        position=pos,
                    )
                )
                logger.debug("scanner=path action=flag pattern=%s pos=%d", pattern, pos)
        return ScanResult(
            found=len(matches) > 0,
            matches=matches,
            scanner_name="sensitive_path_scanner",
        )

    @staticmethod
    def _strip_outer_fence(text: str) -> str:
        """Strip an outer code fence that wraps the entire response.

        Qwen sometimes wraps its full output in a code fence (```markdown,
        ```md, ```text, ```plain, ```html, or bare ```), which causes the
        code-block detection regex to mismatch inner fences (the outer
        opening pairs with the first inner closing).  Stripping the wrapper
        normalises the text for correct inner-block parsing.
        """
        stripped = text.lstrip()
        # Match opening fence: ``` optionally followed by a tag and newline
        m = re.match(r"^```(\w*)\s*\n", stripped)
        if not m:
            return text
        tag = m.group(1).lower()
        # Only strip wrapper fences — not code fences for real languages.
        # A ```python block IS the code, not a wrapper around it.
        wrapper_tags = {"", "markdown", "md", "text", "plain", "html"}
        if tag not in wrapper_tags:
            return text
        inner = stripped[m.end():]
        # The closing ``` must be at the very end (possibly trailing whitespace).
        # Strip trailing whitespace before checking, then remove the fence marker
        # and any newline that immediately preceded it.
        inner_stripped = inner.rstrip()
        if inner_stripped.endswith("```"):
            return inner_stripped[:-3].rstrip("\n")
        return text

    @staticmethod
    def _is_ignore_file_content(block_text: str) -> bool:
        """Heuristic: does this code block look like an ignore-file listing?

        Returns True if >=80% of non-empty lines match the ignore-file entry
        pattern (paths, globs, comments, negations — no code syntax like
        parens, quotes, or semicolons). Requires at least 2 non-empty lines.
        """
        lines = [ln for ln in block_text.splitlines() if ln.strip()]
        if len(lines) < 2:
            return False
        matching = sum(
            1 for ln in lines
            if SensitivePathScanner._IGNORE_ENTRY_RE.match(ln.strip())
        )
        return matching / len(lines) >= 0.8

    @classmethod
    def _surrounding_is_ignore_listing(cls, text: str, pos: int) -> bool:
        """Check if the lines surrounding *pos* form an ignore-file listing.

        Used for .env matches that appear as standalone lines outside
        fenced code blocks (e.g. inside XML-tagged <CONTAINERIGNORE>
        sections).  Examines up to 5 lines before and after *pos* and
        returns True if the group looks like an ignore-file listing
        (≥3 non-empty lines, ≥80% matching the ignore-entry pattern).
        """
        # Collect nearby lines (up to 5 before + 5 after the current line)
        all_lines = text.splitlines(True)
        # Find which line index 'pos' falls on
        offset = 0
        line_idx = 0
        for i, ln in enumerate(all_lines):
            if offset + len(ln) > pos:
                line_idx = i
                break
            offset += len(ln)

        # Window tightened (#25): ±3 lines (was ±5) to avoid nearby prose
        # lines pulling a sparse listing over the threshold.
        start = max(0, line_idx - 3)
        end = min(len(all_lines), line_idx + 4)
        # Exclude XML/HTML wrapper tags (e.g. <CONTAINERIGNORE>) — they are
        # structural markers in worker responses, not content.
        nearby = [
            ln.strip() for ln in all_lines[start:end]
            if ln.strip() and not re.match(r"^</?[A-Za-z][\w-]*>$", ln.strip())
        ]

        if len(nearby) < 3:
            return False
        matching = sum(
            1 for ln in nearby if cls._IGNORE_ENTRY_RE.match(ln)
        )
        # Threshold raised (#25): 85% (was 80%) to reduce FNs in sparse contexts.
        return matching / len(nearby) >= 0.85

    @staticmethod
    def _get_enclosing_block(
        pos: int,
        code_block_ranges: list[tuple[int, int]],
        text: str,
    ) -> str | None:
        """Return the text of the code block enclosing *pos*, or None."""
        for start, end in code_block_ranges:
            if start <= pos < end:
                return text[start:end]
        return None

    def scan_output_text(self, text: str, strict: bool = False) -> ScanResult:
        """Context-aware output scan: only flag paths in operational context.

        Paths in fenced code blocks, shell command lines, or standalone
        path-only lines are flagged. Paths embedded in natural-language
        prose (e.g. "cgroups use /proc/cgroups") are considered educational
        and pass through.

        Args:
            text: The text to scan for sensitive path references.
            strict: When True, disable prose/educational exemptions
                (markdown lists, explanatory prose, YAML config, prose
                fallthrough). Structural exemptions (_CODE_BLOCK_SAFE,
                ignore-file listings) still apply.
        """
        from sentinel.security.context_classifier import (
            build_code_blocks, build_indented_ranges, classify, prepare_text,
        )

        text = prepare_text(text, self._strip_outer_fence)
        matches = []

        # Build context structures from the classifier module
        code_blocks = build_code_blocks(text)
        indented_ranges = build_indented_ranges(text)

        # Backward-compatible ranges for _get_enclosing_block
        code_block_ranges: list[tuple[int, int]] = [
            (b.content_start, b.content_end) for b in code_blocks
        ]

        for pattern in self._patterns:
            idx = 0
            while True:
                pos = text.find(pattern, idx)
                if pos == -1:
                    break
                idx = pos + 1

                # Word-boundary check: skip if the match is part of a longer
                # token (e.g. ".env" inside "environment" or "os.environ").
                if not self._is_boundary_match(text, pattern, pos):
                    continue

                # Classify the context at this position
                ctx = classify(text, pos, code_blocks, indented_ranges)

                # ── Fenced code block ─────────────────────────────
                # Only treat as fenced if pos is within the content range
                # (content_start..content_end), not on the fence line itself.
                # This preserves the original behaviour where only content
                # positions were considered "in a code block".
                in_code_block = any(
                    b.content_start <= pos < b.content_end
                    for b in code_blocks
                )

                if ctx.kind == "fenced_code" and in_code_block:
                    # Shell context: language tag OR shell prefix on line
                    is_shell = (
                        ctx.language in self._SHELL_LANG_TAGS
                        or self._SHELL_PREFIXES.match(ctx.line) is not None
                    )

                    if is_shell:
                        # Shell context inside code block: flag UNLESS
                        # the pattern is in _CODE_BLOCK_SAFE.
                        if pattern in self._CODE_BLOCK_SAFE:
                            logger.debug("scanner=path_output action=suppress pattern=%s reason=code_block_safe_shell", pattern)
                            continue
                        matches.append(ScanMatch(
                            pattern_name="sensitive_path",
                            matched_text=pattern,
                            position=pos,
                        ))
                        logger.debug("scanner=path_output action=flag pattern=%s pos=%d", pattern, pos)
                        continue

                    # Non-shell code: all _CODE_BLOCK_SAFE patterns are exempt
                    if pattern in self._CODE_BLOCK_SAFE:
                        logger.debug("scanner=path_output action=suppress pattern=%s reason=code_block_safe", pattern)
                        continue

                    # .env patterns inside ignore-file listings (gitignore,
                    # containerignore, etc.) are specifying exclusion patterns,
                    # not accessing the file. Skip if the entire block looks
                    # like an ignore-file listing.
                    if ".env" in pattern:
                        block_text = self._get_enclosing_block(
                            pos, code_block_ranges, text,
                        )
                        if block_text and self._is_ignore_file_content(block_text):
                            logger.debug("scanner=path_output action=suppress pattern=%s reason=ignore_file_block", pattern)
                            continue

                    matches.append(ScanMatch(
                        pattern_name="sensitive_path",
                        matched_text=pattern,
                        position=pos,
                    ))
                    logger.debug("scanner=path_output action=flag pattern=%s pos=%d", pattern, pos)
                    continue

                # ── Shell command outside code block ──────────────
                # The classifier uses CMD_LINE_PREFIX for cmd_line detection,
                # but SensitivePathScanner uses _SHELL_PREFIXES (different
                # command set). Check _SHELL_PREFIXES directly on the line
                # regardless of ctx.kind to preserve exact behaviour — a line
                # like "# comment" matches _SHELL_PREFIXES but not
                # CMD_LINE_PREFIX, so the classifier may return "prose" for it.
                if self._SHELL_PREFIXES.match(ctx.line):
                    # Flag unless pattern is _CODE_BLOCK_SAFE and Dockerfile
                    # instructions are nearby. Qwen sometimes outputs
                    # Containerfiles without code fences, and comment lines
                    # (# ...) match _SHELL_PREFIXES.
                    # Locality fix (#22): only exempt if Dockerfile instructions
                    # are within ±15 lines of the match, not anywhere in the
                    # full text. This prevents a Dockerfile at the top of the
                    # output from exempting shell lines dozens of lines later.
                    if pattern in self._CODE_BLOCK_SAFE:
                        lines = text.splitlines(True)
                        match_line_idx = text[:pos].count("\n")
                        start_idx = max(0, match_line_idx - 15)
                        end_idx = min(len(lines), match_line_idx + 16)
                        nearby = "".join(lines[start_idx:end_idx])
                        if CommandPatternScanner._is_dockerfile_content(nearby):
                            logger.debug("scanner=path_output action=suppress pattern=%s reason=dockerfile_context", pattern)
                            continue
                    matches.append(ScanMatch(
                        pattern_name="sensitive_path",
                        matched_text=pattern,
                        position=pos,
                    ))
                    logger.debug("scanner=path_output action=flag pattern=%s pos=%d", pattern, pos)
                    continue

                # ── Indented code / prose / unmatched cmd_line ────
                # Indented code without shell prefix and cmd_line lines that
                # didn't match _SHELL_PREFIXES fall through to prose heuristics.
                # This preserves exact pre-refactor behaviour where the scanner
                # only checked fenced blocks and _SHELL_PREFIXES.

                # Standalone path-only line (just whitespace + path)
                line = ctx.line
                line_start = ctx.line_start
                stripped = line.strip()
                if stripped == pattern or stripped == pattern.rstrip("/"):
                    # .env on its own line inside an ignore-file listing
                    # (e.g. .containerignore, .gitignore content not in a
                    # fenced code block) is an exclusion pattern, not access.
                    if ".env" in pattern and self._surrounding_is_ignore_listing(
                        text, pos,
                    ):
                        logger.debug("scanner=path_output action=suppress pattern=%s reason=standalone_ignore_listing", pattern)
                        continue
                    matches.append(ScanMatch(
                        pattern_name="sensitive_path",
                        matched_text=pattern,
                        position=pos,
                    ))
                    logger.debug("scanner=path_output action=flag pattern=%s pos=%d", pattern, pos)
                    continue

                # Educational/prose heuristics — disabled in strict mode.
                # Strict mode only affects these prose exemptions; structural
                # exemptions (_CODE_BLOCK_SAFE, ignore-file listings) above
                # still apply regardless.
                if not strict:
                    # ── Markdown list item ────────────────────────────
                    # Tightened (#23): require ≥20 chars after the pattern
                    # (was 5). Short items like "- /etc/shadow: yes" are
                    # flagged. When a list item is detected, only this rule
                    # applies — the explanatory-prose and YAML checks below
                    # are skipped entirely so ": yes" can't rescue short items.
                    if re.match(r"^\s*[-*]\s+", line):
                        if len(stripped) > len(pattern) + 20:
                            logger.debug("scanner=path_output action=suppress pattern=%s reason=markdown_list", pattern)
                            continue
                        # Short markdown list item — falls through to flagging.
                        # Skip remaining prose heuristics for this line.

                    else:
                        # ── Non-list prose heuristics ─────────────────
                        # Path followed by explanatory text (e.g. "— stores …")
                        path_end = pos + len(pattern) - line_start
                        after_path = stripped[path_end:].strip() if path_end < len(stripped) else ""
                        if after_path and re.match(r"^[—–\-:]\s+\w", after_path):
                            logger.debug("scanner=path_output action=suppress pattern=%s reason=explanatory_prose", pattern)
                            continue

                        # YAML/HCL config context (indented key: value).
                        # Tightened (#24): require ≥2 indented key: value lines
                        # within ±200 chars. A lone "  key: /path" is flagged;
                        # a genuine multi-key block is exempt.
                        if re.match(r"^\s+\w[\w_-]*\s*:", line):
                            yaml_re = re.compile(r"^\s+\w[\w_-]*\s*:", re.MULTILINE)
                            nearby_start = max(0, text.rfind("\n", 0, max(0, pos - 200)) + 1)
                            nearby_end = min(len(text), pos + 200)
                            nearby_yaml = text[nearby_start:nearby_end]
                            if len(yaml_re.findall(nearby_yaml)) >= 2:
                                logger.debug("scanner=path_output action=suppress pattern=%s reason=yaml_config", pattern)
                                continue
                            # Single yaml-ish line — falls through to flagging.
                            # Skip the generic prose suppression below.

                        else:
                            # Generic prose context — path in running text
                            logger.debug("scanner=path_output action=suppress pattern=%s reason=prose_context", pattern)
                            continue

                # Strict mode: flag everything in prose that wasn't caught
                # by structural exemptions above.
                matches.append(ScanMatch(
                    pattern_name="sensitive_path",
                    matched_text=pattern,
                    position=pos,
                ))
                logger.debug("scanner=path_output action=flag pattern=%s reason=strict_mode pos=%d", pattern, pos)

        return ScanResult(
            found=len(matches) > 0,
            matches=matches,
            scanner_name="sensitive_path_scanner",
        )


class CommandPatternScanner:
    """Regex-based scanner for dangerous command patterns in text.

    Detects pipe-to-shell, reverse shells, base64 decode+exec,
    netcat listeners, nohup, chmod +x, cron injection, and similar
    attack patterns that Qwen might output in prose or code.
    """

    _DEFAULT_PATTERNS: list[tuple[str, re.Pattern]] = [
        # Pipe-to-shell: curl/wget output piped (through any number of
        # intermediate stages such as gunzip, zcat, tar) to sh/bash (#32).
        # The flexible multi-pipe form catches: curl ... | bash,
        # curl ... | gunzip | bash, wget ... | tar xz | bash, etc.
        ("pipe_to_shell", re.compile(
            r"(curl|wget)\s+.*\|\s*(?:.*\|\s*)*(?:ba)?sh\b",
            re.IGNORECASE,
        )),
        # Reverse shell: bash -i >& /dev/tcp/...
        ("reverse_shell_tcp", re.compile(
            r"/dev/tcp/", re.IGNORECASE,
        )),
        # Reverse shell: bash -i >& ...
        ("reverse_shell_bash", re.compile(
            r"bash\s+-i\s+>&", re.IGNORECASE,
        )),
        # Netcat listener/reverse shell (#33).
        # Catches: -e /bin/sh (space), -e/bin/sh (no space), --exec, exec
        ("netcat_shell", re.compile(
            r"(nc|ncat|netcat)\s+.*(-e\s*\S|--exec\s+|exec\s+)", re.IGNORECASE,
        )),
        # Base64 decode piped to execution
        ("base64_exec", re.compile(
            r"base64\s+(-d|--decode)\s*\|", re.IGNORECASE,
        )),
        # Long base64-encoded strings (likely encoded payloads)
        ("encoded_payload", re.compile(
            r"[A-Za-z0-9+/]{100,}={0,2}",
        )),
        # nohup (dangerous regardless of background)
        ("nohup_background", re.compile(
            r"nohup\s+\S+", re.IGNORECASE,
        )),
        # chmod setuid/setgid (privilege escalation)
        ("chmod_setuid", re.compile(
            r"chmod\s+[ugo]*\+[rwx]*s|chmod\s+[2467]\d{3}\s+", re.IGNORECASE,
        )),
        # chmod world-writable (insecure permissions)
        ("chmod_world_writable", re.compile(
            r"chmod\s+(777|666|o\+w)\s+", re.IGNORECASE,
        )),
        # Cron injection
        ("cron_injection", re.compile(
            r"(crontab|/etc/cron)", re.IGNORECASE,
        )),
        # eval/exec with shell commands
        ("eval_exec_shell", re.compile(
            r"\b(eval|exec)\s+[\"']?(\$\(|`|bash|sh\s)", re.IGNORECASE,
        )),
        # curl/wget downloading to file then executing
        ("download_execute", re.compile(
            r"(curl|wget)\s+.*-[oO]\s*\S+.*&&.*(\./|bash|sh|chmod)", re.IGNORECASE,
        )),
        # Python/perl/ruby reverse shells — require socket+connect AND a shell
        # invocation. Legitimate networking code uses sockets without spawning
        # shells. The other reverse shell patterns cover bash/netcat/mkfifo.
        ("scripting_reverse_shell", re.compile(
            r"(python|perl|ruby).*socket.*connect.*(?:subprocess|os\.system|os\.popen|os\.dup2|pty\.spawn|exec\()",
            re.IGNORECASE | re.DOTALL,
        )),
        # PowerShell encoded commands — base64 payload execution.
        # Matches: powershell -EncodedCommand <b64>, powershell -enc <b64>,
        # powershell -e <b64>. The base64 payload must be ≥10 chars to avoid
        # false positives on short flag combinations.
        ("powershell_encoded", re.compile(
            r"powershell(?:\.exe)?\s+.*(?:-e(?:nc(?:oded)?(?:c(?:ommand)?)?)?)\s+[A-Za-z0-9+/=]{10,}",
            re.IGNORECASE,
        )),
        # PowerShell IEX / Invoke-Expression — download-and-execute pattern.
        # Requires both the IEX/Invoke-Expression invocation AND a network
        # retrieval method (WebClient, curl, wget, DownloadString/File).
        ("powershell_iex", re.compile(
            r"(?:IEX|Invoke-Expression)\s*[\(\s].*(?:Net\.WebClient|Invoke-WebRequest|curl|wget|DownloadString|DownloadFile)",
            re.IGNORECASE | re.DOTALL,
        )),
        # PHP reverse shell — fsockopen combined with a shell execution call.
        # Legitimate PHP uses fsockopen for HTTP/API calls, never paired with
        # exec/shell_exec/system/passthru for interactive shell spawning.
        ("php_reverse_shell", re.compile(
            r"fsockopen\s*\(.*(?:exec|shell_exec|system|passthru|popen)\s*\(",
            re.IGNORECASE | re.DOTALL,
        )),
        # socat reverse shell — exec: payload with tcp: redirect.
        # Legitimate socat usage rarely combines exec: with a tcp: connection.
        ("socat_shell", re.compile(
            r"socat\s+.*exec:.*tcp:", re.IGNORECASE,
        )),
        # telnet pipe shell — telnet piped into a shell interpreter.
        # Normal telnet usage does not pipe output directly to /bin/sh or bash.
        ("telnet_shell", re.compile(
            r"telnet\s+\S+\s+\d+\s*\|.*(?:/bin/(?:ba)?sh|bash)",
            re.IGNORECASE,
        )),
        # openssl encrypted reverse shell — s_client used as a covert channel.
        # Legitimate openssl s_client is used for TLS testing, not tunnelling
        # shell I/O. The -connect flag with host:port in a pipeline is the tell.
        ("openssl_shell", re.compile(
            r"openssl\s+s_client\s+.*-connect\s+\S+:\d+",
            re.IGNORECASE,
        )),
        # mkfifo for named pipe reverse shells
        ("mkfifo_shell", re.compile(
            r"mkfifo\s+.*(nc|ncat|netcat|bash)", re.IGNORECASE,
        )),
        # rm with -r/-f flags targeting root, home, or variable paths
        # Catches: rm -rf /, rm -f ~/, rm -Rf $DIR, rm -rf /var/cache/apt/*
        # Does NOT catch: rm file.txt, rm -i temp
        ("dangerous_rm", re.compile(
            r"rm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+(/[^\s]*|\$\w*|~[^\s]*)",
            re.IGNORECASE,
        )),
    ]

    def __init__(self, extra_patterns: list[dict] | None = None):
        self._patterns = list(self._DEFAULT_PATTERNS)
        if extra_patterns:
            for entry in extra_patterns:
                name = entry["name"]
                raw = entry["pattern"]
                self._patterns.append((name, re.compile(raw)))

    # Dockerfile/Containerfile language tags where rm -rf cache cleanup is safe
    _DOCKERFILE_TAGS = frozenset({"dockerfile", "containerfile", "docker"})

    # rm targets that are safe cache/temp cleanup in Dockerfiles
    _DOCKERFILE_SAFE_RM_TARGETS = re.compile(
        r"/var/cache/|/var/lib/apt/|/var/lib/dpkg/|/tmp/|/var/tmp/"
        r"|/root/\.cache/|/var/log/"
    )

    # Dockerfile instruction keywords for content-based detection.
    # Used as fallback when no language tag is present on the code fence
    # (or when content is outside a code fence entirely).
    _DOCKERFILE_INSTRUCTION_RE = re.compile(
        r"^\s*(?:FROM|RUN|COPY|ADD|ENTRYPOINT|CMD|EXPOSE|ENV|ARG|"
        r"WORKDIR|USER|VOLUME|LABEL|HEALTHCHECK|ONBUILD|STOPSIGNAL|SHELL)\s",
        re.MULTILINE | re.IGNORECASE,
    )

    # Build-file language tags where rm in clean targets is standard practice
    _BUILD_FILE_TAGS = frozenset({"makefile", "make", "cmake"})

    # Build-file instruction keywords for content-based detection.
    # Makefiles: .PHONY, target: deps, define/endef, ifeq/ifdef
    _BUILD_FILE_INSTRUCTION_RE = re.compile(
        r"^\s*(?:\.PHONY|\.SUFFIXES|\.DEFAULT|\.PRECIOUS|\.SECONDARY"
        r"|define\s|endef|ifeq\s|ifneq\s|ifdef\s|ifndef\s|endif"
        r"|include\s|-include\s|sinclude\s|override\s|export\s|unexport\s"
        r"|vpath\s)\s*",
        re.MULTILINE | re.IGNORECASE,
    )

    # Makefile target rule pattern: word: (optional deps) — but not URLs (://)
    _MAKEFILE_TARGET_RE = re.compile(
        r"^[a-zA-Z_][a-zA-Z0-9_./-]*\s*:(?!//)",
        re.MULTILINE,
    )

    # dangerous_rm targets that are safe in build files: shell variables like
    # $(VAR) or $VAR (build artifact references), NOT absolute paths or ~/
    _BUILD_FILE_SAFE_RM_TARGET = re.compile(r"rm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+\$")

    # <RESPONSE>/<think> tags that Qwen wraps around output — strip before
    # content-based detection so tags on the same line as FROM/RUN don't
    # prevent the instruction regex from matching (e.g. "<RESPONSE>FROM ...").
    _RESPONSE_TAG_RE = re.compile(r"</?(?:RESPONSE|think)>", re.IGNORECASE)

    @classmethod
    def _is_dockerfile_content(cls, text: str) -> bool:
        """Heuristic: does *text* look like Dockerfile/Containerfile content?

        Returns True if the text contains a ``FROM`` instruction AND at least
        one other Dockerfile instruction (RUN, COPY, etc.).  This avoids
        false positives on generic text that happens to contain "FROM".

        Strips ``<RESPONSE>`` / ``<think>`` wrapper tags before checking,
        because Qwen sometimes places them on the same line as the first
        instruction (e.g. ``<RESPONSE>FROM python:3.12``), which prevents
        the line-anchored instruction regex from matching.
        """
        cleaned = cls._RESPONSE_TAG_RE.sub("", text)
        instructions = cls._DOCKERFILE_INSTRUCTION_RE.findall(cleaned)
        if len(instructions) < 2:
            return False
        # Must have FROM — every valid Dockerfile starts with one
        return any(instr.strip().upper().startswith("FROM") for instr in instructions)

    @classmethod
    def _is_build_file_content(cls, text: str) -> bool:
        """Heuristic: does *text* look like a Makefile or build script?

        Returns True if the text contains a Makefile directive (.PHONY, etc.)
        OR at least one target rule (``word: deps``).  Requires a directive
        or two target rules to avoid false positives on prose containing colons.
        """
        if cls._BUILD_FILE_INSTRUCTION_RE.search(text):
            return True
        # Fallback: two or more target-like rules
        return len(cls._MAKEFILE_TARGET_RE.findall(text)) >= 2

    def _is_safe_rm_in_build_context(
        self,
        name: str,
        match_text: str,
        block_lang: str,
        content: str,
    ) -> bool:
        """Check if a dangerous_rm match is safe due to Dockerfile/Makefile context.

        Args:
            name: Pattern name (only "dangerous_rm" is eligible for exemption).
            match_text: The matched text from the regex hit.
            block_lang: Language tag of the enclosing code block ("" if none).
            content: The surrounding text to check for build-file heuristics.
        """
        if name != "dangerous_rm":
            return False

        # Dockerfile exemption: rm targeting cache/temp dirs in Dockerfile context
        if self._DOCKERFILE_SAFE_RM_TARGETS.search(match_text):
            if block_lang in self._DOCKERFILE_TAGS:
                return True
            # Content-based detection: run regardless of fence tag.
            # Qwen non-deterministically tags Containerfile output as "bash".
            # A real bash script won't have FROM + RUN + COPY instructions,
            # so the heuristic is still discriminating.
            if self._is_dockerfile_content(content):
                return True

        # Build-file exemption: rm targeting variables in Makefile context
        if self._BUILD_FILE_SAFE_RM_TARGET.search(match_text):
            if block_lang in self._BUILD_FILE_TAGS:
                return True
            # Content-based detection: run regardless of fence tag.
            # Same rationale as Dockerfile — Qwen may tag Makefiles as "bash".
            if self._is_build_file_content(content):
                return True
            # Variable-targeted rm in ANY code block is safe — the scanner
            # can't evaluate what shell variables contain, and `rm -rf $DIR`
            # is a standard cleanup pattern in bash/shell scripts, CI/CD
            # runners, setup scripts, etc. The dangerous patterns are
            # hardcoded paths (/etc, ~/) which are caught separately.
            # Only applies inside a fenced code block (block_lang non-empty)
            # to avoid exempting unfenced prose with variable-rm patterns.
            if block_lang:
                return True

        return False

    def scan(self, text: str) -> ScanResult:
        text = normalise_homoglyphs(text)
        matches = []
        for name, pattern in self._patterns:
            for match in pattern.finditer(text):
                matches.append(
                    ScanMatch(
                        pattern_name=name,
                        matched_text=match.group(),
                        position=match.start(),
                    )
                )
                logger.debug("scanner=cmd action=flag pattern=%s text=%.80s", name, match.group())
        return ScanResult(
            found=len(matches) > 0,
            matches=matches,
            scanner_name="command_pattern_scanner",
        )

    def scan_output_text(self, text: str, strict: bool = False) -> ScanResult:
        """Context-aware output scan: only flag commands in code regions.

        Dangerous command patterns in prose (e.g. refusal explanations,
        educational content) are not flagged — only patterns inside
        fenced code blocks, indented code, or shell-prompt lines.

        Dockerfile awareness: ``dangerous_rm`` matches inside code blocks
        tagged as ``dockerfile``/``containerfile``/``docker`` are exempt
        when the rm target is a standard cache/temp directory (e.g.
        ``rm -rf /var/cache/apt/*``).

        Args:
            text: Raw output text to scan.
            strict: When True, flag commands in prose context instead
                of suppressing. Structural exemptions (safe rm in build
                context) still apply.
        """
        from sentinel.security.context_classifier import (
            build_code_blocks, build_indented_ranges, classify, prepare_text,
        )

        text = prepare_text(text, SensitivePathScanner._strip_outer_fence)
        code_blocks = build_code_blocks(text)
        indented_ranges = build_indented_ranges(text)

        matches: list[ScanMatch] = []
        for name, pattern in self._patterns:
            for match in pattern.finditer(text):
                pos = match.start()
                ctx = classify(text, pos, code_blocks, indented_ranges)

                if ctx.kind == "fenced_code":
                    # Dockerfile/Containerfile safe-rm exemption
                    if self._is_safe_rm_in_build_context(
                        name, match.group(), ctx.language, ctx.block_content,
                    ):
                        logger.debug("scanner=cmd_output action=suppress pattern=%s reason=safe_rm_build text=%.80s", name, match.group())
                        continue
                    matches.append(ScanMatch(
                        pattern_name=name,
                        matched_text=match.group(),
                        position=pos,
                    ))
                    logger.debug("scanner=cmd_output action=flag pattern=%s context=fenced text=%.80s", name, match.group())
                    continue

                if ctx.kind == "indented_code":
                    if self._is_safe_rm_in_build_context(
                        name, match.group(), "", text,
                    ):
                        logger.debug("scanner=cmd_output action=suppress pattern=%s reason=safe_rm_build text=%.80s", name, match.group())
                        continue
                    matches.append(ScanMatch(
                        pattern_name=name,
                        matched_text=match.group(),
                        position=pos,
                    ))
                    logger.debug("scanner=cmd_output action=flag pattern=%s context=indented text=%.80s", name, match.group())
                    continue

                if ctx.kind == "cmd_line":
                    if self._is_safe_rm_in_build_context(
                        name, match.group(), "", text,
                    ):
                        logger.debug("scanner=cmd_output action=suppress pattern=%s reason=safe_rm_build text=%.80s", name, match.group())
                        continue
                    matches.append(ScanMatch(
                        pattern_name=name,
                        matched_text=match.group(),
                        position=pos,
                    ))
                    logger.debug("scanner=cmd_output action=flag pattern=%s context=cmd_line text=%.80s", name, match.group())
                    continue

                # Prose context — suppress in normal mode, flag in strict
                if strict:
                    matches.append(ScanMatch(
                        pattern_name=name,
                        matched_text=match.group(),
                        position=pos,
                    ))
                    logger.debug("scanner=cmd_output action=flag pattern=%s reason=strict_mode text=%.80s", name, match.group())
                else:
                    logger.debug("scanner=cmd_output action=suppress pattern=%s reason=prose_context text=%.80s", name, match.group())

        return ScanResult(
            found=len(matches) > 0,
            matches=matches,
            scanner_name="command_pattern_scanner",
        )


class VulnerabilityEchoScanner:
    """Compares vulnerability fingerprints between input and output.

    Detects when Qwen reproduces vulnerable code patterns from the user's
    input instead of fixing them.  Only flags matches in output code blocks
    (fenced or 4-space indented) to avoid FPs on educational prose.
    """

    _FINGERPRINTS: list[tuple[re.Pattern, str]] = [
        # Python dangerous calls
        (re.compile(r"\beval\s*\("), "python_eval"),
        (re.compile(r"\bexec\s*\("), "python_exec"),
        (re.compile(r"\bos\.system\s*\("), "python_os_system"),
        (re.compile(r"\bos\.popen\s*\("), "python_os_popen"),
        (re.compile(r"\bsubprocess\.call\([^)]*shell\s*=\s*True"), "python_subprocess_shell"),
        (re.compile(r"\bpickle\.loads?\s*\("), "python_pickle"),
        (re.compile(r"\byaml\.load\s*\((?!.*Loader)[^)]*\)"), "python_yaml_unsafe"),
        (re.compile(r"__import__\s*\("), "python_import"),
        # JavaScript
        (re.compile(r"\bchild_process\.exec\s*\("), "js_child_process"),
        (re.compile(r"\.innerHTML\s*="), "js_innerhtml"),
        # SQL injection
        (re.compile(r"['\"]?\s*(?:OR|AND)\s+\d+\s*=\s*\d+", re.IGNORECASE), "sql_injection"),
        (re.compile(r"\bUNION\s+SELECT\b", re.IGNORECASE), "sql_union"),
        (re.compile(r";\s*DROP\s+TABLE\b", re.IGNORECASE), "sql_drop"),
        # General
        (re.compile(r"\bdeserialize\s*\("), "deserialization"),
        # Python — expanded dangerous calls
        (re.compile(r"\bsubprocess\.run\([^)]*shell\s*=\s*True"), "python_subprocess_run_shell"),
        (re.compile(r"\bsubprocess\.Popen\s*\("), "python_subprocess_popen"),
        (re.compile(r"\bos\.dup2\s*\("), "python_os_dup2"),
        (re.compile(r"\bos\.exec[lvpe]+\s*\("), "python_os_exec"),
        (re.compile(r"\bos\.spawn[lvpe]*\s*\("), "python_os_spawn"),
        (re.compile(r"\bcommands\.(getoutput|getstatusoutput)\s*\("), "python_commands"),
        # JavaScript — expanded
        (re.compile(r"\bnew\s+Function\s*\("), "js_new_function"),
        (re.compile(r"\bdocument\.write\s*\("), "js_document_write"),
        (re.compile(r"\bwindow\.location\s*="), "js_location_assign"),
        # Path traversal
        (re.compile(r"\.\./\.\./"), "path_traversal"),
        # SSRF indicators
        (re.compile(r"(?:urllib|requests|http\.client|fetch)\s*[\.(].*(?:127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254)", re.DOTALL), "ssrf_local"),
        # XXE — entity declaration in XML (#39)
        (re.compile(r"<!ENTITY\s", re.IGNORECASE), "xxe_entity"),
        # YAML unsafe deserialisation (#42): yaml.unsafe_load bypasses the
        # safe Loader restriction and is equivalent to pickle for untrusted input.
        (re.compile(r"\byaml\.unsafe_load\s*\("), "python_yaml_unsafe_load"),
    ]

    # 4-space/tab indented lines (fenced blocks handled by module-level _CODE_FENCE_RE)
    _INDENTED_LINE_RE = re.compile(r"^(?:    |\t).+", re.MULTILINE)

    def __init__(self) -> None:
        pass

    def _extract_code_regions(self, text: str) -> str:
        """Extract text from code blocks and indented lines.

        Uses the module-level _CODE_FENCE_RE for fenced blocks so that fence
        detection is consistent across all scanners.  group(1) is the language
        tag; group(2) is the block content.
        """
        parts: list[str] = []
        for m in _CODE_FENCE_RE.finditer(text):
            parts.append(m.group(2))  # group(2) is content in _CODE_FENCE_RE
        for m in self._INDENTED_LINE_RE.finditer(text):
            parts.append(m.group(0))
        return "\n".join(parts)

    def _find_fingerprints(self, text: str) -> set[str]:
        """Return the set of vulnerability fingerprint names found in text."""
        found: set[str] = set()
        for pattern, name in self._FINGERPRINTS:
            if pattern.search(text):
                found.add(name)
        return found

    def scan(self, input_text: str, output_text: str) -> ScanResult:
        """Compare vulnerability fingerprints between input and output.

        Only flags fingerprints that appear in BOTH the input AND the output's
        code regions. If a fingerprint is in the input but not in the output
        code, it means Qwen fixed the vulnerability (legitimate).
        """
        input_text = normalise_homoglyphs(input_text)
        output_text = normalise_homoglyphs(output_text)
        input_fps = self._find_fingerprints(input_text)
        if not input_fps:
            return ScanResult(found=False, scanner_name="vulnerability_echo_scanner")

        logger.debug("scanner=vuln_echo input_fingerprints=%s", sorted(input_fps))

        # Only check output code regions — prose mentions shouldn't trigger
        output_code = self._extract_code_regions(output_text)
        output_fps = self._find_fingerprints(output_code)

        echoed = input_fps & output_fps
        if not echoed:
            return ScanResult(found=False, scanner_name="vulnerability_echo_scanner")

        logger.debug("scanner=vuln_echo action=flag echoed=%s", sorted(echoed))

        matches = [
            ScanMatch(
                pattern_name=f"vuln_echo:{fp}",
                matched_text=fp,
            )
            for fp in sorted(echoed)
        ]
        return ScanResult(
            found=True,
            matches=matches,
            scanner_name="vulnerability_echo_scanner",
        )


class EncodingNormalizationScanner:
    """Decodes common encodings and re-scans with existing scanners.

    Only flags when a decoded variant triggers an inner scanner pattern.
    This catches base64, hex, URL encoding, ROT13, HTML entities, and
    character splitting used to hide dangerous payloads from regex scanners.
    """

    # Base64 candidates: 16+ chars from the base64 alphabet, optional padding
    _BASE64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
    # Hex candidates: 16+ hex chars, even length
    _HEX_RE = re.compile(r"[0-9a-fA-F]{16,}")
    # URL encoding: at least one %XX sequence
    _URL_ENCODED_RE = re.compile(r"%[0-9a-fA-F]{2}")
    # HTML entities: numeric (&#123;) or named (&amp;)
    _HTML_ENTITY_RE = re.compile(r"&#\d+;|&#x[0-9a-fA-F]+;|&[a-z]+;", re.IGNORECASE)
    # Char splitting: 4+ single characters separated by spaces or tabs (#46).
    # Catches both "c a t /etc" (space-separated) and "c\ta\tt" (tab-separated)
    # and mixed variants used to evade space-only regex matchers.
    _CHAR_SPLIT_RE = re.compile(r"(?:^|\s)((?:\S[ \t]){3,}\S)(?:\s|$)")
    # Unicode escape patterns: \uXXXX, \xXX, \NNN (octal)
    _UNICODE_ESCAPE_RE = re.compile(
        r"(?:\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|\\[0-3]?[0-7]{1,2})"
    )

    # Minimum printable characters for a decoded result to be considered valid
    _MIN_PRINTABLE = 4

    def __init__(
        self,
        cred_scanner: "CredentialScanner",
        path_scanner: "SensitivePathScanner",
        cmd_scanner: "CommandPatternScanner",
    ):
        self._cred_scanner = cred_scanner
        self._path_scanner = path_scanner
        self._cmd_scanner = cmd_scanner

    def scan(self, text: str) -> ScanResult:
        """Decode text through all encodings and re-scan decoded variants."""
        return self._scan_internal(text, output_mode=False)

    def scan_output_text(self, text: str, strict: bool = False) -> ScanResult:
        """Like scan() but uses context-aware path scanning for output."""
        return self._scan_internal(text, output_mode=True, strict=strict)

    def _scan_internal(self, text: str, output_mode: bool, strict: bool = False) -> ScanResult:
        """Core scan logic shared by scan() and scan_output_text()."""
        decoded_variants = self._decode_all(text)
        if not decoded_variants:
            return ScanResult(found=False, scanner_name="encoding_normalization_scanner")

        all_matches: list[ScanMatch] = []
        for encoding_name, decoded_text in decoded_variants:
            logger.debug("scanner=encoding decoded=%s length=%d", encoding_name, len(decoded_text))
            # Run all 3 inner scanners on each decoded variant.
            # In output mode, use context-aware scanning for path and
            # command scanners (only flag patterns in code regions).
            cred_result = self._cred_scanner.scan(decoded_text)
            if output_mode:
                path_result = self._path_scanner.scan_output_text(decoded_text, strict=strict)
                cmd_result = self._cmd_scanner.scan_output_text(decoded_text, strict=strict)
            else:
                path_result = self._path_scanner.scan(decoded_text)
                cmd_result = self._cmd_scanner.scan(decoded_text)

            for inner_result in (cred_result, path_result, cmd_result):
                for match in inner_result.matches:
                    logger.debug("scanner=encoding action=flag encoding=%s inner_scanner=%s pattern=%s", encoding_name, inner_result.scanner_name, match.pattern_name)
                    all_matches.append(
                        ScanMatch(
                            pattern_name=f"encoded:{encoding_name}:{match.pattern_name}",
                            matched_text=match.matched_text,
                            position=match.position,
                        )
                    )

        return ScanResult(
            found=len(all_matches) > 0,
            matches=all_matches,
            scanner_name="encoding_normalization_scanner",
        )

    def _decode_all(self, text: str) -> list[tuple[str, str]]:
        """Try all decoders and return (encoding_name, decoded_text) pairs."""
        results: list[tuple[str, str]] = []

        for decoded in self._try_base64(text):
            results.append(("base64", decoded))

        for decoded in self._try_hex(text):
            results.append(("hex", decoded))

        url_decoded = self._try_url_decode(text)
        if url_decoded is not None:
            results.append(("url_encoding", url_decoded))

        rot13_decoded = self._try_rot13(text)
        if rot13_decoded is not None:
            results.append(("rot13", rot13_decoded))

        html_decoded = self._try_html_entities(text)
        if html_decoded is not None:
            results.append(("html_entities", html_decoded))

        char_decoded = self._try_char_splitting(text)
        if char_decoded != text:
            results.append(("char_splitting", char_decoded))

        unicode_decoded = self._try_unicode_escapes(text)
        if unicode_decoded is not None:
            results.append(("unicode_escape", unicode_decoded))

        return results

    def _is_valid_decoded(self, text: str) -> bool:
        """Check if decoded text is valid UTF-8 with enough printable chars."""
        printable_count = sum(1 for c in text if c.isprintable())
        return printable_count >= self._MIN_PRINTABLE

    def _try_base64(self, text: str) -> list[str]:
        """Extract and decode base64 candidate substrings."""
        results: list[str] = []
        for match in self._BASE64_RE.finditer(text):
            candidate = match.group()
            try:
                decoded_bytes = base64.b64decode(candidate, validate=True)
                decoded_str = decoded_bytes.decode("utf-8")
                if self._is_valid_decoded(decoded_str):
                    results.append(decoded_str)
            except (ValueError, UnicodeDecodeError):
                continue
        return results

    def _try_hex(self, text: str) -> list[str]:
        """Extract and decode hex candidate substrings (even-length only)."""
        results: list[str] = []
        for match in self._HEX_RE.finditer(text):
            candidate = match.group()
            if len(candidate) % 2 != 0:
                continue
            try:
                decoded_bytes = bytes.fromhex(candidate)
                decoded_str = decoded_bytes.decode("utf-8")
                if self._is_valid_decoded(decoded_str):
                    results.append(decoded_str)
            except (ValueError, UnicodeDecodeError):
                continue
        return results

    def _try_url_decode(self, text: str) -> str | None:
        """URL-decode if text contains percent-encoded sequences."""
        if not self._URL_ENCODED_RE.search(text):
            return None
        decoded = urllib.parse.unquote(text)
        if decoded == text:
            return None
        return decoded

    # Keywords that indicate the ROT13 decoded text is worth scanning.
    # Without this filter, ROT13 runs 3 inner scanners on every input
    # because ROT13(any_alpha_text) != original_text is always true.
    _ROT13_KEYWORDS = re.compile(
        r"(?:eval|exec|system|import|subprocess|socket|connect|password|secret|"
        r"shadow|passwd|ssh|token|key|curl|wget|bash|/bin/|/etc/|\.env)",
        re.IGNORECASE,
    )

    def _try_rot13(self, text: str) -> str | None:
        """ROT13 the full text, but only return if decoded contains relevant keywords."""
        decoded = codecs.decode(text, "rot_13")
        if decoded == text:
            return None
        if self._ROT13_KEYWORDS.search(decoded):
            return decoded
        return None

    def _try_html_entities(self, text: str) -> str | None:
        """Unescape HTML entities if present."""
        if not self._HTML_ENTITY_RE.search(text):
            return None
        decoded = html.unescape(text)
        if decoded == text:
            return None
        return decoded

    def _try_char_splitting(self, text: str) -> str:
        """Collapse single-char-space/tab patterns (e.g. 'c a t' -> 'cat').

        Handles both space-separated ('c a t') and tab-separated ('c\\ta\\tt')
        variants (#46) so that tab-based evasion is caught alongside the
        original space-based technique.
        """
        def _collapse(match: re.Match) -> str:
            segment = match.group(1)
            # Split on space or tab — handle the tab-variant (#46)
            chars = re.split(r"[ \t]", segment)
            if all(len(c) == 1 for c in chars):
                return " " + "".join(chars) + " "
            return match.group(0)

        return self._CHAR_SPLIT_RE.sub(_collapse, text).strip()

    def _try_unicode_escapes(self, text: str) -> str | None:
        """Decode \\uXXXX, \\xXX, and octal \\NNN escape sequences.

        Uses per-match regex substitution to avoid codec pitfalls with mixed
        octal/unicode content. Returns decoded text only if it passes the
        printable-character validity check; returns None if no escapes found.
        """
        if not self._UNICODE_ESCAPE_RE.search(text):
            return None
        try:
            def _replace(m: re.Match) -> str:
                s = m.group(0)
                if s.startswith("\\u"):
                    return chr(int(s[2:], 16))
                elif s.startswith("\\x"):
                    return chr(int(s[2:], 16))
                else:  # octal \NNN
                    return chr(int(s[1:], 8))

            decoded = self._UNICODE_ESCAPE_RE.sub(_replace, text)
            if decoded == text:
                return None
            if self._is_valid_decoded(decoded):
                return decoded
        except (ValueError, OverflowError):
            pass
        return None

