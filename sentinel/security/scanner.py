import base64
import codecs
import html
import re
import urllib.parse

from sentinel.core.models import ScanMatch, ScanResult
from sentinel.security.homoglyph import normalise_homoglyphs

# Shared regex: fenced code blocks with optional language tag.
# Group 1 = language tag (may be empty), Group 2 = block content.
_CODE_FENCE_RE = re.compile(r"```(\w*)\s*\n(.*?)```", re.DOTALL)


class CredentialScanner:
    """Regex-based scanner for credentials and secrets in text."""

    # URI-format pattern names eligible for example-URI suppression.
    # API keys, PATs, JWTs are never allowlisted.
    _URI_PATTERN_NAMES = {"mongodb_uri", "postgres_uri", "redis_uri"}

    # Substrings that mark a URI as an example/placeholder, not a real credential.
    _EXAMPLE_URI_SUBSTRINGS = [
        "localhost", "127.0.0.1", "0.0.0.0", "::1",
        "user:pass@", "user:password@", "username:password@",
        "your-password", "<password>", "changeme",
        # Common compose service names (not real hosts) — use //host: to
        # match the URI host portion, not the scheme (e.g. "postgres://")
        "//db:", "//redis:", "//postgres:", "//mysql:", "//mongo:",
        "//rabbitmq:", "//memcached:",
    ]
    # Example domains checked via proper hostname parsing (not substring),
    # so "evil-example.com" doesn't match "example.com".
    _EXAMPLE_URI_DOMAINS = frozenset({"example.com", "example.org", "example.net"})

    def __init__(self, patterns: list[dict]):
        self._patterns: list[tuple[str, re.Pattern]] = []
        for entry in patterns:
            name = entry["name"]
            raw = entry["pattern"]
            self._patterns.append((name, re.compile(raw)))

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
                    if any(s in matched_text for s in self._EXAMPLE_URI_SUBSTRINGS):
                        continue
                    # Check example domains via proper hostname parsing
                    try:
                        parsed = urllib.parse.urlparse(matched_text)
                        host = (parsed.hostname or "").lower()
                        if host in self._EXAMPLE_URI_DOMAINS or any(
                            host.endswith("." + d) for d in self._EXAMPLE_URI_DOMAINS
                        ):
                            continue
                    except Exception:
                        pass

                matches.append(
                    ScanMatch(
                        pattern_name=name,
                        matched_text=matched_text,
                        position=match.start(),
                    )
                )
        # Defence-in-depth: detect /etc/shadow file content format
        matches.extend(self._check_shadow_content(text))
        return ScanResult(
            found=len(matches) > 0,
            matches=matches,
            scanner_name="credential_scanner",
        )

    # Known system account names that appear in /etc/shadow
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

    # Shell command prefixes that indicate operational context
    _SHELL_PREFIXES = re.compile(
        r"^\s*(?:\$|#|sudo|cat|rm|chmod|chown|ls|cp|mv|mkdir|touch|head|tail|less|more|nano|vi|vim)\s",
        re.IGNORECASE,
    )

    # Patterns that are safe to skip inside fenced code blocks.
    # These paths commonly appear in legitimate infrastructure, monitoring,
    # and configuration code (Terraform, Ansible, Containerfiles, system
    # health scripts, etc.). They remain flagged in shell command lines,
    # standalone path lines, and input scanning — only code blocks are relaxed.
    # Note: .env is NOT included — reading .env files is a common exfiltration
    # technique and should remain flagged even in code blocks.
    _CODE_BLOCK_SAFE: frozenset[str] = frozenset({
        "/etc/passwd",   # world-readable, common in user management (Ansible, Containerfiles)
        "/proc/",        # monitoring, cgroups, system info
        "/sys/",         # sysfs, cgroups, hardware info
        ".config/",      # standard XDG config directory
        ".local/share/", # standard XDG data directory
    })

    # Regex for lines that look like ignore-file entries:
    # comments (#...), negations (!path), glob patterns, paths with
    # slashes/dots/stars/brackets — but NOT code syntax (parens, quotes,
    # semicolons, spaces in the middle).
    _IGNORE_ENTRY_RE = re.compile(r"^(?:#.*|!?[a-zA-Z0-9.*_/\[\]{}\-\\]+/?)$")

    def __init__(self, patterns: list[str]):
        self._patterns = patterns

    @staticmethod
    def _is_boundary_match(text: str, pattern: str, pos: int) -> bool:
        """Check that the match at *pos* isn't a substring of a longer word.

        Patterns ending with ``/`` (e.g. ``.ssh/``, ``/proc/``) are
        boundary-safe by definition.  For patterns without a trailing
        slash (e.g. ``.env``, ``wallet.dat``), the character immediately
        after the match must **not** be alphabetic — otherwise the match
        is part of a longer token (``environment``, ``os.environ``) and
        should be ignored.
        """
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
                    continue

                matches.append(
                    ScanMatch(
                        pattern_name="sensitive_path",
                        matched_text=pattern,
                        position=pos,
                    )
                )
        return ScanResult(
            found=len(matches) > 0,
            matches=matches,
            scanner_name="sensitive_path_scanner",
        )

    @staticmethod
    def _strip_outer_fence(text: str) -> str:
        """Strip an outer ``markdown`` or ``md`` fence that wraps the entire response.

        Qwen sometimes wraps its full output in a markdown fence, which
        causes the code-block detection regex to mismatch inner fences
        (the outer opening pairs with the first inner closing).  Stripping
        the wrapper normalises the text for correct inner-block parsing.
        """
        stripped = text.lstrip()
        for prefix in ("```markdown\n", "```md\n"):
            if stripped.startswith(prefix):
                inner = stripped[len(prefix):]
                # The closing ``` must be at the very end (possibly trailing whitespace)
                if inner.rstrip().endswith("```"):
                    return inner.rstrip()[:-3]
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

        start = max(0, line_idx - 5)
        end = min(len(all_lines), line_idx + 6)
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
        return matching / len(nearby) >= 0.8

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

    def scan_output_text(self, text: str) -> ScanResult:
        """Context-aware output scan: only flag paths in operational context.

        Paths in fenced code blocks, shell command lines, or standalone
        path-only lines are flagged. Paths embedded in natural-language
        prose (e.g. "cgroups use /proc/cgroups") are considered educational
        and pass through.
        """
        # Strip outer markdown wrapper (Qwen quirk) so inner code blocks
        # are detected correctly by the fence regex.
        text = self._strip_outer_fence(text)
        # R12: Normalise homoglyphs before pattern matching
        text = normalise_homoglyphs(text)

        matches = []

        # Extract fenced code blocks with language tags
        # Each entry: (content_start, content_end, language_tag)
        code_block_info: list[tuple[int, int, str]] = []
        for m in _CODE_FENCE_RE.finditer(text):
            code_block_info.append((m.start(2), m.end(2), m.group(1).lower()))
        # Backward-compatible ranges for _get_enclosing_block
        code_block_ranges: list[tuple[int, int]] = [
            (start, end) for start, end, _ in code_block_info
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

                # Check 1: inside a fenced code block
                in_code_block = any(
                    start <= pos < end for start, end in code_block_ranges
                )
                if in_code_block:
                    # Low-risk infrastructure paths are common in legitimate
                    # code (Terraform, Ansible, monitoring scripts, etc.) —
                    # skip them inside code blocks to reduce false positives.
                    if pattern in self._CODE_BLOCK_SAFE:
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
                            continue

                    matches.append(ScanMatch(
                        pattern_name="sensitive_path",
                        matched_text=pattern,
                        position=pos,
                    ))
                    continue

                # Get the line containing this match
                line_start = text.rfind("\n", 0, pos) + 1
                line_end = text.find("\n", pos)
                if line_end == -1:
                    line_end = len(text)
                line = text[line_start:line_end]

                # Check 2: line looks like a shell command
                if self._SHELL_PREFIXES.match(line):
                    matches.append(ScanMatch(
                        pattern_name="sensitive_path",
                        matched_text=pattern,
                        position=pos,
                    ))
                    continue

                # Check 3: standalone path-only line (just whitespace + path)
                stripped = line.strip()
                if stripped == pattern or stripped == pattern.rstrip("/"):
                    # .env on its own line inside an ignore-file listing
                    # (e.g. .containerignore, .gitignore content not in a
                    # fenced code block) is an exclusion pattern, not access.
                    if ".env" in pattern and self._surrounding_is_ignore_listing(
                        text, pos,
                    ):
                        continue
                    matches.append(ScanMatch(
                        pattern_name="sensitive_path",
                        matched_text=pattern,
                        position=pos,
                    ))
                    continue

                # Check 4: markdown list item with surrounding prose (educational)
                if re.match(r"^\s*[-*]\s+", line) and len(stripped) > len(pattern) + 5:
                    continue

                # Check 5: path followed by explanatory text (e.g. "— stores ...")
                path_end = pos + len(pattern) - line_start
                after_path = stripped[path_end:].strip() if path_end < len(stripped) else ""
                if after_path and re.match(r"^[—–\-:]\s+\w", after_path):
                    continue

                # Check 6: YAML/HCL config context (indented key: value structure)
                if re.match(r"^\s+\w[\w_-]*\s*:", line):
                    continue

                # Otherwise: path is in prose context — skip (educational)

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
        # Pipe-to-shell: curl/wget (with optional flags) piped to sh/bash
        ("pipe_to_shell", re.compile(
            r"(curl|wget)\s+[^|]+\|\s*(ba)?sh",
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
        # Netcat listener/reverse shell
        ("netcat_shell", re.compile(
            r"(nc|ncat|netcat)\s+.*(-e\s+|exec\s+)", re.IGNORECASE,
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
            r"(python|perl|ruby).*socket.*connect.*(?:subprocess|os\.system|os\.popen|pty\.spawn|exec\()",
            re.IGNORECASE | re.DOTALL,
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

    # Command-line prefixes: shell prompts, shebangs, and common command
    # names that indicate a line IS a command (not prose mentioning one).
    # Broader than SensitivePathScanner._SHELL_PREFIXES because command
    # patterns frequently appear on lines starting with the command itself.
    _CMD_LINE_PREFIX = re.compile(
        r"^\s*(?:"
        r"\$\s|#!\s*|"                              # Shell prompt ($) or shebang (#!)
        r"sudo\s|"                                   # Privilege escalation
        r"curl\s|wget\s|"                            # Data transfer
        r"echo\s|printf\s|"                          # Output commands
        r"nc\s|ncat\s|netcat\s|"                     # Network tools
        r"bash\s|sh\s|zsh\s|"                        # Shell invocation
        r"nohup\s|crontab\s|"                        # Background/scheduling
        r"cat\s|rm\s|chmod\s|chown\s|cp\s|mv\s|"    # File operations
        r"mkdir\s|touch\s|head\s|tail\s|"            # File operations (cont.)
        r"python[23]?\s|perl\s|ruby\s|"              # Scripting languages
        r"eval\s|exec\s|"                            # Evaluation
        r"mkfifo\s"                                  # Named pipe (common in reverse shells)
        r")",
        re.IGNORECASE,
    )

    # 4-space or tab indented lines (markdown code blocks)
    _INDENTED_LINE_RE = re.compile(r"^(?:    |\t).+", re.MULTILINE)

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

    @classmethod
    def _is_dockerfile_content(cls, text: str) -> bool:
        """Heuristic: does *text* look like Dockerfile/Containerfile content?

        Returns True if the text contains a ``FROM`` instruction AND at least
        one other Dockerfile instruction (RUN, COPY, etc.).  This avoids
        false positives on generic text that happens to contain "FROM".
        """
        instructions = cls._DOCKERFILE_INSTRUCTION_RE.findall(text)
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

    def scan(self, text: str) -> ScanResult:
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
        return ScanResult(
            found=len(matches) > 0,
            matches=matches,
            scanner_name="command_pattern_scanner",
        )

    def scan_output_text(self, text: str) -> ScanResult:
        """Context-aware output scan: only flag commands in code regions.

        Dangerous command patterns in prose (e.g. refusal explanations,
        educational content) are not flagged — only patterns inside
        fenced code blocks, indented code, or shell-prompt lines.

        Dockerfile awareness: ``dangerous_rm`` matches inside code blocks
        tagged as ``dockerfile``/``containerfile``/``docker`` are exempt
        when the rm target is a standard cache/temp directory (e.g.
        ``rm -rf /var/cache/apt/*``).
        """
        text = SensitivePathScanner._strip_outer_fence(text)
        # R14: Normalise homoglyphs + strip zero-width chars before matching
        text = normalise_homoglyphs(text)

        # Build code region ranges — fenced blocks with language tags
        # Each entry: (content_start, content_end, lang_tag)
        code_block_info: list[tuple[int, int, str]] = []
        for m in _CODE_FENCE_RE.finditer(text):
            code_block_info.append((m.start(2), m.end(2), m.group(1).lower()))
        # Plain ranges for indented lines (no language tag)
        indented_ranges: list[tuple[int, int]] = []
        for m in self._INDENTED_LINE_RE.finditer(text):
            indented_ranges.append((m.start(), m.end()))

        matches: list[ScanMatch] = []
        for name, pattern in self._patterns:
            for match in pattern.finditer(text):
                pos = match.start()

                # Check 1: inside a fenced code block
                in_fenced = False
                block_lang = ""
                block_content = ""
                for start, end, lang in code_block_info:
                    if start <= pos < end:
                        in_fenced = True
                        block_lang = lang
                        block_content = text[start:end]
                        break

                if in_fenced:
                    # Dockerfile exemption: dangerous_rm inside a
                    # Dockerfile block targeting cache/temp dirs is safe.
                    # Works with explicit tags AND content-based detection
                    # (Qwen sometimes omits language tags on code fences).
                    if (
                        name == "dangerous_rm"
                        and self._DOCKERFILE_SAFE_RM_TARGETS.search(match.group())
                    ):
                        if block_lang in self._DOCKERFILE_TAGS:
                            continue
                        # Fallback: no tag or unrecognised tag — check content
                        if not block_lang or block_lang not in {"bash", "sh", "shell", "zsh"}:
                            if self._is_dockerfile_content(block_content):
                                continue

                    # Build-file exemption: dangerous_rm targeting variables
                    # (e.g. rm -f $(OBJECTS)) in Makefile clean targets is
                    # standard build artifact cleanup, not an attack.
                    if (
                        name == "dangerous_rm"
                        and self._BUILD_FILE_SAFE_RM_TARGET.search(match.group())
                    ):
                        if block_lang in self._BUILD_FILE_TAGS:
                            continue
                        if not block_lang or block_lang not in {"bash", "sh", "shell", "zsh"}:
                            if self._is_build_file_content(block_content):
                                continue

                    matches.append(ScanMatch(
                        pattern_name=name,
                        matched_text=match.group(),
                        position=pos,
                    ))
                    continue

                # Check 1b: inside an indented code block → flag
                if any(start <= pos < end for start, end in indented_ranges):
                    # Dockerfile exemption: indented lines in Dockerfile
                    # content (e.g. continuation of RUN instructions)
                    if (
                        name == "dangerous_rm"
                        and self._DOCKERFILE_SAFE_RM_TARGETS.search(match.group())
                        and self._is_dockerfile_content(text)
                    ):
                        continue

                    # Build-file exemption for indented content
                    if (
                        name == "dangerous_rm"
                        and self._BUILD_FILE_SAFE_RM_TARGET.search(match.group())
                        and self._is_build_file_content(text)
                    ):
                        continue

                    matches.append(ScanMatch(
                        pattern_name=name,
                        matched_text=match.group(),
                        position=pos,
                    ))
                    continue

                # Check 2: on a top-level command-like line (shell prompt,
                # shebang, or bare command name) → flag.
                # Note: indented continuation lines (e.g. "    && rm -rf
                # /var/lib/apt/lists/*") are handled by Check 1b above,
                # since they match _INDENTED_LINE_RE. Check 2 covers
                # top-level command lines in unfenced Dockerfile output.
                line_start = text.rfind("\n", 0, pos) + 1
                line_end = text.find("\n", pos)
                if line_end == -1:
                    line_end = len(text)
                line = text[line_start:line_end]
                if self._CMD_LINE_PREFIX.match(line):
                    # Dockerfile exemption for unfenced top-level lines:
                    # Qwen may output Containerfile instructions without
                    # any code fence. If the full text looks like a
                    # Dockerfile and the rm target is safe, exempt it.
                    if (
                        name == "dangerous_rm"
                        and self._DOCKERFILE_SAFE_RM_TARGETS.search(match.group())
                        and self._is_dockerfile_content(text)
                    ):
                        continue

                    # Build-file exemption for unfenced top-level lines
                    if (
                        name == "dangerous_rm"
                        and self._BUILD_FILE_SAFE_RM_TARGET.search(match.group())
                        and self._is_build_file_content(text)
                    ):
                        continue

                    matches.append(ScanMatch(
                        pattern_name=name,
                        matched_text=match.group(),
                        position=pos,
                    ))
                    continue

                # Otherwise: prose context — skip (educational/refusal)

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
        (re.compile(r"\bsubprocess\.call\(.*shell\s*=\s*True", re.DOTALL), "python_subprocess_shell"),
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
    ]

    # Regex to extract fenced code blocks and 4-space/tab indented lines
    _CODE_BLOCK_RE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)
    _INDENTED_LINE_RE = re.compile(r"^(?:    |\t).+", re.MULTILINE)

    def __init__(self) -> None:
        pass

    def _extract_code_regions(self, text: str) -> str:
        """Extract text from code blocks and indented lines."""
        parts: list[str] = []
        for m in self._CODE_BLOCK_RE.finditer(text):
            parts.append(m.group(1))
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
        input_fps = self._find_fingerprints(input_text)
        if not input_fps:
            return ScanResult(found=False, scanner_name="vulnerability_echo_scanner")

        # Only check output code regions — prose mentions shouldn't trigger
        output_code = self._extract_code_regions(output_text)
        output_fps = self._find_fingerprints(output_code)

        echoed = input_fps & output_fps
        if not echoed:
            return ScanResult(found=False, scanner_name="vulnerability_echo_scanner")

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
    # Char splitting: 4+ single characters separated by spaces (e.g. "c a t / e t c")
    _CHAR_SPLIT_RE = re.compile(r"(?:^|\s)((?:\S ){3,}\S)(?:\s|$)")

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

    def scan_output_text(self, text: str) -> ScanResult:
        """Like scan() but uses context-aware path scanning for output."""
        return self._scan_internal(text, output_mode=True)

    def _scan_internal(self, text: str, output_mode: bool) -> ScanResult:
        """Core scan logic shared by scan() and scan_output_text()."""
        decoded_variants = self._decode_all(text)
        if not decoded_variants:
            return ScanResult(found=False, scanner_name="encoding_normalization_scanner")

        all_matches: list[ScanMatch] = []
        for encoding_name, decoded_text in decoded_variants:
            # Run all 3 inner scanners on each decoded variant.
            # In output mode, use context-aware scanning for path and
            # command scanners (only flag patterns in code regions).
            cred_result = self._cred_scanner.scan(decoded_text)
            if output_mode:
                path_result = self._path_scanner.scan_output_text(decoded_text)
                cmd_result = self._cmd_scanner.scan_output_text(decoded_text)
            else:
                path_result = self._path_scanner.scan(decoded_text)
                cmd_result = self._cmd_scanner.scan(decoded_text)

            for inner_result in (cred_result, path_result, cmd_result):
                for match in inner_result.matches:
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
        results.append(("rot13", rot13_decoded))

        html_decoded = self._try_html_entities(text)
        if html_decoded is not None:
            results.append(("html_entities", html_decoded))

        char_decoded = self._try_char_splitting(text)
        if char_decoded != text:
            results.append(("char_splitting", char_decoded))

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

    def _try_rot13(self, text: str) -> str:
        """ROT13 the full text (always runs — cheap and low FP risk)."""
        return codecs.decode(text, "rot_13")

    def _try_html_entities(self, text: str) -> str | None:
        """Unescape HTML entities if present."""
        if not self._HTML_ENTITY_RE.search(text):
            return None
        decoded = html.unescape(text)
        if decoded == text:
            return None
        return decoded

    def _try_char_splitting(self, text: str) -> str:
        """Collapse single-char-space patterns (e.g. 'c a t' -> 'cat')."""
        def _collapse(match: re.Match) -> str:
            segment = match.group(1)
            # Only collapse if every other char is a space between single chars
            chars = segment.split(" ")
            if all(len(c) == 1 for c in chars):
                return " " + "".join(chars) + " "
            return match.group(0)

        return self._CHAR_SPLIT_RE.sub(_collapse, text).strip()
