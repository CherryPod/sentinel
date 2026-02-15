import re

from .models import ScanMatch, ScanResult


class CredentialScanner:
    """Regex-based scanner for credentials and secrets in text."""

    # URI-format pattern names eligible for example-URI suppression.
    # API keys, PATs, JWTs are never allowlisted.
    _URI_PATTERN_NAMES = {"mongodb_uri", "postgres_uri", "redis_uri"}

    # Substrings that mark a URI as an example/placeholder, not a real credential.
    _EXAMPLE_URI_HOSTS = [
        "localhost", "127.0.0.1", "0.0.0.0", "::1",
        "example.com", "example.org", "example.net",
        "user:pass@", "user:password@", "username:password@",
        "your-password", "<password>", "changeme",
    ]

    def __init__(self, patterns: list[dict]):
        self._patterns: list[tuple[str, re.Pattern]] = []
        for entry in patterns:
            name = entry["name"]
            raw = entry["pattern"]
            self._patterns.append((name, re.compile(raw)))

    def scan(self, text: str) -> ScanResult:
        matches = []
        for name, pattern in self._patterns:
            for match in pattern.finditer(text):
                matched_text = match.group()

                # Suppress example URIs — real credentials don't use
                # localhost, example.com, or placeholder passwords.
                if name in self._URI_PATTERN_NAMES:
                    if any(host in matched_text for host in self._EXAMPLE_URI_HOSTS):
                        continue

                matches.append(
                    ScanMatch(
                        pattern_name=name,
                        matched_text=matched_text,
                        position=match.start(),
                    )
                )
        return ScanResult(
            found=len(matches) > 0,
            matches=matches,
            scanner_name="credential_scanner",
        )


class SensitivePathScanner:
    """Substring-based scanner for sensitive path references in text."""

    # Shell command prefixes that indicate operational context
    _SHELL_PREFIXES = re.compile(
        r"^\s*(?:\$|#|sudo|cat|rm|chmod|chown|ls|cp|mv|mkdir|touch|head|tail|less|more|nano|vi|vim)\s",
        re.IGNORECASE,
    )

    def __init__(self, patterns: list[str]):
        self._patterns = patterns

    def scan(self, text: str) -> ScanResult:
        matches = []
        for pattern in self._patterns:
            idx = 0
            while True:
                pos = text.find(pattern, idx)
                if pos == -1:
                    break
                matches.append(
                    ScanMatch(
                        pattern_name="sensitive_path",
                        matched_text=pattern,
                        position=pos,
                    )
                )
                idx = pos + 1
        return ScanResult(
            found=len(matches) > 0,
            matches=matches,
            scanner_name="sensitive_path_scanner",
        )

    def scan_output_text(self, text: str) -> ScanResult:
        """Context-aware output scan: only flag paths in operational context.

        Paths in fenced code blocks, shell command lines, or standalone
        path-only lines are flagged. Paths embedded in natural-language
        prose (e.g. "cgroups use /proc/cgroups") are considered educational
        and pass through.
        """
        matches = []

        # Extract lines inside fenced code blocks
        code_block_ranges: list[tuple[int, int]] = []
        for m in re.finditer(r"```[^\n]*\n(.*?)```", text, re.DOTALL):
            code_block_ranges.append((m.start(1), m.end(1)))

        for pattern in self._patterns:
            idx = 0
            while True:
                pos = text.find(pattern, idx)
                if pos == -1:
                    break
                idx = pos + 1

                # Check 1: inside a fenced code block
                in_code_block = any(
                    start <= pos < end for start, end in code_block_ranges
                )
                if in_code_block:
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
                    matches.append(ScanMatch(
                        pattern_name="sensitive_path",
                        matched_text=pattern,
                        position=pos,
                    ))
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
    ]

    def __init__(self, extra_patterns: list[dict] | None = None):
        self._patterns = list(self._DEFAULT_PATTERNS)
        if extra_patterns:
            for entry in extra_patterns:
                name = entry["name"]
                raw = entry["pattern"]
                self._patterns.append((name, re.compile(raw)))

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
        (re.compile(r"\byaml\.load\s*\([^)]*(?!Loader)"), "python_yaml_unsafe"),
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
