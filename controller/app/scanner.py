import re

from .models import ScanMatch, ScanResult


class CredentialScanner:
    """Regex-based scanner for credentials and secrets in text."""

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
            scanner_name="credential_scanner",
        )


class SensitivePathScanner:
    """Substring-based scanner for sensitive path references in text."""

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
        # Python/perl/ruby reverse shells
        ("scripting_reverse_shell", re.compile(
            r"(python|perl|ruby)\s+.*socket.*connect", re.IGNORECASE,
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
