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
