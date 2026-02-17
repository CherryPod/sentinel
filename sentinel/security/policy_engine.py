import fnmatch
import os
import re
from pathlib import Path, PurePosixPath
from urllib.parse import unquote

import yaml

from sentinel.core.models import PolicyResult, ValidationResult


class PolicyEngine:
    def __init__(self, policy_path: str, workspace_path: str = "/workspace"):
        with open(policy_path) as f:
            self._policy = yaml.safe_load(f)

        self._workspace_path = workspace_path

        self._file_access = self._policy.get("file_access", {})
        self._commands = self._policy.get("commands", {})
        self._path_constrained = set(self._commands.get("path_constrained", []))

        # Pre-compile blocked patterns for command checking
        self._blocked_patterns: list[str] = self._commands.get("blocked_patterns", [])

        # Build allowed command set (base commands)
        self._allowed_commands: set[str] = set()
        for cmd in self._commands.get("allowed", []):
            self._allowed_commands.add(cmd)

        # Injection patterns — these are structural, not policy-driven
        self._injection_patterns = [
            re.compile(r"\$\("),       # $( subshell
            re.compile(r"`"),          # backtick subshell
            re.compile(r";\s*"),       # semicolon chaining
            re.compile(r"&&"),         # AND chaining
            re.compile(r"\|\|"),       # OR chaining
            re.compile(r"(?<!\|)\|(?!\|)"),  # bare pipe (not ||)
        ]

    # ── Path normalisation ──────────────────────────────────────────

    @staticmethod
    def _url_decode_iterative(path: str) -> str:
        """Iteratively URL-decode to handle double/triple encoding."""
        previous = None
        current = path
        # Safety limit to prevent infinite loops
        for _ in range(10):
            if current == previous:
                break
            previous = current
            current = unquote(current)
        return current

    @staticmethod
    def _strip_null_bytes(path: str) -> str:
        return path.replace("\x00", "").replace("%00", "")

    def _normalise_path(self, path: str, resolve: bool = True) -> str:
        """Normalise a path: URL decode, strip nulls, resolve symlinks."""
        decoded = self._url_decode_iterative(path)
        cleaned = self._strip_null_bytes(decoded)
        posix = PurePosixPath(cleaned)
        # Use PurePosixPath to collapse .. without touching the filesystem
        # For real filesystem resolution, the caller can use Path.resolve()
        normalised = str(posix)
        if resolve:
            try:
                normalised = str(Path(cleaned).resolve())
            except (OSError, ValueError):
                normalised = str(posix)
        return normalised

    def _detect_traversal(self, raw_path: str) -> bool:
        """Check for path traversal attempts in the raw (pre-normalised) input."""
        decoded = self._url_decode_iterative(raw_path)
        cleaned = self._strip_null_bytes(decoded)

        # Check for .. sequences in any form
        if ".." in cleaned:
            return True

        # Check for null bytes in original (attempted truncation)
        if "\x00" in raw_path or "%00" in raw_path:
            return True

        # Check for encoded traversal in the original string
        # (catches %2e%2e that decodes to ..)
        lower = raw_path.lower()
        if "%2e%2e" in lower or "%252e" in lower:
            return True

        return False

    # ── File access checks ──────────────────────────────────────────

    def _matches_any_glob(self, path: str, patterns: list[str]) -> bool:
        """Check if a path matches any of the given glob patterns."""
        for pattern in patterns:
            if fnmatch.fnmatch(path, pattern):
                return True
            # /workspace matches /workspace/** (the directory itself is allowed)
            if pattern.endswith("/**") and path.rstrip("/") == pattern[:-3].rstrip("/"):
                return True
            basename = PurePosixPath(path).name
            # For patterns like "**/*.env", also try matching the path suffix
            if pattern.startswith("**"):
                suffix_pattern = pattern.lstrip("*")
                if suffix_pattern.startswith("/"):
                    suffix_pattern = suffix_pattern[1:]
                # Check if any suffix of the path matches
                parts = PurePosixPath(path).parts
                for i in range(len(parts)):
                    subpath = "/".join(parts[i:])
                    if fnmatch.fnmatch(subpath, suffix_pattern):
                        return True
                # Also check the filename directly
                if fnmatch.fnmatch(basename, suffix_pattern):
                    return True
        return False

    def check_file_write(self, path: str) -> ValidationResult:
        """Validate a file write operation against policy."""
        # Check traversal on raw input first
        if self._detect_traversal(path):
            return ValidationResult(
                status=PolicyResult.BLOCKED,
                path=path,
                reason="Path traversal detected",
            )

        resolved = self._normalise_path(path)

        # Check blocked patterns first (higher priority)
        blocked = self._file_access.get("blocked", [])
        if self._matches_any_glob(resolved, blocked):
            return ValidationResult(
                status=PolicyResult.BLOCKED,
                path=path,
                resolved_path=resolved,
                reason="Path matches blocked pattern",
            )

        # Check allowed patterns
        allowed = self._file_access.get("write_allowed", [])
        if self._matches_any_glob(resolved, allowed):
            return ValidationResult(
                status=PolicyResult.ALLOWED,
                path=path,
                resolved_path=resolved,
            )

        return ValidationResult(
            status=PolicyResult.BLOCKED,
            path=path,
            resolved_path=resolved,
            reason="Path not in write_allowed list",
        )

    def check_file_read(self, path: str) -> ValidationResult:
        """Validate a file read operation against policy."""
        if self._detect_traversal(path):
            return ValidationResult(
                status=PolicyResult.BLOCKED,
                path=path,
                reason="Path traversal detected",
            )

        resolved = self._normalise_path(path)

        # Check blocked patterns first
        blocked = self._file_access.get("blocked", [])
        if self._matches_any_glob(resolved, blocked):
            return ValidationResult(
                status=PolicyResult.BLOCKED,
                path=path,
                resolved_path=resolved,
                reason="Path matches blocked pattern",
            )

        # Check allowed patterns
        allowed = self._file_access.get("read_allowed", [])
        if self._matches_any_glob(resolved, allowed):
            return ValidationResult(
                status=PolicyResult.ALLOWED,
                path=path,
                resolved_path=resolved,
            )

        return ValidationResult(
            status=PolicyResult.BLOCKED,
            path=path,
            resolved_path=resolved,
            reason="Path not in read_allowed list",
        )

    # ── Command checks ──────────────────────────────────────────────

    def _extract_base_command(self, command: str) -> str:
        """Extract the base command (possibly multi-word like 'podman build')."""
        parts = command.strip().split()
        if not parts:
            return ""

        # Check two-word commands first (e.g. "podman build")
        if len(parts) >= 2:
            two_word = f"{parts[0]} {parts[1]}"
            if two_word in self._allowed_commands:
                return two_word

        return parts[0]

    def _extract_command_args(self, command: str, base_command: str) -> list[str]:
        """Extract arguments after the base command."""
        rest = command.strip()[len(base_command):].strip()
        if not rest:
            return []
        return rest.split()

    def check_command(self, command: str) -> ValidationResult:
        """Validate a shell command against policy."""
        stripped = command.strip()
        if not stripped:
            return ValidationResult(
                status=PolicyResult.BLOCKED,
                reason="Empty command",
            )

        # Check injection patterns first
        for pattern in self._injection_patterns:
            if pattern.search(stripped):
                return ValidationResult(
                    status=PolicyResult.BLOCKED,
                    path=stripped,
                    reason=f"Injection pattern detected: {pattern.pattern}",
                )

        # Check blocked patterns
        for blocked in self._blocked_patterns:
            if blocked in stripped:
                return ValidationResult(
                    status=PolicyResult.BLOCKED,
                    path=stripped,
                    reason=f"Matches blocked pattern: {blocked}",
                )

        # Extract base command and check against allowed list
        base = self._extract_base_command(stripped)
        if base not in self._allowed_commands:
            return ValidationResult(
                status=PolicyResult.BLOCKED,
                path=stripped,
                reason=f"Command not in allowed list: {base}",
            )

        # For path-constrained commands, validate arguments against allowed paths
        if base in self._path_constrained:
            args = self._extract_command_args(stripped, base)
            path_args = []
            for a in args:
                if a.startswith("-") or a.startswith("'") or a.startswith('"'):
                    continue
                if any(c in a for c in ("*", "?", "[")):
                    continue  # skip glob patterns
                if a.startswith("/"):
                    path_args.append(a)
                else:
                    resolved = os.path.normpath(os.path.join(self._workspace_path, a))
                    path_args.append(resolved)
            for path_arg in path_args:
                result = self.check_file_read(path_arg)
                if result.status == PolicyResult.BLOCKED:
                    return ValidationResult(
                        status=PolicyResult.BLOCKED,
                        path=stripped,
                        reason=f"Path-constrained command '{base}' used with blocked path: {path_arg}",
                    )

        return ValidationResult(
            status=PolicyResult.ALLOWED,
            path=stripped,
        )

    @property
    def policy(self) -> dict:
        return self._policy
