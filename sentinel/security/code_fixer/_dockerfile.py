"""Dockerfile / Containerfile fixer.

Fixes common LLM mistakes in Dockerfiles and Containerfiles:
- Single quotes in CMD/ENTRYPOINT/RUN exec-form arrays (JSON requires double)
- ADD -> COPY when source is not a URL or archive
- Shell operators in exec form (warning)
- Missing FROM as first instruction (error)
- Missing USER instruction (warning)
- :latest tag usage (warning)
- apt-get install without prior update (warning)
"""
import logging
import re

from ._core import FixResult, _current_filename

logger = logging.getLogger(__name__)


def fix_dockerfile(content: str) -> FixResult:
    """Fix common LLM Dockerfile mistakes. Both Dockerfile and Containerfile."""
    result = FixResult(content=content)
    original = content
    fname = _current_filename.get()

    logger.debug(
        "Dockerfile fixer starting",
        extra={
            "event": "dockerfile_fixer_start",
            "file": fname,
            "content_length": len(content),
        },
    )

    # Finding #13 fix: single-to-double quote replacement ONLY in
    # CMD/ENTRYPOINT/RUN exec-form arrays (not globally).
    # JSON requires double quotes. LLMs often use Python-style single quotes.
    pattern = r"^(CMD|ENTRYPOINT|RUN)\s+\[([^\]]*)\]"

    def _fix_exec_form(m):
        instruction = m.group(1)
        args = m.group(2)
        if "'" in args:
            args = args.replace("'", '"')
            return f"{instruction} [{args}]"
        return m.group(0)

    content = re.sub(pattern, _fix_exec_form, content, flags=re.MULTILINE)
    if content != original:
        result.fixes_applied.append("Fixed single quotes in exec form")

    # Check FROM exists and is first instruction
    code_lines = [
        line.strip()
        for line in content.split("\n")
        if line.strip() and not line.strip().startswith("#")
    ]
    if code_lines and not code_lines[0].upper().startswith("FROM"):
        result.errors_found.append("First instruction is not FROM")

    lines = content.split("\n")
    new_lines = []
    has_user = False
    has_apt_update = False

    for i, line in enumerate(lines):
        stripped = line.strip()
        upper = stripped.upper()

        if upper.startswith("USER "):
            has_user = True

        if "apt-get install" in stripped and not has_apt_update:
            result.warnings.append(
                f"Line {i + 1}: apt-get install without prior apt-get update"
            )
        if "apt-get update" in stripped:
            has_apt_update = True

        # Finding #25 fix: ADD -> COPY case-insensitive
        # Use re.IGNORECASE so "add", "Add", "ADD" all match
        add_match = re.match(r"^(\s*)(ADD)\s", line, re.IGNORECASE)
        if add_match and not re.match(r"^\s*ADD\s+--", line, re.IGNORECASE):
            args = stripped[4:].strip()
            src = args.split()[0] if args.split() else args
            archive_exts = (
                ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".zip", ".gz",
            )
            if not src.startswith("http") and not any(
                src.endswith(ext) for ext in archive_exts
            ):
                # Preserve leading whitespace, replace instruction with COPY
                leading_ws = add_match.group(1)
                rest_of_line = line[add_match.end(2) :]
                new_line = f"{leading_ws}COPY{rest_of_line}"
                if new_line != line:
                    result.fixes_applied.append(
                        f"Line {i + 1}: ADD -> COPY (not a URL or archive)"
                    )
                    line = new_line

        # Shell operators in exec form — if && || | appear anywhere in
        # the bracket content, warn. In exec form these are string args,
        # not shell operators, so the container will pass them literally.
        exec_match = re.match(r'^(CMD|ENTRYPOINT|RUN)\s+\[(.+)\]', stripped)
        if exec_match:
            args_str = exec_match.group(2)
            if "&&" in args_str or "||" in args_str or "|" in args_str:
                result.warnings.append(
                    f"Line {i + 1}: Shell operators in exec form won't work "
                    f"(needs shell form or explicit sh -c)"
                )

        # Detect :latest tag
        if re.match(r"^\s*FROM\s+\S+:latest", line):
            result.warnings.append(f"Using :latest tag: {stripped}")

        new_lines.append(line)

    content = "\n".join(new_lines)

    # Missing USER instruction
    if not has_user and code_lines:
        result.warnings.append("No USER instruction — container runs as root")

    result.content = content
    result.changed = content != original

    if result.changed:
        logger.debug(
            "Dockerfile fixer applied changes",
            extra={
                "event": "dockerfile_fixer_done",
                "file": fname,
                "fixes": result.fixes_applied,
            },
        )

    return result
