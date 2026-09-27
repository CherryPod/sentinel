"""Shared file operation utilities — syntax validation, fixer, semgrep, sandbox, read, mkdir, shell."""

import asyncio
import base64
import hashlib
import logging
import os
import re
import shlex
import shutil
from uuid import uuid4

from sentinel.core.models import DataSource, PolicyResult, TaggedData, TrustLevel
from sentinel.security import semgrep_scanner
from sentinel.security.code_extractor import extract_code_blocks
from sentinel.security.code_fixer import fix_code as code_fixer_fix
from sentinel.security.provenance import (
    create_tagged_data,
    get_file_writer,
    get_tagged_data,
)
from sentinel.tools._handlers._constants import (
    _CODE_EXTENSIONS,
    _EXTENSIONLESS_FIXER_NAMES,
    _MANIFEST_EXTENSIONS,
    _detect_language_from_path,
)
from sentinel.tools._handlers._registry import tool_handler
from sentinel.tools._handlers._task_exec_context import get_current_task_context
from sentinel.tools._handlers._types import ToolBlockedError, ToolError

logger = logging.getLogger(__name__)

# Maximum file size for file_read and pre-read diff in file_write (1 MiB).
FILE_READ_MAX_BYTES = 1_048_576

# Maximum anchor prefix length for find() calls
_ANCHOR_FIND_LIMIT = 200
# Lines of surrounding context extracted for code fixer
_CONTEXT_WINDOW_LINES = 50


class FileOpsHandlerMixin:
    """Shared file operation utilities — syntax validation, fixer, semgrep, sandbox, read, mkdir, shell."""

    # JS/TS extensions that node --check can validate
    _JS_EXTENSIONS = (".js", ".ts", ".jsx", ".tsx", ".mjs")
    # Shell extensions that bash -n can validate
    _SHELL_EXTENSIONS = (".sh", ".bash")

    _FIXER_META_DEFAULTS: dict = {
        "code_fixer_changed": False,
        "code_fixer_fixes": [],
        "code_fixer_errors": [],
        "code_fixer_warnings": [],
    }

    _FULL_FIXER_META_DEFAULTS: dict = {
        "full_file_fixer_changed": False,
        "full_file_fixer_fixes": [],
        "full_file_fixer_errors": [],
        "full_file_fixer_warnings": [],
    }

    async def _validate_syntax_post_fix(self, path: str, fix_result) -> None:
        """Run post-fix syntax validation via sandbox for JS and shell files.

        Writes content to a temp file inside the sandbox container using base64
        encoding to avoid shell injection from UNTRUSTED worker output (the
        content is Qwen output which may contain arbitrary strings). Validates
        with node --check or bash -n, then cleans up.

        Appends errors to fix_result.errors_found if validation fails.
        No-op when sandbox is unavailable (e.g. in unit tests).
        # TODO: Add CSS/HTML validation when suitable validators are available
        # in the sandbox image (e.g. csslint, html-validate).
        """
        logger.debug(
            "_validate_syntax_post_fix called",
            extra={
                "event": "validate.syntax_post_fix",
                "path": path,
                "has_sandbox": self._sandbox is not None,
                "has_fix_result": fix_result is not None,
            },
        )
        if not self._sandbox or fix_result is None or fix_result.skipped:
            logger.debug(
                "_validate_syntax_post_fix: early return, sandbox or fix_result unavailable",
                extra={
                    "event": "validate.syntax_post_fix_skip",
                    "reason": "precondition",
                },
            )
            return

        ext = os.path.splitext(path)[1].lower()
        if ext in self._JS_EXTENSIONS:
            logger.debug(
                "_validate_syntax_post_fix: clean",
                extra={"event": "validate.syntax_post_fix_skip.clean"},
            )
            validator_cmd = "node --check"
        elif ext in self._SHELL_EXTENSIONS:
            logger.debug(
                "_validate_syntax_post_fix: clean",
                extra={"event": "validate.syntax_post_fix_skip.clean"},
            )
            validator_cmd = "bash -n"
        else:
            logger.debug(
                "_validate_syntax_post_fix: extension not in validated types",
                extra={
                    "event": "validate.syntax_post_fix_skip",
                    "reason": "unsupported_ext",
                    "ext": ext,
                },
            )
            return

        tmp_name = f"/tmp/_validate_{uuid4().hex}{ext}"  # nosec B108 — inside sandbox container (tmpfs, noexec, network=none)
        try:
            # Base64-encode content to avoid shell injection — worker output is
            # UNTRUSTED and could contain heredoc terminators or shell metacharacters.
            b64 = base64.b64encode(fix_result.content.encode()).decode()
            # Q11-U1 documented exception: post-fix syntax-validation probe
            # (write tmp file + run validator). Bounded probe class — not on
            # any external-service hot path; not operator-tunable.
            check = await self._sandbox.run(
                f"echo {b64} | base64 -d > {tmp_name} && {validator_cmd} {tmp_name}",
                timeout=5,
            )
            if check.exit_code != 0:
                err_msg = f"{validator_cmd} failed: {check.stderr.strip()}"
                fix_result.errors_found.append(err_msg)
                logger.warning(
                    "Post-fix syntax validation failed",
                    extra={
                        "event": "post.fix_validation_failed",
                        "path": path,
                        "validator": validator_cmd,
                        "error": err_msg,
                    },
                )
        except Exception as exc:  # catch-all: validation must not block write
            # Validation failure must never block the write
            logger.debug(
                "Post-fix validation error (non-blocking): %s",
                exc,
                extra={
                    "event": "post.fix_validation_error",
                    "path": path,
                    "error": str(exc),
                },
                exc_info=True,
            )

    async def _run_semgrep_prescan(self, content: str, path: str) -> None:
        """D4: Pre-write Semgrep scan at TL3+ — defence-in-depth.

        Fail-closed: if Semgrep crashes, the write is blocked.
        Raises ToolBlockedError if issues are detected or scan fails.
        """
        if self._trust_level < 3 or not semgrep_scanner.is_loaded():
            return

        lang_hint = _detect_language_from_path(path)
        try:
            sg_result = await semgrep_scanner.scan_blocks([(content, lang_hint)])
            if sg_result.found:
                match_names = [m.pattern_name for m in sg_result.matches]
                logger.warning(
                    "file_write blocked by pre-write Semgrep scan",
                    extra={
                        "event": "file.write.semgrep_blocked",
                        "path": path,
                        "matches": match_names,
                    },
                )
                # Q14-FL1: fixed-template user-facing reason (no derived
                # path, no scanner output count). Server-side log above
                # already emits match_names + path via extra={...}.
                raise ToolBlockedError("Pre-write Semgrep scan blocked content")
            logger.debug(
                "Pre-write Semgrep scan clean",
                extra={
                    "event": "file.write.semgrep_clean",
                    "path": path,
                },
            )
        except ToolBlockedError:
            raise  # Re-raise our own ToolBlockedError
        except Exception as exc:
            # B-001: Fail-closed — if Semgrep crashes, block the write
            logger.error(
                "Pre-write Semgrep scan failed — blocking write (fail-closed)",
                extra={
                    "event": "file.write.semgrep_error",
                    "path": path,
                    "error": str(exc),
                    "error_category": "security",
                    "error_class": "permanent",
                },
                exc_info=True,
            )
            # Q14-FL1: fixed-template user-facing reason (no exception
            # text). `from exc` chains the underlying exception
            # server-side; `exc_info=True` log above captures detail.
            raise ToolBlockedError("Pre-write scan failed (fail-closed)") from exc

    @staticmethod
    def _strip_worker_wrapping(content: str) -> str:
        """Strip ``<RESPONSE>`` tags and markdown code fences from worker output.

        Worker LLM often wraps code fragments in these — they must be
        removed before the content is used as a patch.
        """
        _original_len = len(content)

        # Strip <RESPONSE> tags
        if "<RESPONSE>" in content:
            if "</RESPONSE>" in content:
                _m = re.search(r"<RESPONSE>(.*?)</RESPONSE>", content, re.DOTALL)
                if _m:
                    content = _m.group(1).strip()
                    logger.debug(
                        "file_patch: stripped <RESPONSE> tags",
                        extra={
                            "event": "file.patch_strip_response",
                            "stripped_len": _original_len - len(content),
                        },
                    )
            else:
                _s = content.index("<RESPONSE>") + len("<RESPONSE>")
                content = content[_s:].strip()
                logger.debug(
                    "file_patch: stripped unclosed <RESPONSE> tag",
                    extra={
                        "event": "file.patch_strip_response",
                        "stripped_len": _original_len - len(content),
                    },
                )

        # Strip markdown fences
        if "```" in content:
            _pre_fence_len = len(content)
            _lines = content.split("\n")
            if (
                len(_lines) >= 3
                and re.match(r"^```\w*\s*$", _lines[0])
                and _lines[-1].strip() == "```"
            ):
                content = "\n".join(_lines[1:-1])
            else:
                blocks = extract_code_blocks(content)
                if len(blocks) == 1 and blocks[0].code.strip():
                    content = blocks[0].code
            if len(content) != _pre_fence_len:
                logger.debug(
                    "file_patch: stripped markdown fences",
                    extra={
                        "event": "file.patch_strip_fences",
                        "stripped_len": _pre_fence_len - len(content),
                    },
                )

        return content

    @staticmethod
    def _extract_fixer_context(
        anchor: str,
        current: str,
        path: str,
    ) -> str | None:
        """Extract surrounding file lines near the anchor for the code fixer.

        Returns up to ``_CONTEXT_WINDOW_LINES`` lines each side of the
        anchor position, or ``None`` if extraction fails or the anchor
        uses a ``css:`` prefix (position unknown until CSS resolution).
        """
        if anchor.startswith("css:"):
            return None

        try:
            _anchor_pos = current.find(anchor[:_ANCHOR_FIND_LIMIT])
            if _anchor_pos < 0:
                return None
            _anchor_line = current[:_anchor_pos].count("\n")
            _file_lines = current.split("\n")
            _ctx_start = max(0, _anchor_line - _CONTEXT_WINDOW_LINES)
            _ctx_end = min(len(_file_lines), _anchor_line + _CONTEXT_WINDOW_LINES)
            _surrounding_ctx = "\n".join(_file_lines[_ctx_start:_ctx_end])
            logger.debug(
                "file_patch: fixer context extracted (lines %d-%d, %d chars)",
                _ctx_start,
                _ctx_end,
                len(_surrounding_ctx),
                extra={
                    "event": "file.patch_fixer_context",
                    "path": path,
                    "context_start_line": _ctx_start,
                    "context_end_line": _ctx_end,
                    "context_length": len(_surrounding_ctx),
                },
            )
            return _surrounding_ctx
        except Exception as _ctx_exc:  # catch-all: fixer context extraction best-effort
            logger.debug(
                "file_patch: fixer context extraction failed: %s",
                _ctx_exc,
                extra={
                    "event": "file.patch_fixer_context_error",
                    "path": path,
                    "error": str(_ctx_exc),
                },
                exc_info=True,
            )
            return None

    @staticmethod
    def _check_structural_integrity(
        current: str,
        patched: str,
        anchor_result,
        operation: str,
        backend,
        path: str,
        backup_path: str,
    ) -> dict:
        """Run the backend's structural check on the patched content.

        Blocks destructive patches (rolls back from backup) and warns on
        non-fatal element removal.  Delete operations skip the blocking
        check — removing an element is intentional.

        Returns a dict of structural metadata to merge into exec_meta.
        Raises ToolError if the patch destroyed a target element.
        """
        structural_meta: dict = {}
        if not current:
            logger.debug(
                "_check_structural_integrity: not_current",
                extra={
                    "event": "_file_ops._check_structural_integrity.match",
                    "reason": "not_current",
                },
            )  # auto:neg
            return structural_meta

        try:
            survival = backend.structural_check(
                current,
                patched,
                anchor_result,
                operation=operation,
            )
            if survival.get("blocking") and operation != "delete":
                # Target element destroyed — rollback and error
                shutil.copy2(backup_path, path)
                _removed = survival.get("elements_removed", ["?"])
                logger.error(
                    "file_patch: BLOCKED — target element #%s destroyed, rolling back",
                    _removed[0],
                    extra={
                        "event": "file.patch_structural_blocked",
                        "path": path,
                        "target_id": _removed,
                        "backup_path": backup_path,
                    },
                )
                raise ToolError(
                    "file_patch failed: patch destroyed target element, file restored"
                )
            if not survival.get("survival_ok", True):
                structural_meta["structural_elements_removed"] = survival[
                    "elements_removed"
                ]
                logger.warning(
                    "file_patch: structural elements removed: %s",
                    survival["elements_removed"],
                    extra={
                        "event": "file.patch_structural_warning",
                        "path": path,
                        "elements_removed": survival["elements_removed"],
                    },
                )
            else:
                logger.debug(
                    "file_patch: structural check passed",
                    extra={"event": "file.patch_structural_ok", "path": path},
                )
        except ToolError:
            raise  # Re-raise blocking errors
        except Exception as exc:  # catch-all: structural check must not block patch
            logger.warning(
                "file_patch: structural check failed: %s",
                exc,
                extra={
                    "event": "file.structural_survival_error",
                    "path": path,
                    "error": str(exc),
                    "error_category": "validation",
                    "error_class": "permanent",
                },
                exc_info=True,
            )

        return structural_meta

    async def _run_full_file_fixer(
        self,
        path: str,
        patched: str,
        ext: str,
    ) -> tuple[str, dict]:
        """Run the code fixer on the complete patched file content.

        Applies language-aware fixes (syntax repair, formatting) to the
        full file after the patch has been applied.  Falls back gracefully
        on crash.  Returns ``(patched_content, fixer_meta_dict)``.
        """
        _basename_full = os.path.basename(path)
        if (
            ext.lower() not in _CODE_EXTENSIONS
            and _basename_full not in _EXTENSIONLESS_FIXER_NAMES
        ):
            logger.debug(
                "_run_full_file_fixer: condition_match",
                extra={
                    "event": "_file_ops._run_full_file_fixer.match",
                    "reason": "condition_match",
                },
            )  # auto:neg
            return patched, dict(self._FULL_FIXER_META_DEFAULTS)

        try:
            full_fix_result = code_fixer_fix(path, patched)
            if full_fix_result.changed:
                patched = full_fix_result.content
                logger.debug(
                    "file_patch: full-file fixer — %d fixes, %d errors",
                    len(full_fix_result.fixes_applied),
                    len(full_fix_result.errors_found),
                    extra={
                        "event": "file.patch_full_fixer",
                        "path": path,
                        "fixes_count": len(full_fix_result.fixes_applied),
                        "errors_count": len(full_fix_result.errors_found),
                        "changed": True,
                    },
                )
            elif full_fix_result.errors_found:
                logger.warning(
                    "file_patch: full-file fixer found unfixable errors",
                    extra={
                        "event": "file.patch_full_fixer",
                        "path": path,
                        "fixes_count": 0,
                        "errors_count": len(full_fix_result.errors_found),
                        "errors": full_fix_result.errors_found,
                        "changed": False,
                    },
                )
            else:
                logger.debug(
                    "file_patch: full-file fixer — 0 fixes, 0 errors",
                    extra={
                        "event": "file.patch_full_fixer",
                        "path": path,
                        "fixes_count": 0,
                        "errors_count": 0,
                        "changed": False,
                    },
                )
            # Post-fix syntax validation for full-file fixer
            await self._validate_syntax_post_fix(path, full_fix_result)
            return patched, {
                "full_file_fixer_changed": full_fix_result.changed,
                "full_file_fixer_fixes": full_fix_result.fixes_applied,
                "full_file_fixer_errors": full_fix_result.errors_found,
                "full_file_fixer_warnings": full_fix_result.warnings,
            }
        except Exception:  # catch-all: code fixer crash must not block patch
            logger.warning(
                "Full-file code fixer crash in file_patch — using patched content",
                extra={"event": "file.patch_full_fixer_crash", "path": path},
                exc_info=True,
            )
            return patched, dict(self._FULL_FIXER_META_DEFAULTS)

    async def _execute_in_sandbox(
        self, command: str, args: dict
    ) -> tuple[TaggedData, dict | None]:
        """Execute a shell command in a disposable Podman sandbox container."""
        timeout = args.get("timeout")

        sandbox_result = await self._sandbox.run(command, timeout=timeout)

        from sentinel.analysis.logging_injector import truncate_log_capture

        exec_meta = {
            "exit_code": sandbox_result.exit_code,
            "stderr": truncate_log_capture(sandbox_result.stderr or ""),
            "timed_out": sandbox_result.timed_out,
            "oom_killed": sandbox_result.oom_killed,
        }

        # Format output similar to direct shell, but with sandbox-specific info
        if sandbox_result.timed_out:
            output = sandbox_result.stdout
            output += f"\n[sandbox timed out after {self._sandbox.default_timeout}s]"
            if sandbox_result.stderr:
                logger.debug(
                    "_execute_in_sandbox: stderr",
                    extra={
                        "event": "_file_ops._execute_in_sandbox.match",
                        "reason": "stderr",
                    },
                )  # auto:neg
                output += f"\n{sandbox_result.stderr}"
        elif sandbox_result.oom_killed:
            output = sandbox_result.stdout
            output += "\n[sandbox out of memory — container killed]"
        elif sandbox_result.exit_code != 0:
            output = sandbox_result.stdout
            output += (
                f"\n[exit code: {sandbox_result.exit_code}]\n{sandbox_result.stderr}"
            )
        else:
            output = sandbox_result.stdout

        logger.info(
            "Sandbox shell complete",
            extra={
                "event": "sandbox.shell_complete",
                "command_len": len(command),
                "exit_code": sandbox_result.exit_code,
                "container_id": sandbox_result.container_id[:12],
            },
        )

        return await create_tagged_data(
            content=output,
            source=DataSource.SANDBOX,
            trust_level=TrustLevel.UNTRUSTED,
            originated_from=f"sandbox:{command}",
        ), exec_meta

    @tool_handler(
        "file_read",
        description=(
            "Read the contents of a file. All paths must be absolute and under "
            "/workspace/ (e.g. /workspace/sites/my-site/index.html, "
            "/workspace/scripts/app.py)."
        ),
        args={"path": "string (absolute path under /workspace/)"},
        group="file",
        order=10,
    )
    async def _file_read(self, args: dict) -> tuple[TaggedData, dict | None]:
        path = args.get("path", "")
        if not isinstance(path, str):
            raise ToolError("Invalid argument: path must be a string", category="validation")

        result = self._engine.check_file_read(path)
        if result.status != PolicyResult.ALLOWED:
            logger.warning(
                "file_read blocked by policy",
                extra={
                    "event": "file.read_blocked",
                    "path": path,
                    "reason": result.reason,
                },
            )
            raise ToolBlockedError(f"file_read blocked: {result.reason}")

        logger.debug(
            "file_read policy passed",
            extra={"event": "file.read_allowed", "path": path},
        )

        # Cap file size to prevent OOM on large files (module constant)
        try:
            file_size = os.path.getsize(path)
        except (OSError, ValueError) as exc:
            logger.error(
                "file_read OS error",
                extra={"event": "file.read_error", "path": path, "error": str(exc)},
                exc_info=True,
            )
            raise ToolError("file_read failed:") from exc

        if file_size > FILE_READ_MAX_BYTES:
            logger.warning(
                "file_read: file too large",
                extra={
                    "event": "file.read_too_large",
                    "file_size": file_size,
                    "max_bytes": FILE_READ_MAX_BYTES,
                },
            )
            raise ToolError("file_read failed: file too large")

        try:
            with open(path, encoding="utf-8", newline="") as f:
                content = f.read()
        except UnicodeDecodeError as exc:
            # Must be caught before ValueError: UnicodeDecodeError is a subclass
            # of ValueError, so a combined (OSError, ValueError) clause would
            # swallow it first, making this branch unreachable.
            logger.warning(
                "file_read: file is not valid UTF-8",
                extra={
                    "event": "file.read_decode_error",
                    "path": path,
                    "error_category": "validation",
                },
                exc_info=True,
            )
            raise ToolError("File is not valid UTF-8") from exc
        except (OSError, ValueError) as exc:
            logger.error(
                "file_read OS error",
                extra={"event": "file.read_error", "path": path, "error": str(exc)},
                exc_info=True,
            )
            raise ToolError("file_read failed:") from exc

        exec_meta = {
            "file_size": len(content),
        }

        # Content manifest — extract structural metadata so replans have
        # visibility into file structure even before mutations occur
        try:
            from sentinel.analysis.content_manifest import extract_content_manifest

            _manifest_ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
            if _manifest_ext in _MANIFEST_EXTENSIONS:
                exec_meta["content_manifest"] = extract_content_manifest(
                    os.path.basename(path),
                    content,
                    "",
                )
                logger.debug(
                    "file_read: content manifest extracted",
                    extra={"event": "content.manifest_file_read", "path": path},
                )
            else:
                logger.debug(
                    "file_read: manifest skipped (unsupported ext)",
                    extra={
                        "event": "content.manifest_skip",
                        "path": path,
                        "ext": _manifest_ext,
                    },
                )
        except Exception as exc:  # catch-all: manifest extraction best-effort
            logger.warning(
                "file_read: content manifest extraction failed: %s",
                exc,
                extra={
                    "event": "content.manifest_error",
                    "path": path,
                    "error": str(exc),
                },
                exc_info=True,
            )

        # Before-hash for content_changed assertions — captured at read time
        # so the assertion evaluator can verify mutations actually occurred.
        # Hash raw bytes to match the verifier's binary read in
        # _eval_content_changed() (verification.py).
        _read_hash = hashlib.sha256(
            content.encode("utf-8") if isinstance(content, str) else content
        ).hexdigest()
        _ctx = get_current_task_context()
        if _ctx is not None:
            _ctx.file_hashes[path] = _read_hash
        logger.debug(
            "file_read: before_hash captured",
            extra={
                "event": "before.hash_captured",
                "path": path,
                "hash_prefix": _read_hash[:16],
            },
        )

        # Determine trust level: files without a provenance record or with
        # mismatched content hash are UNTRUSTED (prevents trust laundering).
        # Only files with valid provenance AND matching hash inherit TRUSTED.
        trust_level = TrustLevel.UNTRUSTED  # Fail-closed default
        parent_ids = []
        writer_info = await get_file_writer(path)
        if writer_info is not None:
            writer_id, recorded_hash = writer_info
            # Verify content hasn't been tampered with since provenance was recorded
            current_hash = hashlib.sha256(
                content.encode() if isinstance(content, str) else content
            ).hexdigest()
            if recorded_hash and current_hash == recorded_hash:
                logger.debug(
                    "_file_read: clean",
                    extra={"event": "provenance_hash_mismatch.clean"},
                )
                parent_ids = [writer_id]
                writer_data = await get_tagged_data(writer_id)
                if writer_data and writer_data.trust_level == TrustLevel.TRUSTED:
                    trust_level = TrustLevel.TRUSTED
                # else: orphaned record or UNTRUSTED writer → stays UNTRUSTED
            else:
                # Hash mismatch (file overwritten) or empty hash (legacy record)
                logger.warning(
                    "File content hash mismatch — provenance stale",
                    extra={
                        "event": "provenance.hash_mismatch",
                        "path": path,
                        "recorded_hash": recorded_hash[:16] + "..."
                        if recorded_hash
                        else "<empty>",
                    },
                )

        logger.info(
            "File read",
            extra={
                "event": "file.read_success",
                "path": path,
                "size": len(content),
                "trust_level": trust_level.value,
                "inherited_from": writer_info[0] if writer_info else None,
            },
        )
        if _ctx is not None:
            _ctx.file_reads.add(path)
        logger.debug(
            "file_read tracked for file_write enforcement",
            extra={"event": "file.read_tracked", "path": path},
        )
        return await create_tagged_data(
            content=content,
            source=DataSource.FILE,
            trust_level=trust_level,
            originated_from=f"file_read:{path}",
            parent_ids=parent_ids,
        ), exec_meta

    @tool_handler(
        "mkdir",
        description="Create a directory (and parents)",
        args={"path": "string"},
        group="file",
        order=10,
    )
    async def _mkdir(self, args: dict) -> tuple[TaggedData, dict | None]:
        path = args.get("path", "")

        result = self._engine.check_file_write(path)
        if result.status != PolicyResult.ALLOWED:
            logger.warning(
                "mkdir blocked by policy",
                extra={"event": "mkdir.blocked", "path": path, "reason": result.reason},
            )
            raise ToolBlockedError(f"mkdir blocked: {result.reason}")

        try:
            os.makedirs(path, exist_ok=True)
        except OSError as exc:
            logger.error(
                "mkdir OS error",
                extra={"event": "mkdir.error", "path": path, "error": str(exc)},
                exc_info=True,
            )
            raise ToolError("mkdir failed:") from exc

        logger.info(
            "Directory created",
            extra={"event": "mkdir.success", "path": path},
        )

        return await create_tagged_data(
            content=f"Directory created: {path}",
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
            originated_from=f"mkdir:{path}",
        ), None

    @tool_handler(
        "shell",
        description="Run a shell command and return its output",
        args={"command": "string"},
        aliases=("shell_exec",),
        group="file",
        order=10,
    )
    async def _shell(self, args: dict) -> tuple[TaggedData, dict | None]:
        command = args.get("command", "")

        # Sandbox is the security boundary at TL2+ — exempt inline-execution
        # patterns (python3 -c) that are safe within the sandbox's
        # network=none / read-only-root / dropped-caps constraints.
        sandbox_active = self._sandbox is not None
        result = self._engine.check_command(command, sandbox_context=sandbox_active)
        if result.status != PolicyResult.ALLOWED:
            logger.warning(
                "Shell command blocked by policy",
                extra={
                    "event": "shell.blocked",
                    "command_len": len(command),
                    "reason": result.reason,
                },
            )
            raise ToolBlockedError(f"shell blocked: {result.reason}")

        logger.info(
            "Shell command policy passed",
            extra={"event": "shell.allowed", "command_len": len(command)},
        )

        # E5: Route to sandbox when available (regardless of trust level)
        if self._sandbox is not None:
            return await self._execute_in_sandbox(command, args)

        # Fallback: direct shell when sandbox is genuinely unavailable.
        # Output is UNTRUSTED — this path has network access and full
        # container FS, unlike the sandbox (no network, read-only root).
        # E-004: Timeouts — shell from config, podman ops are fixed constants
        # (container-internal operations: podman_build=300s, podman_run=60s, podman_stop=30s).
        from sentinel.core.config import settings

        try:
            proc = await asyncio.create_subprocess_exec(
                *shlex.split(command),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=settings.shell_timeout,
                )
            except TimeoutError as exc:
                proc.kill()
                await proc.wait()
                logger.error(
                    "Shell command timed out",
                    extra={"event": "shell.timeout", "command_len": len(command)},
                    exc_info=True,
                )
                raise ToolError("shell command timed out:") from exc
            stdout = stdout_bytes.decode(errors="replace")
            stderr = stderr_bytes.decode(errors="replace")
            exec_meta = {
                "exit_code": proc.returncode,
                "stderr": stderr[:200] if stderr else "",
            }
            output = stdout
            if proc.returncode != 0:
                output += f"\n[exit code: {proc.returncode}]\n{stderr}"
                logger.warning(
                    "Shell command non-zero exit",
                    extra={
                        "event": "shell.nonzero",
                        "command_len": len(command),
                        "exit_code": proc.returncode,
                    },
                )
        except OSError as exc:
            logger.error(
                "Shell command OS error",
                extra={
                    "event": "shell.error",
                    "command_len": len(command),
                    "error": str(exc),
                },
                exc_info=True,
            )
            raise ToolError("shell failed:") from exc

        return await create_tagged_data(
            content=output,
            source=DataSource.TOOL,
            trust_level=TrustLevel.UNTRUSTED,
            originated_from=f"shell:{command}",
        ), exec_meta
