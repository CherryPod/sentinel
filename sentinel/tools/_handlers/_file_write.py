"""Write operation handlers — file_write and supporting sub-methods."""

import logging
import os
import re
import tempfile

from sentinel.core.context import PrincipalRequiredError, current_user_id
from sentinel.core.models import DataSource, PolicyResult, TaggedData, TrustLevel
from sentinel.security.code_extractor import extract_code_blocks
from sentinel.security.code_fixer import FixResult
from sentinel.security.code_fixer import fix_code as code_fixer_fix
from sentinel.security.provenance import create_tagged_data, record_file_write
from sentinel.tools._handlers._constants import (
    _CODE_EXTENSIONS,
    _EXTENSIONLESS_FIXER_NAMES,
    _MANIFEST_EXTENSIONS,
)
from sentinel.tools._handlers._file_ops import FILE_READ_MAX_BYTES
from sentinel.tools._handlers._registry import tool_handler
from sentinel.tools._handlers._task_exec_context import get_current_task_context
from sentinel.tools._handlers._types import ToolBlockedError, ToolError
from sentinel.tools.anchor_allocator import allocate_anchors
from sentinel.tools.anchor_allocator._memory import clear_anchor_map

logger = logging.getLogger(__name__)

# Capture process umask once at import time (single-threaded) so callers can
# compute open("w")-equivalent permissions without the thread-unsafe
# read-and-restore idiom (os.umask temporarily sets the global to 0).
_PROCESS_UMASK: int = os.umask(0)
os.umask(_PROCESS_UMASK)


class WriteHandlerMixin:
    """Write operation handlers — file_write and supporting sub-methods."""

    # Language map for structural survival check — maps file extension
    # to the language identifier used by structural_survival_check().
    _SURVIVAL_LANG_MAP = {
        "html": "html",
        "htm": "html",
        "js": "javascript",
        "mjs": "javascript",
        "py": "python",
        "css": "css",
    }

    # ── file_write sub-methods ──────────────────────────────────

    async def _run_write_code_fixer(
        self, content: str, path: str, ext: str
    ) -> tuple[str, object]:
        """Run code fixer and post-fix syntax validation on write content.

        Returns (possibly-modified content, fix_result or None).
        Fail-safe: if fixer crashes, original content passes through.
        """
        logger.debug(
            "Running code fixer",
            extra={"event": "file.write.code_fixer_entry", "path": path, "ext": ext},
        )
        fix_result = None
        _basename = os.path.basename(path)
        if (
            ext.lower() not in _CODE_EXTENSIONS
            and _basename not in _EXTENSIONLESS_FIXER_NAMES
        ):
            logger.debug(
                "_run_write_code_fixer: condition_match",
                extra={
                    "event": "_file_write._run_write_code_fixer.match",
                    "reason": "condition_match",
                },
            )  # auto:neg
            return content, fix_result

        try:
            fix_result = code_fixer_fix(path, content)
            if fix_result.changed:
                content = fix_result.content
                logger.info(
                    "Code fixer applied fixes",
                    extra={
                        "event": "file.write.code_fixer_applied",
                        "path": path,
                        "fixes": fix_result.fixes_applied,
                        "errors_found": fix_result.errors_found,
                        "warnings": fix_result.warnings,
                    },
                )
            elif fix_result.errors_found:
                logger.warning(
                    "Code fixer found unfixable errors",
                    extra={
                        "event": "file.write.code_fixer_errors",
                        "path": path,
                        "errors": fix_result.errors_found,
                    },
                )
        except Exception as exc:
            # Fail-safe: fixer crash must never block a file write
            logger.error(
                "Code fixer crashed — writing original content",
                extra={
                    "event": "file.write.code_fixer_crash",
                    "path": path,
                    "error": str(exc),
                },
                exc_info=True,
            )
            fix_result = None

        # Post-fix syntax validation (node --check / bash -n).
        # ORDERING: must run BEFORE exec_meta is built, because validation
        # appends errors to fix_result.errors_found in-place.
        if fix_result is not None:
            await self._validate_syntax_post_fix(path, fix_result)

        return content, fix_result

    async def _run_write_anchor_allocator(
        self, content: str, path: str, ext: str, fix_result: FixResult | None
    ) -> str:
        """Run anchor allocator on written file content.

        Skips if structurally invalid. Returns possibly-modified content.
        """
        from sentinel.core.config import settings as _aa_settings

        if (
            not _aa_settings.anchor_allocator_enabled
            or ext.lower() not in _CODE_EXTENSIONS
        ):
            return content

        _aa_user_id = current_user_id.get()
        _structural_fail = fix_result is not None and any(
            "structural_integrity_failure" in e for e in fix_result.errors_found
        )
        if _structural_fail:
            _ep_store = getattr(self, "_episodic_store", None)
            if _ep_store:
                try:
                    await clear_anchor_map(path, _ep_store, _aa_user_id)
                except PrincipalRequiredError:
                    # Q4.fix.f Coord follow-up: zero-principal must propagate
                    # past the best-effort swallow so the fail-closed invariant
                    # is preserved at the producer boundary.
                    raise
                except Exception:  # catch-all: anchor cleanup best-effort
                    logger.debug(
                        "Anchor map cleanup failed (non-fatal)",
                        extra={"event": "file.anchormap.clearfailed", "path": path},
                        exc_info=True,
                    )
            logger.warning(
                "File structurally invalid — anchor allocation skipped",
                extra={"event": "file.write.anchor_skipped_integrity", "path": path},
            )
            return content

        try:
            _anchor_result = await allocate_anchors(
                path=path,
                content=content,
                episodic_store=getattr(self, "_episodic_store", None),
                user_id=_aa_user_id,
                tier=_aa_settings.anchor_allocator_tier,
            )
            if _anchor_result.changed:
                content = _anchor_result.content
            if _anchor_result.parse_failed:
                logger.warning(
                    "Anchor allocation parse failed",
                    extra={
                        "event": "file.write.anchor_allocation_failed",
                        "path": path,
                        "error": _anchor_result.error,
                    },
                )
        except PrincipalRequiredError:
            # Q4.fix.f Coord follow-up: zero-principal must propagate past
            # the "never block a write" swallow so the fail-closed invariant
            # is preserved at the producer boundary.
            raise
        except Exception:  # catch-all: anchor allocator crash must not block write
            logger.warning(
                "Anchor allocator crash — writing content without anchors",
                extra={"event": "file.write.anchor_allocator_error", "path": path},
                exc_info=True,
            )

        return content

    def _write_to_disk(self, content: str, path: str, ext: str) -> dict:
        """Write content to disk with directory creation and init.py auto-create.

        Returns logging injection metadata dict for exec_meta.
        Raises ToolBlockedError if parent directory policy fails.
        Raises ToolError on OS errors.
        """
        logger.debug(
            "Writing file to disk",
            extra={
                "event": "file.write.disk_entry",
                "path": path,
                "content_len": len(content),
            },
        )
        exec_meta_logging: dict = {}
        try:
            parent = os.path.dirname(path)
            if parent:
                # E-002: Validate parent path against policy before creating
                parent_result = self._engine.check_file_write(parent)
                if parent_result.status != PolicyResult.ALLOWED:
                    raise ToolBlockedError(
                        f"Parent directory blocked by policy: {parent_result.reason}"
                    )
                os.makedirs(parent, exist_ok=True)

            # Defence-in-depth: auto-create missing __init__.py in Python
            # packages. Qwen frequently forgets __init__.py in subdirs,
            # causing ModuleNotFoundError on import.
            if ext.lower() == ".py" and path.startswith("/workspace/"):
                parts = path.split("/")
                # Walk /workspace/<pkg>/ … <parent>/ creating __init__.py.
                # Skip /workspace/ itself — it's not a package.
                for i in range(3, len(parts)):
                    pkg_dir = "/".join(parts[:i])
                    init_path = os.path.join(pkg_dir, "__init__.py")
                    if os.path.isdir(pkg_dir) and not os.path.exists(init_path):
                        with open(init_path, "w") as f:
                            f.write("")
                        logger.info(
                            "Auto-created missing __init__.py",
                            extra={
                                "event": "file.write.auto_init_py",
                                "init_path": init_path,
                                "trigger_file": path,
                            },
                        )

            # Logging injection (shadow copy for sandbox only) — produce an
            # instrumented copy with debug logging for sandbox execution.
            # The CLEAN content goes to disk; the instrumented version is held
            # in memory and stored in exec_meta for sandbox.run() only.
            from sentinel.analysis.logging_injector import inject_logging

            if ext.lower() in (".py", ".js", ".mjs"):
                inject_result = inject_logging(content, ext.lower())
                if inject_result.changed:
                    exec_meta_logging = {
                        "logging_injected": True,
                        "logging_injection_count": inject_result.injection_count,
                        "_instrumented_content": inject_result.content,
                    }
                    logger.debug(
                        "Logging injected (shadow): %d entry points in %s",
                        inject_result.injection_count,
                        path,
                        extra={
                            "event": "file.write.logging_injected",
                            "path": path,
                            "count": inject_result.injection_count,
                        },
                    )

            tmp_fd = None
            tmp_path = None
            try:
                tmp_fd, tmp_path = tempfile.mkstemp(
                    dir=os.path.dirname(path) or ".",
                    suffix=".sentinel_tmp",
                )
                with os.fdopen(tmp_fd, "w", encoding="utf-8", newline="") as f:
                    tmp_fd = None  # os.fdopen took ownership
                    f.write(content)
                try:
                    st = os.stat(path)
                    os.chmod(tmp_path, st.st_mode)
                except OSError:
                    # New file: apply the cached process umask the same way
                    # open("w") would. Using the module-level constant avoids
                    # the thread-unsafe read-and-restore idiom at runtime.
                    os.chmod(tmp_path, 0o666 & ~_PROCESS_UMASK)
                os.replace(tmp_path, path)
                tmp_path = None  # success — don't clean up
            except (ToolBlockedError, ToolError):
                raise
            except OSError as exc:
                logger.error(
                    "file_write OS error",
                    extra={"event": "file.write.os_error", "path": path, "error": str(exc)},
                    exc_info=True,
                )
                raise ToolError("file_write failed:") from exc
            finally:
                if tmp_fd is not None:
                    os.close(tmp_fd)
                if tmp_path is not None:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass

        except (ToolBlockedError, ToolError):
            raise
        except OSError as exc:
            logger.error(
                "file_write OS error",
                extra={"event": "file.write.os_error", "path": path, "error": str(exc)},
                exc_info=True,
            )
            raise ToolError("file_write failed:") from exc

        return exec_meta_logging

    async def _finalize_write(
        self,
        content: str,
        path: str,
        fix_result: FixResult | None,
        before_content: str | None,
        before_size: int | None,
        exec_meta_logging: dict,
    ) -> tuple[TaggedData, dict]:
        """Build tagged data, record provenance, build exec_meta with manifest and survival check."""
        logger.info(
            "File written",
            extra={"event": "file.write.complete", "path": path, "size": len(content)},
        )
        tagged = await create_tagged_data(
            content=f"File written: {path}",
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
            originated_from=f"file_write:{path}",
        )
        # Record file provenance so file_read can inherit trust from the writer.
        await record_file_write(path, tagged.id, content=content)

        exec_meta: dict = {
            "file_size_before": before_size,
            "file_size_after": len(content),
            "file_content_before": before_content,
            "code_fixer_changed": fix_result.changed if fix_result else False,
            "code_fixer_fixes": fix_result.fixes_applied if fix_result else [],
            "code_fixer_errors": fix_result.errors_found if fix_result else [],
            "code_fixer_warnings": fix_result.warnings if fix_result else [],
        }

        # Content manifest — observable properties for verification judge
        self._extract_write_manifest(exec_meta, content, path)

        # Merge logging injection metadata
        exec_meta.update(exec_meta_logging)

        # Structural survival check for overwrites
        self._check_write_structural_survival(exec_meta, before_content, content, path)

        # Warn if file_write used on a previously-read file
        _ctx = get_current_task_context()
        if _ctx is not None and path in _ctx.file_reads:
            exec_meta["file_write_after_read_warning"] = (
                "file_write used on a previously-read file — "
                "consider file_patch for partial modifications"
            )
            logger.info(
                "file_write on previously-read file",
                extra={
                    "event": "file.write.after_read",
                    "path": path,
                    "hint": "consider file_patch",
                },
            )

        return tagged, exec_meta

    @staticmethod
    def _extract_write_manifest(exec_meta: dict, content: str, path: str) -> None:
        """Extract content manifest into exec_meta if file extension is eligible."""
        try:
            from sentinel.analysis.content_manifest import extract_content_manifest

            _manifest_ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
            if _manifest_ext in _MANIFEST_EXTENSIONS:
                logger.debug(
                    "Extracting content manifest",
                    extra={
                        "event": "file.write.manifest_attempt",
                        "path": path,
                        "ext": _manifest_ext,
                    },
                )
                exec_meta["content_manifest"] = extract_content_manifest(
                    os.path.basename(path),
                    content,
                    "",
                )
                logger.debug(
                    "Content manifest extracted",
                    extra={"event": "file.write.manifest_done", "path": path},
                )
            else:
                logger.debug(
                    "Content manifest skipped for ext=%s",
                    _manifest_ext,
                    extra={
                        "event": "file.write.manifest_skip_ext",
                        "path": path,
                        "ext": _manifest_ext,
                    },
                )
        except Exception as exc:  # catch-all: manifest extraction best-effort
            logger.warning(
                "Content manifest extraction failed: %s",
                exc,
                extra={
                    "event": "file.write.manifest_error",
                    "path": path,
                    "error": str(exc),
                },
                exc_info=True,
            )

    @staticmethod
    def _check_write_structural_survival(
        exec_meta: dict,
        before_content: str | None,
        after_content: str,
        path: str,
    ) -> None:
        """Check structural element survival on file overwrite.

        Advisory only — never blocks a write. Populates exec_meta
        with removed elements for the verification judge.
        """
        if not before_content:
            return

        _write_ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
        _write_lang = WriteHandlerMixin._SURVIVAL_LANG_MAP.get(_write_ext, "")
        if not _write_lang:
            return

        try:
            from sentinel.analysis.structural_digest import (
                structural_survival_check,
            )

            survival = structural_survival_check(
                before_content, after_content, _write_lang
            )
            if not survival["survival_ok"]:
                exec_meta["structural_elements_removed"] = survival["elements_removed"]
                logger.warning(
                    "Structural elements removed on overwrite: %s",
                    survival["elements_removed"],
                    extra={
                        "event": "file.write.structural_survival_warning",
                        "path": path,
                        "removed": survival["elements_removed"],
                    },
                )
        except Exception as exc:  # catch-all: survival check must not block write
            # Survival check is advisory — never block a file write
            logger.warning(
                "Structural survival check failed: %s",
                exc,
                extra={
                    "event": "file.write.structural_survival_error",
                    "path": path,
                    "error": str(exc),
                },
                exc_info=True,
            )

    @staticmethod
    def _strip_write_response_tags(content: str, path: str, ext: str) -> str:
        """Defence-in-depth: strip <RESPONSE> tags from code files.

        Primary stripping is in orchestrator (before code block extraction),
        but if tags survive (e.g. edge case, new code path), catch them here
        before writing to disk. Without this, <RESPONSE> on line 1 causes
        SyntaxError in every language.
        """
        if ext.lower() not in _CODE_EXTENSIONS:
            logger.debug(
                "_strip_write_response_tags: condition_match",
                extra={
                    "event": "_file_write._strip_write_response_tags.match",
                    "reason": "condition_match",
                },
            )  # auto:neg
            return content
        logger.debug(
            "_strip_write_response_tags: condition_passed",
            extra={
                "event": "_file_write._strip_write_response_tags.passed",
                "reason": "condition_passed",
            },
        )  # auto:neg

        if "<RESPONSE>" not in content:
            logger.debug(
                "RESPONSE tag check clean — none found",
                extra={"event": "file.write.response_tag_clean", "path": path},
            )
            return content

        if "</RESPONSE>" in content:
            logger.debug(
                "_strip_write_response_tags: </RESPONSE>_in_content",
                extra={
                    "event": "_file_write._strip_write_response_tags.match",
                    "reason": "</RESPONSE>_in_content",
                },
            )  # auto:neg
            match = re.search(r"<RESPONSE>(.*?)</RESPONSE>", content, re.DOTALL)
            if match:
                logger.debug(
                    "_strip_write_response_tags: match",
                    extra={
                        "event": "_file_write._strip_write_response_tags.match",
                        "reason": "match",
                    },
                )  # auto:neg
                content = match.group(1).strip()
        else:
            # Truncated — opening tag but no closing tag (output cap hit).
            # Strip the opening tag and keep everything after it.
            logger.debug(
                "_strip_write_response_tags: </RESPONSE>_in_content",
                extra={
                    "event": "_file_write._strip_write_response_tags.clean",
                    "reason": "</RESPONSE>_in_content",
                },
            )  # auto:neg
            start = content.index("<RESPONSE>") + len("<RESPONSE>")
            content = content[start:].strip()

        if "<RESPONSE>" not in content:  # only log if we actually stripped
            logger.warning(
                "Defence-in-depth: stripped <RESPONSE> tags from file_write content",
                extra={
                    "event": "file.write.response_tag_strip",
                    "path": path,
                },
            )
        return content

    @staticmethod
    def _strip_write_file_tags(content: str, path: str, ext: str) -> str:
        """Defence-in-depth: strip <FILE path="..."> tags from code files.

        When the worker generates multi-file output (e.g. during debug/fix),
        it sometimes wraps each file in <FILE path="...">...</FILE> tags.
        If the planner stores the entire multi-file output in one variable
        and resolves it into multiple file_write steps, every file gets the
        full blob — starting with <FILE> on line 1 → SyntaxError.
        Fix: extract just the block matching this file's path.
        """
        if ext.lower() not in _CODE_EXTENSIONS:
            return content

        if "<FILE" not in content or "</FILE>" not in content:
            logger.debug(
                "FILE tag check clean — none found",
                extra={"event": "file.write.file_tag_clean", "path": path},
            )
            return content

        # Find all <FILE path="...">...</FILE> blocks
        file_blocks = re.findall(
            r'<FILE\s+path="([^"]+)">\s*(.*?)\s*</FILE>',
            content,
            re.DOTALL,
        )
        if not file_blocks:
            return content

        # Try to match by target path: exact match, then basename
        target_basename = os.path.basename(path)
        matched_content = None
        for block_path, block_content in file_blocks:
            if block_path == path or block_path.rstrip("/") == path.rstrip("/"):
                matched_content = block_content.strip()
                break
        if matched_content is None:
            for block_path, block_content in file_blocks:
                if os.path.basename(block_path) == target_basename:
                    matched_content = block_content.strip()
                    break
        # Fallback: if only one block and no path match, use it anyway
        if matched_content is None and len(file_blocks) == 1:
            matched_content = file_blocks[0][1].strip()

        if matched_content is not None:
            content = matched_content
            logger.warning(
                "Defence-in-depth: extracted content from <FILE> tags",
                extra={
                    "event": "file.write.file_tag_strip",
                    "path": path,
                    "blocks_found": len(file_blocks),
                },
            )
        return content

    @staticmethod
    def _strip_write_fences(content: str, path: str, ext: str) -> str:
        """Defence-in-depth: strip markdown fences from code files.

        If the upstream fence unwrap in orchestrator missed a case (e.g.
        prose-wrapped code for DISPLAY destination), catch it here before
        writing fences to disk.  Only applies to code file types.
        """
        if ext.lower() not in _CODE_EXTENSIONS or "```" not in content:
            return content

        stripped_fence = False
        original_content = content

        # Check for outer wrapping fence first: the entire content is
        # wrapped in ```lang ... ```.  Inner embedded fences (e.g. Rust
        # doc comments with /// ```) cause extract_code_blocks() to find
        # multiple blocks, but the fix is simple — peel the outer fence.
        lines = content.split("\n")
        if (
            len(lines) >= 3
            and re.match(r"^```\w*\s*$", lines[0])
            and lines[-1].strip() == "```"
        ):
            content = "\n".join(lines[1:-1])
            stripped_fence = True
        else:
            # Fallback: single code block extraction
            blocks = extract_code_blocks(content)
            if len(blocks) == 1 and blocks[0].code.strip():
                content = blocks[0].code
                stripped_fence = True

        if stripped_fence:
            logger.debug(
                "Stripped markdown fences from file_write content",
                extra={
                    "event": "file.write.fence_strip",
                    "path": path,
                    "original_len": len(original_content),
                    "stripped_len": len(content),
                },
            )
        else:
            logger.debug(
                "Markdown fence check clean — no wrapping fences found",
                extra={"event": "file.write.fence_clean", "path": path},
            )
        return content

    @tool_handler(
        "file_write",
        description=(
            "Write content to a file. All paths must be absolute and under "
            "/workspace/ (e.g. /workspace/scripts/app.py). Files written here "
            "are NOT automatically viewable in a browser. For browser-viewable "
            "web pages, use the 'website' tool instead."
        ),
        args={
            "path": "string (absolute path under /workspace/)",
            "content": "string",
        },
        group="file",
        order=10,
    )
    async def _file_write(self, args: dict) -> tuple[TaggedData, dict | None]:
        path = args.get("path", "")
        content = args.get("content", "")
        if not isinstance(path, str):
            raise ToolError("Invalid argument: path must be a string", category="validation")
        if not isinstance(content, str):
            raise ToolError("Invalid argument: content must be a string", category="validation")

        result = self._engine.check_file_write(path)
        if result.status != PolicyResult.ALLOWED:
            logger.warning(
                "file_write blocked by policy",
                extra={
                    "event": "file.write.blocked",
                    "path": path,
                    "reason": result.reason,
                },
            )
            raise ToolBlockedError(f"file_write blocked: {result.reason}")

        logger.debug(
            "file_write policy passed",
            extra={"event": "file.write.policy_passed", "path": path},
        )

        await self._run_semgrep_prescan(content, path)

        # Content sanitisation pipeline — strip worker output artefacts
        _, ext = os.path.splitext(path)
        content = self._strip_write_response_tags(content, path, ext)
        content = self._strip_write_file_tags(content, path, ext)
        content = self._strip_write_fences(content, path, ext)

        # Code fixer + syntax validation
        content, fix_result = await self._run_write_code_fixer(content, path, ext)

        # Anchor allocator
        content = await self._run_write_anchor_allocator(content, path, ext, fix_result)

        # Late Semgrep scan on final bytes — bytes written must equal bytes scanned.
        # The early scan (above) provides fast-block UX; this scan is load-bearing.
        await self._run_semgrep_prescan(content, path)

        # Pre-read existing file for diff_stats metadata.
        # Cap to FILE_READ_MAX_BYTES (module constant) — prevents OOM.
        _before_content = None
        _before_size = None
        try:
            file_size = os.path.getsize(path)
            _before_size = file_size
            if file_size <= FILE_READ_MAX_BYTES:
                with open(path, encoding="utf-8", newline="") as f:
                    _before_content = f.read()
        except (OSError, ValueError, UnicodeDecodeError):
            logger.debug(
                "_file_write: OSError suppressed",
                extra={"event": "file._file_write.suppressed"},
                exc_info=True,
            )

        # Write to disk (makedirs, init.py auto-create, logging injection)
        exec_meta_logging = self._write_to_disk(content, path, ext)

        # Finalize: tagged data, provenance, exec_meta, manifest, survival check
        return await self._finalize_write(
            content,
            path,
            fix_result,
            _before_content,
            _before_size,
            exec_meta_logging,
        )
