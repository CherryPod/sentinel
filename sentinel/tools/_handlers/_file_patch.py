"""Patch operation handlers — file_patch and supporting sub-methods."""

import logging
import os
import shutil
import time

from sentinel.core.context import PrincipalRequiredError, current_user_id
from sentinel.core.models import DataSource, PolicyResult, TaggedData, TrustLevel
from sentinel.security.code_fixer import fix_code as code_fixer_fix
from sentinel.security.provenance import create_tagged_data, record_file_write
from sentinel.tools._handlers._constants import (
    _CODE_EXTENSIONS,
    _MANIFEST_EXTENSIONS,
)
from sentinel.crypto.blind_index import log_hash
from sentinel.tools._handlers._registry import tool_handler
from sentinel.tools._handlers._types import ToolBlockedError, ToolError
from sentinel.tools.anchor_allocator import allocate_anchors
from sentinel.tools.anchor_allocator._memory import clear_anchor_map

logger = logging.getLogger(__name__)

# file_patch backup retention count
_MAX_PATCH_BACKUPS = 5


def _is_complete_markup_element(content: str | None) -> bool:
    """True when *content* is a full markup element, not inner text.

    Auto-upgrading ``replace`` → ``replace_inner`` would nest this markup
    inside the existing wrapper (duplicate IDs / CRIT-02 resolver-rerun
    blocks). Honor a true element swap instead.
    """
    if not content:
        return False
    stripped = content.lstrip()
    return stripped.startswith("<") and ">" in stripped


def _get_patch_backend(ext: str):
    """Select the appropriate patch backend for a file extension."""
    logger.debug(
        "_get_patch_backend called", extra={"event": "get.patch_backend", "ext": ext}
    )
    from sentinel.tools.patch_backends._css import CSSPatchBackend
    from sentinel.tools.patch_backends._html import HTMLPatchBackend
    from sentinel.tools.patch_backends._javascript import JavaScriptPatchBackend
    from sentinel.tools.patch_backends._python import PythonPatchBackend
    from sentinel.tools.patch_backends._rust import RustPatchBackend
    from sentinel.tools.patch_backends._text import TextPatchBackend

    _BACKEND_MAP = {
        ".html": HTMLPatchBackend,
        ".htm": HTMLPatchBackend,
        ".js": JavaScriptPatchBackend,
        ".mjs": JavaScriptPatchBackend,
        ".jsx": JavaScriptPatchBackend,
        ".tsx": JavaScriptPatchBackend,
        ".ts": JavaScriptPatchBackend,
        ".css": CSSPatchBackend,
        ".py": PythonPatchBackend,
        ".rs": RustPatchBackend,
    }
    return _BACKEND_MAP.get(ext.lower(), TextPatchBackend)()


class PatchHandlerMixin:
    """Patch operation handlers — file_patch and supporting sub-methods.

    Depends on FileOpsHandlerMixin (provides _FIXER_META_DEFAULTS and shared
    utilities). Both mixins are composed in ToolExecutor via MRO.
    """

    # ── Valid file_patch operations ────────────────────────────────
    _VALID_PATCH_OPS = frozenset(
        {
            "insert_after",
            "insert_before",
            "replace",
            "replace_inner",
            "delete",
        }
    )

    @staticmethod
    def _validate_patch_args(args: dict) -> tuple[str, str, str, str]:
        """Parse and validate file_patch arguments.

        Returns (path, operation, anchor, content).  Raises ToolError on
        invalid operation, missing anchor, or missing content for ops
        that require it.
        """
        path = args.get("path", "")
        operation = args.get("operation", "")
        anchor = args.get("anchor", "")
        content = args.get("content")

        if not isinstance(path, str):
            raise ToolError("Invalid argument: path must be a string", category="validation")
        if not isinstance(operation, str):
            raise ToolError("Invalid argument: operation must be a string", category="validation")
        if not isinstance(anchor, str):
            raise ToolError("Invalid argument: anchor must be a string", category="validation")
        if content is not None and not isinstance(content, str):
            raise ToolError("Invalid argument: content must be a string", category="validation")

        if operation not in PatchHandlerMixin._VALID_PATCH_OPS:
            logger.debug(
                "_validate_patch_args: operation_not_in_VALID_PATCH_OPS",
                extra={
                    "event": "_file_patch._validate_patch_args.match",
                    "reason": "operation_not_in_VALID_PATCH_OPS",
                },
            )  # auto:neg
            logger.warning(
                "file_patch: invalid operation",
                extra={
                    "event": "file.patch.invalid_operation",
                    "path": path,
                    "operation_len": len(str(operation)),
                    "operation_hash": log_hash(str(operation)),
                },
            )
            raise ToolError(
                "Invalid operation (must be insert_after, insert_before, "
                "replace, replace_inner, or delete)"
            )
        logger.debug(
            "_validate_patch_args: operation_not_in_VALID_PATCH_OPS_passed",
            extra={
                "event": "_file_patch._validate_patch_args.passed",
                "reason": "operation_not_in_VALID_PATCH_OPS_passed",
            },
        )  # auto:neg

        if not anchor:
            logger.debug(
                "_validate_patch_args: not_anchor",
                extra={
                    "event": "_file_patch._validate_patch_args.match",
                    "reason": "not_anchor",
                },
            )  # auto:neg
            raise ToolError("anchor is required")

        # replace with empty/missing content is equivalent to delete — allow it
        if operation in ("delete", "replace"):
            logger.debug(
                "_validate_patch_args: operation_in",
                extra={
                    "event": "_file_patch._validate_patch_args.match",
                    "reason": "operation_in",
                },
            )  # auto:neg
            content = content or ""
        elif not content:
            logger.debug(
                "_validate_patch_args: operation_in",
                extra={
                    "event": "_file_patch._validate_patch_args.clean",
                    "reason": "operation_in",
                },
            )  # auto:neg
            logger.warning(
                "file_patch: operation requires content",
                extra={
                    "event": "file.patch.missing_content",
                    "path": path,
                    "operation_len": len(str(operation)),
                    "operation_hash": log_hash(str(operation)),
                },
            )
            raise ToolError("content is required")

        return path, operation, anchor, content

    @staticmethod
    def _create_patch_backup(path: str) -> str:
        """Create a timestamped backup of *path* before patching.

        Keeps at most ``_MAX_PATCH_BACKUPS`` recent backups per filename.
        Returns the backup file path.
        """
        backup_dir = os.path.join(os.path.dirname(path), ".patch_backups")
        os.makedirs(backup_dir, exist_ok=True)
        backup_name = f"{os.path.basename(path)}.{time.time_ns()}"
        backup_path = os.path.join(backup_dir, backup_name)
        shutil.copy2(path, backup_path)
        logger.debug(
            "file_patch: backup created at %s",
            backup_path,
            extra={
                "event": "file.patch_backup",
                "path": path,
                "backup_path": backup_path,
            },
        )

        # Cleanup: keep only the most recent backups for this filename
        prefix = os.path.basename(path) + "."
        backups = sorted(
            [
                os.path.join(backup_dir, b)
                for b in os.listdir(backup_dir)
                if b.startswith(prefix)
            ],
            key=lambda b: os.path.getmtime(b),
        )
        for old_backup in backups[:-_MAX_PATCH_BACKUPS]:
            os.unlink(old_backup)
            logger.debug(
                "file_patch old backup removed",
                extra={"event": "file.patch_backup_cleanup", "removed": old_backup},
            )

        return backup_path

    async def _sanitise_patch_content(
        self,
        content: str | None,
        ext: str,
        anchor: str,
        current: str,
        path: str,
        operation: str = "",
    ) -> tuple[str | None, dict]:
        """Clean worker output and run the fragment code fixer.

        Strips ``<RESPONSE>`` tags and markdown fences, extracts
        surrounding file context, runs the code fixer, and validates
        syntax.  Returns ``(sanitised_content, fixer_meta_dict)``.

        ``replace_inner`` bodies are not compilation units — the fragment
        fixer treats them as modules and strips leading indent, which
        then fails AST parse and the CRIT-02 resolver-rerun.
        """
        if not content or ext.lower() not in _CODE_EXTENSIONS:
            return content, dict(self._FIXER_META_DEFAULTS)

        content = self._strip_worker_wrapping(content)
        if operation == "replace_inner":
            logger.debug(
                "file_patch: fragment fixer skipped for replace_inner body",
                extra={
                    "event": "file.patch_code_fixer.skipped_replace_inner",
                    "path": path,
                    "ext": ext,
                },
            )
            return content, dict(self._FIXER_META_DEFAULTS)

        _surrounding_ctx = self._extract_fixer_context(anchor, current, path)

        # Code fixer — crash must never block a patch
        fix_result = None
        fixer_meta = dict(self._FIXER_META_DEFAULTS)
        try:
            fix_result = code_fixer_fix(
                path,
                content,
                surrounding_context=_surrounding_ctx,
            )
            if fix_result and not fix_result.skipped:
                content = fix_result.content
                fixer_meta = {
                    "code_fixer_changed": fix_result.changed,
                    "code_fixer_fixes": fix_result.fixes_applied,
                    "code_fixer_errors": fix_result.errors_found,
                    "code_fixer_warnings": fix_result.warnings,
                }
                if fix_result.changed:
                    logger.debug(
                        "file_patch: fragment fixer — %d fixes, %d errors",
                        len(fix_result.fixes_applied),
                        len(fix_result.errors_found),
                        extra={
                            "event": "file.patch_code_fixer",
                            "path": path,
                            "fixes_count": len(fix_result.fixes_applied),
                            "errors_count": len(fix_result.errors_found),
                            "changed": True,
                        },
                    )
        except Exception:  # catch-all: code fixer crash must not block patch
            logger.warning(
                "Code fixer crash in file_patch — using original content",
                extra={"event": "file.code_fixer_error_patch", "path": path},
                exc_info=True,
            )

        # Post-fix syntax validation (node --check / bash -n).
        # _validate_syntax_post_fix logs WARN internally on failure.
        if fix_result and not fix_result.skipped:
            await self._validate_syntax_post_fix(path, fix_result)
            # Validation may have appended errors in-place
            fixer_meta["code_fixer_errors"] = fix_result.errors_found

        return content, fixer_meta

    # Structural anchor prefixes that language-specific backends handle
    _STRUCTURAL_PREFIXES = ("fn:", "class:", "sel:", "block:")

    @staticmethod
    def _resolve_patch_anchor(
        anchor: str,
        current: str,
        path: str,
        ext: str,
        backend,
        operation: str,
        args: dict,
    ) -> tuple:
        """Route anchor resolution to the correct backend and apply post-resolution fixes.

        Handles css: selectors on HTML, structural prefixes (fn:, class:,
        sel:, block:) on language backends, and plain text anchors.
        Also applies auto-upgrade (replace → replace_inner) and
        replace-size sanity checks.

        Returns ``(anchor_result, operation, resolve_meta_dict)``.
        """
        from sentinel.tools.patch_backends._html import HTMLPatchBackend
        from sentinel.tools.patch_backends._text import TextPatchBackend

        resolve_meta: dict = {}
        _has_structural = any(
            anchor.startswith(p) for p in PatchHandlerMixin._STRUCTURAL_PREFIXES
        )

        # css: prefix on non-HTML files — treat as literal text anchor
        _use_css = anchor.startswith("css:") and isinstance(backend, HTMLPatchBackend)
        if anchor.startswith("css:") and not _use_css:
            logger.debug(
                "file_patch css: prefix on non-HTML file, treating as literal",
                extra={
                    "event": "file.patch_css_literal_fallback",
                    "path": path,
                    "ext": ext,
                },
            )

        _fuzzy = bool(args.get("fuzzy_match", False))

        if _use_css:
            # HTML CSS selector — route to HTMLPatchBackend
            logger.debug(
                "_resolve_patch_anchor: clean",
                extra={"event": "file.patch_structural_fallback.clean"},
            )
            resolving_backend = backend
            anchor_result = backend.resolve_anchor(anchor, current, path)
        elif _has_structural and not isinstance(backend, TextPatchBackend):
            # Structural prefix on a language with a dedicated backend
            logger.debug(
                "_resolve_patch_anchor: clean",
                extra={"event": "file.patch_structural_fallback.clean"},
            )
            resolving_backend = backend
            anchor_result = backend.resolve_anchor(anchor, current, path)
        elif _has_structural and isinstance(backend, TextPatchBackend):
            # Structural prefix on unsupported extension — text fallback
            logger.warning(
                "file_patch: structural prefix on unsupported extension %s, using text match",
                ext,
                extra={
                    "event": "file.patch_structural_fallback",
                    "path": path,
                    "ext": ext,
                    "anchor_prefix": anchor.split(":")[0],
                },
            )
            resolving_backend = backend
            anchor_result = resolving_backend.resolve_anchor(
                anchor,
                current,
                path,
                fuzzy_match=_fuzzy,
            )
        else:
            # Plain text / range anchor
            logger.debug(
                "_resolve_patch_anchor: clean",
                extra={"event": "file.patch_structural_fallback.clean"},
            )
            resolving_backend = (
                backend if isinstance(backend, TextPatchBackend) else TextPatchBackend()
            )
            anchor_result = resolving_backend.resolve_anchor(
                anchor,
                current,
                path,
                fuzzy_match=_fuzzy,
            )

        resolve_meta.update(anchor_result.metadata)

        # Auto-upgrade replace → replace_inner when backend requests it.
        # Skip when the replacement is already a complete element — nesting
        # it as inner content duplicates IDs and fails the survival rerun.
        _content = args.get("content")
        if (
            operation == "replace"
            and anchor_result.prefer_replace_inner
            and not _is_complete_markup_element(_content)
        ):
            logger.warning(
                "file_patch: auto-upgrading replace->replace_inner (backend hint)",
                extra={
                    "event": "file.patch_auto_upgrade",
                    "path": path,
                    "original_operation": operation,
                    "anchor_preview": anchor_result.anchor_text[:60],
                },
            )
            operation = "replace_inner"
            resolve_meta["auto_upgraded_to_replace_inner"] = True
        elif operation == "replace" and anchor_result.prefer_replace_inner:
            logger.debug(
                "file_patch: keeping replace (complete-element content)",
                extra={
                    "event": "file.patch_auto_upgrade.skipped_complete_element",
                    "path": path,
                    "anchor_preview": anchor_result.anchor_text[:60],
                },
            )

        # Replace anchor size sanity check (text backend only)
        if operation == "replace" and isinstance(resolving_backend, TextPatchBackend):
            logger.debug(
                "_resolve_patch_anchor: operation_eq_replace",
                extra={
                    "event": "_file_patch._resolve_patch_anchor.match",
                    "reason": "operation_eq_replace",
                },
            )  # auto:neg
            size_warning = resolving_backend.check_replace_size(
                anchor_result.anchor_text,
                path,
            )
            if size_warning:
                logger.debug(
                    "_resolve_patch_anchor: size_warning",
                    extra={
                        "event": "_file_patch._resolve_patch_anchor.match",
                        "reason": "size_warning",
                    },
                )  # auto:neg
                resolve_meta.update(size_warning)

        return anchor_result, operation, resolve_meta

    @staticmethod
    def _apply_patch_operation(
        operation: str,
        current: str,
        content: str | None,
        anchor: str,
        anchor_result,
        backend,
        path: str,
    ) -> str:
        """Apply a single patch operation and return the modified file content.

        Handles insert_after, insert_before, replace, replace_inner, and
        delete.  Ensures newline separation between anchor and content for
        insert operations.
        """
        idx = anchor_result.anchor_start
        logger.debug(
            "file_patch: applying %s at byte %d (%d bytes content)",
            operation,
            idx,
            len(content) if content else 0,
            extra={
                "event": "file.patch_apply",
                "path": path,
                "operation": operation,
                "anchor_position": idx,
                "content_length": len(content) if content else 0,
            },
        )

        if operation == "insert_after":
            end = idx + len(anchor)
            # Ensure newline separation — the worker often omits the leading
            # newline on fragments, causing content to join the anchor line.
            if content and not anchor.endswith("\n") and not content.startswith("\n"):
                content = "\n" + content
            return current[:end] + content + current[end:]

        if operation == "insert_before":
            if content and not content.endswith("\n") and not anchor.startswith("\n"):
                content = content + "\n"
            return current[:idx] + content + current[idx:]

        if operation == "replace":
            return current[:idx] + content + current[idx + len(anchor) :]

        if operation == "replace_inner":
            # Delegate to backend — needs DOM awareness
            return backend.apply_replace_inner(current, anchor_result, content)

        # delete
        return current[:idx] + current[idx + len(anchor) :]

    async def _run_patch_anchor_allocator(
        self,
        path: str,
        patched: str,
        user_id: int,
        settings,
        fixer_errors: list,
    ) -> tuple[str, dict]:
        """Run the anchor allocator on the full patched file.

        Skips allocation if the file is structurally invalid (code fixer
        reported integrity failures) — clears the anchor map instead.
        Returns ``(patched_content, allocator_meta_dict)``.
        """
        _defaults = {"anchor_allocator_changed": False, "anchor_count": 0}

        if not settings.anchor_allocator_enabled or not patched:
            return patched, _defaults

        # Structural failure → clear existing anchors, skip allocation
        _structural_fail = any(
            "structural_integrity_failure" in e for e in fixer_errors
        )
        if _structural_fail:
            _ep_store = getattr(self, "_episodic_store", None)
            if _ep_store:
                try:
                    await clear_anchor_map(path, _ep_store, user_id)
                except PrincipalRequiredError:
                    # Q4.fix.f Coord follow-up: zero-principal must propagate
                    # past the best-effort swallow so the fail-closed invariant
                    # is preserved at the producer boundary.
                    raise
                except Exception:  # catch-all: anchor cleanup best-effort
                    logger.debug(
                        "anchor map cleanup failed",
                        extra={"event": "file.anchor_cleanup_error"},
                        exc_info=True,
                    )
            logger.warning(
                "File structurally invalid — anchor allocation skipped (file_patch)",
                extra={
                    "event": "file.anchor_allocator_skipped_integrity",
                    "path": path,
                },
            )
            return patched, _defaults

        # Normal allocation
        try:
            _anchor_result = await allocate_anchors(
                path=path,
                content=patched,
                episodic_store=getattr(self, "_episodic_store", None),
                user_id=user_id,
                tier=settings.anchor_allocator_tier,
            )
            if _anchor_result.changed:
                patched = _anchor_result.content
            logger.debug(
                "file_patch: anchor allocator placed %d anchors on full file",
                len(_anchor_result.anchors),
                extra={
                    "event": "file.patch_anchor_allocator",
                    "path": path,
                    "anchor_count": len(_anchor_result.anchors),
                    "changed": _anchor_result.changed,
                },
            )
            if _anchor_result.parse_failed:
                logger.warning(
                    "Anchor allocation parse failed (file_patch, full file)",
                    extra={
                        "event": "file.anchor_allocation_failed",
                        "path": path,
                        "error": _anchor_result.error,
                    },
                )
            return patched, {
                "anchor_allocator_changed": _anchor_result.changed,
                "anchor_count": len(_anchor_result.anchors),
            }
        except PrincipalRequiredError:
            # Q4.fix.f Coord follow-up: zero-principal must propagate past
            # the "never block a patch" swallow so the fail-closed invariant
            # is preserved at the producer boundary.
            raise
        except Exception:  # catch-all: anchor allocator crash must not block patch
            logger.warning(
                "Anchor allocator crash in file_patch",
                extra={"event": "file.anchor_allocator_error", "path": path},
                exc_info=True,
            )
            return patched, _defaults

    async def _finalize_patch(
        self,
        path: str,
        patched: str,
        operation: str,
        backup_path: str,
        backend_name: str,
        exec_meta: dict,
        timing: dict,
    ) -> tuple[TaggedData, dict | None]:
        """Write the patched file, record provenance, extract manifest, and log completion.

        Restores from backup on write failure.  Returns the tagged
        provenance data and the fully populated exec_meta dict.
        """
        # ── Write result ─────────────────────────────────────────────
        try:
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write(patched)
        except OSError as exc:
            shutil.copy2(backup_path, path)
            logger.error(
                "file_patch write failed, restored backup",
                extra={
                    "event": "file.patch_write_error",
                    "path": path,
                    "error": str(exc),
                },
                exc_info=True,
            )
            raise ToolError("file_patch write failed:") from exc

        exec_meta["file_size_after"] = len(patched.encode("utf-8"))
        exec_meta["patch_operation"] = operation

        # ── Timing ───────────────────────────────────────────────────
        exec_meta["timing"] = timing
        logger.debug(
            "file_patch: timing — fix=%dms resolve=%dms apply=%dms total=%dms",
            timing["fix_ms"],
            timing["resolve_ms"],
            timing["apply_ms"],
            timing["total_ms"],
            extra={"event": "file.patch_timing", "path": path, **timing},
        )

        # ── Provenance ───────────────────────────────────────────────
        tagged = await create_tagged_data(
            content=f"File patched: {path} ({operation})",
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
            originated_from=f"file_patch:{path}",
        )
        await record_file_write(path, tagged.id, content=patched)

        # ── Content manifest ─────────────────────────────────────────
        try:
            from sentinel.analysis.content_manifest import extract_content_manifest

            _manifest_ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
            if _manifest_ext in _MANIFEST_EXTENSIONS:
                logger.debug(
                    "file_patch: extracting content manifest for %s",
                    os.path.basename(path),
                    extra={
                        "event": "file.content_manifest_attempt",
                        "path": path,
                        "ext": _manifest_ext,
                    },
                )
                exec_meta["content_manifest"] = extract_content_manifest(
                    os.path.basename(path),
                    patched,
                    "",
                )
                logger.debug(
                    "file_patch: content manifest extracted for %s",
                    os.path.basename(path),
                    extra={"event": "file.content_manifest_extracted", "path": path},
                )
            else:
                logger.debug(
                    "file_patch: content manifest skipped for ext=%s",
                    _manifest_ext,
                    extra={
                        "event": "file.content_manifest_skip_ext",
                        "path": path,
                        "ext": _manifest_ext,
                    },
                )
        except Exception as exc:  # catch-all: manifest extraction best-effort
            logger.warning(
                "file_patch: content manifest extraction failed: %s",
                exc,
                extra={
                    "event": "file.content_manifest_error",
                    "path": path,
                    "error": str(exc),
                },
                exc_info=True,
            )

        # ── Completion ───────────────────────────────────────────────
        _delta = exec_meta["file_size_after"] - exec_meta["file_size_before"]
        logger.info(
            "file_patch: %s complete — %s (%d->%d bytes, %+d)",
            operation,
            os.path.basename(path),
            exec_meta["file_size_before"],
            exec_meta["file_size_after"],
            _delta,
            extra={
                "event": "file.patch_complete",
                "path": path,
                "operation": operation,
                "size_before": exec_meta["file_size_before"],
                "size_after": exec_meta["file_size_after"],
                "delta": _delta,
                "anchor_length": exec_meta["patch_anchor_length"],
                "backup": backup_path,
                "backend_name": backend_name,
            },
        )

        return tagged, exec_meta

    @tool_handler(
        "file_patch",
        description=(
            "Apply an incremental modification to an existing file. "
            "Use instead of file_write when modifying part of a file — "
            "avoids regenerating unchanged content. "
            "For HTML files, use a css: prefix for deterministic element "
            "targeting (e.g. css:#panel-weather). For other files, copy "
            "a unique anchor string verbatim from the file."
        ),
        args={
            "path": "string (absolute path under /workspace/)",
            "operation": "string (insert_after | insert_before | replace | delete)",
            "anchor": (
                "string (for HTML: 'css:#element-id' or 'css:.class'; "
                "for other files: unique text copied verbatim from file_read output)"
            ),
            "content": "string (new content — not needed for delete)",
        },
        group="file",
        order=10,
    )
    async def _file_patch(self, args: dict) -> tuple[TaggedData, dict | None]:
        """Apply an incremental modification to an existing file.

        Shared core — dispatches anchor resolution and structural checking
        to language-specific backends (HTMLPatchBackend, TextPatchBackend).
        The anchor and operation come from the planner (trusted), the content
        comes from the worker (already scanned by the security pipeline).
        """
        import time as _time_mod

        _t_start = _time_mod.monotonic_ns()

        path, operation, anchor, content = self._validate_patch_args(args)
        exec_meta: dict = {}

        # ── Policy gate ──────────────────────────────────────────────
        result = self._engine.check_file_write(path)
        if result.status != PolicyResult.ALLOWED:
            logger.warning(
                "file_patch blocked by policy",
                extra={
                    "event": "file.patch_blocked",
                    "path": path,
                    "reason": result.reason,
                },
            )
            raise ToolBlockedError(f"file_patch blocked: {result.reason}")
        logger.debug(
            "file_patch policy passed",
            extra={
                "event": "file.patch_policy_allowed",
                "path": path,
                "operation": operation,
            },
        )

        # ── Read current file ────────────────────────────────────────
        try:
            with open(path, encoding="utf-8", newline="") as fh:
                current = fh.read()
        except FileNotFoundError as exc:
            logger.warning(
                "file_patch: file not found",
                extra={"event": "file.patch.file_not_found", "path": path},
                exc_info=True,
            )
            raise ToolError("file_patch failed: file not found") from exc
        except OSError as exc:
            logger.warning(
                "file_patch: OS error reading file",
                extra={"event": "file.patch.read_os_error", "path": path, "error": str(exc)},
                exc_info=True,
            )
            raise ToolError("file_patch failed: cannot read file") from exc
        except (ValueError, UnicodeDecodeError) as exc:
            logger.warning(
                "file_patch: cannot read file",
                extra={
                    "event": "file.patch_read_error",
                    "path": path,
                    "error_category": "validation",
                },
                exc_info=True,
            )
            raise ToolError("file_patch failed: cannot read file") from exc

        _, ext = os.path.splitext(path)
        exec_meta["file_size_before"] = len(current.encode("utf-8"))
        exec_meta["file_content_before"] = current[:1_048_576]  # 1MB cap for diff

        # ── Select backend ───────────────────────────────────────────
        backend = _get_patch_backend(ext)
        backend_name = type(backend).__name__
        exec_meta["backend"] = backend_name
        logger.info(
            "file_patch: %s on %s (%s backend)",
            operation,
            path,
            backend_name,
            extra={
                "event": "file.patch_start",
                "path": path,
                "operation": operation,
                "backend_name": backend_name,
                "anchor_preview": anchor[:60],
                "file_size": exec_meta["file_size_before"],
            },
        )
        logger.debug(
            "file_patch: extension '%s' -> %s backend",
            ext,
            backend_name,
            extra={
                "event": "file.patch_backend_selected",
                "path": path,
                "ext": ext,
                "backend_class": backend_name,
            },
        )

        # ── Backup before modification ───────────────────────────────
        backup_path = self._create_patch_backup(path)
        exec_meta["backup_path"] = backup_path

        # ── Anchor allocator settings (used after patch is applied) ──
        from sentinel.core.config import settings as _aa_settings_patch

        _aa_patch_user_id = current_user_id.get()

        # ── Resolve anchor + auto-upgrade + size check ───────────────
        _t_resolve_start = _time_mod.monotonic_ns()
        anchor_result, operation, resolve_meta = self._resolve_patch_anchor(
            anchor,
            current,
            path,
            ext,
            backend,
            operation,
            args,
        )
        exec_meta.update(resolve_meta)
        _t_resolve_end = _time_mod.monotonic_ns()

        # ── Content sanitisation + fragment code fixer ───────────────
        # After resolve so an auto-upgraded replace_inner skips the
        # fragment fixer (bodies are not compilation units).
        _t_fix_start = _time_mod.monotonic_ns()
        content, fixer_meta = await self._sanitise_patch_content(
            content,
            ext,
            anchor,
            current,
            path,
            operation,
        )
        exec_meta.update(fixer_meta)
        _t_fix_end = _time_mod.monotonic_ns()

        anchor = anchor_result.anchor_text
        exec_meta["patch_anchor_length"] = len(anchor)

        # ── Apply operation ──────────────────────────────────────────
        _t_apply_start = _time_mod.monotonic_ns()
        patched = self._apply_patch_operation(
            operation,
            current,
            content,
            anchor,
            anchor_result,
            backend,
            path,
        )
        _t_apply_end = _time_mod.monotonic_ns()

        # ── Structural check via backend ─────────────────────────────
        structural_meta = self._check_structural_integrity(
            current,
            patched,
            anchor_result,
            operation,
            backend,
            path,
            backup_path,
        )
        exec_meta.update(structural_meta)

        # ── Full-file code fixer (post-patch) ────────────────────────
        patched, full_fixer_meta = await self._run_full_file_fixer(
            path,
            patched,
            ext,
        )
        exec_meta.update(full_fixer_meta)

        # ── Anchor allocator (on full patched file) ────────────────────
        patched, allocator_meta = await self._run_patch_anchor_allocator(
            path,
            patched,
            _aa_patch_user_id,
            _aa_settings_patch,
            exec_meta.get("full_file_fixer_errors", []),
        )
        exec_meta.update(allocator_meta)

        # ── Semgrep pre-write gate (D5 parity with file_write) ────────
        await self._run_semgrep_prescan(patched, path)

        # ── Write, provenance, manifest, completion ────────────────────
        _t_end = _time_mod.monotonic_ns()

        def _ms(a: int, b: int) -> int:
            return (b - a) // 1_000_000

        timing = {
            "fix_ms": _ms(_t_fix_start, _t_fix_end),
            "resolve_ms": _ms(_t_resolve_start, _t_resolve_end),
            "apply_ms": _ms(_t_apply_start, _t_apply_end),
            "total_ms": _ms(_t_start, _t_end),
        }

        return await self._finalize_patch(
            path,
            patched,
            operation,
            backup_path,
            backend_name,
            exec_meta,
            timing,
        )
