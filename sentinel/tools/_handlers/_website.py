"""Website handler mixin — create, list, remove sites.

Extracted from executor.py during Phase 1 structural refactor.
The mixin expects these attributes on self (provided by ToolExecutor):
  - _engine: PolicyEngine instance
  - _trust_level: current trust level
  - _sandbox: PodmanSandbox (for _validate_syntax_post_fix)
  - _episodic_store: episodic memory store (for anchor allocator)
"""

import logging
import os
import re
import shutil

from sentinel.core.context import PrincipalRequiredError, current_user_id
from sentinel.core.models import DataSource, PolicyResult, TaggedData, TrustLevel
from sentinel.core.workspace import get_user_workspace
from sentinel.crypto.blind_index import log_hash
from sentinel.security import semgrep_scanner
from sentinel.security.code_fixer import fix_code as code_fixer_fix
from sentinel.security.provenance import create_tagged_data
from sentinel.tools._handlers._constants import (
    _CODE_EXTENSIONS,
    _EXTENSIONLESS_FIXER_NAMES,
    _MANIFEST_EXTENSIONS,
    _detect_language_from_path,
)
from sentinel.tools._handlers._registry import tool_handler
from sentinel.tools._handlers._types import ToolBlockedError, ToolError
from sentinel.tools.anchor_allocator import allocate_anchors

logger = logging.getLogger(__name__)


class WebsiteHandlerMixin:
    """Website tool handlers (create, list, remove sites)."""

    _SITE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
    _FILENAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}$")

    @tool_handler(
        "website",
        description="Manage temporary websites at /workspace/sites/{site_id}/. Actions: create (write HTML/CSS/JS files — overwrites if site_id already exists, so use the same site_id to update a site), remove (delete a site), list (show active sites and their URLs). Sites are viewable in a browser at https://localhost:3001/sites/{site_id}/ and stored on disk at /workspace/sites/{site_id}/. Use file_read with /workspace/sites/{site_id}/index.html to inspect existing content before updating. IMPORTANT: Inline <script> tags are blocked by CSP — JavaScript must be in separate .js files with descriptive names (e.g. dashboard.js, gallery.js) referenced via <script src='feature-name.js'></script>. CSS must also be in separate .css files linked via <link rel='stylesheet' href='style.css'> — inline <style> tags cannot be patched.",
        args={
            "action": "string (create|remove|list)",
            "site_id": "string (URL-safe identifier, e.g. 'weather-dashboard'. Required for create/remove)",
            "files": "object (filename to content map, e.g. {'index.html': '<html>...', 'style.css': '...'}. Required for create)",
            "title": "string (optional human-readable title for the site)",
        },
        group="website",
        order=60,
    )
    async def _website(self, args: dict) -> tuple[TaggedData, dict | None]:
        action = args.get("action", "")
        site_id = args.get("site_id", "")
        # Per-user workspace: sites live under /workspace/<user_id>/sites/
        sites_root = str(get_user_workspace() / "sites")

        if action == "list":
            logger.debug(
                "_website: routing to list",
                extra={"event": "website.dispatch", "action": "list"},
            )
            return await self._website_list(sites_root)
        logger.debug(
            "_website: action_eq_list_passed",
            extra={
                "event": "website.dispatch.passed",
                "reason": "action_eq_list_passed",
            },
        )  # auto:neg

        if action == "create":
            logger.debug(
                "_website: routing to create",
                extra={
                    "event": "website.dispatch",
                    "action": "create",
                    "site_id": site_id,
                },
            )
            return await self._website_create(args, site_id, sites_root)
        logger.debug(
            "_website: action_eq_create_passed",
            extra={
                "event": "website.dispatch.passed",
                "reason": "action_eq_create_passed",
            },
        )  # auto:neg

        if action == "remove":
            logger.debug(
                "_website: routing to remove",
                extra={
                    "event": "website.dispatch",
                    "action": "remove",
                    "site_id": site_id,
                },
            )
            return await self._website_remove(site_id, sites_root)
        logger.debug(
            "_website: action_eq_remove_passed",
            extra={
                "event": "website.dispatch.passed",
                "reason": "action_eq_remove_passed",
            },
        )  # auto:neg

        logger.warning(
            "website: unknown action",
            extra={
                "event": "website.unknown_action",
                "action_len": len(action) if isinstance(action, str) else 0,
                "action_hash": log_hash(str(action)),
            },
        )
        # Site 109 wording carve-out (D34 fix-row 2026-05-01): kept as
        # "unknown action" (mismatching `_sanitise_error`'s `r"unknown tool"`
        # allowlist entry) because the dispatcher dispatches actions, not
        # tools. `genericise_error` still classifies via the dispatcher
        # `"Tool execution failed: ..."` wrap. See session-doc §5.
        raise ToolError("website: unknown action (use create, remove, or list)")

    async def _website_list(self, sites_root: str) -> tuple[TaggedData, dict | None]:
        logger.debug(
            "_website_list called",
            extra={"event": "_website._website_list", "sites_root": sites_root},
        )  # auto:entry
        if not os.path.isdir(sites_root):
            return await create_tagged_data(
                content="No active sites.",
                source=DataSource.TOOL,
                trust_level=TrustLevel.TRUSTED,
                originated_from="website:list",
            ), None

        sites = sorted(
            d
            for d in os.listdir(sites_root)
            if os.path.isdir(os.path.join(sites_root, d))
        )
        if not sites:
            return await create_tagged_data(
                content="No active sites.",
                source=DataSource.TOOL,
                trust_level=TrustLevel.TRUSTED,
                originated_from="website:list",
            ), None

        listing = "\n".join(f"- {s}: https://localhost:3001/sites/{s}/" for s in sites)
        return await create_tagged_data(
            content=f"Active sites:\n{listing}",
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
            originated_from="website:list",
        ), None

    async def _website_create(
        self, args: dict, site_id: str, sites_root: str
    ) -> tuple[TaggedData, dict | None]:
        """Create a website: validate, process files, copy media, return result."""
        logger.debug(
            "_website_create called",
            extra={
                "event": "website.create",
                "site_id": site_id,
                "file_count": len(args.get("files") or {}),
            },
        )

        files = self._validate_website_inputs(site_id, args)
        site_dir = os.path.join(sites_root, site_id)

        # Policy gate on the site directory
        result = self._engine.check_file_write(site_dir)
        if result.status != PolicyResult.ALLOWED:
            raise ToolBlockedError(f"website create blocked: {result.reason}")
        logger.debug(
            "policy gate passed for website create",
            extra={"event": "website.policy_passed", "site_dir": str(site_dir)},
        )

        structural_digests: dict[str, dict] = {}
        content_manifests: dict[str, dict] = {}

        try:
            os.makedirs(site_dir, exist_ok=True)

            for filename, content in files.items():
                filepath = os.path.join(site_dir, filename)
                # Security pipeline: code fixer → anchors → Semgrep → policy → write
                content = await self._process_website_file(
                    filename, content, filepath, site_dir
                )

                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(content)

                # Post-write analysis: structural digest + content manifest
                self._extract_website_file_digests(
                    filename, content, structural_digests, content_manifests
                )

            # Copy binary media assets into site directory
            media_copied = await self._copy_website_media(
                args.get("media", []), site_id, site_dir
            )
            logger.debug(
                "website file processing complete",
                extra={
                    "event": "website.create_files_done",
                    "site_id": site_id,
                    "file_count": len(files),
                    "media_copied": media_copied,
                },
            )

        except (ToolBlockedError, ToolError):
            raise  # Don't wrap our own errors
        except OSError as exc:
            logger.warning(
                "website create write failed",
                extra={"event": "website.create_write_error", "error": str(exc)},
                exc_info=True,
            )
            # Clean up partially-written site directory
            shutil.rmtree(site_dir, ignore_errors=True)
            # Trailing colon kept intentional — matches `_sanitise_error`
            # allowlist `r"failed:"`. `from exc` chains the OS error
            # server-side; the warning above already logs `str(exc)`.
            raise ToolError("website create failed:") from exc

        return await self._build_website_result(
            args, site_id, files, site_dir, structural_digests, content_manifests
        )

    # ------------------------------------------------------------------
    # _website_create sub-methods
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_website_inputs(site_id: str, args: dict) -> dict[str, str]:
        """Validate site_id, files map, and all filenames. Returns the files dict."""
        logger.debug(
            "validating website inputs",
            extra={
                "event": "website.create_validate",
                "site_id": site_id,
                "has_files": bool(args.get("files")),
            },
        )

        if not site_id or not WebsiteHandlerMixin._SITE_ID_RE.match(site_id):
            logger.warning(
                "Invalid site_id",
                extra={
                    "event": "website.invalid_site_id",
                    "site_id_len": len(site_id) if isinstance(site_id, str) else 0,
                    "site_id_hash": log_hash(str(site_id)),
                },
            )
            raise ToolError(
                "Invalid site_id (must be lowercase alphanumeric + hyphens, "
                "1-63 chars, start with alphanumeric)"
            )

        files = args.get("files", {})
        if not files or not isinstance(files, dict):
            # Reworded from "requires a non-empty 'files' map" to
            # "a non-empty 'files' map is required" — matches
            # `_sanitise_error` allowlist `r"is required"`.
            raise ToolError("website create: a non-empty 'files' map is required.")

        # Validate all filenames before writing anything
        for filename in files:
            if not WebsiteHandlerMixin._FILENAME_RE.match(filename):
                logger.warning(
                    "Invalid filename",
                    extra={
                        "event": "website.invalid_filename",
                        "filename_len": (
                            len(filename) if isinstance(filename, str) else 0
                        ),
                        "filename_hash": log_hash(str(filename)),
                    },
                )
                # "in 'files' map" preserves enough location for the
                # Worker LLM to know which input collection it came
                # from, without echoing the bytes.
                raise ToolError(
                    "Invalid filename in 'files' map (must be alphanumeric, "
                    "dots, hyphens, underscores only — no paths or special "
                    "characters)"
                )

        logger.debug(
            "website inputs valid",
            extra={
                "event": "website.create_validate_ok",
                "site_id": site_id,
                "file_count": len(files),
            },
        )
        return files

    async def _process_website_file(
        self,
        filename: str,
        content: str,
        filepath: str,
        site_dir: str,
    ) -> str:
        """Run security pipeline on a single website file. Returns processed content.

        Pipeline: code fixer → anchor allocator → Semgrep prescan → per-file policy.
        On Semgrep block or crash (fail-closed), cleans up the entire site directory.
        """
        from sentinel.core.config import settings as _aa_ws

        logger.debug(
            "processing website file",
            extra={
                "event": "website.create_process_file",
                "file_name": filename,
                "content_len": len(content),
            },
        )

        # Code fixer — same logic as _file_write
        content = await self._run_website_code_fixer(filename, content, filepath)

        # Anchor allocator
        if _aa_ws.anchor_allocator_enabled:
            content = await self._run_website_anchor_allocator(
                content, filepath, _aa_ws.anchor_allocator_tier
            )

        # Pre-write Semgrep scan at TL3+ — defence-in-depth.
        # Without this, worker-generated HTML/JS/CSS bypasses pattern
        # detection and is written to an auth-exempt served directory.
        if self._trust_level >= 3 and semgrep_scanner.is_loaded():
            await self._run_website_semgrep_prescan(
                filename, content, filepath, site_dir
            )

        # Per-file policy check on each content file
        file_policy = self._engine.check_file_write(filepath)
        if file_policy.status != PolicyResult.ALLOWED:
            raise ToolBlockedError(
                f"website file blocked by policy: {file_policy.reason}"
            )

        return content

    async def _run_website_code_fixer(
        self, filename: str, content: str, filepath: str
    ) -> str:
        """Run code fixer on code files. Returns content (possibly fixed).

        Fixer crash never blocks a write — logs warning and returns original content.
        """
        _, ext = os.path.splitext(filename)
        if (
            ext.lower() not in _CODE_EXTENSIONS
            and filename not in _EXTENSIONLESS_FIXER_NAMES
        ):
            logger.debug(
                "_run_website_code_fixer: condition_match",
                extra={
                    "event": "_website._run_website_code_fixer.match",
                    "reason": "condition_match",
                },
            )  # auto:neg
            return content

        try:
            fix_result = code_fixer_fix(filepath, content)
            if fix_result.changed:
                content = fix_result.content
                logger.info(
                    "Code fixer applied fixes (website)",
                    extra={
                        "event": "website.code_fixer_applied",
                        "path": filepath,
                        "fixes": fix_result.fixes_applied,
                    },
                )
            else:
                logger.debug(
                    "code fixer ran, no changes (website)",
                    extra={"event": "website.code_fixer_clean", "path": filepath},
                )
            # Post-fix syntax validation (website).
            # _validate_syntax_post_fix logs WARN internally on failure.
            await self._validate_syntax_post_fix(filepath, fix_result)
        except Exception as exc:  # catch-all: code fixer crash must not block write
            # Fixer crash must never block a write — log and continue
            # with original content. Matches _file_write pattern.
            logger.warning(
                "Code fixer crash in website create — using original content",
                extra={
                    "event": "website.code_fixer_error",
                    "path": filepath,
                    "error": str(exc),
                },
                exc_info=True,
            )

        return content

    async def _run_website_anchor_allocator(
        self, content: str, filepath: str, tier: str
    ) -> str:
        """Run anchor allocator on a website file. Returns content (possibly modified)."""
        try:
            _ws_user_id = current_user_id.get()
            _anchor_result = await allocate_anchors(
                path=filepath,
                content=content,
                episodic_store=getattr(self, "_episodic_store", None),
                user_id=_ws_user_id,
                tier=tier,
            )
            if _anchor_result.changed:
                content = _anchor_result.content
                logger.debug(
                    "anchor allocator applied changes (website)",
                    extra={"event": "website.anchor_allocated", "path": filepath},
                )
            if _anchor_result.parse_failed:
                logger.warning(
                    "Anchor allocation failed (website create)",
                    extra={
                        "event": "website.anchor_allocation_failed",
                        "path": filepath,
                        "error": _anchor_result.error,
                    },
                )
        except PrincipalRequiredError:
            # Q4.fix.f Coord follow-up: zero-principal must propagate past
            # the "never block a website create" swallow so the fail-closed
            # invariant is preserved at the producer boundary.
            raise
        except (
            Exception
        ) as exc:  # catch-all: anchor allocator crash must not block write
            logger.warning(
                "Anchor allocator crash in website create",
                extra={
                    "event": "website.anchor_allocator_error",
                    "path": filepath,
                    "error": str(exc),
                },
                exc_info=True,
            )
        return content

    async def _run_website_semgrep_prescan(
        self,
        filename: str,
        content: str,
        filepath: str,
        site_dir: str,
    ) -> None:
        """Pre-write Semgrep scan (fail-closed). Cleans up site_dir on block/crash."""
        lang_hint = _detect_language_from_path(filepath)
        try:
            sg_result = await semgrep_scanner.scan_blocks([(content, lang_hint)])
            if sg_result.found:
                match_names = [m.pattern_name for m in sg_result.matches]
                logger.warning(
                    "Website file blocked by pre-write Semgrep scan",
                    extra={
                        "event": "website.semgrep_blocked",
                        "path": filepath,
                        "matches": match_names,
                    },
                )
                # Clean up entire site dir — partial sites are worse
                # than no site (broken references, missing assets).
                shutil.rmtree(site_dir, ignore_errors=True)
                # Q14-FL1: fixed-template user-facing reason (no
                # filename, no scanner output count). Server-side log
                # above emits match_names + path via extra={...}.
                raise ToolBlockedError("Pre-write Semgrep scan blocked website file")
            logger.debug(
                "Pre-write Semgrep scan clean for website file",
                extra={
                    "event": "website.semgrep_clean",
                    "path": filepath,
                },
            )
        except ToolBlockedError:
            raise
        except Exception as exc:
            # Fail-closed: if Semgrep crashes, block the write.
            logger.error(
                "Pre-write Semgrep scan failed for website — "
                "blocking write (fail-closed)",
                extra={
                    "event": "website.semgrep_error",
                    "path": filepath,
                    "error": str(exc),
                    "error_category": "security",
                    "error_class": "permanent",
                },
                exc_info=True,
            )
            shutil.rmtree(site_dir, ignore_errors=True)
            # Q14-FL1: fixed-template user-facing reason (no exception
            # text). `from exc` chains underlying exception server-side;
            # `exc_info=True` log above captures detail.
            raise ToolBlockedError("Pre-write scan failed (fail-closed)") from exc

    @staticmethod
    def _extract_website_file_digests(
        filename: str,
        content: str,
        structural_digests: dict[str, dict],
        content_manifests: dict[str, dict],
    ) -> None:
        """Extract structural digest and content manifest for a single file."""
        from sentinel.analysis.content_manifest import extract_content_manifest
        from sentinel.analysis.structural_digest import extract_structural_digest

        # Structural digest — only for digestable extensions
        _ws_ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if _ws_ext in _MANIFEST_EXTENSIONS:
            try:
                _digest = extract_structural_digest(filename, content, "")
                structural_digests[filename] = _digest
                logger.debug(
                    "Structural digest extracted (website)",
                    extra={
                        "event": "website.structural_digest",
                        "file_name": filename,
                    },
                )
            except Exception as exc:  # catch-all: structural digest best-effort
                logger.warning(
                    "Structural digest extraction failed (website)",
                    extra={
                        "event": "website.structural_digest_error",
                        "file_name": filename,
                        "error": str(exc),
                    },
                    exc_info=True,
                )

        # Content manifest
        try:
            _cm = extract_content_manifest(filename, content, "")
            content_manifests[filename] = _cm
            logger.debug(
                "Content manifest extracted (website)",
                extra={
                    "event": "website.content_manifest",
                    "file_name": filename,
                },
            )
        except Exception as exc:  # catch-all: manifest extraction best-effort
            logger.warning(
                "Content manifest extraction failed (website)",
                extra={
                    "event": "website.content_manifest_error",
                    "file_name": filename,
                    "error": str(exc),
                },
                exc_info=True,
            )

    async def _copy_website_media(
        self,
        media_specs: list[dict],
        site_id: str,
        site_dir: str,
    ) -> int:
        """Validate and copy binary media assets into the site directory.

        Source must be within the user workspace. Dest filename validated with
        the same regex as text file names. Returns count of files copied.
        """
        if not media_specs:
            return 0

        logger.debug(
            "copying website media",
            extra={
                "event": "website.media_copy_begin",
                "site_id": site_id,
                "media_count": len(media_specs),
            },
        )

        media_copied = 0
        for media_item in media_specs:
            media_source = media_item.get("source", "")
            media_dest = media_item.get("dest", "")

            # Validate dest filename with same regex as site files.
            if not media_dest or not self._FILENAME_RE.match(media_dest):
                logger.warning(
                    "website media: invalid dest filename",
                    extra={
                        "event": "website.media_invalid_dest",
                        "media_dest_len": (
                            len(media_dest) if isinstance(media_dest, str) else 0
                        ),
                        "media_dest_hash": log_hash(str(media_dest)),
                    },
                )
                # Drops both the value echo AND the `_FILENAME_RE.pattern`
                # interpolation (mild defence-internal disclosure). Matches
                # the plain-English description used at site 252.
                raise ToolError(
                    "website media: invalid dest filename (must be "
                    "alphanumeric, dots, hyphens, underscores only — no "
                    "paths or special characters)"
                )

            # Source must be within the user's workspace.
            resolved_source = os.path.realpath(media_source)
            user_workspace = str(get_user_workspace())
            if not resolved_source.startswith(user_workspace + os.sep):
                logger.warning(
                    "website media: source outside workspace",
                    extra={
                        "event": "website.media_source_oos",
                        "media_source_len": (
                            len(media_source) if isinstance(media_source, str) else 0
                        ),
                        "media_source_hash": log_hash(str(media_source)),
                    },
                )
                # Reworded "must be within user workspace" → "outside user
                # workspace" (semantic equivalent, opposite framing) to
                # match `_sanitise_error` allowlist `r"path.*outside"`.
                raise ToolError("website media: source path outside user workspace")

            if not os.path.isfile(resolved_source):
                logger.warning(
                    "website media: source not found",
                    extra={
                        "event": "website.media_source_missing",
                        "media_source_len": (
                            len(media_source) if isinstance(media_source, str) else 0
                        ),
                        "media_source_hash": log_hash(str(media_source)),
                    },
                )
                raise ToolError("website media: source file not found")

            dest_path = os.path.join(site_dir, media_dest)
            # Verify dest resolves inside site_dir (no traversal).
            resolved_dest = os.path.realpath(dest_path)
            if not resolved_dest.startswith(os.path.realpath(site_dir) + os.sep):
                logger.warning(
                    "website media: dest escape",
                    extra={
                        "event": "website.media_dest_escape",
                        "media_dest_len": (
                            len(media_dest) if isinstance(media_dest, str) else 0
                        ),
                        "media_dest_hash": log_hash(str(media_dest)),
                    },
                )
                # Reworded "escapes site directory" → "outside site
                # directory" to match `_sanitise_error` allowlist
                # `r"path.*outside"`.
                raise ToolError("website media: dest path outside site directory")

            # Per-file policy check — directory-level check above is necessary
            # but not sufficient for individual media files
            media_policy = self._engine.check_file_write(dest_path)
            if media_policy.status != PolicyResult.ALLOWED:
                raise ToolBlockedError(
                    f"website media blocked by policy: {media_policy.reason}"
                )

            shutil.copy2(resolved_source, dest_path)
            media_copied += 1

            logger.info(
                "website media copied",
                extra={
                    "event": "website.media_copied",
                    "site_id": site_id,
                    "media_dest": media_dest,
                    "media_file_size": os.path.getsize(dest_path),
                },
            )

        logger.debug(
            "website media copy complete",
            extra={
                "event": "website.media_copy_done",
                "site_id": site_id,
                "media_copied": media_copied,
            },
        )
        return media_copied

    async def _build_website_result(
        self,
        args: dict,
        site_id: str,
        files: dict[str, str],
        site_dir: str,
        structural_digests: dict[str, dict],
        content_manifests: dict[str, dict],
    ) -> tuple[TaggedData, dict | None]:
        """Assemble tagged data + exec_meta for a successful website create."""
        title = args.get("title", site_id)
        file_count = len(files)
        # TODO(config): derive from application config instead of hardcoding.
        # Tracked as Finding #32 in audit_executor_20260323.md.
        url = f"https://localhost:3001/sites/{site_id}/"

        logger.info(
            "Website created",
            extra={
                "event": "website.created",
                "site_id": site_id,
                "files": file_count,
            },
        )

        try:
            return await create_tagged_data(
                content=f"Website created: {title}\n{url}\n({file_count} files)",
                source=DataSource.TOOL,
                trust_level=TrustLevel.TRUSTED,
                originated_from=f"website:create:{site_id}",
            ), {
                "site_id": site_id,
                "file_count": file_count,
                "url": url,
                "filenames": list(files.keys()),
                "structural_digests": structural_digests,
                "content_manifests": content_manifests,
            }
        except Exception:
            logger.warning(
                "website create failed, cleaning up",
                extra={"event": "website.create_cleanup"},
                exc_info=True,
            )
            # Provenance tagging failed — clean up written files
            shutil.rmtree(site_dir, ignore_errors=True)
            raise

    async def _website_remove(
        self, site_id: str, sites_root: str
    ) -> tuple[TaggedData, dict | None]:
        logger.debug(
            "_website_remove called",
            extra={"event": "website.remove", "site_id": site_id},
        )
        if not site_id or not self._SITE_ID_RE.match(site_id):
            logger.warning(
                "Invalid site_id",
                extra={
                    "event": "website.remove_invalid_site_id",
                    "site_id_len": len(site_id) if isinstance(site_id, str) else 0,
                    "site_id_hash": log_hash(str(site_id)),
                },
            )
            raise ToolError(
                "Invalid site_id (must be lowercase alphanumeric + hyphens, "
                "1-63 chars, start with alphanumeric)"
            )
        logger.debug(
            "_website_remove: not_site_id_passed",
            extra={
                "event": "tools.handlers.website.remove_invalid_site_id.passed",
                "reason": "not_site_id_passed",
            },
        )  # auto:neg

        site_dir = os.path.join(sites_root, site_id)

        if not os.path.isdir(site_dir):
            logger.warning(
                "website remove: site missing",
                extra={
                    "event": "website.remove_site_missing",
                    "site_id_len": len(site_id) if isinstance(site_id, str) else 0,
                    "site_id_hash": log_hash(str(site_id)),
                },
            )
            # Reworded "Site '...' does not exist." → "Site not found"
            # to match `_sanitise_error` allowlist `r"not found"`.
            raise ToolError("Site not found")

        # Policy gate
        result = self._engine.check_file_write(site_dir)
        if result.status != PolicyResult.ALLOWED:
            raise ToolBlockedError(f"website remove blocked: {result.reason}")
        logger.debug(
            "policy gate passed for website remove",
            extra={"event": "website.remove_policy_passed", "site_dir": str(site_dir)},
        )

        try:
            shutil.rmtree(site_dir)
        except OSError as exc:
            logger.warning(
                "website remove failed",
                extra={
                    "event": "website.remove_error",
                    "site_id_len": len(site_id) if isinstance(site_id, str) else 0,
                    "site_id_hash": log_hash(str(site_id)),
                    "error": str(exc),
                },
                exc_info=True,
            )
            # Trailing colon kept intentional — matches `_sanitise_error`
            # allowlist `r"failed:"`. `from exc` chains the OS error
            # server-side.
            raise ToolError("website remove failed:") from exc

        logger.info(
            "Website removed",
            extra={"event": "website.removed", "site_id": site_id},
        )

        return await create_tagged_data(
            content=f"Removed: {site_id}",
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
            originated_from=f"website:remove:{site_id}",
        ), {"site_id": site_id}
