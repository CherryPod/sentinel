"""Email channel — polls IMAP for new messages with attachments.

Periodically checks the IMAP inbox for unseen emails. When an email
with attachments is found, the attachments are ingested via
AttachmentIngester and an IncomingMessage is queued for the
orchestrator. The email body text becomes the user request.

Emails without attachments are ignored — the existing email tools
(imap_email_read/search) handle text-only email interactions.
"""

import asyncio
import logging
import os
import re
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel.core.config import Settings

from sentinel.channels.base import (
    Channel,
    ChannelDescriptor,
    IncomingMessage,
    OutgoingMessage,
)
from sentinel.core.bus import EventBus
from sentinel.core.context import PrincipalRequiredError
from sentinel.crypto.blind_index import log_hash
from sentinel.media.models import is_mime_allowed

logger = logging.getLogger(__name__)


# Q16.fix.d.review Cx-1: `os.path.splitext(filename)[1]` puts EVERYTHING after
# the last `.` into the extension, so attacker-controlled envelope filenames
# can smuggle content (SSNs past the last `.`, `\n`-forged log lines, ANSI
# escapes). Cap length + filter to `[a-z0-9.]` to keep the classification
# signal (`.pdf`, `.jpg`) without letting inbound content leak into logs.
_ATT_EXT_MAX_LEN = 16
_ATT_EXT_SAFE_CHARS = re.compile(r"[^a-z0-9.]")


def _safe_ext(filename: str) -> str:
    """Return a length-capped, alphanumeric-only extension for log redaction."""
    raw = os.path.splitext(filename)[1].lower()
    return _ATT_EXT_SAFE_CHARS.sub("", raw)[:_ATT_EXT_MAX_LEN]


def _consume_helper_task_exception(task: asyncio.Task) -> None:
    """Q11-FL-c1: done-callback for `_check_inbox`'s `_do_imap_work_sync` task.

    Attached at `create_task` time so the task's exception is consumed even if
    the awaiter is abandoned by a second `CancelledError` mid-cleanup. Without
    this callback, a helper that raises after awaiter abandonment would emit
    an asyncio "Task exception was never retrieved" warning.

    `ImapEmailError` is the helper's expected raise class — already handled at
    the `_check_inbox` call site's inner-try arm (logged + returned). Other
    exceptions are unexpected and logged at DEBUG so they aren't silently
    swallowed.
    """
    if task.cancelled():
        return
    try:
        exc = task.exception()
    except asyncio.CancelledError:
        logger.exception(
            "_consume_helper_task_exception: asyncio.CancelledError",
            extra={
                "event": "channels.email_channel._consume_helper_task_exception_cancellederror"
            },
        )  # auto:except
        return
    if exc is None:
        return
    # ImapEmailError import is inline because the type lives in
    # sentinel.integrations.imap_email; module-scope import would create a
    # cyclic dependency on integrations from a channel. Cleanup callback only.
    from sentinel.integrations.imap_email import ImapEmailError

    if isinstance(exc, ImapEmailError):
        return  # already-handled path
    logger.debug(
        "Email poll: helper task raised under abandonment",
        extra={"event": "email.poll_helper_task_unhandled"},
        exc_info=(type(exc), exc, exc.__traceback__),
    )


def _consume_fallback_logout_exception(task: asyncio.Task) -> None:
    """Q11-FL-c1: done-callback for `_check_inbox`'s fallback `conn.logout` task.

    Attached at `create_task` time so the task's exception is consumed even if
    the awaiter is abandoned by a second `CancelledError` mid-cleanup.
    Best-effort: logout failures are logged at DEBUG; cancellation is silent.
    """
    if task.cancelled():
        return
    try:
        exc = task.exception()
    except asyncio.CancelledError:
        logger.exception(
            "_consume_fallback_logout_exception: asyncio.CancelledError",
            extra={
                "event": "channels.email_channel._consume_fallback_logout_exception_cancellederror"
            },
        )  # auto:except
        return
    if exc is None:
        return
    logger.debug(
        "Email poll: fallback logout failed (best-effort)",
        extra={"event": "email.poll_fallback_logout_error"},
        exc_info=(type(exc), exc, exc.__traceback__),
    )


@dataclass
class EmailChannelConfig:
    """Configuration for the email polling channel."""

    poll_interval_seconds: int = 120  # how often to check for new mail
    max_body_length: int = 5000  # truncate email body for planner
    allowed_senders: set[str] = field(default_factory=set)


class EmailChannel(Channel):
    """Email channel that polls IMAP for new messages with attachments.

    Only processes emails that have attachments — text-only emails are
    left for the user to interact with via the email tools. This avoids
    flooding the planner with every incoming email.
    """

    descriptor = ChannelDescriptor(
        name="email",
        tool_name="",  # email_send is a handler mixin, not a channel tool
        tool_description="",
        domain="email",
        config_prefix="email_channel_",
        health_check=True,
        needs_recipient=False,
    )

    def __init__(
        self,
        config: EmailChannelConfig,
        imap_settings,
        event_bus: EventBus | None = None,
    ):
        self._config = config
        self._imap_settings = imap_settings
        self._bus = event_bus
        self._running = False
        self._message_queue: asyncio.Queue[IncomingMessage] = asyncio.Queue()
        self._background_tasks: set[asyncio.Task] = set()
        # Attachment ingester — set by lifecycle.py after startup
        self._ingester = None
        # Track seen UIDs to avoid reprocessing
        self._seen_uids: set[str] = set()

    async def start(self) -> None:
        """Start the IMAP polling loop."""
        self._running = True
        # infrastructure — no user context needed (IMAP polling is channel-level)
        task = asyncio.create_task(self._poll_loop())
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)
        logger.info(
            "Email channel started",
            extra={
                "event": "email_channel.started",
                "poll_interval": self._config.poll_interval_seconds,
                "allowed_senders": len(self._config.allowed_senders),
            },
        )

    async def stop(self) -> None:
        """Stop the polling loop."""
        self._running = False
        for task in list(self._background_tasks):
            task.cancel()
        if self._background_tasks:
            await asyncio.gather(*self._background_tasks, return_exceptions=True)
        self._background_tasks.clear()
        logger.info("Email channel stopped", extra={"event": "email_channel.stopped"})

    async def send(self, message: OutgoingMessage) -> None:
        """Email channel is receive-only — send is a no-op."""

    async def receive(self) -> AsyncIterator[IncomingMessage]:
        """Yield incoming messages queued by the poll loop."""
        while self._running:
            try:
                msg = await asyncio.wait_for(self._message_queue.get(), timeout=1.0)
                yield msg
            except TimeoutError:
                continue

    # -- Registry extensions ---------------------------------------------------

    @classmethod
    def from_settings(cls, settings: "Settings") -> "EmailChannel | None":
        """Build from flat Settings fields. Returns None if disabled."""
        logger.debug(
            "from_settings called",
            extra={
                "event": "email_channel.from_settings",
                "settings_len": len(settings) if hasattr(settings, "__len__") else 0,
            },
        )  # auto:entry
        if not (settings.email_channel_enabled and settings.imap_host):
            return None
        allowed_senders: set[str] = set()
        if settings.email_channel_allowed_senders:
            allowed_senders = {
                s.strip().lower()
                for s in settings.email_channel_allowed_senders.split(",")
                if s.strip()
            }
        config = EmailChannelConfig(
            poll_interval_seconds=settings.email_channel_poll_interval,
            allowed_senders=allowed_senders,
        )
        return cls(config, settings)

    async def send_message(self, text: str, recipient: str | None = None) -> dict:
        """Email channel is receive-only — send is a no-op."""
        return {"status": "unsupported", "channel": "email"}

    @property
    def is_running(self) -> bool:
        return self._running

    async def _poll_loop(self) -> None:
        """Periodically check IMAP for new emails with attachments."""
        # Short initial delay to let other services start
        await asyncio.sleep(10)

        while self._running:
            try:
                await self._check_inbox()
            except asyncio.CancelledError:
                # Q11-F10b: propagate cancellation so the parent's
                # `await task` observes cancelled() is True. A prior `break`
                # exited the poll loop normally and the parent saw a
                # completed task, erasing the "cancelled during shutdown"
                # signal.
                raise
            except Exception as exc:  # catch-all: email poll loop isolation
                logger.warning(
                    "Email poll error",
                    extra={"event": "email.poll_error", "error": str(exc)},
                    exc_info=True,
                )

            # Sleep in small increments so we can stop promptly
            for _ in range(self._config.poll_interval_seconds):
                if not self._running:
                    break
                await asyncio.sleep(1)

    async def _check_inbox(self) -> None:
        """Check IMAP for unseen emails with attachments."""
        import email as email_lib

        from sentinel.integrations.imap_email import (
            ImapEmailError,
            _decode_header_value,
            _extract_body,
            _imap_connect,
            extract_attachments,
        )

        logger.debug(
            "Email poll: checking inbox",
            extra={"event": "email.poll_check", "seen_count": len(self._seen_uids)},
        )

        # Q11-FL-c1: outer try/finally + task-handle ownership tracking closes the
        # cancellation leak window between conn-returned (line 217 below) and
        # `_do_imap_work_sync` actually entering its body on the worker thread.
        # `work_task is None` => helper task never scheduled; outer fallback owns
        # logout. `work_task is not None` => ownership transferred to
        # `_do_imap_work_sync`; helper's internal finally (lines :454-:462) runs
        # logout on the worker thread regardless of awaiter unwind. Outer code
        # MUST NOT call `conn.logout` directly in the latter branch — that
        # reopens the Q14-F8 Cx-2 concurrent-imaplib-access bug. Codex
        # peer-consult thread `019dc6d6-1f40-7042-b6ff-8a9d08e611b5`.
        conn: object | None = None
        work_task: asyncio.Task | None = None
        try:
            try:
                conn = await asyncio.to_thread(
                    _imap_connect,
                    self._imap_settings,
                )
            except ImapEmailError as exc:
                logger.warning(
                    "Email poll: IMAP connect failed",
                    extra={"event": "email.poll_connect_error", "error": str(exc)},
                    exc_info=True,
                )
                return

            # Q14-F8 MC Cx-2 Option A: fetch all UNSEEN message bodies + logout
            # in a SINGLE `asyncio.to_thread` call (helper below). Per-call
            # wrapping (original F8 shape) introduced a cancellation race —
            # cancelling the poll task while `conn.uid("fetch")` was in-flight
            # would leave that worker thread running AND schedule a new
            # `conn.logout` thread in the finally block, producing concurrent
            # imaplib access on the same connection (imaplib is NOT
            # thread-safe). Serialising the entire IMAP sequence into one
            # thread eliminates the race — cancellation of the awaiter does
            # not stop the thread, but the thread completes select / search /
            # fetch / logout serially and never shares the connection.
            #
            # Q11-FL-c1: capture the task handle so the outer finally can
            # reason about ownership. `asyncio.shield(work_task)` keeps the
            # task wrapper alive across awaiter cancellation — once the task
            # exists, `_do_imap_work_sync` is the sole owner of `conn`.
            try:
                work_task = asyncio.create_task(
                    asyncio.to_thread(_do_imap_work_sync, conn, self._seen_uids)
                )
                # Q11-FL-c1 R-MG: consume eventual exception even if a second
                # `CancelledError` abandons the cleanup-path await. Codex
                # merge-gate review (thread `019dc6df-6c10-7f60-ad45-8eb6fff5e7e9`)
                # demonstrated `Task exception was never retrieved` warning
                # under multi-cancellation absent this callback.
                work_task.add_done_callback(_consume_helper_task_exception)
                fetched = await asyncio.shield(work_task)
            except ImapEmailError as exc:
                logger.warning(
                    "Email poll: IMAP error",
                    extra={"event": "email.poll_imap_error", "error": str(exc)},
                    exc_info=True,
                )
                return

            # All async processing (attachment ingest + queue put) happens AFTER
            # the IMAP sequence completes — it cannot race the thread, and
            # cancellation here is safe because the connection is already logged
            # out and closed.
            for uid, raw in fetched:
                msg = email_lib.message_from_bytes(raw)
                raw_attachments = extract_attachments(msg)

                # Only process emails with attachments
                if not raw_attachments:
                    logger.debug(
                        "Email poll: skipping email without attachments",
                        extra={
                            "event": "email.poll_skip_no_attachment",
                            "uid_hash": log_hash(uid),
                            "uid_len": len(uid),
                        },
                    )
                    continue

                # Check sender allowlist (Q13-F14: empty = deny-all, aligned
                # with Signal/Matrix/Telegram per Q13.fix.c)
                sender = _decode_header_value(msg.get("From", ""))
                sender_email = _extract_email_address(sender)
                if sender_email not in self._config.allowed_senders:
                    logger.info(
                        "Email poll: sender not in allowlist",
                        extra={
                            "event": "email.poll_sender_blocked",
                            "sender": _mask_email(sender_email),
                            "uid_hash": log_hash(uid),
                            "uid_len": len(uid),
                        },
                    )
                    continue

                subject = _decode_header_value(msg.get("Subject", ""))
                body = _extract_body(msg, self._config.max_body_length)

                # Build request text from subject + body
                request_text = subject
                if body and body.strip():
                    request_text = f"{subject}\n\n{body.strip()}"
                if not request_text.strip():
                    request_text = "Process these attachments"

                # Ingest attachments
                attachment_metas = await self._ingest_attachments(
                    raw_attachments,
                    uid,
                    sender_email,
                )

                if not attachment_metas:
                    continue

                incoming = IncomingMessage(
                    channel_id=sender_email,
                    source="email",
                    content=request_text,
                    metadata={
                        "message_id": uid,
                        "subject": subject,
                        "type": "task",
                    },
                    attachments=attachment_metas,
                )
                await self._message_queue.put(incoming)

                logger.info(
                    "Email with attachments queued",
                    extra={
                        "event": "email.poll_message_queued",
                        "uid_hash": log_hash(uid),
                        "uid_len": len(uid),
                        "sender": _mask_email(sender_email),
                        "attachment_count": len(attachment_metas),
                        "subject_length": len(subject),
                    },
                )
        finally:
            # Q11-FL-c1: ownership-aware cleanup. `work_task is None` => the
            # helper task was never created (cancellation arrived between conn
            # returning at the connect-await and the `create_task` line above,
            # OR connect itself failed before reaching it). No worker thread is
            # touching `conn`, so a fallback `to_thread(conn.logout)` is safe —
            # no concurrent imaplib access. `work_task is not None` =>
            # ownership transferred to `_do_imap_work_sync`; helper's internal
            # `finally` (lines :454-:462) runs `conn.logout` on the worker
            # thread regardless of awaiter unwind. We MUST NOT call
            # `conn.logout` directly here in that branch — that would re-create
            # the Q14-F8 Cx-2 concurrent-imaplib-access bug. Optional cleanup
            # await on `work_task` is for ordering hygiene only (lets caller
            # cancellation propagate while the worker thread finishes its
            # `finally` independently).
            if conn is not None and work_task is None:
                # Q11-FL-c1 R-MG: capture the cleanup task so its exception is
                # retrieved via done-callback even if a second cancellation
                # abandons the await below.
                logger.debug(
                    "_check_inbox: conn_is_not_None",
                    extra={
                        "event": "channels.email_channel._check_inbox.match",
                        "reason": "conn_is_not_None",
                    },
                )  # auto:neg
                fallback_task = asyncio.create_task(asyncio.to_thread(conn.logout))
                fallback_task.add_done_callback(_consume_fallback_logout_exception)
                try:
                    await asyncio.shield(fallback_task)
                except Exception:  # catch-all: logout best-effort
                    pass  # exception already consumed by done-callback
            elif work_task is not None and not work_task.done():
                # Helper owns conn; await its completion for ordering hygiene.
                # If a second cancellation arrives, propagate normally — helper
                # continues on the worker thread and runs its own logout.
                logger.debug(
                    "_check_inbox: work_task_is_not_None",
                    extra={
                        "event": "channels.email_channel._check_inbox.match",
                        "reason": "work_task_is_not_None",
                    },
                )  # auto:neg
                try:
                    await asyncio.shield(work_task)
                except Exception:  # catch-all: avoid noisy unhandled-task warnings
                    pass

    async def _ingest_attachments(
        self,
        raw_attachments: list[tuple[str, str, bytes]],
        email_uid: str,
        sender: str,
    ) -> list[dict]:
        """Ingest raw email attachments through the AttachmentIngester."""
        if self._ingester is None:
            return []

        metas: list[dict] = []
        for filename, mime_type, data in raw_attachments:
            if not is_mime_allowed(mime_type):
                logger.info(
                    "Email attachment skipped: MIME type not allowed",
                    extra={
                        "event": "email_channel.mime_blocked",
                        "mime_type": mime_type,
                        "att_filename_len": len(filename),
                        "att_ext": _safe_ext(filename),
                        "email_uid_hash": log_hash(email_uid),
                        "email_uid_len": len(email_uid),
                    },
                )
                continue

            try:
                meta = await self._ingester.ingest(
                    data=data,
                    mime_type=mime_type,
                    original_filename=filename,
                    source_channel="email",
                    channel_file_id=f"email-{email_uid}-{filename}",
                )
                metas.append(
                    {
                        "attachment_id": meta.attachment_id,
                        "mime_type": meta.mime_type,
                        "original_filename": meta.original_filename,
                        "safe_filename": meta.safe_filename,
                        "file_size": len(data),
                        "workspace_path": meta.workspace_path,
                    }
                )
                logger.info(
                    "Email attachment ingested",
                    extra={
                        "event": "email_channel.attachment_ingested",
                        "attachment_id": meta.attachment_id,
                        "mime_type": mime_type,
                        "file_size": len(data),
                        "email_uid_hash": log_hash(email_uid),
                        "email_uid_len": len(email_uid),
                    },
                )
            except PrincipalRequiredError:
                # Q4.fix.c: zero-principal from MediaStore.save indicates
                # missing upstream binding (Q4.fix.d scope). IMAP polling is
                # channel-level infrastructure without a user context; let
                # the failure propagate loudly rather than be mis-logged as
                # email_channel.ingest_error.
                raise
            except (ValueError, OSError) as exc:
                logger.warning(
                    "Email attachment ingestion failed",
                    extra={
                        "event": "email_channel.ingest_error",
                        "att_filename_len": len(filename),
                        "att_ext": _safe_ext(filename),
                        "error_detail": str(exc),
                        "email_uid_hash": log_hash(email_uid),
                        "email_uid_len": len(email_uid),
                    },
                    exc_info=True,
                )
                continue

        return metas


_EMAIL_ANGLE_BRACKET = re.compile(r"<([^>]+)>")


def _do_imap_work_sync(conn, seen_uids: set[str]) -> list[tuple[str, bytes]]:
    """Q14-F8 MC Cx-2 Option A: single-thread IMAP sequence.

    Runs select + search + per-UID fetch + logout serially inside one thread.
    Closes the cancellation race introduced by the per-call ``asyncio.to_thread``
    shape — cancelling the outer coroutine does not stop this thread (Python
    cannot forcibly stop a running thread), but because every IMAP op here
    runs on the same thread in sequence, no two ops ever touch ``conn``
    concurrently. ``imaplib.IMAP4_SSL`` is NOT thread-safe, so that serial
    ownership is the invariant this helper exists to enforce.

    Mirrors the pre-fix dedupe semantics: adds each fetched UID to
    ``seen_uids`` BEFORE fetching (so a fetch failure still marks the UID as
    seen — the caller never re-attempts it next poll). ``seen_uids`` is
    mutated in-place; Python's GIL makes ``set.add`` atomic, so cross-thread
    access is safe.

    Returns a list of ``(uid_str, raw_bytes)`` tuples for UIDs whose RFC822
    payload fetched cleanly. ``logout()`` is called in ``finally`` inside this
    helper so it runs on the same thread as the fetches — never concurrently
    with them. ``logout()`` failures are logged at DEBUG and swallowed
    (best-effort cleanup; logging is thread-safe).
    """
    fetched: list[tuple[str, bytes]] = []
    try:
        conn.select("INBOX", readonly=True)
        status, data = conn.uid("search", None, "UNSEEN")
        if status != "OK" or not data[0]:
            return fetched

        # Most recent first
        uids = list(reversed(data[0].split()))

        for uid_bytes in uids:
            uid = (
                uid_bytes.decode("ascii")
                if isinstance(uid_bytes, bytes)
                else str(uid_bytes)
            )
            if uid in seen_uids:
                continue
            # Mark BEFORE fetch — preserves pre-fix dedupe semantics
            # (fetch failure still consumes the UID, no retry next poll).
            seen_uids.add(uid)

            status, msg_data = conn.uid("fetch", uid_bytes, "(RFC822)")
            if status != "OK" or not msg_data or not msg_data[0]:
                continue

            raw = msg_data[0][1] if isinstance(msg_data[0], tuple) else b""
            if raw:
                fetched.append((uid, raw))
    finally:
        try:
            conn.logout()
        except Exception:
            logger.debug(
                "Email poll: logout failed (best-effort)",
                extra={"event": "email.poll_logout_error"},
                exc_info=True,
            )
    return fetched


def _extract_email_address(from_header: str) -> str:
    """Extract bare email address from a From header.

    'John Doe <john@example.com>' -> 'john@example.com'
    'john@example.com' -> 'john@example.com'
    """
    match = _EMAIL_ANGLE_BRACKET.search(from_header)
    if match:
        return match.group(1).strip().lower()
    return from_header.strip().lower()


def _mask_email(address: str) -> str:
    """Mask email address for logging — 'j***@example.com'."""
    if "@" in address:
        return address[0] + "***@" + address.split("@")[-1]
    return "***"
