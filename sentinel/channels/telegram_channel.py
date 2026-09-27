"""Telegram bot channel using python-telegram-bot (long-polling).

Messages from Telegram are yielded as IncomingMessage, and outgoing
messages are sent via the Bot API.  The bot uses long-polling — no
webhook endpoint or inbound port is needed.
"""

import asyncio
import json
import logging
import time
from collections import defaultdict
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
from sentinel.core.config import settings
from sentinel.core.context import PrincipalRequiredError, current_user_id
from sentinel.core.decorators import no_audit_log

logger = logging.getLogger(__name__)

_RATE_WINDOW_SECONDS = 60.0


def _classify_telegram_identifier(identifier: str) -> str:
    """Classify a decrypted telegram contact_channels identifier.

    Returns one of ``healthy_positive`` / ``orphaned_negative`` /
    ``non_canonical``. Used by the Q4.fix.e passive enrollment audit.

    Canonical form: a plain decimal integer with no leading sign, no
    leading zeros (except the single-digit ``0``), and no surrounding
    whitespace. HMAC blind-index lookup (``crypto/blind_index.py``) is
    byte-exact, so anything that is not canonical will miss even when
    the integer value would otherwise match.

    Note: the Telegram Bot API contract specifies that user_ids are
    positive integers. Negative integers are always chat_ids, which
    the F20 fix makes dead as a contact principal.
    """
    logger.debug(
        "_classify_telegram_identifier called",
        extra={
            "event": "channels.telegram_channel._classify_telegram_identifier",
            "identifier_len": (len(identifier) if isinstance(identifier, str) else 0),
        },
    )  # auto:entry — decrypted value; never log raw identifier (Q4.fix.e CR2).
    if not isinstance(identifier, str) or not identifier:
        return "non_canonical"
    try:
        as_int = int(identifier)
    except ValueError:
        return "non_canonical"
    # Canonical round-trip: str(int(s)) == s rejects leading zeros,
    # leading '+', whitespace, and other decorations.
    if str(as_int) != identifier:
        return "non_canonical"
    if as_int <= 0:
        return "orphaned_negative"
    return "healthy_positive"


@dataclass
class TelegramConfig:
    bot_token: str = ""
    allowed_chat_ids: set[int] = field(default_factory=set)
    rate_limit: int = 10  # messages/min per chat
    max_message_length: int = 4096  # Telegram's limit
    polling_timeout: int = 30


class TelegramChannel(Channel):
    """Telegram bot channel using long-polling."""

    descriptor = ChannelDescriptor(
        name="telegram",
        tool_name="telegram_send",
        tool_description="Send a Telegram message. Write op — REQUIRES APPROVAL.",
        domain="messaging",
        config_prefix="telegram_",
        keywords=("send on telegram", "telegram message", "message on telegram"),
        preview_label="Telegram",
        needs_recipient=True,
    )

    def __init__(self, config: TelegramConfig, event_bus=None):
        self._config = config
        self._bus = event_bus
        self._app = None
        self._running = False
        self._message_queue: asyncio.Queue[IncomingMessage] = asyncio.Queue()
        # Rate limiting: chat_id -> list of timestamps
        self._rate_buckets: dict[int, list[float]] = defaultdict(list)
        # Attachment ingester — set by lifecycle.py after startup
        self._ingester = None
        # Contact store — injected by init_channels.py before start() so the
        # passive Q4.fix.e enrollment audit can classify existing rows.
        # Remains None in unit tests that don't exercise the audit path.
        self._contact_store = None

    async def start(self) -> None:
        from telegram.ext import ApplicationBuilder, MessageHandler, filters

        # Q11-FL5 (Q11-U2 umbrella): wire PTB HTTPXRequest timeout and
        # connection-pool controls through Sentinel-controlled settings so
        # no PTB library default is reachable for the approved 10-setter
        # closure surface (connect/read/write/pool timeout + connection
        # pool size, both Bot API and getUpdates) on either HTTP path.
        # Proxy, socket options, and HTTP version are reachable PTB
        # transport knobs but intentionally out of C56 scope. Defaults
        # match PTB 22.x's library defaults at C56 verification time
        # (PTB 22.4+ for connection_pool_size=256; behaviour byte-
        # identical at the resolved version under default settings;
        # per-deployment tuning via settings.*). C67 widened the pin
        # from 21.x → 22.x; resolved version is whatever 22.x pip
        # resolves to at install time (>=22.0,<23.0).
        # Contract test at tests/test_telegram_ptb_contract.py asserts
        # the chain surface holds for whatever 22.x pip resolves to.
        self._app = (
            ApplicationBuilder()
            .token(self._config.bot_token)
            # Bot API HTTP transport (send / fetch / lifecycle / get_me)
            .connect_timeout(settings.telegram_connect_timeout)
            .read_timeout(settings.telegram_read_timeout)
            .write_timeout(settings.telegram_write_timeout)
            .pool_timeout(settings.telegram_pool_timeout)
            .connection_pool_size(settings.telegram_connection_pool_size)
            # getUpdates HTTP transport (long-poll only); read_timeout below is
            # slack added to telegram_polling_timeout per PTB Bot.get_updates
            # formula (effective_read = configured + polling_timeout).
            .get_updates_connect_timeout(settings.telegram_get_updates_connect_timeout)
            .get_updates_read_timeout(settings.telegram_get_updates_read_timeout)
            .get_updates_write_timeout(settings.telegram_get_updates_write_timeout)
            .get_updates_pool_timeout(settings.telegram_get_updates_pool_timeout)
            .get_updates_connection_pool_size(
                settings.telegram_get_updates_connection_pool_size
            )
            .build()
        )
        await self._app.initialize()
        await self._app.start()

        # Register handler for text and media messages
        handler = MessageHandler(
            (
                filters.TEXT
                | filters.PHOTO
                | filters.VIDEO
                | filters.AUDIO
                | filters.VOICE
                | filters.Document.ALL
                | filters.VIDEO_NOTE
            )
            & ~filters.COMMAND,
            self._handle_update,
        )
        self._app.add_handler(handler)
        self._running = True

        logger.info(
            "Telegram channel started",
            extra={
                "event": "telegram_channel.init",
                "allowed_chats": len(self._config.allowed_chat_ids),
                "rate_limit": self._config.rate_limit,
            },
        )

        # Q4.fix.e passive enrollment audit — classifies existing rows
        # so admins see which group-chat enrollments are dead post-fix.
        # Wrapped in try/except: an audit-side failure must not block
        # channel startup (fail-open on observability, fail-closed on
        # security — the security fix already landed via get_sender_id).
        if self._contact_store is not None:
            try:
                await self._audit_existing_enrollments()
            except Exception:  # noqa: BLE001 — CancelledError is BaseException; propagates
                logger.warning(
                    "Telegram enrollment audit failed — continuing startup",
                    extra={"event": "telegram.enrollment_audit.error"},
                    exc_info=True,
                )

    async def _audit_existing_enrollments(self) -> None:
        """Q4.fix.e: classify existing telegram contact_channels rows.

        Three classes:
        - ``healthy_positive`` — decrypted identifier parses as a positive
          integer in canonical decimal form. 1:1 rows and any sender-keyed
          rows match here. These continue to resolve post-fix.
        - ``orphaned_negative`` — identifier parses as a negative integer.
          These were group ``chat_id`` values under the pre-fix scheme and
          are dead post-fix (lookup now keys on sender_user_id).
        - ``non_canonical`` — identifier does not parse as an integer in
          canonical decimal form (leading ``+``, leading zeros, whitespace,
          or non-numeric). Already fragile under HMAC blind-index (which
          is byte-exact), still fragile post-fix; surfaced so the admin
          can normalise.

        Emits:
        - One ``system.telegram_post_migration`` audit event with the
          per-class counts.
        - One warning log per dead row with ``contact_id`` + ``reason``.
          Identifiers are never logged (PII-adjacent + byte-equal to the
          pre-decryption plaintext).
        """
        store = self._contact_store
        if store is None:  # defensive; shouldn't reach here
            return

        rows = await self._fetch_telegram_channel_rows(store)
        healthy = 0
        orphaned_negative = 0
        non_canonical = 0

        for row in rows:
            try:
                decrypted = store._decrypt_channel_row(dict(row))
            except Exception:  # noqa: BLE001
                logger.warning(
                    "Telegram enrollment audit — decrypt failed",
                    extra={
                        "event": "telegram.enrollment_audit.decrypt_failed",
                        "contact_channel_id": row.get("id"),
                    },
                    exc_info=True,
                )
                continue

            identifier = decrypted.get("identifier", "")
            classification = _classify_telegram_identifier(identifier)
            if classification == "healthy_positive":
                healthy += 1
            elif classification == "orphaned_negative":
                orphaned_negative += 1
                logger.warning(
                    "Telegram enrollment audit — dead row (group chat_id)",
                    extra={
                        "event": "telegram.enrollment_audit.dead_row_detected",
                        "contact_channel_id": row.get("id"),
                        "reason": "negative_chat_id",
                    },
                )
            else:
                non_canonical += 1
                logger.warning(
                    "Telegram enrollment audit — dead row (non-canonical)",
                    extra={
                        "event": "telegram.enrollment_audit.dead_row_detected",
                        "contact_channel_id": row.get("id"),
                        "reason": "non_canonical",
                    },
                )

        total = healthy + orphaned_negative + non_canonical
        logger.info(
            "Telegram enrollment audit complete",
            extra={
                "event": "telegram.enrollment_audit.summary",
                "healthy_positive": healthy,
                "orphaned_negative": orphaned_negative,
                "non_canonical": non_canonical,
                "total": total,
            },
        )

        audit_emitter = getattr(store, "_audit_emitter", None)
        if audit_emitter is not None:
            from sentinel.audit.events import SecurityAuditEvent

            outcome = "WARNED" if (orphaned_negative or non_canonical) else "CLEAN"
            severity = "LOW" if (orphaned_negative or non_canonical) else "INFO"
            # D33.design lifecycle-surface ownership: NOT shielded. This runs
            # inside the lifespan startup task — cancellation means SIGTERM
            # during startup (operator-withdrawing). CancelledError propagates.
            # Q6.fix.a — Q6-F2. Telegram channel init runs inside the
            # lifecycle.py:330 bootstrap scope which sets current_user_id=1
            # to satisfy the RLS INSERT invariant on the `routines` table.
            # Without this override the rollout/migration audit event —
            # which is operational-plane, not user-plane — would be emitted
            # under user_id=1 and routed to the app pool. Pin to 0 so
            # AuditEmitter._select_pool routes to the admin audit pool.
            token = current_user_id.set(0)
            try:
                try:
                    await audit_emitter.emit(
                        SecurityAuditEvent(
                            event_type="system.telegram_post_migration",
                            source_component="telegram_channel",
                            outcome=outcome,
                            severity=severity,
                            details={
                                "healthy_positive": healthy,
                                "orphaned_negative": orphaned_negative,
                                "non_canonical": non_canonical,
                                "total": total,
                            },
                        )
                    )
                except asyncio.CancelledError:
                    logger.debug(
                        "Telegram enrollment audit emit cancelled — shutdown in progress",
                        extra={"event": "telegram.enrollment_audit.emit_cancelled"},
                    )
                    raise
                except Exception:  # noqa: BLE001 — observability only
                    logger.warning(
                        "Telegram enrollment audit — emit failed",
                        extra={"event": "telegram.enrollment_audit.emit_failed"},
                        exc_info=True,
                    )
            finally:
                current_user_id.reset(token)

    @staticmethod
    async def _fetch_telegram_channel_rows(store) -> list[dict]:
        """Pull raw telegram rows from the store's pool or in-memory map.

        Used by the Q4.fix.e passive enrollment audit only. Returns the
        encrypted row dicts without decryption — caller decrypts per row.
        """
        pool = getattr(store, "_pool", None)
        if pool is not None:
            async with pool.acquire() as conn:
                records = await conn.fetch(
                    "SELECT * FROM contact_channels WHERE channel = $1",
                    "telegram",
                )
            return [dict(r) for r in records]

        # In-memory fallback (test and development paths).
        channels = getattr(store, "_channels", {})
        return [dict(c) for c in channels.values() if c.get("channel") == "telegram"]

    async def stop(self) -> None:
        self._running = False
        if self._app is not None:
            try:
                if self._app.updater and self._app.updater.running:
                    await self._app.updater.stop()
                await self._app.stop()
                await self._app.shutdown()
            except Exception:  # catch-all: graceful shutdown best-effort
                logger.debug(
                    "stop: Exception suppressed",
                    extra={"event": "telegram_channel.stop.suppressed"},
                    exc_info=True,
                )
        logger.info(
            "Telegram channel stopped", extra={"event": "telegram_channel.stop"}
        )

    async def send(self, message: OutgoingMessage) -> None:
        if self._app is None:
            return
        try:
            chat_id = int(message.channel_id)
        except (ValueError, TypeError):
            logger.warning(
                "Telegram send failed — invalid chat_id",
                extra={
                    "event": "telegram.invalid_chat_id",
                    "chat_id": message.channel_id,
                },
                exc_info=True,
            )
            return
        text = self._format_outgoing(message)

        # Split long messages at Telegram's limit
        chunks = [
            text[i : i + self._config.max_message_length]
            for i in range(0, len(text), self._config.max_message_length)
        ]
        abort = False
        for i, chunk in enumerate(chunks):
            if abort:
                break
            for attempt in range(2):
                try:
                    await asyncio.wait_for(
                        self._app.bot.send_message(chat_id=chat_id, text=chunk),
                        timeout=settings.channel_send_timeout,
                    )
                    break  # chunk sent successfully
                except TimeoutError:
                    logger.warning(
                        "Telegram send timed out",
                        extra={"event": "telegram.send_timeout", "chat_id": chat_id},
                        exc_info=True,
                    )
                    abort = True
                    break  # timeouts are not retryable — also stop remaining chunks
                except Exception as exc:  # catch-all: send retry on transient error
                    if attempt < 1:
                        logger.warning(
                            "Telegram send failed, retrying",
                            extra={
                                "event": "telegram.send_retry",
                                "chat_id": chat_id,
                                "attempt": attempt + 1,
                                "error": str(exc),
                            },
                            exc_info=True,
                        )
                        await asyncio.sleep(2**attempt)
                    else:
                        logger.warning(
                            "Telegram send failed after retry",
                            extra={
                                "event": "telegram.send_failed",
                                "chat_id": chat_id,
                                "chunk": i + 1,
                                "total_chunks": len(chunks),
                                "error": str(exc),
                            },
                            exc_info=True,
                        )
                        abort = True

    async def receive(self) -> AsyncIterator[IncomingMessage]:
        """Yield incoming messages. Must be consumed in an async for loop."""
        while self._running:
            try:
                msg = await asyncio.wait_for(self._message_queue.get(), timeout=1.0)
                yield msg
            except TimeoutError:
                continue

    # -- Registry extensions ---------------------------------------------------

    @classmethod
    def from_settings(cls, settings: "Settings") -> "TelegramChannel | None":
        """Build from flat Settings fields. Returns None if disabled."""
        logger.debug(
            "from_settings called",
            extra={
                "event": "telegram_channel.from_settings",
                "settings_len": len(settings) if hasattr(settings, "__len__") else 0,
            },
        )  # auto:entry
        if not settings.telegram_enabled:
            return None
        token = ""
        if settings.telegram_bot_token_file:
            with open(settings.telegram_bot_token_file) as f:
                token = f.read().strip()
        allowed_chats: set[int] = set()
        if settings.telegram_allowed_chat_ids:
            allowed_chats = {
                int(c.strip())
                for c in settings.telegram_allowed_chat_ids.split(",")
                if c.strip()
            }
        config = TelegramConfig(
            bot_token=token,
            allowed_chat_ids=allowed_chats,
            rate_limit=settings.telegram_rate_limit,
            max_message_length=settings.telegram_max_message_length,
            polling_timeout=settings.telegram_polling_timeout,
        )
        return cls(config)

    async def send_message(self, text: str, recipient: str | None = None) -> dict:
        """High-level send for tool dispatch."""
        out = OutgoingMessage(
            channel_id=recipient or "",
            event_type="tool.telegram_send",
            data={"result": text},
        )
        await self.send(out)
        return {"status": "sent", "channel": "telegram"}

    @property
    def is_running(self) -> bool:
        return self._running

    @no_audit_log
    def get_sender_id(self, message: IncomingMessage) -> str:
        """Resolve Telegram sender via metadata['sender_user_id'].

        Without this override, every member of an allowlisted group chat
        resolves against `channel_id` (== `chat_id`) and maps to whichever
        contact was enrolled under that chat_id — messages from member B
        are attributed to member A's user_id for every downstream store
        write (Q4-F20). Matches Matrix's override pattern at
        matrix_channel.py:338-340.

        Fails closed unless ``sender_user_id`` is a **positive Python
        ``int``**. Rationale (Merge-Coord CR1): the Telegram Bot API
        contract guarantees user_ids are positive integers, so any
        other shape — None, missing, string, negative int, float,
        bool, collection — is malformed input and must not resolve
        to a contact. Returning ``""`` causes ``resolve_sender`` to
        return None and the receive loop drops the message as
        ``telegram.unknown_sender``.

        ``bool`` is rejected explicitly because ``isinstance(True, int)``
        is ``True`` in Python — without the guard a stray
        ``sender_user_id=True`` payload would pass as ``1``.
        """
        sender = message.metadata.get("sender_user_id")
        if not isinstance(sender, int) or isinstance(sender, bool) or sender <= 0:
            return ""
        return str(sender)

    def get_source_key(self, message: IncomingMessage) -> str:
        """Bind source_key to (chat_id, sender_user_id).

        Default base key is ``telegram:{chat_id}`` which collapses every
        member of a group chat onto a single approval/confirmation
        namespace. We include the sender's user id so concurrent senders
        in the same allowlisted group chat don't share state (Q3-F9a).
        Ordering is deliberately ``{chat_id}:{sender_user_id}`` (chat
        first): Q4.fix.e preserves this layout so in-flight pending
        approvals / confirmations / sessions keyed on the existing string
        remain reachable across the deploy. Contact-identity resolution
        happens via ``get_sender_id`` (ingress) and ``_parse_source_key``
        (planner re-resolution), both of which return sender_user_id
        without depending on the source_key ordering.

        Falls back to ``0`` when ``sender_user_id`` is absent from
        metadata — should not happen for live Telegram updates since
        ``_handle_update`` always populates it.
        """
        chat_id = message.metadata.get("chat_id", message.channel_id)
        sender_user_id = message.metadata.get("sender_user_id", 0)
        return f"telegram:{chat_id}:{sender_user_id}"

    def _is_allowed(self, chat_id: int) -> bool:
        """Check if chat_id is in the allowlist.

        Q13-F8: empty allowlist = deny-all (fail-closed). Aligns with Signal's
        existing empty-set-drops semantics and reverses the prior Telegram
        behaviour where an empty list meant "allow everyone". Operators who
        want the old open behaviour must list explicit chat IDs.
        """
        return chat_id in self._config.allowed_chat_ids

    def _check_rate_limit(self, chat_id: int) -> bool:
        logger.debug(
            "_check_rate_limit called",
            extra={"event": "telegram_channel._check_rate_limit", "chat_id": chat_id},
        )
        now = time.monotonic()
        bucket = self._rate_buckets[chat_id]
        # Prune old entries (older than 60s)
        self._rate_buckets[chat_id] = [
            t for t in bucket if now - t < _RATE_WINDOW_SECONDS
        ]
        if len(self._rate_buckets[chat_id]) >= self._config.rate_limit:
            return False
        self._rate_buckets[chat_id].append(now)
        return True

    def _extract_media_info(self, message) -> dict | None:
        """Extract media metadata from a Telegram message.

        Checks for media types in priority order: video, photo, audio,
        voice, document, video_note.  Returns a dict with file_id,
        mime_type, file_name, file_size, media_type — or None if no
        media is present.
        """
        # Priority order matches Telegram's own media hierarchy
        logger.debug(
            "_extract_media_info called",
            extra={
                "event": "telegram_channel._extract_media_info",
                "message_len": len(message) if hasattr(message, "__len__") else 0,
            },
        )
        if message.video:
            return {
                "file_id": message.video.file_id,
                "mime_type": message.video.mime_type or "video/mp4",
                "file_name": message.video.file_name or "video.mp4",
                "file_size": message.video.file_size or 0,
                "media_type": "video",
            }

        if message.photo:
            # Telegram sends multiple resolutions — pick the largest
            largest = max(message.photo, key=lambda p: p.file_size or 0)
            return {
                "file_id": largest.file_id,
                "mime_type": "image/jpeg",  # Telegram photos are always JPEG
                "file_name": "photo.jpg",
                "file_size": largest.file_size or 0,
                "media_type": "photo",
            }

        if message.audio:
            return {
                "file_id": message.audio.file_id,
                "mime_type": message.audio.mime_type or "audio/mpeg",
                "file_name": message.audio.file_name or "audio.mp3",
                "file_size": message.audio.file_size or 0,
                "media_type": "audio",
            }

        if message.voice:
            return {
                "file_id": message.voice.file_id,
                "mime_type": message.voice.mime_type or "audio/ogg",
                "file_name": "voice.ogg",
                "file_size": message.voice.file_size or 0,
                "media_type": "voice",
            }

        if message.document:
            return {
                "file_id": message.document.file_id,
                "mime_type": message.document.mime_type or "application/octet-stream",
                "file_name": message.document.file_name or "document.bin",
                "file_size": message.document.file_size or 0,
                "media_type": "document",
            }

        if message.video_note:
            return {
                "file_id": message.video_note.file_id,
                "mime_type": "video/mp4",  # Video notes are always MP4
                "file_name": "video_note.mp4",
                "file_size": message.video_note.file_size or 0,
                "media_type": "video_note",
            }

        logger.debug(
            "No media found in Telegram message",
            extra={"event": "telegram_channel.extract_media.none"},
        )
        return None

    async def _handle_update(self, update, context) -> None:
        """Called by python-telegram-bot for each incoming message."""
        message = update.message
        if message is None:
            return

        # Use text or caption (media messages use caption instead of text)
        text = message.text or message.caption or ""
        media_info = self._extract_media_info(message)

        # Skip messages with no text and no media
        if not text and media_info is None:
            return

        chat_id = message.chat_id
        # Sender identity for source_key binding. In a 1:1 chat the sender
        # equals the chat; in a group chat the sender is one of N members.
        # Captured here so source_key can distinguish concurrent senders
        # within the same group chat (Q3-F9a).
        sender_user_id = (
            update.effective_user.id if update.effective_user is not None else 0
        )
        if not self._is_allowed(chat_id):
            logger.warning(
                "Telegram message from disallowed chat",
                extra={"event": "telegram.disallowed", "chat_id": chat_id},
            )
            return
        logger.debug(
            "_handle_update: not_is_allowed_chat_id_passed",
            extra={
                "event": "telegram.disallowed.passed",
                "reason": "not_is_allowed_chat_id_passed",
            },
        )  # auto:neg

        if not self._check_rate_limit(chat_id):
            logger.warning(
                "Telegram rate limit exceeded",
                extra={"event": "telegram.rate_limited", "chat_id": chat_id},
            )
            # BH3-071: Timeout on rate-limit response to prevent hanging
            try:
                await asyncio.wait_for(
                    context.bot.send_message(
                        chat_id=chat_id,
                        text="Rate limit exceeded. Please wait a moment.",
                    ),
                    timeout=settings.channel_send_timeout,
                )
            except TimeoutError:
                logger.warning(
                    "Telegram rate-limit response timed out",
                    extra={
                        "event": "telegram.ratelimit_send_timeout",
                        "chat_id": chat_id,
                    },
                    exc_info=True,
                )
            return

        # Download and ingest media if present and ingester is available
        attachment_metas = []
        if media_info is not None and self._ingester is not None:
            try:
                # Q11-F9a: bound the Telegram CDN media-fetch path, mirroring
                # the send paths at :347-349 / :638-643 which already wrap in
                # settings.channel_send_timeout. Previously bare: a slow CDN
                # could tie up the channel coroutine for minutes. The
                # channel_send_timeout (30s) is the right reuse per Q11
                # peer-consult — Telegram media-fetch is server-to-server
                # infra-to-Sentinel over internet backbone, same timeout
                # profile as send.
                tg_file = await asyncio.wait_for(
                    context.bot.get_file(media_info["file_id"]),
                    timeout=settings.channel_send_timeout,
                )
                data = await asyncio.wait_for(
                    tg_file.download_as_bytearray(),
                    timeout=settings.channel_send_timeout,
                )

                meta = await self._ingester.ingest(
                    data=bytes(data),
                    mime_type=media_info["mime_type"],
                    original_filename=media_info["file_name"],
                    source_channel="telegram",
                    channel_file_id=media_info["file_id"],
                    extra={"media_type": media_info["media_type"]},
                )
                attachment_metas.append(
                    {
                        "attachment_id": meta.attachment_id,
                        "mime_type": meta.mime_type,
                        "original_filename": meta.original_filename,
                        "safe_filename": meta.safe_filename,
                        "file_size": meta.file_size,
                        "workspace_path": meta.workspace_path,
                    }
                )

                logger.info(
                    "Telegram media attachment ingested",
                    extra={
                        "event": "telegram.media_ingested",
                        "chat_id": chat_id,
                        "media_type": media_info["media_type"],
                        "attachment_id": meta.attachment_id,
                        "file_size": meta.file_size,
                    },
                )
            except PrincipalRequiredError:
                # Q4.fix.c: zero-principal from MediaStore.save indicates
                # missing upstream binding (Q4.fix.d scope). Telegram update
                # handlers run via python-telegram-bot's MessageHandler
                # without a user context; let the failure propagate loudly
                # rather than be mis-logged as telegram.media_ingest_failed.
                raise
            except Exception:  # catch-all: media ingestion must not block messages
                # Ingestion failure should not block message processing —
                # queue the text content and log the error for debugging
                logger.warning(
                    "Telegram media ingestion failed — queuing text only",
                    exc_info=True,
                    extra={
                        "event": "telegram.media_ingest_failed",
                        "chat_id": chat_id,
                        "media_type": media_info.get("media_type", "unknown"),
                    },
                )

        # Only include channel routing metadata — strip PII fields
        # (username, first_name, last_name) so they never reach the
        # orchestrator or planner. chat_id is needed for reply routing.
        incoming = IncomingMessage(
            channel_id=str(chat_id),
            source="telegram",
            content=text,
            metadata={
                "chat_id": chat_id,
                "sender_user_id": sender_user_id,
            },
            attachments=attachment_metas,
        )
        await self._message_queue.put(incoming)

    @staticmethod
    def _format_outgoing(message: OutgoingMessage) -> str:
        """Format an OutgoingMessage as plain text for Telegram."""
        logger.debug(
            "_format_outgoing called",
            extra={
                "event": "telegram_channel._format_outgoing",
                "message_len": len(message) if hasattr(message, "__len__") else 0,
            },
        )
        data = message.data
        if "result" in data:
            return str(data["result"])
        if "payload" in data:
            return str(data["payload"])
        # Confirmation gate preview
        if "preview" in data and "confirmation_id" in data:
            return f"{data['preview']}\n\nReply 'go' to confirm."

        # Plan approval request
        if "approval_id" in data and "plan_summary" in data:
            summary = data["plan_summary"]
            steps = data.get("steps", [])
            step_lines = "\n".join(
                f"  - {s.get('description', s.get('type', ''))}" for s in steps
            )
            return f"Plan: {summary}\n{step_lines}\n\nReply 'go' to approve."

        logger.debug(
            "format_outgoing: fallback to JSON",
            extra={
                "event": "telegram_channel.format_outgoing.fallback",
                "keys": list(data.keys())[:5],
            },
        )
        return json.dumps(data, indent=2, default=str)

    async def start_polling(self) -> None:
        """Start long-polling in the background. Call after start()."""
        if self._app is None:
            return
        await self._app.updater.start_polling(
            poll_interval=1.0,
            timeout=self._config.polling_timeout,
            drop_pending_updates=True,
        )
