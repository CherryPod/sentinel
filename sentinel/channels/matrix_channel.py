"""Matrix channel using matrix-nio with E2EE.

Connects to an external Tuwunel homeserver over HTTPS. The @sentinel user
is a regular Matrix user with full capabilities (text, media, voice).
E2EE keys are persisted in nio_store via a volume mount.
"""

import asyncio
import contextlib
import logging
import time
from collections import defaultdict
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aiohttp import ClientResponse

    from sentinel.core.config import Settings


from nio import (
    AsyncClient,
    AsyncClientConfig,
    DownloadResponse,
    LoginResponse,
    RoomMessageAudio,
    RoomMessageFile,
    RoomMessageImage,
    RoomMessageText,
    RoomMessageVideo,
)
from nio.client.async_client import client_session as _nio_client_session

from sentinel.channels.base import (
    Channel,
    ChannelDescriptor,
    IncomingMessage,
    OutgoingMessage,
)
from sentinel.core.config import settings
from sentinel.core.context import PrincipalRequiredError
from sentinel.crypto.blind_index import log_hash

logger = logging.getLogger(__name__)

# -- Constants -----------------------------------------------------------------

_RATE_WINDOW_SECONDS = 60.0
# Q11-U1 (cleanup-C49): Matrix /sync long-poll deadline migrated to
# settings.matrix_sync_timeout_ms; consumers below now read it per-call.
# Q11-U1 documented exception: receive-loop poll cadence; yields-control-
# back-to-event-loop idiom (not an external-service deadline) — kept
# literal here and at the wait_for consumer.
_RECEIVE_POLL_SECONDS = 1.0


# -- Q16.fix.d Strategy 3 — Matrix sender redaction helper ---------------------


def _redact_mxid(sender: str) -> dict[str, str | int]:
    """Redact a Matrix user-id (mxid) into log-safe fields.

    Matrix user-ids have shape ``@localpart:homeserver.example`` (federated
    public handles). The homeserver portion is non-PII and signal-bearing
    for federation debugging; the localpart is user-identifying and must
    not be logged raw.

    Returns a dict suitable for splatting into
    ``logger.*(extra={..., **_redact_mxid(sender)})``. Shape parallels
    Strategy 1's ``source_key`` triple — post-pass Q16-U2 consolidation can
    extract the common shape into a shared helper.
    """
    if not sender:
        return {
            "sender_homeserver": "",
            "sender_hash": "",
            "sender_len": 0,
        }
    _, _, homeserver = sender.partition(":")
    return {
        "sender_homeserver": homeserver,
        "sender_hash": log_hash(sender),
        "sender_len": len(sender),
    }


# -- Q12-F2 SSRF hardening -----------------------------------------------------


class _SsrfSafeAsyncClient(AsyncClient):
    """nio AsyncClient subclass forcing allow_redirects=False on every request.

    Q12-F2 (SSRF / MITM redirect containment). nio's send() calls
    aiohttp.ClientSession.request() without allow_redirects, so it defaults
    to True and a malicious or MITM'd homeserver can 3xx-pivot every outbound
    request — including the initial login — to arbitrary hosts.

    This override replicates nio.AsyncClient.send() verbatim and adds
    allow_redirects=False to the underlying aiohttp call. The @client_session
    decorator lazily builds client_session on first call and after close()
    resets it to None, so the override covers request-zero (login) and
    survives close()→rebuild. self.send() is polymorphic — every method that
    routes through _send() hits this override.

    Rollback: SENTINEL_MATRIX_ALLOW_REDIRECTS=true instantiates the vanilla
    AsyncClient instead — see MatrixChannel.start().
    """

    @_nio_client_session
    async def send(
        self,
        method,
        path,
        data=None,
        headers=None,
        trace_context=None,
        timeout=None,
    ) -> "ClientResponse":
        assert self.client_session
        return await self.client_session.request(
            method,
            self.homeserver + path,
            data=data,
            ssl=self.ssl,
            headers=headers,
            trace_request_ctx=trace_context,
            timeout=self.config.request_timeout if timeout is None else timeout,
            allow_redirects=False,
        )


@dataclass
class MatrixConfig:
    """Configuration for MatrixChannel."""

    homeserver_url: str = ""
    user_id: str = ""
    password: str = ""
    store_path: str = ""
    room_id: str = ""  # primary room (conversational)
    alerts_room_id: str = ""  # falls back to room_id
    maintenance_room_id: str = ""  # falls back to room_id
    routines_room_id: str = ""  # falls back to room_id
    allowed_senders: set[str] = field(default_factory=set)
    rate_limit: int = 10
    max_message_length: int = 30000


class MatrixChannel(Channel):
    """Matrix channel with E2EE via matrix-nio.

    Uses nio's AsyncClient with encryption enabled. Maintains a background
    sync loop for E2EE state and message callbacks. Outbound megolm
    session-key sharing is gated on `matrix_ignore_unverified_devices_on_send`
    (default False = fail-closed); see `start()` for the LOUD audit-warning
    behaviour on enable.
    """

    descriptor = ChannelDescriptor(
        name="matrix",
        tool_name="matrix_send",
        tool_description="Send a message via Matrix. Write op — REQUIRES APPROVAL.",
        domain="messaging",
        config_prefix="matrix_",
        keywords=("send on matrix", "matrix message", "message on matrix"),
        preview_label="Matrix",
        needs_recipient=False,  # auto-resolves to primary room
    )

    def __init__(self, config: MatrixConfig, event_bus=None) -> None:
        self._config = config
        self._bus = event_bus
        self._client: AsyncClient | None = None
        self._running = False
        self._sync_task: asyncio.Task | None = None
        self._message_queue: asyncio.Queue[IncomingMessage] = asyncio.Queue()
        self._rate_buckets: dict[str, list[float]] = defaultdict(list)
        self._ingester = None  # set by lifecycle.py after startup

    # -- Public interface (Channel ABC) ----------------------------------------

    async def start(self) -> None:
        """Initialize nio client, login, start background sync."""
        store_path = Path(self._config.store_path)
        store_path.mkdir(parents=True, exist_ok=True)

        client_config = AsyncClientConfig(
            store_sync_tokens=True,
            encryption_enabled=True,
        )
        # Q12-F2: use SSRF-safe subclass that forces allow_redirects=False on
        # every outbound aiohttp request. Rollback: matrix_allow_redirects=True
        # falls back to the vanilla AsyncClient that inherits aiohttp's default
        # allow_redirects=True.
        client_cls = (
            AsyncClient if settings.matrix_allow_redirects else _SsrfSafeAsyncClient
        )
        self._client = client_cls(
            self._config.homeserver_url,
            self._config.user_id,
            store_path=str(store_path),
            config=client_config,
        )

        # Q12-FL3 (cleanup-pass C26): when matrix_allow_redirects=True the
        # Q12-F2 SSRF redirect containment is rolled back to vanilla aiohttp
        # behaviour. Emit a LOUD audit-stream warning so an operator who
        # flipped the setting sees WARNING-grade evidence at startup, mirroring
        # the in-file C40 precedent for matrix_ignore_unverified_devices_on_send.
        if settings.matrix_allow_redirects:
            logger.debug(
                "start: matrix_allow_redirects",
                extra={
                    "event": "channels.matrix_channel.start.match",
                    "reason": "matrix_allow_redirects",
                },
            )  # auto:neg
            logging.getLogger("sentinel.audit").warning(
                "Matrix SSRF redirect containment disabled (rollback) — "
                "outbound aiohttp requests will follow 3xx redirects.",
                extra={
                    "event": "matrix_channel.redirect_policy_allow_enabled",
                    "homeserver": self._config.homeserver_url,
                    **_redact_mxid(self._config.user_id),
                },
            )

        logger.info(
            "Matrix channel connecting",
            extra={
                "event": "matrix_channel.connecting",
                "homeserver": self._config.homeserver_url,
                **_redact_mxid(self._config.user_id),
                "redirect_policy": (
                    "allow" if settings.matrix_allow_redirects else "deny"
                ),
            },
        )

        # Login with password — unique device_id for E2EE key isolation
        response = await asyncio.wait_for(
            self._client.login(self._config.password),
            timeout=settings.channel_send_timeout,
        )
        if not isinstance(response, LoginResponse):
            logger.error(
                "Matrix login failed",
                extra={
                    "event": "matrix_channel.login_failed",
                    "response_type": type(response).__name__,
                },
            )
            raise RuntimeError(f"Matrix login failed: {response}")

        logger.info(
            "Matrix login successful",
            extra={
                "event": "matrix_channel.login_ok",
                "device_id": response.device_id,
            },
        )

        # Initial sync to get room state and device keys
        await asyncio.wait_for(
            self._client.sync(timeout=settings.matrix_sync_timeout_ms, full_state=True),
            timeout=settings.channel_send_timeout
            + (settings.matrix_sync_timeout_ms / 1000),
        )

        # Q12-FL6 (cleanup-pass C40): the only Matrix encryption-posture
        # operator knob is matrix_ignore_unverified_devices_on_send. When
        # True, nio's share_group_session_parallel adds every non-blacklisted
        # device key in the room to the megolm-key recipient list, including
        # unverified ones (olm_machine.py:1683 mark_as_ignored.append branch).
        # This is the ONLY relaxation lever — there is no implicit-trust
        # auto-verify loop. Operators who want full E2EE verification must
        # verify devices out-of-band (Element verification UI etc.).
        #
        # A LOUD audit-stream warning fires on enable so public/shared
        # homeserver misconfigurations are visible to operators who watch
        # the audit stream, not just the app log.
        if settings.matrix_ignore_unverified_devices_on_send:
            logger.debug(
                "start: matrix_ignore_unverified_devices_on_send",
                extra={
                    "event": "channels.matrix_channel.ignore_unverified_on_send.match",
                    "reason": "matrix_ignore_unverified_devices_on_send",
                },
            )  # auto:neg
            logging.getLogger("sentinel.audit").warning(
                "Matrix ignore-unverified-on-send ENABLED — outbound megolm "
                "session keys will be shared with every non-blacklisted "
                "device in the room including unverified ones. This bypasses "
                "recipient device verification. Only safe on private "
                "homeservers; on public/shared servers this leaks plaintext "
                "to unknown devices.",
                extra={
                    "event": "matrix_channel.ignore_unverified_on_send_enabled",
                    "homeserver": self._config.homeserver_url,
                },
            )
        else:
            logger.info(
                "Matrix ignore-unverified-on-send disabled — outbound sends "
                "fail-closed on unverified devices",
                extra={
                    "event": "matrix_channel.ignore_unverified_on_send_disabled",
                    "homeserver": self._config.homeserver_url,
                },
            )

        # Register message callbacks
        self._client.add_event_callback(self._on_room_message, RoomMessageText)
        for event_type in (
            RoomMessageAudio,
            RoomMessageImage,
            RoomMessageVideo,
            RoomMessageFile,
        ):
            self._client.add_event_callback(self._on_room_media, event_type)

        # Start sync_forever in background — infrastructure task, not user-scoped
        self._sync_task = asyncio.create_task(self._sync_loop(), name="matrix-sync")
        self._running = True

        logger.info(
            "Matrix channel started",
            extra={
                "event": "matrix_channel.init",
                "room_count": sum(
                    1
                    for r in [
                        self._config.room_id,
                        self._config.alerts_room_id,
                        self._config.maintenance_room_id,
                        self._config.routines_room_id,
                    ]
                    if r
                ),
                "allowed_senders": len(self._config.allowed_senders),
                "rate_limit": self._config.rate_limit,
            },
        )

    async def stop(self) -> None:
        """Graceful shutdown — cancel sync, close client."""
        self._running = False
        if self._sync_task and not self._sync_task.done():
            self._sync_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._sync_task
        if self._client:
            await self._client.close()
            logger.info(
                "Matrix channel stopped",
                extra={"event": "matrix_channel.stop"},
            )

    async def send(self, message: OutgoingMessage) -> None:
        """Send a message to a Matrix room.

        Resolves room_id from the message (falling back to primary room),
        formats the outgoing payload, splits long messages, and sends each
        chunk as an encrypted m.room.message event.
        """
        if not self._client or not self._running:
            logger.warning(
                "Matrix send skipped — channel not running",
                extra={"event": "matrix_channel.send_skipped"},
            )
            return

        room_id = message.channel_id or self._config.room_id
        text = _format_outgoing(message)
        if not text:
            return

        chunks = _split_message(text, self._config.max_message_length)
        # Q14-F9: abort the remaining chunks on timeout / exception instead of
        # delivering a partial message incoherently. Sibling pattern: Signal
        # and Telegram both set abort=True; break on the same class of error.
        abort = False
        for chunk in chunks:
            if abort:
                break
            try:
                # Q12-FL6 (cleanup-pass C40): ignore_unverified_devices is
                # the only Matrix encryption-posture operator knob. When True,
                # nio's share_group_session_parallel adds every non-blacklisted
                # device in the room to the megolm-key recipient list,
                # including unverified ones (olm_machine.py:1683
                # mark_as_ignored.append branch). Safe on a private homeserver;
                # on public/shared servers this leaks plaintext-to-E2EE-device
                # to unknown devices. A LOUD audit warning fires on enable at
                # startup — see start().
                resp = await asyncio.wait_for(
                    self._client.room_send(
                        room_id=room_id,
                        message_type="m.room.message",
                        content={"msgtype": "m.text", "body": chunk},
                        ignore_unverified_devices=(
                            settings.matrix_ignore_unverified_devices_on_send
                        ),
                    ),
                    timeout=settings.channel_send_timeout,
                )
                if hasattr(resp, "event_id"):
                    logger.debug(
                        "Matrix message sent",
                        extra={
                            "event": "matrix_channel.sent",
                            "room_id": room_id,
                            "event_id": resp.event_id,
                            "length": len(chunk),
                        },
                    )
                else:
                    # Q14-F9 MC Cx-1: RoomSendError (nio protocol-level failure —
                    # rate limit, M_FORBIDDEN, homeserver 5xx) flows through here
                    # per nio's Union[RoomSendResponse, RoomSendError] contract.
                    # Abort the remaining chunks to avoid partial-message
                    # incoherence — same class as the TimeoutError/Exception
                    # branches below.
                    logger.error(
                        "Matrix send failed",
                        extra={
                            "event": "matrix_channel.send_failed",
                            "room_id": room_id,
                            "response_type": type(resp).__name__,
                        },
                    )
                    abort = True
                    break
            except TimeoutError:
                logger.error(
                    "Matrix send timed out",
                    exc_info=True,
                    extra={
                        "event": "matrix_channel.send_timeout",
                        "room_id": room_id,
                    },
                )
                abort = True
                break
            except Exception:
                logger.exception(
                    "Matrix send exception",
                    extra={
                        "event": "matrix_channel.send_error",
                        "room_id": room_id,
                    },
                )
                abort = True
                break

    async def receive(self) -> AsyncIterator[IncomingMessage]:
        """Yield incoming messages from the internal queue."""
        while self._running:
            try:
                msg = await asyncio.wait_for(
                    self._message_queue.get(), timeout=_RECEIVE_POLL_SECONDS
                )
                yield msg
            except TimeoutError:
                continue

    # -- Registry extensions ---------------------------------------------------

    @classmethod
    def from_settings(cls, settings: "Settings") -> "MatrixChannel | None":
        """Build from flat Settings fields. Returns None if disabled."""
        logger.debug(
            "from_settings called",
            extra={
                "event": "matrix_channel.from_settings",
                "settings_len": len(settings) if hasattr(settings, "__len__") else 0,
            },
        )  # auto:entry
        if not settings.matrix_enabled:
            return None
        password = ""
        if settings.matrix_password_file:
            with open(settings.matrix_password_file) as f:
                password = f.read().strip()
        allowed_senders: set[str] = set()
        if settings.matrix_allowed_senders:
            allowed_senders = {
                s.strip()
                for s in settings.matrix_allowed_senders.split(",")
                if s.strip()
            }
        config = MatrixConfig(
            homeserver_url=settings.matrix_homeserver_url,
            user_id=settings.matrix_user_id,
            password=password,
            store_path=settings.matrix_store_path,
            room_id=settings.matrix_room_id,
            alerts_room_id=settings.matrix_alerts_room_id,
            maintenance_room_id=settings.matrix_maintenance_room_id,
            routines_room_id=settings.matrix_routines_room_id,
            allowed_senders=allowed_senders,
            rate_limit=settings.matrix_rate_limit,
            max_message_length=settings.matrix_max_message_length,
        )
        return cls(config)

    async def send_message(self, text: str, recipient: str | None = None) -> dict:
        """High-level send for tool dispatch. Uses primary room."""
        room_id = self.get_room_id("main")
        out = OutgoingMessage(
            channel_id=room_id,
            event_type="tool.matrix_send",
            data={"response": text},
        )
        await self.send(out)
        return {"status": "sent", "channel": "matrix"}

    @property
    def is_running(self) -> bool:
        return self._running

    def get_sender_id(self, message: IncomingMessage) -> str:
        """Matrix sender is in metadata, not channel_id (which is room_id)."""
        return message.metadata.get("sender", "")

    def get_source_key(self, message: IncomingMessage) -> str:
        """Matrix source key binds (sender, room).

        Multiple rooms (main / alerts / maintenance / routines) are
        configured on the same channel, and a message in #alerts carries
        different operational semantics from one in #main. Sender-only
        keying collapses all rooms onto one approval/confirmation
        namespace (Q3-F10). Include room_id from metadata so each
        sender×room pair gets its own session binding. Falls back to
        channel_id (room.room_id at IncomingMessage construction) if
        metadata is unpopulated.
        """
        sender = self.get_sender_id(message)
        room_id = message.metadata.get("room_id", message.channel_id)
        return f"matrix:{sender}:{room_id}"

    # -- Room routing ----------------------------------------------------------

    def get_room_id(self, category: str = "main") -> str:
        """Resolve a room ID by category, falling back to the primary room."""
        if category == "alerts" and self._config.alerts_room_id:
            return self._config.alerts_room_id
        if category == "maintenance" and self._config.maintenance_room_id:
            return self._config.maintenance_room_id
        if category == "routines" and self._config.routines_room_id:
            return self._config.routines_room_id
        return self._config.room_id

    # -- Internal: sync loop ---------------------------------------------------

    async def _sync_loop(self) -> None:
        """Run sync_forever with reconnect-backoff to maintain E2EE state.

        Q14-F1: on transient sync failure (network blip, homeserver
        bounce) the channel reconnects with exponential backoff (1s, 2s,
        4s, ... capped at 300s) instead of dying permanently. Pattern
        mirrors SignalChannel._read_loop / _health_monitor. `_running`
        stays True across transient failures; only explicit shutdown
        (`stop()` → `CancelledError`) exits the loop. Q14-U1 tracks a
        shared-helper extraction across channels.
        """
        # Exponential backoff state — reset after each successful return
        base_delay = 1.0
        max_delay = 300.0
        attempt = 0
        while self._running:
            try:
                await self._client.sync_forever(timeout=settings.matrix_sync_timeout_ms)
                # sync_forever returned cleanly (logout / server close) —
                # reset backoff and loop to reconnect.
                attempt = 0
            except asyncio.CancelledError:
                # Q11-F8 (peer-consulted 2026-04-24 post-Q14.fix.a restructure):
                # propagate CancelledError so the parent's `await self._sync_task`
                # observes cancelled() is True. A prior `break` exited the
                # retry loop normally and the parent saw a completed task,
                # erasing the "cancelled during shutdown" signal. stop() at
                # :313-317 uses contextlib.suppress(CancelledError), so the
                # propagation is absorbed at the parent without affecting
                # shutdown sequencing.
                logger.debug(
                    "Matrix sync loop cancelled",
                    extra={"event": "matrix_channel.sync_cancelled"},
                )
                raise
            except Exception:
                delay = min(base_delay * (2**attempt), max_delay)
                attempt += 1
                logger.exception(
                    "Matrix sync loop crashed — reconnecting with backoff",
                    extra={
                        "event": "matrix_channel.sync_reconnect",
                        "backoff_delay": delay,
                        "attempt": attempt,
                    },
                )
                try:
                    await asyncio.sleep(delay)
                except asyncio.CancelledError:
                    # Q11-F8 second swallow site: cancellation arriving during
                    # backoff sleep. Same propagation rule as the outer handler.
                    raise

    # -- Internal: message callbacks -------------------------------------------

    async def _on_room_message(self, room, event) -> None:
        """Handle incoming text messages.

        Filters out our own messages, checks the sender allowlist, applies
        rate limiting, then queues an IncomingMessage for receive().
        """
        sender = event.sender
        # Ignore our own messages
        if sender == self._config.user_id:
            return
        # Allowlist check
        if not self._is_allowed(sender):
            logger.warning(
                "Matrix message rejected — sender not in allowlist",
                extra={
                    "event": "matrix_channel.sender_rejected",
                    **_redact_mxid(sender),
                    "room_id": room.room_id,
                },
            )
            return
        logger.debug(
            "_on_room_message: not_is_allowed_sender_passed",
            extra={
                "event": "matrix_channel.sender_rejected.passed",
                "reason": "not_is_allowed_sender_passed",
            },
        )  # auto:neg
        # Rate limit check
        if self._is_rate_limited(sender):
            logger.warning(
                "Matrix message rejected — rate limited",
                extra={
                    "event": "matrix_channel.rate_limited",
                    **_redact_mxid(sender),
                },
            )
            return

        self._rate_buckets[sender].append(time.monotonic())

        msg = IncomingMessage(
            channel_id=room.room_id,
            source="matrix",
            content=event.body,
            metadata={
                "room_id": room.room_id,
                "event_id": event.event_id,
                "sender": sender,
            },
        )
        await self._message_queue.put(msg)

        logger.info(
            "Matrix text message received",
            extra={
                "event": "matrix_channel.message_received",
                "room_id": room.room_id,
                **_redact_mxid(sender),
                "length": len(event.body),
            },
        )

    async def _on_room_media(self, room, event) -> None:
        """Handle incoming media messages (images, audio, video, files).

        Determines media type from the event class, builds attachment metadata,
        and queues an IncomingMessage with the attachment for downstream ingestion.
        """
        sender = event.sender
        # Ignore our own messages
        if sender == self._config.user_id:
            return
        if not self._is_allowed(sender):
            logger.warning(
                "Matrix media rejected — sender not in allowlist",
                extra={
                    "event": "matrix_channel.sender_rejected",
                    **_redact_mxid(sender),
                    "room_id": room.room_id,
                },
            )
            return
        logger.debug(
            "_on_room_media: not_is_allowed_sender_passed",
            extra={
                "event": "matrix_channel.sender_rejected.passed",
                "reason": "not_is_allowed_sender_passed",
            },
        )  # auto:neg
        if self._is_rate_limited(sender):
            logger.warning(
                "Matrix media rejected — rate limited",
                extra={
                    "event": "matrix_channel.rate_limited",
                    **_redact_mxid(sender),
                },
            )
            return

        self._rate_buckets[sender].append(time.monotonic())

        # Determine media type from event class name
        event_class = type(event).__name__.lower()
        if "audio" in event_class:
            media_type = "audio"
        elif "image" in event_class:
            media_type = "image"
        elif "video" in event_class:
            media_type = "video"
        else:
            media_type = "file"

        mime_type = getattr(event, "mimetype", None) or ""
        file_name = getattr(event, "body", "attachment")
        file_size = getattr(event, "size", 0) or 0
        mxc_url = getattr(event, "url", "") or ""

        body = getattr(event, "body", "") or f"[{media_type} attachment]"

        # Download and ingest media if ingester is available
        attachment_metas: list[dict] = []
        if mxc_url and self._ingester is not None:
            try:
                response = await asyncio.wait_for(
                    self._client.download(mxc_url),
                    timeout=settings.channel_send_timeout,
                )
                if isinstance(response, DownloadResponse):
                    meta = await self._ingester.ingest(
                        data=response.body,
                        mime_type=mime_type,
                        original_filename=file_name,
                        source_channel="matrix",
                        channel_file_id=mxc_url,
                        extra={"media_type": media_type},
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
                        "Matrix media attachment ingested",
                        extra={
                            "event": "matrix_channel.media_ingested",
                            "room_id": room.room_id,
                            **_redact_mxid(sender),
                            "media_type": media_type,
                            "attachment_id": meta.attachment_id,
                            "file_size": meta.file_size,
                        },
                    )
                else:
                    logger.warning(
                        "Matrix media download failed",
                        extra={
                            "event": "matrix_channel.media_download_failed",
                            "room_id": room.room_id,
                            "mxc_url_length": len(mxc_url),
                            "response_type": type(response).__name__,
                        },
                    )
            except PrincipalRequiredError:
                # Q4.fix.c: zero-principal from MediaStore.save indicates
                # missing upstream binding (Q4.fix.d scope). Matrix sync
                # loop runs as channel-level infrastructure without a user
                # context; let the failure propagate loudly rather than be
                # mis-logged as matrix_channel.media_ingest_failed.
                raise
            except Exception:  # catch-all: media ingestion must not block messages
                # Ingestion failure should not block message processing —
                # queue the text content and log the error for debugging
                logger.warning(
                    "Matrix media ingestion failed — queuing text only",
                    exc_info=True,
                    extra={
                        "event": "matrix_channel.media_ingest_failed",
                        "room_id": room.room_id,
                        "media_type": media_type,
                    },
                )
        elif mxc_url and self._ingester is None:
            # No ingester — include raw metadata so downstream knows media exists
            logger.debug(
                "_on_room_media: mxc_url",
                extra={
                    "event": "matrix_channel.media_ingested.clean",
                    "reason": "mxc_url",
                },
            )  # auto:neg
            attachment_metas.append(
                {
                    "media_type": media_type,
                    "mime_type": mime_type,
                    "file_name": file_name,
                    "file_size": file_size,
                    "mxc_url": mxc_url,
                    "source": "matrix",
                }
            )

        msg = IncomingMessage(
            channel_id=room.room_id,
            source="matrix",
            content=body,
            metadata={
                "room_id": room.room_id,
                "event_id": event.event_id,
                "sender": sender,
            },
            attachments=attachment_metas,
        )
        await self._message_queue.put(msg)

        logger.info(
            "Matrix media message received",
            extra={
                "event": "matrix_channel.media_received",
                "room_id": room.room_id,
                **_redact_mxid(sender),
                "media_type": media_type,
            },
        )

    # -- Internal: access control ----------------------------------------------

    def _is_allowed(self, sender: str) -> bool:
        """Check if sender is in the allowlist.

        Q13-F8: empty allowlist = deny-all (fail-closed). Aligns with Signal's
        existing empty-set-drops semantics and reverses the prior Matrix
        behaviour where an empty list meant "allow everyone". Operators who
        want the old open behaviour must list explicit Matrix user IDs.
        """
        return sender in self._config.allowed_senders

    def _is_rate_limited(self, sender: str) -> bool:
        """Sliding window rate limit per sender."""
        logger.debug(
            "_is_rate_limited called",
            extra={
                "event": "matrix_channel._is_rate_limited",
                **_redact_mxid(sender),
            },
        )  # auto:entry
        now = time.monotonic()
        cutoff = now - _RATE_WINDOW_SECONDS
        bucket = self._rate_buckets[sender]
        # Prune expired entries
        self._rate_buckets[sender] = [t for t in bucket if t > cutoff]
        return len(self._rate_buckets[sender]) >= self._config.rate_limit


# -- Formatting helpers (module-level) -----------------------------------------


def _format_outgoing(message: OutgoingMessage) -> str:
    """Extract readable text from an OutgoingMessage payload.

    Checks standard data dict keys in priority order: response, result,
    text, message, preview. Falls back to JSON serialisation of the whole
    data dict if none match.
    """
    logger.debug(
        "_format_outgoing called",
        extra={
            "event": "matrix_channel._format_outgoing",
            "message_len": len(message) if hasattr(message, "__len__") else 0,
        },
    )  # auto:entry
    data = message.data
    for key in ("response", "result", "text", "message"):
        if data.get(key):
            return str(data[key])
    if "preview" in data:
        return str(data["preview"])
    # Plan approval request — render description-only (parity with Signal/
    # Telegram). Raw step internals (tool/args/prompt) stay off the room;
    # full detail lives only in the authenticated web UI.
    if "approval_id" in data and "plan_summary" in data:
        summary = data["plan_summary"]
        steps = data.get("steps", [])
        step_lines = "\n".join(
            f"  - {s.get('description', s.get('type', ''))}" for s in steps
        )
        return f"Plan: {summary}\n{step_lines}\n\nReply 'go' to approve."
    if data:
        import json

        return json.dumps(data, indent=2, default=str)
    return ""


def _split_message(text: str, max_length: int) -> list[str]:
    """Split text into chunks respecting max_length.

    Tries paragraph boundaries first, then sentence boundaries, then
    hard-splits at max_length as a last resort.
    """
    logger.debug(
        "_split_message called",
        extra={
            "event": "matrix_channel._split_message",
            "text_len": len(text) if hasattr(text, "__len__") else 0,
            "max_length": max_length,
        },
    )  # auto:entry
    if len(text) <= max_length:
        return [text]

    chunks: list[str] = []
    remaining = text
    while remaining:
        if len(remaining) <= max_length:
            chunks.append(remaining)
            break
        # Try paragraph break
        split_pos = remaining.rfind("\n\n", 0, max_length)
        if split_pos > max_length // 2:
            chunks.append(remaining[:split_pos])
            remaining = remaining[split_pos + 2 :]
            continue
        # Try sentence break
        split_pos = remaining.rfind(". ", 0, max_length)
        if split_pos > max_length // 2:
            chunks.append(remaining[: split_pos + 1])
            remaining = remaining[split_pos + 2 :]
            continue
        # Hard split at max_length
        chunks.append(remaining[:max_length])
        remaining = remaining[max_length:]
    return chunks
