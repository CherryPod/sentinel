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
from dataclasses import dataclass, field

from sentinel.channels.base import Channel, IncomingMessage, OutgoingMessage
from sentinel.core.config import settings

logger = logging.getLogger("sentinel.audit")


@dataclass
class TelegramConfig:
    bot_token: str = ""
    allowed_chat_ids: set[int] = field(default_factory=set)
    rate_limit: int = 10            # messages/min per chat
    max_message_length: int = 4096  # Telegram's limit
    polling_timeout: int = 30


class TelegramChannel(Channel):
    """Telegram bot channel using long-polling."""

    channel_type = "telegram"

    def __init__(self, config: TelegramConfig, event_bus=None):
        self._config = config
        self._bus = event_bus
        self._app = None
        self._running = False
        self._message_queue: asyncio.Queue[IncomingMessage] = asyncio.Queue()
        # Rate limiting: chat_id -> list of timestamps
        self._rate_buckets: dict[int, list[float]] = defaultdict(list)

    async def start(self) -> None:
        from telegram.ext import ApplicationBuilder, MessageHandler, filters

        self._app = (
            ApplicationBuilder()
            .token(self._config.bot_token)
            .build()
        )
        await self._app.initialize()
        await self._app.start()

        # Register handler for text messages
        handler = MessageHandler(
            filters.TEXT & ~filters.COMMAND,
            self._handle_update,
        )
        self._app.add_handler(handler)
        self._running = True

        logger.info(
            "Telegram channel started",
            extra={
                "event": "telegram_channel_init",
                "allowed_chats": len(self._config.allowed_chat_ids),
                "rate_limit": self._config.rate_limit,
            },
        )

    async def stop(self) -> None:
        self._running = False
        if self._app is not None:
            try:
                if self._app.updater and self._app.updater.running:
                    await self._app.updater.stop()
                await self._app.stop()
                await self._app.shutdown()
            except Exception:
                pass
        logger.info("Telegram channel stopped", extra={"event": "telegram_channel_stop"})

    async def send(self, message: OutgoingMessage) -> None:
        if self._app is None:
            return
        try:
            chat_id = int(message.channel_id)
        except (ValueError, TypeError):
            logger.error(
                "Telegram send failed — invalid chat_id",
                extra={
                    "event": "telegram_invalid_chat_id",
                    "chat_id": message.channel_id,
                },
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
                except asyncio.TimeoutError:
                    logger.warning(
                        "Telegram send timed out",
                        extra={"event": "telegram_send_timeout", "chat_id": chat_id},
                    )
                    abort = True
                    break  # timeouts are not retryable — also stop remaining chunks
                except Exception as exc:
                    if attempt < 1:
                        logger.warning(
                            "Telegram send failed, retrying",
                            extra={
                                "event": "telegram_send_retry",
                                "chat_id": chat_id,
                                "attempt": attempt + 1,
                                "error": str(exc),
                            },
                        )
                        await asyncio.sleep(2 ** attempt)
                    else:
                        logger.error(
                            "Telegram send failed after retry",
                            extra={
                                "event": "telegram_send_failed",
                                "chat_id": chat_id,
                                "chunk": i + 1,
                                "total_chunks": len(chunks),
                                "error": str(exc),
                            },
                        )
                        abort = True

    async def receive(self):
        """Yield incoming messages. Must be consumed in an async for loop."""
        while self._running:
            try:
                msg = await asyncio.wait_for(
                    self._message_queue.get(), timeout=1.0
                )
                yield msg
            except asyncio.TimeoutError:
                continue

    def _is_allowed(self, chat_id: int) -> bool:
        if not self._config.allowed_chat_ids:
            return True  # empty = allow all
        return chat_id in self._config.allowed_chat_ids

    def _check_rate_limit(self, chat_id: int) -> bool:
        now = time.monotonic()
        bucket = self._rate_buckets[chat_id]
        # Prune old entries (older than 60s)
        self._rate_buckets[chat_id] = [t for t in bucket if now - t < 60]
        if len(self._rate_buckets[chat_id]) >= self._config.rate_limit:
            return False
        self._rate_buckets[chat_id].append(now)
        return True

    async def _handle_update(self, update, context) -> None:
        """Called by python-telegram-bot for each incoming message."""
        message = update.message
        if message is None or message.text is None:
            return

        chat_id = message.chat_id
        if not self._is_allowed(chat_id):
            logger.warning(
                "Telegram message from disallowed chat",
                extra={"event": "telegram_disallowed", "chat_id": chat_id},
            )
            return

        if not self._check_rate_limit(chat_id):
            logger.warning(
                "Telegram rate limit exceeded",
                extra={"event": "telegram_rate_limited", "chat_id": chat_id},
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
            except asyncio.TimeoutError:
                logger.warning(
                    "Telegram rate-limit response timed out",
                    extra={"event": "telegram_ratelimit_send_timeout", "chat_id": chat_id},
                )
            return

        # Only include channel routing metadata — strip PII fields
        # (username, first_name, last_name) so they never reach the
        # orchestrator or planner. chat_id is needed for reply routing.
        incoming = IncomingMessage(
            channel_id=str(chat_id),
            source="telegram",
            content=message.text,
            metadata={
                "chat_id": chat_id,
            },
        )
        await self._message_queue.put(incoming)

    @staticmethod
    def _format_outgoing(message: OutgoingMessage) -> str:
        """Format an OutgoingMessage as plain text for Telegram."""
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
            step_lines = "\n".join(f"  - {s.get('description', s.get('type', ''))}" for s in steps)
            return f"Plan: {summary}\n{step_lines}\n\nReply 'go' to approve."

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
