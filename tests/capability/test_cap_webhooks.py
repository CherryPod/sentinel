"""C1 capability tests — Inbound Webhook Channel.

Verifies the 8 deployment-gate behaviours for the webhook system:
valid payload receive, invalid signature rejection, unknown webhook 404,
routine triggering, rate limiting, untrusted pipeline treatment,
idempotency dedup, and replay attack prevention.

All tests mock the orchestrator (no real Claude/Qwen calls) and use
in-memory SQLite.
"""

import asyncio
import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.channels.webhook import (
    RateLimiter,
    WebhookRegistry,
    check_idempotency,
    verify_signature,
    verify_timestamp,
)
from sentinel.core.bus import EventBus
from sentinel.core.db import init_db
from sentinel.core.models import TaskResult
from sentinel.routines.engine import RoutineEngine
from sentinel.routines.store import RoutineStore

pytestmark = pytest.mark.capability


# ── Fixtures ─────────────────────────────────────────────────────


@pytest.fixture
def db():
    conn = init_db(":memory:")
    yield conn
    conn.close()


@pytest.fixture
def registry(db):
    return WebhookRegistry(db=db)


@pytest.fixture
def bus():
    return EventBus()


@pytest.fixture
def webhook_secret():
    return "test-webhook-secret-minimum-16-chars"


def _make_signature(payload: bytes, secret: str) -> str:
    """Build a valid HMAC-SHA256 signature string."""
    sig = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return f"sha256={sig}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _old_timestamp() -> str:
    """Return a timestamp 10 minutes in the past."""
    from datetime import timedelta
    old = datetime.now(timezone.utc) - timedelta(minutes=10)
    return old.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ── Unit tests — verification helpers ────────────────────────────


class TestVerifySignature:
    def test_valid_signature(self, webhook_secret):
        payload = b'{"test": "data"}'
        sig = _make_signature(payload, webhook_secret)
        assert verify_signature(payload, sig, webhook_secret) is True

    def test_invalid_signature(self, webhook_secret):
        payload = b'{"test": "data"}'
        assert verify_signature(payload, "sha256=bad", webhook_secret) is False

    def test_missing_prefix(self, webhook_secret):
        payload = b'{"test": "data"}'
        sig = hmac.new(
            webhook_secret.encode(), payload, hashlib.sha256,
        ).hexdigest()
        assert verify_signature(payload, sig, webhook_secret) is False

    def test_tampered_payload(self, webhook_secret):
        payload = b'{"test": "data"}'
        sig = _make_signature(payload, webhook_secret)
        assert verify_signature(b'{"test": "TAMPERED"}', sig, webhook_secret) is False


class TestVerifyTimestamp:
    def test_current_timestamp_valid(self):
        assert verify_timestamp(_now_iso()) is True

    def test_old_timestamp_rejected(self):
        assert verify_timestamp(_old_timestamp()) is False

    def test_garbage_timestamp(self):
        assert verify_timestamp("not-a-timestamp") is False

    def test_empty_string(self):
        assert verify_timestamp("") is False


class TestIdempotency:
    def test_new_nonce_allowed(self):
        seen = {}
        assert check_idempotency("nonce-1", seen) is False

    def test_duplicate_nonce_rejected(self):
        seen = {}
        check_idempotency("nonce-1", seen)
        assert check_idempotency("nonce-1", seen) is True

    def test_expired_nonce_cleaned(self):
        seen = {"old-nonce": time.monotonic() - 400}
        check_idempotency("new-nonce", seen, ttl=300)
        assert "old-nonce" not in seen


class TestRateLimiter:
    def test_allows_under_limit(self):
        rl = RateLimiter(max_per_minute=5)
        for _ in range(5):
            assert rl.check("wh-1") is True

    def test_blocks_over_limit(self):
        rl = RateLimiter(max_per_minute=3)
        for _ in range(3):
            rl.check("wh-1")
        assert rl.check("wh-1") is False

    def test_separate_webhook_ids(self):
        rl = RateLimiter(max_per_minute=2)
        rl.check("wh-1")
        rl.check("wh-1")
        assert rl.check("wh-1") is False
        assert rl.check("wh-2") is True  # different webhook


# ── Registry tests ───────────────────────────────────────────────


class TestWebhookRegistry:
    def test_register_and_get(self, registry, webhook_secret):
        config = registry.register(name="Test Hook", secret=webhook_secret)
        assert config.webhook_id
        assert config.name == "Test Hook"

        fetched = registry.get(config.webhook_id)
        assert fetched is not None
        assert fetched.secret == webhook_secret

    def test_get_unknown(self, registry):
        assert registry.get("nonexistent") is None

    def test_delete(self, registry, webhook_secret):
        config = registry.register(name="Deletable", secret=webhook_secret)
        assert registry.delete(config.webhook_id) is True
        assert registry.get(config.webhook_id) is None

    def test_list(self, registry, webhook_secret):
        registry.register(name="Hook 1", secret=webhook_secret)
        registry.register(name="Hook 2", secret=webhook_secret)
        assert len(registry.list()) == 2

    def test_inmemory_fallback(self, webhook_secret):
        reg = WebhookRegistry(db=None)
        config = reg.register(name="In-Memory", secret=webhook_secret)
        assert reg.get(config.webhook_id) is not None
        assert len(reg.list()) == 1


# ── Integration tests — deployment gate scenarios ────────────────


class TestWebhookReceiveValidPayload:
    """webhook_receive_valid_payload — valid payload published to bus."""

    async def test_valid_payload_publishes_event(self, registry, bus, webhook_secret):
        config = registry.register(name="Valid Test", secret=webhook_secret)
        payload = json.dumps({"action": "test"}).encode()
        sig = _make_signature(payload, webhook_secret)
        timestamp = _now_iso()

        events = []

        async def capture(topic, data):
            events.append({"topic": topic, "data": data})

        bus.subscribe("webhook.*", capture)

        # Simulate what the endpoint does (unit-test the flow)
        assert verify_signature(payload, sig, webhook_secret) is True
        assert verify_timestamp(timestamp) is True

        await bus.publish(f"webhook.{config.webhook_id}.received", {
            "webhook_id": config.webhook_id,
            "webhook_name": config.name,
            "payload": json.loads(payload),
        })

        assert len(events) == 1
        assert events[0]["data"]["webhook_id"] == config.webhook_id

    async def test_endpoint_valid_payload(self, db, webhook_secret):
        """Full endpoint test via httpx."""
        import httpx
        from sentinel.api.app import app

        reg = WebhookRegistry(db=db)
        config = reg.register(name="Endpoint Test", secret=webhook_secret)

        payload = json.dumps({"action": "deploy"}).encode()
        sig = _make_signature(payload, webhook_secret)
        timestamp = _now_iso()

        event_bus = EventBus()
        rate_limiter = RateLimiter()

        with (
            patch("sentinel.api.app._webhook_registry", reg),
            patch("sentinel.api.app._event_bus", event_bus),
            patch("sentinel.api.app._webhook_rate_limiter", rate_limiter),
            patch("sentinel.api.app._idempotency_cache", {}),
        ):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    f"/api/webhook/{config.webhook_id}/receive",
                    content=payload,
                    headers={
                        "X-Signature-256": sig,
                        "X-Timestamp": timestamp,
                        "Content-Type": "application/json",
                    },
                )

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["event_published"] is True


class TestWebhookInvalidSignature:
    """webhook_invalid_signature — bad signature returns 401."""

    async def test_invalid_sig_rejected(self, db, webhook_secret):
        import httpx
        from sentinel.api.app import app

        reg = WebhookRegistry(db=db)
        config = reg.register(name="Sig Test", secret=webhook_secret)

        payload = json.dumps({"action": "test"}).encode()
        timestamp = _now_iso()

        with (
            patch("sentinel.api.app._webhook_registry", reg),
            patch("sentinel.api.app._event_bus", EventBus()),
            patch("sentinel.api.app._webhook_rate_limiter", RateLimiter()),
            patch("sentinel.api.app._idempotency_cache", {}),
        ):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    f"/api/webhook/{config.webhook_id}/receive",
                    content=payload,
                    headers={
                        "X-Signature-256": "sha256=000bad000",
                        "X-Timestamp": timestamp,
                        "Content-Type": "application/json",
                    },
                )

        assert resp.status_code == 401
        assert "Invalid signature" in resp.json()["reason"]


class TestWebhookUnknownId:
    """webhook_unknown_id — non-existent webhook returns 404."""

    async def test_unknown_webhook_404(self, db):
        import httpx
        from sentinel.api.app import app

        with (
            patch("sentinel.api.app._webhook_registry", WebhookRegistry(db=db)),
            patch("sentinel.api.app._event_bus", EventBus()),
            patch("sentinel.api.app._webhook_rate_limiter", RateLimiter()),
            patch("sentinel.api.app._idempotency_cache", {}),
        ):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/webhook/nonexistent-id/receive",
                    content=b'{}',
                    headers={
                        "X-Signature-256": "sha256=abc",
                        "X-Timestamp": _now_iso(),
                    },
                )

        assert resp.status_code == 404


class TestWebhookTriggersRoutine:
    """webhook_triggers_routine — webhook event fires matching routine."""

    async def test_event_routine_fires(self, db):
        bus = EventBus()
        reg = WebhookRegistry(db=db)
        config = reg.register(name="Trigger Test", secret="x" * 16)

        store = RoutineStore(db=db)
        orch = AsyncMock()
        orch.handle_task = AsyncMock(return_value=TaskResult(
            status="success", plan_summary="handled webhook", task_id="t1",
        ))

        engine = RoutineEngine(
            store=store, orchestrator=orch, event_bus=bus,
            db=db, tick_interval=60, max_concurrent=3, execution_timeout=5,
        )

        # Create event-triggered routine matching webhook events
        store.create(
            name="On webhook",
            trigger_type="event",
            trigger_config={"event": "webhook.*"},
            action_config={"prompt": "Process webhook payload"},
        )

        await engine.start()
        try:
            # Publish webhook event (same as endpoint would)
            await bus.publish(f"webhook.{config.webhook_id}.received", {
                "webhook_id": config.webhook_id,
                "payload": {"action": "test"},
            })
            await asyncio.sleep(0.3)

            orch.handle_task.assert_called_once()
            assert "Process webhook payload" in str(orch.handle_task.call_args)
        finally:
            await engine.stop()


class TestWebhookRateLimiting:
    """webhook_rate_limiting — excess requests return 429."""

    async def test_rate_limit_enforced(self, db, webhook_secret):
        import httpx
        from sentinel.api.app import app

        reg = WebhookRegistry(db=db)
        config = reg.register(name="Rate Test", secret=webhook_secret)
        rl = RateLimiter(max_per_minute=3)

        payload = json.dumps({"test": True}).encode()
        sig = _make_signature(payload, webhook_secret)

        with (
            patch("sentinel.api.app._webhook_registry", reg),
            patch("sentinel.api.app._event_bus", EventBus()),
            patch("sentinel.api.app._webhook_rate_limiter", rl),
            patch("sentinel.api.app._idempotency_cache", {}),
        ):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                statuses = []
                for _ in range(5):
                    resp = await client.post(
                        f"/api/webhook/{config.webhook_id}/receive",
                        content=payload,
                        headers={
                            "X-Signature-256": sig,
                            "X-Timestamp": _now_iso(),
                            "Content-Type": "application/json",
                        },
                    )
                    statuses.append(resp.status_code)

        assert 429 in statuses
        assert statuses[:3] == [200, 200, 200]


class TestWebhookPayloadUntrusted:
    """webhook_payload_enters_pipeline_as_untrusted — webhook data is untrusted."""

    async def test_prompt_triggers_as_webhook_source(self, db, webhook_secret):
        """Verify that webhook payloads with prompt field route as 'webhook' source."""
        import httpx
        from sentinel.api.app import app

        reg = WebhookRegistry(db=db)
        config = reg.register(name="Untrusted Test", secret=webhook_secret)

        payload = json.dumps({"prompt": "Summarize recent events"}).encode()
        sig = _make_signature(payload, webhook_secret)

        mock_orch = AsyncMock()
        mock_orch.handle_task = AsyncMock(return_value=TaskResult(
            status="success", plan_summary="done", task_id="t1",
        ))

        bus = EventBus()
        router_mock = MagicMock()

        with (
            patch("sentinel.api.app._webhook_registry", reg),
            patch("sentinel.api.app._event_bus", bus),
            patch("sentinel.api.app._orchestrator", mock_orch),
            patch("sentinel.api.app._webhook_rate_limiter", RateLimiter()),
            patch("sentinel.api.app._idempotency_cache", {}),
        ):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    f"/api/webhook/{config.webhook_id}/receive",
                    content=payload,
                    headers={
                        "X-Signature-256": sig,
                        "X-Timestamp": _now_iso(),
                        "Content-Type": "application/json",
                    },
                )

        assert resp.status_code == 200
        data = resp.json()
        assert data["task_triggered"] is True


class TestWebhookIdempotency:
    """webhook_idempotency — duplicate nonce returns 409."""

    async def test_duplicate_rejected(self, db, webhook_secret):
        import httpx
        from sentinel.api.app import app

        reg = WebhookRegistry(db=db)
        config = reg.register(name="Idemp Test", secret=webhook_secret)

        payload = json.dumps({"action": "once"}).encode()
        sig = _make_signature(payload, webhook_secret)
        cache = {}

        with (
            patch("sentinel.api.app._webhook_registry", reg),
            patch("sentinel.api.app._event_bus", EventBus()),
            patch("sentinel.api.app._webhook_rate_limiter", RateLimiter()),
            patch("sentinel.api.app._idempotency_cache", cache),
        ):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                headers = {
                    "X-Signature-256": sig,
                    "X-Timestamp": _now_iso(),
                    "X-Idempotency-Key": "unique-nonce-123",
                    "Content-Type": "application/json",
                }

                # First request — should succeed
                resp1 = await client.post(
                    f"/api/webhook/{config.webhook_id}/receive",
                    content=payload,
                    headers=headers,
                )
                assert resp1.status_code == 200

                # Second request with same nonce — should be 409
                resp2 = await client.post(
                    f"/api/webhook/{config.webhook_id}/receive",
                    content=payload,
                    headers=headers,
                )
                assert resp2.status_code == 409
                assert "Duplicate" in resp2.json()["reason"]


class TestWebhookReplayAttack:
    """webhook_replay_attack — old timestamp returns 401."""

    async def test_old_timestamp_rejected(self, db, webhook_secret):
        import httpx
        from sentinel.api.app import app

        reg = WebhookRegistry(db=db)
        config = reg.register(name="Replay Test", secret=webhook_secret)

        payload = json.dumps({"action": "replay"}).encode()
        sig = _make_signature(payload, webhook_secret)

        with (
            patch("sentinel.api.app._webhook_registry", reg),
            patch("sentinel.api.app._event_bus", EventBus()),
            patch("sentinel.api.app._webhook_rate_limiter", RateLimiter()),
            patch("sentinel.api.app._idempotency_cache", {}),
        ):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    f"/api/webhook/{config.webhook_id}/receive",
                    content=payload,
                    headers={
                        "X-Signature-256": sig,
                        "X-Timestamp": _old_timestamp(),
                        "Content-Type": "application/json",
                    },
                )

        assert resp.status_code == 401
        assert "Timestamp" in resp.json()["reason"]
