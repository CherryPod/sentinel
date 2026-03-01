"""B1: HTTP Tool Capability Tests.

Verifies http_fetch dispatches through sidecar with correct UNTRUSTED trust
tagging, allowlist passthrough, error handling for SSRF/timeout/size, and
credential/leak detection. All tests use mocked sidecar — no real HTTP calls.

11 tests total, covering the full B1 deployment checklist.
"""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel.core.models import DataSource, PolicyResult, TaggedData, TrustLevel, ValidationResult
from sentinel.security.provenance import create_tagged_data, get_tagged_data, is_trust_safe_for_execution
from sentinel.tools.executor import (
    _EXTERNAL_DATA_TOOLS,
    ToolError,
    ToolExecutor,
)
from sentinel.tools.sidecar import SidecarClient, SidecarResponse


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_sidecar(**execute_kwargs) -> AsyncMock:
    """Create a mock SidecarClient with a pre-configured execute response."""
    sidecar = AsyncMock(spec=SidecarClient)
    sidecar.execute = AsyncMock(
        return_value=SidecarResponse(**execute_kwargs),
    )
    sidecar.is_running = True
    return sidecar


def _mock_engine(policy: dict | None = None) -> MagicMock:
    """PolicyEngine that allows everything, with optional policy dict."""
    engine = MagicMock()
    allowed = ValidationResult(status=PolicyResult.ALLOWED, path="")
    engine.check_file_read.return_value = allowed
    engine.check_file_write.return_value = allowed
    engine.check_command.return_value = allowed
    engine._policy = policy or {
        "network": {
            "http_tool_allowed_domains": [
                "api.search.brave.com",
                "*.googleapis.com",
            ],
        },
    }
    return engine


# ---------------------------------------------------------------------------
# Test 1: HTTP GET success — returns TaggedData with WEB + UNTRUSTED
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_http_get_success():
    """GET returns TaggedData with source=WEB, trust_level=UNTRUSTED."""
    sidecar = _mock_sidecar(
        success=True,
        result="ok",
        data={"status": 200, "body": "<html>Hello</html>", "headers": {}},
    )
    executor = ToolExecutor(policy_engine=_mock_engine(), sidecar=sidecar)

    result = await executor.execute("http_fetch", {
        "url": "https://api.search.brave.com/res/v1/web/search?q=test",
        "method": "GET",
    })

    assert isinstance(result, TaggedData)
    assert result.source == DataSource.WEB
    assert result.trust_level == TrustLevel.UNTRUSTED
    assert "sidecar:http_fetch" in result.originated_from


# ---------------------------------------------------------------------------
# Test 2: HTTP POST with body — passes body to sidecar, same trust tagging
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_http_post_with_body():
    """POST passes body to sidecar, result is WEB + UNTRUSTED."""
    sidecar = _mock_sidecar(
        success=True,
        result="ok",
        data={"status": 200, "body": '{"result": "created"}', "headers": {}},
    )
    executor = ToolExecutor(policy_engine=_mock_engine(), sidecar=sidecar)

    result = await executor.execute("http_fetch", {
        "url": "https://api.search.brave.com/endpoint",
        "method": "POST",
        "body": '{"query": "test"}',
    })

    # Verify body was passed through to sidecar
    call_args = sidecar.execute.call_args
    assert call_args.kwargs["args"]["body"] == '{"query": "test"}'
    assert call_args.kwargs["args"]["method"] == "POST"

    assert result.source == DataSource.WEB
    assert result.trust_level == TrustLevel.UNTRUSTED


# ---------------------------------------------------------------------------
# Test 3: HTTP rejects plain HTTP — sidecar returns error -> ToolError
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_http_rejects_plain_http():
    """URL starting with http:// -> sidecar returns error -> ToolError."""
    sidecar = _mock_sidecar(
        success=False,
        result="HTTPS required: http:// URLs are not allowed",
    )
    executor = ToolExecutor(policy_engine=_mock_engine(), sidecar=sidecar)

    with pytest.raises(ToolError, match="HTTPS required"):
        await executor.execute("http_fetch", {
            "url": "http://example.com/insecure",
            "method": "GET",
        })


# ---------------------------------------------------------------------------
# Test 4: HTTP SSRF private IP — sidecar error -> ToolError
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_http_ssrf_private_ip():
    """Private IP URL -> sidecar error -> ToolError."""
    sidecar = _mock_sidecar(
        success=False,
        result="SSRF blocked: private IP address 192.168.1.1",
    )
    executor = ToolExecutor(policy_engine=_mock_engine(), sidecar=sidecar)

    with pytest.raises(ToolError, match="SSRF blocked"):
        await executor.execute("http_fetch", {
            "url": "https://192.168.1.1/internal",
            "method": "GET",
        })


# ---------------------------------------------------------------------------
# Test 5: HTTP SSRF DNS rebinding — sidecar error -> ToolError
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_http_ssrf_dns_rebinding():
    """DNS rebinding URL -> sidecar error -> ToolError."""
    sidecar = _mock_sidecar(
        success=False,
        result="SSRF blocked: DNS resolved to private address",
    )
    executor = ToolExecutor(policy_engine=_mock_engine(), sidecar=sidecar)

    with pytest.raises(ToolError, match="SSRF blocked"):
        await executor.execute("http_fetch", {
            "url": "https://evil.rebind.example.com/attack",
            "method": "GET",
        })


# ---------------------------------------------------------------------------
# Test 6: HTTP timeout — sidecar timeout -> ToolError
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_http_timeout():
    """Sidecar timeout -> ToolError."""
    sidecar = _mock_sidecar(
        success=False,
        result="sidecar timeout after 30s",
    )
    executor = ToolExecutor(policy_engine=_mock_engine(), sidecar=sidecar)

    with pytest.raises(ToolError, match="timeout"):
        await executor.execute("http_fetch", {
            "url": "https://api.search.brave.com/slow",
            "method": "GET",
        })


# ---------------------------------------------------------------------------
# Test 7: HTTP response too large — sidecar error or truncation
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_http_response_too_large():
    """Sidecar response indicating too-large payload -> ToolError."""
    sidecar = _mock_sidecar(
        success=False,
        result="response too large: 52428800 bytes exceeds 10485760 limit",
    )
    executor = ToolExecutor(policy_engine=_mock_engine(), sidecar=sidecar)

    with pytest.raises(ToolError, match="too large"):
        await executor.execute("http_fetch", {
            "url": "https://api.search.brave.com/huge",
            "method": "GET",
        })


# ---------------------------------------------------------------------------
# Test 8: HTTP credential injection — credentials passed through to sidecar
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_http_credential_injection():
    """Verify credentials dict is passed through to sidecar.execute()."""
    sidecar = _mock_sidecar(
        success=True,
        result="ok",
        data={"status": 200, "body": "authenticated response", "headers": {}},
    )
    executor = ToolExecutor(policy_engine=_mock_engine(), sidecar=sidecar)

    # http_fetch passes credentials via the args dict — the sidecar handles
    # injecting them into the Authorization header internally
    result = await executor.execute("http_fetch", {
        "url": "https://api.search.brave.com/search",
        "method": "GET",
        "headers": {"Authorization": "Bearer test-key"},
    })

    # The args with headers should have been passed to sidecar
    call_args = sidecar.execute.call_args
    assert "Authorization" in call_args.kwargs["args"]["headers"]

    assert result.source == DataSource.WEB
    assert result.trust_level == TrustLevel.UNTRUSTED


# ---------------------------------------------------------------------------
# Test 9: HTTP leak detection — response.leaked=True logs warning, returns result
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_http_leak_detection():
    """response.leaked=True -> log warning, still returns result."""
    sidecar = _mock_sidecar(
        success=True,
        result="ok",
        data={"status": 200, "body": "leaked secret data", "headers": {}},
        leaked=True,
    )
    executor = ToolExecutor(policy_engine=_mock_engine(), sidecar=sidecar)

    result = await executor.execute("http_fetch", {
        "url": "https://api.search.brave.com/search",
        "method": "GET",
    })

    # Result is still returned (leak detection is warning, not blocking)
    assert isinstance(result, TaggedData)
    assert result.source == DataSource.WEB
    assert result.trust_level == TrustLevel.UNTRUSTED


# ---------------------------------------------------------------------------
# Test 10: HTTP allowlist enforcement — policy domains passed to sidecar
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_http_allowlist_enforcement():
    """Verify http_allowlist from policy is passed to sidecar.execute()."""
    sidecar = _mock_sidecar(
        success=True,
        result="ok",
        data={"status": 200, "body": "response", "headers": {}},
    )
    policy = {
        "network": {
            "http_tool_allowed_domains": ["api.search.brave.com", "*.googleapis.com"],
        },
    }
    executor = ToolExecutor(policy_engine=_mock_engine(policy), sidecar=sidecar)

    await executor.execute("http_fetch", {
        "url": "https://api.search.brave.com/search",
        "method": "GET",
    })

    # Verify the allowlist was passed to sidecar
    call_args = sidecar.execute.call_args
    assert call_args.kwargs["http_allowlist"] == ["api.search.brave.com", "*.googleapis.com"]

    # Verify other WASM tools do NOT get http_allowlist
    sidecar.execute.reset_mock()
    sidecar.execute.return_value = SidecarResponse(success=True, result="ok")

    await executor.execute("file_read", {"path": "/workspace/test.txt"})

    call_args = sidecar.execute.call_args
    assert "http_allowlist" not in call_args.kwargs


# ---------------------------------------------------------------------------
# Test 11: HTTP response enters pipeline as UNTRUSTED + provenance check
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_http_response_enters_pipeline_as_untrusted():
    """TaggedData has trust_level=UNTRUSTED and provenance chain blocks execution."""
    sidecar = _mock_sidecar(
        success=True,
        result="ok",
        data={"status": 200, "body": "external data", "headers": {}},
    )
    executor = ToolExecutor(policy_engine=_mock_engine(), sidecar=sidecar)

    result = await executor.execute("http_fetch", {
        "url": "https://api.search.brave.com/search",
        "method": "GET",
    })

    # Verify trust tagging
    assert result.trust_level == TrustLevel.UNTRUSTED
    assert result.source == DataSource.WEB

    # Verify the _EXTERNAL_DATA_TOOLS constant is correctly configured
    assert "http_fetch" in _EXTERNAL_DATA_TOOLS
    ext_source, ext_trust = _EXTERNAL_DATA_TOOLS["http_fetch"]
    assert ext_source == DataSource.WEB
    assert ext_trust == TrustLevel.UNTRUSTED

    # Verify provenance: data from http_fetch should be blocked by trust gate
    assert is_trust_safe_for_execution(result.id) is False
