import os
from pathlib import Path

import pytest

from sentinel.api.sessions import create_session_token
from sentinel.api.rate_limit import limiter
from sentinel.security.policy_engine import PolicyEngine
from sentinel.security.scanner import CommandPatternScanner, CredentialScanner, SensitivePathScanner


@pytest.fixture(autouse=True)
def _disable_rate_limiting():
    """Disable rate limiting during tests to avoid 429s from rapid requests."""
    limiter.enabled = False
    yield
    limiter.enabled = True


def auth_headers(user_id: int = 1, role: str = "owner") -> dict:
    """Generate Bearer token headers for test requests."""
    token = create_session_token(user_id=user_id, role=role)
    return {"Authorization": f"Bearer {token}"}

# Locate the real policy YAML — works both locally and in container
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_POLICY_PATH = _PROJECT_ROOT / "policies" / "sentinel-policy.yaml"

# Fallback for container layout (/policies/sentinel-policy.yaml)
if not _POLICY_PATH.exists():
    _POLICY_PATH = Path("/policies/sentinel-policy.yaml")


@pytest.fixture
def engine() -> PolicyEngine:
    """PolicyEngine loaded with the real sentinel-policy.yaml (TL0 default)."""
    return PolicyEngine(str(_POLICY_PATH), workspace_path="/workspace")


@pytest.fixture
def engine_tl4() -> PolicyEngine:
    """PolicyEngine at TL4 — structural injection patterns relaxed."""
    return PolicyEngine(str(_POLICY_PATH), workspace_path="/workspace", trust_level=4)


@pytest.fixture
def cred_scanner(engine: PolicyEngine) -> CredentialScanner:
    """CredentialScanner with patterns from real policy."""
    return CredentialScanner(engine.policy.get("credential_patterns", []))


@pytest.fixture
def path_scanner(engine: PolicyEngine) -> SensitivePathScanner:
    """SensitivePathScanner with patterns from real policy."""
    return SensitivePathScanner(engine.policy.get("sensitive_path_patterns", []))


@pytest.fixture
def cmd_scanner() -> CommandPatternScanner:
    """CommandPatternScanner with default patterns."""
    return CommandPatternScanner()


@pytest.fixture
def encoding_scanner(cred_scanner, path_scanner, cmd_scanner):
    """EncodingNormalizationScanner wired to real policy-based inner scanners."""
    from sentinel.security.scanner import EncodingNormalizationScanner
    return EncodingNormalizationScanner(cred_scanner, path_scanner, cmd_scanner)


@pytest.fixture
def echo_scanner():
    """VulnerabilityEchoScanner with default config."""
    from sentinel.security.scanner import VulnerabilityEchoScanner
    return VulnerabilityEchoScanner()
