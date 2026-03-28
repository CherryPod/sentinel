"""B3 infrastructure configuration validation tests.

Parses podman-compose.yaml and container/Containerfile to verify security
properties WITHOUT requiring running containers. These are unit-style tests
that catch config drift — run them in CI and before any compose changes.

Validates: network segmentation, container security posture, secret handling,
volume isolation, Containerfile security, resource limits.
"""

import re
from pathlib import Path

import pytest
import yaml

# ── Fixtures ─────────────────────────────────────────────────────

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_COMPOSE_PATH = _PROJECT_ROOT / "podman-compose.yaml"
_CONTAINERFILE_PATH = _PROJECT_ROOT / "container" / "Containerfile"


@pytest.fixture
def compose() -> dict:
    """Parsed podman-compose.yaml."""
    return yaml.safe_load(_COMPOSE_PATH.read_text())


@pytest.fixture
def containerfile() -> str:
    """Raw Containerfile content."""
    return _CONTAINERFILE_PATH.read_text()


@pytest.fixture
def sentinel_service(compose) -> dict:
    """The 'sentinel' service definition from compose."""
    return compose["services"]["sentinel"]


@pytest.fixture
def ollama_service(compose) -> dict:
    """The 'sentinel-ollama' service definition from compose."""
    return compose["services"]["sentinel-ollama"]


# ── Network Segmentation ────────────────────────────────────────


class TestNetworkSegmentation:
    """Verify network topology enforces the air gap."""

    def test_internal_network_is_internal(self, compose):
        """sentinel_internal must have internal: true to prevent external routing."""
        internal_net = compose["networks"]["sentinel_internal"]
        assert internal_net.get("internal") is True, (
            "sentinel_internal network must have 'internal: true' to enforce air gap"
        )

    def test_egress_network_exists(self, compose):
        """sentinel_egress network must exist for Claude API access."""
        assert "sentinel_egress" in compose["networks"]

    def test_egress_network_not_internal(self, compose):
        """sentinel_egress must NOT be internal (needs external routing)."""
        egress_net = compose["networks"]["sentinel_egress"]
        assert egress_net.get("internal") is not True, (
            "sentinel_egress should allow external routing for Claude API"
        )

    def test_ollama_only_on_internal_network(self, ollama_service):
        """sentinel-ollama must only be on sentinel_internal — never sentinel_egress."""
        networks = ollama_service.get("networks", [])
        assert "sentinel_internal" in networks, (
            "sentinel-ollama must be on sentinel_internal"
        )
        assert "sentinel_egress" not in networks, (
            "sentinel-ollama must NOT be on sentinel_egress — this would break the air gap"
        )

    def test_sentinel_on_both_networks(self, sentinel_service):
        """sentinel must be on both internal (for ollama) and egress (for Claude API)."""
        networks = sentinel_service.get("networks", [])
        assert "sentinel_internal" in networks, (
            "sentinel must be on sentinel_internal to reach ollama"
        )
        assert "sentinel_egress" in networks, (
            "sentinel must be on sentinel_egress to reach Claude API"
        )

    def test_internal_network_has_subnet(self, compose):
        """sentinel_internal should have an explicit subnet for deterministic routing."""
        internal_net = compose["networks"]["sentinel_internal"]
        ipam = internal_net.get("ipam", {})
        config = ipam.get("config", [])
        assert len(config) > 0, "sentinel_internal should have explicit IPAM config"
        assert "subnet" in config[0], "sentinel_internal should have an explicit subnet"


# ── Container Security ───────────────────────────────────────────


class TestContainerSecurity:
    """Verify container-level security hardening."""

    def test_sentinel_read_only(self, sentinel_service):
        """sentinel container must have read-only rootfs."""
        assert sentinel_service.get("read_only") is True, (
            "sentinel must have 'read_only: true' for rootfs protection"
        )

    def test_sentinel_tmpfs_mounted(self, sentinel_service):
        """sentinel /tmp must be tmpfs (noexec deliberately omitted — signal-cli
        GraalVM native binary extracts libsignal_jni to /tmp at runtime)."""
        tmpfs = sentinel_service.get("tmpfs", [])
        tmp_entries = [e for e in tmpfs if "/tmp" in str(e)]
        assert len(tmp_entries) > 0, "sentinel must have /tmp as tmpfs"

    def test_sentinel_memory_limit(self, sentinel_service):
        """sentinel must have a memory limit set."""
        mem = sentinel_service.get("mem_limit")
        assert mem is not None, "sentinel must have mem_limit set"

    def test_sentinel_cpu_limit(self, sentinel_service):
        """sentinel must have a CPU limit set."""
        cpus = sentinel_service.get("cpus")
        assert cpus is not None, "sentinel must have cpus set"

    def test_ollama_memory_limit(self, ollama_service):
        """sentinel-ollama must have a memory limit set."""
        mem = ollama_service.get("mem_limit")
        assert mem is not None, "sentinel-ollama must have mem_limit set"

    def test_ollama_cpu_limit(self, ollama_service):
        """sentinel-ollama must have a CPU limit set."""
        cpus = ollama_service.get("cpus")
        assert cpus is not None, "sentinel-ollama must have cpus set"

    def test_sentinel_healthcheck_exists(self, sentinel_service):
        """sentinel must have a health check for restart reliability."""
        assert "healthcheck" in sentinel_service, (
            "sentinel must have a healthcheck defined"
        )

    def test_ollama_healthcheck_exists(self, ollama_service):
        """sentinel-ollama must have a health check."""
        assert "healthcheck" in ollama_service, (
            "sentinel-ollama must have a healthcheck defined"
        )

    def test_sentinel_restart_policy(self, sentinel_service):
        """sentinel restart: no — systemd owns the lifecycle (sentinel.service)."""
        assert sentinel_service.get("restart") == "no"

    def test_ollama_restart_policy(self, ollama_service):
        """sentinel-ollama restart: no — systemd owns the lifecycle."""
        assert ollama_service.get("restart") == "no"


# ── Secret Handling ──────────────────────────────────────────────


class TestSecretHandling:
    """Verify secrets are handled via files, never environment variables."""

    def test_secrets_defined_as_files(self, compose):
        """Top-level secrets must use file references (not external or inline)."""
        secrets = compose.get("secrets", {})
        assert "claude_api_key" in secrets, "claude_api_key secret must be defined"
        assert "sentinel_pin" in secrets, "sentinel_pin secret must be defined"
        for name, defn in secrets.items():
            assert "file" in defn, (
                f"Secret '{name}' must use 'file:' reference, not inline or external"
            )

    def test_sentinel_receives_secrets(self, sentinel_service):
        """sentinel service must reference both secrets."""
        svc_secrets = sentinel_service.get("secrets", [])
        assert "claude_api_key" in svc_secrets
        assert "sentinel_pin" in svc_secrets

    def test_ollama_has_no_secrets(self, ollama_service):
        """sentinel-ollama must NOT have any secrets — it's air-gapped and untrusted."""
        svc_secrets = ollama_service.get("secrets", [])
        assert len(svc_secrets) == 0, (
            "sentinel-ollama must not have secrets — the worker is untrusted"
        )

    def test_no_secret_values_in_sentinel_env(self, sentinel_service):
        """sentinel environment must not contain actual secret values."""
        env = sentinel_service.get("environment", [])
        # Secret-looking patterns that should never appear as env var values
        secret_patterns = [
            r"sk-ant-",           # Anthropic API key prefix
            r"CLAUDE_API_KEY=.",  # API key as env var value (not just file path)
        ]
        env_str = "\n".join(env) if isinstance(env, list) else str(env)
        for pattern in secret_patterns:
            assert not re.search(pattern, env_str), (
                f"Secret pattern '{pattern}' found in sentinel environment variables"
            )

    def test_sentinel_uses_secret_file_paths(self, sentinel_service):
        """sentinel should reference secrets via file paths, not values."""
        env = sentinel_service.get("environment", [])
        env_str = "\n".join(env) if isinstance(env, list) else str(env)
        # PIN is referenced by file path
        assert "SENTINEL_PIN_FILE=/run/secrets/" in env_str, (
            "sentinel should use SENTINEL_PIN_FILE pointing to /run/secrets/"
        )

    def test_no_secret_values_in_ollama_env(self, ollama_service):
        """sentinel-ollama environment must not contain any secret-like values."""
        env = ollama_service.get("environment", [])
        env_str = "\n".join(env) if isinstance(env, list) else str(env)
        secret_keywords = ["KEY=", "SECRET=", "TOKEN=", "PASSWORD=", "PIN="]
        for kw in secret_keywords:
            assert kw not in env_str, (
                f"Secret keyword '{kw}' found in sentinel-ollama environment"
            )

    def test_session_key_secret_exists(self, sentinel_service):
        """JWT session key secret must be available — it is required for auth."""
        svc_secrets = sentinel_service.get("secrets", [])
        assert "session_key" in svc_secrets, (
            "session_key secret must be available to sentinel service — "
            "JWT auth requires it for token signing/verification"
        )


# ── Volume Isolation ─────────────────────────────────────────────


class TestVolumeIsolation:
    """Verify no volumes are shared between containers."""

    @staticmethod
    def _extract_named_volumes(service: dict) -> set[str]:
        """Extract named volume names from a service's volume mounts.

        Handles both string format ('volume-name:/path') and dict format
        ({'type': 'volume', 'source': 'volume-name', 'target': '/path'}).
        Bind mounts look like './host/path:/container/path' or '/host:/container'.
        """
        volumes = service.get("volumes", [])
        named = set()
        for vol in volumes:
            if isinstance(vol, dict):
                # Long-form dict syntax
                if vol.get("type", "volume") == "volume" and vol.get("source"):
                    named.add(vol["source"])
            else:
                # Short-form string syntax
                source = str(vol).split(":")[0]
                # Named volumes don't start with . or /
                if not source.startswith((".", "/")):
                    named.add(source)
        return named

    def test_no_shared_named_volumes(self, sentinel_service, ollama_service):
        """Named volumes must not be shared between containers."""
        sentinel_vols = self._extract_named_volumes(sentinel_service)
        ollama_vols = self._extract_named_volumes(ollama_service)
        shared = sentinel_vols & ollama_vols
        assert len(shared) == 0, (
            f"Shared named volumes between containers: {shared} — "
            "data should only flow through the Ollama API, not shared volumes"
        )

    def test_sentinel_policies_readonly(self, sentinel_service):
        """Policies volume must be mounted read-only."""
        volumes = sentinel_service.get("volumes", [])
        policy_vols = [v for v in volumes if "/policies" in str(v)]
        assert len(policy_vols) > 0, "sentinel must mount policies"
        assert any(":ro" in str(v) for v in policy_vols), (
            "Policies volume must be mounted read-only (:ro)"
        )

    def test_podman_socket_readonly(self, sentinel_service):
        """Podman socket must be mounted read-only."""
        volumes = sentinel_service.get("volumes", [])
        socket_vols = [v for v in volumes if "podman.sock" in str(v)]
        assert len(socket_vols) > 0, "sentinel must mount Podman socket (for E5 sandbox)"
        assert any(":ro" in str(v) for v in socket_vols), (
            "Podman socket must be mounted read-only (:ro)"
        )

    def test_ollama_has_no_podman_socket(self, ollama_service):
        """sentinel-ollama must NOT have the Podman socket — it's an untrusted worker."""
        volumes = ollama_service.get("volumes", [])
        assert not any("podman.sock" in str(v) for v in volumes), (
            "sentinel-ollama must not have Podman socket access — "
            "a compromised worker could use it to escape the sandbox"
        )

    def test_all_named_volumes_declared(self, compose):
        """All named volumes used in services must be declared at top level."""
        declared = set(compose.get("volumes", {}).keys())
        used = set()
        for svc_name, svc in compose.get("services", {}).items():
            for vol in svc.get("volumes", []):
                source = str(vol).split(":")[0]
                if not source.startswith((".", "/")):
                    used.add(source)
        undeclared = used - declared
        assert len(undeclared) == 0, (
            f"Named volumes used but not declared: {undeclared}"
        )


# ── Containerfile Security ───────────────────────────────────────


class TestContainerfileSecurity:
    """Validate Containerfile security properties."""

    def test_exposed_ports_expected(self, containerfile):
        """EXPOSE should only list expected ports (8443, 8080)."""
        expose_lines = re.findall(r"^EXPOSE\s+(.+)$", containerfile, re.MULTILINE)
        assert len(expose_lines) > 0, "Containerfile should have EXPOSE directive"
        all_ports = set()
        for line in expose_lines:
            all_ports.update(line.strip().split())
        expected = {"8443", "8080"}
        unexpected = all_ports - expected
        assert len(unexpected) == 0, (
            f"Unexpected EXPOSE ports: {unexpected} — only {expected} expected"
        )

    def test_hf_token_uses_build_secret(self, containerfile):
        """HuggingFace token must use --mount=type=secret, not ARG or ENV."""
        # Should NOT have ARG HF_TOKEN or ENV HF_TOKEN
        assert not re.search(r"^(ARG|ENV)\s+HF_TOKEN\b", containerfile, re.MULTILINE), (
            "HF_TOKEN must not be passed via ARG or ENV — use --mount=type=secret"
        )
        # Should have --mount=type=secret,id=hf_token
        assert "--mount=type=secret,id=hf_token" in containerfile, (
            "HF_TOKEN should be loaded via --mount=type=secret"
        )

    def test_base_image_pinned_by_digest(self, containerfile):
        """Base image must be pinned by sha256 digest, not a mutable tag."""
        from_lines = re.findall(r"^FROM\s+(\S+)", containerfile, re.MULTILINE)
        assert len(from_lines) > 0, "Containerfile must have a FROM directive"
        for image in from_lines:
            assert "@sha256:" in image, (
                f"Base image '{image}' must be pinned by digest (@sha256:...), not by tag"
            )

    def test_no_user_root_directive(self, containerfile):
        """Flag if there is no USER directive (known gap — runs as root).

        This test documents the known gap: no USER directive means the
        container runs as in-container root. Rootless Podman mitigates
        this (maps to unprivileged host user), but a USER directive
        would be defence-in-depth.
        """
        user_lines = re.findall(r"^USER\s+(.+)$", containerfile, re.MULTILINE)
        if len(user_lines) == 0:
            pytest.xfail(
                "Known gap: no USER directive in Containerfile — runs as in-container root. "
                "Rootless Podman mitigates but USER should be added for defence-in-depth."
            )
        else:
            # If a USER directive exists, ensure it's not 'root'
            for user in user_lines:
                assert user.strip() != "root", (
                    "USER root without subsequent non-root USER is a security gap"
                )

    def test_no_sensitive_copies(self, containerfile):
        """COPY should not include sensitive files (.env, secrets, keys)."""
        copy_lines = re.findall(r"^COPY\s+(.+)$", containerfile, re.MULTILINE)
        sensitive_patterns = [".env", "secret", ".key", ".pem", "credentials"]
        for line in copy_lines:
            source = line.split()[0].lower()
            for pattern in sensitive_patterns:
                # Skip the TLS key generation (that's an RUN, not COPY)
                if pattern in source:
                    pytest.fail(
                        f"Potentially sensitive file in COPY: '{line}' matches '{pattern}'"
                    )


# ── Ollama Image Security ────────────────────────────────────────


class TestOllamaImageSecurity:
    """Validate ollama container image configuration."""

    def test_ollama_image_specified(self, ollama_service):
        """Ollama image must be explicitly specified (tag or digest)."""
        image = ollama_service.get("image", "")
        assert image, "Ollama image must be specified"
        # Prefer digest pinning for supply-chain safety, but tag is
        # acceptable during model trials (e.g. ollama/ollama:0.17.7)
        assert ":" in image or "@" in image, (
            f"Ollama image '{image}' should include a tag (:version) or "
            "digest (@sha256:...) — never use :latest implicitly"
        )

    def test_ollama_has_gpu_device(self, ollama_service):
        """sentinel-ollama should have GPU access for model inference."""
        devices = ollama_service.get("devices", [])
        assert any("gpu" in str(d).lower() or "nvidia" in str(d).lower() for d in devices), (
            "sentinel-ollama should have GPU device access"
        )


# ── Port Mapping ─────────────────────────────────────────────────


class TestPortMapping:
    """Verify only expected ports are exposed to the host."""

    def test_sentinel_ports_expected(self, sentinel_service):
        """sentinel should only expose ports 3001 (HTTPS) and 3002 (HTTP redirect)."""
        ports = sentinel_service.get("ports", [])
        port_strs = {str(p) for p in ports}
        expected = {"3001:8443", "3002:8080"}
        unexpected = port_strs - expected
        assert len(unexpected) == 0, (
            f"Unexpected port mappings: {unexpected} — only {expected} expected"
        )

    def test_ollama_no_host_ports(self, ollama_service):
        """sentinel-ollama must NOT expose any ports to the host."""
        ports = ollama_service.get("ports", [])
        assert len(ports) == 0, (
            f"sentinel-ollama must not expose ports to host: {ports} — "
            "it should only be reachable via sentinel_internal network"
        )
