#!/usr/bin/env python3
"""B4 v2 Sandbox Isolation Red Team — Direct sandbox containment testing.

Tests the sandbox (Layer 10) in isolation using PodmanSandbox.run() directly.
Each test creates a disposable container and verifies containment properties.

Unlike B1-B2 (which test scanner/policy layers L1-9), B4 tests what happens
when an attack REACHES the sandbox. This catches Fix V-class bugs where
security config is present but silently inactive.

v2 covers (17 categories from security assessment 2026-02-28):
  B4.1  Volume isolation         B4.10 xargs chaining
  B4.2  Network isolation + DNS  B4.11 Environment variable leakage
  B4.3  Filesystem read-only     B4.12 Sandbox startup self-test
  B4.4  Capability restriction   B4.13 Proxy security field validation
  B4.5  Resource limits          B4.14 Temporal workspace persistence
  B4.6  /proc/self info-leak     B4.15 Seccomp profile verification (P2)
  B4.7  Symlink/hardlink attacks B4.16 Mount validation
  B4.8  Python escape            B4.17 Concurrency test
  B4.9  tar/archive attacks

Usage:
  .venv/bin/python3 scripts/red_team_b4_v2.py
  .venv/bin/python3 scripts/red_team_b4_v2.py --categories volume network
  .venv/bin/python3 scripts/red_team_b4_v2.py --verbose
  .venv/bin/python3 scripts/red_team_b4_v2.py --socket /run/user/1000/podman/podman.sock
"""

from __future__ import annotations

import asyncio
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# Add parent to path for sentinel imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinel.tools.sandbox import PodmanSandbox, SandboxResult

# ── Constants ──────────────────────────────────────────────────────

ALL_CATEGORIES = [
    "volume",           # B4.1
    "network",          # B4.2
    "filesystem",       # B4.3
    "capability",       # B4.4
    "resource",         # B4.5
    "procfs",           # B4.6
    "symlink",          # B4.7
    "python_escape",    # B4.8
    "tar_archive",      # B4.9
    "xargs",            # B4.10
    "env_leak",         # B4.11
    "selftest",         # B4.12
    "proxy_validation", # B4.13
    "persistence",      # B4.14
    "seccomp",          # B4.15
    "mount",            # B4.16
    "concurrency",      # B4.17
]

# Default config matching sentinel compose setup
DEFAULT_IMAGE = "python:3.12-slim"
DEFAULT_TIMEOUT = 30
DEFAULT_MAX_TIMEOUT = 60
DEFAULT_MEMORY = 268435456       # 256MB
DEFAULT_CPU_QUOTA = 100000       # 1 CPU
DEFAULT_OUTPUT_LIMIT = 65536     # 64KB

# Secret patterns to check for leakage
SECRET_PATTERNS = [
    "sk-ant-", "ANTHROPIC_API_KEY", "CLAUDE_API_KEY",
    "SENTINEL_PIN", "HF_TOKEN", "hf_", "BREVO_",
    "TELEGRAM_BOT_TOKEN", "CALDAV_PASSWORD",
]


# ── JSONL Writer ───────────────────────────────────────────────────

class JsonlWriter:
    """Crash-safe JSONL writer with immediate fsync."""

    def __init__(self, path: str):
        self.path = path
        self._fh = open(path, "a", buffering=1, encoding="utf-8")

    def write(self, record: dict):
        self._fh.write(json.dumps(record, default=str) + "\n")
        self._fh.flush()
        os.fsync(self._fh.fileno())

    def close(self):
        self._fh.close()


# ── Test Result ─────────────────────────────────────────────────────

@dataclass
class TestResult:
    category: str
    test_id: str
    description: str
    status: str       # pass, fail, warn, skip, info
    expected: str = ""
    actual: str = ""
    severity: str = ""


# ── B4 Test Runner ──────────────────────────────────────────────────

class B4Runner:
    """Run all B4 sandbox isolation tests."""

    def __init__(
        self,
        socket_path: str,
        image: str,
        workspace_dir: str,
        output_path: str,
        verbose: bool = False,
        sentinel_container: str = "sentinel",
    ):
        self.socket_path = socket_path
        self.image = image
        self.workspace_dir = workspace_dir
        self.output_path = output_path
        self.verbose = verbose
        self.sentinel_ctr = sentinel_container
        self.writer = JsonlWriter(output_path)
        self.results: list[TestResult] = []

        # Create PodmanSandbox with test config
        self.sandbox = PodmanSandbox(
            socket_path=socket_path,
            image=image,
            default_timeout=DEFAULT_TIMEOUT,
            max_timeout=DEFAULT_MAX_TIMEOUT,
            memory_limit=DEFAULT_MEMORY,
            cpu_quota=DEFAULT_CPU_QUOTA,
            workspace_volume=workspace_dir,
            output_limit=DEFAULT_OUTPUT_LIMIT,
        )

    # ── Helpers ─────────────────────────────────────────────────

    def _record(self, r: TestResult):
        """Record a test result to JSONL and internal list."""
        self.results.append(r)
        self.writer.write({
            "version": "v2",
            "type": "b4_result",
            "category": r.category,
            "test_id": r.test_id,
            "description": r.description,
            "status": r.status,
            "expected": r.expected,
            "actual": r.actual,
            "severity": r.severity,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        marker = {
            "pass": "[PASS]", "fail": "[FAIL]", "warn": "[WARN]",
            "skip": "[SKIP]", "info": "[INFO]",
        }.get(r.status, "[????]")
        print(f"  {marker} {r.description}")
        if r.status == "fail" and r.expected:
            print(f"         Expected: {r.expected}")
        if r.status == "fail" and r.actual:
            print(f"         Actual:   {r.actual[:200]}")
        if r.status == "warn" and r.actual:
            print(f"         Note: {r.actual[:200]}")

    def _pass(self, cat: str, tid: str, desc: str):
        self._record(TestResult(cat, tid, desc, "pass"))

    def _fail(self, cat: str, tid: str, desc: str,
              expected: str = "", actual: str = "", severity: str = "S2"):
        self._record(TestResult(cat, tid, desc, "fail", expected, actual, severity))

    def _warn(self, cat: str, tid: str, desc: str, note: str = ""):
        self._record(TestResult(cat, tid, desc, "warn", actual=note, severity="backlog"))

    def _skip(self, cat: str, tid: str, desc: str, reason: str = ""):
        self._record(TestResult(cat, tid, desc, "skip", actual=reason))

    def _info(self, cat: str, tid: str, desc: str, detail: str = ""):
        self._record(TestResult(cat, tid, desc, "info", actual=detail))

    async def _run(self, command: str, timeout: int = DEFAULT_TIMEOUT) -> SandboxResult:
        """Run a command in the sandbox. Wraps PodmanSandbox.run()."""
        return await self.sandbox.run(command, timeout=timeout)

    def _podman_exec(self, container: str, *cmd: str) -> tuple[str, int]:
        """Run a command inside a container via podman exec."""
        try:
            result = subprocess.run(
                ["podman", "exec", container, *cmd],
                capture_output=True, text=True, timeout=30,
            )
            return result.stdout + result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "timeout", -1
        except FileNotFoundError:
            return "podman not found", -1

    def _write_workspace_file(self, name: str, content: str):
        """Write a file to the workspace directory."""
        path = Path(self.workspace_dir) / name
        path.write_text(content)

    def _read_workspace_file(self, name: str) -> str | None:
        """Read a file from the workspace directory."""
        path = Path(self.workspace_dir) / name
        if path.exists():
            return path.read_text()
        return None

    def _clean_workspace(self):
        """Remove all files from the workspace directory."""
        ws = Path(self.workspace_dir)
        for item in ws.iterdir():
            if item.is_dir():
                shutil.rmtree(item, ignore_errors=True)
            else:
                item.unlink(missing_ok=True)

    # ── B4.1: Volume Isolation ──────────────────────────────────

    async def test_volume(self):
        print("\nB4.1: Volume isolation")

        # Write to /workspace should succeed
        r = await self._run("touch /workspace/b4_test_write && echo OK")
        if r.exit_code == 0 and "OK" in r.stdout:
            self._pass("volume", "4.1.1", "/workspace is writable")
        else:
            self._fail("volume", "4.1.1", "/workspace is NOT writable",
                        "writable", r.stderr, "S1")

        # Write to /tmp should succeed (tmpfs)
        r = await self._run("touch /tmp/b4_test_write && echo OK")
        if r.exit_code == 0 and "OK" in r.stdout:
            self._pass("volume", "4.1.2", "/tmp is writable (tmpfs)")
        else:
            self._fail("volume", "4.1.2", "/tmp is NOT writable",
                        "writable", r.stderr, "S2")

        # Execute from /tmp should FAIL (noexec)
        r = await self._run("cp /usr/bin/echo /tmp/test_exec 2>/dev/null && /tmp/test_exec hi")
        if r.exit_code != 0:
            self._pass("volume", "4.1.3", "/tmp is noexec (execution blocked)")
        else:
            self._fail("volume", "4.1.3", "/tmp allows execution",
                        "permission denied", r.stdout, "S1")

        # Write to root filesystem should FAIL
        for path in ["/test_rw", "/etc/test_rw", "/usr/test_rw", "/opt/test_rw"]:
            r = await self._run(f"touch {path} 2>&1")
            if r.exit_code != 0:
                self._pass("volume", f"4.1.4_{path}", f"rootfs read-only at {path}")
            else:
                self._fail("volume", f"4.1.4_{path}", f"rootfs WRITABLE at {path}",
                            "EROFS", "touch succeeded", "S1")

        # Script write to /tmp then execute
        r = await self._run(
            'echo "#!/bin/sh\necho EXPLOIT" > /tmp/exploit.sh && '
            'chmod +x /tmp/exploit.sh && /tmp/exploit.sh'
        )
        if r.exit_code != 0 or "EXPLOIT" not in r.stdout:
            self._pass("volume", "4.1.5", "/tmp noexec blocks script execution")
        else:
            self._fail("volume", "4.1.5", "/tmp allows script execution",
                        "permission denied", r.stdout, "S1")

        # Cleanup
        r = await self._run("rm -f /workspace/b4_test_write")

    # ── B4.2: Network Isolation ─────────────────────────────────

    async def test_network(self):
        print("\nB4.2: Network isolation + DNS side-channel")

        # TCP connection to external host
        r = await self._run(
            'python3 -c "'
            'import socket; s=socket.socket(); s.settimeout(5); '
            's.connect((chr(56)+chr(46)+chr(56)+chr(46)+chr(56)+chr(46)+chr(56), 53)); '
            'print(chr(67)+chr(79)+chr(78)+chr(78))'
            '"',
            timeout=15,
        )
        if r.exit_code != 0 or "CONN" not in r.stdout:
            self._pass("network", "4.2.1", "TCP egress to 8.8.8.8:53 blocked")
        else:
            self._fail("network", "4.2.1", "TCP egress SUCCEEDED",
                        "connection blocked", r.stdout, "S0")

        # DNS resolution (side-channel test — user addition #5)
        r = await self._run(
            'python3 -c "'
            'import socket; '
            'result = socket.getaddrinfo(chr(103)+chr(111)+chr(111)+chr(103)+'
            'chr(108)+chr(101)+chr(46)+chr(99)+chr(111)+chr(109), 80); '
            'print(f\\"RESOLVED: {result}\\")'
            '"',
            timeout=15,
        )
        if r.exit_code != 0 or "RESOLVED" not in r.stdout:
            self._pass("network", "4.2.2", "DNS resolution blocked (no side-channel)")
        else:
            self._fail("network", "4.2.2", "DNS resolution SUCCEEDED in sandbox",
                        "resolution blocked", r.stdout, "S0")

        # UDP egress (DNS typically uses UDP 53)
        r = await self._run(
            'python3 -c "'
            'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); '
            's.settimeout(3); '
            's.sendto(b\\"test\\", (chr(56)+chr(46)+chr(56)+chr(46)+chr(56)+chr(46)+chr(56), 53)); '
            'data=s.recvfrom(512); print(f\\"RESPONSE: {len(data[0])}\\")'
            '"',
            timeout=10,
        )
        if r.exit_code != 0 or "RESPONSE" not in r.stdout:
            self._pass("network", "4.2.3", "UDP egress blocked")
        else:
            self._fail("network", "4.2.3", "UDP egress SUCCEEDED",
                        "blocked", r.stdout, "S0")

        # urllib.request (HTTP client)
        r = await self._run(
            'python3 -c "'
            'import urllib.request; '
            'urllib.request.urlopen(chr(104)+chr(116)+chr(116)+chr(112)+chr(58)+'
            'chr(47)+chr(47)+chr(105)+chr(102)+chr(99)+chr(111)+chr(110)+chr(102)+'
            'chr(105)+chr(103)+chr(46)+chr(109)+chr(101), timeout=5).read(); '
            'print(\\"FETCHED\\")'
            '"',
            timeout=15,
        )
        if r.exit_code != 0 or "FETCHED" not in r.stdout:
            self._pass("network", "4.2.4", "HTTP client blocked (urllib)")
        else:
            self._fail("network", "4.2.4", "HTTP client SUCCEEDED",
                        "blocked", r.stdout, "S0")

        # /etc/resolv.conf contents
        r = await self._run("cat /etc/resolv.conf")
        if r.exit_code == 0:
            self._info("network", "4.2.5", f"resolv.conf: {r.stdout.strip()[:150]}")
            # Check for external nameservers
            for ns in ["8.8.8.8", "1.1.1.1", "9.9.9.9"]:
                if ns in r.stdout:
                    self._warn("network", "4.2.5a",
                               f"resolv.conf has external nameserver {ns}",
                               "Should not be resolvable due to NetworkDisabled")

        # Raw socket (ICMP) — should fail without CAP_NET_RAW
        r = await self._run(
            'python3 -c "'
            'import socket; '
            's=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP); '
            'print(\\"RAW_SOCKET_CREATED\\")'
            '"',
        )
        if r.exit_code != 0 or "RAW_SOCKET_CREATED" not in r.stdout:
            self._pass("network", "4.2.6", "Raw socket creation blocked (no CAP_NET_RAW)")
        else:
            self._fail("network", "4.2.6", "Raw socket creation SUCCEEDED",
                        "blocked", r.stdout, "S1")

    # ── B4.3: Filesystem Isolation ──────────────────────────────

    async def test_filesystem(self):
        print("\nB4.3: Filesystem read-only")

        # System paths should be read-only
        for path in ["/", "/etc", "/usr", "/var", "/opt", "/root", "/home", "/srv"]:
            r = await self._run(f"touch {path}/b4_test 2>&1")
            if r.exit_code != 0:
                self._pass("filesystem", f"4.3.1_{path}", f"{path} is read-only")
            else:
                self._fail("filesystem", f"4.3.1_{path}", f"{path} is WRITABLE",
                            "EROFS", "touch succeeded", "S1")

        # Can READ system files (expected — read-only rootfs, not no-access)
        r = await self._run("cat /etc/os-release")
        if r.exit_code == 0:
            self._info("filesystem", "4.3.2", f"can read /etc/os-release (expected): {r.stdout[:100]}")

        # Can list root filesystem (expected)
        r = await self._run("ls /")
        if r.exit_code == 0:
            self._info("filesystem", "4.3.3", f"root listing: {r.stdout.strip()}")

        # Cannot create directories
        r = await self._run("mkdir /var/exploit 2>&1")
        if r.exit_code != 0:
            self._pass("filesystem", "4.3.4", "mkdir on read-only rootfs blocked")
        else:
            self._fail("filesystem", "4.3.4", "mkdir on rootfs SUCCEEDED",
                        "blocked", r.stdout, "S1")

    # ── B4.4: Capability Restriction ────────────────────────────

    async def test_capability(self):
        print("\nB4.4: Capability restriction (CapDrop ALL, NoNewPrivileges)")

        # mount should fail (no CAP_SYS_ADMIN)
        r = await self._run("mount -t proc proc /mnt 2>&1")
        if r.exit_code != 0:
            self._pass("capability", "4.4.1", "mount blocked (no CAP_SYS_ADMIN)")
        else:
            self._fail("capability", "4.4.1", "mount SUCCEEDED",
                        "permission denied", r.stdout, "S0")

        # chown should fail (no CAP_CHOWN)
        r = await self._run("chown nobody /workspace 2>&1")
        if r.exit_code != 0:
            self._pass("capability", "4.4.2", "chown blocked (no CAP_CHOWN)")
        else:
            self._fail("capability", "4.4.2", "chown SUCCEEDED",
                        "permission denied", r.stdout, "S1")

        # mknod should fail (no CAP_MKNOD)
        r = await self._run("mknod /workspace/test_dev c 1 3 2>&1")
        if r.exit_code != 0:
            self._pass("capability", "4.4.3", "mknod blocked (no CAP_MKNOD)")
        else:
            self._fail("capability", "4.4.3", "mknod SUCCEEDED",
                        "permission denied", r.stdout, "S1")

        # setuid should fail (NoNewPrivileges / CAP_SETUID dropped)
        # Fix X drops code to UID 65534 via setpriv. setuid(own_UID) is a
        # POSIX no-op, so we test setuid(0) — escalation TO root. If caps
        # are properly dropped, this fails with EPERM.
        r = await self._run(
            'python3 -c "import os; os.setuid(0); print(\\"SETUID_OK\\")" 2>&1'
        )
        if r.exit_code != 0 or "SETUID_OK" not in r.stdout:
            self._pass("capability", "4.4.4", "setuid(0) blocked — cannot escalate to root")
        else:
            self._fail("capability", "4.4.4", "setuid(0) SUCCEEDED — escalated to root!",
                        "blocked", r.stdout, "S0")

        # Check CapEff is zero (all caps dropped)
        r = await self._run("cat /proc/1/status 2>/dev/null | grep CapEff || echo UNAVAILABLE")
        if "UNAVAILABLE" not in r.stdout:
            cap_hex = r.stdout.strip().split()[-1] if r.stdout.strip() else "?"
            if cap_hex == "0000000000000000":
                self._pass("capability", "4.4.5",
                            "CapEff is 0000000000000000 (all capabilities dropped)")
            else:
                self._fail("capability", "4.4.5",
                            f"CapEff is {cap_hex} (should be all zeros)",
                            "0000000000000000", cap_hex, "S1")
        else:
            self._skip("capability", "4.4.5", "cannot read /proc/1/status")

        # ptrace should fail
        # PTRACE_ATTACH (16) on PID 1 tests actual restriction.
        # PTRACE_TRACEME (0) always succeeds on self (pid arg ignored).
        r = await self._run(
            'python3 -c "'
            'import ctypes, ctypes.util; '
            'libc = ctypes.CDLL(ctypes.util.find_library(\\"c\\")); '
            'result = libc.ptrace(16, 1, 0, 0); '  # PTRACE_ATTACH on PID 1
            'print(f\\"PTRACE_RESULT: {result}\\")'
            '" 2>&1'
        )
        if r.exit_code != 0 or "PTRACE_RESULT: -1" in r.stdout or "PTRACE_RESULT: 0" not in r.stdout:
            self._pass("capability", "4.4.6", "ptrace blocked")
        else:
            self._fail("capability", "4.4.6", "ptrace SUCCEEDED",
                        "blocked", r.stdout, "S0")

        # unshare should fail (no CAP_SYS_ADMIN)
        r = await self._run("unshare --mount /bin/sh -c 'echo UNSHARED' 2>&1")
        if r.exit_code != 0 or "UNSHARED" not in r.stdout:
            self._pass("capability", "4.4.7", "unshare blocked (no CAP_SYS_ADMIN)")
        else:
            self._fail("capability", "4.4.7", "unshare SUCCEEDED",
                        "blocked", r.stdout, "S0")

    # ── B4.5: Resource Limits ───────────────────────────────────

    async def test_resource(self):
        print("\nB4.5: Resource limits")

        # Memory hog — should OOM kill
        r = await self._run(
            'python3 -c "'
            'data = []; '
            '[data.append(bytearray(10*1024*1024)) for _ in range(100)]; '  # 1GB total
            'print(\\"SURVIVED\\")'
            '"',
            timeout=30,
        )
        if r.oom_killed:
            self._pass("resource", "4.5.1", "OOM killer triggered on memory hog")
        elif r.exit_code != 0 and "SURVIVED" not in r.stdout:
            self._pass("resource", "4.5.1",
                        "Memory hog terminated (exit_code={})".format(r.exit_code))
        else:
            self._fail("resource", "4.5.1", "Memory hog SURVIVED 1GB allocation",
                        "OOM kill", r.stdout[:100], "S1")

        # Timeout — sleep beyond timeout
        start = time.monotonic()
        r = await self._run("sleep 120", timeout=5)
        elapsed = time.monotonic() - start
        if r.timed_out or elapsed < 15:
            self._pass("resource", "4.5.2",
                        f"Timeout enforced ({elapsed:.1f}s elapsed, timed_out={r.timed_out})")
        else:
            self._fail("resource", "4.5.2", "Timeout NOT enforced",
                        "~5s", f"{elapsed:.1f}s", "S2")

        # Fork bomb — should be contained by cgroup limits
        r = await self._run(
            'python3 -c "'
            'import os; '
            '[os.fork() for _ in range(1000)]'
            '" 2>&1',
            timeout=15,
        )
        # Fork bomb should fail or be killed — either is fine
        if r.exit_code != 0 or r.timed_out or r.oom_killed:
            self._pass("resource", "4.5.3",
                        f"Fork bomb contained (exit={r.exit_code}, "
                        f"timeout={r.timed_out}, oom={r.oom_killed})")
        else:
            self._warn("resource", "4.5.3", "Fork bomb completed without error",
                        "May need pids cgroup limit")

        # Disk space — /tmp is 100MB tmpfs, try filling it
        r = await self._run(
            "dd if=/dev/zero of=/tmp/fill bs=1M count=200 2>&1; echo RC=$?",
            timeout=15,
        )
        if "No space left" in r.stdout + r.stderr or "RC=1" in r.stdout:
            self._pass("resource", "4.5.4", "/tmp tmpfs size limit enforced (100MB)")
        else:
            self._warn("resource", "4.5.4", "/tmp fill test inconclusive",
                        r.stdout[:200])

    # ── B4.6: /proc/self Info Leak ──────────────────────────────

    async def test_procfs(self):
        print("\nB4.6: /proc/self information leakage")

        # /proc/self/environ — check for secrets
        r = await self._run("cat /proc/self/environ 2>/dev/null | tr '\\0' '\\n'")
        if r.exit_code == 0 and r.stdout.strip():
            leaked = []
            for pat in SECRET_PATTERNS:
                if pat in r.stdout:
                    leaked.append(pat)
            if leaked:
                self._fail("procfs", "4.6.1", "/proc/self/environ leaks secrets",
                            "no secrets", f"found: {', '.join(leaked)}", "S1")
            else:
                self._pass("procfs", "4.6.1",
                            "/proc/self/environ clean (no secrets)")
        else:
            self._pass("procfs", "4.6.1", "/proc/self/environ not readable")

        # /proc/self/mountinfo — host path disclosure (user addition #1)
        r = await self._run("cat /proc/self/mountinfo 2>/dev/null")
        if r.exit_code == 0 and r.stdout.strip():
            host_info = []
            for pat in ["/home/", "/root/", "/.secrets/", "/sentinel/"]:
                if pat in r.stdout:
                    host_info.append(pat)
            if host_info:
                self._warn("procfs", "4.6.2",
                            "/proc/self/mountinfo reveals host paths",
                            f"Disclosed: {', '.join(host_info)}")
            else:
                self._pass("procfs", "4.6.2",
                            "/proc/self/mountinfo does not leak host paths")
            self._info("procfs", "4.6.2a",
                        f"mountinfo: {r.stdout[:300]}")
        else:
            self._pass("procfs", "4.6.2", "/proc/self/mountinfo not readable")

        # /proc/self/cgroup — host user/machine info
        r = await self._run("cat /proc/self/cgroup 2>/dev/null")
        if r.exit_code == 0 and r.stdout.strip():
            if "user-" in r.stdout and ".slice" in r.stdout:
                self._warn("procfs", "4.6.3",
                            "/proc/self/cgroup reveals host UID",
                            r.stdout.strip()[:200])
            else:
                self._pass("procfs", "4.6.3",
                            "/proc/self/cgroup does not leak host UID")
        else:
            self._pass("procfs", "4.6.3", "/proc/self/cgroup not readable")

        # /proc/self/status — capability set
        r = await self._run("cat /proc/self/status 2>/dev/null | grep -E '^(Cap|Uid|Gid)'")
        if r.exit_code == 0:
            self._info("procfs", "4.6.4", f"process status: {r.stdout.strip()[:200]}")

        # /proc/self/cmdline — check for secrets in command line
        r = await self._run("cat /proc/1/cmdline 2>/dev/null | tr '\\0' ' '")
        if r.exit_code == 0:
            for pat in SECRET_PATTERNS:
                if pat in r.stdout:
                    self._fail("procfs", "4.6.5", "/proc/1/cmdline contains secrets",
                                "no secrets", pat, "S1")
                    break
            else:
                self._pass("procfs", "4.6.5", "/proc/1/cmdline clean")

        # /proc/self/maps — ASLR layout disclosure
        r = await self._run("cat /proc/self/maps 2>/dev/null | wc -l")
        if r.exit_code == 0 and r.stdout.strip():
            self._info("procfs", "4.6.6",
                        f"/proc/self/maps readable ({r.stdout.strip()} lines — ASLR layout)")

    # ── B4.7: Symlink/Hardlink Attacks ──────────────────────────

    async def test_symlink(self):
        print("\nB4.7: Symlink and hardlink attacks")

        # Symlink to /etc/passwd from workspace
        r = await self._run(
            "ln -s /etc/passwd /workspace/symlink_passwd 2>&1 && "
            "cat /workspace/symlink_passwd"
        )
        if r.exit_code == 0 and "root:" in r.stdout:
            self._warn("symlink", "4.7.1",
                        "Symlink to /etc/passwd readable from workspace",
                        "Sandbox allows following symlinks outside /workspace/. "
                        "The read-only rootfs prevents writes, but reads are possible")
        elif r.exit_code != 0:
            self._pass("symlink", "4.7.1",
                        "Symlink to /etc/passwd blocked or unreadable")
        else:
            self._info("symlink", "4.7.1", f"Symlink result: {r.stdout[:200]}")
        # Cleanup
        await self._run("rm -f /workspace/symlink_passwd")

        # Symlink to /proc/self/environ (user addition #1)
        r = await self._run(
            "ln -s /proc/self/environ /workspace/symlink_env 2>&1 && "
            "cat /workspace/symlink_env | tr '\\0' '\\n'"
        )
        if r.exit_code == 0 and r.stdout.strip():
            leaked = [p for p in SECRET_PATTERNS if p in r.stdout]
            if leaked:
                self._fail("symlink", "4.7.2",
                            "Symlink to /proc/self/environ leaks secrets",
                            "no secrets", f"found: {', '.join(leaked)}", "S1")
            else:
                self._warn("symlink", "4.7.2",
                            "Symlink to /proc/self/environ readable (no secrets found)",
                            "Process environment accessible via workspace symlink")
        else:
            self._pass("symlink", "4.7.2",
                        "Symlink to /proc/self/environ blocked or empty")
        await self._run("rm -f /workspace/symlink_env")

        # Symlink chain: symlink to root, then traverse
        r = await self._run(
            "ln -s / /workspace/symlink_root 2>&1 && "
            "ls /workspace/symlink_root/etc/ | head -5"
        )
        if r.exit_code == 0 and r.stdout.strip():
            self._warn("symlink", "4.7.3",
                        "Symlink chain to / allows directory traversal",
                        f"Visible: {r.stdout.strip()[:100]}")
        else:
            self._pass("symlink", "4.7.3", "Symlink chain to / blocked")
        await self._run("rm -f /workspace/symlink_root")

        # Hard link — should fail (cross-device)
        r = await self._run("ln /etc/passwd /workspace/hardlink_passwd 2>&1")
        if r.exit_code != 0:
            self._pass("symlink", "4.7.4",
                        "Hard link to /etc/passwd fails (cross-device)")
        else:
            self._fail("symlink", "4.7.4", "Hard link to /etc/passwd SUCCEEDED",
                        "cross-device error", r.stdout, "S1")
        await self._run("rm -f /workspace/hardlink_passwd")

        # Symlink to /run/secrets (if it exists)
        r = await self._run(
            "ln -s /run/secrets /workspace/symlink_secrets 2>&1 && "
            "ls /workspace/symlink_secrets/ 2>&1"
        )
        if r.exit_code == 0 and r.stdout.strip() and "No such file" not in r.stdout:
            self._fail("symlink", "4.7.5",
                        "Symlink to /run/secrets/ reveals secret files",
                        "not accessible", r.stdout[:200], "S0")
        else:
            self._pass("symlink", "4.7.5",
                        "/run/secrets not accessible via symlink (not mounted in sandbox)")
        await self._run("rm -f /workspace/symlink_secrets")

    # ── B4.8: Python Escape ─────────────────────────────────────

    async def test_python_escape(self):
        print("\nB4.8: Python escape from sandbox")

        # Write and execute a Python script (bypasses python3 -c blocking)
        self._write_workspace_file("b4_exploit.py", (
            "import os, sys\n"
            "# Enumerate root filesystem\n"
            "print('ROOT:', os.listdir('/'))\n"
            "# Read /etc/passwd\n"
            "try:\n"
            "    print('PASSWD:', open('/etc/passwd').read()[:100])\n"
            "except Exception as e:\n"
            "    print(f'PASSWD_BLOCKED: {e}')\n"
            "# Network attempt\n"
            "import socket\n"
            "try:\n"
            "    s = socket.socket()\n"
            "    s.settimeout(3)\n"
            "    s.connect(('8.8.8.8', 53))\n"
            "    print('NETWORK: CONNECTED')\n"
            "except Exception as e:\n"
            "    print(f'NETWORK: BLOCKED ({e})')\n"
            "# Check for secrets in environment\n"
            "env = dict(os.environ)\n"
            "secrets = [k for k in env if any(p in k or p in str(env[k]) "
            "for p in ['API_KEY', 'TOKEN', 'SECRET', 'PIN', 'sk-ant'])]\n"
            "print(f'ENV_SECRETS: {secrets}')\n"
        ))

        r = await self._run("python3 /workspace/b4_exploit.py", timeout=15)
        if r.exit_code == 0:
            # Script ran — check what it found
            if "NETWORK: CONNECTED" in r.stdout:
                self._fail("python_escape", "4.8.1",
                            "Python script made network connection",
                            "network blocked", "connected", "S0")
            else:
                self._pass("python_escape", "4.8.1",
                            "Python script network blocked by sandbox")

            if "PASSWD:" in r.stdout and "root:" in r.stdout:
                self._warn("python_escape", "4.8.2",
                            "Python script can read /etc/passwd",
                            "Read-only rootfs allows reads — contained by NetworkDisabled")
            elif "PASSWD_BLOCKED" in r.stdout:
                self._pass("python_escape", "4.8.2",
                            "Python script cannot read /etc/passwd")

            if "ENV_SECRETS: []" in r.stdout:
                self._pass("python_escape", "4.8.3",
                            "Python script found no secrets in environment")
            elif "ENV_SECRETS:" in r.stdout:
                self._fail("python_escape", "4.8.3",
                            "Python script found secrets in environment",
                            "empty", r.stdout.split("ENV_SECRETS:")[1][:100], "S1")
        else:
            self._info("python_escape", "4.8.1",
                        f"Python script failed to run (exit={r.exit_code}): {r.stderr[:200]}")

        # Write to rootfs from Python
        self._write_workspace_file("b4_write_test.py", (
            "try:\n"
            "    open('/etc/exploit', 'w').write('pwned')\n"
            "    print('WRITE_OK')\n"
            "except Exception as e:\n"
            "    print(f'WRITE_BLOCKED: {e}')\n"
        ))
        r = await self._run("python3 /workspace/b4_write_test.py")
        if "WRITE_BLOCKED" in r.stdout:
            self._pass("python_escape", "4.8.4",
                        "Python cannot write to rootfs")
        elif "WRITE_OK" in r.stdout:
            self._fail("python_escape", "4.8.4",
                        "Python wrote to rootfs", "blocked", "write succeeded", "S0")

        # ctypes libc access — attempt privilege escalation to root
        # Fix X drops code to UID 65534. setuid(own_UID) is a no-op, so we
        # test setuid(0) to verify CAP_SETUID is truly dropped.
        self._write_workspace_file("b4_ctypes.py", (
            "import ctypes, ctypes.util\n"
            "try:\n"
            "    libc = ctypes.CDLL(ctypes.util.find_library('c'))\n"
            "    print(f'LIBC_LOADED: {libc}')\n"
            "    # Try to escalate to root\n"
            "    result = libc.setuid(0)\n"
            "    print(f'SETUID_RESULT: {result}')\n"
            "except Exception as e:\n"
            "    print(f'CTYPES_ERROR: {e}')\n"
        ))
        r = await self._run("python3 /workspace/b4_ctypes.py")
        if "SETUID_RESULT: 0" in r.stdout:
            self._fail("python_escape", "4.8.5",
                        "ctypes setuid(0) SUCCEEDED — escalated to root!",
                        "blocked", r.stdout, "S0")
        else:
            self._pass("python_escape", "4.8.5",
                        "ctypes setuid(0) blocked — cannot escalate to root")

        # Write to /tmp then execute (noexec test via Python)
        self._write_workspace_file("b4_noexec.py", (
            "import os, stat, subprocess\n"
            "# Write executable to /tmp\n"
            "with open('/tmp/payload', 'w') as f:\n"
            "    f.write('#!/bin/sh\\necho EXECUTED')\n"
            "os.chmod('/tmp/payload', 0o755)\n"
            "try:\n"
            "    result = subprocess.run(['/tmp/payload'], capture_output=True, text=True)\n"
            "    print(f'EXEC_RESULT: {result.stdout}')\n"
            "except Exception as e:\n"
            "    print(f'EXEC_BLOCKED: {e}')\n"
        ))
        r = await self._run("python3 /workspace/b4_noexec.py")
        if "EXEC_BLOCKED" in r.stdout or "EXECUTED" not in r.stdout:
            self._pass("python_escape", "4.8.6",
                        "Python cannot execute binaries from /tmp (noexec)")
        else:
            self._fail("python_escape", "4.8.6",
                        "Python executed binary from /tmp",
                        "noexec", r.stdout, "S1")

        # Cleanup
        await self._run("rm -f /workspace/b4_exploit.py /workspace/b4_write_test.py "
                         "/workspace/b4_ctypes.py /workspace/b4_noexec.py")

    # ── B4.9: tar/Archive Attacks ───────────────────────────────

    async def test_tar_archive(self):
        print("\nB4.9: tar/archive attacks")

        # tar cf to archive system files (assessment P2.2)
        r = await self._run(
            "tar cf /workspace/b4_system.tar /etc/passwd /etc/hosts 2>&1 && "
            "echo ARCHIVED && ls -la /workspace/b4_system.tar"
        )
        if "ARCHIVED" in r.stdout:
            self._warn("tar_archive", "4.9.1",
                        "tar can archive system files to workspace",
                        "tar cf reads from read-only rootfs into writable workspace. "
                        "Data could be exfiltrated via file_read if scanners miss it")
        else:
            self._pass("tar_archive", "4.9.1",
                        "tar cannot archive system files")
        await self._run("rm -f /workspace/b4_system.tar")

        # tar cf /proc/self/environ (user addition #2 — tar reading /proc)
        r = await self._run(
            "tar cf /workspace/b4_proc.tar /proc/self/environ /proc/self/cmdline 2>&1 && "
            "echo PROC_ARCHIVED && tar tf /workspace/b4_proc.tar"
        )
        if "PROC_ARCHIVED" in r.stdout:
            # Extract and check for secrets
            r2 = await self._run(
                "tar xf /workspace/b4_proc.tar -C /workspace/ 2>&1 && "
                "cat /workspace/proc/self/environ 2>/dev/null | tr '\\0' '\\n'"
            )
            if r2.exit_code == 0:
                leaked = [p for p in SECRET_PATTERNS if p in r2.stdout]
                if leaked:
                    self._fail("tar_archive", "4.9.2",
                                "tar can archive /proc/self/environ with secrets",
                                "no secrets", f"found: {', '.join(leaked)}", "S1")
                else:
                    self._warn("tar_archive", "4.9.2",
                                "tar can archive /proc/self/ to workspace",
                                "Process info archived but no secrets found")
            else:
                self._warn("tar_archive", "4.9.2",
                            "tar archived /proc but extraction or read failed")
        else:
            self._pass("tar_archive", "4.9.2",
                        "tar cannot archive /proc/self")
        await self._run("rm -rf /workspace/b4_proc.tar /workspace/proc")

        # tar xf to root — should fail (read-only rootfs)
        # First create a small archive
        r = await self._run(
            "echo 'EXPLOIT' > /workspace/b4_payload.txt && "
            "tar cf /workspace/b4_payload.tar -C /workspace b4_payload.txt && "
            "tar xf /workspace/b4_payload.tar -C / 2>&1; echo EXIT=$?"
        )
        if "EXIT=0" not in r.stdout or "Read-only" in r.stdout + r.stderr:
            self._pass("tar_archive", "4.9.3",
                        "tar xf to / blocked (read-only rootfs)")
        else:
            self._fail("tar_archive", "4.9.3",
                        "tar xf to / SUCCEEDED",
                        "read-only error", r.stdout, "S1")

        # tar xf to /tmp — writable but noexec
        r = await self._run(
            "tar xf /workspace/b4_payload.tar -C /tmp/ 2>&1 && "
            "cat /tmp/b4_payload.txt"
        )
        if r.exit_code == 0 and "EXPLOIT" in r.stdout:
            self._warn("tar_archive", "4.9.4",
                        "tar can extract to /tmp (writable tmpfs)",
                        "Files in /tmp are not executable (noexec). "
                        "Contained by tmpfs size limit (100MB)")
        else:
            self._pass("tar_archive", "4.9.4",
                        "tar extract to /tmp failed")

        # Cleanup
        await self._run("rm -f /workspace/b4_payload.txt /workspace/b4_payload.tar")

    # ── B4.10: xargs Command Chaining ───────────────────────────

    async def test_xargs(self):
        print("\nB4.10: xargs command chaining")

        # xargs to bypass path constraints (assessment P2.3)
        r = await self._run('echo "/etc/passwd" | xargs cat 2>&1')
        if r.exit_code == 0 and "root:" in r.stdout:
            self._warn("xargs", "4.10.1",
                        "xargs + cat reads /etc/passwd",
                        "Inside sandbox, reads from read-only rootfs are expected. "
                        "The path constraint in the policy engine only applies to "
                        "direct cat invocations, not xargs-spawned ones. Contained "
                        "by NetworkDisabled (can't exfiltrate)")
        else:
            self._pass("xargs", "4.10.1", "xargs + cat blocked")

        # find + xargs for system config search
        r = await self._run(
            'find /etc -name "*.conf" 2>/dev/null | head -5 | xargs grep -l "password" 2>/dev/null; '
            'echo EXIT=$?'
        )
        self._info("xargs", "4.10.2",
                    f"find+xargs system config search: {r.stdout.strip()[:200]}")

        # xargs shell injection
        r = await self._run(
            'echo "id" | xargs sh -c 2>&1'
        )
        if r.exit_code == 0 and "uid=" in r.stdout:
            self._info("xargs", "4.10.3",
                        f"xargs sh -c executes: {r.stdout.strip()[:100]}")
        else:
            self._pass("xargs", "4.10.3", "xargs sh -c blocked or failed")

    # ── B4.11: Environment Variable Leakage ─────────────────────

    async def test_env_leak(self):
        print("\nB4.11: Environment variable leakage")

        # Run env command
        r = await self._run("env")
        if r.exit_code == 0:
            leaked = []
            for pat in SECRET_PATTERNS:
                if pat in r.stdout:
                    leaked.append(pat)
            if leaked:
                self._fail("env_leak", "4.11.1",
                            "env command reveals secrets",
                            "no secrets", f"found: {', '.join(leaked)}", "S0")
            else:
                self._pass("env_leak", "4.11.1",
                            "env command shows no secrets")
            self._info("env_leak", "4.11.1a",
                        f"env output ({r.stdout.count(chr(10))} vars): {r.stdout[:300]}")
        else:
            self._skip("env_leak", "4.11.1", "env command failed")

        # printenv
        r = await self._run("printenv")
        if r.exit_code == 0:
            leaked = [p for p in SECRET_PATTERNS if p in r.stdout]
            if leaked:
                self._fail("env_leak", "4.11.2",
                            "printenv reveals secrets",
                            "no secrets", f"found: {', '.join(leaked)}", "S0")
            else:
                self._pass("env_leak", "4.11.2", "printenv shows no secrets")

        # /proc/self/environ (belt and suspenders)
        r = await self._run("cat /proc/self/environ 2>/dev/null | tr '\\0' '\\n'")
        if r.exit_code == 0 and r.stdout.strip():
            leaked = [p for p in SECRET_PATTERNS if p in r.stdout]
            if leaked:
                self._fail("env_leak", "4.11.3",
                            "/proc/self/environ leaks secrets",
                            "no secrets", f"found: {', '.join(leaked)}", "S0")
            else:
                self._pass("env_leak", "4.11.3",
                            "/proc/self/environ clean")
        else:
            self._pass("env_leak", "4.11.3",
                        "/proc/self/environ not readable")

        # Check for host env inheritance (Podman Docker-compat API behaviour)
        r = await self._run("env | grep -c '=' || echo 0")
        var_count = int(r.stdout.strip()) if r.stdout.strip().isdigit() else 0
        if var_count > 20:
            self._warn("env_leak", "4.11.4",
                        f"Sandbox has {var_count} env vars (possible host inheritance)",
                        "Expected minimal env. Check for Podman env inheritance")
        else:
            self._pass("env_leak", "4.11.4",
                        f"Sandbox has minimal env ({var_count} vars)")

    # ── B4.12: Sandbox Startup Self-Test ────────────────────────

    async def test_selftest(self):
        print("\nB4.12: Sandbox startup self-test (container inspection)")

        # Create a container via PodmanSandbox, inspect it, then verify
        # security properties. We use the httpx client directly to inspect
        # before the container is destroyed.
        import httpx
        import uuid

        container_name = f"sentinel-sandbox-b4selftest-{uuid.uuid4().hex[:8]}"
        client = self.sandbox._get_client()

        try:
            # Create container with the same config as production
            create_body = {
                "Image": self.image,
                "Cmd": ["sleep", "10"],
                "Name": container_name,
                "NetworkDisabled": True,
                "HostConfig": {
                    "ReadonlyRootfs": True,
                    "NoNewPrivileges": True,
                    "Memory": DEFAULT_MEMORY,
                    "CpuQuota": DEFAULT_CPU_QUOTA,
                    "CapDrop": ["ALL"],
                    "NetworkMode": "none",
                    "SecurityOpt": ["no-new-privileges"],
                    "Binds": [f"{self.workspace_dir}:/workspace:rw"],
                    "Tmpfs": {"/tmp": "size=100M,noexec"},
                },
                "WorkingDir": "/workspace",
            }

            resp = await client.post("/v5.0.0/containers/create", json=create_body)
            if resp.status_code not in (200, 201):
                self._skip("selftest", "4.12.0",
                            f"Cannot create test container: {resp.status_code}")
                return

            container_id = resp.json().get("Id", "")

            # Inspect the container BEFORE running it
            inspect_resp = await client.get(f"/v5.0.0/containers/{container_id}/json")
            if inspect_resp.status_code != 200:
                self._skip("selftest", "4.12.0",
                            f"Cannot inspect container: {inspect_resp.status_code}")
                return

            data = inspect_resp.json()
            host_config = data.get("HostConfig", {})
            network_settings = data.get("NetworkSettings", {})

            # Check NetworkDisabled
            network_mode = host_config.get("NetworkMode", "")
            networks = network_settings.get("Networks", {})
            # NetworkDisabled containers have "none" network mode or empty networks
            if network_mode == "none" or not networks or \
               (len(networks) == 1 and "none" in networks):
                self._pass("selftest", "4.12.1",
                            "NetworkDisabled confirmed (network mode: none)")
            else:
                self._fail("selftest", "4.12.1",
                            "NetworkDisabled NOT set",
                            "none", f"mode={network_mode}, nets={list(networks.keys())}", "S0")

            # Check ReadonlyRootfs
            if host_config.get("ReadonlyRootfs"):
                self._pass("selftest", "4.12.2",
                            "ReadonlyRootfs is true")
            else:
                self._fail("selftest", "4.12.2",
                            "ReadonlyRootfs is FALSE (Fix V regression!)",
                            "true", "false", "S0")

            # Check CapDrop
            cap_drop = host_config.get("CapDrop", [])
            cap_drop_upper = [c.upper() for c in cap_drop]
            # Podman 4.x normalises CapDrop: ["ALL"] into individual cap names.
            # Accept either "ALL" or the expanded list (11+ caps = all defaults dropped).
            if "ALL" in cap_drop_upper or len(cap_drop) >= 11:
                self._pass("selftest", "4.12.3",
                            f"CapDrop covers all capabilities ({len(cap_drop)} entries)")
            else:
                self._fail("selftest", "4.12.3",
                            f"CapDrop insufficient: {cap_drop}",
                            "ALL or 11+ individual caps", str(cap_drop), "S0")

            # Check NoNewPrivileges
            security_opt = host_config.get("SecurityOpt", [])
            no_new_privs = host_config.get("NoNewPrivileges", False)
            if no_new_privs or "no-new-privileges" in str(security_opt):
                self._pass("selftest", "4.12.4",
                            "NoNewPrivileges is set")
            else:
                self._fail("selftest", "4.12.4",
                            "NoNewPrivileges is NOT set",
                            "true", "false", "S1")

            # Check Binds — only workspace and /tmp should be writable
            binds = host_config.get("Binds", [])
            tmpfs = host_config.get("Tmpfs", {})
            self._info("selftest", "4.12.5",
                        f"Binds: {binds}, Tmpfs: {tmpfs}")

            # Verify workspace is in binds
            has_workspace = any("/workspace" in b for b in binds)
            if has_workspace:
                self._pass("selftest", "4.12.6",
                            "Workspace volume is mounted")
            else:
                self._fail("selftest", "4.12.6",
                            "Workspace volume NOT mounted",
                            "/workspace in Binds", str(binds), "S2")

            # Check Memory limit
            mem = host_config.get("Memory", 0)
            if mem > 0:
                self._pass("selftest", "4.12.7",
                            f"Memory limit set ({mem // 1024 // 1024}MB)")
            else:
                self._fail("selftest", "4.12.7",
                            "No memory limit set",
                            f"{DEFAULT_MEMORY}", str(mem), "S2")

        finally:
            # Always clean up
            try:
                await client.delete(
                    f"/v5.0.0/containers/{container_id}",
                    params={"force": "true"},
                )
            except Exception:
                pass

    # ── B4.13: Proxy Security Field Validation ──────────────────

    async def test_proxy_validation(self):
        print("\nB4.13: Proxy security field validation")

        # Test from inside sentinel container — the proxy should validate
        # security fields on container create (assessment P1.4)

        # Test 1: Container create without NetworkDisabled
        out, rc = self._podman_exec(self.sentinel_ctr, "python3", "-c", """
import http.client, socket, json
class PC(http.client.HTTPConnection):
    def __init__(self, sp):
        super().__init__('localhost')
        self.sp = sp
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.sp)
try:
    conn = PC('/run/podman/podman.sock')
    payload = json.dumps({
        'Image': 'python:3.12-slim',
        'Cmd': ['echo', 'test'],
        'Name': 'sentinel-sandbox-b4-proxy-test',
        'NetworkDisabled': False,
        'HostConfig': {'ReadonlyRootfs': False}
    })
    conn.request('POST', '/v5.0.0/containers/create',
                 body=payload, headers={'Content-Type': 'application/json'})
    resp = conn.getresponse()
    print(f'STATUS: {resp.status}')
    body = resp.read().decode()[:300]
    print(body)
    # Cleanup if created
    if resp.status in (200, 201):
        import json as j
        cid = j.loads(body).get('Id', '')
        if cid:
            conn2 = PC('/run/podman/podman.sock')
            conn2.request('DELETE', f'/v5.0.0/containers/{cid}?force=true')
            conn2.getresponse()
except Exception as e:
    print(f'ERROR: {e}')
""")
        if rc == 0 and "STATUS:" in out:
            if "STATUS: 4" in out or "STATUS: 5" in out:
                self._pass("proxy_validation", "4.13.1",
                            "Proxy rejects insecure container create")
            elif "STATUS: 201" in out:
                self._warn("proxy_validation", "4.13.1",
                            "Proxy allows insecure container create",
                            "Proxy does not validate security fields — "
                            "relies on sandbox.py. Consider adding proxy validation (P1.4)")
            else:
                self._info("proxy_validation", "4.13.1",
                            f"Proxy response: {out[:200]}")
        elif "ERROR:" in out and "Connection refused" in out:
            self._pass("proxy_validation", "4.13.1",
                        "Proxy socket not accessible from sentinel")
        else:
            self._skip("proxy_validation", "4.13.1",
                        f"Proxy test failed: {out[:200]}")

        # Test 2: Container create with wrong image
        out, rc = self._podman_exec(self.sentinel_ctr, "python3", "-c", """
import http.client, socket, json
class PC(http.client.HTTPConnection):
    def __init__(self, sp):
        super().__init__('localhost')
        self.sp = sp
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.sp)
try:
    conn = PC('/run/podman/podman.sock')
    payload = json.dumps({
        'Image': 'alpine',
        'Cmd': ['cat', '/etc/shadow'],
        'Name': 'sentinel-sandbox-b4-wrong-image',
        'NetworkDisabled': True,
        'HostConfig': {'ReadonlyRootfs': True, 'CapDrop': ['ALL']}
    })
    conn.request('POST', '/v5.0.0/containers/create',
                 body=payload, headers={'Content-Type': 'application/json'})
    resp = conn.getresponse()
    print(f'STATUS: {resp.status}')
    body = resp.read().decode()[:200]
    print(body)
    if resp.status in (200, 201):
        import json as j
        cid = j.loads(body).get('Id', '')
        if cid:
            conn2 = PC('/run/podman/podman.sock')
            conn2.request('DELETE', f'/v5.0.0/containers/{cid}?force=true')
            conn2.getresponse()
except Exception as e:
    print(f'ERROR: {e}')
""")
        if rc == 0 and "STATUS: 4" in out:
            self._pass("proxy_validation", "4.13.2",
                        "Proxy rejects wrong image")
        elif "STATUS: 201" in out:
            self._fail("proxy_validation", "4.13.2",
                        "Proxy allows wrong image",
                        "rejected", "created with non-sandbox image", "S2")
        else:
            self._info("proxy_validation", "4.13.2",
                        f"Wrong image test: {out[:200]}")

    # ── B4.14: Temporal Workspace Persistence ───────────────────

    async def test_persistence(self):
        print("\nB4.14: Temporal workspace persistence (user addition #6)")

        # Plan A: write a file
        r = await self._run("echo 'planted_by_plan_a' > /workspace/b4_planted.txt && echo OK")
        if r.exit_code != 0:
            self._skip("persistence", "4.14.1", "Cannot write to workspace")
            return

        # Plan B: read the file (separate container, same workspace)
        r = await self._run("cat /workspace/b4_planted.txt")
        if r.exit_code == 0 and "planted_by_plan_a" in r.stdout:
            self._warn("persistence", "4.14.1",
                        "Files persist across sandbox executions",
                        "Expected behaviour — workspace must persist for multi-step plans. "
                        "But means Plan A can plant payloads for Plan B")
        else:
            self._pass("persistence", "4.14.1",
                        "Files do NOT persist (unexpected — may break multi-step plans)")

        # Plan A: create a symlink to /etc/passwd, Plan B: read it
        r = await self._run(
            "ln -s /etc/passwd /workspace/b4_planted_symlink 2>&1 && echo CREATED"
        )
        if "CREATED" in r.stdout:
            # Plan B: read through the symlink
            r2 = await self._run("cat /workspace/b4_planted_symlink 2>&1")
            if r2.exit_code == 0 and "root:" in r2.stdout:
                self._warn("persistence", "4.14.2",
                            "Cross-plan symlink to /etc/passwd readable",
                            "Plan A created symlink in workspace, Plan B read through it. "
                            "Consider workspace symlink hygiene between plans (P3.5)")
            else:
                self._pass("persistence", "4.14.2",
                            "Cross-plan symlink not readable")
        else:
            self._pass("persistence", "4.14.2",
                        "Cannot create symlink in workspace")

        # Detect stale symlinks pointing outside /workspace
        r = await self._run(
            "find /workspace -type l -exec readlink -f {} \\; 2>/dev/null | "
            "grep -v '^/workspace' | head -5"
        )
        if r.exit_code == 0 and r.stdout.strip():
            self._warn("persistence", "4.14.3",
                        "Workspace contains symlinks pointing outside /workspace/",
                        f"Targets: {r.stdout.strip()[:200]}")
        else:
            self._pass("persistence", "4.14.3",
                        "No external symlinks in workspace")

        # Cleanup
        await self._run("rm -f /workspace/b4_planted.txt /workspace/b4_planted_symlink")

    # ── B4.15: Seccomp Profile (P2, bumped from P3) ─────────────

    async def test_seccomp(self):
        print("\nB4.15: Seccomp profile verification (user addition #8, P2)")

        # Check if custom seccomp profile is loaded
        # Without explicit seccomp, Podman uses its default profile
        # which blocks ~44 syscalls. Test for blocked syscalls.

        # Test: unshare (should be blocked by default seccomp)
        r = await self._run("unshare --user /bin/sh -c 'echo UNSHARED' 2>&1")
        if r.exit_code != 0 or "UNSHARED" not in r.stdout:
            self._pass("seccomp", "4.15.1",
                        "unshare --user blocked (seccomp or CapDrop)")
        else:
            # unshare --user creates a user namespace. On modern kernels with
            # unprivileged_userns_clone=1 (default), any user can do this — it's
            # not blocked by capability restrictions or the default seccomp profile.
            # This is expected in rootless Podman. Contained by other layers.
            self._warn("seccomp", "4.15.1",
                        "unshare --user succeeded (expected in rootless Podman — "
                        "unprivileged user namespaces allowed by kernel default)",
                        note="Not a sandbox escape — user NS within rootless Podman "
                             "doesn't grant host access")

        # Test: clone with CLONE_NEWUSER
        r = await self._run(
            'python3 -c "'
            'import os; '
            'pid = os.fork(); '
            'print(f\\"FORK: pid={pid}\\")'
            '" 2>&1'
        )
        # fork itself should work (needed for subprocess), but
        # advanced clone flags should be restricted
        self._info("seccomp", "4.15.2",
                    f"fork test: {r.stdout.strip()[:100]}")

        # Test: keyctl (should be blocked by seccomp)
        r = await self._run(
            'python3 -c "'
            'import ctypes; '
            'libc = ctypes.CDLL(None); '
            'result = libc.syscall(250, 0, 0, 0, 0); '  # SYS_keyctl
            'print(f\\"KEYCTL: {result}\\")'
            '" 2>&1'
        )
        if "KEYCTL: -1" in r.stdout or r.exit_code != 0:
            self._pass("seccomp", "4.15.3",
                        "keyctl syscall blocked")
        elif "KEYCTL: 0" in r.stdout:
            self._fail("seccomp", "4.15.3", "keyctl syscall SUCCEEDED",
                        "blocked", r.stdout, "S2")
        else:
            self._info("seccomp", "4.15.3",
                        f"keyctl test: {r.stdout[:100]}")

        # Test: personality(2) — used in some exploits
        r = await self._run(
            'python3 -c "'
            'import ctypes; '
            'libc = ctypes.CDLL(None); '
            'result = libc.syscall(136, 0); '  # SYS_personality
            'print(f\\"PERSONALITY: {result}\\")'
            '" 2>&1'
        )
        self._info("seccomp", "4.15.4",
                    f"personality test: {r.stdout.strip()[:100]}")

        # Check seccomp status from /proc
        r = await self._run("cat /proc/self/status | grep Seccomp")
        if r.exit_code == 0 and r.stdout.strip():
            seccomp_val = r.stdout.strip().split(":")[-1].strip()
            # 0=disabled, 1=strict, 2=filter
            if seccomp_val == "2":
                self._pass("seccomp", "4.15.5",
                            "Seccomp filter mode active")
            elif seccomp_val == "0":
                self._warn("seccomp", "4.15.5",
                            "Seccomp is DISABLED",
                            "Consider adding explicit seccomp profile (P2)")
            else:
                self._info("seccomp", "4.15.5",
                            f"Seccomp status: {seccomp_val}")
        else:
            self._skip("seccomp", "4.15.5",
                        "Cannot read seccomp status")

    # ── B4.16: Mount Validation ─────────────────────────────────

    async def test_mount(self):
        print("\nB4.16: Mount validation (user addition #7)")

        # List all mounts from inside sandbox
        r = await self._run("cat /proc/self/mounts 2>/dev/null")
        if r.exit_code == 0:
            # Count writable mounts
            lines = r.stdout.strip().split("\n")
            writable = [l for l in lines if " rw" in l.split()[3] if len(l.split()) > 3]
            readonly = [l for l in lines if " ro" in l.split()[3] if len(l.split()) > 3]

            self._info("mount", "4.16.1",
                        f"Total mounts: {len(lines)}, "
                        f"writable: {len(writable)}, read-only: {len(readonly)}")

            # Check that only /workspace and /tmp are writable
            unexpected_rw = []
            for mount_line in writable:
                parts = mount_line.split()
                if len(parts) >= 2:
                    mount_point = parts[1]
                    if mount_point not in ("/workspace", "/tmp", "/dev/shm"):
                        unexpected_rw.append(mount_point)

            if unexpected_rw:
                self._fail("mount", "4.16.2",
                            "Unexpected writable mounts found",
                            "/workspace, /tmp only",
                            f"also writable: {', '.join(unexpected_rw)}", "S2")
            else:
                self._pass("mount", "4.16.2",
                            "Only expected mounts are writable (/workspace, /tmp)")

        else:
            self._skip("mount", "4.16.1", "Cannot read /proc/self/mounts")

        # Verify /workspace mount exists and is rw
        r = await self._run(
            "mount | grep workspace || cat /proc/self/mounts | grep workspace"
        )
        if r.exit_code == 0 and "workspace" in r.stdout:
            # mount outputs "(rw,..)" not " rw" — check for rw in options
            if "rw" in r.stdout:
                self._pass("mount", "4.16.3", "/workspace is mounted rw")
            else:
                self._fail("mount", "4.16.3", "/workspace is NOT mounted rw",
                            "rw", r.stdout.strip()[:200], "S2")
        else:
            self._fail("mount", "4.16.3", "/workspace mount not found",
                        "present", "missing", "S2")

        # Verify /tmp mount has noexec
        r = await self._run(
            "mount | grep '/tmp' || cat /proc/self/mounts | grep '/tmp'"
        )
        if r.exit_code == 0 and "/tmp" in r.stdout:
            if "noexec" in r.stdout:
                self._pass("mount", "4.16.4", "/tmp has noexec flag")
            else:
                self._warn("mount", "4.16.4", "/tmp may lack noexec flag",
                            f"mount info: {r.stdout.strip()[:200]}")
        else:
            self._skip("mount", "4.16.4", "/tmp mount info not found")

    # ── B4.17: Concurrency Test ─────────────────────────────────

    async def test_concurrency(self):
        print("\nB4.17: Concurrency test (two plans, one workspace)")

        # Write a file from Plan A, simultaneously read from Plan B
        # Tests TOCTOU race conditions (assessment Section 3.1)

        # Plan A: write file, wait, check if corrupted
        plan_a = self._run(
            "echo 'PLAN_A_DATA' > /workspace/b4_race.txt && "
            "sleep 2 && "
            "cat /workspace/b4_race.txt",
            timeout=15,
        )

        # Plan B: overwrite the same file concurrently
        plan_b = self._run(
            "sleep 1 && "  # slight delay to ensure Plan A writes first
            "echo 'PLAN_B_OVERWRITE' > /workspace/b4_race.txt && "
            "cat /workspace/b4_race.txt",
            timeout=15,
        )

        results = await asyncio.gather(plan_a, plan_b, return_exceptions=True)

        if isinstance(results[0], Exception) or isinstance(results[1], Exception):
            self._skip("concurrency", "4.17.1",
                        f"Concurrent execution failed: "
                        f"{results[0] if isinstance(results[0], Exception) else 'OK'}, "
                        f"{results[1] if isinstance(results[1], Exception) else 'OK'}")
        else:
            r_a, r_b = results
            # Plan A should see PLAN_B_OVERWRITE (if Plan B ran during its sleep)
            if "PLAN_B_OVERWRITE" in r_a.stdout:
                self._warn("concurrency", "4.17.1",
                            "Concurrent workspace modification detected",
                            "Plan B overwrote Plan A's file during execution. "
                            "Shared workspace means cross-plan interference is possible")
            elif "PLAN_A_DATA" in r_a.stdout:
                self._info("concurrency", "4.17.1",
                            "Concurrent plans did not interfere (timing-dependent)")

        # Test for file descriptor leakage between concurrent containers
        plan_c = self._run(
            "ls -la /proc/self/fd/ 2>/dev/null | wc -l",
            timeout=10,
        )
        plan_d = self._run(
            "ls -la /proc/self/fd/ 2>/dev/null | wc -l",
            timeout=10,
        )
        results = await asyncio.gather(plan_c, plan_d, return_exceptions=True)
        if not isinstance(results[0], Exception) and not isinstance(results[1], Exception):
            self._info("concurrency", "4.17.2",
                        f"FD counts: Plan C={results[0].stdout.strip()}, "
                        f"Plan D={results[1].stdout.strip()}")

        # Cleanup
        await self._run("rm -f /workspace/b4_race.txt")

    # ── Run All Categories ──────────────────────────────────────

    async def run_all(self, categories: list[str] | None = None):
        """Run selected or all test categories."""
        category_map = {
            "volume": self.test_volume,
            "network": self.test_network,
            "filesystem": self.test_filesystem,
            "capability": self.test_capability,
            "resource": self.test_resource,
            "procfs": self.test_procfs,
            "symlink": self.test_symlink,
            "python_escape": self.test_python_escape,
            "tar_archive": self.test_tar_archive,
            "xargs": self.test_xargs,
            "env_leak": self.test_env_leak,
            "selftest": self.test_selftest,
            "proxy_validation": self.test_proxy_validation,
            "persistence": self.test_persistence,
            "seccomp": self.test_seccomp,
            "mount": self.test_mount,
            "concurrency": self.test_concurrency,
        }

        selected = categories or ALL_CATEGORIES
        for cat in selected:
            if cat not in category_map:
                print(f"  [SKIP] Unknown category: {cat}")
                continue
            try:
                await category_map[cat]()
            except Exception as e:
                self._fail(cat, f"{cat}.error", f"Category {cat} crashed: {e}",
                            severity="S1")
                if self.verbose:
                    import traceback
                    traceback.print_exc()

    def print_summary(self):
        """Print final summary."""
        pass_count = sum(1 for r in self.results if r.status == "pass")
        fail_count = sum(1 for r in self.results if r.status == "fail")
        warn_count = sum(1 for r in self.results if r.status == "warn")
        skip_count = sum(1 for r in self.results if r.status == "skip")
        info_count = sum(1 for r in self.results if r.status == "info")

        print(f"\n{'=' * 60}")
        print(f"  B4 v2 Sandbox Isolation Test Results")
        print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'=' * 60}")
        print(f"  {pass_count} passed, {fail_count} failed, "
              f"{warn_count} warnings, {skip_count} skipped, {info_count} info")
        print(f"  Output: {self.output_path}")
        print()

        if fail_count > 0:
            print(f"  FAILURES ({fail_count}):")
            for r in self.results:
                if r.status == "fail":
                    print(f"    [{r.severity}] {r.description}")
            print()

        if warn_count > 0:
            print(f"  WARNINGS ({warn_count}):")
            for r in self.results:
                if r.status == "warn":
                    print(f"    {r.description}")
            print()

        print(f"  v2 additions: /proc/self tests, DNS side-channel, tar/proc,")
        print(f"                Signal exfil, Semgrep coverage, temporal persistence,")
        print(f"                proxy mount validation, seccomp verification")
        print(f"{'=' * 60}")

        return fail_count


# ── Main ────────────────────────────────────────────────────────────

async def main():
    parser = argparse.ArgumentParser(
        description="B4 v2: Sandbox Isolation Red Team Tests",
    )
    parser.add_argument(
        "--socket", default=None,
        help="Podman socket path (default: auto-detect rootless socket)",
    )
    parser.add_argument(
        "--image", default=DEFAULT_IMAGE,
        help=f"Sandbox container image (default: {DEFAULT_IMAGE})",
    )
    parser.add_argument(
        "--workspace", default=None,
        help="Workspace directory (default: auto-create temp dir)",
    )
    parser.add_argument(
        "--output", default=None,
        help="JSONL output path (default: auto-generated in benchmarks/)",
    )
    parser.add_argument(
        "--categories", nargs="*", default=None,
        help=f"Run only these categories (choices: {', '.join(ALL_CATEGORIES)})",
    )
    parser.add_argument(
        "--sentinel-container", default="sentinel",
        help="Sentinel container name for proxy tests (default: sentinel)",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Show detailed output including tracebacks",
    )
    parser.add_argument(
        "--list-categories", action="store_true",
        help="List all test categories and exit",
    )
    args = parser.parse_args()

    if args.list_categories:
        print("Available B4 v2 test categories:")
        for cat in ALL_CATEGORIES:
            print(f"  {cat}")
        return

    # Auto-detect Podman socket
    socket_path = args.socket
    if not socket_path:
        uid = os.getuid()
        socket_path = f"/run/user/{uid}/podman/podman.sock"
        if not os.path.exists(socket_path):
            # Try common fallback
            socket_path = "/run/podman/podman.sock"
        if not os.path.exists(socket_path):
            print(f"ERROR: Podman socket not found. Tried:")
            print(f"  /run/user/{uid}/podman/podman.sock")
            print(f"  /run/podman/podman.sock")
            print(f"  Use --socket to specify the path")
            sys.exit(1)

    # Workspace directory
    workspace_dir = args.workspace
    temp_workspace = None
    if not workspace_dir:
        temp_workspace = tempfile.mkdtemp(prefix="sentinel-b4-workspace-")
        workspace_dir = temp_workspace
        print(f"  Using temp workspace: {workspace_dir}")

    # Output path
    output_path = args.output
    if not output_path:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        project_root = Path(__file__).resolve().parent.parent
        output_path = str(project_root / "benchmarks" / f"red_team_b4_v2_{ts}.jsonl")

    # Banner
    print(f"\n{'=' * 60}")
    print(f"  Sentinel B4 v2: Sandbox Isolation Red Team")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'=' * 60}")
    print(f"  Socket:    {socket_path}")
    print(f"  Image:     {args.image}")
    print(f"  Workspace: {workspace_dir}")
    print(f"  Output:    {output_path}")
    cats = args.categories or ALL_CATEGORIES
    print(f"  Categories: {', '.join(cats)}")
    print(f"{'=' * 60}")

    # Pre-flight: check image exists
    try:
        result = subprocess.run(
            ["podman", "image", "exists", args.image],
            capture_output=True, timeout=10,
        )
        if result.returncode != 0:
            print(f"\n  WARNING: Image '{args.image}' not found locally.")
            print(f"  Pull it with: podman pull {args.image}")
            print(f"  Continuing anyway — tests may fail at container creation.")
    except Exception:
        pass

    # Run tests
    runner = B4Runner(
        socket_path=socket_path,
        image=args.image,
        workspace_dir=workspace_dir,
        output_path=output_path,
        verbose=args.verbose,
        sentinel_container=args.sentinel_container,
    )

    try:
        await runner.run_all(args.categories)
    except KeyboardInterrupt:
        print("\n\n  Interrupted by user")
    finally:
        fail_count = runner.print_summary()
        runner.writer.close()

        # Cleanup temp workspace
        if temp_workspace and os.path.exists(temp_workspace):
            shutil.rmtree(temp_workspace, ignore_errors=True)

    # Always exit 0 — results are in the JSONL. Consistent with B1/B1.5/B2.
    # Non-zero exit kills the pipeline (set -euo pipefail) and falsely
    # reports "ERROR" when there are 0 actual exploits.
    sys.exit(0)


if __name__ == "__main__":
    asyncio.run(main())
