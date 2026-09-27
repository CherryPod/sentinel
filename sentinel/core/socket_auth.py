"""Q13.fix.f — Unix socket peer authentication + runtime-dir validation.

Centralised helpers for the two peer-authenticated Unix sockets in Sentinel:
sidecar (sentinel/tools/sidecar.py) and signal-cli (sentinel/channels/signal_channel.py).
Design: docs/hardening/2026-04-20-hardening-Q13-protocol-auth-findings.md §Design Cluster 2.

Two helpers:

* ``_assert_peer_uid(writer, path, module_event_prefix)`` — run after every
  ``open_unix_connection`` succeeds; reads SO_PEERCRED and raises
  ``PermissionError`` on UID mismatch. Callers handle the PermissionError
  per their subsystem's fail-closed semantics (sidecar returns a failure
  SidecarResponse without retry; signal resets ``_reader/_writer=None``
  and lets the caller drive backoff).

* ``validate_runtime_dir(path, expected_uid)`` — invoked once at controller
  startup from ``sentinel/api/init/orchestrator.py`` (sidecar path) and
  ``sentinel/api/init/channels.py`` (signal path) BEFORE client instantiation.
  Fail-closed: raises ``RuntimeError`` on any of (missing, not-a-directory,
  mode != 0700, owner UID mismatch). Callers skip channel registration on
  RuntimeError — the channel stays disabled rather than binding a weaker
  socket. Does NOT run inside SidecarClient / SignalChannel constructors or
  per-connect code paths, so unit tests using /tmp/ fixtures remain valid.

Per-transport event-name prefixes are passed in via ``module_event_prefix``
so callers retain their existing ``sidecar.peer_uid`` / ``signal.peer_uid``
dot-convention prefix (module.action event
naming). The helper appends ``_match``, ``_mismatch``, or ``_unavailable``
depending on outcome.

Linux-only: SO_PEERCRED is AF_UNIX + Linux. On non-Linux or kernel quirk,
``getsockopt`` raises ``OSError`` — callers catch it, log
``*.peercred_unavailable`` at warning level once, and fall back to
ACL-only (0700 permissions + UID ownership still pin the runtime dir;
tmpfs is recommended for socket-lifetime ephemerality but is not
enforced by the validator).
"""

import asyncio
import logging
import os
import socket
import stat
import struct
from pathlib import Path

logger = logging.getLogger(__name__)

# ucred struct (Linux kernel): pid_t pid, uid_t uid, gid_t gid — all 32-bit ints.
_STRUCT_UCRED = struct.Struct("3i")

_RUNTIME_DIR_REQUIRED_MODE = 0o700


async def _assert_peer_uid(
    writer: asyncio.StreamWriter,
    path: str,
    module_event_prefix: str,
) -> None:
    """Assert the connected peer's UID matches this process's UID.

    Called after ``asyncio.open_unix_connection`` succeeds on the client
    side. Reads SO_PEERCRED from the underlying socket, asserts UID equality,
    and raises ``PermissionError`` on mismatch (after closing the writer).

    Audit event names are derived by appending suffixes to
    ``module_event_prefix``:
        ``<prefix>_match`` — clean path (peer UID matches; trust boundary held)
        ``<prefix>_mismatch`` — fail-closed reject path
        ``<prefix>_unavailable`` — transport did not expose a raw socket

    Args:
        writer: the StreamWriter returned by ``open_unix_connection``.
        path: the socket path — logged for operator diagnostics.
        module_event_prefix: per-transport event-name prefix (no trailing
            suffix), e.g. ``"sidecar.peer_uid"`` or ``"signal.peer_uid"``.

    Raises:
        PermissionError: peer UID does not match ``os.getuid()``. Caller
            handles fail-closed semantics (don't retry the socket — the
            peer is not who we expect).
        OSError: getsockopt failed (non-Linux kernel / missing SO_PEERCRED).
            Caller logs ``*.peercred_unavailable`` and falls back to ACL-only.
    """
    logger.debug(
        "_assert_peer_uid called",
        extra={
            "event": "core.socket_auth._assert_peer_uid",
            "socket": str(path),
            "module_event_prefix": module_event_prefix,
        },
    )  # auto:entry
    sock: socket.socket | None = writer.get_extra_info("socket")
    if sock is None:
        # Never observed in the asyncio stack under CPython for AF_UNIX, but
        # fail-closed if the transport does not expose a raw socket.
        logger.warning(
            "Peer socket unavailable for SO_PEERCRED check",
            extra={
                "event": f"{module_event_prefix}_unavailable",
                "socket": str(path),
                "reason": "no_extra_info_socket",
            },
        )
        raise PermissionError(f"peer socket unavailable on {path!s}")

    cred_bytes = sock.getsockopt(
        socket.SOL_SOCKET,
        socket.SO_PEERCRED,
        _STRUCT_UCRED.size,
    )
    pid, uid, gid = _STRUCT_UCRED.unpack(cred_bytes)
    expected = os.getuid()
    if uid != expected:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # catch-all: close is best-effort on auth-failed path
            logger.debug(
                "Writer wait_closed suppressed after UID mismatch",
                extra={
                    "event": f"{module_event_prefix}_mismatch",
                    "socket": str(path),
                },
            )
        logger.warning(
            "Peer UID mismatch on unix socket",
            extra={
                "event": f"{module_event_prefix}_mismatch",
                "socket": str(path),
                "expected_uid": expected,
                "peer_uid": uid,
                "peer_pid": pid,
                "peer_gid": gid,
            },
        )
        raise PermissionError(f"peer UID mismatch on {path!s}")

    # Negative-path logging on security checks (log both
    # 'applied' AND 'clean')." Emit the trust-boundary-held event so
    # operator forensics can reconstruct that the SO_PEERCRED gate
    # actually fired and matched, not just that no warning was logged.
    logger.debug(
        "Peer UID matched on unix socket",
        extra={
            "event": f"{module_event_prefix}_match",
            "socket": str(path),
            "peer_uid": uid,
            "peer_pid": pid,
        },
    )


def validate_runtime_dir(path: str, expected_uid: int) -> None:
    """Validate ``settings.runtime_dir`` at controller startup.

    Enforced at init time (orchestrator + channels) BEFORE the client
    classes are constructed. Fail-closed: raises ``RuntimeError`` on any
    failure so the caller can skip the affected channel registration.

    Checks:
        1. Path exists.
        2. Path is a directory.
        3. Mode is exactly 0700.
        4. Owner UID equals ``expected_uid`` (typically ``os.getuid()``).

    Does NOT call ``chmod`` / ``chown`` — this is a verification, not a
    fixup. Operators who misconfigure the runtime_dir perms or owner
    (via podman-compose tmpfs entry, systemd ``RuntimeDirectory``, or
    bare-metal ``mkdir``) see the channel refuse to register rather
    than silently binding a socket inside a directory outside the
    validated trust boundary. Filesystem type (tmpfs vs other) is NOT
    enforced — tmpfs is recommended for socket-lifetime ephemerality
    but is an operator deployment choice, not a validated invariant.

    Args:
        path: filesystem path to validate.
        expected_uid: UID the runtime_dir must be owned by.

    Raises:
        RuntimeError: any of the four checks failed. The exception message
            identifies the specific failure for operator diagnostics.
    """
    logger.debug(
        "validate_runtime_dir called",
        extra={
            "event": "core.socket_auth.validate_runtime_dir",
            "path_len": len(path) if hasattr(path, "__len__") else 0,
            "expected_uid": expected_uid,
        },
    )  # auto:entry
    p = Path(path)
    try:
        st = p.stat()
    except FileNotFoundError as exc:
        raise RuntimeError(f"runtime_dir missing: {path!r}") from exc
    except OSError as exc:
        # Surface permissions / ENOTDIR-on-parent issues.
        raise RuntimeError(
            f"runtime_dir stat failed: {path!r} ({exc.__class__.__name__})"
        ) from exc

    if not stat.S_ISDIR(st.st_mode):
        raise RuntimeError(f"runtime_dir is not a directory: {path!r}")

    actual_mode = stat.S_IMODE(st.st_mode)
    if actual_mode != _RUNTIME_DIR_REQUIRED_MODE:
        raise RuntimeError(
            f"runtime_dir perms must be 0{_RUNTIME_DIR_REQUIRED_MODE:o}, "
            f"found 0{actual_mode:o}: {path!r}"
        )

    if st.st_uid != expected_uid:
        raise RuntimeError(
            f"runtime_dir owner UID {st.st_uid} does not match "
            f"expected UID {expected_uid}: {path!r}"
        )
