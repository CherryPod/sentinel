# Sandboxed Execution

Sentinel executes worker-generated code in disposable Podman containers, providing strong isolation between the worker LLM and the host system. Each execution gets a fresh container that is destroyed after use.

## Key Design Decisions

- **Network isolation** — sandbox containers run with `NetworkMode: "none"`. Worker-generated code cannot make network connections.
- **Capability dropping** — containers run with `no-new-privileges` and drop all capabilities not needed for code execution.
- **Disposable containers** — each execution creates a new container from a pinned base image. No state persists between executions.
- **Podman API proxy** — the sentinel container communicates with Podman via a restricted proxy that only allows sandbox-related operations, preventing the worker from manipulating other containers.

## How It Works

### Execution Flow

1. The orchestrator receives a shell execution step from the planner
2. The security pipeline scans the command (policy engine, pattern scanner, Semgrep)
3. `sandbox.py` creates a new container via the Podman API proxy:
   - Base image: `sentinel-sandbox:latest` (33 pre-installed Python packages)
   - Network: disabled
   - Filesystem: read-only root, writable `/workspace` volume
   - Security: no-new-privileges, capability drop
4. The command is executed inside the container
5. stdout/stderr are captured via the Podman multiplexed stream protocol (8-byte framed, not plain text)
6. The container is destroyed
7. Output is scanned by the security pipeline before being returned

### Sandbox Image

The `sentinel-sandbox:latest` image includes 33 commonly-needed Python packages (requests, flask, pandas, numpy, etc.) because `pip install` is blocked by the read-only filesystem and disabled network. The image is built separately and pinned.

### Podman API Quirks

The Podman Docker-compatibility API has several quirks that the sandbox handles:
- **PascalCase required** — snake_case fields are silently ignored
- **`NetworkDisabled` ignored** — must use `NetworkMode: "none"` instead
- **`CapDrop` ignored** — must use `SecurityOpt: ["no-new-privileges"]`
- **Multiplexed stream output** — 8-byte frame headers, not plain text
- **Keep-alive handling** — `Connection: close` header injected to prevent proxy hangs

## Where the Code Lives

| File | Purpose |
|------|---------|
| `sentinel/tools/sandbox.py` | Container lifecycle, stream demuxing, API proxy |
| `container/Containerfile.sandbox` | Sandbox base image with pre-installed packages |
| `sentinel/planner/tool_dispatch.py` | Integration point — routes shell steps to sandbox |
