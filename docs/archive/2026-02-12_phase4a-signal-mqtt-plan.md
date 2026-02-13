# Phase 4a: Signal + MQTT Integration (PAUSED)

> **Status:** Plan complete, paused for consideration. User is evaluating whether to set up a separate Signal-CLI instance on a dedicated number, or pivot to WebUI-first approach.
> **Date:** 2026-02-12

## Context

Phase 3 is complete — full CaMeL pipeline deployed with 259 tests passing. The controller accepts tasks via HTTP API, creates Claude plans, executes via Qwen, and supports approval flow. But there's no way for users to interact with it naturally. Phase 4a connects Signal messaging to the Sentinel pipeline via MQTT, so users can send tasks and approve plans from their phone.

**Two projects are modified:** `~/sentinel/` (controller) and `~/signal-notifs/` (Signal bot).

---

## Architecture

```
Signal App                          MQTT (mosquitto:1883)              Sentinel Controller
┌──────────────┐                   ┌─────────────────────┐            ┌──────────────────┐
│ User sends   │  @sentinel msg    │ sentinel/tasks      │  subscribe │ MQTT client      │
│ "@sentinel   │ ──► Redis queue ──┼──► (JSON)           ├───────────►│ → orchestrator   │
│  build site" │    sentinel_msgs  │                     │            │   → Claude plans  │
│              │                   │ sentinel/approval/req│  publish   │   → needs approval│
│ Receives     │◄── Redis outgoing ┼──◄ (JSON)           │◄───────────┤   → publishes req │
│ approval     │    _messages      │                     │            │                  │
│ request      │                   │ sentinel/approval/res│  subscribe │                  │
│              │  @sentinel approve│──► (JSON)            ├───────────►│ → submits approval│
│ Replies      │ ──► Redis queue ──┤                     │            │   → executes plan │
│              │                   │ sentinel/results     │  publish   │                  │
│ Gets result  │◄── Redis outgoing ┼──◄ (JSON)           │◄───────────┤ → publishes result│
└──────────────┘                   └─────────────────────┘            └──────────────────┘
     signal-notifs/                                                      sentinel/
     sentinel_handler.py                                                 mqtt_client.py
```

---

## MQTT Topic Schema

| Topic | Direction | Publisher | Format |
|-------|-----------|-----------|--------|
| `sentinel/tasks` | Signal → Controller | signal sentinel_handler | `{"request_id": "sig-<uuid>", "sender": "+44...", "body": "...", "timestamp": "ISO"}` |
| `sentinel/results` | Controller → Signal | sentinel mqtt_client | `{"request_id": "...", "sender": "...", "status": "success\|blocked\|error", "plan_summary": "...", "reason": "..."}` |
| `sentinel/approval/req` | Controller → Signal | sentinel mqtt_client | `{"request_id": "...", "sender": "...", "approval_id": "<uuid>", "plan_summary": "...", "steps": [...]}` |
| `sentinel/approval/res` | Signal → Controller | signal sentinel_handler | `{"approval_id": "<uuid>", "granted": bool, "reason": "...", "approved_by": "signal:+44..."}` |

---

## Implementation Steps

### Prerequisites (manual, before coding)

1. **Create MQTT user for Sentinel** — mosquitto uses `allow_anonymous false`, need a `sentinel` user
   - `podman exec mosquitto mosquitto_passwd /mosquitto/config/passwd sentinel`
   - Store password in `~/.secrets/mqtt_sentinel_password.txt`
   - Restart mosquitto to reload passwd file

2. **Verify signal-app can reach mosquitto** — signal-app is in a pod (slirp4netns), needs host LAN IP not `host.containers.internal`. Confirm `192.168.0.40:1883` is reachable or determine correct address.

### Step 1: Controller MQTT Client

**New file: `controller/app/mqtt_client.py`**
- `AsyncMQTTClient` class wrapping paho-mqtt v2 with asyncio integration
- Uses `CallbackAPIVersion.VERSION2` and asyncio socket helpers (`add_reader`/`add_writer`)
- Subscribes to `sentinel/tasks` and `sentinel/approval/res` on connect
- Publishes to `sentinel/results` and `sentinel/approval/req`
- Callbacks dispatch to registered task/approval handlers
- Handles reconnection (paho built-in) and logs disconnects
- JSON validation on incoming messages (drop invalid, log errors)

**Modify: `controller/app/config.py`**
- Add `mqtt_enabled: bool = False` (off by default for tests)
- Add `mqtt_client_id`, `mqtt_username`, `mqtt_password_file`
- Rename `mqtt_topic_in`/`mqtt_topic_out`/`mqtt_topic_approval` to explicit names:
  - `mqtt_topic_tasks`, `mqtt_topic_results`, `mqtt_topic_approval_req`, `mqtt_topic_approval_res`

**Modify: `controller/app/main.py`**
- Add MQTT startup/shutdown in `lifespan()` context manager
- Add `_handle_mqtt_task()` — receives MQTT message, calls `orchestrator.handle_task()`, publishes result or approval request
- Add `_handle_mqtt_approval()` — receives approval response, calls `approval_manager.submit_approval()` then `orchestrator.execute_approved_plan()`, publishes result
- Add `mqtt_enabled` to `/health` response

**Modify: `controller/requirements.txt`**
- Add `paho-mqtt>=2.1.0,<3.0.0`

### Step 2: Controller Tests

**New file: `controller/tests/test_mqtt_client.py`** (~15 tests)
- MQTT client connects with credentials
- Subscribes to correct topics on connect
- Publishes correctly formatted JSON for results and approval requests
- Dispatches incoming task messages to handler callback
- Dispatches incoming approval messages to handler callback
- Handles invalid JSON gracefully (logs, doesn't crash)
- Handles missing required fields

**New file: `controller/tests/test_mqtt_integration.py`** (~8 tests)
- Full flow: MQTT task → orchestrator → approval request published
- Full flow: approval response → execution → result published
- Blocked input → blocked result published
- Planner error → error result published
- Approval timeout → timeout result published
- Auto approval mode → result published directly (no approval step)

### Step 3: Signal Handler

**New file: `signal-notifs/app/sentinel_handler.py`**
- Supervisord process following existing handler pattern (blpop loop + paho-mqtt threaded loop)
- MQTT client with `loop_start()` (threaded, matches sync codebase)
- Subscribes to `sentinel/results` and `sentinel/approval/req`
- On `@sentinel <message>`: publish to `sentinel/tasks`, send ack to user
- On `@sentinel approve`: find pending approval for sender, publish to `sentinel/approval/res`
- On `@sentinel deny [reason]`: same, with granted=false
- Tracks `_pending_approvals: dict[approval_id, sender]` and `_pending_requests: dict[request_id, sender]`
- Formats results and approval requests as readable Signal messages
- Truncates long messages to ~1500 chars

**Modify: `signal-notifs/app/signal_proxy.py` (line ~168-171)**
- Add `@sentinel` routing before the default `else`:
  ```python
  elif body.lower().startswith("@sentinel"):
      queue = "sentinel_messages"
  ```

**Modify: `signal-notifs/supervisord.conf`**
- Add `[program:sentinel-handler]` block (priority=200, autorestart=true)

**Modify: `signal-notifs/requirements.txt` (or Containerfile pip install)**
- Add `paho-mqtt>=2.1.0,<3.0.0`

### Step 4: Deployment Config

**Modify: `sentinel/podman-compose.yaml`**
- Add `mqtt_password` secret pointing to `~/.secrets/mqtt_sentinel_password.txt`
- Mount secret in sentinel-controller
- Add `SENTINEL_MQTT_ENABLED=true`, `SENTINEL_MQTT_USERNAME=sentinel`, `SENTINEL_MQTT_PASSWORD_FILE=/run/secrets/mqtt_password` env vars

### Step 5: Build & Deploy

1. Run controller tests locally (`pytest controller/tests/ -v`)
2. Rebuild sentinel-controller (`podman compose up -d --build sentinel-controller`)
3. Run container tests (`podman exec sentinel-controller pytest /app/tests/ -v`)
4. Rebuild signal-notifs (existing build/deploy workflow for that project)
5. Verify both containers can reach mosquitto

---

## Approval Flow (User Experience)

```
User: @sentinel build me a portfolio site on port 8080

Bot:  [Sentinel] Request received. Processing...

Bot:  [Sentinel] Plan ready for approval:
      Build portfolio website with HTML and Podman container

      Steps:
        step_1: Generate HTML content (Qwen)
        step_2: Write file to /workspace/portfolio/index.html
        step_3: Build Podman container
        step_4: Run container on port 8080

      Reply: @sentinel approve or @sentinel deny

User: @sentinel approve

Bot:  [Sentinel] Approved. Executing...

Bot:  [Sentinel] Task complete!
      Build portfolio website with HTML and Podman container

      step_1: OK - Generated HTML
      step_2: OK - File written
      step_3: OK - Container built
      step_4: OK - Container running on port 8080
```

---

## Key Files

| File | Action | Project |
|------|--------|---------|
| `controller/app/mqtt_client.py` | CREATE | sentinel |
| `controller/app/main.py` | MODIFY (lifespan + handlers) | sentinel |
| `controller/app/config.py` | MODIFY (MQTT settings) | sentinel |
| `controller/requirements.txt` | MODIFY (add paho-mqtt) | sentinel |
| `controller/tests/test_mqtt_client.py` | CREATE | sentinel |
| `controller/tests/test_mqtt_integration.py` | CREATE | sentinel |
| `podman-compose.yaml` | MODIFY (secret + env vars) | sentinel |
| `app/sentinel_handler.py` | CREATE | signal-notifs |
| `app/signal_proxy.py` | MODIFY (1 line: @sentinel routing) | signal-notifs |
| `supervisord.conf` | MODIFY (add process) | signal-notifs |
| `requirements.txt` or `Containerfile` | MODIFY (add paho-mqtt) | signal-notifs |

---

## Flags & Risks

1. **Cross-project changes** — signal-notifs is a separate project. Changes there should be minimal (new handler + 1 routing line + supervisord entry). The existing handlers are untouched.

2. **Mosquitto auth** — needs `sentinel` user created before deployment. Also needs same password stored in `~/.secrets/` for both projects.

3. **Signal-app network** — signal-app pod uses slirp4netns, so `host.containers.internal` may not resolve. Need to use host LAN IP (likely `192.168.0.40`) for MQTT broker address. This is configured via env var, not hardcoded.

4. **Single pending approval per sender** — if a user sends two tasks rapidly, approvals are matched FIFO (oldest first). Adequate for Phase 4a; numbered selection can come in 4b.

5. **In-memory state** — sentinel_handler tracks pending approvals in-memory. If the process restarts, pending approvals are lost. Acceptable for Phase 4a (Signal user just re-sends).

---

## Open Question: Separate Signal Instance

User is considering setting up a second signal-cli instance on a dedicated phone number specifically for Sentinel, rather than adding @sentinel commands to the existing notification bot. This would:

**Pros:**
- Clean separation — Sentinel has its own Signal identity, no @prefix needed
- No modifications to existing signal-notifs project
- Feels more natural (messaging "Sentinel" directly, not prefixing commands)
- Could be a simpler standalone container

**Cons:**
- Two signal-cli instances on same IP — needs research on whether Signal allows this
- Second phone number needed
- Second container to manage
- Duplicates some infrastructure (Redis, supervisord)

**Research needed:** Can two signal-cli instances run simultaneously on the same server IP with different phone numbers? Signal's anti-spam may flag this.

---

## Verification

1. **Unit tests**: `PYTHONPATH=controller .venv/bin/python -m pytest controller/tests/ -v` — all 259 existing + new MQTT tests pass
2. **Container tests**: `podman exec sentinel-controller pytest /app/tests/ -v` — all pass
3. **MQTT connectivity**: `podman exec sentinel-controller python -c "import paho.mqtt.client as mqtt; c=mqtt.Client(mqtt.CallbackAPIVersion.VERSION2); c.username_pw_set('sentinel','<pw>'); c.connect('host.containers.internal',1883); print('OK')"`
4. **End-to-end Signal**: Send `@sentinel Write me a hello world HTML page` via Signal → receive plan → approve → receive result
5. **Denial test**: Send task → receive plan → reply `@sentinel deny` → receive denial confirmation
6. **Health check**: `curl http://localhost:8000/health` shows `mqtt_connected: true`
