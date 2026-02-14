# Project Sentinel — Session Summary (2026-02-13)

## What Sentinel Is

A CaMeL-based defence-in-depth architecture running on "thebeast" (Ubuntu, Ryzen 7 5700X, 64GB RAM, RTX 3060 12GB). Three components:

- **Claude API (Privileged Planner):** Receives user requests, creates structured JSON plans. Decides what to do. Never executes anything directly. Never sees untrusted external content.
- **Qwen 3 14B (Quarantined Worker):** Air-gapped local LLM on sentinel_internal network (no internet). Receives text instructions, returns text. Has zero tool access. Assumed compromised at all times.
- **Controller (Python/FastAPI):** The only component that executes actions (file writes, shell commands, podman operations). Follows Claude's plans step by step. Enforces security policy on every action. Scans all LLM output. Sits between everything — nothing bypasses it.

Key principle: The thing that touches untrusted data (Qwen) has no tools. The thing that decides what to do (Claude) never touches untrusted data. The thing with the tools (Controller) has no intelligence, just rules.

## What We Built and Tested Today

The basic Sentinel pipeline is working: sentinel-controller, sentinel-qwen, and sentinel-ui containers are running. The flow is: User → UI → Controller → Claude API (planning) → Controller → Qwen (text generation) → Controller (scanning) → UI.

### Tests Run

1. **"What is the capital of France?"** — Full pipeline worked. Claude planned an llm_task, Qwen answered correctly. Proved end-to-end flow works.

2. **"What's the date today?"** — Qwen correctly responded that it doesn't have access to real-time information. Expected behaviour for an air-gapped model. Identified need for Controller to inject current date/time into Qwen's system prompt, and for Claude to have a `direct_answer` response type for questions it can answer without Qwen.

3. **All 5 code tests at once (Python x3, HTML, Dockerfile)** — Claude planned all 5 as separate llm_task steps correctly. However, the HTML output broke the Controller/UI — the raw HTML was parsed as JSON, causing an "Unexpected token '<'" error. **Bug: Controller needs to treat Qwen's output as opaque strings, not attempt JSON parsing.**

4. **Python CSV processing script** — Clean, correct code. Proper error handling, defaultdict, sorted output, f-string formatting. Would run correctly out of the box.

5. **Dockerfile for Flask app** — Mostly correct. Multi-stage build, non-root user, healthcheck. Two minor issues: dependencies copied from wrong path (/app instead of /usr/local/lib/python3.11/site-packages), and healthcheck uses curl which isn't available in python:3.11-slim. Functional but would fail on build.

6. **Podman Containerfile test** — Good result. Qwen understood Podman vs Docker distinction, used correct terminology, created non-root user properly, used python http.server correctly. Added Podman-specific notes. Completed in ~90 seconds (vs 7 minutes for first test — GPU was already loaded).

## Key Issues Identified

### 1. HTML Output Breaks JSON Parsing
When Qwen generates raw HTML, the Controller or UI tries to parse it as JSON and crashes. Fix: treat all Qwen output as opaque text strings, never parse the content.

### 2. Claude Summarises Instructions Too Aggressively
When given a detailed request, Claude's plan compresses the instructions into vague one-liners before passing to Qwen. Example: detailed Podman Containerfile spec with specific requirements became just "Generate a Containerfile with non-root configuration." Qwen loses the detail it needs.

**Fix:** Add to Claude's planner system prompt: "When creating llm_task steps, pass through ALL detail from the user's request. Do not summarise or compress requirements. The worker performs better with specific, detailed instructions. Include exact specifications, constraints, naming conventions, compatibility requirements, and any technical details."

### 3. Qwen Has No System Context
Qwen doesn't know the date, the OS, the directory structure, or system conventions. It's air-gapped with no tools or file access.

**Fixes needed:**
- Controller should inject current date/time into Qwen's system prompt on every request
- Add to Qwen's system prompt: "You are generating code and configuration files for an Ubuntu Linux server running Podman containers. Use Linux conventions: forward slash paths, LF line endings, bash-compatible shell syntax, Linux file permissions."
- Qwen does NOT need to know directory paths — Claude provides specific paths in its instructions. Qwen just writes code using whatever paths Claude specifies.

### 4. Secrets Handling
Qwen should never know where secrets are stored or reference them directly. Claude should instruct Qwen to write code that reads from environment variables. The Controller handles actual secret injection at runtime via Podman secrets or environment variables. Secrets stay completely outside the LLM layer.

### 5. Claude Latency on First Request
First request takes ~7 minutes (model loading into VRAM). Subsequent requests while model is loaded take ~90 seconds. This is Ollama's keep-alive behaviour — model loads on first request, stays loaded for the configured timeout, then unloads to free GPU for other services.

## Architecture Decisions Made

### Claude as Planner Has Tools Concern
Identified that Claude (the planner) could theoretically be destructive — it decides what commands to run. Mitigations already in place:
- Policy file limits what the Controller will execute (whitelisted commands, allowed paths only)
- Human approval mode (currently "full" — every plan requires approval)
- Audit logging of every action
- Rate limiting could be added (max tool calls per task, max MB written)
- Plan validation rules could be added (deterministic sanity checks on Claude's plans)
- The policy file is a static YAML on the host, read-only mounted. Claude cannot modify it.

### Internet/Search Integration
For questions needing live data (Bitcoin price, news, etc.), two approaches discussed:
- **direct_answer:** Claude answers the question itself without involving Qwen. New plan type. Controller passes Claude's response to UI. Cheaper than a full response from Claude since many questions are short answers.
- **Search tool:** Add Brave API or existing SearXNG as a Controller tool. Claude plans: "Step 1: search. Step 2: send results to Qwen to summarise." Search results tagged as untrusted, spotlighted before Qwen sees them. Keeps token cost down — Claude only plans, Qwen does the writing.
- **Routing decision:** Claude handles this, not the Controller. Claude is the intelligent router — it knows when to answer directly, when to search, and when to delegate to Qwen. Controller just follows the labels.

### External Agent Integration (Moltbook, Friend's OpenClaw Agent)
- External agents connect via adapter containers → Controller → pipeline → Controller → adapter
- Adapters sit on sentinel_egress (internet access), Qwen stays on sentinel_internal (air-gapped)
- For hostile environments: full "paranoia sandwich" pipeline — Claude reviews incoming AND outgoing messages. API in → Controller → Claude (review incoming) → Controller → Qwen (draft response) → Controller → Claude (review outgoing) → Controller → API out
- For trusted conversations: lighter pipeline, Qwen with scanning only, Claude optional
- Pipeline mode is configurable per adapter in the policy
- Tailscale suggested for friend's agent connection (private encrypted tunnel)

### Comparison with OpenClaw
OpenClaw is essentially: Request → LLM (direct tool access) → executes immediately. No Controller, no policy, no scanning, no separation. Same capability as Sentinel but with zero security. OpenClaw's framework is functionally a controller that does whatever the LLM asks without any checks. Retrofitting security onto OpenClaw is harder than building secure from scratch because the architecture assumes inline tool access.

### Claude Memory File
Like Claude Code's CLAUDE.md — a static markdown file loaded into Claude's system prompt on every API call. Contains: system layout, Podman preferences, known quirks, project context, directory structure. Read-only mounted from host, no security risk (trusted data, same as policy YAML). Controller reads it and appends to system prompt:
```python
memory = open("/policies/sentinel-memory.md").read()
system_prompt = PLANNER_PROMPT + "\n\n" + memory
```

### Error Feedback Loop
For iterative development tasks: Controller runs a command, it fails, Controller captures error output, sends it back to Claude: "Step N failed with this error: [error text]. Revise the plan." Claude creates updated plan. Qwen regenerates. Controller retries. Same pattern as Claude Code but distributed across two models with security layer.

## Pipeline Modes Summary

The Controller supports different pipeline configurations:

| Mode | Flow | Use Case |
|------|------|----------|
| Full CaMeL | User → Claude (plan) → Qwen (work) → UI | Standard tasks, building things |
| Direct answer | User → Claude (answers directly) → UI | Simple questions, live data |
| Search + summarise | User → Claude (plan) → Search API → Qwen (summarise) → UI | Questions needing web data |
| Paranoia sandwich | API in → Claude (review) → Qwen (draft) → Claude (review) → API out | Hostile environments, Moltbook |
| Chat only | User → Qwen (direct) → UI | Private conversations, skip Claude |

All modes go through the Controller. All external data tagged untrusted. All outputs scanned.

## Next Steps

1. **Fix HTML/JSON parsing bug** — Controller must treat Qwen output as opaque strings
2. **Add Claude memory file** (sentinel-memory.md) with system context, Podman preferences
3. **Fix Claude instruction passing** — update planner system prompt to pass full detail to Qwen
4. **Add date/time injection** to Qwen's system prompt via Controller
5. **Add direct_answer plan type** so Claude can answer simple questions without Qwen
6. **Add Qwen system prompt** with Linux/Podman context
7. **Implement error feedback loop** for iterative task execution
8. **Add search integration** (SearXNG or Brave API) as Controller tool
9. **Continue Phase 2-3 of build plan** (security scanning pipeline, provenance tracking)
