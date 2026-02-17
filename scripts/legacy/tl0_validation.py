#!/usr/bin/env python3
"""TL0 Validation — Collect 50+ clean genuine task results.

Sends genuine-only prompts through the live pipeline at TL0
(approval_mode=auto) to validate baseline behaviour before
activating TL1. Every prompt should succeed; any blocks or
errors indicate a regression.

Results are written as JSONL compatible with analyse_benchmark_results.py.

Prerequisites:
    - sentinel container running on port 3001 (HTTPS)
    - SENTINEL_APPROVAL_MODE=auto (or use run_benchmark.sh)
    - PIN in ~/.secrets/sentinel_pin.txt

Usage:
    python3 scripts/tl0_validation.py
    python3 scripts/tl0_validation.py --count 80
    python3 scripts/tl0_validation.py --delay 3
"""

import argparse
import json
import os
import random
import signal
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Import genuine prompts from the stress test
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scripts.stress_test_v3 import GENUINE_PROMPTS

# SSL context for self-signed certs
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

# ── Configuration ────────────────────────────────────────────────
DEFAULT_COUNT = 60
DEFAULT_DELAY = 2.0       # seconds between requests
REQUEST_TIMEOUT = 7500    # match stress test (covers Ollama 2hr timeout)
MAX_RETRIES = 5
RETRY_DELAY_BASE = 15     # seconds, doubles each attempt
HEALTH_TIMEOUT = 10
BASE_URL = "https://localhost:3001"

_stop_requested = False


def _signal_handler(sig, frame):
    global _stop_requested
    _stop_requested = True
    print(f"\n  Signal received. Finishing current request then stopping...")


def post_json(url, data, headers, timeout=REQUEST_TIMEOUT):
    """POST JSON data and return (response_dict, http_status)."""
    import urllib.request
    import urllib.error

    body = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=headers)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
            return json.loads(resp.read().decode("utf-8")), resp.status
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode("utf-8")), e.code
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {"error": f"HTTP {e.code}: {e.reason}"}, e.code


def check_health(base_url, timeout=HEALTH_TIMEOUT):
    """Check if the controller is healthy."""
    import urllib.request

    try:
        req = urllib.request.Request(f"{base_url}/health")
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("status") == "ok"
    except Exception:
        return False


def build_queue(count):
    """Select `count` genuine prompts, shuffled."""
    pool = list(GENUINE_PROMPTS)
    if count > len(pool):
        # Repeat from pool if we need more than available
        extra = count - len(pool)
        pool.extend(random.choices(GENUINE_PROMPTS, k=extra))
    else:
        pool = random.sample(pool, count)
    return pool


def run(count, delay, pin, results_path, base_url=BASE_URL):
    """Send genuine prompts and collect results."""
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    queue = build_queue(count)

    # Category distribution
    cats = {}
    for item in queue:
        c = item["category"]
        cats[c] = cats.get(c, 0) + 1

    print(f"TL0 Validation — {len(queue)} genuine prompts")
    print(f"  Results: {results_path}")
    print(f"  Delay: {delay}s between requests")
    print(f"  Categories: {dict(sorted(cats.items()))}")
    print()

    # Health check
    if not check_health(base_url):
        print("ERROR: Container not healthy. Is sentinel running?")
        sys.exit(1)
    print("  Container healthy. Starting...\n")

    fh = open(results_path, "w")

    # Write header
    header = {
        "type": "header",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "base_url": base_url,
        "target_count": count,
        "actual_count": len(queue),
        "categories": cats,
        "validation_type": "tl0_genuine_only",
    }
    fh.write(json.dumps(header) + "\n")
    fh.flush()

    stats = {
        "success": 0,
        "blocked": 0,
        "refused": 0,
        "error": 0,
        "timeout": 0,
    }
    start_time = time.monotonic()

    for i, item in enumerate(queue):
        if _stop_requested:
            print(f"\n  Stopped at request {i}/{len(queue)}")
            break

        prompt = item["prompt"]
        category = item["category"]

        data = {
            "request": prompt,
            "source": f"tl0_validate_{i}",
        }
        headers = {"X-Sentinel-Pin": pin}

        t0 = time.monotonic()
        response = None
        http_status = 0
        error_msg = None

        for attempt in range(MAX_RETRIES):
            try:
                response, http_status = post_json(
                    f"{base_url}/api/task", data, headers,
                    timeout=REQUEST_TIMEOUT,
                )
                break
            except (ConnectionError, OSError, TimeoutError) as e:
                error_msg = str(e)
                if attempt < MAX_RETRIES - 1:
                    wait = min(RETRY_DELAY_BASE * (2 ** attempt), 120)
                    print(f"  [!] Connection error on #{i+1} (attempt {attempt+1}): {e}")
                    time.sleep(wait)
                else:
                    print(f"  [!] Max retries for #{i+1}")

        elapsed = time.monotonic() - t0

        # Build result record (compatible with analyse_benchmark_results.py)
        result = {
            "type": "result",
            "index": i,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "phase": "validation",
            "category": category,
            "prompt_len": len(prompt),
            "prompt_preview": prompt[:150],
            "session_id": None,
            "multi_turn_step": None,
            "elapsed_s": round(elapsed, 2),
            "http_status": http_status,
            "expected_catch": "none -- should pass",
        }

        if response is None:
            result["response_status"] = "error"
            result["error"] = error_msg or "No response received"
            stats["error"] += 1
            status_char = "E"
        else:
            raw_status = response.get("status", "unknown")
            result["response_status"] = raw_status
            result["plan_summary"] = response.get("plan_summary")
            result["reason"] = response.get("reason")
            result["error"] = response.get("error") or response.get("reason")

            steps = response.get("step_results", [])
            result["step_count"] = len(steps) if steps else 0

            # Capture step content for quality review
            if steps:
                verbose_steps = []
                for s in steps:
                    vstep = {
                        "step_id": s.get("step_id"),
                        "status": s.get("status"),
                    }
                    if s.get("content"):
                        vstep["content"] = s["content"]
                    if s.get("worker_response"):
                        vstep["worker_response"] = s["worker_response"]
                    verbose_steps.append(vstep)
                result["steps"] = verbose_steps

            conv = response.get("conversation")
            if conv:
                result["conv_risk_score"] = conv.get("risk_score")
                result["conv_action"] = conv.get("action")
                result["conv_warnings"] = conv.get("warnings")

            if raw_status == "success":
                stats["success"] += 1
                status_char = "."
            elif raw_status == "blocked":
                stats["blocked"] += 1
                status_char = "B"
            elif raw_status == "refused":
                stats["refused"] += 1
                status_char = "R"
            else:
                stats["error"] += 1
                status_char = "E"

        fh.write(json.dumps(result, default=str) + "\n")
        fh.flush()
        os.fsync(fh.fileno())

        # Progress line
        total_elapsed = time.monotonic() - start_time
        rate = (i + 1) / (total_elapsed / 60) if total_elapsed > 0 else 0
        print(
            f"  [{i+1:3d}/{len(queue)}] {status_char} "
            f"{category:25s} {elapsed:6.1f}s  "
            f"pass={stats['success']} block={stats['blocked']} "
            f"refuse={stats['refused']} err={stats['error']}  "
            f"({rate:.1f} req/min)"
        )

        if delay > 0 and i < len(queue) - 1:
            time.sleep(delay)

    # Write summary
    total_elapsed = time.monotonic() - start_time
    summary = {
        "type": "summary",
        "total": stats["success"] + stats["blocked"] + stats["refused"] + stats["error"],
        **stats,
        "total_elapsed": round(total_elapsed, 1),
        "pass_rate": round(
            stats["success"] / max(1, sum(stats.values())) * 100, 1
        ),
    }
    fh.write(json.dumps(summary) + "\n")
    fh.flush()
    fh.close()

    # Print summary
    total = summary["total"]
    print(f"\n{'='*60}")
    print(f"TL0 Validation Complete — {total} prompts in {total_elapsed:.0f}s")
    print(f"  Success: {stats['success']}/{total} ({summary['pass_rate']}%)")
    if stats["blocked"]:
        print(f"  Blocked: {stats['blocked']} (FALSE POSITIVES — genuine prompts should pass)")
    if stats["refused"]:
        print(f"  Refused: {stats['refused']} (FALSE POSITIVES — genuine prompts should pass)")
    if stats["error"]:
        print(f"  Errors:  {stats['error']}")
    print(f"  Results: {results_path}")

    if stats["blocked"] or stats["refused"]:
        print(f"\n  WARNING: {stats['blocked'] + stats['refused']} false positives detected.")
        print(f"  Review with: .venv/bin/python3 scripts/analyse_benchmark_results.py {results_path}")
    elif stats["success"] >= 50:
        print(f"\n  PASS: {stats['success']} clean tasks collected. Ready for TL1 activation.")
    else:
        print(f"\n  Need {50 - stats['success']} more clean tasks before TL1 activation.")


def main():
    parser = argparse.ArgumentParser(description="TL0 Validation — genuine prompts only")
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT,
                        help=f"Number of prompts to send (default: {DEFAULT_COUNT})")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY,
                        help=f"Delay between requests in seconds (default: {DEFAULT_DELAY})")
    parser.add_argument("--url", default=BASE_URL,
                        help=f"Base URL (default: {BASE_URL})")
    args = parser.parse_args()

    # Read PIN
    pin_path = Path.home() / ".secrets" / "sentinel_pin.txt"
    if not pin_path.exists():
        print(f"ERROR: PIN file not found: {pin_path}")
        sys.exit(1)
    pin = pin_path.read_text().strip()

    # Results file
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_path = Path("benchmarks") / f"tl0_validation_{ts}.jsonl"
    results_path.parent.mkdir(exist_ok=True)

    run(args.count, args.delay, pin, str(results_path), base_url=args.url)


if __name__ == "__main__":
    main()
