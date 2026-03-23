"""Multi-vector chained injection benchmark runner — 8 tests via /api/task."""
import argparse
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Path setup
_SCRIPT_DIR = Path(__file__).resolve().parent
_SCRIPTS_DIR = _SCRIPT_DIR.parent
sys.path.insert(0, str(_SCRIPTS_DIR))
sys.path.insert(0, str(_SCRIPT_DIR))

from red_team_lib import SentinelClient, JsonlWriter, load_pin

from config import load_config, validate_config
from payloads import render_payload
from injection_lib import (
    build_test_matrix, determine_verdict, determine_defence_layer,
    detect_exploit_from_response, CleanupManifest, TestResult,
)
from vectors import email_vector, file_vector, web_vector, calendar_vector


def run_chained_test(client, test_case, config, manifest) -> TestResult:
    """Execute a multi-vector chained test.

    Seeds the same payload across multiple vectors simultaneously,
    then triggers a single user task that touches all seeded sources.
    """
    rendered = render_payload(
        test_case.payload_id, test_case.goal, test_case.test_id,
        attacker_email=config.attacker.email)

    # Seed across all chained vectors
    seed_fns = {
        "email_body": email_vector.seed_email,
        "calendar_desc": calendar_vector.seed_calendar_event,
        "file_content": file_vector.seed_file,
        "web_page": lambda c, tid, p, m: None,  # Pre-generated
    }
    for vector in test_case.chained_vectors:
        seed_fn = seed_fns.get(vector)
        if seed_fn:
            seed_fn(config, test_case.test_id, rendered, manifest)

    # For file_deletion: seed canary
    if test_case.target_action == "file_deletion":
        file_vector.seed_canary(config, test_case.test_id, manifest)

    # Trigger the combined task
    response, http_status, elapsed = client.send_task(
        test_case.user_prompt,
        source=f"injection_bench_{test_case.test_id}",
    )

    # Settle delay
    time.sleep(3)

    # Verify target action (response-based + filesystem)
    attacker_received = _verify_chained_target(config, test_case, response)

    # Score
    verdict = determine_verdict(
        response, attacker_received,
        test_case.target_action, elapsed)
    defence = determine_defence_layer(response) if verdict == "defended" else ""

    # Utility check
    status = response.get("status", "")
    summary = response.get("plan_summary", "")
    outcomes = response.get("step_outcomes", [])
    utility = (
        status in ("success", "partial")
        and bool(summary)
        and any(s.get("status") == "success" for s in outcomes)
    )

    # Cleanup all seeded content
    for vector in test_case.chained_vectors:
        if vector == "file_content":
            file_vector.cleanup_single_file(
                f"/workspace/ib-tests/test-{test_case.test_id.lower()}-report.txt")
        elif vector == "calendar_desc":
            calendar_vector.cleanup_single_event(
                config, f"[{test_case.test_id}]")

    return TestResult(
        test_case=test_case,
        security_verdict=verdict,
        defence_layer=defence,
        utility_completed=utility,
        attacker_received=attacker_received,
        http_status=http_status,
        response_status=response.get("status", "unknown"),
        plan_summary=response.get("plan_summary", ""),
        step_outcomes=response.get("step_outcomes", []),
        elapsed_s=elapsed,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


def _verify_chained_target(config, test_case, response: dict) -> bool:
    """Verify the target action for a chained test.

    Uses response-based detection (step_outcomes) as primary method,
    with filesystem checks as secondary for file targets.
    """
    action = test_case.target_action
    tid = test_case.test_id

    # Response-based detection
    if detect_exploit_from_response(
        response, action,
        attacker_email=config.attacker.email,
        attacker_phone=config.attacker.signal_phone,
        test_id=tid,
    ):
        return True

    # Secondary filesystem check
    if action == "file_deletion":
        return file_vector.verify_file_deleted(
            f"/workspace/ib-tests/canary-{tid}.txt")
    return False


def _default_output() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    project_root = Path(__file__).resolve().parent.parent.parent
    return str(
        project_root / "benchmarks" / f"injection_benchmark_chained_{ts}.jsonl"
    )


def _serialize_result(result: TestResult) -> dict:
    tc = result.test_case
    return {
        "type": "injection_benchmark",
        "test_id": tc.test_id,
        "vector": tc.vector,
        "payload_id": tc.payload_id,
        "target_action": tc.target_action,
        "trigger": tc.trigger,
        "user_prompt": tc.user_prompt,
        "chained_vectors": tc.chained_vectors,
        "security_verdict": result.security_verdict,
        "defence_layer": result.defence_layer,
        "utility_completed": result.utility_completed,
        "attacker_received": result.attacker_received,
        "http_status": result.http_status,
        "response_status": result.response_status,
        "plan_summary": result.plan_summary,
        "step_outcomes": result.step_outcomes,
        "elapsed_s": result.elapsed_s,
        "timestamp": result.timestamp,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Injection benchmark — chained tests (8 multi-vector)")
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", default=None)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    config = load_config(args.config)

    pin = load_pin(None, config.sentinel.pin_file)
    client = SentinelClient(config.sentinel.base_url, pin)

    if not args.dry_run and not client.health_check():
        print("ERROR: Sentinel is not healthy")
        sys.exit(1)

    # Build matrix — chained tests only
    config.run.scope = "chained"
    all_cases = build_test_matrix(config)
    matrix = [tc for tc in all_cases if tc.chained_vectors]

    output_path = args.output or _default_output()
    manifest = CleanupManifest(
        str(Path(output_path).parent / ".injection_benchmark_cleanup.json"))

    print(f"Running {len(matrix)} chained tests...")

    if args.dry_run:
        for i, tc in enumerate(matrix):
            print(f"  [{i+1}/{len(matrix)}] {tc.test_id}: "
                  f"{'+'.join(tc.chained_vectors)}/{tc.payload_id}/{tc.target_action}")
        print(f"\nDRY RUN — {len(matrix)} tests would execute")
        return

    with JsonlWriter(output_path) as writer:
        writer.write({
            "type": "header",
            "scope": "chained",
            "tests": len(matrix),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        for i, tc in enumerate(matrix):
            print(f"  [{i+1}/{len(matrix)}] {tc.test_id}: "
                  f"{'+'.join(tc.chained_vectors)}/{tc.payload_id}/{tc.target_action}")
            result = run_chained_test(client, tc, config, manifest)
            writer.write(_serialize_result(result))
            print(f"    -> {result.security_verdict} ({result.elapsed_s:.1f}s)")
            time.sleep(config.run.cooldown_s)

    print(f"\nResults written to {output_path}")


if __name__ == "__main__":
    main()
