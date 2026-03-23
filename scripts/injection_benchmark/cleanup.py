"""Standalone cleanup for interrupted injection benchmark runs.

Reads the cleanup manifest and removes all seeded content (emails,
files, calendar events) that were planted during an interrupted run.
"""
import argparse
import sys
from pathlib import Path

# Path setup
_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR.parent))      # scripts/ → red_team_lib
sys.path.insert(0, str(_SCRIPT_DIR))              # scripts/injection_benchmark/

from config import load_config
from injection_lib import CleanupManifest
from vectors import email_vector, calendar_vector, file_vector


def main():
    parser = argparse.ArgumentParser(
        description="Clean up seeded injection benchmark data")
    parser.add_argument("--config", required=True,
                        help="Path to config YAML")
    parser.add_argument("--manifest",
                        default="benchmarks/.injection_benchmark_cleanup.json",
                        help="Path to cleanup manifest")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be cleaned without doing it")
    parser.add_argument("--full", action="store_true",
                        help="Also clean all [IB-*] emails and files "
                             "regardless of manifest")
    args = parser.parse_args()

    config = load_config(args.config)
    manifest = CleanupManifest(args.manifest)
    items = manifest.load()

    if not items and not args.full:
        print("No items in cleanup manifest — nothing to do")
        print("Use --full to clean all [IB-*] artifacts regardless of manifest")
        return

    # Manifest-based cleanup
    if items:
        print(f"Cleaning {len(items)} items from manifest...")
        for item in items:
            label = f"{item['type']}: {item['identifier']}"
            if args.dry_run:
                print(f"  Would clean: {label}")
                continue

            print(f"  Cleaning: {label}")
            if item["type"] == "email":
                email_vector.cleanup_single_email(config, item["identifier"])
            elif item["type"] == "file":
                file_vector.cleanup_single_file(item["identifier"])
            elif item["type"] == "calendar":
                calendar_vector.cleanup_single_event(
                    config, item["identifier"])

    # Full cleanup (removes everything with IB prefix)
    if args.full:
        print("Running full cleanup (all [IB-*] artifacts)...")
        if not args.dry_run:
            email_vector.cleanup_emails(config)
            calendar_vector.cleanup_calendar_events(config)
            file_vector.cleanup_files(manifest)
            print("  Full cleanup complete")
        else:
            print("  Would clean: all [IB-*] emails, calendar events, "
                  "and /workspace/ib-tests/ files")

    # Clear manifest
    if not args.dry_run:
        manifest.clear()
        print(f"Cleaned {len(items)} manifest items")
    else:
        print(f"DRY RUN — {len(items)} items would be cleaned")


if __name__ == "__main__":
    main()
