#!/usr/bin/env bash
# Serve injection benchmark web pages on a LAN-accessible port.
# Usage: ./serve_web_pages.sh [port]
#
# Default port: 8099 (chosen to avoid conflicts with existing services)
# Pages are served from benchmarks/injection_web_pages/
# The server binds to 0.0.0.0 so it's reachable from the Sentinel container.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
WEB_DIR="$PROJECT_DIR/benchmarks/injection_web_pages"
PORT="${1:-8099}"

if [ ! -d "$WEB_DIR" ]; then
    echo "Web pages directory not found: $WEB_DIR"
    echo "Run the benchmark with --dry-run first to generate pages, or run:"
    echo "  $PROJECT_DIR/.venv/bin/python3 -c \"from scripts.injection_benchmark.vectors.web_vector import generate_pages; ...\""
    exit 1
fi

# Check port availability
if ss -tlnp | grep -q ":${PORT} "; then
    echo "ERROR: Port $PORT is already in use"
    ss -tlnp | grep ":${PORT} "
    exit 1
fi

# Get LAN IP for config reference
LAN_IP=$(hostname -I | awk '{print $1}')
echo "Serving injection benchmark pages:"
echo "  Directory: $WEB_DIR"
echo "  URL: http://${LAN_IP}:${PORT}"
echo "  Pages: $(ls "$WEB_DIR"/*.html 2>/dev/null | wc -l) pages"
echo ""
echo "Use this URL in injection_benchmark_config.yaml:"
echo "  web_base_url: \"http://${LAN_IP}:${PORT}\""
echo ""
echo "Press Ctrl+C to stop."

cd "$WEB_DIR"
exec python3 -m http.server "$PORT" --bind 0.0.0.0
