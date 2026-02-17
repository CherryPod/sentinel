#!/bin/bash
# Monthly container rebuild with CVE gate
# Run AFTER host update/reboot, AFTER Ollama is healthy
set -euo pipefail
cd $HOME/sentinel

echo "[sentinel] Rebuilding container image..."
podman build \
  --no-cache \
  --secret id=hf_token,src=$HOME/.secrets/hf_token.txt \
  -t sentinel -f container/Containerfile .

echo "[sentinel] Running CVE audit on new image..."
if ! podman run --rm sentinel pip-audit --strict; then
    echo "[sentinel] CVE audit FAILED — not deploying. Review output above."
    exit 1
fi

echo "[sentinel] CVE audit passed. Deploying..."
podman tag sentinel sentinel_sentinel
podman compose down
podman compose up -d

echo "[sentinel] Rebuild complete."
