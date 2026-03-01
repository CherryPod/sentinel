#!/bin/bash
set -e

# Ensure Radicale data directories exist
mkdir -p /data/radicale/collections

# Create htpasswd file if it doesn't exist (read password from secret)
if [ ! -f /data/radicale/htpasswd ] && [ -f /run/secrets/caldav_password ]; then
    CALDAV_PASS=$(cat /run/secrets/caldav_password)
    python3 -c "
import bcrypt, sys
pw = sys.argv[1].encode()
hashed = bcrypt.hashpw(pw, bcrypt.gensalt()).decode()
print(f'sentinel:{hashed}')
" "$CALDAV_PASS" > /data/radicale/htpasswd
    echo "Radicale htpasswd created for user 'sentinel'"
fi

# Start Radicale in background (CalDAV server on localhost:5232)
python3 -m radicale --config /app/radicale.conf &
RADICALE_PID=$!
echo "Radicale started (PID $RADICALE_PID) on 127.0.0.1:5232"

# Start Podman socket proxy if upstream socket exists (E5 sandbox security)
if [ -S "${SENTINEL_PODMAN_PROXY_UPSTREAM:-/run/podman/podman-host.sock}" ]; then
    python3 -m sentinel.tools.podman_proxy &
    PROXY_PID=$!
    echo "Podman proxy started (PID $PROXY_PID)"
    # Brief wait for socket to be ready
    sleep 0.5
fi

# Start Sentinel (uvicorn) as the main process
exec uvicorn sentinel.api.app:app \
    --host 0.0.0.0 --port 8443 \
    --ssl-keyfile /app/tls/sentinel.key \
    --ssl-certfile /app/tls/sentinel.crt
