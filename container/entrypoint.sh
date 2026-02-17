#!/bin/bash
set -e

# PostgreSQL binaries are in /usr/lib/postgresql/17/bin (not on default PATH)
export PATH="/usr/lib/postgresql/17/bin:$PATH"

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

# PostgreSQL startup
# Ensure pgdata directory exists and is owned by postgres (volume may be fresh)
mkdir -p /data/pgdata
chown postgres:postgres /data/pgdata

# First-run: initialize data directory
if [ ! -f /data/pgdata/PG_VERSION ]; then
    echo "Initialising PostgreSQL data directory..."
    su -c "initdb -D /data/pgdata --auth=trust --no-locale --encoding=UTF8" postgres
    # Configure for Unix socket on /tmp, minimal memory, no TCP
    cat >> /data/pgdata/postgresql.conf << 'PGCONF'
unix_socket_directories = '/tmp'
listen_addresses = ''
shared_buffers = 32MB
work_mem = 4MB
maintenance_work_mem = 16MB
max_connections = 10
log_destination = 'stderr'
logging_collector = off
PGCONF
fi

# Start PostgreSQL (-w waits until ready before proceeding)
su -c "pg_ctl -D /data/pgdata -l /dev/null start -w" postgres
echo "PostgreSQL started on /tmp/.s.PGSQL.5432"

# Create database if it doesn't exist
su -c "createdb -h /tmp sentinel 2>/dev/null" postgres || true

# Enable pgvector extension
su -c "psql -h /tmp -d sentinel -c 'CREATE EXTENSION IF NOT EXISTS vector'" postgres 2>/dev/null || true

# Create application roles (idempotent — DO NOTHING if exists)
su -c "psql -h /tmp -d sentinel" postgres << 'ROLESQL'
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sentinel_owner') THEN
        CREATE ROLE sentinel_owner WITH LOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sentinel_app') THEN
        CREATE ROLE sentinel_app WITH LOGIN;
    END IF;
END
$$;

-- sentinel_owner owns all objects (for migrations)
GRANT ALL PRIVILEGES ON DATABASE sentinel TO sentinel_owner;

-- sentinel_app gets DML only (subject to RLS)
GRANT CONNECT ON DATABASE sentinel TO sentinel_app;

-- Safe default: unset session variable returns user_id=0 (no rows match)
ALTER DATABASE sentinel SET app.current_user_id = '0';

-- Revoke PL/pgSQL from PUBLIC, grant only to sentinel_owner.
-- Blocks DO $$ anonymous blocks from sentinel_app, closing LISTEN/NOTIFY + DO $$ attack vector.
-- Must run as superuser (postgres) — sentinel_owner cannot revoke from PUBLIC.
REVOKE ALL ON LANGUAGE plpgsql FROM PUBLIC;
GRANT USAGE ON LANGUAGE plpgsql TO sentinel_owner;
ROLESQL

# Start Sentinel (uvicorn) as the main process
exec uvicorn sentinel.api.app:app \
    --host 0.0.0.0 --port 8443 \
    --ssl-keyfile /app/tls/sentinel.key \
    --ssl-certfile /app/tls/sentinel.crt
