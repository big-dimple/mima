#!/usr/bin/env bash
# Start or reuse the dedicated PostgreSQL container for Mima tests.
set -euo pipefail

NAME=${MIMA_POSTGRES_CONTAINER:-mima-postgres}
PORT=${MIMA_POSTGRES_PORT:-55432}
IMAGE=postgres:18-trixie

if docker ps --format '{{.Names}}' | grep -qx "$NAME"; then
  echo "$NAME already running"
elif docker ps -a --format '{{.Names}}' | grep -qx "$NAME"; then
  docker start "$NAME"
else
  docker run -d --name "$NAME" \
    -e POSTGRES_USER=mima \
    -e POSTGRES_PASSWORD=mima_dev_pw \
    -e POSTGRES_DB=mima \
    -p "127.0.0.1:${PORT}:5432" \
    "$IMAGE"
fi

echo -n "waiting for postgres"
for _ in $(seq 1 30); do
  if docker exec "$NAME" pg_isready -U mima -d mima >/dev/null 2>&1; then
    echo " ready"
    exit 0
  fi
  echo -n .
  sleep 1
done
echo " timed out" >&2
exit 1
