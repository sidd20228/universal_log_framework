#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$repo_root"

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  compose='docker compose'
elif command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1 && podman compose version >/dev/null 2>&1; then
  compose='podman compose'
else
  printf '%s\n' 'compose smoke: SKIP (no available Docker Compose or Podman Compose engine)'
  exit 0
fi

command -v curl >/dev/null 2>&1 || {
  printf '%s\n' 'compose smoke: SKIP (curl is unavailable)'
  exit 0
}

token=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
password=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
export ULPF_API_TOKEN=$token
export CLICKHOUSE_PASSWORD=$password
export ULPF_HTTP_PORT=${ULPF_HTTP_PORT:-18080}

cleanup() {
  $compose down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

$compose up --build --detach --wait

response=$(curl --silent --show-error --fail-with-body \
  -H "Authorization: Bearer $ULPF_API_TOKEN" \
  -H 'Content-Type: application/octet-stream' \
  --data-binary '{"event_type":"traffic","action":"allow"}' \
  "http://127.0.0.1:$ULPF_HTTP_PORT/api/v1/ingest")
printf '%s' "$response" | grep -q '"receipt_id"'

attempt=0
while test "$attempt" -lt 50; do
  page=$(curl --silent --show-error --fail-with-body \
    -H "Authorization: Bearer $ULPF_API_TOKEN" \
    "http://127.0.0.1:$ULPF_HTTP_PORT/api/v1/events?tenant_id=demo")
  if printf '%s' "$page" | grep -q '"revision_id"'; then
    printf '%s\n' 'compose smoke: healthy admission-to-query path verified'
    exit 0
  fi
  attempt=$((attempt + 1))
  sleep 0.1
done

printf '%s\n' 'compose smoke: admitted event did not become queryable' >&2
exit 1
