#!/bin/sh
set -eu

if test "$#" -ne 2; then
  printf '%s\n' 'usage: ./scripts/test-offline-install.sh ARCHIVE TRUSTED_PUBLIC_KEY' >&2
  exit 2
fi

archive=$1
trusted_public_key=$2
started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
archive=$(CDPATH= cd -- "$(dirname -- "$archive")" && pwd)/$(basename -- "$archive")
test -f "$archive" || { printf 'archive not found: %s\n' "$archive" >&2; exit 2; }

command -v docker >/dev/null 2>&1 || { printf '%s\n' 'Docker is required' >&2; exit 2; }
docker info >/dev/null
docker compose version >/dev/null
command -v curl >/dev/null 2>&1 || { printf '%s\n' 'curl is required' >&2; exit 2; }

temporary=$(mktemp -d)
install_dir=$temporary/release
project=ulpf-offline-proof

cleanup() {
  if test -f "$install_dir/compose/compose.yaml"; then
    docker compose -p "$project" -f "$install_dir/compose/compose.yaml" down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
  rm -rf "$temporary"
}
trap cleanup EXIT INT TERM

python3 "$repo_root/scripts/verify-offline-bundle.py" "$archive" \
  --trusted-public-key "$trusted_public_key" --extract "$install_dir"
compose=$install_dir/compose/compose.yaml

images=$(docker compose -p "$project" -f "$compose" config --images)
test "$(printf '%s\n' "$images" | sed '/^$/d' | wc -l | tr -d ' ')" -eq 2
network_name=$(docker compose -p "$project" -f "$compose" config --format json | python3 -c '
import json, sys
networks = json.load(sys.stdin).get("networks", {})
denied = [name for name, value in networks.items()
          if value.get("driver") == "bridge" and
          value.get("driver_opts", {}).get("com.docker.network.bridge.enable_ip_masquerade") == "false"]
if len(denied) != 1:
    raise SystemExit("offline Compose must define exactly one non-masqueraded bridge")
print(denied[0])
')

# This proof starts with neither release image tagged in the engine, then loads
# exactly the archives carried by the verified package. pull_policy and --pull
# both prohibit a registry fallback.
printf '%s\n' "$images" | while IFS= read -r image; do
  test -n "$image" && docker image rm --force "$image" >/dev/null 2>&1 || true
done

architecture=$(python3 - "$archive" <<'PY'
import re, sys
match = re.search(r"-(amd64|arm64)\.tar(?:\.zst)?$", sys.argv[1])
if not match:
    raise SystemExit("cannot determine archive architecture")
print(match.group(1))
PY
)
docker load --input "$install_dir/images/ulpf-$architecture.tar" >/dev/null
docker load --input "$install_dir/images/clickhouse-$architecture.tar" >/dev/null
printf '%s\n' "$images" | while IFS= read -r image; do
  test -n "$image" && docker image inspect "$image" >/dev/null
done
image_ids=$(printf '%s\n' "$images" | while IFS= read -r image; do
  test -n "$image" && docker image inspect "$image" --format '{{.Id}}'
done)

docker compose -p "$project" -f "$compose" up --detach --wait --pull never
docker network inspect "${project}_${network_name}" \
  --format '{{index .Options "com.docker.network.bridge.enable_ip_masquerade"}}' | grep -qx false
if docker compose -p "$project" -f "$compose" exec -T clickhouse \
  wget -T 3 -qO- http://1.1.1.1 >/dev/null 2>&1; then
  printf '%s\n' 'offline network unexpectedly permits external egress' >&2
  exit 1
fi

response=$(curl --silent --show-error --fail-with-body \
  -H "Authorization: Bearer $ULPF_API_TOKEN" \
  -H 'Content-Type: application/octet-stream' \
  --data-binary '{"event_type":"offline-proof","action":"allow"}' \
  http://127.0.0.1:8080/api/v1/ingest)
receipt_id=$(printf '%s' "$response" | python3 -c 'import json,sys; print(json.load(sys.stdin)["receipt_id"])')

attempt=0
page=
while test "$attempt" -lt 100; do
  page=$(curl --silent --show-error --fail-with-body \
    -H "Authorization: Bearer $ULPF_API_TOKEN" \
    'http://127.0.0.1:8080/api/v1/events?tenant_id=demo')
  if printf '%s' "$page" | grep -q '"revision_id"'; then
    break
  fi
  attempt=$((attempt + 1))
  sleep 0.1
done
printf '%s' "$page" | grep -q '"revision_id"'

curl --silent --show-error --fail-with-body \
  -H "Authorization: Bearer $ULPF_API_TOKEN" \
  'http://127.0.0.1:8080/api/v1/dashboard/summary?tenant_id=demo' | grep -q '"committed_total":1'

docker compose -p "$project" -f "$compose" restart ulpf >/dev/null
docker compose -p "$project" -f "$compose" up --detach --wait --pull never >/dev/null
curl --silent --show-error --fail-with-body \
  -H "Authorization: Bearer $ULPF_API_TOKEN" \
  'http://127.0.0.1:8080/api/v1/events?tenant_id=demo' | grep -q '"revision_id"'

if test -n "${ULPF_OFFLINE_EVIDENCE_PATH:-}"; then
  archive_sha256=$(python3 - "$archive" <<'PY'
import hashlib, pathlib, sys
digest = hashlib.sha256()
with pathlib.Path(sys.argv[1]).open("rb") as stream:
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(block)
print(digest.hexdigest())
PY
)
  finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  python3 - "$ULPF_OFFLINE_EVIDENCE_PATH" "$archive_sha256" "$architecture" "$receipt_id" "$started_at" "$finished_at" "$image_ids" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
value = {
    "contract_version": "ulpf-offline-install-proof/1",
    "archive_sha256": sys.argv[2],
    "architecture": sys.argv[3],
    "receipt_id": sys.argv[4],
    "started_at": sys.argv[5],
    "finished_at": sys.argv[6],
    "image_ids": sorted(line for line in sys.argv[7].splitlines() if line),
    "controls": {"pull_policy_never": True, "clean_release_tags": True, "container_egress_denied": True},
    "checks": {"signature": True, "ingest": True, "query": True, "dashboard": True, "restart_persistence": True},
}
path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
fi

printf 'offline clean-install proof passed: receipt=%s architecture=%s pull_policy=never\n' "$receipt_id" "$architecture"
