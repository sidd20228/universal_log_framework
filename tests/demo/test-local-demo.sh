#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$repo_root"

workspace=$(mktemp -d)
trap 'rm -rf "$workspace"' EXIT INT TERM

go build -trimpath -ldflags '-s -w -buildid= -X main.version=test -X main.commit=0000000000000000000000000000000000000000 -X main.buildDate=1970-01-01T00:00:00Z' -o "$workspace/ulpf" ./cmd/ulpf

./scripts/run-local-demo.sh \
  --binary "$workspace/ulpf" \
  --output-dir "$workspace/evidence" \
  --run-label test-run \
  --port 18083

python3 - "$workspace/evidence/test-run.json" "$workspace/evidence/test-run.md" <<'PY'
import json
from pathlib import Path
import sys

machine = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
markdown = Path(sys.argv[2]).read_text(encoding="utf-8")
assert machine["evidence_version"] == "ulpf-local-demo/1.0.0"
assert machine["result"] == "pass"
assert machine["duration_ms"] <= 120_000
assert machine["observations"]["unauthenticated_status"] == 401
assert machine["observations"]["admission_status"] == 202
assert machine["trace"]["status"] == "PARTIALLY_PARSED"
assert machine["trace"]["parser_id"] == "generic-json"
assert machine["invariants"] and all(machine["invariants"].values())
assert "Result: **PASS**" in markdown
assert machine["trace"]["receipt_id"] in markdown
print("local demo evidence test: PASS")
PY
