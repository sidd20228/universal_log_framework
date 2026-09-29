#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$repo_root"

output_dir=${1:-output/demo}
run_label=${2:-local-demo}
port=${ULPF_DEMO_PORT:-18080}
workspace=$(mktemp -d)
trap 'rm -rf "$workspace"' EXIT INT TERM

commit=$(git rev-parse HEAD 2>/dev/null || printf unknown)
build_date=$(date -u +%Y-%m-%dT%H:%M:%SZ)
go build -trimpath \
  -ldflags "-s -w -buildid= -X main.version=demo -X main.commit=$commit -X main.buildDate=$build_date" \
  -o "$workspace/ulpf" ./cmd/ulpf

exec ./scripts/run-local-demo.sh \
  --binary "$workspace/ulpf" \
  --output-dir "$output_dir" \
  --run-label "$run_label" \
  --port "$port" \
  --limit-seconds 120
