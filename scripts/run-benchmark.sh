#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

if [ "$#" -lt 1 ]; then
  printf '%s\n' 'usage: ./scripts/run-benchmark.sh NEW_REPORT_DIRECTORY [ulpf-benchmark flags...]' >&2
  exit 2
fi

output=$1
shift

go run ./cmd/ulpf-benchmark -out "$output" "$@"

