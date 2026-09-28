#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

go test -race ./tests/e2e -count=1 "$@"
