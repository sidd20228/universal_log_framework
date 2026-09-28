#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$repo_root"

./scripts/verify-container.sh

temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT INT TERM

expect_rejected() {
  name=$1
  candidate=$2
  ignore=${3:-.dockerignore}
  if DOCKERFILE="$candidate" DOCKERIGNORE="$ignore" ./scripts/verify-container.sh >/dev/null 2>&1; then
    printf '%s\n' "container policy test: $name unexpectedly passed" >&2
    exit 1
  fi
}

sed 's/@sha256:[0-9a-f]*//' Dockerfile >"$temporary/unpinned.Dockerfile"
expect_rejected 'unpinned bases' "$temporary/unpinned.Dockerfile"

sed 's/^USER 65532:65532$/USER 0:0/' Dockerfile >"$temporary/root.Dockerfile"
expect_rejected 'root runtime user' "$temporary/root.Dockerfile"

awk '/^USER / { print "ENV API_TOKEN=embedded-secret" } { print }' Dockerfile >"$temporary/secret.Dockerfile"
expect_rejected 'embedded secret' "$temporary/secret.Dockerfile"

awk '/^COPY go.mod/ { print "COPY . ." } { print }' Dockerfile >"$temporary/broad-copy.Dockerfile"
expect_rejected 'broad context copy' "$temporary/broad-copy.Dockerfile"

grep -Fvx '.env' .dockerignore >"$temporary/incomplete.dockerignore"
expect_rejected 'incomplete dockerignore' Dockerfile "$temporary/incomplete.dockerignore"

printf '%s\n' 'container policy test: success and rejection cases passed'
