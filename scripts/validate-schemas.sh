#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
validator=${JSONSCHEMA_BIN:-jsonschema}

if ! command -v "$validator" >/dev/null 2>&1; then
  printf '%s\n' "JSON Schema CLI '$validator' is required (jsonschema >= 4 with Draft 2020-12 support)" >&2
  exit 2
fi

validate_valid() {
  schema=$1
  instance=$2
  "$validator" -V Draft202012Validator "$schema" -i "$instance"
  printf 'valid: %s\n' "$instance"
}

validate_invalid() {
  schema=$1
  instance=$2
  if "$validator" -V Draft202012Validator "$schema" -i "$instance" >/dev/null 2>&1; then
    printf 'expected validation failure: %s\n' "$instance" >&2
    exit 1
  fi
  printf 'invalid as expected: %s\n' "$instance"
}

validate_valid "$repo_root/schemas/ulpf-envelope-1.0.0.json" "$repo_root/tests/schema/examples/valid/envelope.json"
validate_invalid "$repo_root/schemas/ulpf-envelope-1.0.0.json" "$repo_root/tests/schema/examples/invalid/envelope.json"
validate_invalid "$repo_root/schemas/ulpf-envelope-1.0.0.json" "$repo_root/tests/schema/examples/invalid/envelope-missing-raw-integrity.json"

validate_valid "$repo_root/schemas/ulpf-config-1.0.0.json" "$repo_root/tests/schema/examples/valid/config.json"
validate_invalid "$repo_root/schemas/ulpf-config-1.0.0.json" "$repo_root/tests/schema/examples/invalid/config.json"
validate_invalid "$repo_root/schemas/ulpf-config-1.0.0.json" "$repo_root/tests/schema/examples/invalid/config-inline-secret.json"

validate_valid "$repo_root/schemas/parser-bundle-manifest-1.0.0.json" "$repo_root/tests/schema/examples/valid/parser-bundle-manifest.json"
validate_invalid "$repo_root/schemas/parser-bundle-manifest-1.0.0.json" "$repo_root/tests/schema/examples/invalid/parser-bundle-manifest.json"
validate_invalid "$repo_root/schemas/parser-bundle-manifest-1.0.0.json" "$repo_root/tests/schema/examples/invalid/parser-bundle-path-traversal.json"
validate_invalid "$repo_root/schemas/parser-bundle-manifest-1.0.0.json" "$repo_root/tests/schema/examples/invalid/parser-bundle-executable.json"

"$repo_root/scripts/verify-ocsf-vendor.sh"
