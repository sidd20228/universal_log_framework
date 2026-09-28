#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/ulpf-ocsf-integrity.XXXXXX")
trap 'rm -rf "$temporary_root"' EXIT HUP INT TERM

cp -R "$repo_root/schemas/vendor/ocsf/1.9.0" "$temporary_root/1.9.0"
printf '\n' >> "$temporary_root/1.9.0/version.json"

if OCSF_VENDOR_DIR="$temporary_root/1.9.0" "$repo_root/scripts/verify-ocsf-vendor.sh" >/dev/null 2>&1; then
  printf '%s\n' "tampered OCSF source unexpectedly passed checksum verification" >&2
  exit 1
fi

printf '%s\n' "tampered OCSF source rejected as expected"
