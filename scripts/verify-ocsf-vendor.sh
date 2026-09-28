#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
vendor_dir=${OCSF_VENDOR_DIR:-"$repo_root/schemas/vendor/ocsf/1.9.0"}

if command -v sha256sum >/dev/null 2>&1; then
  calculated_manifest_digest=$(sha256sum "$vendor_dir/SHA256SUMS" | awk '{print $1}')
  (
    cd "$vendor_dir"
    sha256sum -c SHA256SUMS
  )
elif command -v shasum >/dev/null 2>&1; then
  calculated_manifest_digest=$(shasum -a 256 "$vendor_dir/SHA256SUMS" | awk '{print $1}')
  (
    cd "$vendor_dir"
    shasum -a 256 -c SHA256SUMS
  )
else
  printf '%s\n' "sha256sum or shasum is required" >&2
  exit 2
fi

recorded_manifest_digest=$(tr -d '[:space:]' < "$vendor_dir/TREE_SHA256")
if [ "$calculated_manifest_digest" != "$recorded_manifest_digest" ]; then
  printf '%s\n' "OCSF checksum manifest digest does not match TREE_SHA256" >&2
  exit 1
fi

printf '%s\n' "OCSF 1.9.0 vendor checksums verified"
