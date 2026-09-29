#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$repo_root"

fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT INT TERM

mkdir -p "$fixture/docs" "$fixture/schemas" "$fixture/images"
printf '%s\n' '# Offline fixture runbook' >"$fixture/docs/runbook.md"
printf '%s\n' '{"type":"object"}' >"$fixture/schemas/example.json"
printf '%s\n' 'fixture project license' >"$fixture/LICENSE"
printf '%s\n' 'fixture schema license' >"$fixture/OCSF-LICENSE"
printf '%s\n' 'synthetic release notice' >"$fixture/NOTICE"
printf '%s\n' 'services: {}' >"$fixture/compose.yaml"
printf '%s\n' 'config_version: ulpf-config/1' >"$fixture/ulpf.yaml"

python3 - "$fixture/images" <<'PY'
import io
from pathlib import Path
import sys
import tarfile

root = Path(sys.argv[1])
for name in ("ulpf", "clickhouse", "prometheus"):
    with tarfile.open(root / f"{name}.tar", "w", format=tarfile.GNU_FORMAT) as archive:
        body = b"[]\n"
        info = tarfile.TarInfo("manifest.json")
        info.size = len(body)
        info.mode = 0o644
        info.mtime = 0
        archive.addfile(info, io.BytesIO(body))
PY

build_bundle() {
  output=$1
  ./scripts/build-offline-bundle.sh \
    --version 1.2.3 \
    --arch amd64 \
    --source-commit aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    --source-date-epoch 0 \
    --output "$output" \
    --compose "$fixture/compose.yaml" \
    --config "$fixture/ulpf.yaml" \
    --docs-root "$fixture/docs" \
    --schemas-root "$fixture/schemas" \
    --license "$fixture/LICENSE" \
    --ocsf-license "$fixture/OCSF-LICENSE" \
    --artifact "notice:reports/NOTICE=$fixture/NOTICE" \
    --image "ulpf=$fixture/images/ulpf.tar" \
    --image "clickhouse=$fixture/images/clickhouse.tar" \
    --image "prometheus=$fixture/images/prometheus.tar"
}

build_bundle "$fixture/first.tar"
build_bundle "$fixture/second.tar"
cmp "$fixture/first.tar" "$fixture/second.tar"
./scripts/verify-offline-bundle.sh "$fixture/first.tar"

cp "$fixture/first.tar" "$fixture/no-sidecar.tar"
./scripts/verify-offline-bundle.sh "$fixture/no-sidecar.tar" >/dev/null
ln -s "$fixture/first.tar" "$fixture/archive-link.tar"
if ./scripts/verify-offline-bundle.sh "$fixture/archive-link.tar" >/dev/null 2>&1; then
  printf '%s\n' 'symlinked release archive unexpectedly verified' >&2
  exit 1
fi

./scripts/verify-offline-bundle.sh "$fixture/first.tar" --extract "$fixture/extracted"
cmp "$fixture/ulpf.yaml" "$fixture/extracted/config/ulpf.yaml"
test -x "$fixture/extracted/install/verify-offline-bundle.py"

if command -v zstd >/dev/null 2>&1; then
  build_bundle "$fixture/first.tar.zst"
  build_bundle "$fixture/second.tar.zst"
  cmp "$fixture/first.tar.zst" "$fixture/second.tar.zst"
  ./scripts/verify-offline-bundle.sh "$fixture/first.tar.zst"
fi

cp "$fixture/first.tar" "$fixture/tampered.tar"
python3 - "$fixture/tampered.tar" <<'PY'
import sys
import tarfile

path = sys.argv[1]
with tarfile.open(path, "r:") as archive:
    member = archive.getmember("ulpf-offline-1.2.3-amd64/config/ulpf.yaml")
    offset = member.offset_data
with open(path, "r+b") as stream:
    stream.seek(offset)
    original = stream.read(1)
    stream.seek(offset)
    stream.write(b"X" if original != b"X" else b"Y")
PY
if ./scripts/verify-offline-bundle.sh "$fixture/tampered.tar" >/dev/null 2>&1; then
  printf '%s\n' 'tampered archive unexpectedly verified' >&2
  exit 1
fi

cp "$fixture/first.tar" "$fixture/trailing-data.tar"
printf '%s' 'appended-data' >>"$fixture/trailing-data.tar"
if ./scripts/verify-offline-bundle.sh "$fixture/trailing-data.tar" >/dev/null 2>&1; then
  printf '%s\n' 'archive with trailing data unexpectedly verified' >&2
  exit 1
fi

python3 - "$fixture" <<'PY'
import io
from pathlib import Path
import sys
import tarfile

root = Path(sys.argv[1])

def write(name, entries):
    with tarfile.open(root / name, "w", format=tarfile.GNU_FORMAT) as archive:
        for path, kind in entries:
            info = tarfile.TarInfo(path)
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = 0
            if kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                archive.addfile(info)
            else:
                body = b"{}\n"
                info.size = len(body)
                info.mode = 0o644
                archive.addfile(info, io.BytesIO(body))

write("traversal.tar", [("../escape", "file")])
write("symlink.tar", [("ulpf-offline-1.2.3-amd64/link", "symlink")])
write("duplicate.tar", [
    ("ulpf-offline-1.2.3-amd64/manifest.json", "file"),
    ("ulpf-offline-1.2.3-amd64/manifest.json", "file"),
])

with tarfile.open(root / "duplicate-key.tar", "w", format=tarfile.GNU_FORMAT) as archive:
    body = b'{"manifest_version":"one","manifest_version":"two"}\n'
    for path, payload in (
        ("ulpf-offline-1.2.3-amd64/manifest.json", body),
        ("ulpf-offline-1.2.3-amd64/SHA256SUMS", b"0" * 64 + b"  manifest.json\n"),
    ):
        info = tarfile.TarInfo(path)
        info.size = len(payload)
        info.mode = 0o644
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        info.mtime = 0
        archive.addfile(info, io.BytesIO(payload))
PY

for malicious in traversal symlink duplicate duplicate-key; do
  if ./scripts/verify-offline-bundle.sh "$fixture/$malicious.tar" >/dev/null 2>&1; then
    printf '%s\n' "$malicious archive unexpectedly verified" >&2
    exit 1
  fi
done

if ./scripts/build-offline-bundle.sh \
  --version 1.2.3 --arch amd64 --output "$fixture/incomplete.tar" \
  --compose "$fixture/compose.yaml" --config "$fixture/ulpf.yaml" \
  --docs-root "$fixture/docs" --schemas-root "$fixture/schemas" \
  --license "$fixture/LICENSE" --ocsf-license "$fixture/OCSF-LICENSE" \
  --image "ulpf=$fixture/images/ulpf.tar" \
  --image "clickhouse=$fixture/images/clickhouse.tar" >/dev/null 2>&1; then
  printf '%s\n' 'incomplete image inventory unexpectedly assembled' >&2
  exit 1
fi

python3 - "$fixture/images/bad.tar" <<'PY'
import io
import sys
import tarfile

with tarfile.open(sys.argv[1], "w", format=tarfile.GNU_FORMAT) as archive:
    for path in ("manifest.json", "../escape"):
        body = b"[]\n"
        info = tarfile.TarInfo(path)
        info.size = len(body)
        info.mode = 0o644
        info.mtime = 0
        archive.addfile(info, io.BytesIO(body))
PY
if ./scripts/build-offline-bundle.sh \
  --version 1.2.3 --arch amd64 --output "$fixture/bad-image-bundle.tar" \
  --compose "$fixture/compose.yaml" --config "$fixture/ulpf.yaml" \
  --docs-root "$fixture/docs" --schemas-root "$fixture/schemas" \
  --license "$fixture/LICENSE" --ocsf-license "$fixture/OCSF-LICENSE" \
  --image "ulpf=$fixture/images/bad.tar" \
  --image "clickhouse=$fixture/images/clickhouse.tar" \
  --image "prometheus=$fixture/images/prometheus.tar" >/dev/null 2>&1; then
  printf '%s\n' 'unsafe nested image archive unexpectedly assembled' >&2
  exit 1
fi
test ! -e "$fixture/bad-image-bundle.tar"

printf '%s\n' 'offline bundle tests passed'
