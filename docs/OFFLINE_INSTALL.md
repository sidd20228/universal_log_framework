# Offline release assembly and installation

The offline release is a self-contained `ulpf-offline-<version>-<arch>.tar.zst`
archive. It carries the three container image archives (`ulpf`, `clickhouse`,
and `prometheus`), the Compose definition, the ULPF configuration inventory,
documentation, schemas, project and OCSF licenses, and an executable copy of
the verifier. `manifest.json` records the release version, architecture,
source commit, creation time, role, mode, byte length, and SHA-256 digest of
every artifact. `SHA256SUMS` covers every artifact and the manifest. An
adjacent `.sha256` file covers the complete compressed archive.

The SHA-256 files detect corruption and unintended changes. They do not prove
who produced the release. Transfer the archive and its sidecar through the
organization's authenticated release and media-control process. Release
signing and signature policy are not implemented by this script.

## Assemble on a connected build host

Build or mirror all images before assembly. The Compose file must reference
the exact tags saved into the archive and must be configured to use no
unpackaged runtime dependency. Replace the example paths and image references
with the release inputs produced by the deployment build:

```sh
version=0.1.0
arch=amd64
commit=$(git rev-parse HEAD)
epoch=$(git show -s --format=%ct "$commit")

SOURCE_DATE_EPOCH=$epoch ./scripts/build-offline-bundle.sh \
  --version "$version" \
  --arch "$arch" \
  --source-commit "$commit" \
  --compose compose.yaml \
  --config configs/ulpf.yaml \
  --image-ref "ulpf=ulpf:$version" \
  --image-ref "clickhouse=clickhouse/clickhouse-server:<pinned-version>" \
  --image-ref "prometheus=prom/prometheus:<pinned-version>" \
  --output "dist/ulpf-offline-$version-$arch.tar.zst"
```

`--image-ref` uses a running Docker or Podman engine, verifies that each image
is already local, and exports it. It never pulls. A host without an engine can
assemble the same release from existing Docker-save or OCI archives:

```sh
./scripts/build-offline-bundle.sh \
  --version "$version" --arch "$arch" --source-commit "$commit" \
  --source-date-epoch "$epoch" \
  --compose compose.yaml \
  --config configs/ulpf.yaml \
  --image "ulpf=release-inputs/ulpf-$arch.tar" \
  --image "clickhouse=release-inputs/clickhouse-$arch.tar" \
  --image "prometheus=release-inputs/prometheus-$arch.tar" \
  --output "dist/ulpf-offline-$version-$arch.tar.zst"
```

The builder rejects missing or extra image roles, symlinked inputs, unsafe
paths, and duplicate destinations. It writes entries in a stable order with
fixed ownership, modes, and `SOURCE_DATE_EPOCH`, then runs the verifier before
reporting success. Identical input bytes and metadata produce identical `.tar`
and `.tar.zst` bytes. Container-engine export bytes are an input to that
guarantee; export each image once and reuse that file when checking release
reproducibility.

`configs/ulpf.yaml` records the release defaults for inspection and change
control. The current runtime receives the equivalent values through the
`ulpf serve` arguments in `compose.yaml`; it does not parse the YAML file.

Add generated release evidence with repeatable
`--artifact ROLE:DESTINATION=FILE` arguments. Supported optional roles are
`sbom`, `vulnerability_report`, `notice`, and `signature`; each added file is
covered by the manifest and both checksum layers.

Run verification on the build host before transfer:

```sh
./scripts/verify-offline-bundle.sh \
  "dist/ulpf-offline-$version-$arch.tar.zst"
```

Python 3 is required. `zstd` is also required for `.tar.zst`; use `.tar` when
zstd is unavailable. Assembly and verification make no network requests.

## Verify and install with networking disabled

Copy both the archive and its `<archive>.sha256` sidecar to a clean target.
Disconnect the target from external networks, or apply the site's egress-deny
policy, before running these commands. Keep that control enabled for the whole
test so an accidental pull cannot succeed.

```sh
archive=ulpf-offline-0.1.0-amd64.tar.zst
install_dir=/opt/ulpf/releases/0.1.0-amd64

python3 ./verify-offline-bundle.py "$archive"
python3 ./verify-offline-bundle.py "$archive" --extract "$install_dir"
```

The extraction destination must not exist. Verification completes before the
temporary extraction is renamed into place. The verifier rejects absolute or
parent paths, non-canonical paths, duplicate members, links, devices and other
special files, undeclared files, missing required roles, malformed or
duplicate-key manifests, checksum/size/mode mismatches, and unsafe nested
image-archive members. It places explicit limits on archive size and member
count. Set `ULPF_OFFLINE_MAX_ARCHIVE_BYTES` to a smaller site limit if needed.

Load only the verified image archives:

```sh
docker load --input "$install_dir/images/ulpf-amd64.tar"
docker load --input "$install_dir/images/clickhouse-amd64.tar"
docker load --input "$install_dir/images/prometheus-amd64.tar"
```

Use `podman load --input ...` for Podman. Before startup, confirm that every
image referenced by Compose exists locally:

```sh
docker compose -f "$install_dir/compose/compose.yaml" config --images |
while IFS= read -r image; do
  docker image inspect "$image" >/dev/null || exit 1
done
```

Generate runtime secret files on the offline host and apply the ownership and
permissions described by the deployment configuration. Do not add secrets to
the extracted configuration or image layers. Validate the rendered Compose
configuration, then start with pulls prohibited:

```sh
docker compose -f "$install_dir/compose/compose.yaml" config --quiet
docker compose -f "$install_dir/compose/compose.yaml" up --detach --pull never
docker compose -f "$install_dir/compose/compose.yaml" ps
curl --fail --silent http://127.0.0.1:8080/health/ready
```

A successful clean-install test has all services healthy, readiness returning
success, and no allowed egress observed by the host firewall or network
control. Record the bundle digest, image IDs, rendered Compose validation,
health output, and egress-control log with the release evidence.

## Verifier-only test and validation limits

The repository test does not need Docker, Podman, or network access:

```sh
./tests/offline/test-offline-bundle.sh
```

It creates a complete synthetic release, proves repeatable tar and zstd output,
verifies and extracts it, detects byte tampering, and checks rejection of path
traversal, symlink, duplicate-member, and incomplete-inventory archives.

Without a running container engine, automated validation stops after checking
the nested archive structure and cryptographic inventory. It cannot prove that
an engine accepts each image, that the image architecture matches its label,
or that the full Compose stack reaches health. Those checks must run on the
offline target (or an equivalent isolated host) with the intended engine and
architecture. The current archive contract permits SBOM, vulnerability-report,
notice, and signature roles, but release production must add and enforce those
artifacts when the corresponding generation and trust policy are available.
