# Offline release assembly and installation

The offline release is a self-contained `ulpf-offline-<version>-<arch>.tar.zst`
archive. It carries Docker-save archives for ULPF and ClickHouse, an image-only
Compose definition, the ClickHouse schema migration, the ULPF configuration
inventory, documentation, schemas, project and OCSF licenses, and an executable
copy of the verifier. `manifest.json` records the release version,
architecture, source commit, creation time, role, mode, byte length, and
SHA-256 digest of every artifact. `SHA256SUMS` covers every artifact and the
manifest. Required adjacent `.sha256`, `.signature.json`, and `.signature.sig`
files bind the complete compressed archive to an expiring publisher statement.
The verifier derives the RSA public-key fingerprint, checks revocation policy,
validates the signed interval and archive digest, then verifies the detached
RSA/SHA-256 signature. Provision the trusted public key and revoked-key list
through a separate authenticated channel; they are not carried in the archive.
The repository versions its current verification key at
[`release/trust/offline-signing-public.pem`](../release/trust/offline-signing-public.pem).
Pin that file through the same authenticated Git source used for the release;
the matching private key exists only as a GitHub Actions secret.

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
  --compose deployments/offline/compose.yaml \
  --config configs/ulpf.yaml \
  --clickhouse-migration migrations/clickhouse/001_events.sql \
  --image-ref "ulpf=ulpf:$version" \
  --image-ref "clickhouse=clickhouse/clickhouse-server:<pinned-version>" \
  --signing-key /secure/release-signing-key.pem \
  --signing-public-key /release-trust/ulpf-release-public.pem \
  --signature-expires-at 2027-09-29T00:00:00Z \
  --artifact sbom:reports/ulpf.spdx.json=release-inputs/ulpf.spdx.json \
  --artifact vulnerability_report:reports/vulnerabilities.json=release-inputs/vulnerabilities.json \
  --artifact license_inventory:reports/licenses.json=release-inputs/licenses.json \
  --output "dist/ulpf-offline-$version-$arch.tar.zst"
```

`--image-ref` uses a running Docker or Podman engine, verifies that each image
is already local, and exports it. It never pulls. A host without an engine can
assemble the same release from existing Docker-save archives:

```sh
./scripts/build-offline-bundle.sh \
  --version "$version" --arch "$arch" --source-commit "$commit" \
  --source-date-epoch "$epoch" \
  --compose deployments/offline/compose.yaml \
  --config configs/ulpf.yaml \
  --clickhouse-migration migrations/clickhouse/001_events.sql \
  --image "ulpf=release-inputs/ulpf-$arch.tar" \
  --image "clickhouse=release-inputs/clickhouse-$arch.tar" \
  --signing-key /secure/release-signing-key.pem \
  --signing-public-key /release-trust/ulpf-release-public.pem \
  --signature-expires-at 2027-09-29T00:00:00Z \
  --artifact sbom:reports/ulpf.spdx.json=release-inputs/ulpf.spdx.json \
  --artifact vulnerability_report:reports/vulnerabilities.json=release-inputs/vulnerabilities.json \
  --artifact license_inventory:reports/licenses.json=release-inputs/licenses.json \
  --output "dist/ulpf-offline-$version-$arch.tar.zst"
```

The builder rejects missing or extra image roles, symlinked inputs, unsafe
paths, and duplicate destinations. Each image archive must contain exactly one
Docker-save manifest entry. The ULPF image repository basename must be `ulpf`
and its tag must equal the release version. The ClickHouse image must have a
versioned `clickhouse/clickhouse-server` tag.
The builder validates the Linux OS, requested architecture, content-addressed
configuration, referenced layers, and root-filesystem layer inventory. It then
renders those proven tags into the release Compose template. The resulting
Compose file has no build context, sets `pull_policy: never` on both services,
and uses a non-masqueraded Docker bridge. The services can communicate with
each other and the operator can use the published localhost port, while
containers cannot route outbound through Docker's external NAT.

Entries are written in a stable order with fixed ownership, modes, and
`SOURCE_DATE_EPOCH`, then the complete archive is verified before success is
reported. Identical input bytes and metadata produce identical `.tar` and
`.tar.zst` bytes. Container-engine export bytes are an input to that guarantee;
export each image once and reuse that file when checking release
reproducibility.

`configs/ulpf.yaml` records the release defaults for inspection and change
control. The current runtime receives the equivalent values through the
`ulpf serve` arguments in `compose.yaml`; it does not parse the YAML file.

Add generated release evidence with repeatable
`--artifact ROLE:DESTINATION=FILE` arguments. `sbom`,
`vulnerability_report`, and `license_inventory` are mandatory; `notice` is
optional. Every artifact is covered by the manifest and both checksum layers.
The builder refuses unsigned release output. `--unsigned-test-bundle` exists
only for repository fixtures and makes the verifier require `--test-mode`.

Run verification on the build host before transfer:

```sh
./scripts/verify-offline-bundle.sh \
  "dist/ulpf-offline-$version-$arch.tar.zst" \
  --trusted-public-key /release-trust/ulpf-release-public.pem \
  --revoked-key-file /release-trust/revoked-key-ids.txt
```

Python 3 is required. `zstd` is also required for `.tar.zst`; use `.tar` when
zstd is unavailable. Assembly and verification make no network requests.

## Verify and install with networking disabled

Copy the archive plus its `.sha256`, `.signature.json`, and `.signature.sig`
sidecars to a clean target. Separately provision the trusted publisher public
key and current ASCII revocation list. Verification fails when trust material
is absent, the key is wrong or revoked, the statement is expired, or the
signature/digest differs. `--test-mode` permits missing outer trust material
only for repository fixtures and must never approve or install a transferred
release. Stage the matching
`scripts/verify-offline-bundle.py` through the same authenticated media process;
the copy inside the archive is retained for subsequent re-verification after a
successful safe extraction.
Keep the target disconnected from external networks while loading the archive.
The packaged Compose definition also disables IP masquerading on its Docker
bridge. The clean-install harness rejects the deployment if that engine control
is absent and fails if a container can reach an external IP. Pulling remains
disabled independently through `pull_policy: never` and the harness's
`--pull never` invocation.

```sh
archive=ulpf-offline-0.1.0-amd64.tar.zst
install_dir=/opt/ulpf/releases/0.1.0-amd64

python3 ./verify-offline-bundle.py "$archive" \
  --trusted-public-key /release-trust/ulpf-release-public.pem \
  --revoked-key-file /release-trust/revoked-key-ids.txt
python3 ./verify-offline-bundle.py "$archive" \
  --trusted-public-key /release-trust/ulpf-release-public.pem \
  --revoked-key-file /release-trust/revoked-key-ids.txt \
  --extract "$install_dir"
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
```

Use `podman load --input ...` for Podman. Before startup, confirm that every
image referenced by Compose exists locally. Set fresh runtime secrets first
because Compose validates the required variables even for `config --images`:

```sh
export ULPF_API_TOKEN="$(openssl rand -hex 32)"
export CLICKHOUSE_PASSWORD="$(openssl rand -hex 32)"

docker compose -f "$install_dir/compose/compose.yaml" config --images |
while IFS= read -r image; do
  docker image inspect "$image" >/dev/null || exit 1
done
```

Generate runtime secrets on the offline host and follow the site's secret
handling procedure. Do not add secrets to the extracted configuration or
image layers. The packaged Compose file mounts the
packaged ClickHouse migration into the database initialization directory; on a
new ClickHouse data volume, readiness therefore verifies that `ulpf.events`
exists. Initialization scripts do not rerun on an existing database volume,
so upgrades must apply newly introduced migrations through the release's
documented upgrade procedure.

Validate the rendered Compose configuration, then start with pulls prohibited:

```sh
docker compose -f "$install_dir/compose/compose.yaml" config --quiet
docker compose -f "$install_dir/compose/compose.yaml" up --detach --pull never
docker compose -f "$install_dir/compose/compose.yaml" ps
curl --fail --silent http://127.0.0.1:8080/health/ready
```

A successful clean-install test has all services healthy, readiness returning
success, and the Compose network reported as non-masqueraded by the engine.
Record the bundle digest, image IDs, rendered Compose validation, health output,
and failed external egress probe with the release evidence.

## Verifier-only test and validation limits

The repository test does not need Docker, Podman, or network access:

```sh
./tests/offline/test-offline-bundle.sh
```

It creates structurally valid synthetic Docker-save images and a complete
release, proves repeatable tar and zstd output, verifies and extracts it,
detects byte tampering, and checks rejection of path traversal, symlinks,
duplicate members, missing sidecars, incomplete inventories, wrong image tags,
wrong architectures, missing image layers, and inconsistent layer digests.

Without a running container engine, automated validation stops after checking
the Docker-save structure, image configuration OS/architecture, referenced
layers, rendered Compose definition, and cryptographic inventory. It cannot
prove that the target engine accepts or natively executes each image or that
the full Compose stack reaches health. Those checks must run on the offline
target (or an equivalent isolated host) with the intended engine and
architecture. The clean-install harness also verifies the engine applied the
non-masqueraded network control and rejects an allowed external egress probe.
The release workflow uses native
amd64 and arm64 runners, requires SBOM, vulnerability, and dependency-license
inventories, signs and attests outputs, and invokes
`scripts/test-offline-install.sh`. Publishing depends on protected signing-key
secrets and both native runner jobs passing.
