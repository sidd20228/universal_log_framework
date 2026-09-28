# Container and secret hardening

The ULPF image is built with a digest-pinned Go builder and a digest-pinned
distroless runtime. The build copies only the Go module, command, internal
packages, and embedded migrations into its build stage. The runtime receives
only the static `ulpf` binary and empty runtime directories.

The pinned multi-platform image indexes are:

- `docker.io/library/golang:1.24.0-alpine3.21@sha256:2d40d4fc278dad38be0777d5e2a88a2c6dee51b0b29c97a764fc6c6a11ca893c`
- `gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab`

Update these pins deliberately after reviewing the upstream image and testing
both `linux/amd64` and `linux/arm64`. Digest pinning makes the selected input
stable; it does not eliminate the need to review and scan that input. Docker's
official guidance describes [multi-stage builds](https://docs.docker.com/build/building/multi-stage/),
[digest pinning](https://docs.docker.com/build/building/best-practices/#pin-base-image-versions),
and the [`USER` and `HEALTHCHECK` instructions](https://docs.docker.com/reference/dockerfile/).

## Build

Supply deterministic release metadata explicitly. The defaults are stable
development values, including a Unix-epoch build date.

```sh
docker build \
  --build-arg VERSION=0.1.0 \
  --build-arg COMMIT="$(git rev-parse HEAD)" \
  --build-arg BUILD_DATE=2026-09-29T00:00:00Z \
  -t ulpf:0.1.0 .
```

The build uses `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false`, and stripped
symbols. Repeating a build with the same source, build arguments, Go toolchain,
and pinned base-image manifests removes known timestamp and VCS-path variance.
The repository does not yet publish a byte-for-byte image reproducibility
attestation.

## Runtime policy

The image declares numeric user and group `65532:65532`. Its home, temporary,
raw evidence, SQLite state, and installed-bundle paths are below
`/var/lib/ulpf`. Run it with that path supplied as a writable volume or tmpfs;
the remainder of the root filesystem can stay read-only.

```sh
docker run --rm \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --tmpfs /var/lib/ulpf:rw,noexec,nosuid,nodev,size=64m \
  ulpf:0.1.0 version --json
```

Persistent deployments should mount `/var/lib/ulpf` from storage owned by UID
and GID 65532 instead of using tmpfs. Configuration and parser source bundles
should be mounted read-only. T32 owns the Compose resource limits, networks,
volume declarations, and service command.

The image health check executes `ulpf version` without a shell. This confirms
that the process image remains executable under the configured identity. It is
compatible with a long-running service command, but it is not an application
readiness probe. A deployment should target the public readiness endpoint once
the server command exposes it.

## Secrets

Do not pass credentials through Docker build arguments, Dockerfile `ENV`
instructions, image labels, committed configuration, or command-line flags.
The build context excludes common environment, private-key, certificate,
database, raw-data, and secret-directory paths. Runtime secrets belong in
orchestrator-managed files mounted outside the image with the narrowest
possible permissions. Configuration should contain only the mounted file path
or provider reference.

Environment variables remain visible through container inspection and process
metadata. Use them only when the deployment's threat model accepts that
exposure. The current application validates secret-free configuration; an
external secret-manager integration is outside the MVP.

## Verification

Run:

```sh
./tests/container/test-policy.sh
```

Static checks always run and reject unpinned bases, a root runtime user,
secret-like build arguments or environment variables, broad context copies,
missing ignore rules, and shell-form entrypoints or health checks. When Docker
or Podman is available, the same command builds the image, inspects its user
and health check, and executes it with a read-only root, all Linux capabilities
dropped, `no-new-privileges`, and only `/var/lib/ulpf` writable. Runtime checks
report a clear skip when neither engine is available; static checks never skip.
