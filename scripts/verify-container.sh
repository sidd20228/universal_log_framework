#!/bin/sh
set -eu

dockerfile=${DOCKERFILE:-Dockerfile}
dockerignore=${DOCKERIGNORE:-.dockerignore}

fail() {
  printf '%s\n' "container policy: FAIL: $*" >&2
  exit 1
}

require_file() {
  test -f "$1" || fail "required file $1 is missing"
}

require_file "$dockerfile"
require_file "$dockerignore"

from_count=$(awk 'toupper($1) == "FROM" { count++ } END { print count + 0 }' "$dockerfile")
test "$from_count" -eq 2 || fail "Dockerfile must contain exactly two build stages"

builder_go_version=$(awk '$1 == "toolchain" { sub(/^go/, "", $2); print $2; exit }' go.mod)
if test -z "$builder_go_version"; then
  builder_go_version=$(awk '$1 == "go" { print $2; exit }' go.mod)
fi
grep -Fq "FROM docker.io/library/golang:${builder_go_version}-" "$dockerfile" || fail "builder Go version must match the go.mod toolchain"

awk '
  toupper($1) == "FROM" {
    if ($2 !~ /@sha256:[0-9a-f][0-9a-f]*$/ || length($2) != length(substr($2, 1, index($2, "@sha256:") + 7)) + 64) {
      exit 1
    }
  }
' "$dockerfile" || fail "every base image must be pinned to a 64-character sha256 digest"

final_from=$(awk 'toupper($1) == "FROM" { image=$2 } END { print image }' "$dockerfile")
case "$final_from" in
  gcr.io/distroless/static-debian12:nonroot@sha256:*) ;;
  *) fail "runtime stage must use the pinned distroless nonroot static image" ;;
esac

final_user=$(awk 'toupper($1) == "USER" { user=$2 } END { print user }' "$dockerfile")
test "$final_user" = "65532:65532" || fail "runtime USER must be the explicit non-root uid:gid 65532:65532"

grep -Eq 'CGO_ENABLED=0' "$dockerfile" || fail "build must disable cgo"
grep -Eq 'go build .*-[^ ]*trimpath|go build .* -trimpath' "$dockerfile" || fail "build must use -trimpath"
grep -Eq -- '-buildvcs=false' "$dockerfile" || fail "build must disable implicit VCS stamping"
grep -Eq '^HEALTHCHECK .*\\$' "$dockerfile" || fail "an exec-form healthcheck is required"
grep -Eq 'CMD \["/usr/local/bin/ulpf", "version"\]' "$dockerfile" || fail "healthcheck must invoke the binary without a shell"
grep -Eq '^ENTRYPOINT \["/usr/local/bin/ulpf"\]$' "$dockerfile" || fail "entrypoint must use exec form"
grep -Eq '^WORKDIR /var/lib/ulpf$' "$dockerfile" || fail "runtime work directory must be under /var/lib/ulpf"
grep -Eq 'HOME=/var/lib/ulpf' "$dockerfile" || fail "runtime HOME must use the writable state path"
grep -Eq 'TMPDIR=/var/lib/ulpf/tmp' "$dockerfile" || fail "runtime TMPDIR must use the writable state path"

if grep -Eiq '^[[:space:]]*ADD[[:space:]]' "$dockerfile"; then
  fail "ADD is forbidden; use explicit COPY instructions"
fi
if grep -Eq '^[[:space:]]*COPY([[:space:]]+--[^[:space:]]+)*[[:space:]]+\.[[:space:]]+\.' "$dockerfile"; then
  fail "COPY . . is forbidden; copy only required build inputs"
fi
if grep -Eiq '^[[:space:]]*(ARG|ENV)[[:space:]].*(SECRET|PASSWORD|PASSWD|TOKEN|PRIVATE[_-]?KEY|API[_-]?KEY)' "$dockerfile"; then
  fail "secret-like ARG or ENV instructions are forbidden"
fi

for pattern in '.git' 'bin' '.env' '.env.*' '*.key' '*.pem' 'secrets' '*.sqlite' 'raw'; do
  grep -Fqx "$pattern" "$dockerignore" || fail ".dockerignore must contain $pattern"
done

printf '%s\n' 'container policy: static checks passed'

engine=
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  engine=docker
elif command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
  engine=podman
fi

if test -z "$engine"; then
  printf '%s\n' 'container policy: SKIP runtime checks (no available Docker or Podman engine)'
  exit 0
fi

image="ulpf-container-policy:local-$$"
container="ulpf-container-policy-$$"
cleanup() {
  "$engine" rm -f "$container" >/dev/null 2>&1 || true
  "$engine" image rm -f "$image" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

if test "$engine" = docker; then
  "$engine" build --pull=false --tag "$image" --file "$dockerfile" .
else
  "$engine" build --pull=missing --tag "$image" --file "$dockerfile" .
fi

image_user=$("$engine" image inspect --format '{{.Config.User}}' "$image")
test "$image_user" = '65532:65532' || fail "built image user is $image_user"

healthcheck=$("$engine" image inspect --format '{{json .Config.Healthcheck.Test}}' "$image")
case "$healthcheck" in
  *'/usr/local/bin/ulpf'*'version'*) ;;
  *) fail "built image healthcheck is missing or unexpected: $healthcheck" ;;
esac

if "$engine" image inspect "$image" | grep -Eiq '(^|[" =])(PASSWORD|PASSWD|TOKEN|SECRET|PRIVATE_KEY|API_KEY)='; then
  fail "built image configuration contains a secret-like value"
fi

"$engine" create \
  --name "$container" \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --tmpfs /var/lib/ulpf:rw,noexec,nosuid,nodev,size=16m \
  "$image" version --json >/dev/null

readonly_root=$("$engine" inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$container")
test "$readonly_root" = true || fail "container root filesystem is not read-only"

capabilities=$("$engine" inspect --format '{{json .HostConfig.CapDrop}}' "$container")
case "$capabilities" in
  *ALL*) ;;
  *) fail "container does not drop all capabilities: $capabilities" ;;
esac

security_options=$("$engine" inspect --format '{{json .HostConfig.SecurityOpt}}' "$container")
case "$security_options" in
  *no-new-privileges*) ;;
  *) fail "container does not set no-new-privileges: $security_options" ;;
esac

output=$("$engine" start --attach "$container")
printf '%s' "$output" | grep -Eq '"version"' || fail "hardened container did not execute the binary"

printf '%s\n' "container policy: runtime checks passed with $engine"
