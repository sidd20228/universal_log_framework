#!/bin/sh
set -eu

duration=${FUZZTIME:-10s}
case "$duration" in
  *[!0-9smh.]*)
    printf '%s\n' "FUZZTIME must be a Go duration using digits, '.', s, m, or h" >&2
    exit 2
    ;;
esac

run_target() {
  package=$1
  target=$2
  printf '%s\n' "fuzzing $package $target for $duration"
  go test "$package" -run '^$' -fuzz "^${target}$" -fuzztime "$duration"
}

run_target ./internal/securitytest FuzzSyslogHeader
run_target ./internal/securitytest FuzzCEFLEEFEscaping
run_target ./internal/securitytest FuzzJSONWrapper
run_target ./internal/securitytest FuzzXMLWrapper
run_target ./internal/securitytest FuzzKVTokenizer
run_target ./internal/securitytest FuzzDeclarativeRE2
run_target ./internal/securitytest FuzzRE2Config
run_target ./internal/ingress FuzzTCPFraming
run_target ./internal/registry FuzzBundleManifest
run_target ./internal/registry FuzzBundleManifestPath
run_target ./internal/auth FuzzBearerTokenParsing
run_target ./internal/auth FuzzAuthorizationScopeIsolation
