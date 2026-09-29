#!/bin/sh
set -u

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root" || exit 1

artifacts_only=false
report=output/evaluation/verification.txt

while test "$#" -gt 0; do
  case "$1" in
    --artifacts-only) artifacts_only=true ;;
    --report)
      shift
      test "$#" -gt 0 || { printf '%s\n' '--report requires a path' >&2; exit 2; }
      report=$1
      ;;
    -h|--help)
      printf '%s\n' 'usage: ./scripts/verify-evaluation.sh [--artifacts-only] [--report FILE]'
      exit 0
      ;;
    *) printf 'unknown option: %s\n' "$1" >&2; exit 2 ;;
  esac
  shift
done

mkdir -p "$(dirname "$report")"
: >"$report"

passes=0
failures=0
pending=0
limits=0

log() {
  printf '%s\n' "$*" | tee -a "$report"
}

pass() {
  passes=$((passes + 1))
  log "PASS  $*"
}

fail() {
  failures=$((failures + 1))
  log "FAIL  $*"
}

pending() {
  pending=$((pending + 1))
  log "PENDING  $*"
}

limit() {
  limits=$((limits + 1))
  log "LIMIT  $*"
}

require_files() {
  label=$1
  shift
  missing=
  for path in "$@"; do
    test -s "$path" || missing="$missing $path"
  done
  if test -z "$missing"; then
    pass "$label"
  else
    fail "$label; missing:$missing"
  fi
}

run_check() {
  label=$1
  shift
  temporary=$(mktemp)
  if "$@" >"$temporary" 2>&1; then
    sed 's/[[:space:]]*$//' "$temporary" >>"$report"
    pass "$label"
  else
    sed 's/[[:space:]]*$//' "$temporary" >>"$report"
    fail "$label"
  fi
  rm -f "$temporary"
}

log "ULPF evaluation verification"
log "generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "git_commit=$(git rev-parse HEAD 2>/dev/null || printf unknown)"
if test -n "$(git status --porcelain -- . ':(exclude)output/evaluation/verification.txt' 2>/dev/null)"; then
  log 'git_dirty=true'
else
  log 'git_dirty=false'
fi

require_files 'T01 ADRs and acceptance contract' docs/adr/0001-durable-acceptance-boundary.md docs/adr/0002-modular-monolith.md docs/adr/0003-canonical-ocsf-envelope.md
require_files 'T02 vendored OCSF provenance and checksums' schemas/vendor/ocsf/1.9.0/SOURCE.json schemas/vendor/ocsf/1.9.0/SHA256SUMS schemas/vendor/ocsf/1.9.0/TREE_SHA256 schemas/vendor/ocsf/1.9.0/LICENSE
require_files 'T03 envelope/config/bundle schemas' schemas/ulpf-envelope-1.0.0.json schemas/ulpf-config-1.0.0.json schemas/parser-bundle-manifest-1.0.0.json
require_files 'T04-T06 CLI, config, and state model' cmd/ulpf/main.go internal/control/config.go internal/model/state.go
require_files 'T07-T10 durability and observability' internal/evidence/filesystem.go internal/inbox/sqlite.go internal/ingress/admission.go internal/observe/metrics.go internal/observe/audit.go
require_files 'T11-T18 interpretation stack' internal/registry/loader.go internal/detect/detector.go internal/interpret/syslog/parser.go internal/interpret/json/parser.go internal/interpret/xml/parser.go internal/interpret/csv/parser.go internal/interpret/kv/parser.go internal/interpret/cef/parser.go internal/interpret/re2parser/parser.go internal/interpret/mapping/engine.go internal/envelope/build.go
require_files 'T19-T27 worker, outputs, query, transports, auth, and lifecycle' internal/worker/worker.go internal/deliver/clickhouse/connector.go internal/deliver/ndjson/connector.go internal/deliver/coordinator.go internal/query/http.go internal/ingress/syslog_udp.go internal/ingress/syslog_tcp.go internal/auth/authorizer.go internal/registry/lifecycle.go
require_files 'T28-T31 corpus, security, faults, and generator' tests/corpus/manifest.json internal/securitytest/parser_security_test.go tests/e2e/fault_injection_test.go benchmarks/scenarios/default.json cmd/ulpf-benchgen/main.go
require_files 'T32-T34 deployment and offline tooling' compose.yaml Dockerfile scripts/test-compose.sh scripts/verify-container.sh scripts/build-offline-bundle.sh scripts/verify-offline-bundle.sh tests/offline/test-offline-bundle.sh
require_files 'T35 measured performance artifacts' benchmarks/profiles/local-e2e.json benchmarks/results/local-20260929-darwin-arm64/report.json benchmarks/results/local-20260929-darwin-arm64/report.md benchmarks/results/local-20260929-darwin-arm64/cpu.pprof benchmarks/results/local-20260929-darwin-arm64/heap.pprof

if grep -Eiq '^## (Quick start|Getting started)' README.md && test -s docs/OPERATIONS.md && test -s docs/PARSER_AUTHORING.md; then
  pass 'T36 fresh-user, operator, and parser-authoring documentation'
else
  pending 'T36 requires README quick start, docs/OPERATIONS.md, and docs/PARSER_AUTHORING.md'
fi

require_files 'T37 architecture source and PDF' docs/ARCHITECTURE_TWO_PAGER.md scripts/build-architecture-pdf.py output/pdf/ULPF-Architecture-Two-Pager.pdf

demo_reports=$(find tests/demo/evidence -type f -name 'rehearsal-*.json' -print 2>/dev/null | LC_ALL=C sort)
if test -s docs/DEMO_SCRIPT.md && test -x scripts/run-demo.sh && test -n "$demo_reports"; then
  if python3 - $demo_reports <<'PY'
import json, sys
paths = sys.argv[1:]
if len(paths) < 2:
    raise SystemExit("fewer than two demo runs")
for path in paths:
    run = json.load(open(path, encoding="utf-8"))
    duration_ms = run.get("duration_ms")
    invariants = run.get("invariants", {})
    if run.get("result") != "pass" or not isinstance(duration_ms, (int, float)) or duration_ms > 120000:
        raise SystemExit("demo run did not pass within 120 seconds")
    if not invariants or not all(value is True for value in invariants.values()):
        raise SystemExit("demo invariant failed")
PY
  then
    pass 'T38 two successful demo rehearsals within 120 seconds'
  else
    fail 'T38 rehearsal evidence is invalid'
  fi
else
  fail 'T38 requires docs/DEMO_SCRIPT.md, executable scripts/run-demo.sh, and two tests/demo/evidence/rehearsal-*.json files'
fi

require_files 'T39 editable five-slide presentation' docs/TECHNICAL_PRESENTATION.md output/presentation/ULPF-Technical-Presentation.pptx
require_files 'T40 trace document, expected outcomes, and verifier' docs/EVALUATION_TRACE.md docs/EXPECTED_OUTCOMES.md scripts/verify-evaluation.sh
require_files 'T41 dynamic dashboard frontend, API, guide, and design reference' docs/DASHBOARD.md docs/assets/dashboard-concept.png internal/dashboard/handler.go internal/dashboard/assets/index.html internal/dashboard/assets/styles.css internal/dashboard/assets/app.js internal/dashboardapi/summary.go internal/dashboardapi/http.go
require_files 'T42-T53 completed runtime slices and handbook' docs/PROJECT_HANDBOOK.md internal/bundlecompile/compiler.go internal/reprocess/executor.go internal/deliver/parquet/connector.go internal/analytics/export.go internal/dashboardapi/federated.go scripts/test-offline-install.sh .github/workflows/release.yml
require_files 'Bundle trust and operational recovery completion' internal/registry/scaffold.go internal/backup/backup.go internal/capacity/disk.go internal/maintenance/maintenance.go internal/server/metrics.go deployments/monitoring/ulpf-alerts.yaml migrations/sqlite/0008_maintenance.sql
require_files 'Native arm64 offline clean-install evidence' output/evaluation/offline-clean-install-arm64.txt output/evaluation/offline-clean-install-arm64.json

if command -v pdfinfo >/dev/null 2>&1; then
  pages=$(pdfinfo output/pdf/ULPF-Architecture-Two-Pager.pdf 2>/dev/null | awk '/^Pages:/ {print $2}')
  if test "$pages" = 2; then pass 'T37 architecture PDF has exactly two pages'; else fail "T37 architecture PDF page count is ${pages:-unknown}"; fi
else
  limit 'T37 PDF page count not checked because pdfinfo is unavailable'
fi

if command -v python3 >/dev/null 2>&1; then
  if python3 - output/presentation/ULPF-Technical-Presentation.pptx <<'PY'
import re, sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as archive:
    slides = [name for name in archive.namelist() if re.fullmatch(r"ppt/slides/slide[0-9]+\.xml", name)]
if len(slides) != 5:
    raise SystemExit(f"expected 5 slides, found {len(slides)}")
PY
  then pass 'T39 presentation contains exactly five slides'; else fail 'T39 presentation slide count'; fi
else
  fail 'Python 3 is required to count presentation slides'
fi

if command -v python3 >/dev/null 2>&1; then
  if python3 - benchmarks/results/local-20260929-darwin-arm64/report.json <<'PY'
import hashlib, json, pathlib, sys
path = pathlib.Path(sys.argv[1])
report = json.loads(path.read_text(encoding="utf-8"))
m = report["measurements"]
assert m["submitted"] == m["accepted"] + m["rejected"]
assert m["accepted"] == m["revisions"] == m["raw_verified"]
assert m["hash_mismatches"] == m["linkage_failures"] == 0
assert "not a production" in report["claim"]
for artifact in report.get("artifacts", []):
    actual = hashlib.sha256((path.parent / artifact["path"]).read_bytes()).hexdigest()
    assert actual == artifact["sha256"]
PY
  then pass 'T35 report accounting, claim boundary, and profile digests'; else fail 'T35 report integrity'; fi
fi

if test "$artifacts_only" = false; then
  run_check 'Go unit/integration suite' go test ./...
  run_check 'Focused race suite for durable, security, and dashboard boundaries' go test -race ./internal/auth ./internal/evidence ./internal/inbox ./internal/ingress ./internal/worker ./internal/deliver ./internal/query ./internal/dashboard ./internal/dashboardapi ./internal/server ./tests/e2e
  run_check 'Go vet' go vet ./...
  run_check 'OCSF vendor checksums' ./scripts/verify-ocsf-vendor.sh
  run_check 'JSON Schema positive/negative examples' ./scripts/validate-schemas.sh
  run_check 'Synthetic corpus hashes, coverage, provenance, and ground truth' ./scripts/verify-corpus.sh
  run_check 'Bounded security regression smoke' make security-smoke
  run_check 'Container static success and rejection policy' ./tests/container/test-policy.sh
  run_check 'Offline archive determinism and hostile archive rejection' ./tests/offline/test-offline-bundle.sh
else
  log 'INFO  executable tests skipped by --artifacts-only'
fi

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  if test "$artifacts_only" = false; then
    run_check 'Docker engine-backed Compose smoke' ./scripts/test-compose.sh
  else
    limit 'Docker engine is available, but Compose smoke was skipped by --artifacts-only'
  fi
elif command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
  if test "$artifacts_only" = false; then
    run_check 'Podman engine-backed Compose smoke' ./scripts/test-compose.sh
  else
    limit 'Podman engine is available, but Compose smoke was skipped by --artifacts-only'
  fi
else
  limit 'No working Docker/Podman daemon: container runtime and Compose health are unverified'
fi

limit 'The arm64 clean-install proof is complete; native amd64 clean-install evidence requires the release runner'
limit 'No production-scale, sustained, replicated, multi-node disaster-recovery, or organization-specific retention result is claimed'

log "SUMMARY passes=$passes failures=$failures pending=$pending limits=$limits"
log "report=$report"

if test "$failures" -ne 0; then
  exit 1
fi
if test "$pending" -ne 0; then
  exit 1
fi
exit 0
