#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
python_bin=${PYTHON_BIN:-python3}

if ! command -v "$python_bin" >/dev/null 2>&1; then
  printf '%s\n' "Python 3 is required to verify the corpus" >&2
  exit 2
fi

exec "$python_bin" - "$repo_root" <<'PY'
import csv
import hashlib
import io
import json
import os
import re
import sys
import xml.etree.ElementTree as element_tree
from collections import defaultdict
from pathlib import Path, PurePosixPath


repo_root = Path(sys.argv[1]).resolve()
corpus_root = repo_root / "tests" / "corpus"
manifest_path = corpus_root / "manifest.json"
errors = []


def check(condition, message):
    if not condition:
        errors.append(message)


def reject_duplicate_manifest_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate manifest key: {key}")
        result[key] = value
    return result


try:
    manifest = json.loads(
        manifest_path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_manifest_keys,
    )
except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
    print(f"corpus manifest is unreadable: {error}", file=sys.stderr)
    sys.exit(1)

check(manifest.get("manifest_version") == "ulpf-synthetic-corpus/1.0.0", "unexpected manifest_version")
check(manifest.get("synthetic") is True, "corpus must be marked synthetic")
check(manifest.get("vendor_support_claim") == "none", "corpus must make no vendor support claim")

license_metadata = manifest.get("license", {})
check(license_metadata.get("spdx_id") == "Apache-2.0", "corpus license must be Apache-2.0")
for key in ("license_file", "notice_file"):
    relative = license_metadata.get(key)
    check(isinstance(relative, str) and relative, f"license.{key} is required")
    if isinstance(relative, str) and relative:
        candidate = (corpus_root / relative).resolve()
        try:
            inside_repo = os.path.commonpath((str(repo_root), str(candidate))) == str(repo_root)
        except ValueError:
            inside_repo = False
        check(inside_repo, f"license.{key} escapes the repository")
        check(candidate.is_file(), f"license.{key} does not exist: {relative}")

review = manifest.get("review", {})
check(review.get("reviewed") is True, "corpus review must be recorded")
check(isinstance(review.get("method"), str) and review.get("method"), "review method is required")

provenance_records = manifest.get("provenance", [])
check(isinstance(provenance_records, list) and provenance_records, "at least one provenance record is required")
provenance_by_id = {}
for record in provenance_records if isinstance(provenance_records, list) else []:
    identifier = record.get("id") if isinstance(record, dict) else None
    check(isinstance(identifier, str) and identifier, "each provenance record needs an id")
    if isinstance(identifier, str):
        check(identifier not in provenance_by_id, f"duplicate provenance id: {identifier}")
        provenance_by_id[identifier] = record
    if isinstance(record, dict):
        check(record.get("kind") == "synthetic", f"provenance {identifier} is not synthetic")
        check(record.get("contains_real_events") is False, f"provenance {identifier} permits real events")
        check(record.get("contains_personal_data") is False, f"provenance {identifier} permits personal data")
        check(record.get("contains_secrets") is False, f"provenance {identifier} permits secrets")

required_scenarios = manifest.get("required_scenarios", [])
check(isinstance(required_scenarios, list), "required_scenarios must be an array")
check(len(required_scenarios) == len(set(required_scenarios)), "required_scenarios contains duplicates")

fixtures = manifest.get("fixtures", [])
check(isinstance(fixtures, list) and fixtures, "fixtures must be a non-empty array")
fixture_ids = set()
fixture_paths = set()
occurrence_ids = set()
covered_scenarios = set()
duplicate_groups = defaultdict(list)
allowed_statuses = {"PARSED", "PARTIALLY_PARSED", "UNPARSED", "INVALID"}
issue_code_pattern = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
sha256_pattern = re.compile(r"^[0-9a-f]{64}$")
semver_pattern = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
fixture_bytes = {}

for fixture in fixtures if isinstance(fixtures, list) else []:
    if not isinstance(fixture, dict):
        errors.append("fixture entry is not an object")
        continue

    fixture_id = fixture.get("id")
    path_text = fixture.get("path")
    occurrence_id = fixture.get("occurrence_id")
    scenario = fixture.get("scenario")

    check(isinstance(fixture_id, str) and fixture_id, "fixture id is required")
    if isinstance(fixture_id, str):
        check(fixture_id not in fixture_ids, f"duplicate fixture id: {fixture_id}")
        fixture_ids.add(fixture_id)

    check(isinstance(occurrence_id, str) and occurrence_id, f"{fixture_id}: occurrence_id is required")
    if isinstance(occurrence_id, str):
        check(occurrence_id not in occurrence_ids, f"duplicate occurrence_id: {occurrence_id}")
        occurrence_ids.add(occurrence_id)

    check(isinstance(scenario, str) and scenario, f"{fixture_id}: scenario is required")
    if isinstance(scenario, str):
        covered_scenarios.add(scenario)

    check(fixture.get("synthetic") is True, f"{fixture_id}: fixture must be marked synthetic")
    provenance_id = fixture.get("provenance_id")
    check(provenance_id in provenance_by_id, f"{fixture_id}: unknown provenance_id {provenance_id}")

    safe_path = False
    if isinstance(path_text, str):
        pure_path = PurePosixPath(path_text)
        safe_path = not pure_path.is_absolute() and ".." not in pure_path.parts and pure_path.parts[:1] == ("raw",)
    check(safe_path, f"{fixture_id}: unsafe or non-raw fixture path {path_text}")
    if not safe_path:
        continue
    check(path_text not in fixture_paths, f"fixture path referenced more than once: {path_text}")
    fixture_paths.add(path_text)

    raw_path = corpus_root / path_text
    check(raw_path.is_file() and not raw_path.is_symlink(), f"{fixture_id}: fixture is missing or is a symlink")
    if not raw_path.is_file() or raw_path.is_symlink():
        continue

    payload = raw_path.read_bytes()
    fixture_bytes[fixture_id] = payload
    actual_hash = hashlib.sha256(payload).hexdigest()
    recorded_hash = fixture.get("raw_sha256")
    recorded_size = fixture.get("raw_size_bytes")
    check(isinstance(recorded_hash, str) and sha256_pattern.fullmatch(recorded_hash) is not None, f"{fixture_id}: invalid raw_sha256")
    check(actual_hash == recorded_hash, f"{fixture_id}: raw SHA-256 mismatch")
    check(recorded_size == len(payload), f"{fixture_id}: raw byte count mismatch")

    encoding = fixture.get("content_encoding")
    if encoding == "utf-8":
        try:
            payload.decode("utf-8")
        except UnicodeDecodeError:
            errors.append(f"{fixture_id}: declared UTF-8 payload is invalid")
    elif encoding == "binary":
        try:
            payload.decode("utf-8")
        except UnicodeDecodeError:
            pass
        else:
            errors.append(f"{fixture_id}: binary negative fixture unexpectedly decodes as UTF-8")
    else:
        errors.append(f"{fixture_id}: unsupported content_encoding {encoding}")

    expected = fixture.get("expected")
    check(isinstance(expected, dict), f"{fixture_id}: expected object is required")
    if not isinstance(expected, dict):
        continue
    status = expected.get("status")
    parser = expected.get("parser")
    canonical_fields = expected.get("canonical_fields")
    issue_codes = expected.get("issue_codes")
    check(status in allowed_statuses, f"{fixture_id}: invalid expected status {status}")
    if parser is None:
        check(status == "UNPARSED", f"{fixture_id}: only UNPARSED may omit the parser")
    else:
        check(isinstance(parser, dict), f"{fixture_id}: parser must be an object or null")
        if isinstance(parser, dict):
            check(isinstance(parser.get("id"), str) and parser.get("id"), f"{fixture_id}: parser id is required")
            check(isinstance(parser.get("version"), str) and semver_pattern.fullmatch(parser.get("version", "")) is not None, f"{fixture_id}: parser version is not semantic")
    check(isinstance(canonical_fields, dict), f"{fixture_id}: canonical_fields must be an object")
    if isinstance(canonical_fields, dict):
        for field_name in canonical_fields:
            check(field_name.startswith("event."), f"{fixture_id}: non-event canonical field {field_name}")
        if status in {"UNPARSED", "INVALID"}:
            check(not canonical_fields, f"{fixture_id}: {status} must not assert trusted canonical fields")
        if canonical_fields.get("event.action") == "deny":
            check(canonical_fields.get("event.status") != "failure", f"{fixture_id}: deny must not fabricate failure status")
    check(isinstance(issue_codes, list), f"{fixture_id}: issue_codes must be an array")
    if isinstance(issue_codes, list):
        check(len(issue_codes) == len(set(issue_codes)), f"{fixture_id}: duplicate issue code")
        for issue_code in issue_codes:
            check(isinstance(issue_code, str) and issue_code_pattern.fullmatch(issue_code) is not None, f"{fixture_id}: invalid issue code {issue_code}")

    duplicate_group = fixture.get("duplicate_group")
    if duplicate_group is not None:
        check(isinstance(duplicate_group, str) and duplicate_group, f"{fixture_id}: invalid duplicate_group")
        duplicate_groups[duplicate_group].append(fixture)

actual_raw_paths = {
    path.relative_to(corpus_root).as_posix()
    for path in (corpus_root / "raw").rglob("*")
    if path.is_file()
}
check(actual_raw_paths == fixture_paths, f"manifest/raw coverage mismatch: missing={sorted(actual_raw_paths - fixture_paths)} extra={sorted(fixture_paths - actual_raw_paths)}")
check(set(required_scenarios) == covered_scenarios, f"scenario coverage mismatch: missing={sorted(set(required_scenarios) - covered_scenarios)} extra={sorted(covered_scenarios - set(required_scenarios))}")

for group_name, group in sorted(duplicate_groups.items()):
    check(len(group) >= 2, f"duplicate group {group_name} needs at least two occurrences")
    hashes = {fixture.get("raw_sha256") for fixture in group}
    paths = {fixture.get("path") for fixture in group}
    occurrences = {fixture.get("occurrence_id") for fixture in group}
    expected_results = [fixture.get("expected") for fixture in group]
    check(len(hashes) == 1, f"duplicate group {group_name} does not have identical bytes")
    check(len(paths) == len(group), f"duplicate group {group_name} reuses a fixture path")
    check(len(occurrences) == len(group), f"duplicate group {group_name} reuses an occurrence identity")
    check(all(fixture.get("preserve_as_distinct_occurrence") is True for fixture in group), f"duplicate group {group_name} is not marked for distinct preservation")
    check(all(result == expected_results[0] for result in expected_results[1:]), f"duplicate group {group_name} has inconsistent expected interpretations")
    payloads = {fixture_bytes.get(fixture.get("id")) for fixture in group}
    check(len(payloads) == 1, f"duplicate group {group_name} payload bytes differ")

check(bool(duplicate_groups), "at least one byte-identical duplicate group is required")

json_valid_scenarios = {"json_firewall", "json_ids", "byte_identical_repeated_occurrence"}
for fixture in fixtures:
    if not isinstance(fixture, dict) or fixture.get("scenario") not in json_valid_scenarios:
        continue
    try:
        json.loads((corpus_root / fixture["path"]).read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_manifest_keys)
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        errors.append(f"{fixture.get('id')}: expected valid unique-key JSON: {error}")

malformed_path = corpus_root / next(fixture["path"] for fixture in fixtures if fixture.get("scenario") == "malformed_json")
try:
    json.loads(malformed_path.read_text(encoding="utf-8"))
except json.JSONDecodeError:
    pass
else:
    errors.append("malformed_json fixture unexpectedly parsed")

duplicate_path = corpus_root / next(fixture["path"] for fixture in fixtures if fixture.get("scenario") == "duplicate_json_keys")
duplicate_keys = []


def track_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            duplicate_keys.append(key)
        result[key] = value
    return result


try:
    json.loads(duplicate_path.read_text(encoding="utf-8"), object_pairs_hook=track_duplicate_keys)
except json.JSONDecodeError as error:
    errors.append(f"duplicate_json_keys fixture must otherwise be valid JSON: {error}")
check(duplicate_keys == ["action"], f"duplicate_json_keys fixture must duplicate only action, found {duplicate_keys}")

csv_path = corpus_root / next(fixture["path"] for fixture in fixtures if fixture.get("scenario") == "csv")
csv_rows = list(csv.reader(io.StringIO(csv_path.read_text(encoding="utf-8"))))
check(len(csv_rows) == 2 and len(csv_rows[0]) == len(csv_rows[1]), "CSV fixture is not a two-row rectangular record")

xml_path = corpus_root / next(fixture["path"] for fixture in fixtures if fixture.get("scenario") == "xml")
try:
    element_tree.fromstring(xml_path.read_bytes())
except element_tree.ParseError as error:
    errors.append(f"XML fixture is malformed: {error}")

prefixes = {
    "generic_syslog": b"<134>1 ",
    "cef": b"CEF:0|",
    "leef": b"LEEF:2.0|",
    "router_text": b"IFACE_DOWN|",
    "unknown_proprietary_text": b"VX9~",
}
for scenario, prefix in prefixes.items():
    fixture = next(item for item in fixtures if item.get("scenario") == scenario)
    check((corpus_root / fixture["path"]).read_bytes().startswith(prefix), f"{scenario} fixture has the wrong signature")

if errors:
    for error in sorted(errors):
        print(f"ERROR: {error}", file=sys.stderr)
    sys.exit(1)

print(
    "verified "
    f"{len(fixtures)} fixture occurrences, "
    f"{len(actual_raw_paths)} raw files, "
    f"{len(covered_scenarios)} required scenarios, and "
    f"{len(duplicate_groups)} byte-identical occurrence group"
)
PY
