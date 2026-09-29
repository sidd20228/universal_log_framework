#!/usr/bin/env python3
"""Run the bounded, Docker-free ULPF demonstration and write evidence."""

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


TENANT = "demo"
EXPECTED_SCHEMA = "ulpf-envelope/1.0.0"
EXPECTED_PARSER = "generic-json"
EXPECTED_STATUS = "PARTIALLY_PARSED"


class DemoError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise DemoError(message)


def sha256_bytes(body):
    return hashlib.sha256(body).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def elapsed_ms(started):
    return round((time.monotonic() - started) * 1000, 3)


def http_request(url, method="GET", body=None, token=None):
    headers = {}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    if body is not None:
        headers["Content-Type"] = "application/octet-stream"
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            return response.status, dict(response.headers.items()), response.read()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers.items()), error.read()
    except urllib.error.URLError as error:
        raise DemoError(f"HTTP request failed: {error.reason}") from error


def decode_json(body, label):
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DemoError(f"{label} was not valid UTF-8 JSON: {error}") from error
    require(isinstance(value, dict), f"{label} must be a JSON object")
    return value


class Service:
    def __init__(self, binary, base_url, port, state_dir, token_file, log_path):
        self.binary = binary
        self.base_url = base_url
        self.port = port
        self.state_dir = state_dir
        self.token_file = token_file
        self.log_path = log_path
        self.process = None
        self.log = None

    def start(self):
        require(self.process is None, "service is already running")
        self.log = self.log_path.open("ab")
        self.process = subprocess.Popen(
            [
                str(self.binary),
                "serve",
                "--listen", f"127.0.0.1:{self.port}",
                "--sqlite", str(self.state_dir / "state" / "ulpf.sqlite"),
                "--raw-root", str(self.state_dir / "raw"),
                "--tenant", TENANT,
                "--token-file", str(self.token_file),
                "--workers", "1",
            ],
            stdin=subprocess.DEVNULL,
            stdout=self.log,
            stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise DemoError(f"service exited during startup with status {self.process.returncode}")
            check = subprocess.run(
                [str(self.binary), "healthcheck", "--url", self.base_url + "/health/ready", "--timeout", "500ms"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if check.returncode == 0:
                return
            time.sleep(0.05)
        raise DemoError("service did not become ready within 8 seconds")

    def stop(self):
        if self.process is None:
            return
        process = self.process
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=12)
            except subprocess.TimeoutExpired as error:
                process.kill()
                process.wait(timeout=2)
                raise DemoError("service did not stop after SIGTERM") from error
        require(process.returncode == 0, f"service exited with status {process.returncode}")
        self.process = None
        if self.log is not None:
            self.log.close()
            self.log = None

    def force_stop(self):
        if self.process is not None and self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=2)
        self.process = None
        if self.log is not None:
            self.log.close()
            self.log = None


def find_revision(base_url, token, receipt_id):
    deadline = time.monotonic() + 8
    last_body = b""
    while time.monotonic() < deadline:
        status, _, last_body = http_request(
            base_url + "/api/v1/events?tenant_id=" + TENANT + "&limit=20", token=token
        )
        if status == 200:
            page = decode_json(last_body, "event query")
            items = page.get("items")
            require(isinstance(items, list), "event query items must be an array")
            for item in items:
                if isinstance(item, dict) and item.get("receipt_id") == receipt_id:
                    revision_id = item.get("revision_id")
                    require(isinstance(revision_id, str) and revision_id, "query result omitted revision_id")
                    return revision_id, item, len(items)
        time.sleep(0.05)
    raise DemoError(f"receipt did not become queryable; last response was {last_body[:512]!r}")


def validate_trace(receipt, envelope, raw_body, raw_headers, payload, receipt_id, revision_id, expected_hash):
    receipt_view = receipt.get("receipt")
    require(isinstance(receipt_view, dict), "receipt response omitted receipt metadata")
    raw_meta = receipt_view.get("raw")
    require(isinstance(raw_meta, dict), "receipt response omitted raw metadata")
    require(receipt_view.get("id") == receipt_id, "receipt response changed receipt id")
    require(receipt_view.get("tenant_id") == TENANT, "receipt response changed tenant")
    require(receipt_view.get("state") == "REVISION_COMMITTED", "receipt is not revision committed")
    require(raw_meta.get("sha256") == expected_hash, "receipt raw hash differs from submitted bytes")
    require(raw_meta.get("size_bytes") == len(payload), "receipt raw length differs from submitted bytes")
    require(raw_meta.get("available") is True, "receipt reports raw evidence unavailable")
    revisions = receipt.get("revisions")
    require(isinstance(revisions, list) and len(revisions) == 1, "receipt must have one immutable demo revision")
    require(revisions[0].get("revision_id") == revision_id, "receipt revision link differs from query result")

    require(envelope.get("schema_version") == EXPECTED_SCHEMA, "unexpected envelope schema")
    require(envelope.get("receipt", {}).get("id") == receipt_id, "envelope receipt link differs")
    require(envelope.get("raw", {}).get("sha256") == expected_hash, "envelope raw hash differs")
    processing = envelope.get("processing", {})
    require(processing.get("revision_id") == revision_id, "envelope revision link differs")
    require(processing.get("status") == EXPECTED_STATUS, "demo fixture has an unexpected processing status")
    require(processing.get("parser", {}).get("id") == EXPECTED_PARSER, "unexpected parser selected")
    issues = processing.get("issues")
    require(
        isinstance(issues, list) and any(issue.get("code") == "MAPPING_NOT_CONFIGURED" for issue in issues if isinstance(issue, dict)),
        "envelope did not record the missing built-in mapping",
    )
    require(envelope.get("parsed", {}).get("fields", {}).get("action") == "allow", "parsed action was not preserved")
    require(raw_body == payload, "retrieved raw bytes differ from submitted bytes")
    require(sha256_bytes(raw_body) == expected_hash, "retrieved raw SHA-256 differs")
    normalized_headers = {key.lower(): value for key, value in raw_headers.items()}
    require(normalized_headers.get("x-content-sha256") == expected_hash, "raw response hash header differs")


def markdown_report(result):
    timings = result["timings_ms"]
    invariants = result["invariants"]
    rows = "\n".join(
        f"| `{name}` | {'PASS' if passed else 'FAIL'} |" for name, passed in invariants.items()
    )
    timing_rows = "\n".join(f"| `{name}` | {value:.3f} |" for name, value in timings.items())
    return f"""# Local demo rehearsal: {result['run_label']}

- Result: **{result['result'].upper()}**
- Started: `{result['started_at']}`
- Duration: `{result['duration_ms']:.3f} ms`
- Limit: `{result['limit_ms']} ms`
- Platform: `{result['environment']['platform']}` / `{result['environment']['machine']}`
- Binary SHA-256: `{result['binary']['sha256']}`
- Fixture: `{result['fixture']['path']}`
- Receipt: `{result['trace']['receipt_id']}`
- Revision: `{result['trace']['revision_id']}`
- Raw SHA-256: `{result['trace']['raw_sha256']}`

## Verified invariants

| Invariant | Result |
|---|---|
{rows}

## Timings

| Stage | Milliseconds |
|---|---:|
{timing_rows}

The first service process accepted and processed one synthetic JSON firewall
fixture. After a controlled `SIGTERM`, a new process opened the same SQLite and
raw-evidence paths. The original receipt, revision, envelope, and exact bytes
remained available. The unauthenticated request was rejected before admission.
"""


def parse_args():
    repo_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, help="path to an already-built ulpf binary")
    parser.add_argument("--fixture", default=str(repo_root / "tests/corpus/raw/json_firewall.json"))
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--run-label", default="local-demo")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--limit-seconds", type=int, default=120)
    args = parser.parse_args()
    if args.port < 1024 or args.port > 65535:
        parser.error("--port must be between 1024 and 65535")
    if args.limit_seconds < 1 or args.limit_seconds > 120:
        parser.error("--limit-seconds must be between 1 and 120")
    return args


def run_demo(args):
    overall_started = time.monotonic()
    started_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    binary = Path(os.path.abspath(os.path.expanduser(args.binary)))
    fixture = Path(os.path.abspath(os.path.expanduser(args.fixture)))
    output_dir = Path(os.path.abspath(os.path.expanduser(args.output_dir)))
    require(binary.is_file() and os.access(binary, os.X_OK), "--binary must be an executable file")
    require(fixture.is_file() and not fixture.is_symlink(), "--fixture must be a regular non-symlink file")
    require("/" not in args.run_label and args.run_label not in ("", ".", ".."), "run label is invalid")
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{args.run_label}.json"
    markdown_path = output_dir / f"{args.run_label}.md"
    require(not json_path.is_symlink() and not markdown_path.is_symlink(), "evidence output cannot be a symlink")

    payload = fixture.read_bytes()
    expected_hash = sha256_bytes(payload)
    version = decode_json(
        subprocess.check_output([str(binary), "version", "--json"], timeout=3), "binary version"
    )
    timings = {}
    base_url = f"http://127.0.0.1:{args.port}"
    token = secrets.token_urlsafe(32)

    with tempfile.TemporaryDirectory(prefix="ulpf-local-demo-") as temporary:
        work = Path(temporary)
        state_dir = work / "durable"
        state_dir.mkdir()
        token_file = work / "api-token"
        token_file.write_text(token + "\n", encoding="utf-8")
        token_file.chmod(0o600)
        service = Service(binary, base_url, args.port, state_dir, token_file, work / "service.log")
        try:
            stage = time.monotonic()
            service.start()
            status, _, health_body = http_request(base_url + "/health/ready")
            require(status == 200 and decode_json(health_body, "readiness").get("status") == "ready", "readiness failed")
            timings["initial_start_and_health"] = elapsed_ms(stage)

            stage = time.monotonic()
            denied_status, _, denied_body = http_request(base_url + "/api/v1/ingest", method="POST", body=payload)
            denied = decode_json(denied_body, "unauthenticated response")
            require(denied_status == 401 and denied.get("code") == "UNAUTHENTICATED", "unauthenticated admission was not rejected")
            require("receipt_id" not in denied, "rejected admission returned a receipt id")
            timings["unauthenticated_rejection"] = elapsed_ms(stage)

            stage = time.monotonic()
            admitted_status, _, admitted_body = http_request(
                base_url + "/api/v1/ingest", method="POST", body=payload, token=token
            )
            admitted = decode_json(admitted_body, "admission response")
            receipt_id = admitted.get("receipt_id")
            require(admitted_status == 202 and admitted.get("status") == "ACCEPTED", "authenticated admission failed")
            require(isinstance(receipt_id, str) and receipt_id, "admission omitted receipt id")
            timings["authenticated_admission"] = elapsed_ms(stage)

            stage = time.monotonic()
            revision_id, summary, query_count = find_revision(base_url, token, receipt_id)
            require(summary.get("raw_sha256") == expected_hash, "query summary raw hash differs")
            require(summary.get("status") == EXPECTED_STATUS, "query summary status is unexpected")
            receipt_status, _, receipt_body = http_request(base_url + "/api/v1/receipts/" + receipt_id, token=token)
            envelope_status, _, envelope_body = http_request(base_url + "/api/v1/events/" + revision_id, token=token)
            raw_status, raw_headers, raw_body = http_request(base_url + "/api/v1/receipts/" + receipt_id + "/raw", token=token)
            require(receipt_status == envelope_status == raw_status == 200, "trace retrieval returned a non-200 response")
            receipt = decode_json(receipt_body, "receipt response")
            envelope = decode_json(envelope_body, "envelope response")
            validate_trace(receipt, envelope, raw_body, raw_headers, payload, receipt_id, revision_id, expected_hash)
            timings["query_envelope_and_raw_trace"] = elapsed_ms(stage)

            stage = time.monotonic()
            service.stop()
            service.start()
            status, _, restarted_health = http_request(base_url + "/health/ready")
            require(status == 200 and decode_json(restarted_health, "restarted readiness").get("status") == "ready", "restart readiness failed")
            timings["controlled_stop_and_restart"] = elapsed_ms(stage)

            stage = time.monotonic()
            post_receipt_status, _, post_receipt_body = http_request(base_url + "/api/v1/receipts/" + receipt_id, token=token)
            post_envelope_status, _, post_envelope_body = http_request(base_url + "/api/v1/events/" + revision_id, token=token)
            post_raw_status, post_raw_headers, post_raw_body = http_request(base_url + "/api/v1/receipts/" + receipt_id + "/raw", token=token)
            require(post_receipt_status == post_envelope_status == post_raw_status == 200, "post-restart trace retrieval failed")
            post_receipt = decode_json(post_receipt_body, "post-restart receipt")
            post_envelope = decode_json(post_envelope_body, "post-restart envelope")
            validate_trace(
                post_receipt, post_envelope, post_raw_body, post_raw_headers,
                payload, receipt_id, revision_id, expected_hash,
            )
            timings["post_restart_trace"] = elapsed_ms(stage)
            service.stop()
        finally:
            service.force_stop()

    duration = elapsed_ms(overall_started)
    require(duration <= args.limit_seconds * 1000, "demo exceeded its configured time limit")
    invariants = {
        "health_ready_before_and_after_restart": True,
        "unauthenticated_admission_rejected_without_receipt": True,
        "authenticated_admission_returned_202_and_receipt": True,
        "query_links_receipt_to_immutable_revision": True,
        "receipt_envelope_and_raw_sha256_match": True,
        "retrieved_raw_bytes_equal_fixture": True,
        "generic_json_fields_are_preserved_with_mapping_gap_explicit": True,
        "restart_preserves_receipt_revision_envelope_and_raw": True,
    }
    result = {
        "evidence_version": "ulpf-local-demo/1.0.0",
        "run_label": args.run_label,
        "result": "pass",
        "started_at": started_at,
        "duration_ms": duration,
        "limit_ms": args.limit_seconds * 1000,
        "environment": {"platform": platform.system(), "machine": platform.machine(), "python": platform.python_version()},
        "binary": {"sha256": sha256_file(binary), "version": version},
        "fixture": {"path": "tests/corpus/raw/json_firewall.json", "size_bytes": len(payload), "sha256": expected_hash, "synthetic": True},
        "observations": {"unauthenticated_status": denied_status, "admission_status": admitted_status, "query_items": query_count},
        "trace": {"receipt_id": receipt_id, "revision_id": revision_id, "raw_sha256": expected_hash, "status": EXPECTED_STATUS, "parser_id": EXPECTED_PARSER},
        "invariants": invariants,
        "timings_ms": {**timings, "total": duration},
    }
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(markdown_report(result), encoding="utf-8")
    print(f"local demo PASS: {duration:.3f} ms; evidence={json_path}")


def main():
    args = parse_args()
    try:
        run_demo(args)
    except (DemoError, OSError, subprocess.SubprocessError) as error:
        print(f"local demo FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
