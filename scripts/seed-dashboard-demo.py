#!/usr/bin/env python3
"""Seed a running ULPF instance with synthetic, multi-source dashboard events."""

import argparse
import datetime as dt
import json
import os
import time
import urllib.error
import urllib.request


SOURCES = (
    ("Palo Alto Firewall", "Network", "json"),
    ("Windows Security", "Endpoint", "json"),
    ("AWS CloudTrail", "Cloud", "json"),
    ("Okta System Log", "Identity", "json"),
    ("Kubernetes Audit", "Infrastructure", "json"),
    ("CrowdStrike Falcon", "Endpoint", "json"),
    ("PaymentApp", "Application", "json"),
    ("Cisco ASA", "Network", "cef"),
    ("IBM QRadar IPS", "Network", "leef"),
    ("NGINX Access", "Application", "kv"),
    ("Linux Syslog", "Infrastructure", "syslog"),
    ("Oracle Audit", "Infrastructure", "xml"),
    ("SaaS Audit Export", "Application", "csv"),
    ("Microsoft Entra ID", "Identity", "json"),
)


def timestamp(sequence):
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(milliseconds=sequence)).isoformat().replace("+00:00", "Z")


def payload_for(name, family, format_name, sequence):
    stamp = timestamp(sequence)
    source_ip = f"10.24.{sequence % 8}.{20 + sequence % 200}"
    destination_ip = f"198.51.100.{10 + sequence % 200}"
    action = "deny" if sequence % 3 == 0 else "allow"
    if format_name == "json":
        return json.dumps({
            "timestamp": stamp, "source_name": name, "source_family": family,
            "event_type": "security_event", "action": action, "src_ip": source_ip,
            "dst_ip": destination_ip, "user": f"demo-user-{sequence % 7}",
            "severity": ["low", "medium", "high"][sequence % 3], "synthetic": True,
        }, separators=(",", ":")).encode()
    if format_name == "cef":
        return f"CEF:0|Cisco|ASA|9.18|106023|Synthetic connection event|6|src={source_ip} dst={destination_ip} spt={41000 + sequence} dpt=443 proto=TCP act={action} msg=synthetic-demo".encode()
    if format_name == "leef":
        return f"LEEF:2.0|IBM|QRadar IPS|7.5|200|^|src={source_ip}^|dst={destination_ip}^|srcPort={41000 + sequence}^|dstPort=443^|proto=TCP^|action={action}^|sev=6".encode()
    if format_name == "kv":
        return f'time={stamp} source_name="NGINX Access" source_family=Application type=http src={source_ip} dst={destination_ip} method=POST path=/api/payments status=403 action={action} synthetic=true'.encode()
    if format_name == "syslog":
        return f'<134>1 {stamp} demo-host linux-syslog {1000 + sequence} SECURITY [demo source_name="Linux Syslog" source_family="Infrastructure" src="{source_ip}" dst="{destination_ip}" action="{action}"] synthetic event'.encode()
    if format_name == "xml":
        return f'<?xml version="1.0"?><event synthetic="true"><timestamp>{stamp}</timestamp><source_name>Oracle Audit</source_name><source_family>Infrastructure</source_family><source_ip>{source_ip}</source_ip><destination_ip>{destination_ip}</destination_ip><action>{action}</action></event>'.encode()
    if format_name == "csv":
        return f"timestamp,source_name,source_family,event_type,src_ip,dst_ip,action,synthetic\n{stamp},SaaS Audit Export,Application,audit,{source_ip},{destination_ip},{action},true\n".encode()
    raise ValueError(f"unsupported demo format: {format_name}")


def request_json(url, token, method="GET", body=None):
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/octet-stream"
    request = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            return response.status, json.loads(response.read().decode())
    except urllib.error.HTTPError as error:
        detail = error.read().decode(errors="replace")[:500]
        raise RuntimeError(f"HTTP {error.code} from {url}: {detail}") from error
    except urllib.error.URLError as error:
        raise RuntimeError(f"cannot reach {url}: {error.reason}") from error


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8080", help="running ULPF HTTP origin")
    parser.add_argument("--tenant", default="demo", help="tenant used by the running service")
    parser.add_argument("--rounds", type=int, default=2, choices=range(1, 6), metavar="1-5", help="events per source")
    parser.add_argument("--token", default=os.environ.get("ULPF_API_TOKEN", ""), help="API token; defaults to ULPF_API_TOKEN")
    parser.add_argument("--list", action="store_true", help="list synthetic source shapes without sending them")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.list:
        for name, family, format_name in SOURCES:
            print(f"{family:14} {format_name.upper():12} {name}")
        return 0
    if len(args.token) < 32:
        raise SystemExit("set ULPF_API_TOKEN or pass --token with the running service token")
    base_url = args.base_url.rstrip("/")
    status, before = request_json(f"{base_url}/api/v1/dashboard/summary?tenant_id={args.tenant}", args.token)
    if status != 200:
        raise SystemExit(f"dashboard summary returned HTTP {status}")
    baseline = int(before.get("totals", {}).get("revisions", 0))
    accepted = []
    sequence = 0
    for round_number in range(args.rounds):
        for name, family, format_name in SOURCES:
            sequence += 1
            payload = payload_for(name, family, format_name, sequence + round_number * len(SOURCES))
            status, response = request_json(f"{base_url}/api/v1/ingest", args.token, method="POST", body=payload)
            if status != 202 or not response.get("receipt_id"):
                raise RuntimeError(f"{name} was not durably accepted: HTTP {status} {response}")
            accepted.append((name, format_name, response["receipt_id"]))

    target = baseline + len(accepted)
    deadline = time.monotonic() + 20
    summary = {}
    while time.monotonic() < deadline:
        _, summary = request_json(f"{base_url}/api/v1/dashboard/summary?tenant_id={args.tenant}", args.token)
        if int(summary.get("totals", {}).get("revisions", 0)) >= target:
            break
        time.sleep(0.2)
    else:
        raise RuntimeError(f"accepted {len(accepted)} events, but processing did not reach {target} revisions")

    print(f"Seeded {len(accepted)} synthetic events from {len(SOURCES)} source shapes.")
    print("Formats: " + ", ".join(sorted({item[1].upper() for item in accepted})))
    print(f"Dashboard: {base_url}/dashboard/ (tenant {args.tenant})")
    print(f"Receipts: {summary.get('totals', {}).get('receipts', 0)}; revisions: {summary.get('totals', {}).get('revisions', 0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
