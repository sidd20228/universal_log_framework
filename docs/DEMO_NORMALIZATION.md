# Demo normalization

The default Compose runtime assigns HTTP inputs to the trusted `enterprise-demo`
source profile. Its immutable bundle is checked in at `bundles/demo/enterprise`
and installed into the persistent `ulpf-bundles` volume. It includes seven
parsers, seven explicit mapping configurations, and 14 valid input/output
fixtures matching the dashboard simulation.

These are synthetic demonstration contracts, not certified production vendor
parsers. Real deployments should bind a reviewed bundle to each trusted source
profile and add representative source fixtures before activation.

| Demo sources | Format | Canonical class |
| --- | --- | --- |
| Palo Alto Firewall | JSON | Network Activity (4001) |
| Cisco ASA | CEF | Network Activity (4001) |
| IBM QRadar IPS | LEEF | Network Activity (4001) |
| Windows Security, Okta System Log, Microsoft Entra ID | JSON | Authentication (3002) |
| AWS CloudTrail, Kubernetes Audit, PaymentApp | JSON | API Activity (6003) |
| SaaS Audit Export | CSV | API Activity (6003) |
| CrowdStrike Falcon | JSON | Process Activity (1007) |
| NGINX Access | Key/value | HTTP Activity (4002) |
| Linux Syslog | RFC 5424 | Event Log Activity (1008) |
| Oracle Audit | XML | Datastore Activity (6005) |

Mappings normalize class, action, source IP, and available destination IP and
timestamp fields. CEF/LEEF seed templates lack a structured event timestamp, so
their mappings omit canonical time; extra live-template time attributes remain
in the parsed evidence. Unknown source classes, unsupported actions,
invalid IPs, and missing required fields remain partially parsed with mapping
diagnostics. Extra attributes remain available in the parsed/unmapped evidence.
Each canonical field records its mapping provenance; original bytes and their
SHA-256 are retained independently of normalization.

## Why older logs appeared partially parsed

Previously the demo listener used generic syntax parsers without a source-profile
mapping. Extraction succeeded, but normalization correctly reported
`MAPPING_NOT_CONFIGURED`. Configuring the bundle fixes new events. Historical
events require explicit reprocessing; activation does not rewrite history.

Use the authenticated [bundle lifecycle API](BUNDLE_LIFECYCLE.md#live-control-api)
to obtain the installed bundle digest, then schedule each eligible retained
synthetic receipt through `POST /api/v1/admin/reprocess`:

```json
{
  "receipt_id": "<existing synthetic demo receipt>",
  "pipeline_version": "1.0.1",
  "bundle_sha256": "<installed enterprise-demo digest>",
  "reason": "Apply reviewed normalization to retained synthetic demo evidence"
}
```

Only reprocess receipts that match these demo contracts. Poll the returned job
until completion and inspect its new revision. Jobs are idempotent for the
receipt, pipeline version, and bundle digest. Old revisions, receipt IDs, and raw
hashes remain unchanged. The dashboard summarizes the latest revision per receipt;
the event query and receipt history APIs retain access to every revision.

## Regression checks

- `node --test internal/dashboard/live_test.cjs` checks fixture/template agreement.
- `go test ./internal/bundlecompile ./internal/registry ./internal/dashboardapi`
  checks normalization outputs/provenance, artifact validation, and latest-revision
  dashboard counts without discarding history.
- `go test ./internal/server -run TestEnterpriseDemo` sends all 14 templates through
  the HTTP service and checks canonical output, raw hashes, and an invalid-IP case
  that must remain partially parsed.
