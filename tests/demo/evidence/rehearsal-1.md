# Local demo rehearsal: rehearsal-1

- Result: **PASS**
- Started: `2026-09-29T00:18:26Z`
- Duration: `850.176 ms`
- Limit: `120000 ms`
- Platform: `Darwin` / `arm64`
- Binary SHA-256: `97fcff544da719bcf1fb671467ab94d13256a6cdf759bf300afbe4df370b588d`
- Fixture: `tests/corpus/raw/json_firewall.json`
- Receipt: `01a0ea86-ef4d-7c29-9fd1-2e1633df23d1`
- Revision: `01a0ea86-efca-741c-aa44-2d11edfbee85`
- Raw SHA-256: `9aaf15a078fe0d21dfb1d71315c456fff0f6e4afd80436a22700cbba537b8efb`

## Verified invariants

| Invariant | Result |
|---|---|
| `health_ready_before_and_after_restart` | PASS |
| `unauthenticated_admission_rejected_without_receipt` | PASS |
| `authenticated_admission_returned_202_and_receipt` | PASS |
| `query_links_receipt_to_immutable_revision` | PASS |
| `receipt_envelope_and_raw_sha256_match` | PASS |
| `retrieved_raw_bytes_equal_fixture` | PASS |
| `generic_json_fields_are_preserved_with_mapping_gap_explicit` | PASS |
| `restart_preserves_receipt_revision_envelope_and_raw` | PASS |

## Timings

| Stage | Milliseconds |
|---|---:|
| `initial_start_and_health` | 91.016 |
| `unauthenticated_rejection` | 0.972 |
| `authenticated_admission` | 36.041 |
| `query_envelope_and_raw_trace` | 119.918 |
| `controlled_stop_and_restart` | 86.616 |
| `post_restart_trace` | 3.241 |
| `total` | 850.176 |

The first service process accepted and processed one synthetic JSON firewall
fixture. After a controlled `SIGTERM`, a new process opened the same SQLite and
raw-evidence paths. The original receipt, revision, envelope, and exact bytes
remained available. The unauthenticated request was rejected before admission.
