# ULPF schemas

This directory contains the normative JSON Schema Draft 2020-12 contracts for the ULPF envelope, authored configuration, and parser bundle manifest.

- `ulpf-envelope-1.0.0.json` validates the immutable receipt/raw/processing contract and its optional normalized projection.
- `ulpf-config-1.0.0.json` validates JSON configuration documents. JSON examples are also valid YAML documents; the configuration loader is responsible for converting YAML into the same JSON data model before validation.
- `parser-bundle-manifest-1.0.0.json` validates declarative bundle metadata and excludes executable parser implementations.
- `vendor/ocsf/1.9.0/` contains the official OCSF schema source pinned to tag `1.9.0`, commit `856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba`.

The OCSF files retain the upstream `LICENSE` and `NOTICE`. `SOURCE.json` records provenance and scope, `SHA256SUMS` records every vendored upstream file, and `TREE_SHA256` protects that manifest.

Run all positive and negative examples plus the vendor integrity check:

```sh
./scripts/validate-schemas.sh
```

Exercise the checksum verifier's tamper-detection path without modifying the vendored tree:

```sh
./tests/schema/test-vendor-integrity.sh
```

The validation script uses the `jsonschema` command from Python jsonschema 4.x and selects `Draft202012Validator` explicitly. Set `JSONSCHEMA_BIN` when the executable has a different name or path.

The envelope checks include the golden output produced by `internal/envelope`.
Cross-field invariants that JSON Schema cannot express, including complete
canonical-field provenance and deterministic quality counts, are enforced by
`envelope.Envelope.Validate`.

JSON Schema cannot express cross-document constraints such as unique listener IDs, artifact-path completeness, checksum equality, or whether a source profile references an installed bundle. The configuration and bundle activation paths must perform those semantic checks after schema validation.
