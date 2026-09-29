# Parser authoring guide

ULPF separates byte-level syntax extraction from semantic mapping. A syntax
parser may identify fields that are present in the input; it must not guess
that a vendor field means a canonical source address, action, class, or time.
Reviewed declarative mappings make those decisions and attach per-field
provenance.

Read [built-in parser behavior](PARSERS.md), the [envelope contract](ENVELOPE.md),
and [bundle lifecycle](BUNDLE_LIFECYCLE.md) before adding a format.

## Choose an extension type

Use a built-in parser when the syntax needs a bounded state machine or broadly
reusable implementation. Use `declarative_re2` when a complete record can be
matched by one anchored RE2 expression with named captures. Package an
existing built-in parser in a bundle when only fingerprints, mappings,
taxonomies, fixtures, or source-profile selection change.

Bundles cannot load Python, JavaScript, shared libraries, shell commands, or
other executable parser code. Allowed implementation names are:

```text
builtin_syslog  builtin_json  builtin_xml  builtin_csv
builtin_cef     builtin_leef  builtin_kv   declarative_re2
```

The `ulpf serve` command currently uses a fixed built-in registry. Bundle
installation and activation are Go lifecycle APIs, not CLI operations.

## Syntax parser contract

All syntax parsers implement:

```go
type SyntaxParser interface {
    Descriptor() ParserDescriptor
    Parse(context.Context, Payload, Limits) ParseResult
}
```

Follow these rules:

- Treat `Payload.Bytes` as immutable and copy any retained byte slices.
- Apply `Limits.WithDefaults()` and enforce input, field, depth, and token
  limits during parsing rather than after building an unbounded tree.
- Check context cancellation inside loops.
- Return stable, documented issue codes and byte offsets. Error messages must
  not reproduce raw payloads.
- Preserve fields exactly enough for later mappings. Keep any uninterpreted
  suffix in `ParsedDocument.Unmatched`.
- Return `INVALID` when no trustworthy structure can be produced,
  `PARTIALLY_PARSED` when bounded fields are trustworthy but material remains
  or issues occurred, and `PARSED` only for complete syntax extraction.
- Preserve duplicates where the source syntax allows them. Never silently
  overwrite an earlier occurrence.
- Keep results deterministic for the same bytes, limits, and parser version.

Parser identity is immutable. Any behavioral change requires a new semantic
version and updated fixtures.

## Declarative RE2 configuration

The parser configuration is strict JSON:

```json
{
  "config_version": "ulpf-re2-parser/1",
  "id": "lab-router-text",
  "version": "1.0.0",
  "format": "router-text",
  "pattern": "^(?P<event>[A-Z_]+)\\|device=(?P<device>[^|]+)$",
  "required_captures": ["event", "device"]
}
```

Patterns must be anchored, use Go's RE2-compatible `regexp` syntax, and have
at least one uniquely named capture. Backreferences and look-around are not
supported. `required_captures` may only name declared captures. Keep patterns
specific enough that unrelated text becomes a negative fixture.

For every parser, test at least:

- a representative valid record and exact expected fields;
- a non-matching record;
- malformed and truncated input;
- the configured byte, field, depth, and token boundaries that apply;
- cancellation and invalid UTF-8 when the format requires UTF-8;
- duplicate keys or attributes when the syntax permits them;
- deterministic output across repeated runs.

`re2parser.Parser.ValidateFixtures` requires positive and negative fixtures and
checks exact expected fields for matches. Run the focused implementation tests
with:

```sh
go test ./internal/interpret/re2parser -count=1
go test ./internal/securitytest -count=1
```

## Bundle layout

A bundle is a real directory without symbolic links. Use one manifest and
declare every regular file:

```text
lab-router-1.0.0/
├── manifest.json
├── parser.json
└── fixtures/
    ├── valid/
    │   └── router.log
    ├── invalid/
    │   └── unrelated.log
    └── expected/
        └── router.json
```

The fixture directories must exist. Files below them are artifacts too and
must appear in the manifest. Artifact files must be regular, non-executable
files. Paths must be relative slash-separated paths without empty, dot, or
parent components.

Minimal manifest shape:

```json
{
  "manifest_version": "ulpf-parser-bundle/1",
  "bundle_id": "lab-router",
  "version": "1.0.0",
  "description": "Parser and fixtures for the synthetic lab router format.",
  "license": "Apache-2.0",
  "compatibility": {
    "envelope_schema": "ulpf-envelope/1.0.0",
    "minimum_engine_version": "1.0.0",
    "maximum_engine_version": "1.0.0",
    "ocsf_version": "1.9.0"
  },
  "source": {
    "kind": "synthetic",
    "reference": "internal fixture specification"
  },
  "parsers": [
    {
      "id": "lab-router-text",
      "implementation": "declarative_re2",
      "config": "parser.json",
      "priority": 100
    }
  ],
  "fixtures": {
    "valid": "fixtures/valid",
    "invalid": "fixtures/invalid",
    "expected": "fixtures/expected"
  },
  "artifacts": [
    {
      "path": "parser.json",
      "role": "parser_config",
      "sha256": "<64-lowercase-hex-sha256>",
      "media_type": "application/json"
    },
    {
      "path": "fixtures/valid/router.log",
      "role": "valid_fixture",
      "sha256": "<64-lowercase-hex-sha256>"
    },
    {
      "path": "fixtures/invalid/unrelated.log",
      "role": "invalid_fixture",
      "sha256": "<64-lowercase-hex-sha256>"
    },
    {
      "path": "fixtures/expected/router.json",
      "role": "expected_output",
      "sha256": "<64-lowercase-hex-sha256>",
      "media_type": "application/json"
    }
  ]
}
```

Add every fixture using `valid_fixture`, `invalid_fixture`, or
`expected_output`. Optional bundle-level paths use the corresponding roles:
`fingerprints`, `mappings`, `taxonomies`, or `event_schema`. Documentation may
use `documentation`. A manifest is decoded with unknown fields rejected and
must contain one JSON value. A file named `manifest.yaml` is accepted only
when its content is JSON; use `manifest.json` to avoid ambiguity.

Generate lowercase SHA-256 values after all files are final:

```sh
sha256sum parser.json fixtures/valid/router.log \
  fixtures/invalid/unrelated.log fixtures/expected/router.json
```

On macOS, use `shasum -a 256`. Copy the values into the artifact entries. A
later byte change is intentional only with a new checksum and, after a version
has been installed or activated, a new semantic version.

## Mapping rules

Mappings use explicit source and target paths. A rule declares its conversion,
whether its source is required, and an optional reviewed taxonomy. Supported
conversions include string, IP address, integer/port, timestamp, lowercase,
and taxonomy lookup. Targets are restricted by the mapping package allowlist.

Mapping failures do not justify guessing. Keep the original source field in
`parsed.unmapped`, emit the stable mapping issue, and leave the canonical field
absent. Every canonical event leaf must have mapping provenance or envelope
validation rejects the result. See the examples and strict configuration tests
in `internal/interpret/mapping`.

## Review and activation checklist

1. Document the format source and licensing. Use `official_documentation`,
   `reviewed_capture`, or `synthetic` as the source kind.
2. Remove secrets, personal data, and production identifiers from fixtures.
3. Run positive, negative, malformed, boundary, and determinism tests.
4. Generate artifact hashes and verify there are no undeclared files,
   symbolic links, executable bits, or traversal paths.
5. Set compatibility to the versions actually tested; do not use a broad
   maximum without evidence.
6. Load the directory with `registry.Loader` in a test using the intended
   runtime compatibility.
7. Install through `registry.Lifecycle.Install`, then activate by immutable
   digest and expected configuration revision.
8. Verify the last-known-good snapshot remains active after a deliberately
   invalid candidate.
9. Reprocess retained receipts explicitly when comparing a new version; never
   overwrite an earlier revision or raw evidence.

Run the package gates before review:

```sh
go test -race ./internal/registry ./internal/interpret/... ./internal/envelope
go vet ./internal/registry ./internal/interpret/... ./internal/envelope
./scripts/verify-corpus.sh
```

Manifest checksums establish bundle integrity inside the catalog. The
optional signature metadata accepts `cosign` or `minisign` declarations, but
the current loader does not verify cryptographic signatures. Apply an external
reviewed signature policy before treating a bundle as publisher-authenticated.
