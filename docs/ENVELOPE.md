# Envelope construction and validation

`internal/envelope.Build` creates the stable `ulpf-envelope/1.0.0` projection
from an accepted `model.Receipt`, an immutable `model.Revision`, a parser's
`interpret.ParsedDocument`, and a `mapping.Result`.

The builder preserves the parsed field tree, flattened unmapped values, and
unmatched parser bytes. Byte slices are copied before they enter the envelope.
Raw evidence remains external and is linked through its receipt-scoped path,
size, SHA-256 digest, availability, and explicit `none` or `zstd` compression.

Every canonical event leaf must have exactly one provenance entry. Provenance
must identify its source path, rule, and mapping identity. Missing, extra, or
mixed-version provenance rejects the envelope instead of publishing a trusted
event with incomplete lineage.

Quality is calculated only from evidence the mapper supplies:

```text
score = (required_present + provenance_present)
        / (required_total + canonical_event_leaves)
```

An empty denominator produces a score of zero. Counts are bounded before the
calculation. Parser confidence is copied only when a revision explicitly
supplies it; the envelope builder does not derive or guess confidence.

Cross-field validation checks receipt/revision linkage, schema and mapping
versions, processing status, canonical field types and vocabularies, required
mapping completion, provenance coverage, issue bounds, and processing times.
Parser and mapping issues are converted to bounded UTF-8 strings without raw
control characters.

Run the Go and JSON Schema contract checks with:

```sh
go test ./internal/envelope ./internal/model ./internal/evidence
./scripts/validate-schemas.sh
```
