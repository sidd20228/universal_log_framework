# Governed analytics datasets

ULPF exports deterministic, tenant-scoped Parquet datasets from immutable canonical revisions. The exporter reads envelopes from the local SQLite state, applies a versioned feature-set contract, assigns stable train/validation/test splits, and writes an immutable artifact with a validated manifest. Raw evidence bytes are never read or copied.

Feature sets use `ulpf-feature-set/1.0.0`. A feature selects an approved `event.*`, `quality.*`, or `processing.*` path and declares its type and null policy. Required missing values stop export; nullable missing values become JSON `null` in the row's `features_json` field. This makes schema gaps visible rather than replacing them with guessed values.

Every export must choose one policy for `PARTIALLY_PARSED` revisions:

- `include` retains selected partial revisions and preserves nullable missing features as null.
- `exclude` omits partial revisions from the immutable revision set.
- `reject` stops the export when a selected partial revision is encountered.

The received-at interval is half-open: `--from` is inclusive and `--to` is exclusive. Statuses and tenant ID are also part of selection. The manifest records all of these choices, so changing the partial-event policy changes the dataset identity.

Run an export with the bundled CLI:

```sh
ulpf dataset export \
  --sqlite /var/lib/ulpf/state/ulpf.sqlite \
  --tenant demo \
  --feature-set ./features/network-risk.json \
  --output /var/lib/ulpf/datasets \
  --from 2026-09-01T00:00:00Z \
  --to 2026-10-01T00:00:00Z \
  --statuses PARSED,PARTIALLY_PARSED \
  --partial-policy include \
  --split-seed evaluation-v1 \
  --train-bp 8000 --validation-bp 1000 --test-bp 1000
```

Rows are sorted by immutable revision ID. Split assignment hashes the seed and revision ID with `sha256_revision_id_v1`, then maps the result into 10,000 basis-point buckets. Reordering source records or repeating the export produces the same dataset ID, row order, splits, and Parquet digest.

Artifacts are stored at `tenant=<tenant>/dataset=<dataset_id>/dataset.parquet`, alongside `manifest.json`. The manifest binds the tenant, envelope schema, feature-set digest, selection, partial-event policy, revision-set digest, split policy, artifact digest, row count, and required lineage columns. Publishing uses an immutable directory; an existing identity with different bytes is rejected.

Each Parquet row includes receipt and revision IDs, tenant ID, receive time, raw SHA-256 reference, pipeline/parser/mapping/schema versions, processing status, quality score, issue codes, split, and the feature JSON. Consumers can verify `artifact.sha256`, load `features_json` according to the referenced feature set, and join a prediction back to the canonical revision with `revision_id`.
