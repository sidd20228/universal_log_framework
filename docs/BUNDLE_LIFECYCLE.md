# Parser bundle lifecycle

ULPF installs declarative parser bundles into a controlled filesystem catalog,
pins installed bundle digests to source profiles, and schedules explicit
reprocessing jobs against retained receipts. These operations use the
`registry.Lifecycle` API and the SQLite lifecycle store.

## Install

Create the lifecycle with the runtime compatibility policy, catalog directory,
and SQLite store:

```go
loader, err := registry.NewLoader(registry.RuntimeCompatibility{
    EngineVersion:  "1.0.0",
    EnvelopeSchema: "ulpf-envelope/1.0.0",
    OCSFVersion:    "1.9.0",
})
if err != nil {
    return err
}

state, err := inbox.OpenSQLite(ctx, "/var/lib/ulpf/state.sqlite")
if err != nil {
    return err
}

bundles, err := registry.NewLifecycle(
    ctx,
    "/var/lib/ulpf/bundles",
    loader,
    state,
)
```

Install a staged bundle directory with `bundles.Install(ctx, directory)`. The
operation validates its manifest, runtime compatibility, declared artifacts,
checksums, paths, fixture directories, and executable-file policy before
copying it. It validates the staged copy again, syncs it, makes it read-only,
and atomically renames it to:

```text
/var/lib/ulpf/bundles/<bundle-id>/<semantic-version>/
```

The immutable identity is the bundle ID, semantic version, and SHA-256 digest.
Reinstalling the same digest is idempotent. Different bytes with an installed
ID and version are rejected; operators must publish a new semantic version.
The source directory is no longer needed after installation.

## Per-parser normalization

A parser declaration may set `mappings` to the relative path of a declared
artifact with role `mappings`. The compiler verifies its checksum and loads it
as that parser's mapping configuration, including its inline taxonomies. This
overrides the bundle-level mapping for that parser. Parsers without this field
continue to inherit the bundle-level mapping. Bundle-level external taxonomy
artifacts apply to the bundle-level mapping only.

This allows one trusted source profile to accept several formats with distinct
field paths. The [enterprise demo bundle](DEMO_NORMALIZATION.md) uses this for
JSON, CEF, LEEF, key/value, Syslog, XML, and CSV. Invalid artifact references or
mapping configurations prevent activation.

## Activate and roll back

Activation binds one source profile to one installed digest. The expected
revision is a global compare-and-swap token, so concurrent or stale updates do
not overwrite a newer configuration.

```go
activation, err := bundles.Activate(
    ctx,
    "lab-firewall-a",
    installed.Digest,
    bundles.ActivationSnapshot().ConfigRevision(),
    "operator@example.test",
)
```

Only a completely validated installed copy can activate. SQLite commits the
new pin and revision before the process publishes its new immutable registry
and activation snapshots. Any validation or revision conflict leaves the
last-known-good snapshots in place. A restart reconstructs and verifies the
snapshots from SQLite and the catalog.

Rollback is another activation using the prior installed digest and the
current configuration revision. Installed versions remain available until a
separate retention policy removes them.

## Reprocess

Reprocessing is separate from activation and always names a receipt, target
pipeline version, installed bundle digest, reason, and actor:

```go
job, created, err := bundles.ScheduleReprocess(
    ctx,
    receiptID,
    "pipeline-2",
    installed.Digest,
    "apply reviewed firewall mapping v2",
    "operator@example.test",
)
```

The request is idempotent for `(receipt_id, pipeline_version, bundle_digest)`.
A worker leases it with `ClaimReprocess`, reads the original receipt and raw
evidence, then calls `CommitReprocess` with a revision and its complete
validated envelope. The receipt, pipeline, and parser bundle digest must match
the job. `ReleaseReprocess` either queues a
retry or records a terminal failure with a bounded error code.

The server runs the durable executor whenever bundle lifecycle is enabled.
Attempt counts are persisted with the job, transient processing failures retry
up to three claims, and expired leases are recovered after a process restart.
Every attempt reloads the named installed digest and verifies the retained raw
reference before parsing.

Completion inserts a new immutable processing revision and marks the job
complete in one SQLite transaction. Both `revision_json` and `envelope_json`
are stored, giving reprocessed output the same query and delivery contract as
first-pass output. It does not update the receipt state, raw
reference, raw hash, or earlier revisions. The same accepted occurrence can
therefore be compared across bundle and pipeline versions without creating a
new receipt or rewriting evidence.

The delivery reconciler exports the new revision independently. If an earlier
revision was already delivered, enqueueing the new required delivery moves the
receipt back to `DELIVERY_PENDING` until all required deliveries complete. The
old revision's delivery record stays delivered; repeated enqueueing is idempotent.

The automated onboarding scenario in
`internal/registry/lifecycle_test.go` installs and activates a synthetic v1
bundle, records an initial revision, installs and activates v2, reprocesses the
same receipt into a second revision, restarts from durable state, and rolls the
source profile back to v1.

## Live control API

When bundle lifecycle storage is configured, the runtime exposes authenticated
control routes:

- `GET /api/v1/admin/bundles` (`config:read`) lists immutable installed bundles.
- `GET|POST /api/v1/admin/activations` (`config:write`) reads or changes source
  profile pins. POST accepts `source_profile_id`, `bundle_sha256`, and
  `expected_revision`; selecting an older digest performs a rollback.
- `POST /api/v1/admin/reprocess` and
  `GET /api/v1/admin/reprocess/{job_id}` (`replay:write`) schedule and inspect
  durable jobs.

Activation compiles the candidate before the durable compare-and-swap. The
router publishes one complete snapshot atomically, so concurrent receipts see
the prior snapshot or the new snapshot. A rejected candidate leaves the last
known-good routes serving traffic. Restart reconstructs and compiles the
durable pins before readiness.
