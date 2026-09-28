# Durable interpretation worker

The `internal/worker` package advances accepted receipts through the evidence
and interpretation pipeline. Each worker claims one SQLite inbox row with a
lease, verifies and reads its immutable evidence, detects a parser, parses and
maps the payload, builds a validated envelope, and commits the revision and
receipt state in one transaction.

```go
processor, err := worker.New(worker.Config{
    Owner:             "worker-01",
    PipelineVersion:   "0.1.0",
    LeaseDuration:     30 * time.Second,
    RenewInterval:     10 * time.Second,
    ProcessingTimeout: 20 * time.Second,
    MaxAttempts:       3,
}, inboxStore, evidenceStore, detector, resolver)
if err != nil {
    return err
}
return processor.Run(ctx)
```

The renewal interval must be shorter than the lease. Processing is bounded to
one in-flight operation per `Worker`; callers may create a configured pool of
workers for parallelism. A parser that ignores cancellation retains that slot
until it exits, so repeated timeouts cannot create an unbounded number of
goroutines.

Retryable failures release the receipt to `ACCEPTED` until `MaxAttempts` is
reached. The last attempt atomically records an `ERROR` envelope and moves the
receipt to `DEAD_LETTER`. Detection outcomes with no safe selection record an
`UNPARSED` revision. Parser panics are recovered per receipt and recorded as
`WORKER_PANIC`; processing deadlines use `WORKER_TIMEOUT`.

SQLite recovers an expired `PROCESSING` lease during the next claim. Revision
uniqueness is enforced by receipt, pipeline version, and parser bundle digest,
and the raw evidence reference remains unchanged across retries and restarts.
