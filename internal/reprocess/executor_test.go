package reprocess_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/envelope"
	"github.com/sidd20228/universal_log_framework/internal/evidence"
	"github.com/sidd20228/universal_log_framework/internal/inbox"
	"github.com/sidd20228/universal_log_framework/internal/model"
	"github.com/sidd20228/universal_log_framework/internal/registry"
	"github.com/sidd20228/universal_log_framework/internal/reprocess"
	"github.com/sidd20228/universal_log_framework/internal/worker"
)

func TestExecutorReprocessesExactEvidenceIntoCompleteEnvelope(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	catalog := filepath.Join(root, "catalog")
	t.Cleanup(func() {
		_ = filepath.Walk(catalog, func(path string, info os.FileInfo, err error) error {
			if err == nil {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	store, err := inbox.OpenSQLite(ctx, filepath.Join(root, "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	raw, err := evidence.NewFilesystem(filepath.Join(root, "raw"))
	if err != nil {
		t.Fatal(err)
	}
	loader, err := registry.NewLoader(registry.RuntimeCompatibility{EngineVersion: "1.0.0", EnvelopeSchema: envelope.SchemaVersion, OCSFVersion: "1.9.0"})
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := registry.NewLifecycle(ctx, catalog, loader, store)
	if err != nil {
		t.Fatal(err)
	}
	installed, err := lifecycle.Install(ctx, filepath.Join("..", "..", "bundles", "reference", "json-firewall"))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(filepath.Join("..", "..", "bundles", "reference", "json-firewall", "fixtures", "valid", "traffic.json"))
	if err != nil {
		t.Fatal(err)
	}
	received := time.Now().UTC().Add(-time.Minute)
	receiptID := "018f9f18-1f53-7a64-8c2c-2cf05f89b001"
	reference, err := raw.Write(ctx, receiptID, received, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	receipt := model.Receipt{ID: receiptID, TenantID: "tenant-a", ReceivedAt: received, ListenerID: "test", Transport: model.TransportHTTP,
		SourceProfileID: "edge", Framing: model.Framing{Mode: model.FramingHTTPOctets, Complete: true, ObservedBytes: uint64(len(payload))}, Raw: reference, State: model.StateAccepted}
	if err := store.InsertReceipt(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	job, _, err := lifecycle.ScheduleReprocess(ctx, receipt.ID, "2.0.0", installed.Digest, "test exact evidence", "operator")
	if err != nil {
		t.Fatal(err)
	}
	flaky := &onceOpenFailure{delegate: raw}
	flaky.fail.Store(true)
	executor, err := reprocess.New(reprocess.Config{Owner: "worker", LeaseDuration: time.Minute, ProcessingTimeout: 5 * time.Second, MaxEvidenceBytes: 1 << 20}, lifecycle, store, flaky)
	if err != nil {
		t.Fatal(err)
	}
	step, err := executor.RunOnce(ctx)
	if err != nil || step.Outcome != worker.OutcomeRetry {
		t.Fatalf("first RunOnce() = (%+v, %v)", step, err)
	}
	retrying, err := lifecycle.GetReprocessJob(ctx, job.ID)
	if err != nil || retrying.Status != registry.ReprocessQueued || retrying.Attempts != 1 {
		t.Fatalf("retrying job = (%+v, %v)", retrying, err)
	}
	executor, err = reprocess.New(reprocess.Config{Owner: "worker-restarted", LeaseDuration: time.Minute, ProcessingTimeout: 5 * time.Second, MaxEvidenceBytes: 1 << 20}, lifecycle, store, flaky)
	if err != nil {
		t.Fatal(err)
	}
	step, err = executor.RunOnce(ctx)
	if err != nil || step.Outcome != worker.OutcomeCommitted {
		t.Fatalf("restarted RunOnce() = (%+v, %v)", step, err)
	}
	completed, err := lifecycle.GetReprocessJob(ctx, job.ID)
	if err != nil || completed.Status != registry.ReprocessComplete {
		t.Fatalf("job = (%+v, %v)", completed, err)
	}
	built, err := store.GetEnvelope(ctx, completed.CompletedRevisionID)
	if err != nil {
		t.Fatal(err)
	}
	if built.Raw != reference || built.Receipt.ID != receipt.ID || len(built.Event) == 0 || len(built.Provenance) == 0 {
		t.Fatalf("incomplete envelope: %+v", built)
	}
}

type onceOpenFailure struct {
	delegate *evidence.Filesystem
	fail     atomic.Bool
}

func (store *onceOpenFailure) Verify(ctx context.Context, reference model.RawReference) error {
	return store.delegate.Verify(ctx, reference)
}

func (store *onceOpenFailure) Open(ctx context.Context, reference model.RawReference) (io.ReadCloser, error) {
	if store.fail.CompareAndSwap(true, false) {
		return nil, evidence.ErrUnavailable
	}
	return store.delegate.Open(ctx, reference)
}
