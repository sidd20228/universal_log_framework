package registry_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/envelope"
	"github.com/sidd20228/universal_log_framework/internal/inbox"
	"github.com/sidd20228/universal_log_framework/internal/interpret/mapping"
	"github.com/sidd20228/universal_log_framework/internal/model"
	"github.com/sidd20228/universal_log_framework/internal/registry"
)

func TestBundleLifecycleDemoOnboardingAndImmutableReprocess(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store, err := inbox.OpenSQLite(ctx, filepath.Join(root, "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	lifecycle, err := registry.NewLifecycle(ctx, filepath.Join(root, "bundles"), testLoader(t), store)
	if err != nil {
		t.Fatal(err)
	}
	cleanupReadOnlyCatalog(t, filepath.Join(root, "bundles"))

	sourceRoot := filepath.Join(root, "sources")
	v1Source := createBundle(t, filepath.Join(sourceRoot, "v1"), "lab-firewall", "1.0.0", nil)
	v1, err := lifecycle.Install(ctx, v1Source)
	if err != nil {
		t.Fatal(err)
	}
	idempotent, err := lifecycle.Install(ctx, v1Source)
	if err != nil || idempotent.Digest != v1.Digest || idempotent.Directory != v1.Directory {
		t.Fatalf("idempotent install = (%+v, %v)", idempotent, err)
	}
	if v1.Directory != filepath.Join(root, "bundles", "lab-firewall", "1.0.0") {
		t.Fatalf("installed directory = %q", v1.Directory)
	}
	activationV1, err := lifecycle.Activate(ctx, "lab-firewall-a", v1.Digest, 0, "operator@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if activationV1.ConfigRevision != 1 || lifecycle.RegistrySnapshot().Len() != 1 {
		t.Fatalf("v1 activation = %+v, registry size = %d", activationV1, lifecycle.RegistrySnapshot().Len())
	}

	receivedAt := time.Now().UTC().Add(-time.Minute)
	receipt := lifecycleReceipt("018f9f18-1f53-7a64-8c2c-2cf05f89a001", receivedAt)
	if err := store.InsertReceipt(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	claim, err := store.Claim(ctx, "initial-worker", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	initialRevision := lifecycleRevision("018f9f18-1f53-7a64-8c2c-2cf05f89a002", receipt.ID, "1.0.0", v1, receivedAt.Add(time.Second))
	if _, created, err := store.CommitRevision(ctx, initialRevision, claim.LeaseOwner); err != nil || !created {
		t.Fatalf("CommitRevision() = created %v, error %v", created, err)
	}
	receiptBefore, err := store.GetReceipt(ctx, receipt.ID)
	if err != nil {
		t.Fatal(err)
	}

	v2Source := createBundle(t, filepath.Join(sourceRoot, "v2"), "lab-firewall", "2.0.0", func(manifest map[string]any) {
		manifest["description"] = "Synthetic updated parser bundle."
	})
	v2, err := lifecycle.Install(ctx, v2Source)
	if err != nil {
		t.Fatal(err)
	}
	activationV2, err := lifecycle.Activate(ctx, "lab-firewall-a", v2.Digest, 1, "operator@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if activationV2.ConfigRevision != 2 || activationV2.BundleDigest != v2.Digest {
		t.Fatalf("v2 activation = %+v", activationV2)
	}

	job, created, err := lifecycle.ScheduleReprocess(ctx, receipt.ID, "2.0.0", v2.Digest, "apply reviewed v2 mapping", "operator@example.test")
	if err != nil || !created {
		t.Fatalf("ScheduleReprocess() = (%+v, %v, %v)", job, created, err)
	}
	duplicate, created, err := lifecycle.ScheduleReprocess(ctx, receipt.ID, "2.0.0", v2.Digest, "duplicate request", "operator@example.test")
	if err != nil || created || duplicate.ID != job.ID {
		t.Fatalf("duplicate ScheduleReprocess() = (%+v, %v, %v)", duplicate, created, err)
	}
	claimedJob, err := lifecycle.ClaimReprocess(ctx, "reprocess-worker", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	reprocessed := lifecycleRevision("018f9f18-1f53-7a64-8c2c-2cf05f89a003", receipt.ID, "2.0.0", v2, receivedAt.Add(2*time.Second))
	committed, created, err := lifecycle.CommitReprocess(ctx, claimedJob.ID, "reprocess-worker", reprocessed, lifecycleEnvelope(t, receipt, reprocessed))
	if err != nil || !created || committed.ID != reprocessed.ID {
		t.Fatalf("CommitReprocess() = (%+v, %v, %v)", committed, created, err)
	}
	storedEnvelope, err := store.GetEnvelope(ctx, reprocessed.ID)
	if err != nil || storedEnvelope.Processing.RevisionID != reprocessed.ID || storedEnvelope.Raw != receipt.Raw {
		t.Fatalf("stored reprocess envelope = (%+v, %v)", storedEnvelope, err)
	}
	completedJob, err := lifecycle.GetReprocessJob(ctx, job.ID)
	if err != nil || completedJob.Status != registry.ReprocessComplete || completedJob.CompletedRevisionID != reprocessed.ID {
		t.Fatalf("completed job = (%+v, %v)", completedJob, err)
	}

	revisions, err := store.ListRevisions(ctx, receipt.ID)
	if err != nil {
		t.Fatal(err)
	}
	receiptAfter, err := store.GetReceipt(ctx, receipt.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(revisions) != 2 || revisions[0].ID != initialRevision.ID || revisions[1].ID != reprocessed.ID {
		t.Fatalf("revisions = %+v", revisions)
	}
	if receiptAfter.Receipt.Raw != receiptBefore.Receipt.Raw || receiptAfter.Receipt.ID != receiptBefore.Receipt.ID || receiptAfter.Receipt.State != receiptBefore.Receipt.State {
		t.Fatalf("reprocessing mutated receipt/raw: before=%+v after=%+v", receiptBefore.Receipt, receiptAfter.Receipt)
	}

	restarted, err := registry.NewLifecycle(ctx, filepath.Join(root, "bundles"), testLoader(t), store)
	if err != nil {
		t.Fatal(err)
	}
	restored, found := restarted.ActivationSnapshot().Resolve("lab-firewall-a")
	if !found || restored.BundleDigest != v2.Digest || restarted.ActivationSnapshot().ConfigRevision() != 2 {
		t.Fatalf("restored activation = (%+v, %v), revision=%d", restored, found, restarted.ActivationSnapshot().ConfigRevision())
	}
	rolledBack, err := restarted.Activate(ctx, "lab-firewall-a", v1.Digest, 2, "operator@example.test")
	if err != nil || rolledBack.BundleDigest != v1.Digest || rolledBack.ConfigRevision != 3 {
		t.Fatalf("rollback = (%+v, %v)", rolledBack, err)
	}
}

func TestBundleLifecycleFailuresPreserveActiveSnapshot(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store, err := inbox.OpenSQLite(ctx, filepath.Join(root, "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	lifecycle, err := registry.NewLifecycle(ctx, filepath.Join(root, "bundles"), testLoader(t), store)
	if err != nil {
		t.Fatal(err)
	}
	cleanupReadOnlyCatalog(t, filepath.Join(root, "bundles"))
	source := createBundle(t, filepath.Join(root, "source"), "stable", "1.0.0", nil)
	installed, err := lifecycle.Install(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	parserInfo, err := os.Stat(filepath.Join(installed.Directory, "parser.json"))
	if err != nil {
		t.Fatal(err)
	}
	if parserInfo.Mode().Perm()&0o222 != 0 {
		t.Fatalf("installed parser mode = %o, want read-only", parserInfo.Mode().Perm())
	}
	if _, err := lifecycle.Activate(ctx, "edge", installed.Digest, 0, "operator"); err != nil {
		t.Fatal(err)
	}
	before := lifecycle.ActivationSnapshot()
	if _, err := lifecycle.Activate(ctx, "edge", installed.Digest, 0, "stale-operator"); !errors.Is(err, registry.ErrActivationConflict) {
		t.Fatalf("stale activation error = %v", err)
	}
	if lifecycle.ActivationSnapshot() != before {
		t.Fatal("failed activation replaced the active snapshot")
	}
	unknown := fmt.Sprintf("%x", sha256.Sum256([]byte("unknown")))
	if _, err := lifecycle.Activate(ctx, "edge", unknown, 1, "operator"); !errors.Is(err, registry.ErrBundleNotInstalled) {
		t.Fatalf("unknown activation error = %v", err)
	}
	if lifecycle.ActivationSnapshot() != before {
		t.Fatal("unknown bundle replaced the active snapshot")
	}
	tamperedSource := createBundle(t, filepath.Join(root, "tampered"), "candidate", "2.0.0", nil)
	tampered, err := lifecycle.Install(ctx, tamperedSource)
	if err != nil {
		t.Fatal(err)
	}
	tamperedParser := filepath.Join(tampered.Directory, "parser.json")
	if err := os.Chmod(tamperedParser, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tamperedParser, []byte(`{"changed":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.Activate(ctx, "edge", tampered.Digest, 1, "operator"); !errors.Is(err, registry.ErrArtifactIntegrity) {
		t.Fatalf("tampered activation error = %v", err)
	}
	if lifecycle.ActivationSnapshot() != before {
		t.Fatal("tampered bundle replaced the active snapshot")
	}

	replacement := createBundle(t, filepath.Join(root, "replacement"), "stable", "1.0.0", nil)
	rewriteParserArtifact(t, replacement, []byte(`{"format":"json"}`))
	if _, err := lifecycle.Install(ctx, replacement); !errors.Is(err, registry.ErrDuplicateBundle) {
		t.Fatalf("immutable replacement error = %v", err)
	}
}

func TestReprocessRejectsMismatchedRevisionAndSupportsRetry(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store, err := inbox.OpenSQLite(ctx, filepath.Join(root, "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	lifecycle, err := registry.NewLifecycle(ctx, filepath.Join(root, "bundles"), testLoader(t), store)
	if err != nil {
		t.Fatal(err)
	}
	cleanupReadOnlyCatalog(t, filepath.Join(root, "bundles"))
	installed, err := lifecycle.Install(ctx, createBundle(t, filepath.Join(root, "source"), "retry", "1.0.0", nil))
	if err != nil {
		t.Fatal(err)
	}
	receipt := lifecycleReceipt("018f9f18-1f53-7a64-8c2c-2cf05f89a011", time.Now().UTC())
	if err := store.InsertReceipt(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	job, _, err := lifecycle.ScheduleReprocess(ctx, receipt.ID, "1.0.0", installed.Digest, "retry test", "operator")
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := lifecycle.ClaimReprocess(ctx, "worker-a", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	mismatched := lifecycleRevision("018f9f18-1f53-7a64-8c2c-2cf05f89a012", receipt.ID, "9.9.9", installed, time.Now().UTC())
	if _, _, err := lifecycle.CommitReprocess(ctx, job.ID, claimed.LeaseOwner, mismatched, lifecycleEnvelope(t, receipt, mismatched)); !errors.Is(err, registry.ErrInvalidLifecycle) {
		t.Fatalf("mismatched commit error = %v", err)
	}
	if err := lifecycle.ReleaseReprocess(ctx, job.ID, claimed.LeaseOwner, true, "TRANSIENT"); err != nil {
		t.Fatal(err)
	}
	retried, err := lifecycle.ClaimReprocess(ctx, "worker-b", time.Now().UTC(), time.Minute)
	if err != nil || retried.ID != job.ID || retried.LastErrorCode != "" {
		t.Fatalf("retried job = (%+v, %v)", retried, err)
	}
}

func lifecycleReceipt(id string, receivedAt time.Time) model.Receipt {
	payload := []byte("synthetic firewall event")
	digest := sha256.Sum256(payload)
	return model.Receipt{
		ID: id, TenantID: "tenant-a", ReceivedAt: receivedAt, ListenerID: "demo",
		Transport: model.TransportSyslogUDP, Peer: &model.Peer{IP: netip.MustParseAddr("192.0.2.10"), Port: 514},
		SourceProfileID: "lab-firewall-a",
		Framing:         model.Framing{Mode: model.FramingDatagram, Complete: true, ObservedBytes: uint64(len(payload))},
		Raw:             model.RawReference{Ref: "raw/" + id + ".bin", SHA256: fmt.Sprintf("%x", digest), SizeBytes: uint64(len(payload)), Compression: "none", Available: true},
		State:           model.StateAccepted,
	}
}

func lifecycleRevision(id, receiptID, pipeline string, bundle registry.InstalledBundle, completedAt time.Time) model.Revision {
	confidence := 1.0
	return model.Revision{
		ID: id, ReceiptID: receiptID, PipelineVersion: pipeline, SchemaVersion: "ulpf-envelope/1.0.0",
		Parser: &model.ParserIdentity{ID: bundle.BundleID + "-parser", Version: bundle.Version, BundleSHA256: bundle.Digest},
		Status: model.StatusInvalid, Confidence: &confidence, Issues: []model.Issue{},
		StartedAt: completedAt.Add(-time.Millisecond), CompletedAt: completedAt,
	}
}

func lifecycleEnvelope(t *testing.T, receipt model.Receipt, revision model.Revision) envelope.Envelope {
	t.Helper()
	built, err := envelope.Build(envelope.Input{Receipt: receipt, Revision: revision, Mapping: mapping.Result{}})
	if err != nil {
		t.Fatal(err)
	}
	return built
}

func TestInstalledBundleIsIndependentOfSourceDirectory(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store, err := inbox.OpenSQLite(ctx, filepath.Join(root, "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	lifecycle, err := registry.NewLifecycle(ctx, filepath.Join(root, "bundles"), testLoader(t), store)
	if err != nil {
		t.Fatal(err)
	}
	cleanupReadOnlyCatalog(t, filepath.Join(root, "bundles"))
	source := createBundle(t, filepath.Join(root, "source"), "copied", "1.0.0", nil)
	installed, err := lifecycle.Install(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(source); err != nil {
		t.Fatal(err)
	}
	restarted, err := registry.NewLifecycle(ctx, filepath.Join(root, "bundles"), testLoader(t), store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Activate(ctx, "copied-source", installed.Digest, 0, "operator"); err != nil {
		t.Fatalf("activate copied bundle after source deletion: %v", err)
	}
}

func cleanupReadOnlyCatalog(t *testing.T, root string) {
	t.Helper()
	t.Cleanup(func() {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				return os.Chmod(path, 0o700)
			}
			return os.Chmod(path, 0o600)
		})
	})
}
