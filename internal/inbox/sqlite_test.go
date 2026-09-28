package inbox

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/model"
	sqlitemigrations "github.com/sidd20228/universal_log_framework/migrations/sqlite"
)

func openTestStore(t *testing.T) (*SQLiteStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "inbox.sqlite")
	store, err := OpenSQLite(context.Background(), path)
	if err != nil {
		t.Fatalf("OpenSQLite() error = %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store, path
}

func testReceipt(id string, receivedAt time.Time) model.Receipt {
	return model.Receipt{
		ID:         id,
		TenantID:   "tenant-a",
		ReceivedAt: receivedAt.UTC(),
		ListenerID: "syslog-udp-5514",
		Transport:  model.TransportSyslogUDP,
		Peer:       &model.Peer{IP: netip.MustParseAddr("192.0.2.10"), Port: 49152},
		Framing: model.Framing{
			Mode:          model.FramingDatagram,
			Complete:      true,
			ObservedBytes: 143,
		},
		Raw: model.RawReference{
			Ref:          "raw/" + id + ".bin.zst",
			SHA256:       strings.Repeat("a", 64),
			SizeBytes:    143,
			EncodingHint: "utf-8",
			Compression:  "zstd",
			Available:    true,
		},
		State: model.StateAccepted,
	}
}

func testRevision(id, receiptID, bundleDigest string, completedAt time.Time) model.Revision {
	confidence := 0.99
	return model.Revision{
		ID:              id,
		ReceiptID:       receiptID,
		PipelineVersion: "0.1.0",
		SchemaVersion:   "ulpf-envelope/1.0.0",
		MappingVersion:  "network-security/1.0.0",
		Parser: &model.ParserIdentity{
			ID:           "cef",
			Version:      "1.0.0",
			BundleSHA256: bundleDigest,
		},
		Status:      model.StatusParsed,
		Confidence:  &confidence,
		Issues:      []model.Issue{},
		StartedAt:   completedAt.Add(-time.Millisecond),
		CompletedAt: completedAt,
	}
}

func TestMigrationsAreIdempotentAndDurabilityIsConfigured(t *testing.T) {
	store, path := openTestStore(t)
	entries, err := sqlitemigrations.Files.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	expectedMigrations := 0
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			expectedMigrations++
		}
	}
	var count int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != expectedMigrations {
		t.Fatalf("migration count = %d, want %d", count, expectedMigrations)
	}
	var journalMode string
	var synchronous int
	if err := store.db.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("PRAGMA synchronous").Scan(&synchronous); err != nil {
		t.Fatal(err)
	}
	if journalMode != "wal" || synchronous != 2 {
		t.Fatalf("durability settings = (%s, %d), want (wal, 2)", journalMode, synchronous)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenSQLite(context.Background(), path)
	if err != nil {
		t.Fatalf("second OpenSQLite() error = %v", err)
	}
	t.Cleanup(func() { reopened.Close() })
	if err := reopened.db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != expectedMigrations {
		t.Fatalf("migration count after reopen = %d, want %d", count, expectedMigrations)
	}
}

func TestConcurrentClaimsReturnEachReceiptOnce(t *testing.T) {
	store, _ := openTestStore(t)
	now := time.Now().UTC()
	for index := 0; index < 8; index++ {
		if err := store.InsertReceipt(context.Background(), testReceipt(fmt.Sprintf("receipt-%02d", index), now.Add(time.Duration(index)*time.Nanosecond))); err != nil {
			t.Fatal(err)
		}
	}

	var wait sync.WaitGroup
	claimed := make(chan string, 24)
	errorsFound := make(chan error, 24)
	for worker := 0; worker < 24; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			record, err := store.Claim(context.Background(), fmt.Sprintf("worker-%02d", worker), now, time.Minute)
			if err == nil {
				claimed <- record.Receipt.ID
				return
			}
			if !errors.Is(err, ErrNoWork) {
				errorsFound <- err
			}
		}(worker)
	}
	wait.Wait()
	close(claimed)
	close(errorsFound)
	for err := range errorsFound {
		t.Errorf("Claim() unexpected error = %v", err)
	}
	seen := make(map[string]struct{})
	for receiptID := range claimed {
		if _, exists := seen[receiptID]; exists {
			t.Errorf("receipt %s was claimed more than once", receiptID)
		}
		seen[receiptID] = struct{}{}
	}
	if len(seen) != 8 {
		t.Fatalf("claimed %d receipts, want 8", len(seen))
	}
}

func TestExpiredLeaseIsRecoveredAndAttemptIsAccounted(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	receipt := testReceipt("receipt-expiry", now)
	if err := store.InsertReceipt(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	first, err := store.Claim(ctx, "worker-a", now, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if first.Attempts != 1 {
		t.Fatalf("first attempts = %d, want 1", first.Attempts)
	}
	second, err := store.Claim(ctx, "worker-b", now.Add(2*time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if second.LeaseOwner != "worker-b" || second.Attempts != 2 || second.LastErrorCode != leaseExpiredCode {
		t.Fatalf("recovered record = %+v", second)
	}
	if err := store.RenewLease(ctx, receipt.ID, "worker-a", now.Add(2*time.Second), time.Minute); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("old owner RenewLease() error = %v, want ErrLeaseLost", err)
	}
}

func TestRecoverExpiredLeasesOnlyRecoversExpiredWork(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for index, id := range []string{"receipt-expired", "receipt-active"} {
		if err := store.InsertReceipt(ctx, testReceipt(id, now.Add(time.Duration(index)*time.Nanosecond))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Claim(ctx, "worker-expired", now, time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Claim(ctx, "worker-active", now, time.Hour); err != nil {
		t.Fatal(err)
	}
	count, err := store.RecoverExpiredLeases(ctx, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("recovered count = %d, want 1", count)
	}
	expired, err := store.GetReceipt(ctx, "receipt-expired")
	if err != nil {
		t.Fatal(err)
	}
	active, err := store.GetReceipt(ctx, "receipt-active")
	if err != nil {
		t.Fatal(err)
	}
	if expired.Receipt.State != model.StateAccepted || expired.LastErrorCode != leaseExpiredCode {
		t.Fatalf("expired record = %+v", expired)
	}
	if active.Receipt.State != model.StateProcessing || active.LeaseOwner != "worker-active" {
		t.Fatalf("active record = %+v", active)
	}
}

func TestTransitionsAndLeaseOwnershipAreStrict(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	receipt := testReceipt("receipt-transition", now)
	if err := store.InsertReceipt(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	if err := store.Transition(ctx, receipt.ID, model.StateAccepted, model.StateDelivered, ""); err == nil {
		t.Fatal("invalid state transition succeeded")
	}
	if err := store.Transition(ctx, receipt.ID, model.StateAccepted, model.StateProcessing, ""); err == nil {
		t.Fatal("processing state was entered without a lease")
	}
	if _, err := store.Claim(ctx, "worker-a", now, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := store.ReleaseLease(ctx, receipt.ID, "worker-b", model.StateAccepted, "RETRY"); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("wrong-owner ReleaseLease() error = %v, want ErrLeaseLost", err)
	}
	if err := store.ReleaseLease(ctx, receipt.ID, "worker-a", model.StateAccepted, "RETRY"); err != nil {
		t.Fatal(err)
	}
	stored, err := store.GetReceipt(ctx, receipt.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Receipt.State != model.StateAccepted || stored.LeaseOwner != "" || stored.Attempts != 1 || stored.LastErrorCode != "RETRY" {
		t.Fatalf("released record = %+v", stored)
	}
}

func TestLeaseRenewalExtendsOnlyAnActiveOwnedLease(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	receipt := testReceipt("receipt-renew", now)
	if err := store.InsertReceipt(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Claim(ctx, "worker-a", now, time.Minute); err != nil {
		t.Fatal(err)
	}
	renewedUntil := now.Add(10 * time.Second).Add(2 * time.Minute)
	if err := store.RenewLease(ctx, receipt.ID, "worker-a", now.Add(10*time.Second), 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	record, err := store.GetReceipt(ctx, receipt.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !record.LeaseUntil.Equal(renewedUntil) {
		t.Fatalf("lease until = %s, want %s", record.LeaseUntil, renewedUntil)
	}
	if err := store.RenewLease(ctx, receipt.ID, "worker-b", now.Add(20*time.Second), time.Minute); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("wrong-owner RenewLease() error = %v, want ErrLeaseLost", err)
	}
}

func TestCommitRevisionIsIdempotentByProcessingInputs(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	receipt := testReceipt("receipt-revision", now)
	if err := store.InsertReceipt(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Claim(ctx, "worker-a", now, time.Minute); err != nil {
		t.Fatal(err)
	}
	bundleDigest := strings.Repeat("b", 64)
	first := testRevision("revision-first", receipt.ID, bundleDigest, now.Add(time.Second))
	stored, created, err := store.CommitRevision(ctx, first, "worker-a")
	if err != nil {
		t.Fatal(err)
	}
	if !created || stored.ID != first.ID {
		t.Fatalf("first commit = (%s, %t), want (%s, true)", stored.ID, created, first.ID)
	}
	loaded, err := store.GetRevision(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ID != first.ID || loaded.ReceiptID != receipt.ID {
		t.Fatalf("loaded revision = %+v", loaded)
	}
	duplicate := testRevision("revision-duplicate", receipt.ID, bundleDigest, now.Add(2*time.Second))
	stored, created, err = store.CommitRevision(ctx, duplicate, "worker-a")
	if err != nil {
		t.Fatal(err)
	}
	if created || stored.ID != first.ID {
		t.Fatalf("duplicate commit = (%s, %t), want (%s, false)", stored.ID, created, first.ID)
	}
	record, err := store.GetReceipt(ctx, receipt.ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.Receipt.State != model.StateRevisionCommitted || record.LeaseOwner != "" {
		t.Fatalf("receipt after commit = %+v", record)
	}
	if err := store.Transition(ctx, receipt.ID, model.StateRevisionCommitted, model.StateDelivered, ""); err != nil {
		t.Fatalf("delivery transition failed: %v", err)
	}
}

func TestReceiptPersistsAcrossRestart(t *testing.T) {
	store, path := openTestStore(t)
	ctx := context.Background()
	receipt := testReceipt("receipt-restart", time.Now().UTC())
	if err := store.InsertReceipt(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenSQLite(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	stored, err := reopened.GetReceipt(ctx, receipt.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Receipt.ID != receipt.ID || stored.Receipt.Raw.SHA256 != receipt.Raw.SHA256 || stored.Receipt.Peer.IP != receipt.Peer.IP {
		t.Fatalf("stored receipt differs after restart: %+v", stored.Receipt)
	}
}
