package ingress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/model"
)

type memoryEvidence struct {
	mu       sync.Mutex
	values   map[string][]byte
	writeErr error
	order    *[]string
	calls    int
}

func (store *memoryEvidence) Write(ctx context.Context, receiptID string, _ time.Time, source io.Reader) (model.RawReference, error) {
	store.mu.Lock()
	store.calls++
	if store.order != nil {
		*store.order = append(*store.order, "evidence")
	}
	store.mu.Unlock()
	if store.writeErr != nil {
		return model.RawReference{}, store.writeErr
	}
	body, err := io.ReadAll(source)
	if err != nil {
		return model.RawReference{}, err
	}
	digest := sha256.Sum256(body)
	store.mu.Lock()
	if store.values == nil {
		store.values = make(map[string][]byte)
	}
	store.values[receiptID] = bytes.Clone(body)
	store.mu.Unlock()
	return model.RawReference{
		Ref:         "raw/" + receiptID + ".bin",
		SHA256:      fmt.Sprintf("%x", digest[:]),
		SizeBytes:   uint64(len(body)),
		Compression: model.CompressionNone,
		Available:   true,
	}, nil
}

func (store *memoryEvidence) count() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.values)
}

func (store *memoryEvidence) value(receiptID string) []byte {
	store.mu.Lock()
	defer store.mu.Unlock()
	return bytes.Clone(store.values[receiptID])
}

type memoryInbox struct {
	mu        sync.Mutex
	receipts  map[string]model.Receipt
	insertErr error
	order     *[]string
}

func (store *memoryInbox) InsertReceipt(_ context.Context, receipt model.Receipt) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.order != nil {
		*store.order = append(*store.order, "inbox")
	}
	if store.insertErr != nil {
		return store.insertErr
	}
	if store.receipts == nil {
		store.receipts = make(map[string]model.Receipt)
	}
	if _, exists := store.receipts[receipt.ID]; exists {
		return errors.New("duplicate receipt id")
	}
	store.receipts[receipt.ID] = receipt
	return nil
}

func (store *memoryInbox) count() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.receipts)
}

func fixedCoordinator(t *testing.T, evidence evidenceWriter, inbox inboxWriter, maximum int64) *Coordinator {
	t.Helper()
	coordinator, err := newCoordinator(
		evidence,
		inbox,
		maximum,
		newUUIDv7Generator(),
		func() time.Time { return time.Date(2026, 9, 29, 10, 20, 30, 123000000, time.UTC) },
	)
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}

func testAdmissionRequest(payload []byte) AdmissionRequest {
	return AdmissionRequest{
		Payload:         bytes.NewReader(payload),
		TenantID:        "tenant-a",
		ListenerID:      "http-8080",
		SourceProfileID: "lab-firewall-a",
	}
}

func TestAdmissionWritesEvidenceBeforeInboxAndPreservesExactBytes(t *testing.T) {
	var order []string
	evidence := &memoryEvidence{order: &order}
	inbox := &memoryInbox{order: &order}
	coordinator := fixedCoordinator(t, evidence, inbox, 1024)
	payload := []byte{0xff, 0xfe, 0x00, 'a', '\r', '\n'}

	result, err := coordinator.Admit(context.Background(), testAdmissionRequest(payload))
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(order) != "[evidence inbox]" {
		t.Fatalf("operation order = %v", order)
	}
	if !bytes.Equal(evidence.value(result.Receipt.ID), payload) {
		t.Fatalf("evidence bytes changed: %x", evidence.value(result.Receipt.ID))
	}
	if result.Receipt.State != model.StateAccepted || result.Receipt.Raw.SizeBytes != uint64(len(payload)) {
		t.Fatalf("receipt = %+v", result.Receipt)
	}
}

func TestAdmissionDoesNotAcceptOnEvidenceFailure(t *testing.T) {
	evidence := &memoryEvidence{writeErr: errors.New("disk unavailable")}
	inbox := &memoryInbox{}
	coordinator := fixedCoordinator(t, evidence, inbox, 1024)

	_, err := coordinator.Admit(context.Background(), testAdmissionRequest([]byte("event")))
	if !errors.Is(err, ErrEvidenceWrite) {
		t.Fatalf("Admit() error = %v, want ErrEvidenceWrite", err)
	}
	if inbox.count() != 0 {
		t.Fatal("inbox receipt was inserted after evidence failure")
	}
}

func TestAdmissionChecksCapacityBeforeWritingEvidence(t *testing.T) {
	evidence := &memoryEvidence{}
	inbox := &memoryInbox{}
	coordinator := fixedCoordinator(t, evidence, inbox, 1024)
	coordinator.capacity = failingCapacity{err: errors.New("high watermark")}
	_, err := coordinator.Admit(context.Background(), testAdmissionRequest([]byte("event")))
	if !errors.Is(err, ErrCapacity) {
		t.Fatalf("Admit error=%v, want ErrCapacity", err)
	}
	if evidence.calls != 0 || inbox.count() != 0 {
		t.Fatal("capacity rejection reached durable stores")
	}
}

type failingCapacity struct{ err error }

func (guard failingCapacity) Check(context.Context) error { return guard.err }

func TestAdmissionReportsOrphanWithoutAcceptanceOnInboxFailure(t *testing.T) {
	evidence := &memoryEvidence{}
	inbox := &memoryInbox{insertErr: errors.New("database unavailable")}
	coordinator := fixedCoordinator(t, evidence, inbox, 1024)

	_, err := coordinator.Admit(context.Background(), testAdmissionRequest([]byte("event")))
	if !errors.Is(err, ErrInboxWrite) {
		t.Fatalf("Admit() error = %v, want ErrInboxWrite", err)
	}
	var admissionErr *AdmissionError
	if !errors.As(err, &admissionErr) || admissionErr.Orphan == nil {
		t.Fatalf("inbox failure did not return orphan metadata: %v", err)
	}
	if evidence.count() != 1 || inbox.count() != 0 || admissionErr.Orphan.Raw.SizeBytes != 5 {
		t.Fatalf("orphan outcome is inconsistent: %+v", admissionErr.Orphan)
	}
}

func TestOversizePayloadCreatesNoDurableReceipt(t *testing.T) {
	evidence := &memoryEvidence{}
	inbox := &memoryInbox{}
	coordinator := fixedCoordinator(t, evidence, inbox, 4)

	_, err := coordinator.Admit(context.Background(), testAdmissionRequest([]byte("12345")))
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("Admit() error = %v, want ErrPayloadTooLarge", err)
	}
	if evidence.count() != 0 || inbox.count() != 0 {
		t.Fatalf("oversize event became durable: evidence=%d inbox=%d", evidence.count(), inbox.count())
	}
}

func TestCancelledAdmissionWritesNothing(t *testing.T) {
	evidence := &memoryEvidence{}
	inbox := &memoryInbox{}
	coordinator := fixedCoordinator(t, evidence, inbox, 1024)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := coordinator.Admit(ctx, testAdmissionRequest([]byte("event")))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Admit() error = %v, want context.Canceled", err)
	}
	if evidence.calls != 0 || inbox.count() != 0 {
		t.Fatal("cancelled admission reached a durable store")
	}
}

func TestConcurrentAdmissionsProduceUniqueUUIDv7OccurrenceIDs(t *testing.T) {
	evidence := &memoryEvidence{}
	inbox := &memoryInbox{}
	coordinator := fixedCoordinator(t, evidence, inbox, 1024)
	const submissions = 1000

	ids := make(chan string, submissions)
	errorsFound := make(chan error, submissions)
	var wait sync.WaitGroup
	for index := 0; index < submissions; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			request := testAdmissionRequest([]byte(fmt.Sprintf("event-%d", index)))
			result, err := coordinator.Admit(context.Background(), request)
			if err != nil {
				errorsFound <- err
				return
			}
			ids <- result.Receipt.ID
		}(index)
	}
	wait.Wait()
	close(ids)
	close(errorsFound)
	for err := range errorsFound {
		t.Errorf("Admit() error = %v", err)
	}
	seen := make(map[string]struct{}, submissions)
	for id := range ids {
		if _, exists := seen[id]; exists {
			t.Errorf("duplicate occurrence id %s", id)
		}
		seen[id] = struct{}{}
		if len(id) != 36 || id[14] != '7' || !strings.ContainsRune("89ab", rune(id[19])) {
			t.Errorf("id %q is not UUIDv7", id)
		}
	}
	if len(seen) != submissions || evidence.count() != submissions || inbox.count() != submissions {
		t.Fatalf("completed ids=%d evidence=%d inbox=%d", len(seen), evidence.count(), inbox.count())
	}
}
