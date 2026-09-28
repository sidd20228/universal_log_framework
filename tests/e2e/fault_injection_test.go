package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/auth"
	"github.com/sidd20228/universal_log_framework/internal/deliver"
	"github.com/sidd20228/universal_log_framework/internal/detect"
	"github.com/sidd20228/universal_log_framework/internal/envelope"
	"github.com/sidd20228/universal_log_framework/internal/evidence"
	"github.com/sidd20228/universal_log_framework/internal/inbox"
	"github.com/sidd20228/universal_log_framework/internal/ingress"
	"github.com/sidd20228/universal_log_framework/internal/interpret"
	jsonparser "github.com/sidd20228/universal_log_framework/internal/interpret/json"
	"github.com/sidd20228/universal_log_framework/internal/model"
	"github.com/sidd20228/universal_log_framework/internal/query"
	"github.com/sidd20228/universal_log_framework/internal/worker"
)

const (
	tenantASecret      = "tenant-a-fault-test-secret-00000001"
	tenantBSecret      = "tenant-b-fault-test-secret-00000002"
	eventsOnlyASecret  = "tenant-a-events-only-secret-00000003"
	normalRevisionID   = "0199a1f0-81b2-7680-89c3-d5c53fe8f101"
	panicRevisionID    = "0199a1f0-81b2-7680-89c3-d5c53fe8f102"
	timeoutRevisionID  = "0199a1f0-81b2-7680-89c3-d5c53fe8f103"
	corruptRevisionID  = "0199a1f0-81b2-7680-89c3-d5c53fe8f104"
	testPipeline       = "1.0.0"
	testConnectorID    = "fault-sink"
	testSourceProfile  = "fault-source"
	testListener       = "fault-http"
	testMaximumPayload = 64 * 1024
)

var validPayload = []byte(`{"event_type":"traffic","action":"blocked","src_ip":"192.0.2.10"}`)

func TestRestartConnectorDeadLetterReplayAndTenantIsolation(t *testing.T) {
	ctx := context.Background()
	fixture := newDurableFixture(t)
	result := fixture.admit(t, "tenant-a", validPayload)

	// Simulate a process dying after it claimed durable work and before it
	// committed a revision. Reopening the same database is the restart boundary.
	old := time.Now().UTC().Add(-2 * time.Hour)
	claimed, err := fixture.queue.Claim(ctx, "killed-worker", old, time.Minute)
	if err != nil || claimed.Receipt.ID != result.Receipt.ID {
		t.Fatalf("pre-restart claim = %+v, %v", claimed, err)
	}
	fixture.restart(t)

	processor := newWorker(t, fixture.queue, fixture.raw, jsonparser.New(), normalRevisionID, time.Second, 2)
	step, err := processor.RunOnce(ctx)
	if err != nil || step.Outcome != worker.OutcomeCommitted {
		t.Fatalf("worker after restart = %+v, %v", step, err)
	}
	record, err := fixture.queue.GetReceipt(ctx, result.Receipt.ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.Attempts != 2 || record.Receipt.State != model.StateRevisionCommitted {
		t.Fatalf("recovered receipt = %+v", record)
	}
	revisions, err := fixture.queue.ListRevisions(ctx, result.Receipt.ID)
	if err != nil || len(revisions) != 1 {
		t.Fatalf("revisions after restart = %+v, %v", revisions, err)
	}
	stored, err := fixture.queue.GetEnvelope(ctx, step.RevisionID)
	if err != nil {
		t.Fatal(err)
	}

	index := newMemoryIndex()
	connector := &scriptedConnector{
		index: index,
		statuses: []deliver.DeliveryStatus{
			deliver.DeliveryRetryable,
			deliver.DeliveryRetryable,
			deliver.DeliverySucceeded,
		},
	}
	deliveryPath := filepath.Join(fixture.root, "delivery.sqlite")
	deliveryStore, err := deliver.OpenSQLiteState(ctx, deliveryPath)
	if err != nil {
		t.Fatal(err)
	}
	coordinator := newDeliveryCoordinator(t, deliveryStore)
	recordForDelivery := exportRecord(t, stored)
	base := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	if err := coordinator.Enqueue(ctx, connector, []deliver.ExportRecord{recordForDelivery}, base); err != nil {
		t.Fatal(err)
	}
	if count, err := coordinator.RunOnce(ctx, connector, base); err != nil || count != 1 {
		t.Fatalf("first unavailable delivery = %d, %v", count, err)
	}
	if err := deliveryStore.Close(); err != nil {
		t.Fatal(err)
	}

	// The retry survives a delivery-state restart, then exhausts into the DLQ.
	deliveryStore, err = deliver.OpenSQLiteState(ctx, deliveryPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = deliveryStore.Close() })
	coordinator = newDeliveryCoordinator(t, deliveryStore)
	if count, err := coordinator.RunOnce(ctx, connector, base.Add(2*time.Millisecond)); err != nil || count != 1 {
		t.Fatalf("second unavailable delivery = %d, %v", count, err)
	}
	dead, err := deliveryStore.Get(ctx, testConnectorID, step.RevisionID)
	if err != nil {
		t.Fatal(err)
	}
	if dead.State != deliver.StateDeadLetter || dead.Attempts != 2 || dead.LastCode != "RETRY_EXHAUSTED" {
		t.Fatalf("delivery after exhaustion = %+v", dead)
	}
	if index.count() != 0 {
		t.Fatal("failed deliveries became query-visible")
	}

	if err := deliveryStore.Replay(ctx, testConnectorID, step.RevisionID, base.Add(3*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if count, err := coordinator.RunOnce(ctx, connector, base.Add(3*time.Millisecond)); err != nil || count != 1 {
		t.Fatalf("delivery after explicit replay = %d, %v", count, err)
	}
	delivered, err := deliveryStore.Get(ctx, testConnectorID, step.RevisionID)
	if err != nil {
		t.Fatal(err)
	}
	if delivered.State != deliver.StateDelivered || delivered.Attempts != 1 {
		t.Fatalf("replayed delivery = %+v", delivered)
	}

	handler := newQueryHandler(t, fixture.queue, index, fixture.raw)
	response := queryRequest(t, handler, tenantASecret, "/api/v1/events/"+step.RevisionID)
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(step.RevisionID)) {
		t.Fatalf("event after replay: status=%d body=%s", response.Code, response.Body.String())
	}
	response = queryRequest(t, handler, tenantASecret, "/api/v1/receipts/"+result.Receipt.ID+"/raw")
	if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), validPayload) {
		t.Fatalf("raw after restarts: status=%d body=%q", response.Code, response.Body.Bytes())
	}
	if response.Header().Get("X-Content-SHA256") != result.Receipt.Raw.SHA256 {
		t.Fatalf("raw hash header = %q", response.Header().Get("X-Content-SHA256"))
	}

	for _, target := range []string{
		"/api/v1/events/" + step.RevisionID,
		"/api/v1/receipts/" + result.Receipt.ID + "/raw",
	} {
		response = queryRequest(t, handler, tenantBSecret, target)
		if response.Code != http.StatusNotFound || bytes.Contains(response.Body.Bytes(), []byte("tenant-a")) {
			t.Fatalf("cross-tenant query %s: status=%d body=%s", target, response.Code, response.Body.String())
		}
	}
}

func TestParserFaultsRemainDurableAndInvisibleToEventQueries(t *testing.T) {
	tests := []struct {
		name       string
		parser     interpret.SyntaxParser
		revisionID string
		timeout    time.Duration
		wantCode   string
		release    func()
	}{
		{name: "panic", parser: panicParser{}, revisionID: panicRevisionID, timeout: time.Second, wantCode: worker.CodePanic},
	}
	release := make(chan struct{})
	tests = append(tests, struct {
		name       string
		parser     interpret.SyntaxParser
		revisionID string
		timeout    time.Duration
		wantCode   string
		release    func()
	}{name: "timeout", parser: blockingParser{release: release}, revisionID: timeoutRevisionID, timeout: 20 * time.Millisecond, wantCode: worker.CodeTimeout, release: func() { close(release) }})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDurableFixture(t)
			admitted := fixture.admit(t, "tenant-a", validPayload)
			processor := newWorker(t, fixture.queue, fixture.raw, test.parser, test.revisionID, test.timeout, 1)
			step, err := processor.RunOnce(context.Background())
			if err != nil || step.Outcome != worker.OutcomeDeadLetter || step.ErrorCode != test.wantCode {
				t.Fatalf("fault outcome = %+v, %v", step, err)
			}
			if test.release != nil {
				test.release()
				waitForWorkerSlot(t, processor)
			}
			record, err := fixture.queue.GetReceipt(context.Background(), admitted.Receipt.ID)
			if err != nil {
				t.Fatal(err)
			}
			if record.Receipt.State != model.StateDeadLetter || record.Attempts != 1 || record.LastErrorCode != test.wantCode {
				t.Fatalf("durable fault state = %+v", record)
			}
			stored, err := fixture.queue.GetEnvelope(context.Background(), step.RevisionID)
			if err != nil {
				t.Fatal(err)
			}
			if stored.Processing.Status != model.StatusError || len(stored.Processing.Issues) != 1 || stored.Processing.Issues[0].Code != test.wantCode {
				t.Fatalf("error envelope = %+v", stored.Processing)
			}
			if err := fixture.raw.Verify(context.Background(), admitted.Receipt.Raw); err != nil {
				t.Fatalf("fault changed raw evidence: %v", err)
			}

			handler := newQueryHandler(t, fixture.queue, newMemoryIndex(), fixture.raw)
			response := queryRequest(t, handler, tenantASecret, "/api/v1/receipts/"+admitted.Receipt.ID+"/raw")
			if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), validPayload) {
				t.Fatalf("durable raw after fault: status=%d body=%q", response.Code, response.Body.Bytes())
			}
			response = queryRequest(t, handler, eventsOnlyASecret, "/api/v1/receipts/"+admitted.Receipt.ID+"/raw")
			if response.Code != http.StatusForbidden {
				t.Fatalf("raw without raw scope: status=%d body=%s", response.Code, response.Body.String())
			}
			response = queryRequest(t, handler, tenantASecret, "/api/v1/events/"+step.RevisionID)
			if response.Code != http.StatusNotFound {
				t.Fatalf("undelivered error became event-visible: status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestCorruptRawEvidenceStopsBeforeParserAndExport(t *testing.T) {
	fixture := newDurableFixture(t)
	admitted := fixture.admit(t, "tenant-a", validPayload)
	corrupted := []byte("attacker-controlled replacement")
	path := filepath.Join(fixture.rawRoot, filepath.FromSlash(admitted.Receipt.Raw.Ref))
	if err := os.WriteFile(path, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	parser := &countingParser{delegate: jsonparser.New()}
	processor := newWorker(t, fixture.queue, fixture.raw, parser, corruptRevisionID, time.Second, 3)
	step, err := processor.RunOnce(context.Background())
	if err != nil || step.Outcome != worker.OutcomeDeadLetter || step.ErrorCode != worker.CodeEvidenceIntegrity {
		t.Fatalf("corrupt evidence outcome = %+v, %v", step, err)
	}
	if parser.calls.Load() != 0 {
		t.Fatalf("parser called %d times for corrupt evidence", parser.calls.Load())
	}
	if err := fixture.raw.Verify(context.Background(), admitted.Receipt.Raw); !errors.Is(err, evidence.ErrIntegrity) {
		t.Fatalf("Verify() error = %v, want integrity failure", err)
	}
	record, err := fixture.queue.GetReceipt(context.Background(), admitted.Receipt.ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.Receipt.State != model.StateDeadLetter || record.Attempts != 1 {
		t.Fatalf("corrupt receipt state = %+v", record)
	}
	stored, err := fixture.queue.GetEnvelope(context.Background(), step.RevisionID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Processing.Status != model.StatusError || stored.Processing.Issues[0].Code != worker.CodeEvidenceIntegrity {
		t.Fatalf("corrupt evidence envelope = %+v", stored.Processing)
	}

	index := newMemoryIndex()
	handler := newQueryHandler(t, fixture.queue, index, fixture.raw)
	response := queryRequest(t, handler, tenantASecret, "/api/v1/receipts/"+admitted.Receipt.ID+"/raw")
	if response.Code != http.StatusInternalServerError || !bytes.Contains(response.Body.Bytes(), []byte(`"code":"RAW_INTEGRITY_FAILED"`)) {
		t.Fatalf("corrupt raw response: status=%d body=%s", response.Code, response.Body.String())
	}
	if bytes.Contains(response.Body.Bytes(), corrupted) || bytes.Contains(response.Body.Bytes(), []byte(path)) {
		t.Fatalf("corrupt raw response leaked evidence or storage path: %s", response.Body.String())
	}
	if response.Header().Get("X-Request-ID") == "" || index.count() != 0 {
		t.Fatalf("request id=%q indexed=%d", response.Header().Get("X-Request-ID"), index.count())
	}
}

type durableFixture struct {
	root     string
	rawRoot  string
	inboxDB  string
	raw      *evidence.Filesystem
	queue    *inbox.SQLiteStore
	queueUp  bool
	admitter ingress.Admission
}

func newDurableFixture(t *testing.T) *durableFixture {
	t.Helper()
	root := t.TempDir()
	rawRoot := filepath.Join(root, "raw")
	raw, err := evidence.NewFilesystem(rawRoot)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &durableFixture{root: root, rawRoot: rawRoot, inboxDB: filepath.Join(root, "inbox.sqlite"), raw: raw}
	fixture.reopenQueue(t)
	t.Cleanup(func() {
		if fixture.queueUp {
			_ = fixture.queue.Close()
		}
	})
	return fixture
}

func (fixture *durableFixture) reopenQueue(t *testing.T) {
	t.Helper()
	queue, err := inbox.OpenSQLite(context.Background(), fixture.inboxDB)
	if err != nil {
		t.Fatal(err)
	}
	admitter, err := ingress.NewCoordinator(fixture.raw, queue, testMaximumPayload)
	if err != nil {
		_ = queue.Close()
		t.Fatal(err)
	}
	fixture.queue = queue
	fixture.queueUp = true
	fixture.admitter = admitter
}

func (fixture *durableFixture) closeQueue(t *testing.T) {
	t.Helper()
	if err := fixture.queue.Close(); err != nil {
		t.Fatal(err)
	}
	fixture.queueUp = false
}

func (fixture *durableFixture) restart(t *testing.T) {
	t.Helper()
	fixture.closeQueue(t)
	raw, err := evidence.NewFilesystem(fixture.rawRoot)
	if err != nil {
		t.Fatal(err)
	}
	fixture.raw = raw
	fixture.reopenQueue(t)
}

func (fixture *durableFixture) admit(t *testing.T, tenant string, payload []byte) ingress.AdmissionResult {
	t.Helper()
	result, err := fixture.admitter.Admit(context.Background(), ingress.AdmissionRequest{
		Payload: bytes.NewReader(payload), TenantID: tenant, ListenerID: testListener,
		SourceProfileID: testSourceProfile, Transport: model.TransportHTTP, FramingMode: model.FramingHTTPOctets,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func newWorker(t *testing.T, queue worker.Inbox, raw worker.Evidence, parser interpret.SyntaxParser, revisionID string, timeout time.Duration, maxAttempts int) *worker.Worker {
	t.Helper()
	detector, err := detect.NewDefault()
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := worker.NewStaticResolver([]worker.Pipeline{{Parser: parser}})
	if err != nil {
		t.Fatal(err)
	}
	processor, err := worker.New(worker.Config{
		Owner: "fault-worker", PipelineVersion: testPipeline, LeaseDuration: time.Second,
		RenewInterval: 100 * time.Millisecond, ProcessingTimeout: timeout, MaxAttempts: maxAttempts,
		RevisionID: func(time.Time) (string, error) { return revisionID, nil },
	}, queue, raw, detector, resolver)
	if err != nil {
		t.Fatal(err)
	}
	return processor
}

func newDeliveryCoordinator(t *testing.T, store deliver.StateStore) *deliver.Coordinator {
	t.Helper()
	coordinator, err := deliver.NewCoordinator(store, deliver.CoordinatorConfig{
		Owner: "fault-delivery", LeaseDuration: time.Second, BatchSize: 10, MaxAttempts: 2,
		BaseBackoff: time.Millisecond, MaxBackoff: 10 * time.Millisecond,
		CircuitFailures: 10, CircuitCooldown: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}

func exportRecord(t *testing.T, value envelope.Envelope) deliver.ExportRecord {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	issues := make([]string, len(value.Processing.Issues))
	for index := range value.Processing.Issues {
		issues[index] = value.Processing.Issues[index].Code
	}
	result := deliver.ExportRecord{
		ReceiptID: value.Receipt.ID, RevisionID: value.Processing.RevisionID, TenantID: value.Receipt.TenantID,
		ReceivedAt: value.Receipt.ReceivedAt, SourceProfile: value.Receipt.SourceProfileID,
		Status: string(value.Processing.Status), SchemaVersion: value.SchemaVersion,
		RawSHA256: value.Raw.SHA256, QualityScore: float32(value.Quality.Score), IssueCodes: issues, EnvelopeJSON: body,
	}
	if value.Processing.Parser != nil {
		result.ParserID = value.Processing.Parser.ID
		result.ParserVersion = value.Processing.Parser.Version
	}
	if action, ok := value.Event["action"].(string); ok {
		result.Action = action
	}
	return result
}

type scriptedConnector struct {
	mu       sync.Mutex
	statuses []deliver.DeliveryStatus
	calls    int
	index    *memoryIndex
}

func (*scriptedConnector) Descriptor() deliver.ConnectorDescriptor {
	return deliver.ConnectorDescriptor{ID: testConnectorID, Kind: "fault", Version: "1.0.0"}
}

func (connector *scriptedConnector) Health(context.Context) deliver.Health {
	return deliver.Health{Healthy: true}
}

func (connector *scriptedConnector) Deliver(_ context.Context, records []deliver.ExportRecord) deliver.BatchResult {
	connector.mu.Lock()
	defer connector.mu.Unlock()
	status := deliver.DeliverySucceeded
	if connector.calls < len(connector.statuses) {
		status = connector.statuses[connector.calls]
	}
	connector.calls++
	results := make([]deliver.RecordResult, len(records))
	for index, record := range records {
		results[index] = deliver.RecordResult{RevisionID: record.RevisionID, Status: status}
		if status == deliver.DeliveryRetryable {
			results[index].Code = "SINK_UNAVAILABLE"
			results[index].Message = "synthetic connector outage"
			continue
		}
		if status == deliver.DeliverySucceeded {
			connector.index.add(record)
		}
	}
	return deliver.BatchResult{Records: results}
}

type memoryIndex struct {
	mu        sync.RWMutex
	summaries []query.EventSummary
	events    map[string]envelope.Envelope
}

func newMemoryIndex() *memoryIndex { return &memoryIndex{events: make(map[string]envelope.Envelope)} }

func (index *memoryIndex) add(record deliver.ExportRecord) {
	var value envelope.Envelope
	if err := json.Unmarshal(record.EnvelopeJSON, &value); err != nil {
		return
	}
	index.mu.Lock()
	defer index.mu.Unlock()
	key := record.TenantID + "/" + record.RevisionID
	if _, exists := index.events[key]; exists {
		return
	}
	index.events[key] = value
	index.summaries = append(index.summaries, query.EventSummary{
		ReceiptID: record.ReceiptID, RevisionID: record.RevisionID, TenantID: record.TenantID,
		ReceivedAt: record.ReceivedAt, SourceProfileID: record.SourceProfile,
		Status: value.Processing.Status, RawSHA256: record.RawSHA256, QualityScore: record.QualityScore,
	})
}

func (index *memoryIndex) count() int {
	index.mu.RLock()
	defer index.mu.RUnlock()
	return len(index.events)
}

func (index *memoryIndex) GetEvent(_ context.Context, tenantID, revisionID string) (envelope.Envelope, error) {
	index.mu.RLock()
	defer index.mu.RUnlock()
	value, found := index.events[tenantID+"/"+revisionID]
	if !found {
		return envelope.Envelope{}, query.ErrNotFound
	}
	return value, nil
}

func (index *memoryIndex) ListEvents(_ context.Context, request query.EventQuery) (query.EventPage, error) {
	index.mu.RLock()
	defer index.mu.RUnlock()
	items := make([]query.EventSummary, 0, len(index.summaries))
	for _, item := range index.summaries {
		if item.TenantID == request.TenantID {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(left, right int) bool {
		if !items[left].ReceivedAt.Equal(items[right].ReceivedAt) {
			return items[left].ReceivedAt.Before(items[right].ReceivedAt)
		}
		return items[left].RevisionID < items[right].RevisionID
	})
	if len(items) > request.Limit {
		items = items[:request.Limit]
	}
	return query.EventPage{Items: items}, nil
}

func newQueryHandler(t *testing.T, receipts query.ReceiptReader, events query.EventReader, raw query.EvidenceReader) http.Handler {
	t.Helper()
	authorizer, err := auth.New([]auth.TokenConfig{
		{ID: "tenant-a-all", Secret: tenantASecret, Actor: "fault-reader-a", Scopes: []auth.Scope{auth.ScopeEventsRead, auth.ScopeRawRead}, Tenants: []string{"tenant-a"}},
		{ID: "tenant-b-all", Secret: tenantBSecret, Actor: "fault-reader-b", Scopes: []auth.Scope{auth.ScopeEventsRead, auth.ScopeRawRead}, Tenants: []string{"tenant-b"}},
		{ID: "tenant-a-events", Secret: eventsOnlyASecret, Actor: "fault-events-a", Scopes: []auth.Scope{auth.ScopeEventsRead}, Tenants: []string{"tenant-a"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := query.NewHTTPHandler(authorizer, receipts, events, raw)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func queryRequest(t *testing.T, handler http.Handler, secret, path string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("Authorization", "Bearer "+secret)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func waitForWorkerSlot(t *testing.T, processor *worker.Worker) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		step, err := processor.RunOnce(context.Background())
		if err == nil {
			if step.Outcome != worker.OutcomeNoWork {
				t.Fatalf("post-timeout worker step = %+v", step)
			}
			return
		}
		if !errors.Is(err, worker.ErrBusy) {
			t.Fatalf("post-timeout worker error = %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for bounded worker slot")
		}
		time.Sleep(time.Millisecond)
	}
}

type panicParser struct{}

func (panicParser) Descriptor() interpret.ParserDescriptor {
	return jsonparser.New().Descriptor()
}

func (panicParser) Parse(context.Context, interpret.Payload, interpret.Limits) interpret.ParseResult {
	panic("synthetic parser fault")
}

type blockingParser struct{ release <-chan struct{} }

func (blockingParser) Descriptor() interpret.ParserDescriptor {
	return jsonparser.New().Descriptor()
}

func (parser blockingParser) Parse(context.Context, interpret.Payload, interpret.Limits) interpret.ParseResult {
	<-parser.release
	return interpret.ParseResult{Status: interpret.StatusInvalid, Document: interpret.ParsedDocument{Format: "json"}, Issues: []interpret.Issue{{Code: "SYNTHETIC_RELEASE", Severity: interpret.SeverityError, Message: "released"}}}
}

type countingParser struct {
	delegate interpret.SyntaxParser
	calls    atomic.Int32
}

func (parser *countingParser) Descriptor() interpret.ParserDescriptor {
	return parser.delegate.Descriptor()
}

func (parser *countingParser) Parse(ctx context.Context, payload interpret.Payload, limits interpret.Limits) interpret.ParseResult {
	parser.calls.Add(1)
	return parser.delegate.Parse(ctx, payload, limits)
}
