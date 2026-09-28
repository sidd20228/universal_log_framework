package worker_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/detect"
	"github.com/sidd20228/universal_log_framework/internal/evidence"
	"github.com/sidd20228/universal_log_framework/internal/inbox"
	"github.com/sidd20228/universal_log_framework/internal/interpret"
	jsonparser "github.com/sidd20228/universal_log_framework/internal/interpret/json"
	"github.com/sidd20228/universal_log_framework/internal/interpret/mapping"
	"github.com/sidd20228/universal_log_framework/internal/model"
	"github.com/sidd20228/universal_log_framework/internal/worker"
)

func TestWorkerEndToEndCommitsImmutableEnvelope(t *testing.T) {
	fixture := readFixture(t, "json_firewall.json")
	queue, evidenceStore, receipt := setupDurableReceipt(t, fixture)
	processor := newJSONWorker(t, queue, evidenceStore, worker.Config{
		Owner: "worker-a", PipelineVersion: "0.1.0", LeaseDuration: time.Second,
		RenewInterval: 100 * time.Millisecond, ProcessingTimeout: time.Second, MaxAttempts: 3,
		RevisionID: fixedRevisionIDs("0199a1f0-81b2-7680-89c3-d5c53fe8e101"),
	})

	step, err := processor.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if step.Outcome != worker.OutcomeCommitted || step.ReceiptID != receipt.ID || step.RevisionID == "" || !step.Created {
		t.Fatalf("step = %+v", step)
	}
	record, err := queue.GetReceipt(context.Background(), receipt.ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.Receipt.State != model.StateRevisionCommitted || record.Attempts != 1 || record.LeaseOwner != "" {
		t.Fatalf("record = %+v", record)
	}
	revision, err := queue.GetRevision(context.Background(), step.RevisionID)
	if err != nil {
		t.Fatal(err)
	}
	if revision.Status != model.StatusParsed || revision.MappingVersion != "worker-json/1.0.0" || revision.Parser == nil || revision.Parser.ID != "generic-json" {
		t.Fatalf("revision = %+v", revision)
	}
	storedEnvelope, err := queue.GetEnvelope(context.Background(), step.RevisionID)
	if err != nil {
		t.Fatal(err)
	}
	if storedEnvelope.Event["action"] != "allow" || storedEnvelope.Quality.Score != 1 || len(storedEnvelope.Provenance) != 10 {
		t.Fatalf("envelope = %+v", storedEnvelope)
	}
	if storedEnvelope.Receipt.ID != receipt.ID || storedEnvelope.Raw.SHA256 != receipt.Raw.SHA256 {
		t.Fatalf("traceability lost: %+v", storedEnvelope)
	}
	if err := evidenceStore.Verify(context.Background(), receipt.Raw); err != nil {
		t.Fatalf("raw evidence changed: %v", err)
	}
}

func TestWorkerRestartReclaimsExpiredLeaseWithoutDuplicatingOccurrence(t *testing.T) {
	fixture := readFixture(t, "json_firewall.json")
	databasePath := filepath.Join(t.TempDir(), "inbox.sqlite")
	queue, err := inbox.OpenSQLite(context.Background(), databasePath)
	if err != nil {
		t.Fatal(err)
	}
	evidenceStore, err := evidence.NewFilesystem(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	receipt := insertReceipt(t, queue, evidenceStore, fixture, "0199a1f0-7c4a-7b2c-8e25-8b4627a1c102")
	past := time.Now().UTC().Add(-time.Hour)
	claimed, err := queue.Claim(context.Background(), "killed-worker", past, time.Minute)
	if err != nil || claimed.Receipt.ID != receipt.ID {
		t.Fatalf("initial claim = %+v, %v", claimed, err)
	}
	if err := queue.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := inbox.OpenSQLite(context.Background(), databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	processor := newJSONWorker(t, reopened, evidenceStore, worker.Config{
		Owner: "restart-worker", PipelineVersion: "0.1.0", LeaseDuration: time.Second,
		RenewInterval: 100 * time.Millisecond, ProcessingTimeout: time.Second, MaxAttempts: 3,
		RevisionID: fixedRevisionIDs("0199a1f0-81b2-7680-89c3-d5c53fe8e102"),
	})
	step, err := processor.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if step.Outcome != worker.OutcomeCommitted {
		t.Fatalf("step = %+v", step)
	}
	record, err := reopened.GetReceipt(context.Background(), receipt.ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.Attempts != 2 || record.LastErrorCode != "" || record.Receipt.State != model.StateRevisionCommitted {
		t.Fatalf("recovered record = %+v", record)
	}
	revisions, err := reopened.ListRevisions(context.Background(), receipt.ID)
	if err != nil || len(revisions) != 1 {
		t.Fatalf("revisions = %+v, %v", revisions, err)
	}
	reader, err := evidenceStore.Open(context.Background(), receipt.Raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if err != nil || reader.Close() != nil || !bytes.Equal(got, fixture) {
		t.Fatalf("raw after restart = %q, %v", got, err)
	}
}

func TestWorkerRenewsLeaseDuringLongParse(t *testing.T) {
	queue, evidenceStore, _ := setupDurableReceipt(t, readFixture(t, "json_firewall.json"))
	mapper := newFirewallMapper(t)
	resolver, err := worker.NewStaticResolver([]worker.Pipeline{{
		Parser: delayedParser{delay: 180 * time.Millisecond, delegate: jsonparser.New()}, Mapper: mapper,
	}})
	if err != nil {
		t.Fatal(err)
	}
	detector, err := detect.NewDefault()
	if err != nil {
		t.Fatal(err)
	}
	processor, err := worker.New(worker.Config{
		Owner: "renew-worker", PipelineVersion: "0.1.0", LeaseDuration: 70 * time.Millisecond,
		RenewInterval: 15 * time.Millisecond, ProcessingTimeout: time.Second, MaxAttempts: 2,
		RevisionID: fixedRevisionIDs("0199a1f0-81b2-7680-89c3-d5c53fe8e103"),
	}, queue, evidenceStore, detector, resolver)
	if err != nil {
		t.Fatal(err)
	}
	step, err := processor.RunOnce(context.Background())
	if err != nil || step.Outcome != worker.OutcomeCommitted {
		t.Fatalf("RunOnce() = %+v, %v", step, err)
	}
}

func TestWorkerRetriesPanicThenCommitsErrorToDeadLetter(t *testing.T) {
	queue, evidenceStore, receipt := setupDurableReceipt(t, readFixture(t, "json_firewall.json"))
	resolver, err := worker.NewStaticResolver([]worker.Pipeline{{Parser: panicParser{}}})
	if err != nil {
		t.Fatal(err)
	}
	detector, err := detect.NewDefault()
	if err != nil {
		t.Fatal(err)
	}
	var ids atomic.Int32
	processor, err := worker.New(worker.Config{
		Owner: "panic-worker", PipelineVersion: "0.1.0", LeaseDuration: time.Second,
		RenewInterval: 100 * time.Millisecond, ProcessingTimeout: time.Second, MaxAttempts: 2,
		RevisionID: func(time.Time) (string, error) {
			if ids.Add(1) == 1 {
				return "0199a1f0-81b2-7680-89c3-d5c53fe8e104", nil
			}
			return "0199a1f0-81b2-7680-89c3-d5c53fe8e105", nil
		},
	}, queue, evidenceStore, detector, resolver)
	if err != nil {
		t.Fatal(err)
	}

	first, err := processor.RunOnce(context.Background())
	if err != nil || first.Outcome != worker.OutcomeRetry || first.ErrorCode != worker.CodePanic {
		t.Fatalf("first attempt = %+v, %v", first, err)
	}
	retrying, err := queue.GetReceipt(context.Background(), receipt.ID)
	if err != nil || retrying.Receipt.State != model.StateAccepted || retrying.LastErrorCode != worker.CodePanic {
		t.Fatalf("retry state = %+v, %v", retrying, err)
	}
	second, err := processor.RunOnce(context.Background())
	if err != nil || second.Outcome != worker.OutcomeDeadLetter || second.ErrorCode != worker.CodePanic {
		t.Fatalf("second attempt = %+v, %v", second, err)
	}
	if strings.Contains(second.ErrorMessage, "secret") || strings.ContainsAny(second.ErrorMessage, "\r\n\t") {
		t.Fatalf("panic content leaked through public failure: %q", second.ErrorMessage)
	}
	failed, err := queue.GetReceipt(context.Background(), receipt.ID)
	if err != nil || failed.Receipt.State != model.StateDeadLetter || failed.LastErrorCode != worker.CodePanic || failed.Attempts != 2 {
		t.Fatalf("dead letter state = %+v, %v", failed, err)
	}
	revision, err := queue.GetRevision(context.Background(), second.RevisionID)
	if err != nil || revision.Status != model.StatusError || len(revision.Issues) != 1 || revision.Issues[0].Code != worker.CodePanic {
		t.Fatalf("error revision = %+v, %v", revision, err)
	}
	storedEnvelope, err := queue.GetEnvelope(context.Background(), second.RevisionID)
	if err != nil || storedEnvelope.Event != nil || storedEnvelope.Processing.Status != model.StatusError {
		t.Fatalf("error envelope = %+v, %v", storedEnvelope, err)
	}
}

func TestWorkerBoundsIgnoredCancellation(t *testing.T) {
	queue, evidenceStore, _ := setupDurableReceipt(t, readFixture(t, "json_firewall.json"))
	blocked := make(chan struct{})
	resolver, err := worker.NewStaticResolver([]worker.Pipeline{{Parser: blockingParser{release: blocked}}})
	if err != nil {
		t.Fatal(err)
	}
	detector, err := detect.NewDefault()
	if err != nil {
		t.Fatal(err)
	}
	processor, err := worker.New(worker.Config{
		Owner: "timeout-worker", PipelineVersion: "0.1.0", LeaseDuration: time.Second,
		RenewInterval: 100 * time.Millisecond, ProcessingTimeout: 30 * time.Millisecond, MaxAttempts: 2,
		RevisionID: fixedRevisionIDs("0199a1f0-81b2-7680-89c3-d5c53fe8e106"),
	}, queue, evidenceStore, detector, resolver)
	if err != nil {
		t.Fatal(err)
	}
	first, err := processor.RunOnce(context.Background())
	if err != nil || first.Outcome != worker.OutcomeRetry || first.ErrorCode != worker.CodeTimeout {
		t.Fatalf("timeout attempt = %+v, %v", first, err)
	}
	if _, err := processor.RunOnce(context.Background()); !errors.Is(err, worker.ErrBusy) {
		t.Fatalf("second RunOnce() error = %v, want ErrBusy", err)
	}
	close(blocked)
	deadline := time.Now().Add(time.Second)
	for {
		_, err = processor.RunOnce(context.Background())
		if !errors.Is(err, worker.ErrBusy) || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err != nil {
		t.Fatalf("worker did not release bounded slot: %v", err)
	}
}

func newJSONWorker(t *testing.T, queue worker.Inbox, evidenceStore worker.Evidence, config worker.Config) *worker.Worker {
	t.Helper()
	detector, err := detect.NewDefault()
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := worker.NewStaticResolver([]worker.Pipeline{{Parser: jsonparser.New(), Mapper: newFirewallMapper(t)}})
	if err != nil {
		t.Fatal(err)
	}
	processor, err := worker.New(config, queue, evidenceStore, detector, resolver)
	if err != nil {
		t.Fatal(err)
	}
	return processor
}

func newFirewallMapper(t *testing.T) *mapping.Engine {
	t.Helper()
	config := mapping.Config{
		ConfigVersion: mapping.ConfigVersion, ID: "worker-json", Version: "1.0.0",
		Rules: []mapping.Rule{
			{ID: "class-uid", From: "fields.event_type", To: "event.class_uid", Convert: mapping.ConvertLowercase, Lookup: "class-uid", Required: true},
			{ID: "class-name", From: "fields.event_type", To: "event.class_name", Convert: mapping.ConvertLowercase, Lookup: "class-name", Required: true},
			{ID: "activity", From: "fields.event_type", To: "event.activity", Convert: mapping.ConvertLowercase, Lookup: "activity", Required: true},
			{ID: "time", From: "fields.timestamp", To: "event.time", Convert: mapping.ConvertTimestamp, TimestampLayouts: []string{"RFC3339Nano"}},
			{ID: "source-ip", From: "fields.src_ip", To: "event.src_endpoint.ip", Convert: mapping.ConvertIP, Required: true},
			{ID: "source-port", From: "fields.src_port", To: "event.src_endpoint.port", Convert: mapping.ConvertPort},
			{ID: "destination-ip", From: "fields.dst_ip", To: "event.dst_endpoint.ip", Convert: mapping.ConvertIP, Required: true},
			{ID: "destination-port", From: "fields.dst_port", To: "event.dst_endpoint.port", Convert: mapping.ConvertPort},
			{ID: "protocol", From: "fields.protocol", To: "event.connection_info.protocol_name", Convert: mapping.ConvertLowercase},
			{ID: "action", From: "fields.action", To: "event.action", Convert: mapping.ConvertLowercase, Lookup: "action", Required: true},
		},
		Taxonomies: map[string]map[string][]string{
			"class-uid":  {"4001": {"traffic"}},
			"class-name": {"Network Activity": {"traffic"}},
			"activity":   {"Traffic": {"traffic"}},
			"action":     {"allow": {"allow", "permit"}, "deny": {"deny", "blocked"}},
		},
	}
	mapper, err := mapping.New(config)
	if err != nil {
		t.Fatal(err)
	}
	return mapper
}

func setupDurableReceipt(t *testing.T, payload []byte) (*inbox.SQLiteStore, *evidence.Filesystem, model.Receipt) {
	t.Helper()
	queue, err := inbox.OpenSQLite(context.Background(), filepath.Join(t.TempDir(), "inbox.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { queue.Close() })
	evidenceStore, err := evidence.NewFilesystem(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	receipt := insertReceipt(t, queue, evidenceStore, payload, "0199a1f0-7c4a-7b2c-8e25-8b4627a1c101")
	return queue, evidenceStore, receipt
}

func insertReceipt(t *testing.T, queue *inbox.SQLiteStore, store *evidence.Filesystem, payload []byte, receiptID string) model.Receipt {
	t.Helper()
	received := time.Now().UTC().Add(-time.Second)
	raw, err := store.Write(context.Background(), receiptID, received, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	receipt := model.Receipt{
		ID: receiptID, TenantID: "demo", ReceivedAt: received, ListenerID: "test-listener",
		Transport: model.TransportHTTP, Peer: &model.Peer{IP: netip.MustParseAddr("192.0.2.1"), Port: 1234},
		Framing: model.Framing{Mode: model.FramingHTTPOctets, Complete: true, ObservedBytes: uint64(len(payload))},
		Raw:     raw, State: model.StateAccepted,
	}
	if err := queue.InsertReceipt(context.Background(), receipt); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "corpus", "raw", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func fixedRevisionIDs(ids ...string) worker.RevisionIDGenerator {
	var index atomic.Int32
	return func(time.Time) (string, error) {
		position := int(index.Add(1)) - 1
		if position >= len(ids) {
			return ids[len(ids)-1], nil
		}
		return ids[position], nil
	}
}

type delayedParser struct {
	delay    time.Duration
	delegate interpret.SyntaxParser
}

func (parser delayedParser) Descriptor() interpret.ParserDescriptor {
	return parser.delegate.Descriptor()
}
func (parser delayedParser) Parse(ctx context.Context, payload interpret.Payload, limits interpret.Limits) interpret.ParseResult {
	select {
	case <-ctx.Done():
		return interpret.ParseResult{Status: interpret.StatusInvalid, Document: interpret.ParsedDocument{Format: "json"}, Issues: []interpret.Issue{{Code: "TEST_CANCELLED", Severity: interpret.SeverityError, Message: ctx.Err().Error()}}}
	case <-time.After(parser.delay):
		return parser.delegate.Parse(ctx, payload, limits)
	}
}

type panicParser struct{}

func (panicParser) Descriptor() interpret.ParserDescriptor {
	return interpret.ParserDescriptor{ID: "generic-json", Version: "1.0.0", Formats: []string{"json"}}
}
func (panicParser) Parse(context.Context, interpret.Payload, interpret.Limits) interpret.ParseResult {
	panic("secret payload\r\nsynthetic parser panic")
}

type blockingParser struct{ release <-chan struct{} }

func (blockingParser) Descriptor() interpret.ParserDescriptor {
	return interpret.ParserDescriptor{ID: "generic-json", Version: "1.0.0", Formats: []string{"json"}}
}
func (parser blockingParser) Parse(context.Context, interpret.Payload, interpret.Limits) interpret.ParseResult {
	<-parser.release
	return interpret.ParseResult{Status: interpret.StatusInvalid, Document: interpret.ParsedDocument{Format: "json"}, Issues: []interpret.Issue{{Code: "TEST_RELEASED", Severity: interpret.SeverityError, Message: "released"}}}
}
