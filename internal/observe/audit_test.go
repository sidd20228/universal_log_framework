package observe_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/sidd20228/universal_log_framework/internal/observe"
)

func TestAuditRecordValidation(t *testing.T) {
	valid := observe.AuditRecord{
		ID:       "audit-1",
		Time:     fixedObserveTime(),
		Actor:    "operator@example.test",
		Action:   "raw.read",
		Target:   "receipt-1",
		Outcome:  observe.AuditSucceeded,
		Reason:   "incident investigation",
		Metadata: map[string]string{"tenant_id": "tenant-a"},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid audit rejected: %v", err)
	}

	for name, mutate := range map[string]func(*observe.AuditRecord){
		"missing id":        func(record *observe.AuditRecord) { record.ID = "" },
		"missing actor":     func(record *observe.AuditRecord) { record.Actor = "" },
		"invalid outcome":   func(record *observe.AuditRecord) { record.Outcome = "maybe" },
		"payload metadata":  func(record *observe.AuditRecord) { record.Metadata["payload"] = "secret" },
		"raw body metadata": func(record *observe.AuditRecord) { record.Metadata["event.original"] = "secret" },
	} {
		t.Run(name, func(t *testing.T) {
			record := valid
			record.Metadata = map[string]string{"tenant_id": "tenant-a"}
			mutate(&record)
			if err := record.Validate(); err == nil {
				t.Fatal("Validate() accepted invalid audit")
			}
		})
	}
}

func TestJSONAuditLogAppendsValidatedRecords(t *testing.T) {
	var output bytes.Buffer
	audit := observe.NewJSONAuditLog(&output)
	var sink observe.AuditSink = audit
	record := observe.AuditRecord{
		ID:      "audit-1",
		Time:    fixedObserveTime(),
		Actor:   "operator",
		Action:  "config.activate",
		Target:  "config-sha256",
		Outcome: observe.AuditSucceeded,
	}
	if err := sink.Append(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	record.ID = "audit-2"
	record.Outcome = observe.AuditDenied
	record.Reason = "approval required"
	if err := sink.Append(context.Background(), record); err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("audit lines = %d, want 2: %q", len(lines), output.String())
	}
	for index, line := range lines {
		var decoded observe.AuditRecord
		if err := json.Unmarshal([]byte(line), &decoded); err != nil {
			t.Fatalf("line %d is invalid JSON: %v", index, err)
		}
		if decoded.ID != []string{"audit-1", "audit-2"}[index] {
			t.Fatalf("line %d ID = %q", index, decoded.ID)
		}
	}

	before := output.String()
	if err := sink.Append(context.Background(), observe.AuditRecord{}); err == nil {
		t.Fatal("Append() accepted invalid audit")
	}
	if output.String() != before {
		t.Fatal("invalid audit mutated append-only output")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sink.Append(cancelled, record); !errors.Is(err, context.Canceled) {
		t.Fatalf("Append() error = %v, want context cancellation", err)
	}
}
