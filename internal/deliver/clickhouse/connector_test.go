package clickhouse

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/deliver"
)

func TestDeliverUsesStableIdempotencyTokenAndExcludesRawBytes(t *testing.T) {
	var mu sync.Mutex
	var tokens []string
	var bodies [][]byte
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("query") == "SELECT 1" {
			writer.Write([]byte("1\n"))
			return
		}
		if request.Header.Get("X-ClickHouse-User") != "ulpf" || request.Header.Get("X-ClickHouse-Key") != "secret" {
			t.Error("missing ClickHouse credentials")
		}
		body, _ := io.ReadAll(request.Body)
		mu.Lock()
		tokens = append(tokens, request.URL.Query().Get("insert_deduplication_token"))
		bodies = append(bodies, body)
		mu.Unlock()
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	connector := newTestConnector(t, server.URL)
	records := []deliver.ExportRecord{testRecord("revision-b"), testRecord("revision-a")}
	if result := connector.Deliver(context.Background(), records); !result.AllSucceeded() {
		t.Fatalf("first result = %#v", result)
	}
	if result := connector.Deliver(context.Background(), records); !result.AllSucceeded() {
		t.Fatalf("second result = %#v", result)
	}
	if len(tokens) != 2 || tokens[0] == "" || tokens[0] != tokens[1] {
		t.Fatalf("tokens = %#v", tokens)
	}
	if !strings.Contains(string(bodies[0]), `"envelope_json":"{\"schema_version\":\"ulpf-envelope/1.0.0\"}"`) {
		t.Fatalf("envelope was not encoded as a JSON string: %s", bodies[0])
	}
	if strings.Contains(string(bodies[0]), "raw_payload") {
		t.Fatal("raw payload entered connector body")
	}
	var row map[string]any
	if err := json.Unmarshal([]byte(strings.Split(strings.TrimSpace(string(bodies[0])), "\n")[0]), &row); err != nil {
		t.Fatal(err)
	}
	if row["revision_id"] != "revision-b" || row["src_ip"] != "10.0.0.8" {
		t.Fatalf("row = %#v", row)
	}
	if health := connector.Health(context.Background()); !health.Healthy {
		t.Fatalf("health = %#v", health)
	}
}

func TestDeliveryClassifiesFailuresAndBoundsBatches(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		want   deliver.DeliveryStatus
	}{
		{name: "rate limited", status: http.StatusTooManyRequests, want: deliver.DeliveryRetryable},
		{name: "server", status: http.StatusServiceUnavailable, want: deliver.DeliveryRetryable},
		{name: "schema", status: http.StatusBadRequest, want: deliver.DeliveryPermanent},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(test.status)
				writer.Write([]byte("bad\nresponse\x00secret-safe"))
			}))
			defer server.Close()
			result := newTestConnector(t, server.URL).Deliver(context.Background(), []deliver.ExportRecord{testRecord("revision")})
			if result.Records[0].Status != test.want || strings.ContainsAny(result.Records[0].Message, "\r\n\x00") {
				t.Fatalf("result = %#v", result)
			}
		})
	}
	connector, err := New(Config{ID: "clickhouse", Endpoint: "http://127.0.0.1:8123", Database: "ulpf", Table: "events", Username: "ulpf", MaxBatchRecords: 1})
	if err != nil {
		t.Fatal(err)
	}
	result := connector.Deliver(context.Background(), []deliver.ExportRecord{testRecord("a"), testRecord("b")})
	if result.Records[0].Status != deliver.DeliveryPermanent || result.Records[0].Code != "BATCH_TOO_LARGE" {
		t.Fatalf("result = %#v", result)
	}
}

func TestInvalidRecordsAndConfigAreRejected(t *testing.T) {
	for _, endpoint := range []string{"file:///tmp/clickhouse", "http://user:pass@localhost:8123", "http://localhost:8123/path", "http://localhost:8123/?secret=x"} {
		if _, err := New(Config{ID: "id", Endpoint: endpoint, Database: "ulpf", Table: "events", Username: "user"}); err == nil {
			t.Fatalf("accepted endpoint %q", endpoint)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("invalid record reached server") }))
	defer server.Close()
	connector := newTestConnector(t, server.URL)
	record := testRecord("revision")
	record.RawSHA256 = "bad"
	result := connector.Deliver(context.Background(), []deliver.ExportRecord{record})
	if result.Records[0].Code != "INVALID_EXPORT_RECORD" {
		t.Fatalf("result = %#v", result)
	}
	duplicate := testRecord("same")
	result = connector.Deliver(context.Background(), []deliver.ExportRecord{duplicate, duplicate})
	if result.Records[0].Code != "DUPLICATE_REVISION" {
		t.Fatalf("result = %#v", result)
	}
}

func newTestConnector(t *testing.T, endpoint string) *Connector {
	t.Helper()
	connector, err := New(Config{ID: "primary", Endpoint: endpoint, Database: "ulpf", Table: "events", Username: "ulpf", Password: "secret", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return connector
}

func testRecord(revision string) deliver.ExportRecord {
	now := time.Date(2026, 9, 29, 10, 20, 30, 123456000, time.UTC)
	source := netip.MustParseAddr("10.0.0.8")
	class := uint32(4001)
	return deliver.ExportRecord{
		ReceiptID: "receipt-1", RevisionID: revision, TenantID: "tenant-a", ReceivedAt: now,
		SourceProfile: "lab", ClassUID: &class, Action: "deny", SourceIP: &source,
		Status: "PARSED", SchemaVersion: "ulpf-envelope/1.0.0",
		RawSHA256: strings.Repeat("a", 64), QualityScore: 1, IssueCodes: []string{},
		EnvelopeJSON: json.RawMessage(`{"schema_version":"ulpf-envelope/1.0.0"}`),
	}
}
