package query

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/envelope"
)

func TestClickHouseReaderUsesTypedParametersAndPaginates(t *testing.T) {
	var observedQuery string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-ClickHouse-User") != "reader" || request.Header.Get("X-ClickHouse-Key") != "secret" {
			t.Fatal("missing ClickHouse credentials")
		}
		observedQuery = request.URL.Query().Get("query")
		if request.URL.Query().Get("param_tenant") != "tenant-a" || request.URL.Query().Get("param_action") != "deny' OR 1=1 --" || request.URL.Query().Get("param_limit") != "2" {
			t.Fatalf("query parameters = %v", request.URL.Query())
		}
		if request.URL.Query().Get("output_format_json_quote_64bit_integers") != "0" {
			t.Fatalf("64-bit JSON setting = %q", request.URL.Query().Get("output_format_json_quote_64bit_integers"))
		}
		writer.Header().Set("Content-Type", "application/x-ndjson")
		for index := 1; index <= 2; index++ {
			fmt.Fprintf(writer, `{"receipt_id":"receipt-%d","revision_id":"revision-%d","tenant_id":"tenant-a","received_at_ns":%d,"event_time_ns":null,"source_profile_id":"synthetic","class_uid":4001,"action":"deny","src_ip":"192.0.2.%d","dst_ip":null,"status":"PARSED","raw_sha256":"%s","quality_score":1}`+"\n",
				index, index, time.Date(2026, 9, 29, 10, 0, index, 0, time.UTC).UnixNano(), index, strings.Repeat("a", 64))
		}
	}))
	defer server.Close()
	reader, err := NewClickHouseReader(ClickHouseConfig{
		Endpoint: server.URL, Database: "ulpf", Table: "events", Username: "reader", Password: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	page, err := reader.ListEvents(context.Background(), EventQuery{TenantID: "tenant-a", Limit: 1, Action: "deny' OR 1=1 --"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].RevisionID != "revision-1" || page.NextCursor == nil || page.NextCursor.RevisionID != "revision-1" {
		t.Fatalf("page = %#v", page)
	}
	if strings.Contains(observedQuery, "deny' OR 1=1") || !strings.Contains(observedQuery, "action = {action:String}") {
		t.Fatalf("query did not use a typed action parameter: %s", observedQuery)
	}
}

func TestClickHouseReaderBoundsResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte(strings.Repeat("x", 129)))
	}))
	defer server.Close()
	reader, err := NewClickHouseReader(ClickHouseConfig{
		Endpoint: server.URL, Database: "ulpf", Table: "events", Username: "reader", Password: "secret", MaxResponseBytes: 128,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ListEvents(context.Background(), EventQuery{TenantID: "tenant-a", Limit: 1}); err == nil || !strings.Contains(err.Error(), "response exceeded limit") {
		t.Fatalf("ListEvents() error = %v", err)
	}
}

func TestClickHouseReaderReturnsValidatedEnvelope(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "envelope", "testdata", "envelope.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected envelope.Envelope
	if err := json.Unmarshal(body, &expected); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("param_tenant") != expected.Receipt.TenantID || request.URL.Query().Get("param_revision") != expected.Processing.RevisionID {
			t.Fatalf("query parameters = %v", request.URL.Query())
		}
		if err := json.NewEncoder(writer).Encode(map[string]string{"envelope_json": string(body)}); err != nil {
			t.Fatal(err)
		}
	}))
	defer server.Close()
	reader, err := NewClickHouseReader(ClickHouseConfig{
		Endpoint: server.URL, Database: "ulpf", Table: "events", Username: "reader", Password: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := reader.GetEvent(context.Background(), expected.Receipt.TenantID, expected.Processing.RevisionID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Receipt.ID != expected.Receipt.ID || got.Processing.RevisionID != expected.Processing.RevisionID {
		t.Fatalf("event trace = %#v", got)
	}
}

func TestClickHouseReaderRejectsUnsafeConfiguration(t *testing.T) {
	for _, config := range []ClickHouseConfig{
		{Endpoint: "http://localhost", Database: "ulpf; DROP", Table: "events", Username: "reader"},
		{Endpoint: "file:///tmp/database", Database: "ulpf", Table: "events", Username: "reader"},
		{Endpoint: "http://localhost/path", Database: "ulpf", Table: "events", Username: "reader"},
		{Endpoint: "http://localhost", Database: "ulpf", Table: "events", Username: "bad\nheader"},
	} {
		if _, err := NewClickHouseReader(config); err == nil {
			t.Fatalf("unsafe config was accepted: %#v", config)
		}
	}
}
