package clickhouse

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/deliver"
)

func TestClickHouseIntegrationIdempotentBatch(t *testing.T) {
	endpoint := os.Getenv("ULPF_TEST_CLICKHOUSE_URL")
	if endpoint == "" {
		t.Skip("set ULPF_TEST_CLICKHOUSE_URL to run ClickHouse integration")
	}
	user := os.Getenv("ULPF_TEST_CLICKHOUSE_USER")
	if user == "" {
		user = "default"
	}
	password := os.Getenv("ULPF_TEST_CLICKHOUSE_PASSWORD")
	migration, err := os.ReadFile(filepath.Join("..", "..", "..", "migrations", "clickhouse", "001_events.sql"))
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint+"/?multiquery=1", bytes.NewReader(migration))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-ClickHouse-User", user)
	request.Header.Set("X-ClickHouse-Key", password)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		t.Fatalf("migration: %s: %s", response.Status, responseBody)
	}

	connector, err := New(Config{ID: "integration", Endpoint: endpoint, Database: "ulpf", Table: "events", Username: user, Password: password, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	revisionID := fmt.Sprintf("integration-%d", time.Now().UnixNano())
	record := testRecord(revisionID)
	for run := 0; run < 2; run++ {
		if result := connector.Deliver(context.Background(), []deliver.ExportRecord{record}); !result.AllSucceeded() {
			t.Fatalf("delivery %d: %#v", run, result)
		}
	}
	queryURL := endpoint + "/?database=ulpf&query=" + url.QueryEscape("SELECT count() FROM events WHERE revision_id = '"+revisionID+"'")
	queryRequest, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, queryURL, nil)
	queryRequest.Header.Set("X-ClickHouse-User", user)
	queryRequest.Header.Set("X-ClickHouse-Key", password)
	queryResponse, err := http.DefaultClient.Do(queryRequest)
	if err != nil {
		t.Fatal(err)
	}
	countBody, _ := io.ReadAll(queryResponse.Body)
	queryResponse.Body.Close()
	count, err := strconv.Atoi(strings.TrimSpace(string(countBody)))
	if err != nil || count != 1 {
		t.Fatalf("stored rows = %q, want 1", countBody)
	}
}
