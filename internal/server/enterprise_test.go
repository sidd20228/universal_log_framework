package server_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/server"
)

func TestEnterpriseDemoHTTPNormalizesAllFormatsAndKeepsInvalidFieldsPartial(t *testing.T) {
	root := t.TempDir()
	t.Cleanup(func() {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err == nil {
				_ = os.Chmod(path, 0700)
			}
			return nil
		})
	})
	bundle := filepath.Join("..", "..", "bundles", "demo", "enterprise")
	service, err := server.New(context.Background(), server.Config{SQLitePath: filepath.Join(root, "state.db"), RawRoot: filepath.Join(root, "raw"), BundleRoot: filepath.Join(root, "bundles"), TenantID: "demo", Token: testToken, Workers: 2, ProcessingTimeout: time.Second, SourceProfileID: "enterprise-demo", SourceBundles: []server.SourceBundle{{SourceProfileID: "enterprise-demo", Directory: bundle}}})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = service.Serve(ctx, listener) }()
	base := "http://" + listener.Addr().String()
	waitReady(t, base)
	request := func(method, path string, body []byte) map[string]any {
		t.Helper()
		req, err := http.NewRequest(method, base+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+testToken)
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/octet-stream")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
			t.Fatalf("%s %s: status %d", method, path, resp.StatusCode)
		}
		var result map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	fixtures, err := filepath.Glob(filepath.Join(bundle, "fixtures", "valid", "*.log"))
	if err != nil || len(fixtures) != 14 {
		t.Fatalf("fixtures: %d %v", len(fixtures), err)
	}
	expected := map[string]map[string]any{}
	hashes := map[string]string{}
	for _, fixture := range fixtures {
		payload, err := os.ReadFile(fixture)
		if err != nil {
			t.Fatal(err)
		}
		ack := request(http.MethodPost, "/api/v1/ingest", payload)
		receipt := ack["receipt_id"].(string)
		digest := sha256.Sum256(payload)
		hashes[receipt] = hex.EncodeToString(digest[:])
		name := strings.TrimSuffix(filepath.Base(fixture), ".log") + ".json"
		canonical, err := os.ReadFile(filepath.Join(bundle, "expected", name))
		if err != nil {
			t.Fatal(err)
		}
		var event map[string]any
		if err = json.Unmarshal(canonical, &event); err != nil {
			t.Fatal(err)
		}
		expected[receipt] = event
	}
	bad := []byte(`{"source_name":"Palo Alto Firewall","synthetic":true,"action":"allow","src_ip":"not-an-ip","dst_ip":"198.51.100.2","timestamp":"2026-09-29T10:20:29Z"}`)
	badReceipt := request(http.MethodPost, "/api/v1/ingest", bad)["receipt_id"].(string)
	waitForEventCount(t, base, 15)
	page := request(http.MethodGet, "/api/v1/events?tenant_id=demo", nil)
	for _, raw := range page["items"].([]any) {
		item := raw.(map[string]any)
		detail := request(http.MethodGet, "/api/v1/events/"+item["revision_id"].(string), nil)
		processing := detail["processing"].(map[string]any)
		receipt := detail["receipt"].(map[string]any)["id"].(string)
		if receipt == badReceipt {
			if processing["status"] != "PARTIALLY_PARSED" {
				t.Fatalf("invalid IP was promoted: %v", processing)
			}
			if !strings.Contains(string(mustJSON(t, processing)), "MAPPING_CONVERSION_FAILED") {
				t.Fatalf("missing field diagnostic: %v", processing)
			}
			continue
		}
		if processing["status"] != "PARSED" || processing["mapping_version"] == nil {
			t.Fatalf("not normalized: %v", processing)
		}
		if !reflect.DeepEqual(detail["event"], expected[receipt]) {
			t.Fatalf("canonical event = %v; want %v", detail["event"], expected[receipt])
		}
		if len(detail["provenance"].(map[string]any)) == 0 {
			t.Fatal("normalized event has no provenance")
		}
		if detail["raw"].(map[string]any)["sha256"] != hashes[receipt] {
			t.Fatal("raw evidence hash changed")
		}
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
