package observe_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/observe"
)

func TestJSONLoggerOmitsPayloadFields(t *testing.T) {
	var output bytes.Buffer
	logger := observe.NewJSONLogger(&output)
	secret := "SECRET-PAYLOAD-CONTENTS"
	err := logger.Log(observe.LogEntry{
		Time:      fixedObserveTime(),
		Level:     observe.LevelInfo,
		Component: "ingress",
		Message:   "event accepted",
		ReceiptID: "receipt-1",
		Fields: map[string]string{
			"listener_id": "http-main",
			"payload":     secret,
			"raw_bytes":   secret,
			"event.body":  secret,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), secret) {
		t.Fatalf("log leaked payload: %s", output.String())
	}
	var entry map[string]any
	if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
		t.Fatalf("log is not JSON: %v", err)
	}
	fields, ok := entry["fields"].(map[string]any)
	if !ok || fields["listener_id"] != "http-main" {
		t.Fatalf("safe fields missing: %#v", entry["fields"])
	}
	for _, key := range []string{"payload", "raw_bytes", "event.body"} {
		if _, exists := fields[key]; exists {
			t.Fatalf("sensitive field %q was retained", key)
		}
	}
}

func TestJSONLoggerEscapesControlCharactersIntoOneRecord(t *testing.T) {
	var output bytes.Buffer
	logger := observe.NewJSONLogger(&output)
	message := "failed\nforged-record\r\t\x00"
	if err := logger.Log(observe.LogEntry{
		Time:      fixedObserveTime(),
		Level:     observe.LevelWarn,
		Component: "parser",
		Message:   message,
		Fields:    map[string]string{"detail": "line1\nline2"},
	}); err != nil {
		t.Fatal(err)
	}
	if lines := bytes.Count(output.Bytes(), []byte{'\n'}); lines != 1 {
		t.Fatalf("physical newline count = %d, want one record delimiter: %q", lines, output.Bytes())
	}
	var decoded struct {
		Message string            `json:"message"`
		Fields  map[string]string `json:"fields"`
	}
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Message != message || decoded.Fields["detail"] != "line1\nline2" {
		t.Fatalf("escaped values did not round-trip: %#v", decoded)
	}
}

func fixedObserveTime() time.Time {
	return time.Date(2026, 9, 29, 11, 12, 13, 456000000, time.UTC)
}
