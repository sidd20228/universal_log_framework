package ndjson

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sidd20228/universal_log_framework/internal/deliver"
)

func TestGoldenNDJSONExport(t *testing.T) {
	var output bytes.Buffer
	connector, err := NewWriter("cold-export", &output, 10, 4096)
	if err != nil {
		t.Fatal(err)
	}
	records := []deliver.ExportRecord{
		{RevisionID: "revision-1", EnvelopeJSON: json.RawMessage("{\n  \"schema_version\": \"ulpf-envelope/1.0.0\", \"receipt\": {\"id\": \"one\"}\n}")},
		{RevisionID: "revision-2", EnvelopeJSON: json.RawMessage(`{"schema_version":"ulpf-envelope/1.0.0","receipt":{"id":"two"}}`)},
	}
	result := connector.Deliver(context.Background(), records)
	if !result.AllSucceeded() {
		t.Fatalf("result = %#v", result)
	}
	want := "{\"schema_version\":\"ulpf-envelope/1.0.0\",\"receipt\":{\"id\":\"one\"}}\n" +
		"{\"schema_version\":\"ulpf-envelope/1.0.0\",\"receipt\":{\"id\":\"two\"}}\n"
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
}

func TestFileExportAppendsAndSyncs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	connector, err := OpenFile("file-export", path, 10, 4096)
	if err != nil {
		t.Fatal(err)
	}
	for _, revision := range []string{"one", "two"} {
		result := connector.Deliver(context.Background(), []deliver.ExportRecord{{RevisionID: revision, EnvelopeJSON: json.RawMessage(`{"revision":"` + revision + `"}`)}})
		if !result.AllSucceeded() {
			t.Fatalf("result = %#v", result)
		}
	}
	if err := connector.Close(); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "{\"revision\":\"one\"}\n{\"revision\":\"two\"}\n" {
		t.Fatalf("contents = %q", contents)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
}

func TestFailuresAreClassifiedWithoutPartialValidationWrites(t *testing.T) {
	writer := &failingWriter{err: errors.New("disk full")}
	connector, err := NewWriter("failure", writer, 1, 64)
	if err != nil {
		t.Fatal(err)
	}
	result := connector.Deliver(context.Background(), []deliver.ExportRecord{{RevisionID: "one", EnvelopeJSON: json.RawMessage(`{"ok":true}`)}})
	if result.Records[0].Status != deliver.DeliveryRetryable || result.Records[0].Code != "NDJSON_WRITE_FAILED" {
		t.Fatalf("result = %#v", result)
	}

	var output bytes.Buffer
	connector, err = NewWriter("validation", &output, 1, 64)
	if err != nil {
		t.Fatal(err)
	}
	result = connector.Deliver(context.Background(), []deliver.ExportRecord{{RevisionID: "one", EnvelopeJSON: json.RawMessage(`{"ok":true}`)}, {RevisionID: "two", EnvelopeJSON: json.RawMessage(`invalid`)}})
	if result.Records[0].Status != deliver.DeliveryPermanent || output.Len() != 0 {
		t.Fatalf("result = %#v, output = %q", result, output.Bytes())
	}
}

func TestFileDestinationRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := OpenFile("unsafe", link, 1, 1024); err == nil {
		t.Fatal("symlink destination was accepted")
	}
}

func TestContextHealthDuplicateAndLimits(t *testing.T) {
	var output bytes.Buffer
	connector, err := NewWriter("bounded", &output, 2, 32)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := deliver.ExportRecord{RevisionID: "same", EnvelopeJSON: json.RawMessage(`{"a":1}`)}
	result := connector.Deliver(context.Background(), []deliver.ExportRecord{duplicate, duplicate})
	if result.Records[0].Code != "DUPLICATE_REVISION" || output.Len() != 0 {
		t.Fatalf("duplicate result = %#v", result)
	}
	result = connector.Deliver(context.Background(), []deliver.ExportRecord{{RevisionID: "large", EnvelopeJSON: json.RawMessage(`{"value":"` + strings.Repeat("x", 40) + `"}`)}})
	if result.Records[0].Code != "BATCH_TOO_LARGE" {
		t.Fatalf("large result = %#v", result)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result = connector.Deliver(ctx, []deliver.ExportRecord{{RevisionID: "cancelled", EnvelopeJSON: json.RawMessage(`{"a":1}`)}})
	if result.Records[0].Code != "DELIVERY_CANCELLED" {
		t.Fatalf("cancel result = %#v", result)
	}
	if health := connector.Health(context.Background()); !health.Healthy {
		t.Fatalf("health = %#v", health)
	}
}

type failingWriter struct{ err error }

func (writer *failingWriter) Write([]byte) (int, error) { return 0, writer.err }

var _ io.Writer = (*failingWriter)(nil)
