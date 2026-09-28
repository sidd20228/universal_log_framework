package csvparser_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/sidd20228/universal_log_framework/internal/interpret"
	csvparser "github.com/sidd20228/universal_log_framework/internal/interpret/csv"
)

func TestParseCorpusCSVMapsHeaderAndRecord(t *testing.T) {
	t.Parallel()

	result := csvparser.New().Parse(context.Background(), interpret.Payload{Bytes: corpusFixture(t, "csv.csv")}, interpret.Limits{})
	if result.Status != interpret.StatusParsed || len(result.Issues) != 0 {
		t.Fatalf("result = %#v", result)
	}
	columns := result.Document.Fields["columns"].([]string)
	if len(columns) != 9 || columns[0] != "timestamp" || columns[8] != "note" {
		t.Fatalf("columns = %#v", columns)
	}
	records := result.Document.Fields["records"].([]map[string]any)
	if len(records) != 1 || records[0]["src_port"] != "51514" || records[0]["note"] != "synthetic,\nquoted field" {
		t.Fatalf("records = %#v", records)
	}
}

func TestParseQuotedNewlineAsOneRecord(t *testing.T) {
	t.Parallel()

	payload := []byte("id,message\n1,\"line one\nline two\"\n")
	result := csvparser.New().Parse(context.Background(), interpret.Payload{Bytes: payload}, interpret.Limits{})
	if result.Status != interpret.StatusParsed {
		t.Fatalf("result = %#v", result)
	}
	records := result.Document.Fields["records"].([]map[string]any)
	want := []map[string]any{{"id": "1", "message": "line one\nline two"}}
	if !reflect.DeepEqual(records, want) {
		t.Fatalf("records = %#v, want %#v", records, want)
	}
}

func TestParseRejectsMalformedRowsAndUnsafeHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload string
		code    string
	}{
		{name: "unterminated quote", payload: "a,b\n1,\"two\n", code: csvparser.IssueSyntax},
		{name: "short row", payload: "a,b\n1\n", code: csvparser.IssueSyntax},
		{name: "long row", payload: "a,b\n1,2,3\n", code: csvparser.IssueSyntax},
		{name: "duplicate header", payload: "a,a\n1,2\n", code: csvparser.IssueDuplicateHeader},
		{name: "empty header", payload: "a,\n1,2\n", code: csvparser.IssueEmptyHeader},
		{name: "empty input", payload: "", code: csvparser.IssueEmptyInput},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := csvparser.New().Parse(context.Background(), interpret.Payload{Bytes: []byte(test.payload)}, interpret.Limits{})
			assertIssue(t, result, test.code)
		})
	}
}

func TestParseEnforcesCSVLimits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload string
		limits  interpret.Limits
		code    string
	}{
		{name: "bytes", payload: "a\n1\n", limits: interpret.Limits{MaxInputBytes: 3}, code: csvparser.IssuePayloadTooLarge},
		{name: "fields", payload: "a,b,c\n1,2,3\n", limits: interpret.Limits{MaxFields: 2}, code: csvparser.IssueFieldLimit},
		{name: "tokens", payload: "a,b\n1,2\n", limits: interpret.Limits{MaxTokens: 5}, code: csvparser.IssueTokenLimit},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := csvparser.New().Parse(context.Background(), interpret.Payload{Bytes: []byte(test.payload)}, test.limits)
			assertIssue(t, result, test.code)
		})
	}
}

func TestParseRejectsInvalidUTF8AndCancellationWithoutMutatingInput(t *testing.T) {
	t.Parallel()

	invalid := csvparser.New().Parse(context.Background(), interpret.Payload{Bytes: []byte{'a', '\n', 0xff}}, interpret.Limits{})
	assertIssue(t, invalid, csvparser.IssueInvalidUTF8)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	canceled := csvparser.New().Parse(ctx, interpret.Payload{Bytes: []byte("a\n1\n")}, interpret.Limits{})
	assertIssue(t, canceled, csvparser.IssueContextCanceled)

	payload := []byte("a\nvalue\n")
	original := bytes.Clone(payload)
	result := csvparser.New().Parse(context.Background(), interpret.Payload{Bytes: payload}, interpret.Limits{})
	if result.Status != interpret.StatusParsed || !bytes.Equal(payload, original) {
		t.Fatalf("parser mutated or rejected input: result=%#v input=%q", result, payload)
	}
	for index := range payload {
		payload[index] = 'x'
	}
	if got := result.Document.Fields["records"].([]map[string]any)[0]["a"]; got != "value" {
		t.Fatalf("parsed result retained input storage: %#v", got)
	}
}

func assertIssue(t *testing.T, result interpret.ParseResult, code string) {
	t.Helper()
	if result.Status != interpret.StatusInvalid || len(result.Issues) != 1 || result.Issues[0].Code != code {
		t.Fatalf("result = %#v, want issue %s", result, code)
	}
}

func corpusFixture(t *testing.T, name string) []byte {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "corpus", "raw", name))
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
