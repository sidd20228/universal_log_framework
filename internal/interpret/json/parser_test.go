package jsonparser_test

import (
	"bytes"
	"context"
	stdjson "encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/sidd20228/universal_log_framework/internal/interpret"
	jsonparser "github.com/sidd20228/universal_log_framework/internal/interpret/json"
)

func TestDescriptor(t *testing.T) {
	t.Parallel()

	descriptor := jsonparser.New().Descriptor()
	if descriptor.ID != jsonparser.ParserID || descriptor.Version != jsonparser.ParserVersion {
		t.Fatalf("descriptor identity = %s@%s", descriptor.ID, descriptor.Version)
	}
	if !reflect.DeepEqual(descriptor.Formats, []string{jsonparser.FormatJSON}) {
		t.Fatalf("descriptor formats = %#v", descriptor.Formats)
	}
}

func TestParseCorpusJSONPreservesNestedValuesAndScalarTypes(t *testing.T) {
	t.Parallel()

	parser := jsonparser.New()
	firewall := parseCorpusFixture(t, parser, "json_firewall.json")
	if firewall.Status != interpret.StatusParsed || len(firewall.Issues) != 0 {
		t.Fatalf("firewall result = %#v", firewall)
	}
	if got := firewall.Document.Fields["src_port"]; got != stdjson.Number("53000") {
		t.Fatalf("src_port = %#v (%T)", got, got)
	}
	if got := firewall.Document.Fields["synthetic"]; got != true {
		t.Fatalf("synthetic = %#v (%T)", got, got)
	}

	ids := parseCorpusFixture(t, parser, "json_ids.json")
	alert, ok := ids.Document.Fields["alert"].(map[string]any)
	if !ok {
		t.Fatalf("alert = %#v (%T)", ids.Document.Fields["alert"], ids.Document.Fields["alert"])
	}
	if got := alert["signature"]; got != "Synthetic TLS Policy Alert" {
		t.Fatalf("alert.signature = %#v", got)
	}
	if got := alert["signature_id"]; got != stdjson.Number("900001") {
		t.Fatalf("alert.signature_id = %#v (%T)", got, got)
	}
}

func TestParsePreservesArraysNullAndExactNumbers(t *testing.T) {
	t.Parallel()

	result := jsonparser.New().Parse(context.Background(), interpret.Payload{Bytes: []byte(
		`{"values":[1,2.50,true,null,{"nested":"value"}],"large":9007199254740993}`,
	)}, interpret.Limits{})
	if result.Status != interpret.StatusParsed {
		t.Fatalf("status = %s, issues = %#v", result.Status, result.Issues)
	}
	values, ok := result.Document.Fields["values"].([]any)
	if !ok || len(values) != 5 {
		t.Fatalf("values = %#v", result.Document.Fields["values"])
	}
	wantValues := []any{
		stdjson.Number("1"),
		stdjson.Number("2.50"),
		true,
		nil,
		map[string]any{"nested": "value"},
	}
	if !reflect.DeepEqual(values, wantValues) {
		t.Fatalf("values = %#v, want %#v", values, wantValues)
	}
	if got := result.Document.Fields["large"]; got != stdjson.Number("9007199254740993") {
		t.Fatalf("large = %#v (%T)", got, got)
	}
}

func TestParseRepresentsNonObjectRootWithoutTypeLoss(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload string
		want    any
	}{
		{name: "array", payload: `[1,"two",false]`, want: []any{stdjson.Number("1"), "two", false}},
		{name: "string", payload: `"value"`, want: "value"},
		{name: "number", payload: `-0.125e+3`, want: stdjson.Number("-0.125e+3")},
		{name: "boolean", payload: `true`, want: true},
		{name: "null", payload: `null`, want: nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := jsonparser.New().Parse(context.Background(), interpret.Payload{Bytes: []byte(test.payload)}, interpret.Limits{})
			if result.Status != interpret.StatusParsed {
				t.Fatalf("status = %s, issues = %#v", result.Status, result.Issues)
			}
			if got := result.Document.Fields["$"]; !reflect.DeepEqual(got, test.want) {
				t.Fatalf("root = %#v (%T), want %#v (%T)", got, got, test.want, test.want)
			}
		})
	}
}

func TestParseRejectsDuplicateKeysAtEveryDepth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload []byte
	}{
		{name: "root", payload: readCorpusFixture(t, "duplicate_keys.json")},
		{name: "nested object", payload: []byte(`{"outer":{"key":1,"key":2}}`)},
		{name: "object in array", payload: []byte(`[{"key":1,"key":2}]`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := jsonparser.New().Parse(context.Background(), interpret.Payload{Bytes: test.payload}, interpret.Limits{})
			assertSingleIssue(t, result, jsonparser.IssueDuplicateKey)
			if result.Document.Fields != nil {
				t.Fatalf("invalid document exposed fields: %#v", result.Document.Fields)
			}
		})
	}
}

func TestParseRejectsMalformedTrailingAndEmptyInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		payload  []byte
		wantCode string
	}{
		{name: "malformed corpus", payload: readCorpusFixture(t, "malformed_json.json"), wantCode: jsonparser.IssueSyntax},
		{name: "trailing object", payload: []byte(`{"a":1} {"b":2}`), wantCode: jsonparser.IssueTrailingData},
		{name: "trailing garbage", payload: []byte("{\"a\":1}\nxyz"), wantCode: jsonparser.IssueTrailingData},
		{name: "empty", payload: nil, wantCode: jsonparser.IssueEmptyInput},
		{name: "whitespace", payload: []byte(" \t\r\n"), wantCode: jsonparser.IssueEmptyInput},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := jsonparser.New().Parse(context.Background(), interpret.Payload{Bytes: test.payload}, interpret.Limits{})
			assertSingleIssue(t, result, test.wantCode)
		})
	}
}

func TestParseRejectsInvalidUTF8BeforeJSONDecode(t *testing.T) {
	t.Parallel()

	payload := readCorpusFixture(t, "invalid_utf8.bin")
	result := jsonparser.New().Parse(context.Background(), interpret.Payload{Bytes: payload}, interpret.Limits{})
	assertSingleIssue(t, result, jsonparser.IssueInvalidUTF8)
	if result.Issues[0].Offset != 0 {
		t.Fatalf("invalid UTF-8 offset = %d, want 0", result.Issues[0].Offset)
	}
}

func TestParseEnforcesIndependentLimits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		payload  string
		limits   interpret.Limits
		wantCode string
	}{
		{
			name:     "bytes",
			payload:  `{"a":1}`,
			limits:   interpret.Limits{MaxInputBytes: 6},
			wantCode: jsonparser.IssuePayloadTooLarge,
		},
		{
			name:     "fields across nested objects",
			payload:  `{"a":1,"nested":{"b":2}}`,
			limits:   interpret.Limits{MaxFields: 2},
			wantCode: jsonparser.IssueFieldLimit,
		},
		{
			name:     "depth",
			payload:  `{"a":[{"b":1}]}`,
			limits:   interpret.Limits{MaxDepth: 2},
			wantCode: jsonparser.IssueDepthLimit,
		},
		{
			name:     "tokens",
			payload:  `{"a":1}`,
			limits:   interpret.Limits{MaxTokens: 3},
			wantCode: jsonparser.IssueTokenLimit,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := jsonparser.New().Parse(context.Background(), interpret.Payload{Bytes: []byte(test.payload)}, test.limits)
			assertSingleIssue(t, result, test.wantCode)
		})
	}

	exactBoundary := jsonparser.New().Parse(
		context.Background(),
		interpret.Payload{Bytes: []byte(`{"a":[{"b":1}]}`)},
		interpret.Limits{MaxDepth: 3, MaxFields: 3, MaxTokens: 11},
	)
	if exactBoundary.Status != interpret.StatusParsed {
		t.Fatalf("exact-boundary payload rejected: %#v", exactBoundary.Issues)
	}
}

func TestParseReportsCanceledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := jsonparser.New().Parse(ctx, interpret.Payload{Bytes: []byte(`{"a":1}`)}, interpret.Limits{})
	assertSingleIssue(t, result, jsonparser.IssueContextCanceled)
}

func TestParseDoesNotMutateOrRetainInput(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"name":"original","nested":{"enabled":true}}`)
	original := bytes.Clone(payload)
	result := jsonparser.New().Parse(context.Background(), interpret.Payload{Bytes: payload}, interpret.Limits{})
	if result.Status != interpret.StatusParsed {
		t.Fatalf("status = %s, issues = %#v", result.Status, result.Issues)
	}
	if !bytes.Equal(payload, original) {
		t.Fatal("parser mutated the input buffer")
	}
	for index := range payload {
		payload[index] = 'x'
	}
	if got := result.Document.Fields["name"]; got != "original" {
		t.Fatalf("parsed string retained input storage: %#v", got)
	}
	nested := result.Document.Fields["nested"].(map[string]any)
	if got := nested["enabled"]; got != true {
		t.Fatalf("parsed nested value changed after input mutation: %#v", got)
	}
}

func TestParseIsDeterministicAndSafeForConcurrentUse(t *testing.T) {
	t.Parallel()

	parser := jsonparser.New()
	payload := readCorpusFixture(t, "repeated_occurrence_a.json")
	want := parser.Parse(context.Background(), interpret.Payload{Bytes: payload}, interpret.Limits{})
	const workers = 32
	const iterations = 64
	errCh := make(chan string, workers)
	var waitGroup sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for iteration := 0; iteration < iterations; iteration++ {
				got := parser.Parse(context.Background(), interpret.Payload{Bytes: payload}, interpret.Limits{})
				if !reflect.DeepEqual(got, want) {
					errCh <- "concurrent parse result differed"
					return
				}
			}
		}()
	}
	waitGroup.Wait()
	close(errCh)
	for message := range errCh {
		t.Error(message)
	}

	repeated := readCorpusFixture(t, "repeated_occurrence_b.json")
	if !bytes.Equal(payload, repeated) {
		t.Fatal("corpus repeated occurrences are not byte-identical")
	}
	got := parser.Parse(context.Background(), interpret.Payload{Bytes: repeated}, interpret.Limits{})
	if !reflect.DeepEqual(got, want) {
		t.Fatal("byte-identical occurrences produced different parse results")
	}
}

func assertSingleIssue(t *testing.T, result interpret.ParseResult, wantCode string) {
	t.Helper()
	if result.Status != interpret.StatusInvalid {
		t.Fatalf("status = %s, want %s", result.Status, interpret.StatusInvalid)
	}
	if len(result.Issues) != 1 {
		t.Fatalf("issues = %#v, want one", result.Issues)
	}
	if result.Issues[0].Code != wantCode {
		t.Fatalf("issue code = %q, want %q; issue = %#v", result.Issues[0].Code, wantCode, result.Issues[0])
	}
	if result.Issues[0].Severity != interpret.SeverityError {
		t.Fatalf("issue severity = %s", result.Issues[0].Severity)
	}
}

func parseCorpusFixture(t *testing.T, parser jsonparser.Parser, name string) interpret.ParseResult {
	t.Helper()
	return parser.Parse(context.Background(), interpret.Payload{Bytes: readCorpusFixture(t, name)}, interpret.Limits{})
}

func readCorpusFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "..", "tests", "corpus", "raw", name)
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read corpus fixture %s: %v", name, err)
	}
	return payload
}
