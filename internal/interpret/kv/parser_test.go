package kvparser_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/sidd20228/universal_log_framework/internal/interpret"
	kvparser "github.com/sidd20228/universal_log_framework/internal/interpret/kv"
)

func TestParseCorpusKeyValueFirewall(t *testing.T) {
	t.Parallel()

	result := kvparser.New().Parse(context.Background(), interpret.Payload{Bytes: corpusFixture(t, "key_value_firewall.log")}, interpret.Limits{})
	if result.Status != interpret.StatusParsed || len(result.Issues) != 0 {
		t.Fatalf("result = %#v", result)
	}
	attributes := result.Document.Fields["attributes"].(map[string]any)
	if attributes["src"] != "10.0.0.8" || attributes["dport"] != "443" || attributes["action"] != "blocked" {
		t.Fatalf("attributes = %#v", attributes)
	}
}

func TestParseQuotedValuesAndEscapes(t *testing.T) {
	t.Parallel()

	payload := []byte(`message="line one\nline two" path='c:\\tmp' empty= literal="keep\q"`)
	result := kvparser.New().Parse(context.Background(), interpret.Payload{Bytes: payload}, interpret.Limits{})
	if result.Status != interpret.StatusPartiallyParsed || len(result.Issues) != 1 || result.Issues[0].Code != kvparser.IssueUnknownEscape {
		t.Fatalf("result = %#v", result)
	}
	attributes := result.Document.Fields["attributes"].(map[string]any)
	want := map[string]any{
		"message": "line one\nline two",
		"path":    `c:\tmp`,
		"empty":   "",
		"literal": `keep\q`,
	}
	if !reflect.DeepEqual(attributes, want) {
		t.Fatalf("attributes = %#v, want %#v", attributes, want)
	}
}

func TestParsePreservesDuplicateValuesInArrivalOrder(t *testing.T) {
	t.Parallel()

	result := kvparser.New().Parse(context.Background(), interpret.Payload{Bytes: []byte(`action=allow action=deny action=drop`)}, interpret.Limits{})
	if result.Status != interpret.StatusPartiallyParsed || len(result.Issues) != 2 {
		t.Fatalf("result = %#v", result)
	}
	for _, issue := range result.Issues {
		if issue.Code != kvparser.IssueDuplicateKey {
			t.Fatalf("issue = %#v", issue)
		}
	}
	values := result.Document.Fields["attributes"].(map[string]any)["action"]
	if !reflect.DeepEqual(values, []string{"allow", "deny", "drop"}) {
		t.Fatalf("duplicate values = %#v", values)
	}
}

func TestParseMalformedSuffixIsPreserved(t *testing.T) {
	t.Parallel()

	payload := []byte(`src=10.0.0.8 malformed suffix`)
	result := kvparser.New().Parse(context.Background(), interpret.Payload{Bytes: payload}, interpret.Limits{})
	if result.Status != interpret.StatusPartiallyParsed || len(result.Issues) != 1 || result.Issues[0].Code != kvparser.IssueMalformedToken {
		t.Fatalf("result = %#v", result)
	}
	if string(result.Document.Unmatched) != "malformed suffix" {
		t.Fatalf("unmatched = %q", result.Document.Unmatched)
	}
	originalUnmatched := bytes.Clone(result.Document.Unmatched)
	for index := range payload {
		payload[index] = 'x'
	}
	if !bytes.Equal(result.Document.Unmatched, originalUnmatched) {
		t.Fatal("unmatched bytes retained the input buffer")
	}
}

func TestParseRejectsMalformedFirstTokenAndUnterminatedQuote(t *testing.T) {
	t.Parallel()

	tests := []struct {
		payload string
		code    string
	}{
		{payload: "not-a-pair", code: kvparser.IssueMalformedToken},
		{payload: `key="unterminated`, code: kvparser.IssueUnterminated},
		{payload: `key="closed"suffix`, code: kvparser.IssueMalformedToken},
		{payload: " \t\r\n", code: kvparser.IssueEmptyInput},
	}
	for _, test := range tests {
		result := kvparser.New().Parse(context.Background(), interpret.Payload{Bytes: []byte(test.payload)}, interpret.Limits{})
		assertIssue(t, result, test.code)
	}
}

func TestParseEnforcesKVLimits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload string
		limits  interpret.Limits
		code    string
	}{
		{name: "bytes", payload: "a=1", limits: interpret.Limits{MaxInputBytes: 2}, code: kvparser.IssuePayloadTooLarge},
		{name: "fields", payload: "a=1 b=2", limits: interpret.Limits{MaxFields: 1}, code: kvparser.IssueFieldLimit},
		{name: "tokens", payload: "a=1 b=2", limits: interpret.Limits{MaxTokens: 2}, code: kvparser.IssueTokenLimit},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := kvparser.New().Parse(context.Background(), interpret.Payload{Bytes: []byte(test.payload)}, test.limits)
			if test.name == "bytes" {
				assertIssue(t, result, test.code)
				return
			}
			if result.Status != interpret.StatusPartiallyParsed || len(result.Issues) != 1 || result.Issues[0].Code != test.code {
				t.Fatalf("result = %#v", result)
			}
			if string(result.Document.Unmatched) != "b=2" {
				t.Fatalf("unmatched = %q", result.Document.Unmatched)
			}
		})
	}
}

func TestParseRejectsInvalidUTF8AndCancellation(t *testing.T) {
	t.Parallel()

	invalid := kvparser.New().Parse(context.Background(), interpret.Payload{Bytes: []byte{'a', '=', 0xff}}, interpret.Limits{})
	assertIssue(t, invalid, kvparser.IssueInvalidUTF8)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	canceled := kvparser.New().Parse(ctx, interpret.Payload{Bytes: []byte("a=1")}, interpret.Limits{})
	assertIssue(t, canceled, kvparser.IssueContextCanceled)
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
