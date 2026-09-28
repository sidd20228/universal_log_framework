package syslog_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/sidd20228/universal_log_framework/internal/interpret"
	"github.com/sidd20228/universal_log_framework/internal/interpret/syslog"
)

func TestParserParsesRFC5424CorpusMessage(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "corpus", "raw", "generic_syslog.log"))
	if err != nil {
		t.Fatal(err)
	}
	result := syslog.New().Parse(context.Background(), interpret.Payload{Bytes: payload}, interpret.Limits{})
	if result.Status != interpret.StatusParsed {
		t.Fatalf("status = %s, issues = %+v", result.Status, result.Issues)
	}
	assertField(t, result.Document.Fields, "priority", 134)
	assertField(t, result.Document.Fields, "facility", 16)
	assertField(t, result.Document.Fields, "severity", 6)
	assertField(t, result.Document.Fields, "timestamp", "2026-09-29T10:20:29Z")
	assertField(t, result.Document.Fields, "hostname", "edge-fw")
	assertField(t, result.Document.Fields, "app_name", "labfw")
	assertField(t, result.Document.Fields, "msg_id", "TRAFFIC")
	message, ok := result.Document.Fields["message"].([]byte)
	if !ok || !bytes.Equal(message, []byte("blocked\n")) {
		t.Fatalf("message = %q", message)
	}
	elements, ok := result.Document.Fields["structured_data"].([]syslog.StructuredDataElement)
	if !ok || len(elements) != 1 || elements[0].ID != "net" || len(elements[0].Parameters) != 6 {
		t.Fatalf("structured data = %#v", result.Document.Fields["structured_data"])
	}
	if len(result.Document.Unmatched) != 0 {
		t.Fatalf("unmatched = %q, want empty", result.Document.Unmatched)
	}
}

func TestParserDecodesRFC5424StructuredDataEscapes(t *testing.T) {
	payload := []byte(`<165>1 2003-10-11T22:14:15.003Z host app 123 ID47 [example@32473 escaped="a\]b\"c\\d"][meta key="value"] message`)
	result := syslog.New().Parse(context.Background(), interpret.Payload{Bytes: payload}, interpret.Limits{})
	if result.Status != interpret.StatusParsed {
		t.Fatalf("status = %s, issues = %+v, unmatched = %q", result.Status, result.Issues, result.Document.Unmatched)
	}
	elements := result.Document.Fields["structured_data"].([]syslog.StructuredDataElement)
	if len(elements) != 2 || elements[0].Parameters[0].Value != `a]b"c\d` {
		t.Fatalf("structured data = %#v", elements)
	}
	if got := result.Document.Fields["message"].([]byte); !bytes.Equal(got, []byte("message")) {
		t.Fatalf("message = %q", got)
	}
}

func TestParserReportsInvalidRFC5424TimestampWithoutDroppingFields(t *testing.T) {
	payload := []byte("<13>1 not-a-time host app - ID - body")
	result := syslog.New().Parse(context.Background(), interpret.Payload{Bytes: payload}, interpret.Limits{})
	if result.Status != interpret.StatusPartiallyParsed || !hasIssue(result, syslog.IssueInvalidTimestamp) {
		t.Fatalf("result = %+v", result)
	}
	assertField(t, result.Document.Fields, "timestamp", "not-a-time")
	assertField(t, result.Document.Fields, "hostname", "host")
	if got := result.Document.Fields["message"].([]byte); !bytes.Equal(got, []byte("body")) {
		t.Fatalf("message = %q", got)
	}
}

func TestParserParsesRFC3164WithoutInventingYear(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("testdata", "rfc3164.log"))
	if err != nil {
		t.Fatal(err)
	}
	result := syslog.New().Parse(context.Background(), interpret.Payload{Bytes: payload}, interpret.Limits{})
	if result.Status != interpret.StatusPartiallyParsed {
		t.Fatalf("status = %s, issues = %+v", result.Status, result.Issues)
	}
	assertField(t, result.Document.Fields, "priority", 34)
	assertField(t, result.Document.Fields, "timestamp", "Oct 11 22:14:15")
	assertField(t, result.Document.Fields, "timestamp_month", 10)
	assertField(t, result.Document.Fields, "timestamp_day", 11)
	assertField(t, result.Document.Fields, "hostname", "mymachine")
	assertField(t, result.Document.Fields, "tag", "su")
	assertField(t, result.Document.Fields, "proc_id", "123")
	if _, exists := result.Document.Fields["year"]; exists {
		t.Fatal("RFC3164 parser fabricated a year")
	}
	if !hasIssue(result, syslog.IssueRFC3164YearUnknown) {
		t.Fatalf("issues = %+v, want %s", result.Issues, syslog.IssueRFC3164YearUnknown)
	}
	if got := result.Document.Fields["message"].([]byte); !bytes.Equal(got, []byte("authentication failed\n")) {
		t.Fatalf("message = %q", got)
	}
}

func TestParserPreservesMalformedStructuredDataAsUnmatched(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("testdata", "rfc5424_malformed_sd.log"))
	if err != nil {
		t.Fatal(err)
	}
	result := syslog.New().Parse(context.Background(), interpret.Payload{Bytes: payload}, interpret.Limits{})
	if result.Status != interpret.StatusPartiallyParsed || !hasIssue(result, syslog.IssueInvalidStructuredData) {
		t.Fatalf("result = %+v", result)
	}
	want := []byte(`[meta key="unterminated] trailing` + "\n")
	if !bytes.Equal(result.Document.Unmatched, want) {
		t.Fatalf("unmatched = %q, want %q", result.Document.Unmatched, want)
	}
}

func TestParserPreservesRFC3164ContentWhenTagIsMissing(t *testing.T) {
	payload := []byte("<13>Feb  5 17:32:18 host message without tag")
	result := syslog.New().Parse(context.Background(), interpret.Payload{Bytes: payload}, interpret.Limits{})
	if result.Status != interpret.StatusPartiallyParsed || !hasIssue(result, syslog.IssueRFC3164TagMissing) {
		t.Fatalf("result = %+v", result)
	}
	if got := result.Document.Fields["message"].([]byte); !bytes.Equal(got, []byte("message without tag")) {
		t.Fatalf("message = %q", got)
	}
}

func TestParserPreservesAllRFC3164ContentWhenTagIsInvalid(t *testing.T) {
	payload := []byte("<13>Feb  5 17:32:18 host malformed tag: still evidence")
	result := syslog.New().Parse(context.Background(), interpret.Payload{Bytes: payload}, interpret.Limits{})
	if result.Status != interpret.StatusPartiallyParsed || !hasIssue(result, syslog.IssueHeaderField) {
		t.Fatalf("result = %+v", result)
	}
	if got := result.Document.Fields["message"].([]byte); !bytes.Equal(got, []byte("malformed tag: still evidence")) {
		t.Fatalf("message = %q", got)
	}
}

func TestParserRejectsInvalidPriorityAndRetainsInput(t *testing.T) {
	payload := []byte("<999>1 2026-09-29T10:20:29Z host app - ID - body")
	original := append([]byte(nil), payload...)
	result := syslog.New().Parse(context.Background(), interpret.Payload{Bytes: payload}, interpret.Limits{})
	if result.Status != interpret.StatusInvalid || !hasIssue(result, syslog.IssueInvalidPriority) {
		t.Fatalf("result = %+v", result)
	}
	if !bytes.Equal(result.Document.Unmatched, original) {
		t.Fatalf("unmatched = %q, want original", result.Document.Unmatched)
	}
	payload[0] = '!'
	if !bytes.Equal(result.Document.Unmatched, original) {
		t.Fatal("result retained an alias to caller-owned payload bytes")
	}
}

func TestParserCopiesRetainedMessageBytes(t *testing.T) {
	payload := []byte("<13>1 2026-09-29T10:20:29Z host app - ID - original")
	result := syslog.New().Parse(context.Background(), interpret.Payload{Bytes: payload}, interpret.Limits{})
	if result.Status != interpret.StatusParsed {
		t.Fatalf("result = %+v", result)
	}
	message := result.Document.Fields["message"].([]byte)
	copy(payload[len(payload)-len("original"):], "MUTATED!")
	if !bytes.Equal(message, []byte("original")) {
		t.Fatalf("retained message changed to %q", message)
	}
}

func TestParserEnforcesTokenLimit(t *testing.T) {
	payload := []byte(`<13>1 2026-09-29T10:20:29Z host app - ID [meta a="1" b="2"] body`)
	result := syslog.New().Parse(context.Background(), interpret.Payload{Bytes: payload}, interpret.Limits{MaxTokens: 3})
	if result.Status != interpret.StatusPartiallyParsed || !hasIssue(result, syslog.IssueTokenLimit) {
		t.Fatalf("result = %+v", result)
	}
}

func TestParserIsDeterministic(t *testing.T) {
	payload := interpret.Payload{Bytes: []byte(`<165>1 2003-10-11T22:14:15.003Z host app 123 ID47 [meta b="2" a="1"] message`)}
	first := syslog.New().Parse(context.Background(), payload, interpret.Limits{})
	second := syslog.New().Parse(context.Background(), payload, interpret.Limits{})
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("repeated parses differ:\nfirst:  %#v\nsecond: %#v", first, second)
	}
}

func FuzzParserNeverPanics(fuzz *testing.F) {
	for _, seed := range [][]byte{
		[]byte("<34>Oct 11 22:14:15 host app[1]: message"),
		[]byte(`<165>1 2003-10-11T22:14:15.003Z host app 123 ID47 [meta key="value"] message`),
		[]byte("<999>bad"),
		{0x00, 0xff, '<', '1', '>'},
	} {
		fuzz.Add(seed)
	}
	fuzz.Fuzz(func(t *testing.T, payload []byte) {
		original := append([]byte(nil), payload...)
		result := syslog.New().Parse(context.Background(), interpret.Payload{Bytes: payload}, interpret.Limits{MaxInputBytes: 4096, MaxFields: 64, MaxTokens: 128})
		if !bytes.Equal(payload, original) {
			t.Fatal("parser mutated input")
		}
		if result.Status != interpret.StatusParsed && result.Status != interpret.StatusPartiallyParsed && result.Status != interpret.StatusInvalid {
			t.Fatalf("unexpected status %q", result.Status)
		}
	})
}

func assertField(t *testing.T, fields map[string]any, name string, want any) {
	t.Helper()
	if got := fields[name]; got != want {
		t.Fatalf("field %q = %#v, want %#v", name, got, want)
	}
}

func hasIssue(result interpret.ParseResult, code string) bool {
	for _, parseIssue := range result.Issues {
		if parseIssue.Code == code {
			return true
		}
	}
	return false
}
