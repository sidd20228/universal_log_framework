package cef

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/sidd20228/universal_log_framework/internal/interpret"
)

func TestCEFParsesCorpusEscapesAndFields(t *testing.T) {
	payload := corpusFixture(t, "cef.log")
	result := NewCEF().Parse(context.Background(), interpret.Payload{Bytes: payload}, interpret.Limits{})
	if result.Status != interpret.StatusParsed {
		t.Fatalf("status = %s, issues = %#v", result.Status, result.Issues)
	}
	header := result.Document.Fields["header"].(map[string]any)
	if header["device_vendor"] != "Example" || header["severity"] != "7" {
		t.Fatalf("unexpected header: %#v", header)
	}
	extension := result.Document.Fields["extension"].(map[string]any)
	if extension["src"] != "10.0.0.8" || extension["msg"] != `synthetic=policy\test` {
		t.Fatalf("unexpected extension: %#v", extension)
	}
	if len(result.Document.Unmatched) != 0 {
		t.Fatalf("unexpected unmatched bytes: %q", result.Document.Unmatched)
	}
}

func TestCEFHeaderEscapesAndValueSpaces(t *testing.T) {
	input := []byte(`CEF:1|Vendor\|Lab|Product|2.0|42|name with \| pipe|5|msg=hello world act=deny equation=a\=b path=c:\\tmp`)
	result := NewCEF().Parse(context.Background(), interpret.Payload{Bytes: input}, interpret.Limits{})
	if result.Status != interpret.StatusParsed {
		t.Fatalf("status = %s, issues = %#v", result.Status, result.Issues)
	}
	header := result.Document.Fields["header"].(map[string]any)
	if header["device_vendor"] != "Vendor|Lab" || header["name"] != "name with | pipe" {
		t.Fatalf("unexpected header: %#v", header)
	}
	extension := result.Document.Fields["extension"].(map[string]any)
	want := map[string]any{"msg": "hello world", "act": "deny", "equation": "a=b", "path": `c:\tmp`}
	if !reflect.DeepEqual(extension, want) {
		t.Fatalf("extension = %#v, want %#v", extension, want)
	}
}

func TestCEFMalformedExtensionPreservesUnmatchedSuffix(t *testing.T) {
	input := []byte(`CEF:0|V|P|1|100|event|4|malformed extension`)
	result := NewCEF().Parse(context.Background(), interpret.Payload{Bytes: input}, interpret.Limits{})
	if result.Status != interpret.StatusPartiallyParsed || len(result.Issues) != 1 || result.Issues[0].Code != "CEF_EXTENSION_MALFORMED" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if string(result.Document.Unmatched) != "malformed extension" {
		t.Fatalf("unmatched = %q", result.Document.Unmatched)
	}
}

func TestLEEFParsesCorpusCompatibilityDelimiter(t *testing.T) {
	payload := corpusFixture(t, "leef.log")
	result := NewLEEF().Parse(context.Background(), interpret.Payload{Bytes: payload}, interpret.Limits{})
	if result.Status != interpret.StatusParsed {
		t.Fatalf("status = %s, issues = %#v, unmatched = %q", result.Status, result.Issues, result.Document.Unmatched)
	}
	header := result.Document.Fields["header"].(map[string]any)
	if header["delimiter"] != "^" || header["attribute_delimiter"] != "^|" {
		t.Fatalf("unexpected delimiter metadata: %#v", header)
	}
	attributes := result.Document.Fields["attributes"].(map[string]any)
	if attributes["src"] != "10.0.0.8" || attributes["dstPort"] != "443" || attributes["action"] != "blocked" {
		t.Fatalf("unexpected attributes: %#v", attributes)
	}
}

func TestLEEFSupportsTabAndHexDelimiters(t *testing.T) {
	tests := []struct {
		name  string
		input string
		key   string
		value string
	}{
		{name: "v1 tab", input: "LEEF:1.0|V|P|1|id|src=192.0.2.1\tdst=198.51.100.2", key: "dst", value: "198.51.100.2"},
		{name: "v2 hex", input: "LEEF:2.0|V|P|1|id|x5E|src=192.0.2.1^dst=198.51.100.2", key: "dst", value: "198.51.100.2"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := NewLEEF().Parse(context.Background(), interpret.Payload{Bytes: []byte(test.input)}, interpret.Limits{})
			if result.Status != interpret.StatusParsed {
				t.Fatalf("unexpected result: %#v", result)
			}
			if got := result.Document.Fields["attributes"].(map[string]any)[test.key]; got != test.value {
				t.Fatalf("attribute = %#v", got)
			}
		})
	}
}

func TestLEEFMissingHeaderAndBadDelimiterAreInvalid(t *testing.T) {
	for _, test := range []struct {
		input string
		code  string
	}{
		{input: "LEEF:2.0|V|P|1|id", code: "LEEF_HEADER_FIELD_MISSING"},
		{input: "LEEF:2.0|V|P|1|id|0x0000|src=1", code: "LEEF_DELIMITER_INVALID"},
	} {
		result := NewLEEF().Parse(context.Background(), interpret.Payload{Bytes: []byte(test.input)}, interpret.Limits{})
		if result.Status != interpret.StatusInvalid || result.Issues[0].Code != test.code {
			t.Fatalf("input %q: %#v", test.input, result)
		}
	}
}

func TestLimitsCancellationAndInputImmutability(t *testing.T) {
	input := []byte(`CEF:0|V|P|1|id|name|3|a=1 b=2 c=3`)
	original := append([]byte(nil), input...)
	result := NewCEF().Parse(context.Background(), interpret.Payload{Bytes: input}, interpret.Limits{MaxInputBytes: len(input), MaxFields: 2})
	if result.Status != interpret.StatusPartiallyParsed || result.Issues[0].Code != "FIELD_LIMIT_EXCEEDED" || string(result.Document.Unmatched) != "c=3" {
		t.Fatalf("unexpected limited result: %#v", result)
	}
	if !reflect.DeepEqual(input, original) {
		t.Fatal("parser mutated input")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result = NewCEF().Parse(ctx, interpret.Payload{Bytes: input}, interpret.Limits{})
	if result.Status != interpret.StatusInvalid || result.Issues[0].Code != "PARSER_CANCELLED" {
		t.Fatalf("unexpected cancelled result: %#v", result)
	}
	result = NewCEF().Parse(context.Background(), interpret.Payload{Bytes: input}, interpret.Limits{MaxInputBytes: len(input) - 1})
	if result.Status != interpret.StatusInvalid || result.Issues[0].Code != "INPUT_TOO_LARGE" {
		t.Fatalf("unexpected oversized result: %#v", result)
	}
}

func TestDuplicateAttributesArePreservedInOrder(t *testing.T) {
	result := NewCEF().Parse(context.Background(), interpret.Payload{Bytes: []byte(`CEF:0|V|P|1|id|name|3|cs1=a cs1=b`)}, interpret.Limits{})
	got := result.Document.Fields["extension"].(map[string]any)["cs1"]
	if !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("duplicate values = %#v", got)
	}
}

func corpusFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "..", "tests", "corpus", "raw", name)
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
