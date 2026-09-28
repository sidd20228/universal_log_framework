package xmlparser_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/sidd20228/universal_log_framework/internal/interpret"
	xmlparser "github.com/sidd20228/universal_log_framework/internal/interpret/xml"
)

func TestParseCorpusXMLPreservesElementsAttributesAndTypes(t *testing.T) {
	t.Parallel()

	result := xmlparser.New().Parse(context.Background(), interpret.Payload{Bytes: corpusFixture(t, "xml.xml")}, interpret.Limits{})
	if result.Status != interpret.StatusParsed || len(result.Issues) != 0 {
		t.Fatalf("result = %#v", result)
	}
	root := result.Document.Fields["event"].(map[string]any)
	if got := root["@attributes"].(map[string]any)["synthetic"]; got != "true" {
		t.Fatalf("synthetic attribute = %#v", got)
	}
	if got := root["timestamp"]; got != "2026-09-29T10:20:29Z" {
		t.Fatalf("timestamp = %#v", got)
	}
	source := root["source"].(map[string]any)["@attributes"].(map[string]any)
	wantSource := map[string]any{"ip": "10.0.0.8", "port": "51514"}
	if !reflect.DeepEqual(source, wantSource) {
		t.Fatalf("source = %#v, want %#v", source, wantSource)
	}
}

func TestParsePreservesNamespacesRepeatedChildrenAndMixedText(t *testing.T) {
	t.Parallel()

	payload := []byte(`<root xmlns="urn:root" xmlns:x="urn:item" id="1">before<x:item>A</x:item><x:item code="b">B</x:item>after</root>`)
	result := xmlparser.New().Parse(context.Background(), interpret.Payload{Bytes: payload}, interpret.Limits{})
	if result.Status != interpret.StatusParsed {
		t.Fatalf("result = %#v", result)
	}
	root := result.Document.Fields["{urn:root}root"].(map[string]any)
	if root["#text"] != "beforeafter" {
		t.Fatalf("mixed text = %#v", root["#text"])
	}
	items := root["{urn:item}item"].([]any)
	if items[0] != "A" {
		t.Fatalf("first item = %#v", items[0])
	}
	second := items[1].(map[string]any)
	if second["#text"] != "B" || second["@attributes"].(map[string]any)["code"] != "b" {
		t.Fatalf("second item = %#v", second)
	}
}

func TestParseRejectsDTDAndEntities(t *testing.T) {
	t.Parallel()

	tests := []string{
		`<!DOCTYPE event [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><event>&xxe;</event>`,
		`<!doctype event [<!ENTITY nested "value">]><event>&nested;</event>`,
	}
	for _, payload := range tests {
		result := xmlparser.New().Parse(context.Background(), interpret.Payload{Bytes: []byte(payload)}, interpret.Limits{})
		assertIssue(t, result, xmlparser.IssueDTDForbidden)
	}

	undeclared := xmlparser.New().Parse(context.Background(), interpret.Payload{Bytes: []byte(`<event>&unknown;</event>`)}, interpret.Limits{})
	assertIssue(t, undeclared, xmlparser.IssueSyntax)

	standaloneDeclaration := xmlparser.New().Parse(context.Background(), interpret.Payload{Bytes: []byte(`<!ENTITY unsafe "value"><event/>`)}, interpret.Limits{})
	assertIssue(t, standaloneDeclaration, xmlparser.IssueEntityForbidden)
}

func TestParseRejectsTrailingRootsMalformedAndEmptyInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		payload string
		code    string
	}{
		{payload: `<one/><two/>`, code: xmlparser.IssueTrailingData},
		{payload: `<one>`, code: xmlparser.IssueSyntax},
		{payload: `text<one/>`, code: xmlparser.IssueSyntax},
		{payload: ``, code: xmlparser.IssueEmptyInput},
		{payload: " \t\r\n", code: xmlparser.IssueEmptyInput},
	}
	for _, test := range tests {
		result := xmlparser.New().Parse(context.Background(), interpret.Payload{Bytes: []byte(test.payload)}, interpret.Limits{})
		assertIssue(t, result, test.code)
	}
}

func TestParseEnforcesXMLLimits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload string
		limits  interpret.Limits
		code    string
	}{
		{name: "bytes", payload: `<a/>`, limits: interpret.Limits{MaxInputBytes: 3}, code: xmlparser.IssuePayloadTooLarge},
		{name: "depth", payload: `<a><b><c/></b></a>`, limits: interpret.Limits{MaxDepth: 2}, code: xmlparser.IssueDepthLimit},
		{name: "fields", payload: `<a x="1"><b/></a>`, limits: interpret.Limits{MaxFields: 2}, code: xmlparser.IssueFieldLimit},
		{name: "tokens", payload: `<a>text</a>`, limits: interpret.Limits{MaxTokens: 2}, code: xmlparser.IssueTokenLimit},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := xmlparser.New().Parse(context.Background(), interpret.Payload{Bytes: []byte(test.payload)}, test.limits)
			assertIssue(t, result, test.code)
		})
	}
}

func TestParseRejectsInvalidUTF8AndCancellation(t *testing.T) {
	t.Parallel()

	invalidUTF8 := xmlparser.New().Parse(context.Background(), interpret.Payload{Bytes: []byte{'<', 'a', '>', 0xff, '<', '/', 'a', '>'}}, interpret.Limits{})
	assertIssue(t, invalidUTF8, xmlparser.IssueInvalidUTF8)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	canceled := xmlparser.New().Parse(ctx, interpret.Payload{Bytes: []byte(`<a/>`)}, interpret.Limits{})
	assertIssue(t, canceled, xmlparser.IssueContextCanceled)
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
