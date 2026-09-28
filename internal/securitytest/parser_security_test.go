package securitytest

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"github.com/sidd20228/universal_log_framework/internal/interpret"
	"github.com/sidd20228/universal_log_framework/internal/interpret/cef"
	jsonparser "github.com/sidd20228/universal_log_framework/internal/interpret/json"
	"github.com/sidd20228/universal_log_framework/internal/interpret/kv"
	"github.com/sidd20228/universal_log_framework/internal/interpret/re2parser"
	"github.com/sidd20228/universal_log_framework/internal/interpret/syslog"
	xmlparser "github.com/sidd20228/universal_log_framework/internal/interpret/xml"
)

var hostileLimits = interpret.Limits{
	MaxInputBytes: 4 << 10,
	MaxFields:     32,
	MaxDepth:      8,
	MaxTokens:     128,
}

func FuzzSyslogHeader(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("<34>1 2026-09-29T10:20:29Z host app 7 ID47 [meta@1 key=\"value\"] message"),
		[]byte("<13>Feb  5 17:32:18 host app[12]: message"),
		[]byte("<999>1 - - - - - -"),
		{0xff, 0x00, '<', '1', '3', '>'},
	} {
		f.Add(seed)
	}
	parser := syslog.New()
	f.Fuzz(func(t *testing.T, input []byte) {
		assertParserInvariants(t, parser, input)
	})
}

func FuzzCEFLEEFEscaping(f *testing.F) {
	seeds := []struct {
		leef  bool
		input []byte
	}{
		{false, []byte(`CEF:0|Vendor\|Lab|Product|1|id|name with \| pipe|5|msg=a\=b act=deny`)},
		{false, []byte(`CEF:0|V|P|1|id|name|3|path=c:\\tmp msg=tail\`)},
		{true, []byte("LEEF:1.0|V|P|1|id|src=192.0.2.1\tmsg=value")},
		{true, []byte(`LEEF:2.0|V|P|1|id|x5E|src=192.0.2.1^msg=a\^b`)},
	}
	for _, seed := range seeds {
		f.Add(seed.leef, seed.input)
	}
	f.Fuzz(func(t *testing.T, leef bool, input []byte) {
		if leef {
			assertParserInvariants(t, cef.NewLEEF(), input)
			return
		}
		assertParserInvariants(t, cef.NewCEF(), input)
	})
}

func FuzzJSONWrapper(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"event":{"source":"synthetic"},"ports":[0,65535]}`),
		[]byte(`{"duplicate":1,"duplicate":2}`),
		[]byte(`[[[[[[[[[0]]]]]]]]]`),
		[]byte(`{"unterminated":"value`),
		{0xff, 0xfe, '{', '}'},
	} {
		f.Add(seed)
	}
	parser := jsonparser.New()
	f.Fuzz(func(t *testing.T, input []byte) {
		assertParserInvariants(t, parser, input)
	})
}

func FuzzXMLWrapper(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`<event source="synthetic"><message>ok</message></event>`),
		[]byte(`<!DOCTYPE event [<!ENTITY x "expansion">]><event>&x;</event>`),
		[]byte(`<a><b><c><d><e><f><g><h><i/></h></g></f></e></d></c></b></a>`),
		[]byte(`<event key="one" key="two"/>`),
		{0xff, '<', 'x', '/', '>'},
	} {
		f.Add(seed)
	}
	parser := xmlparser.New()
	f.Fuzz(func(t *testing.T, input []byte) {
		assertParserInvariants(t, parser, input)
	})
}

func FuzzKVTokenizer(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`src=192.0.2.1 message="quoted value" action=allow`),
		[]byte(`duplicate=one duplicate=two`),
		[]byte(`message="unterminated\`),
		[]byte("key=value\x00next=value"),
		{0xff, '=', 'x'},
	} {
		f.Add(seed)
	}
	parser := kvparser.New()
	f.Fuzz(func(t *testing.T, input []byte) {
		assertParserInvariants(t, parser, input)
	})
}

func FuzzDeclarativeRE2(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("ab"),
		bytes.Repeat([]byte{'a'}, 1024),
		[]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"),
		{0xff, 'a', 'b'},
	} {
		f.Add(seed)
	}
	parser, err := re2parser.New(re2parser.Config{
		ConfigVersion: re2parser.ConfigVersion,
		ID:            "security-re2",
		Version:       "1.0.0",
		Format:        "synthetic-text",
		Pattern:       `^(?P<body>(a+)+)b$`,
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		assertParserInvariants(t, parser, input)
	})
}

func FuzzRE2Config(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"config_version":"ulpf-re2-parser/1","id":"synthetic","version":"1.0.0","format":"text","pattern":"^(?P<value>.*)$"}`),
		[]byte(`{"config_version":"ulpf-re2-parser/1","id":"synthetic","version":"1.0.0","format":"text","pattern":"(?P<value>.*)"}`),
		[]byte(`{"pattern":"^(?P<x>a)\\1$"}`),
		{0xff, 0x00, '{', '}'},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 66<<10 {
			return
		}
		first, firstErr := re2parser.LoadConfig(input)
		second, secondErr := re2parser.LoadConfig(input)
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatalf("config acceptance changed between identical calls: first=%v second=%v", firstErr, secondErr)
		}
		if firstErr == nil && !reflect.DeepEqual(first.Descriptor(), second.Descriptor()) {
			t.Fatalf("config descriptor is nondeterministic: first=%#v second=%#v", first.Descriptor(), second.Descriptor())
		}
	})
}

func TestSecurityHostileParserCorpus(t *testing.T) {
	tests := []struct {
		name      string
		parser    interpret.SyntaxParser
		input     []byte
		limits    interpret.Limits
		issueCode string
	}{
		{name: "json depth", parser: jsonparser.New(), input: []byte(`[[[0]]]`), limits: interpret.Limits{MaxInputBytes: 64, MaxDepth: 2, MaxFields: 8, MaxTokens: 32}, issueCode: jsonparser.IssueDepthLimit},
		{name: "json duplicate", parser: jsonparser.New(), input: []byte(`{"x":1,"x":2}`), limits: hostileLimits, issueCode: jsonparser.IssueDuplicateKey},
		{name: "xml dtd", parser: xmlparser.New(), input: []byte(`<!DOCTYPE x [<!ENTITY e "boom">]><x>&e;</x>`), limits: hostileLimits, issueCode: xmlparser.IssueDTDForbidden},
		{name: "xml depth", parser: xmlparser.New(), input: []byte(`<a><b><c/></b></a>`), limits: interpret.Limits{MaxInputBytes: 64, MaxDepth: 2, MaxFields: 8, MaxTokens: 32}, issueCode: xmlparser.IssueDepthLimit},
		{name: "kv token limit", parser: kvparser.New(), input: []byte(`a=1 b=2 c=3`), limits: interpret.Limits{MaxInputBytes: 64, MaxFields: 8, MaxDepth: 8, MaxTokens: 4}, issueCode: kvparser.IssueTokenLimit},
		{name: "cef invalid utf8", parser: cef.NewCEF(), input: []byte{'C', 'E', 'F', ':', 0xff}, limits: hostileLimits, issueCode: "INVALID_UTF8"},
		{name: "syslog oversized", parser: syslog.New(), input: bytes.Repeat([]byte{'x'}, 65), limits: interpret.Limits{MaxInputBytes: 64, MaxFields: 8, MaxDepth: 8, MaxTokens: 32}, issueCode: syslog.IssueInputTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := test.parser.Parse(context.Background(), interpret.Payload{Bytes: test.input}, test.limits)
			if !hasIssue(result, test.issueCode) {
				t.Fatalf("issues = %#v, want %s", result.Issues, test.issueCode)
			}
		})
	}
}

func assertParserInvariants(t *testing.T, parser interpret.SyntaxParser, input []byte) {
	t.Helper()
	if len(input) > 64<<10 {
		return
	}
	original := bytes.Clone(input)
	first := parser.Parse(context.Background(), interpret.Payload{Bytes: input}, hostileLimits)
	if !bytes.Equal(input, original) {
		t.Fatal("parser mutated input")
	}
	second := parser.Parse(context.Background(), interpret.Payload{Bytes: bytes.Clone(input)}, hostileLimits)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("parser output is nondeterministic: first=%#v second=%#v", first, second)
	}
	switch first.Status {
	case interpret.StatusParsed, interpret.StatusPartiallyParsed, interpret.StatusInvalid:
	default:
		t.Fatalf("invalid parse status %q", first.Status)
	}
	if first.Document.Format == "" {
		t.Fatal("parser returned an empty format")
	}
	if len(first.Document.Fields) > hostileLimits.MaxFields+8 {
		t.Fatalf("parser returned %d fields under a %d-field limit", len(first.Document.Fields), hostileLimits.MaxFields)
	}
	if len(first.Issues) > hostileLimits.MaxTokens+8 {
		t.Fatalf("parser returned an unbounded issue list of length %d", len(first.Issues))
	}
	for _, issue := range first.Issues {
		if issue.Code == "" || issue.Offset < 0 || issue.Offset > len(input) {
			t.Fatalf("unsafe issue metadata: %#v for %d-byte input", issue, len(input))
		}
	}
}

func hasIssue(result interpret.ParseResult, code string) bool {
	for _, issue := range result.Issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}
