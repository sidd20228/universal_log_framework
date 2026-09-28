package re2parser

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/interpret"
)

func TestRouterFixtureParsesWithNamedCaptures(t *testing.T) {
	parser := routerParser(t)
	payload := corpusFixture(t, "router_text.log")
	result := parser.Parse(context.Background(), interpret.Payload{Bytes: payload}, interpret.Limits{})
	if result.Status != interpret.StatusParsed {
		t.Fatalf("unexpected result: %#v", result)
	}
	want := map[string]any{
		"event":     "IFACE_DOWN",
		"timestamp": "2026-09-29T10:21:00Z",
		"device":    "lab-router-1",
		"interface": "xe-0/0/1",
		"reason":    "loss-of-signal",
	}
	if !reflect.DeepEqual(result.Document.Fields, want) {
		t.Fatalf("fields = %#v, want %#v", result.Document.Fields, want)
	}
}

func TestStrictConfigAndRE2Restrictions(t *testing.T) {
	config := Config{
		ConfigVersion: ConfigVersion,
		ID:            "lab-router-text",
		Version:       "1.0.0",
		Format:        "router-text",
		Pattern:       `^(?P<event>[A-Z_]+)$`,
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(encoded); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(Config) Config{
		"unanchored":       func(value Config) Config { value.Pattern = `(?P<event>.+)`; return value },
		"backreference":    func(value Config) Config { value.Pattern = `^(?P<x>a)\1$`; return value },
		"unknown required": func(value Config) Config { value.Required = []string{"missing"}; return value },
		"no named capture": func(value Config) Config { value.Pattern = `^.+$`; return value },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(mutate(config)); err == nil {
				t.Fatal("expected config rejection")
			}
		})
	}
	withUnknown := append(encoded[:len(encoded)-1], []byte(`,"executable":"plugin.so"}`)...)
	if _, err := LoadConfig(withUnknown); err == nil {
		t.Fatal("unknown field was accepted")
	}
}

func TestFixtureValidationRequiresPositiveNegativeAndExactFields(t *testing.T) {
	parser := routerParser(t)
	valid := corpusFixture(t, "router_text.log")
	fixtures := []Fixture{
		{
			Name:    "valid router",
			Input:   valid,
			Matches: true,
			Expected: map[string]string{
				"event": "IFACE_DOWN", "timestamp": "2026-09-29T10:21:00Z", "device": "lab-router-1",
				"interface": "xe-0/0/1", "reason": "loss-of-signal",
			},
		},
		{Name: "unknown", Input: corpusFixture(t, "unknown_proprietary.bin"), Matches: false},
	}
	if err := parser.ValidateFixtures(context.Background(), fixtures, interpret.Limits{}); err != nil {
		t.Fatal(err)
	}
	fixtures[0].Expected["device"] = "wrong"
	if err := parser.ValidateFixtures(context.Background(), fixtures, interpret.Limits{}); err == nil {
		t.Fatal("wrong fixture output was accepted")
	}
	if err := parser.ValidateFixtures(context.Background(), fixtures[:1], interpret.Limits{}); err == nil {
		t.Fatal("fixture set without a negative was accepted")
	}
}

func TestLimitsRequiredCaptureAndCancellation(t *testing.T) {
	parser, err := New(Config{
		ConfigVersion: ConfigVersion,
		ID:            "optional-test",
		Version:       "1.0.0",
		Format:        "text",
		Pattern:       `^(?P<first>a)(?P<second>b)?$`,
		Required:      []string{"second"},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := parser.Parse(context.Background(), interpret.Payload{Bytes: []byte("a")}, interpret.Limits{})
	if result.Status != interpret.StatusPartiallyParsed || result.Issues[0].Code != "RE2_REQUIRED_CAPTURE_MISSING" {
		t.Fatalf("unexpected required result: %#v", result)
	}
	result = parser.Parse(context.Background(), interpret.Payload{Bytes: []byte("ab")}, interpret.Limits{MaxFields: 1})
	if result.Status != interpret.StatusPartiallyParsed || result.Issues[0].Code != "FIELD_LIMIT_EXCEEDED" {
		t.Fatalf("unexpected field-limited result: %#v", result)
	}
	result = parser.Parse(context.Background(), interpret.Payload{Bytes: []byte("ab")}, interpret.Limits{MaxInputBytes: 1})
	if result.Status != interpret.StatusInvalid || result.Issues[0].Code != "INPUT_TOO_LARGE" {
		t.Fatalf("unexpected byte-limited result: %#v", result)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result = parser.Parse(ctx, interpret.Payload{Bytes: []byte("ab")}, interpret.Limits{})
	if result.Status != interpret.StatusInvalid || result.Issues[0].Code != "PARSER_CANCELLED" {
		t.Fatalf("unexpected cancelled result: %#v", result)
	}
}

func TestPathologicalPatternCompletesWithoutBacktracking(t *testing.T) {
	parser, err := New(Config{
		ConfigVersion: ConfigVersion,
		ID:            "linear-time-test",
		Version:       "1.0.0",
		Format:        "text",
		Pattern:       `^(?P<body>(a+)+)b$`,
	})
	if err != nil {
		t.Fatal(err)
	}
	input := []byte(strings.Repeat("a", 250_000))
	done := make(chan interpret.ParseResult, 1)
	go func() {
		done <- parser.Parse(context.Background(), interpret.Payload{Bytes: input}, interpret.Limits{MaxInputBytes: len(input)})
	}()
	select {
	case result := <-done:
		if result.Status != interpret.StatusInvalid || result.Issues[0].Code != "RE2_NO_MATCH" {
			t.Fatalf("unexpected result: %#v", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RE2 match exceeded bounded regression timeout")
	}
}

func TestDescriptorIsDefensiveCopy(t *testing.T) {
	parser := routerParser(t)
	first := parser.Descriptor()
	first.Formats[0] = "mutated"
	if parser.Descriptor().Formats[0] != "router-text" {
		t.Fatal("descriptor formats were mutable")
	}
}

func routerParser(t *testing.T) *Parser {
	t.Helper()
	parser, err := New(Config{
		ConfigVersion: ConfigVersion,
		ID:            "lab-router-text",
		Version:       "1.0.0",
		Format:        "router-text",
		Pattern:       `^(?P<event>[A-Z_]+)\|ts=(?P<timestamp>[^|]+)\|device=(?P<device>[^|]+)\|iface=(?P<interface>[^|]+)\|reason=(?P<reason>[^|]+)\|synthetic=true\n$`,
		Required:      []string{"event", "timestamp", "device", "interface", "reason"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return parser
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
