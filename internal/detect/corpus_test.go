package detect

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSyntheticCorpusCandidateGoldenTable(t *testing.T) {
	detector, err := NewDefault()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		fixture  string
		outcome  Outcome
		parserID string
		reason   string
	}{
		{"generic_syslog.log", OutcomeSelected, "generic-syslog", ReasonSelected},
		{"json_firewall.json", OutcomeSelected, "generic-json", ReasonSelected},
		{"json_ids.json", OutcomeSelected, "generic-json", ReasonSelected},
		{"cef.log", OutcomeSelected, "generic-cef", ReasonSelected},
		{"leef.log", OutcomeSelected, "generic-leef", ReasonSelected},
		{"key_value_firewall.log", OutcomeSelected, "generic-kv", ReasonSelected},
		{"csv.csv", OutcomeSelected, "generic-csv", ReasonSelected},
		{"xml.xml", OutcomeSelected, "generic-xml", ReasonSelected},
		{"router_text.log", OutcomeSelected, "generic-router-text", ReasonSelected},
		{"duplicate_keys.json", OutcomeSelected, "generic-json", ReasonSelected},
		{"repeated_occurrence_a.json", OutcomeSelected, "generic-json", ReasonSelected},
		{"repeated_occurrence_b.json", OutcomeSelected, "generic-json", ReasonSelected},
		{"malformed_json.json", OutcomeUnknown, "", ReasonBelowThreshold},
		{"unknown_proprietary.bin", OutcomeUnknown, "", ReasonBelowThreshold},
		{"invalid_utf8.bin", OutcomeUnknown, "", ReasonNoCandidate},
	} {
		t.Run(test.fixture, func(t *testing.T) {
			payload, err := os.ReadFile(filepath.Join("..", "..", "tests", "corpus", "raw", test.fixture))
			if err != nil {
				t.Fatal(err)
			}
			result, err := detector.Detect(context.Background(), bytes.NewReader(payload), Hints{})
			if err != nil {
				t.Fatal(err)
			}
			if result.Outcome != test.outcome || result.ReasonCode != test.reason {
				t.Fatalf("decision = (%s, %s), want (%s, %s); candidates=%+v", result.Outcome, result.ReasonCode, test.outcome, test.reason, result.Candidates)
			}
			if test.parserID == "" {
				if result.Selected != nil {
					t.Fatalf("unexpected parser selected: %+v", result.Selected)
				}
				return
			}
			if result.Selected == nil || result.Selected.ParserID != test.parserID {
				t.Fatalf("selected = %+v, want %s", result.Selected, test.parserID)
			}
		})
	}
}

func TestAmbiguousCorpusLikeInputRemainsUnparsed(t *testing.T) {
	jsonCandidate := candidateProber("generic-json", "json", 900)
	vendorCandidate := candidateProber("synthetic-vendor-json", "vendor-json", 850)
	detector, err := New(DefaultConfig(), []Prober{vendorCandidate, jsonCandidate})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(filepath.Join("..", "..", "tests", "corpus", "raw", "json_firewall.json"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := detector.Detect(context.Background(), bytes.NewReader(payload), Hints{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != OutcomeAmbiguous || result.Selected != nil || result.ReasonCode != ReasonAmbiguous {
		t.Fatalf("ambiguous input was forced to a parser: %+v", result)
	}
}
