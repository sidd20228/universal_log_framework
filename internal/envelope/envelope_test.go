package envelope_test

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/sidd20228/universal_log_framework/internal/envelope"
	"github.com/sidd20228/universal_log_framework/internal/interpret"
	"github.com/sidd20228/universal_log_framework/internal/interpret/mapping"
	"github.com/sidd20228/universal_log_framework/internal/model"
)

func TestBuildMatchesGoldenEnvelope(t *testing.T) {
	input := validInput()
	got, err := envelope.Build(input)
	if err != nil {
		t.Fatal(err)
	}
	if got.Processing.Confidence != nil {
		t.Fatal("builder fabricated parser confidence")
	}
	if got.Quality.Score != 8.0/9.0 || got.Quality.RequiredPresent != 3 || got.Quality.RequiredTotal != 4 || got.Quality.ProvenancePresent != 5 || got.Quality.ProvenanceTotal != 5 {
		t.Fatalf("quality = %+v", got.Quality)
	}
	encoded, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	want, err := os.ReadFile(filepath.Join("testdata", "envelope.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var gotJSON, wantJSON any
	if err := json.Unmarshal(encoded, &gotJSON); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(want, &wantJSON); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotJSON, wantJSON) {
		t.Fatalf("envelope does not match golden\ngot:\n%s\nwant:\n%s", encoded, want)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("built envelope failed validation: %v", err)
	}
}

func TestBuildRejectsBrokenCrossFieldInvariants(t *testing.T) {
	tests := map[string]func(*envelope.Input){
		"receipt revision mismatch": func(input *envelope.Input) { input.Revision.ReceiptID = "0199a1f0-7c4a-7b2c-8e25-8b4627a1c999" },
		"missing leaf provenance":   func(input *envelope.Input) { delete(input.Mapping.Provenance, "event.action") },
		"extra provenance": func(input *envelope.Input) {
			input.Mapping.Provenance["event.device.type"] = validProvenance("device", "fields.device")
		},
		"mapping identity mismatch": func(input *envelope.Input) { input.Revision.MappingVersion = "other/1.0.0" },
		"invalid endpoint port": func(input *envelope.Input) {
			input.Mapping.Event["src_endpoint"].(map[string]any)["port"] = int64(70000)
		},
		"parsed with incomplete required fields": func(input *envelope.Input) { input.Revision.Status = model.StatusParsed },
		"unparsed with trusted event":            func(input *envelope.Input) { input.Revision.Status = model.StatusUnparsed },
		"unmatched bytes differ":                 func(input *envelope.Input) { input.Mapping.Unmatched = []byte("different") },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := validInput()
			mutate(&input)
			if _, err := envelope.Build(input); err == nil {
				t.Fatal("Build accepted an invalid cross-field combination")
			}
		})
	}
}

func TestBuildCopiesParsedAndMappedMaterial(t *testing.T) {
	input := validInput()
	got, err := envelope.Build(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Document.Fields["action"] = "mutated"
	input.Document.Fields["binary"].([]byte)[0] = 'X'
	input.Mapping.Unmapped["fields.vendorCounter"] = "mutated"
	input.Mapping.Unmatched[0] = 'X'
	input.Mapping.Event["action"] = "allow"

	if got.Parsed.Fields["action"] != "blocked" || !bytes.Equal(got.Parsed.Fields["binary"].([]byte), []byte{0, 0xff}) {
		t.Fatalf("parsed fields changed with caller input: %#v", got.Parsed.Fields)
	}
	if got.Parsed.Unmapped["fields.vendorCounter"] != json.Number("17") || bytes.Equal(got.Parsed.Unmatched, input.Mapping.Unmatched) {
		t.Fatalf("preserved material aliases caller input: %+v", got.Parsed)
	}
	if got.Event["action"] != "deny" {
		t.Fatalf("event aliases caller input: %#v", got.Event)
	}
}

func TestIssueConversionIsBoundedAndControlSafe(t *testing.T) {
	input := validInput()
	input.ParseIssues = []interpret.Issue{{
		Code:     "bad code\n",
		Severity: interpret.IssueSeverity("BOGUS"),
		Offset:   7,
		Message:  strings.Repeat("x", 1100) + "\x00\n",
	}}
	got, err := envelope.Build(input)
	if err != nil {
		t.Fatal(err)
	}
	issue := got.Processing.Issues[1]
	if issue.Code != "BAD_CODE" || issue.Severity != model.SeverityWarning || issue.Offset == nil || *issue.Offset != 7 {
		t.Fatalf("converted issue = %+v", issue)
	}
	if len(issue.Message) > envelope.MaxIssueMessageBytes || !utf8.ValidString(issue.Message) {
		t.Fatalf("unsafe issue message length/encoding: %d", len(issue.Message))
	}
	for _, character := range issue.Message {
		if character < 0x20 || character == 0x7f {
			t.Fatalf("issue retained control character %#x", character)
		}
	}
}

func TestComputeQualityDoesNotExceedBounds(t *testing.T) {
	quality := envelope.ComputeQuality(mapping.Result{
		Event:           map[string]any{"class_uid": int64(1), "class_name": "x"},
		Provenance:      map[string]mapping.Provenance{"event.class_uid": validProvenance("class", "fields.type")},
		RequiredPresent: 5,
		RequiredTotal:   2,
	})
	if quality.Score != 0.75 || quality.RequiredPresent != 2 || quality.ProvenancePresent != 1 || quality.ProvenanceTotal != 2 {
		t.Fatalf("quality = %+v", quality)
	}
	empty := envelope.ComputeQuality(mapping.Result{})
	if empty.Score != 0 {
		t.Fatalf("empty score = %v, want zero", empty.Score)
	}
}

func validInput() envelope.Input {
	received := time.Date(2026, 9, 29, 10, 20, 30, 123456000, time.UTC)
	receiptID := "0199a1f0-7c4a-7b2c-8e25-8b4627a1c001"
	return envelope.Input{
		Receipt: model.Receipt{
			ID: receiptID, TenantID: "demo", ReceivedAt: received, ListenerID: "syslog-udp-5514",
			Transport: model.TransportSyslogUDP,
			Peer:      &model.Peer{IP: netip.MustParseAddr("192.0.2.10"), Port: 49152},
			Framing:   model.Framing{Mode: model.FramingDatagram, Complete: true, ObservedBytes: 143},
			Raw: model.RawReference{
				Ref: "raw/2026/09/29/receipt.bin", SHA256: strings.Repeat("a", 64), SizeBytes: 143,
				EncodingHint: "utf-8", Compression: model.CompressionNone, Available: true,
			},
			State: model.StateAccepted,
		},
		Revision: model.Revision{
			ID: "0199a1f0-81b2-7680-89c3-d5c53fe8e002", ReceiptID: receiptID,
			PipelineVersion: "0.1.0", SchemaVersion: envelope.SchemaVersion, MappingVersion: "golden/1.0.0",
			Parser:    &model.ParserIdentity{ID: "generic-json", Version: "1.0.0"},
			Status:    model.StatusPartiallyParsed,
			Issues:    []model.Issue{{Code: "SOURCE_PROFILE_MISSING", Stage: "enrichment", Severity: model.SeverityWarning, Message: "source profile was not configured"}},
			StartedAt: received.Add(time.Millisecond), CompletedAt: received.Add(2 * time.Millisecond),
		},
		Document: interpret.ParsedDocument{
			Format:    "json",
			Fields:    map[string]any{"type": "traffic", "src": "10.0.0.8", "sport": json.Number("51514"), "action": "blocked", "vendorCounter": json.Number("17"), "binary": []byte{0, 0xff}},
			Unmatched: []byte{0xde, 0xad},
		},
		Mapping: mapping.Result{
			Event: map[string]any{
				"class_uid": int64(4001), "class_name": "Network Activity", "action": "deny",
				"src_endpoint": map[string]any{"ip": netip.MustParseAddr("10.0.0.8"), "port": uint16(51514)},
			},
			Unmapped:  map[string]any{"fields.vendorCounter": json.Number("17"), "fields.binary": []byte{0, 0xff}},
			Unmatched: []byte{0xde, 0xad},
			Provenance: map[string]mapping.Provenance{
				"event.class_uid":         validProvenance("class-uid", "fields.type"),
				"event.class_name":        validProvenance("class-name", "fields.type"),
				"event.action":            validProvenance("action", "fields.action"),
				"event.src_endpoint.ip":   validProvenance("source-ip", "fields.src"),
				"event.src_endpoint.port": validProvenance("source-port", "fields.sport"),
			},
			Issues:          []mapping.Issue{{Code: mapping.IssueConversionFailed, RuleID: "severity", SourcePath: "fields.severity", TargetPath: "event.severity_id", Message: "text is not an integer"}},
			RequiredPresent: 3,
			RequiredTotal:   4,
		},
		ParseIssues: []interpret.Issue{{Code: "PARSER_ESCAPE_INVALID", Severity: interpret.SeverityWarning, Offset: 4, Message: "invalid escape was preserved"}},
	}
}

func validProvenance(rule, source string) mapping.Provenance {
	return mapping.Provenance{
		Kind: mapping.ProvenanceNormalized, SourcePath: source, RuleID: rule,
		MappingID: "golden", MappingVersion: "1.0.0",
	}
}

func TestBuildIsDeterministic(t *testing.T) {
	first, err := envelope.Build(validInput())
	if err != nil {
		t.Fatal(err)
	}
	second, err := envelope.Build(validInput())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("builds differ:\n%#v\n%#v", first, second)
	}
}

func TestBuildRepresentsInfrastructureErrorWithoutTrustedEvent(t *testing.T) {
	input := validInput()
	input.Revision.Status = model.StatusError
	input.Revision.Parser = nil
	input.Revision.MappingVersion = ""
	input.Revision.Issues = []model.Issue{{
		Code: "PROCESSING_TIMEOUT", Stage: "parsing", Severity: model.SeverityError,
		Retryable: true, Message: "processing timed out",
	}}
	input.Mapping = mapping.Result{Unmatched: append([]byte(nil), input.Document.Unmatched...)}
	input.ParseIssues = nil
	got, err := envelope.Build(input)
	if err != nil {
		t.Fatal(err)
	}
	if got.Event != nil || got.Provenance != nil || got.Quality.Score != 0 || got.Processing.Parser != nil {
		t.Fatalf("error envelope contains unsupported trusted output: %+v", got)
	}
}
