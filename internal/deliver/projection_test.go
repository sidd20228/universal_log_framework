package deliver_test

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/deliver"
	"github.com/sidd20228/universal_log_framework/internal/envelope"
)

func TestProjectEnvelopeBuildsCompleteConnectorRecord(t *testing.T) {
	value := goldenEnvelope(t)
	value.Receipt.EnvironmentID = "prod-in"
	value.Receipt.InstanceID = "collector-a"
	value.Event["activity_id"] = json.Number("6")
	value.Event["time"] = "2026-09-29T10:20:29.123456Z"
	value.Event["severity_id"] = uint8(4)
	value.Event["dst_endpoint"] = map[string]any{"ip": netip.MustParseAddr("2001:db8::25"), "port": float64(443)}
	value.Event["connection_info"] = map[string]any{"protocol_name": "tcp"}
	for path, source := range map[string]string{
		"event.activity_id": "fields.activity", "event.time": "fields.time", "event.severity_id": "fields.severity",
		"event.dst_endpoint.ip": "fields.dst", "event.dst_endpoint.port": "fields.dport", "event.connection_info.protocol_name": "fields.protocol",
	} {
		value.Provenance[path] = envelope.FieldProvenance{Kind: "normalized", SourcePath: source, RuleID: "projection-test", MappingVersion: "golden/1.0.0"}
	}
	value.Quality.ProvenancePresent = 11
	value.Quality.ProvenanceTotal = 11
	value.Quality.Score = 14.0 / 15.0

	record, err := deliver.ProjectEnvelope(value)
	if err != nil {
		t.Fatal(err)
	}
	if record.ReceiptID != value.Receipt.ID || record.RevisionID != value.Processing.RevisionID || record.TenantID != "demo" {
		t.Fatalf("projected identity = %#v", record)
	}
	if record.EnvironmentID != "prod-in" || record.InstanceID != "collector-a" {
		t.Fatalf("origin identity = %q/%q", record.EnvironmentID, record.InstanceID)
	}
	if record.ClassUID == nil || *record.ClassUID != 4001 || record.ActivityID == nil || *record.ActivityID != 6 || record.SeverityID == nil || *record.SeverityID != 4 {
		t.Fatalf("projected taxonomy ids = class=%v activity=%v severity=%v", record.ClassUID, record.ActivityID, record.SeverityID)
	}
	if record.EventTime == nil || !record.EventTime.Equal(time.Date(2026, 9, 29, 10, 20, 29, 123456000, time.UTC)) {
		t.Fatalf("event time = %v", record.EventTime)
	}
	if record.Action != "deny" || record.Protocol != "tcp" {
		t.Fatalf("action/protocol = %q/%q", record.Action, record.Protocol)
	}
	if record.SourceIP == nil || *record.SourceIP != netip.MustParseAddr("10.0.0.8") || record.SourcePort == nil || *record.SourcePort != 51514 {
		t.Fatalf("source endpoint = %v:%v", record.SourceIP, record.SourcePort)
	}
	if record.DestinationIP == nil || *record.DestinationIP != netip.MustParseAddr("2001:db8::25") || record.DestinationPort == nil || *record.DestinationPort != 443 {
		t.Fatalf("destination endpoint = %v:%v", record.DestinationIP, record.DestinationPort)
	}
	if record.ParserID != "generic-json" || record.ParserVersion != "1.0.0" || record.RawSHA256 != value.Raw.SHA256 {
		t.Fatalf("parser/raw projection = %#v", record)
	}
	if len(record.IssueCodes) != 3 || record.IssueCodes[0] != "SOURCE_PROFILE_MISSING" {
		t.Fatalf("issue codes = %v", record.IssueCodes)
	}
	if !json.Valid(record.EnvelopeJSON) || bytes.Contains(record.EnvelopeJSON, []byte(`"raw_payload"`)) {
		t.Fatalf("envelope JSON is invalid or contains raw payload: %s", record.EnvelopeJSON)
	}
	var roundTrip envelope.Envelope
	if err := json.Unmarshal(record.EnvelopeJSON, &roundTrip); err != nil || roundTrip.Processing.RevisionID != value.Processing.RevisionID {
		t.Fatalf("round-trip envelope = %#v, %v", roundTrip, err)
	}
}

func TestProjectEnvelopeSupportsMetadataOnlyRevision(t *testing.T) {
	value := goldenEnvelope(t)
	value.Event = nil
	value.Provenance = nil
	value.Quality = envelope.Quality{}
	value.Processing.MappingVersion = ""
	value.Processing.Status = "UNPARSED"
	record, err := deliver.ProjectEnvelope(value)
	if err != nil {
		t.Fatal(err)
	}
	if record.ClassUID != nil || record.SourceIP != nil || record.IssueCodes == nil {
		t.Fatalf("metadata-only projection = %#v", record)
	}
}

func TestProjectEnvelopeRejectsInvalidEnvelope(t *testing.T) {
	value := goldenEnvelope(t)
	value.Raw.SHA256 = "not-a-digest"
	if _, err := deliver.ProjectEnvelope(value); err == nil {
		t.Fatal("ProjectEnvelope accepted an invalid envelope")
	}
}

func goldenEnvelope(t *testing.T) envelope.Envelope {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "envelope", "testdata", "envelope.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var value envelope.Envelope
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatal(err)
	}
	return value
}
