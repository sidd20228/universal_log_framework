package mapping_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/envelope"
	"github.com/sidd20228/universal_log_framework/internal/interpret"
	"github.com/sidd20228/universal_log_framework/internal/interpret/mapping"
	"github.com/sidd20228/universal_log_framework/internal/model"
)

func TestMappingTargetsCoverEveryCanonicalEnvelopeLeaf(t *testing.T) {
	config := mapping.Config{
		ConfigVersion: mapping.ConfigVersion, ID: "target-parity", Version: "1.0.0",
		Rules: []mapping.Rule{
			{ID: "class-uid", From: "fields.class_uid", To: "event.class_uid", Convert: mapping.ConvertInteger, Required: true},
			{ID: "class-name", From: "fields.class_name", To: "event.class_name", Convert: mapping.ConvertString, Required: true},
			{ID: "activity-id", From: "fields.activity_id", To: "event.activity_id", Convert: mapping.ConvertInteger},
			{ID: "activity", From: "fields.activity", To: "event.activity", Convert: mapping.ConvertString},
			{ID: "time", From: "fields.time", To: "event.time", Convert: mapping.ConvertTimestamp, TimestampLayouts: []string{"RFC3339Nano"}},
			{ID: "action", From: "fields.action", To: "event.action", Convert: mapping.ConvertLowercase, Lookup: "action"},
			{ID: "status", From: "fields.status", To: "event.status", Convert: mapping.ConvertLowercase},
			{ID: "severity-id", From: "fields.severity_id", To: "event.severity_id", Convert: mapping.ConvertInteger},
			{ID: "severity", From: "fields.severity", To: "event.severity", Convert: mapping.ConvertLowercase, Lookup: "severity"},
			{ID: "src-ip", From: "fields.src_ip", To: "event.src_endpoint.ip", Convert: mapping.ConvertIP},
			{ID: "src-port", From: "fields.src_port", To: "event.src_endpoint.port", Convert: mapping.ConvertPort},
			{ID: "src-host", From: "fields.src_host", To: "event.src_endpoint.hostname", Convert: mapping.ConvertLowercase},
			{ID: "src-mac", From: "fields.src_mac", To: "event.src_endpoint.mac", Convert: mapping.ConvertLowercase},
			{ID: "dst-ip", From: "fields.dst_ip", To: "event.dst_endpoint.ip", Convert: mapping.ConvertIP},
			{ID: "dst-port", From: "fields.dst_port", To: "event.dst_endpoint.port", Convert: mapping.ConvertPort},
			{ID: "dst-host", From: "fields.dst_host", To: "event.dst_endpoint.hostname", Convert: mapping.ConvertLowercase},
			{ID: "dst-mac", From: "fields.dst_mac", To: "event.dst_endpoint.mac", Convert: mapping.ConvertLowercase},
			{ID: "protocol-name", From: "fields.protocol", To: "event.connection_info.protocol_name", Convert: mapping.ConvertLowercase},
			{ID: "protocol-num", From: "fields.protocol_num", To: "event.connection_info.protocol_num", Convert: mapping.ConvertInteger},
			{ID: "device-type", From: "fields.device_type", To: "event.device.type", Convert: mapping.ConvertLowercase, Lookup: "device"},
			{ID: "device-host", From: "fields.device_host", To: "event.device.hostname", Convert: mapping.ConvertLowercase},
			{ID: "device-vendor", From: "fields.device_vendor", To: "event.device.vendor_name", Convert: mapping.ConvertString},
			{ID: "device-product", From: "fields.device_product", To: "event.device.product_name", Convert: mapping.ConvertString},
			{ID: "signature", From: "fields.signature", To: "event.finding.signature", Convert: mapping.ConvertString},
			{ID: "signature-id", From: "fields.signature_id", To: "event.finding.signature_id", Convert: mapping.ConvertInteger},
			{ID: "extension", From: "fields.vendor_code", To: "event.extensions.acme.code", Convert: mapping.ConvertString},
		},
		Taxonomies: map[string]map[string][]string{
			"action":   {"deny": {"block"}},
			"severity": {"medium": {"warning"}},
			"device":   {"firewall": {"fw"}},
		},
	}
	engine, err := mapping.New(config)
	if err != nil {
		t.Fatal(err)
	}
	document := interpret.ParsedDocument{Format: "synthetic", Fields: map[string]any{
		"class_uid": "2004", "class_name": "Detection Finding", "activity_id": "1", "activity": "Alert",
		"time": "2026-09-29T10:20:29Z", "action": "BLOCK", "status": "OPEN", "severity_id": "3", "severity": "WARNING",
		"src_ip": "10.0.0.8", "src_port": "51514", "src_host": "CLIENT.EXAMPLE", "src_mac": "02:00:00:00:00:08",
		"dst_ip": "198.51.100.25", "dst_port": "443", "dst_host": "SERVER.EXAMPLE", "dst_mac": "02:00:00:00:00:19",
		"protocol": "TCP", "protocol_num": "6", "device_type": "FW", "device_host": "EDGE-01",
		"device_vendor": "Synthetic", "device_product": "Reference IDS", "signature": "Synthetic alert", "signature_id": "900001",
		"vendor_code": "A-17", "opaque": "preserve-me",
	}}
	mapped := engine.Map(context.Background(), document)
	if len(mapped.Issues) != 0 || mapped.RequiredPresent != 2 || mapped.RequiredTotal != 2 {
		t.Fatalf("mapping result = %+v", mapped)
	}
	if mapped.Unmapped["fields.opaque"] != "preserve-me" {
		t.Fatalf("unmapped = %#v", mapped.Unmapped)
	}
	payload := []byte("synthetic raw event")
	digest := sha256.Sum256(payload)
	received := time.Date(2026, 9, 29, 10, 20, 29, 0, time.UTC)
	receipt := model.Receipt{
		ID: "0199a1f0-7c4a-7b2c-8e25-8b4627a1c501", TenantID: "demo", ReceivedAt: received,
		ListenerID: "test", Transport: model.TransportHTTP, Framing: model.Framing{Mode: model.FramingHTTPOctets, Complete: true, ObservedBytes: uint64(len(payload))},
		Raw:   model.RawReference{Ref: "raw/fixture", SHA256: fmt.Sprintf("%x", digest), SizeBytes: uint64(len(payload)), Compression: model.CompressionNone, Available: true},
		State: model.StateProcessing,
	}
	revision := model.Revision{
		ID: "0199a1f0-81b2-7680-89c3-d5c53fe8e501", ReceiptID: receipt.ID, PipelineVersion: "1.0.0", SchemaVersion: envelope.SchemaVersion,
		MappingVersion: "target-parity/1.0.0", Parser: &model.ParserIdentity{ID: "synthetic", Version: "1.0.0"}, Status: model.StatusParsed,
		Issues: []model.Issue{}, StartedAt: received, CompletedAt: received.Add(time.Millisecond),
	}
	built, err := envelope.Build(envelope.Input{Receipt: receipt, Revision: revision, Document: document, Mapping: mapped})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if len(built.Provenance) != parityLeafCount(built.Event) {
		t.Fatalf("provenance count = %d, event leaves = %d", len(built.Provenance), parityLeafCount(built.Event))
	}
}

func TestExternalTaxonomyArtifactIsStrictAndMerged(t *testing.T) {
	mappingJSON, err := json.Marshal(mapping.Config{
		ConfigVersion: mapping.ConfigVersion, ID: "external-taxonomy", Version: "1.0.0",
		Rules: []mapping.Rule{{ID: "action", From: "fields.action", To: "event.action", Convert: mapping.ConvertLowercase, Lookup: "action"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	taxonomyJSON := []byte(`{"config_version":"ulpf-taxonomies/1","taxonomies":{"action":{"deny":["block"]}}}`)
	engine, err := mapping.LoadConfigWithTaxonomies(mappingJSON, taxonomyJSON)
	if err != nil {
		t.Fatal(err)
	}
	result := engine.Map(context.Background(), interpret.ParsedDocument{Fields: map[string]any{"action": "BLOCK"}})
	if result.Event["action"] != "deny" || len(result.Issues) != 0 {
		t.Fatalf("result = %+v", result)
	}
	if _, err := mapping.LoadConfigWithTaxonomies(mappingJSON, append(taxonomyJSON, []byte(` {}`)...)); err == nil {
		t.Fatal("external taxonomy accepted trailing JSON")
	}
}

func parityLeafCount(value any) int {
	switch typed := value.(type) {
	case map[string]any:
		total := 0
		for _, child := range typed {
			total += parityLeafCount(child)
		}
		return total
	default:
		return 1
	}
}
