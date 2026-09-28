package mapping_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/interpret"
	"github.com/sidd20228/universal_log_framework/internal/interpret/cef"
	jsonparser "github.com/sidd20228/universal_log_framework/internal/interpret/json"
	"github.com/sidd20228/universal_log_framework/internal/interpret/mapping"
	"github.com/sidd20228/universal_log_framework/internal/interpret/re2parser"
	"github.com/sidd20228/universal_log_framework/internal/interpret/syslog"
)

func TestTrafficGoldenMappingsAcrossKVCEFSyslog(t *testing.T) {
	type sourceCase struct {
		name      string
		document  interpret.ParsedDocument
		source    map[string]string
		timestamp bool
	}

	keyValuePayload := readCorpus(t, "key_value_firewall.log")
	keyValueParser, err := re2parser.New(re2parser.Config{
		ConfigVersion: re2parser.ConfigVersion,
		ID:            "fixture-kv",
		Version:       "1.0.0",
		Format:        "kv",
		Pattern:       `^time=(?P<time>\S+) type=(?P<type>\S+) src=(?P<src>\S+) dst=(?P<dst>\S+) sport=(?P<sport>\S+) dport=(?P<dport>\S+) proto=(?P<proto>\S+) action=(?P<action>\S+) device=(?P<device>\S+) synthetic=(?P<synthetic>\S+)\n?$`,
	})
	if err != nil {
		t.Fatal(err)
	}
	keyValueResult := keyValueParser.Parse(context.Background(), interpret.Payload{Bytes: keyValuePayload}, interpret.Limits{})
	cefResult := cef.NewCEF().Parse(context.Background(), interpret.Payload{Bytes: readCorpus(t, "cef.log")}, interpret.Limits{})
	syslogResult := syslog.New().Parse(context.Background(), interpret.Payload{Bytes: readCorpus(t, "generic_syslog.log")}, interpret.Limits{})
	for name, result := range map[string]interpret.ParseResult{"kv": keyValueResult, "cef": cefResult, "syslog": syslogResult} {
		if result.Status == interpret.StatusInvalid {
			t.Fatalf("%s fixture did not parse: %+v", name, result.Issues)
		}
	}

	cases := []sourceCase{
		{
			name:     "kv",
			document: keyValueResult.Document,
			source: map[string]string{
				"time": "fields.time", "type": "fields.type", "src": "fields.src", "dst": "fields.dst",
				"sport": "fields.sport", "dport": "fields.dport", "protocol": "fields.proto", "action": "fields.action",
			},
			timestamp: true,
		},
		{
			name:     "cef",
			document: cefResult.Document,
			source: map[string]string{
				"type": "fields.header.name", "src": "fields.extension.src", "dst": "fields.extension.dst",
				"sport": "fields.extension.spt", "dport": "fields.extension.dpt", "protocol": "fields.extension.proto", "action": "fields.extension.act",
			},
		},
		{
			name:     "syslog",
			document: syslogResult.Document,
			source: map[string]string{
				"time": "fields.timestamp", "type": "fields.msg_id",
				"src": "fields.structured_data.net.parameters.src.value", "dst": "fields.structured_data.net.parameters.dst.value",
				"sport": "fields.structured_data.net.parameters.spt.value", "dport": "fields.structured_data.net.parameters.dpt.value",
				"protocol": "fields.structured_data.net.parameters.proto.value", "action": "fields.structured_data.net.parameters.action.value",
			},
			timestamp: true,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			engine := loadEngine(t, trafficConfig("traffic-"+test.name, test.source))
			result := engine.Map(context.Background(), test.document)
			if len(result.Issues) != 0 {
				t.Fatalf("mapping issues = %+v", result.Issues)
			}
			want := map[string]any{
				"class_uid":  int64(4001),
				"class_name": "Network Activity",
				"activity":   "Traffic",
				"action":     "deny",
				"src_endpoint": map[string]any{
					"ip": netip.MustParseAddr("10.0.0.8"), "port": uint16(51514),
				},
				"dst_endpoint": map[string]any{
					"ip": netip.MustParseAddr("198.51.100.25"), "port": uint16(443),
				},
				"connection_info": map[string]any{"protocol_name": "tcp"},
			}
			if test.timestamp {
				want["time"] = time.Date(2026, 9, 29, 10, 20, 29, 0, time.UTC)
			}
			if !reflect.DeepEqual(result.Event, want) {
				t.Fatalf("event = %#v\nwant  = %#v", result.Event, want)
			}
			if len(result.Provenance) != countLeaves(result.Event) {
				t.Fatalf("provenance count = %d, event leaves = %d", len(result.Provenance), countLeaves(result.Event))
			}
			for target, provenance := range result.Provenance {
				if provenance.MappingID != "traffic-"+test.name || provenance.MappingVersion != "1.0.0" || provenance.RuleID == "" || provenance.SourcePath == "" {
					t.Fatalf("provenance %s = %+v", target, provenance)
				}
			}
		})
	}
}

func TestJSONFirewallAndIDSGoldenMappingsPreserveUnknownFields(t *testing.T) {
	firewallParsed := jsonparser.New().Parse(context.Background(), interpret.Payload{Bytes: readCorpus(t, "json_firewall.json")}, interpret.Limits{})
	firewall := loadEngine(t, firewallConfig()).Map(context.Background(), firewallParsed.Document)
	if len(firewall.Issues) != 0 {
		t.Fatalf("firewall issues = %+v", firewall.Issues)
	}
	if firewall.Event["action"] != "allow" || firewall.Event["device"].(map[string]any)["type"] != "firewall" {
		t.Fatalf("firewall event = %#v", firewall.Event)
	}
	if firewall.Unmapped["fields.synthetic"] != true {
		t.Fatalf("unmapped = %#v, want synthetic source field", firewall.Unmapped)
	}
	if _, mappedStillPresent := firewall.Unmapped["fields.src_ip"]; mappedStillPresent {
		t.Fatal("successfully mapped field remained unmapped")
	}

	idsParsed := jsonparser.New().Parse(context.Background(), interpret.Payload{Bytes: readCorpus(t, "json_ids.json")}, interpret.Limits{})
	ids := loadEngine(t, idsConfig()).Map(context.Background(), idsParsed.Document)
	if len(ids.Issues) != 0 {
		t.Fatalf("IDS issues = %+v", ids.Issues)
	}
	if ids.Event["class_uid"] != int64(2004) || ids.Event["class_name"] != "Detection Finding" {
		t.Fatalf("IDS class = %#v", ids.Event)
	}
	finding := ids.Event["finding"].(map[string]any)
	if finding["signature"] != "Synthetic TLS Policy Alert" || finding["signature_id"] != int64(900001) {
		t.Fatalf("IDS finding = %#v", finding)
	}
}

func TestConversionFailureAndTaxonomyMissRemainUnmapped(t *testing.T) {
	config := trafficConfig("failure", map[string]string{
		"type": "fields.type", "src": "fields.src", "dst": "fields.dst", "sport": "fields.sport",
		"dport": "fields.dport", "protocol": "fields.proto", "action": "fields.action",
	})
	engine := loadEngine(t, config)
	document := interpret.ParsedDocument{Fields: map[string]any{
		"type": "traffic", "src": "not-an-ip", "dst": "198.51.100.25", "sport": "99999",
		"dport": "443", "proto": "tcp", "action": "vendor-magic", "opaque": "keep-me",
	}}
	result := engine.Map(context.Background(), document)
	for _, code := range []string{mapping.IssueConversionFailed, mapping.IssueTaxonomyMiss} {
		if !hasMappingIssue(result, code) {
			t.Fatalf("issues = %+v, want %s", result.Issues, code)
		}
	}
	if _, exists := result.Event["action"]; exists {
		t.Fatal("unknown vendor action entered trusted event")
	}
	for _, path := range []string{"fields.src", "fields.sport", "fields.action", "fields.opaque"} {
		if _, preserved := result.Unmapped[path]; !preserved {
			t.Fatalf("unmapped source %q was not preserved: %#v", path, result.Unmapped)
		}
	}
}

func TestRequiredMissingFieldProducesIssue(t *testing.T) {
	config := mapping.Config{
		ConfigVersion: mapping.ConfigVersion,
		ID:            "required-test",
		Version:       "1.0.0",
		Rules: []mapping.Rule{{
			ID: "source-ip", From: "fields.src", To: "event.src_endpoint.ip", Convert: mapping.ConvertIP, Required: true,
		}},
	}
	result := loadEngine(t, config).Map(context.Background(), interpret.ParsedDocument{Fields: map[string]any{"other": "value"}})
	if !hasMappingIssue(result, mapping.IssueRequiredMissing) || result.RequiredPresent != 0 || result.RequiredTotal != 1 {
		t.Fatalf("result = %+v", result)
	}
	if result.Unmapped["fields.other"] != "value" {
		t.Fatalf("unmapped = %#v", result.Unmapped)
	}
}

func TestLoadConfigIsStrictBoundedAndDescriptorImmutable(t *testing.T) {
	config := firewallConfig()
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := mapping.LoadConfig(encoded)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := engine.Descriptor()
	if descriptor.ID() != config.ID || descriptor.Version() != config.Version || len(descriptor.Digest()) != 64 {
		t.Fatalf("descriptor = %s@%s %s", descriptor.ID(), descriptor.Version(), descriptor.Digest())
	}
	config.ID = "mutated"
	config.Rules[0].From = "fields.mutated"
	if again := engine.Descriptor(); again.ID() != descriptor.ID() || again.Digest() != descriptor.Digest() {
		t.Fatal("engine descriptor changed after caller config mutation")
	}

	unknown := bytes.Replace(encoded, []byte(`"version":"1.0.0"`), []byte(`"version":"1.0.0","surprise":true`), 1)
	if _, err := mapping.LoadConfig(unknown); err == nil {
		t.Fatal("LoadConfig() accepted an unknown field")
	}
	tooMany := mapping.Config{ConfigVersion: mapping.ConfigVersion, ID: "too-many", Version: "1.0.0"}
	for index := 0; index < mapping.MaxRules+1; index++ {
		tooMany.Rules = append(tooMany.Rules, mapping.Rule{
			ID: "rule-" + strings.Repeat("x", index%2), From: "fields.value", To: "event.class_name", Convert: mapping.ConvertString,
		})
	}
	if _, err := mapping.New(tooMany); err == nil {
		t.Fatal("New() accepted more than MaxRules")
	}
}

func TestRejectsUnallowlistedTargetAndAmbiguousTaxonomy(t *testing.T) {
	config := mapping.Config{
		ConfigVersion: mapping.ConfigVersion,
		ID:            "unsafe",
		Version:       "1.0.0",
		Rules: []mapping.Rule{{
			ID: "unsafe-target", From: "fields.src", To: "receipt.peer.ip", Convert: mapping.ConvertIP,
		}},
	}
	if _, err := mapping.New(config); err == nil {
		t.Fatal("New() accepted a target outside the event allowlist")
	}

	config.Rules[0] = mapping.Rule{ID: "action", From: "fields.action", To: "event.action", Convert: mapping.ConvertLowercase, Lookup: "action-v1"}
	config.Taxonomies = map[string]map[string][]string{
		"action-v1": {"allow": {"same"}, "deny": {"same"}},
	}
	if _, err := mapping.New(config); err == nil {
		t.Fatal("New() accepted one alias with two meanings")
	}
}

func TestEngineIsDeterministicAndConcurrentSafe(t *testing.T) {
	config := trafficConfig("concurrent", map[string]string{
		"type": "fields.type", "src": "fields.src", "dst": "fields.dst", "sport": "fields.sport",
		"dport": "fields.dport", "protocol": "fields.proto", "action": "fields.action",
	})
	engine := loadEngine(t, config)
	document := interpret.ParsedDocument{Fields: map[string]any{
		"type": "traffic", "src": "::ffff:10.0.0.8", "dst": "198.51.100.25", "sport": "51514",
		"dport": json.Number("443"), "proto": "TCP", "action": "BLOCKED", "opaque": []byte{0, 1, 255},
	}}
	want := engine.Map(context.Background(), document)
	if got := want.Event["src_endpoint"].(map[string]any)["ip"]; got != netip.MustParseAddr("10.0.0.8") {
		t.Fatalf("canonical IPv4 = %v", got)
	}

	errors := make(chan error, 32)
	for index := 0; index < cap(errors); index++ {
		go func() {
			got := engine.Map(context.Background(), document)
			if !reflect.DeepEqual(got, want) {
				errors <- fmt.Errorf("concurrent result differs: %#v", got)
				return
			}
			errors <- nil
		}()
	}
	for index := 0; index < cap(errors); index++ {
		if err := <-errors; err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(want.Unmapped["fields.opaque"].([]byte), []byte{0, 1, 255}) {
		t.Fatalf("unmapped bytes changed: %v", want.Unmapped["fields.opaque"])
	}
}

func TestExplicitTimestampTimezoneAndAmbiguousSelector(t *testing.T) {
	config := mapping.Config{
		ConfigVersion: mapping.ConfigVersion,
		ID:            "explicit-timezone",
		Version:       "1.0.0",
		Rules: []mapping.Rule{
			{ID: "time", From: "fields.time", To: "event.time", Convert: mapping.ConvertTimestamp, TimestampLayouts: []string{"2006-01-02 15:04:05"}, Timezone: "+05:30"},
			{ID: "source-ip", From: "fields.items.source.value", To: "event.src_endpoint.ip", Convert: mapping.ConvertIP},
		},
	}
	engine := loadEngine(t, config)
	result := engine.Map(context.Background(), interpret.ParsedDocument{Fields: map[string]any{
		"time": "2026-09-29 15:50:29",
		"items": []any{
			map[string]any{"name": "source", "value": "10.0.0.8"},
			map[string]any{"name": "source", "value": "10.0.0.9"},
		},
	}})
	if result.Event["time"] != time.Date(2026, 9, 29, 10, 20, 29, 0, time.UTC) {
		t.Fatalf("time = %v", result.Event["time"])
	}
	if !hasMappingIssue(result, mapping.IssueSourceAmbiguous) {
		t.Fatalf("issues = %+v", result.Issues)
	}
	if _, exists := result.Event["src_endpoint"]; exists {
		t.Fatal("ambiguous source selector produced a trusted target")
	}
}

func TestStrictDecodeRejectsUnknownRuleFieldAndTrailingValue(t *testing.T) {
	unknownRule := []byte(`{"config_version":"ulpf-mapping/1","id":"strict","version":"1.0.0","rules":[{"id":"name","from":"fields.name","to":"event.class_name","convert":"string","guess":true}]}`)
	if _, err := mapping.LoadConfig(unknownRule); err == nil {
		t.Fatal("LoadConfig accepted an unknown nested rule field")
	}
	valid, err := json.Marshal(mapping.Config{
		ConfigVersion: mapping.ConfigVersion,
		ID:            "strict",
		Version:       "1.0.0",
		Rules:         []mapping.Rule{{ID: "name", From: "fields.name", To: "event.class_name", Convert: mapping.ConvertString}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mapping.LoadConfig(append(valid, []byte(` {}`)...)); err == nil {
		t.Fatal("LoadConfig accepted a trailing JSON value")
	}
}

func trafficConfig(id string, source map[string]string) mapping.Config {
	rules := []mapping.Rule{
		{ID: "class-uid", From: source["type"], To: "event.class_uid", Convert: mapping.ConvertLowercase, Lookup: "traffic-class-uid", Required: true},
		{ID: "class-name", From: source["type"], To: "event.class_name", Convert: mapping.ConvertLowercase, Lookup: "traffic-class-name", Required: true},
		{ID: "activity", From: source["type"], To: "event.activity", Convert: mapping.ConvertLowercase, Lookup: "traffic-activity", Required: true},
		{ID: "source-ip", From: source["src"], To: "event.src_endpoint.ip", Convert: mapping.ConvertIP, Required: true},
		{ID: "destination-ip", From: source["dst"], To: "event.dst_endpoint.ip", Convert: mapping.ConvertIP, Required: true},
		{ID: "source-port", From: source["sport"], To: "event.src_endpoint.port", Convert: mapping.ConvertPort},
		{ID: "destination-port", From: source["dport"], To: "event.dst_endpoint.port", Convert: mapping.ConvertPort},
		{ID: "protocol", From: source["protocol"], To: "event.connection_info.protocol_name", Convert: mapping.ConvertLowercase},
		{ID: "action", From: source["action"], To: "event.action", Convert: mapping.ConvertLowercase, Lookup: "action-v1", Required: true},
	}
	if source["time"] != "" {
		rules = append(rules, mapping.Rule{ID: "time", From: source["time"], To: "event.time", Convert: mapping.ConvertTimestamp, TimestampLayouts: []string{"RFC3339Nano"}})
	}
	return mapping.Config{
		ConfigVersion: mapping.ConfigVersion,
		ID:            id,
		Version:       "1.0.0",
		Rules:         rules,
		Taxonomies: map[string]map[string][]string{
			"traffic-class-uid":  {"4001": {"traffic", "traffic denied"}},
			"traffic-class-name": {"Network Activity": {"traffic", "traffic denied"}},
			"traffic-activity":   {"Traffic": {"traffic", "traffic denied"}},
			"action-v1":          {"allow": {"allow", "permit", "accept"}, "deny": {"deny", "blocked", "block", "drop", "reject"}},
		},
	}
}

func firewallConfig() mapping.Config {
	config := trafficConfig("json-firewall", map[string]string{
		"time": "fields.timestamp", "type": "fields.event_type", "src": "fields.src_ip", "dst": "fields.dst_ip",
		"sport": "fields.src_port", "dport": "fields.dst_port", "protocol": "fields.protocol", "action": "fields.action",
	})
	config.Rules = append(config.Rules, mapping.Rule{
		ID: "device-type", From: "fields.device_type", To: "event.device.type", Convert: mapping.ConvertLowercase, Lookup: "device-type-v1",
	})
	config.Taxonomies["device-type-v1"] = map[string][]string{"firewall": {"firewall"}}
	return config
}

func idsConfig() mapping.Config {
	return mapping.Config{
		ConfigVersion: mapping.ConfigVersion,
		ID:            "json-ids",
		Version:       "1.0.0",
		Rules: []mapping.Rule{
			{ID: "class-uid", From: "fields.event_type", To: "event.class_uid", Convert: mapping.ConvertLowercase, Lookup: "ids-class-uid", Required: true},
			{ID: "class-name", From: "fields.event_type", To: "event.class_name", Convert: mapping.ConvertLowercase, Lookup: "ids-class-name", Required: true},
			{ID: "time", From: "fields.timestamp", To: "event.time", Convert: mapping.ConvertTimestamp, TimestampLayouts: []string{"RFC3339Nano"}},
			{ID: "source-ip", From: "fields.src_ip", To: "event.src_endpoint.ip", Convert: mapping.ConvertIP},
			{ID: "source-port", From: "fields.src_port", To: "event.src_endpoint.port", Convert: mapping.ConvertPort},
			{ID: "destination-ip", From: "fields.dest_ip", To: "event.dst_endpoint.ip", Convert: mapping.ConvertIP},
			{ID: "destination-port", From: "fields.dest_port", To: "event.dst_endpoint.port", Convert: mapping.ConvertPort},
			{ID: "protocol", From: "fields.protocol", To: "event.connection_info.protocol_name", Convert: mapping.ConvertLowercase},
			{ID: "signature", From: "fields.alert.signature", To: "event.finding.signature", Convert: mapping.ConvertString, Required: true},
			{ID: "signature-id", From: "fields.alert.signature_id", To: "event.finding.signature_id", Convert: mapping.ConvertInteger},
			{ID: "severity", From: "fields.alert.severity", To: "event.severity_id", Convert: mapping.ConvertInteger},
		},
		Taxonomies: map[string]map[string][]string{
			"ids-class-uid":  {"2004": {"alert"}},
			"ids-class-name": {"Detection Finding": {"alert"}},
		},
	}
}

func loadEngine(t *testing.T, config mapping.Config) *mapping.Engine {
	t.Helper()
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := mapping.LoadConfig(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func readCorpus(t *testing.T, name string) []byte {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "corpus", "raw", name))
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func hasMappingIssue(result mapping.Result, code string) bool {
	for _, issue := range result.Issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}

func countLeaves(value any) int {
	switch typed := value.(type) {
	case map[string]any:
		total := 0
		for _, child := range typed {
			total += countLeaves(child)
		}
		return total
	default:
		return 1
	}
}
