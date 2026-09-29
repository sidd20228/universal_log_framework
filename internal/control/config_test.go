package control

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validConfigYAML = `config_version: ulpf-config/1
deployment:
  environment_id: lab
  instance_id: node-a
  tenant_id: tenant-a
  api_token_ref: env:ULPF_TEST_TOKEN
listeners:
  - id: syslog-udp-5514
    kind: syslog_udp
    address: 0.0.0.0:5514
    max_event_bytes: 65536
    source_profile_by_cidr:
      192.0.2.10/32: lab-firewall-a
processing:
  workers: 8
  parser_timeout: 100ms
  detection_threshold: 0.80
  ambiguity_margin: 0.10
storage:
  raw_root: /var/lib/ulpf/raw
  sqlite_path: /var/lib/ulpf/state/ulpf.sqlite
  high_watermark_percent: 85
retention:
  raw_days: 7
connectors:
  - id: normalized-clickhouse
    kind: clickhouse
    required: true
    endpoint: http://clickhouse:8123
    database: ulpf
    table: normalized_events
    username: ulpf
    password_ref: env:CLICKHOUSE_PASSWORD
`

func TestParseValidConfiguration(t *testing.T) {
	snapshot, err := Parse([]byte(validConfigYAML), "test")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(snapshot.Digest()) != 64 {
		t.Fatalf("Digest() length = %d, want 64", len(snapshot.Digest()))
	}
	if snapshot.Source() != "test" {
		t.Fatalf("Source() = %q, want test", snapshot.Source())
	}
	if snapshot.Config().Processing.ParserTimeout.Duration().String() != "100ms" {
		t.Fatalf("parser timeout was not decoded")
	}
}

func TestParseRejectsUnknownAndSemanticallyInvalidFields(t *testing.T) {
	for name, body := range map[string]string{
		"unknown field":      validConfigYAML + "surprise: true\n",
		"duplicate listener": strings.Replace(validConfigYAML, "  - id: syslog-udp-5514", "  - id: syslog-udp-5514\n  - id: syslog-udp-5514\n    kind: http\n    address: 127.0.0.1:8080\n    max_event_bytes: 1024", 1),
		"relative raw root":  strings.Replace(validConfigYAML, "/var/lib/ulpf/raw", "var/lib/ulpf/raw", 1),
		"bad cidr":           strings.Replace(validConfigYAML, "192.0.2.10/32", "192.0.2.999/32", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(body), "test"); err == nil {
				t.Fatal("Parse() accepted invalid configuration")
			}
		})
	}
}

func TestManagerDoesNotActivateInvalidConfiguration(t *testing.T) {
	initial, err := Parse([]byte(validConfigYAML), "initial")
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(initial)
	if _, err := manager.Activate([]byte("config_version: wrong\n"), "bad"); err == nil {
		t.Fatal("Activate() accepted invalid configuration")
	}
	current, ok := manager.Current()
	if !ok || current.Digest() != initial.Digest() {
		t.Fatal("invalid activation replaced the last known good snapshot")
	}
}

func TestSnapshotReturnsDefensiveCopies(t *testing.T) {
	snapshot, err := Parse([]byte(validConfigYAML), "test")
	if err != nil {
		t.Fatal(err)
	}
	config := snapshot.Config()
	config.Listeners[0].ID = "changed"
	config.Listeners[0].SourceProfileByCIDR["192.0.2.10/32"] = "changed"
	body := snapshot.Bytes()
	body[0] = 'X'

	again := snapshot.Config()
	if again.Listeners[0].ID != "syslog-udp-5514" || again.Listeners[0].SourceProfileByCIDR["192.0.2.10/32"] != "lab-firewall-a" {
		t.Fatal("snapshot configuration was mutated through a returned copy")
	}
	if snapshot.Bytes()[0] == 'X' {
		t.Fatal("snapshot bytes were mutated through a returned copy")
	}
}

func TestLoadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ulpf.yaml")
	if err := os.WriteFile(path, []byte(validConfigYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
}
