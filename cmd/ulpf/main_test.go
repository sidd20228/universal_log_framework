package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := run([]string{"version", "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run() code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"version":"dev"`) {
		t.Fatalf("version output = %q", stdout.String())
	}
}

func TestValidateConfigCommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ulpf.yaml")
	body := `config_version: ulpf-config/1
listeners:
  - id: http-8080
    kind: http
    address: 127.0.0.1:8080
    max_event_bytes: 1048576
processing:
  workers: 2
  parser_timeout: 100ms
  detection_threshold: 0.8
  ambiguity_margin: 0.1
storage:
  raw_root: /tmp/ulpf/raw
  high_watermark_percent: 85
retention:
  raw_days: 7
connectors: []
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := run([]string{"validate-config", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("run() code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "configuration valid") {
		t.Fatalf("output = %q", stdout.String())
	}
}

func TestValidateConfigCommandRejectsInvalidConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ulpf.yaml")
	if err := os.WriteFile(path, []byte("config_version: bad\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := run([]string{"validate-config", "--config", path}, &stdout, &stderr); code != 1 {
		t.Fatalf("run() code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "configuration invalid") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestLoadAPITokenFromFileAndRejectsAmbiguousSources(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api-token")
	secret := "file-token-00000000000000000000001"
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ULPF_API_TOKEN", "")
	os.Unsetenv("ULPF_API_TOKEN")
	got, err := loadAPIToken(path)
	if err != nil || got != secret {
		t.Fatalf("loadAPIToken() = %q, %v", got, err)
	}
	t.Setenv("ULPF_API_TOKEN", "environment-token-000000000000001")
	if _, err := loadAPIToken(path); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("ambiguous secret error = %v", err)
	}
}
