package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sidd20228/universal_log_framework/internal/registry"
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
deployment:
  environment_id: test
  instance_id: node-a
  tenant_id: test
  api_token_ref: env:ULPF_TEST_TOKEN
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
  sqlite_path: /tmp/ulpf/state/ulpf.sqlite
  high_watermark_percent: 85
retention:
  raw_days: 7
connectors: []
`
	t.Setenv("ULPF_TEST_TOKEN", "test-token-000000000000000000000001")
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

func TestBundleValidateAndInstallCommands(t *testing.T) {
	bundle := filepath.Join("..", "..", "bundles", "reference", "json-firewall")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"bundle", "validate", "--json", bundle}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), `"status":"valid"`) {
		t.Fatalf("bundle validate code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	root := t.TempDir()
	t.Cleanup(func() {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err == nil {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"bundle", "install", "--sqlite", filepath.Join(root, "state.sqlite"), "--catalog", filepath.Join(root, "catalog"), bundle}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), `"bundle_id":"reference-json-firewall"`) {
		t.Fatalf("bundle install code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestBundleScaffoldTestAndSignaturePolicy(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "starter")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"bundle", "scaffold", "--id", "starter-firewall", "--format", "json", directory}, &stdout, &stderr); code != 0 {
		t.Fatalf("scaffold code=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"bundle", "test", "--json", directory}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), `"status":"tested"`) {
		t.Fatalf("test code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"bundle", "scaffold", "--id", "starter-firewall", "--format", "json", directory}, &stdout, &stderr); code != 0 {
		t.Fatalf("idempotent scaffold code=%d stderr=%s", code, stderr.String())
	}

	manifestPath := filepath.Join(directory, "manifest.json")
	encoded, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(encoded, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest["signature"] = map[string]any{"algorithm": "ed25519", "key_id": "publisher-a", "file": "bundle.sig"}
	encoded, _ = json.MarshalIndent(manifest, "", "  ")
	encoded = append(encoded, '\n')
	if err := os.WriteFile(manifestPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "bundle.sig"), []byte("pending"), 0o600); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := registry.SigningPayload(context.Background(), directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "bundle.sig"), []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "publisher.pub")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(publicKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"bundle", "test", "--require-signature", "--trust-root", "publisher-a=" + keyPath, directory}, &stdout, &stderr); code != 0 {
		t.Fatalf("signed test code=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"bundle", "test", directory}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "not trusted") {
		t.Fatalf("untrusted test code=%d stderr=%s", code, stderr.String())
	}
}

func TestBundleRollbackCommand(t *testing.T) {
	root := t.TempDir()
	t.Cleanup(func() {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err == nil {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	sqlitePath, catalog := filepath.Join(root, "state.sqlite"), filepath.Join(root, "catalog")
	install := func(bundle string) registry.InstalledBundle {
		var stdout, stderr bytes.Buffer
		if code := run([]string{"bundle", "install", "--sqlite", sqlitePath, "--catalog", catalog, bundle}, &stdout, &stderr); code != 0 {
			t.Fatalf("install code=%d stderr=%s", code, stderr.String())
		}
		var installed registry.InstalledBundle
		if err := json.Unmarshal(stdout.Bytes(), &installed); err != nil {
			t.Fatal(err)
		}
		return installed
	}
	jsonBundle := install(filepath.Join("..", "..", "bundles", "reference", "json-firewall"))
	kvBundle := install(filepath.Join("..", "..", "bundles", "reference", "kv-firewall"))
	command := func(name, digest, revision string) registry.Activation {
		var stdout, stderr bytes.Buffer
		if code := run([]string{"bundle", name, "--sqlite", sqlitePath, "--catalog", catalog, "--source-profile", "edge", "--sha256", digest, "--expected-revision", revision}, &stdout, &stderr); code != 0 {
			t.Fatalf("%s code=%d stderr=%s", name, code, stderr.String())
		}
		var activation registry.Activation
		if err := json.Unmarshal(stdout.Bytes(), &activation); err != nil {
			t.Fatal(err)
		}
		return activation
	}
	command("activate", jsonBundle.Digest, "0")
	command("activate", kvBundle.Digest, "1")
	rolledBack := command("rollback", jsonBundle.Digest, "2")
	if rolledBack.BundleDigest != jsonBundle.Digest || rolledBack.ConfigRevision != 3 {
		t.Fatalf("rollback = %+v", rolledBack)
	}
}
