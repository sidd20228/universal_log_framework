package registry_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sidd20228/universal_log_framework/internal/registry"
)

func TestLoaderAcceptsValidImmutableBundle(t *testing.T) {
	bundleDirectory := createBundle(t, t.TempDir(), "lab-firewall", "1.2.3", nil)
	descriptor, err := testLoader(t).LoadDirectory(context.Background(), bundleDirectory)
	if err != nil {
		t.Fatalf("LoadDirectory() error = %v", err)
	}
	if descriptor.BundleID() != "lab-firewall" || descriptor.Version() != "1.2.3" {
		t.Fatalf("descriptor identity = %s@%s", descriptor.BundleID(), descriptor.Version())
	}
	if len(descriptor.Digest()) != 64 {
		t.Fatalf("descriptor digest length = %d, want 64", len(descriptor.Digest()))
	}
	manifest := descriptor.Manifest()
	manifest.Parsers[0].ID = "mutated"
	manifest.Artifacts[0].Path = "mutated.json"
	second := descriptor.Manifest()
	if second.Parsers[0].ID != "lab-firewall-parser" || second.Artifacts[0].Path != "parser.json" {
		t.Fatal("descriptor exposed mutable manifest state")
	}
}

func TestLoaderRejectsUnknownManifestFields(t *testing.T) {
	directory := createBundle(t, t.TempDir(), "unknown-field", "1.0.0", func(manifest map[string]any) {
		manifest["surprise"] = true
	})
	_, err := testLoader(t).LoadDirectory(context.Background(), directory)
	if !errors.Is(err, registry.ErrInvalidManifest) {
		t.Fatalf("LoadDirectory() error = %v, want ErrInvalidManifest", err)
	}
}

func TestLoaderRejectsTraversalAndSymlinks(t *testing.T) {
	t.Run("traversal", func(t *testing.T) {
		directory := createBundle(t, t.TempDir(), "traversal", "1.0.0", func(manifest map[string]any) {
			parsers := manifest["parsers"].([]any)
			parsers[0].(map[string]any)["config"] = "../outside.json"
		})
		_, err := testLoader(t).LoadDirectory(context.Background(), directory)
		if !errors.Is(err, registry.ErrUnsafePath) {
			t.Fatalf("LoadDirectory() error = %v, want ErrUnsafePath", err)
		}
	})

	t.Run("symlink artifact", func(t *testing.T) {
		parent := t.TempDir()
		directory := createBundle(t, parent, "symlink", "1.0.0", nil)
		outside := filepath.Join(parent, "outside.json")
		if err := os.WriteFile(outside, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		parserPath := filepath.Join(directory, "parser.json")
		if err := os.Remove(parserPath); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, parserPath); err != nil {
			t.Fatal(err)
		}
		_, err := testLoader(t).LoadDirectory(context.Background(), directory)
		if !errors.Is(err, registry.ErrUnsafePath) {
			t.Fatalf("LoadDirectory() error = %v, want ErrUnsafePath", err)
		}
	})
}

func TestLoaderRejectsChecksumMismatchAndTampering(t *testing.T) {
	directory := createBundle(t, t.TempDir(), "tampered", "1.0.0", nil)
	if err := os.WriteFile(filepath.Join(directory, "parser.json"), []byte(`{"changed":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := testLoader(t).LoadDirectory(context.Background(), directory)
	if !errors.Is(err, registry.ErrArtifactIntegrity) {
		t.Fatalf("LoadDirectory() error = %v, want ErrArtifactIntegrity", err)
	}
}

func TestLoaderVerifiesEd25519SignatureAgainstTrustRoots(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := createBundle(t, t.TempDir(), "signed", "1.0.0", func(manifest map[string]any) {
		manifest["signature"] = map[string]any{"algorithm": "ed25519", "key_id": "publisher-a", "file": "bundle.sig"}
	})
	if err := os.WriteFile(filepath.Join(directory, "bundle.sig"), []byte("pending"), 0o600); err != nil {
		t.Fatal(err)
	}
	payload, err := registry.SigningPayload(context.Background(), directory)
	if err != nil {
		t.Fatal(err)
	}
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)) + "\n"
	if err := os.WriteFile(filepath.Join(directory, "bundle.sig"), []byte(signature), 0o600); err != nil {
		t.Fatal(err)
	}
	loader, err := registry.NewLoader(registry.RuntimeCompatibility{EngineVersion: "1.0.0", EnvelopeSchema: "ulpf-envelope/1.0.0", OCSFVersion: "1.9.0",
		TrustRoots: map[string]ed25519.PublicKey{"publisher-a": publicKey}, RequireSignature: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loader.LoadDirectory(context.Background(), directory); err != nil {
		t.Fatalf("signed bundle rejected: %v", err)
	}

	if err := os.WriteFile(filepath.Join(directory, "bundle.sig"), []byte(base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loader.LoadDirectory(context.Background(), directory); !errors.Is(err, registry.ErrSignatureInvalid) {
		t.Fatalf("tampered signature error = %v", err)
	}
	unknown, err := registry.NewLoader(registry.RuntimeCompatibility{EngineVersion: "1.0.0", EnvelopeSchema: "ulpf-envelope/1.0.0", OCSFVersion: "1.9.0",
		TrustRoots: map[string]ed25519.PublicKey{"publisher-b": publicKey}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unknown.LoadDirectory(context.Background(), directory); !errors.Is(err, registry.ErrSignatureUntrusted) {
		t.Fatalf("unknown key error = %v", err)
	}
}

func TestLoaderRequiresSignatureWhenPolicyEnabled(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := createBundle(t, t.TempDir(), "unsigned", "1.0.0", nil)
	loader, err := registry.NewLoader(registry.RuntimeCompatibility{EngineVersion: "1.0.0", EnvelopeSchema: "ulpf-envelope/1.0.0", OCSFVersion: "1.9.0",
		TrustRoots: map[string]ed25519.PublicKey{"publisher-a": publicKey}, RequireSignature: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loader.LoadDirectory(context.Background(), directory); !errors.Is(err, registry.ErrSignatureRequired) {
		t.Fatalf("unsigned error = %v", err)
	}
}

func TestLoaderRejectsSignaturePathCollision(t *testing.T) {
	directory := createBundle(t, t.TempDir(), "collision", "1.0.0", func(manifest map[string]any) {
		manifest["signature"] = map[string]any{"algorithm": "ed25519", "key_id": "publisher-a", "file": "parser.json"}
	})
	_, err := testLoader(t).LoadDirectory(context.Background(), directory)
	if !errors.Is(err, registry.ErrInvalidManifest) {
		t.Fatalf("collision error = %v", err)
	}
}

func TestLoaderRejectsExecutableParserImplementations(t *testing.T) {
	directory := createBundle(t, t.TempDir(), "executable", "1.0.0", func(manifest map[string]any) {
		parsers := manifest["parsers"].([]any)
		parsers[0].(map[string]any)["implementation"] = "python"
	})
	_, err := testLoader(t).LoadDirectory(context.Background(), directory)
	if !errors.Is(err, registry.ErrExecutableImplementation) {
		t.Fatalf("LoadDirectory() error = %v, want ErrExecutableImplementation", err)
	}
}

func TestLoaderRejectsCompatibilityFailures(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"engine too old": func(manifest map[string]any) {
			compatibility := manifest["compatibility"].(map[string]any)
			compatibility["minimum_engine_version"] = "2.0.0"
			compatibility["maximum_engine_version"] = "3.0.0"
		},
		"engine too new": func(manifest map[string]any) {
			manifest["compatibility"].(map[string]any)["maximum_engine_version"] = "0.9.0"
		},
		"envelope mismatch": func(manifest map[string]any) {
			manifest["compatibility"].(map[string]any)["envelope_schema"] = "ulpf-envelope/2.0.0"
		},
		"ocsf mismatch": func(manifest map[string]any) {
			manifest["compatibility"].(map[string]any)["ocsf_version"] = "1.8.0"
		},
	} {
		t.Run(name, func(t *testing.T) {
			directory := createBundle(t, t.TempDir(), strings.ReplaceAll(name, " ", "-"), "1.0.0", mutate)
			_, err := testLoader(t).LoadDirectory(context.Background(), directory)
			if !errors.Is(err, registry.ErrIncompatible) {
				t.Fatalf("LoadDirectory() error = %v, want ErrIncompatible", err)
			}
		})
	}
}

func TestRegistryRejectsDuplicateBundleIDAndVersion(t *testing.T) {
	parent := t.TempDir()
	first := createBundle(t, filepath.Join(parent, "one"), "duplicate", "1.0.0", nil)
	second := createBundle(t, filepath.Join(parent, "two"), "duplicate", "1.0.0", nil)
	active := registry.New(testLoader(t))
	err := active.ActivateDirectories(context.Background(), []string{first, second})
	if !errors.Is(err, registry.ErrDuplicateBundle) {
		t.Fatalf("ActivateDirectories() error = %v, want ErrDuplicateBundle", err)
	}
	if active.Snapshot().Len() != 0 {
		t.Fatal("failed initial activation changed the empty snapshot")
	}
}

func TestFailedActivationPreservesLastKnownGoodSnapshot(t *testing.T) {
	parent := t.TempDir()
	good := createBundle(t, filepath.Join(parent, "good"), "stable", "1.0.0", nil)
	active := registry.New(testLoader(t))
	if err := active.ActivateDirectories(context.Background(), []string{good}); err != nil {
		t.Fatal(err)
	}
	before := active.Snapshot()
	descriptor, found := before.Find("stable", "1.0.0")
	if !found {
		t.Fatal("active snapshot does not contain valid bundle")
	}

	bad := createBundle(t, filepath.Join(parent, "bad"), "bad", "1.0.0", nil)
	if err := os.WriteFile(filepath.Join(bad, "parser.json"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := active.ActivateDirectories(context.Background(), []string{bad}); !errors.Is(err, registry.ErrArtifactIntegrity) {
		t.Fatalf("failed activation error = %v", err)
	}
	after := active.Snapshot()
	if after != before {
		t.Fatal("failed activation replaced the snapshot pointer")
	}
	got, found := after.Find("stable", "1.0.0")
	if !found || got.Digest() != descriptor.Digest() {
		t.Fatal("failed activation did not preserve last-known-good bundle")
	}
}

func TestRegistryRejectsDifferentBytesForAnActiveIDAndVersion(t *testing.T) {
	parent := t.TempDir()
	first := createBundle(t, filepath.Join(parent, "first"), "immutable", "1.0.0", nil)
	active := registry.New(testLoader(t))
	if err := active.ActivateDirectories(context.Background(), []string{first}); err != nil {
		t.Fatal(err)
	}
	before := active.Snapshot()

	replacement := createBundle(t, filepath.Join(parent, "replacement"), "immutable", "1.0.0", nil)
	rewriteParserArtifact(t, replacement, []byte(`{"format":"json"}`))
	if err := active.ActivateDirectories(context.Background(), []string{replacement}); !errors.Is(err, registry.ErrDuplicateBundle) {
		t.Fatalf("replacement activation error = %v, want ErrDuplicateBundle", err)
	}
	if active.Snapshot() != before {
		t.Fatal("immutable-version rejection replaced the active snapshot")
	}
}

func TestLoaderRequiresFixtureDirectories(t *testing.T) {
	directory := createBundle(t, t.TempDir(), "fixtures", "1.0.0", nil)
	if err := os.Remove(filepath.Join(directory, "fixtures", "invalid")); err != nil {
		t.Fatal(err)
	}
	_, err := testLoader(t).LoadDirectory(context.Background(), directory)
	if !errors.Is(err, registry.ErrInvalidManifest) {
		t.Fatalf("LoadDirectory() error = %v, want ErrInvalidManifest", err)
	}
}

func testLoader(t *testing.T) *registry.Loader {
	t.Helper()
	loader, err := registry.NewLoader(registry.RuntimeCompatibility{
		EngineVersion:  "1.0.0",
		EnvelopeSchema: "ulpf-envelope/1.0.0",
		OCSFVersion:    "1.9.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	return loader
}

func createBundle(t *testing.T, parent, bundleID, version string, mutate func(map[string]any)) string {
	t.Helper()
	directory := filepath.Join(parent, bundleID+"-"+version)
	for _, relative := range []string{"fixtures/valid", "fixtures/invalid", "expected"} {
		if err := os.MkdirAll(filepath.Join(directory, filepath.FromSlash(relative)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	parserContents := []byte(`{"format":"kv"}`)
	if err := os.WriteFile(filepath.Join(directory, "parser.json"), parserContents, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{
		"manifest_version": "ulpf-parser-bundle/1",
		"bundle_id":        bundleID,
		"version":          version,
		"description":      "Synthetic test parser bundle.",
		"license":          "Apache-2.0",
		"compatibility": map[string]any{
			"envelope_schema":        "ulpf-envelope/1.0.0",
			"minimum_engine_version": "0.9.0",
			"maximum_engine_version": "1.5.0",
			"ocsf_version":           "1.9.0",
		},
		"source": map[string]any{
			"kind":      "synthetic",
			"reference": "test fixture",
		},
		"parsers": []any{map[string]any{
			"id":             bundleID + "-parser",
			"implementation": "builtin_kv",
			"config":         "parser.json",
			"priority":       10,
		}},
		"fixtures": map[string]any{
			"valid":    "fixtures/valid",
			"invalid":  "fixtures/invalid",
			"expected": "expected",
		},
		"artifacts": []any{map[string]any{
			"path":       "parser.json",
			"role":       "parser_config",
			"sha256":     fmt.Sprintf("%x", sha256.Sum256(parserContents)),
			"media_type": "application/json",
		}},
	}
	if mutate != nil {
		mutate(manifest)
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "manifest.json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return directory
}

func rewriteParserArtifact(t *testing.T, directory string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, "parser.json"), contents, 0o600); err != nil {
		t.Fatal(err)
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
	artifacts := manifest["artifacts"].([]any)
	artifacts[0].(map[string]any)["sha256"] = fmt.Sprintf("%x", sha256.Sum256(contents))
	encoded, err = json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestParserMappingReferenceRequiresSafeDeclaredArtifact(t *testing.T) {
	for _, path := range []string{"../outside.json", "missing.json", "parser.json"} {
		t.Run(path, func(t *testing.T) {
			directory := createBundle(t, t.TempDir(), "mapping-reference", "1.0.0", func(manifest map[string]any) {
				manifest["parsers"].([]any)[0].(map[string]any)["mappings"] = path
			})
			if _, err := testLoader(t).LoadDirectory(context.Background(), directory); err == nil {
				t.Fatal("accepted invalid parser mapping reference")
			}
		})
	}
}
