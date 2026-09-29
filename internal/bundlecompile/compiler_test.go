package bundlecompile_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/sidd20228/universal_log_framework/internal/bundlecompile"
	"github.com/sidd20228/universal_log_framework/internal/detect"
	"github.com/sidd20228/universal_log_framework/internal/interpret"
	"github.com/sidd20228/universal_log_framework/internal/model"
	"github.com/sidd20228/universal_log_framework/internal/registry"
)

func TestReferenceBundlesCompileDetectAndNormalizeEquivalentEvents(t *testing.T) {
	ctx := context.Background()
	loader := referenceLoader(t)
	type reference struct {
		name    string
		valid   string
		invalid string
	}
	references := []reference{
		{name: "json-firewall", valid: "fixtures/valid/traffic.json", invalid: "fixtures/invalid/unrelated.json"},
		{name: "kv-firewall", valid: "fixtures/valid/traffic.log", invalid: "fixtures/invalid/unrelated.log"},
	}
	var canonical []byte
	for _, test := range references {
		t.Run(test.name, func(t *testing.T) {
			root := referenceRoot(test.name)
			descriptor, err := loader.LoadDirectory(ctx, root)
			if err != nil {
				t.Fatal(err)
			}
			compiled, err := bundlecompile.Compile(ctx, descriptor)
			if err != nil {
				t.Fatal(err)
			}
			if compiled.BundleID() != "reference-"+test.name || compiled.Version() != "1.0.0" || compiled.Digest() != descriptor.Digest() {
				t.Fatalf("compiled identity = %s@%s %s", compiled.BundleID(), compiled.Version(), compiled.Digest())
			}
			detector, err := compiled.NewDetector(detect.DefaultConfig())
			if err != nil {
				t.Fatal(err)
			}
			valid := readFile(t, filepath.Join(root, filepath.FromSlash(test.valid)))
			detection, err := detector.Detect(ctx, bytes.NewReader(valid), detect.Hints{})
			if err != nil || detection.Outcome != detect.OutcomeSelected || detection.Selected == nil {
				t.Fatalf("valid detection = %+v, %v", detection, err)
			}
			if detection.Selected.BundleDigest != descriptor.Digest() {
				t.Fatalf("selected digest = %q", detection.Selected.BundleDigest)
			}
			resolver, err := compiled.NewResolver()
			if err != nil {
				t.Fatal(err)
			}
			pipeline, err := resolver.Resolve(ctx, model.Receipt{}, *detection.Selected)
			if err != nil {
				t.Fatal(err)
			}
			parsed := pipeline.Parser.Parse(ctx, interpret.Payload{Bytes: valid}, interpret.Limits{})
			if parsed.Status != interpret.StatusParsed {
				t.Fatalf("parse status = %s, issues = %+v", parsed.Status, parsed.Issues)
			}
			mapped := pipeline.Mapper.Map(ctx, parsed.Document)
			if len(mapped.Issues) != 0 || mapped.RequiredPresent != mapped.RequiredTotal {
				t.Fatalf("mapping = %+v", mapped)
			}
			if len(mapped.Provenance) != leafCount(mapped.Event) {
				t.Fatalf("provenance count = %d, leaves = %d", len(mapped.Provenance), leafCount(mapped.Event))
			}
			if _, found := mapped.Unmapped[opaquePath(test.name)]; !found {
				t.Fatalf("unmapped fields lost opaque input: %#v", mapped.Unmapped)
			}
			actual := normalizedJSON(t, mapped.Event)
			expected := normalizedJSONBytes(t, readFile(t, filepath.Join(root, "expected", "traffic.json")))
			if !bytes.Equal(actual, expected) {
				t.Fatalf("canonical event = %s\nexpected = %s", actual, expected)
			}
			if canonical == nil {
				canonical = actual
			} else if !bytes.Equal(canonical, actual) {
				t.Fatalf("source bundles normalized differently:\nfirst = %s\nthis  = %s", canonical, actual)
			}

			invalid := readFile(t, filepath.Join(root, filepath.FromSlash(test.invalid)))
			unknown, err := detector.Detect(ctx, bytes.NewReader(invalid), detect.Hints{})
			if err != nil || unknown.Outcome != detect.OutcomeUnknown {
				t.Fatalf("invalid detection = %+v, %v", unknown, err)
			}
		})
	}
}

func TestCompileRejectsArtifactChangedAfterRegistryValidation(t *testing.T) {
	ctx := context.Background()
	root := copyTree(t, referenceRoot("json-firewall"))
	descriptor, err := referenceLoader(t).LoadDirectory(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "mappings.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bundlecompile.Compile(ctx, descriptor); err == nil {
		t.Fatal("Compile accepted an artifact changed after descriptor validation")
	}
}

func TestCompileRejectsChecksummedSemanticConfigFailure(t *testing.T) {
	ctx := context.Background()
	root := copyTree(t, referenceRoot("json-firewall"))
	invalidMapping := []byte(`{"config_version":"ulpf-mapping/1","id":"broken","version":"1.0.0","rules":[]}`)
	if err := os.WriteFile(filepath.Join(root, "mappings.json"), invalidMapping, 0o600); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "manifest.json")
	var manifest map[string]any
	if err := json.Unmarshal(readFile(t, manifestPath), &manifest); err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(invalidMapping))
	for _, value := range manifest["artifacts"].([]any) {
		artifact := value.(map[string]any)
		if artifact["path"] == "mappings.json" {
			artifact["sha256"] = digest
		}
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	descriptor, err := referenceLoader(t).LoadDirectory(ctx, root)
	if err != nil {
		t.Fatalf("registry structural validation unexpectedly failed: %v", err)
	}
	if _, err := bundlecompile.Compile(ctx, descriptor); err == nil {
		t.Fatal("Compile accepted a checksummed mapping with no rules")
	}
}

func referenceLoader(t *testing.T) *registry.Loader {
	t.Helper()
	loader, err := registry.NewLoader(registry.RuntimeCompatibility{
		EngineVersion: "1.0.0", EnvelopeSchema: "ulpf-envelope/1.0.0", OCSFVersion: "1.9.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	return loader
}

func referenceRoot(name string) string {
	return filepath.Join("..", "..", "bundles", "reference", name)
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func normalizedJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return normalizedJSONBytes(t, encoded)
}

func normalizedJSONBytes(t *testing.T, encoded []byte) []byte {
	t.Helper()
	var value any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	normalized, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return normalized
}

func leafCount(value any) int {
	switch typed := value.(type) {
	case map[string]any:
		total := 0
		for _, child := range typed {
			total += leafCount(child)
		}
		return total
	default:
		return 1
	}
}

func opaquePath(name string) string {
	if name == "kv-firewall" {
		return "fields.attributes.opaque"
	}
	return "fields.opaque"
}

func copyTree(t *testing.T, source string) string {
	t.Helper()
	target := filepath.Join(t.TempDir(), "bundle")
	err := filepath.WalkDir(source, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		destination := filepath.Join(target, relative)
		if entry.IsDir() {
			return os.MkdirAll(destination, 0o700)
		}
		return os.WriteFile(destination, readFile(t, path), 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	return target
}
