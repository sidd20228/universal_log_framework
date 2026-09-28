package registry

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"
	"testing"
)

func FuzzBundleManifest(f *testing.F) {
	valid, err := json.Marshal(Manifest{
		ManifestVersion: ManifestVersion,
		BundleID:        "synthetic-security",
		Version:         "1.0.0",
		Description:     "Synthetic fuzz seed.",
		License:         "Apache-2.0",
		Compatibility: Compatibility{
			EnvelopeSchema:       "ulpf-envelope/1.0.0",
			MinimumEngineVersion: "1.0.0",
			MaximumEngineVersion: "1.0.0",
			OCSFVersion:          "1.9.0",
		},
		Source:  &Source{Kind: "synthetic", Reference: "repository fuzz seed"},
		Parsers: []Parser{{ID: "synthetic", Implementation: "builtin_json", Config: "parser.json"}},
		Fixtures: Fixtures{
			Valid: "fixtures/valid", Invalid: "fixtures/invalid", Expected: "fixtures/expected",
		},
		Artifacts: []Artifact{{Path: "parser.json", Role: "parser_config", SHA256: strings.Repeat("0", 64)}},
	})
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range [][]byte{
		valid,
		[]byte(`{"manifest_version":"ulpf-parser-bundle/1","bundle_id":"../../escape"}`),
		[]byte(`{"manifest_version":"ulpf-parser-bundle/1","unknown":"field"}`),
		[]byte(`{} {}`),
		{0xff, 0x00, '{', '}'},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 66<<10 {
			return
		}
		first, firstErr := decodeAndValidateManifest(input)
		second, secondErr := decodeAndValidateManifest(input)
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatalf("manifest acceptance changed between identical calls: first=%v second=%v", firstErr, secondErr)
		}
		if firstErr == nil {
			firstJSON, err := json.Marshal(first)
			if err != nil {
				t.Fatal(err)
			}
			secondJSON, err := json.Marshal(second)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(firstJSON, secondJSON) {
				t.Fatal("manifest decoding is nondeterministic")
			}
		}
	})
}

func FuzzBundleManifestPath(f *testing.F) {
	for _, seed := range []string{
		"parser.json",
		"fixtures/valid/event.log",
		"../outside.json",
		"fixtures/../../outside",
		"/etc/passwd",
		`fixtures\..\outside`,
		"fixtures//event.log",
		"fixtures/%2e%2e/event.log",
		"fixtures/\x00/event.log",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, candidate string) {
		first := validateRelativePath(candidate)
		second := validateRelativePath(candidate)
		if (first == nil) != (second == nil) {
			t.Fatalf("path acceptance changed between identical calls: first=%v second=%v", first, second)
		}
		if first != nil {
			if !errors.Is(first, ErrUnsafePath) {
				t.Fatalf("unsafe path returned unexpected error: %v", first)
			}
			return
		}
		if candidate == "" || len(candidate) > 512 || path.IsAbs(candidate) || path.Clean(candidate) != candidate || strings.Contains(candidate, `\`) {
			t.Fatalf("unsafe path was accepted: %q", candidate)
		}
		for _, component := range strings.Split(candidate, "/") {
			if component == "" || component == "." || component == ".." {
				t.Fatalf("unsafe component was accepted in %q", candidate)
			}
		}
	})
}

func TestSecurityBundleManifestPathCorpus(t *testing.T) {
	tests := map[string]bool{
		"parser.json":                 true,
		"fixtures/valid/event-01.log": true,
		"../outside":                  false,
		"fixtures/../outside":         false,
		"/absolute":                   false,
		`windows\absolute`:            false,
		"double//separator":           false,
		"dot/./component":             false,
		"control/\x00byte":            false,
	}
	for candidate, wantValid := range tests {
		err := validateRelativePath(candidate)
		if (err == nil) != wantValid {
			t.Errorf("validateRelativePath(%q) error = %v, want valid=%t", candidate, err, wantValid)
		}
	}
}

func decodeAndValidateManifest(input []byte) (Manifest, error) {
	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Manifest{}, errors.New("multiple manifest values")
		}
		return Manifest{}, err
	}
	if err := validateManifest(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}
