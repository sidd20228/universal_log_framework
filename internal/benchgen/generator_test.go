package benchgen

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDefaultScenarioGenerationIsReproducible(t *testing.T) {
	root := filepath.Join("..", "..")
	scenario := filepath.Join(root, "benchmarks", "scenarios", "default.json")
	corpus := filepath.Join(root, "tests", "corpus", "manifest.json")
	firstDirectory := filepath.Join(t.TempDir(), "first")
	secondDirectory := filepath.Join(t.TempDir(), "second")
	first, err := Generate(scenario, corpus, firstDirectory)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Generate(scenario, corpus, secondDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) || first.DatasetSHA256 == "" {
		t.Fatalf("reports differ:\n%#v\n%#v", first, second)
	}
	for _, name := range []string{"manifest.json", "generation-report.json", "generation-report.md"} {
		left, err := os.ReadFile(filepath.Join(firstDirectory, name))
		if err != nil {
			t.Fatal(err)
		}
		right, err := os.ReadFile(filepath.Join(secondDirectory, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(left, right) {
			t.Fatalf("%s is not reproducible", name)
		}
	}
	if first.GeneratedEvents != 100 || first.ScenarioCounts["generic_syslog"] != 20 || first.ScenarioCounts["cef"] != 15 || first.ScenarioCounts["unknown_proprietary_text"] != 5 {
		t.Fatalf("unexpected mix: %#v", first.ScenarioCounts)
	}
	if first.RequestedSizeCounts["256"] != 20 || first.RequestedSizeCounts["65536"] != 20 {
		t.Fatalf("unexpected size distribution: %#v", first.RequestedSizeCounts)
	}
}

func TestGeneratedFilesMatchManifestAndRemainDistinctOccurrences(t *testing.T) {
	root := filepath.Join("..", "..")
	output := filepath.Join(t.TempDir(), "dataset")
	report, err := Generate(filepath.Join(root, "benchmarks", "scenarios", "default.json"), filepath.Join(root, "tests", "corpus", "manifest.json"), output)
	if err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(filepath.Join(output, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest DatasetManifest
	if err := json.Unmarshal(contents, &manifest); err != nil {
		t.Fatal(err)
	}
	identities := make(map[string]struct{}, len(manifest.Events))
	for _, event := range manifest.Events {
		payload, err := os.ReadFile(filepath.Join(output, filepath.FromSlash(event.Path)))
		if err != nil {
			t.Fatal(err)
		}
		if len(payload) != event.SizeBytes || digestHex(payload) != event.SHA256 {
			t.Fatalf("event %d failed byte/hash verification", event.Index)
		}
		if _, duplicate := identities[event.OccurrenceID]; duplicate {
			t.Fatalf("duplicate occurrence id %q", event.OccurrenceID)
		}
		identities[event.OccurrenceID] = struct{}{}
	}
	if datasetDigest(manifest.Events) != report.DatasetSHA256 {
		t.Fatal("dataset digest mismatch")
	}
}

func TestInvalidScenarioAndExistingOutputAreRejected(t *testing.T) {
	directory := t.TempDir()
	scenarioPath := filepath.Join(directory, "invalid.json")
	if err := os.WriteFile(scenarioPath, []byte(`{"scenario_version":"wrong"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadScenario(scenarioPath); err == nil {
		t.Fatal("invalid scenario was accepted")
	}
	root := filepath.Join("..", "..")
	if _, err := Generate(filepath.Join(root, "benchmarks", "scenarios", "default.json"), filepath.Join(root, "tests", "corpus", "manifest.json"), directory); err == nil {
		t.Fatal("existing output directory was accepted")
	}
}
