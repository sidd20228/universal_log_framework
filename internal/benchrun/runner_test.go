package benchrun

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSummarizeLatencyUsesNearestRank(t *testing.T) {
	values := make([]time.Duration, 100)
	for index := range values {
		values[index] = time.Duration(index+1) * time.Millisecond
	}
	result := summarizeLatency(values)
	if result.MinNS != int64(time.Millisecond) || result.P50NS != int64(50*time.Millisecond) || result.P95NS != int64(95*time.Millisecond) || result.P99NS != int64(99*time.Millisecond) || result.MaxNS != int64(100*time.Millisecond) {
		t.Fatalf("latency = %+v", result)
	}
}

func TestLoadConfigRejectsUnknownAndUnsafeLimits(t *testing.T) {
	tests := []string{
		`{"profile_version":"ulpf-benchmark-profile/1","name":"x","tenant_id":"t","listener_id":"l","pipeline_version":"1.0.0","max_event_bytes":1,"lease_duration_ms":2,"renew_interval_ms":1,"processing_timeout_ms":1,"max_attempts":1,"capture_profiles":false,"extra":true}`,
		`{"profile_version":"ulpf-benchmark-profile/1","name":"x","tenant_id":"t","listener_id":"l","pipeline_version":"1.0.0","max_event_bytes":1,"lease_duration_ms":1,"renew_interval_ms":1,"processing_timeout_ms":1,"max_attempts":1,"capture_profiles":false}`,
	}
	for _, contents := range tests {
		path := filepath.Join(t.TempDir(), "profile.json")
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := LoadConfig(path); err == nil {
			t.Fatalf("LoadConfig(%s) succeeded", contents)
		}
	}
}

func TestLoadAndVerifyDatasetRejectsTampering(t *testing.T) {
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "events"), 0o700); err != nil {
		t.Fatal(err)
	}
	eventPath := filepath.Join(directory, "events", "000000.bin")
	if err := os.WriteFile(eventPath, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{
		"manifest_version": "ulpf-benchmark-dataset/1",
		"scenario":         "test", "seed": 1,
		"events": []map[string]any{{"index": 0, "occurrence_id": "one", "path": "events/000000.bin", "source_fixture": "one", "source_scenario": "json", "requested_bytes": 7, "size_bytes": 7, "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
	}
	contents, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "manifest.json"), contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAndVerifyDataset(directory); err == nil {
		t.Fatal("tampered dataset was accepted")
	}
}

func TestRunWritesAccountedReport(t *testing.T) {
	repository := filepath.Clean(filepath.Join("..", ".."))
	root := t.TempDir()
	profile := filepath.Join(root, "profile.json")
	scenario := filepath.Join(root, "scenario.json")
	profileBytes, err := os.ReadFile(filepath.Join(repository, "benchmarks", "profiles", "local-e2e.json"))
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(profileBytes, &config); err != nil {
		t.Fatal(err)
	}
	config["capture_profiles"] = false
	profileBytes, _ = json.Marshal(config)
	if err := os.WriteFile(profile, profileBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	scenarioBytes := []byte(`{"scenario_version":"ulpf-benchmark-scenario/1","name":"tiny-json","seed":7,"event_count":2,"max_event_bytes":1024,"mix":[{"fixture_id":"json-firewall-allow","weight":1}],"sizes":[{"bytes":256,"weight":1}]}`)
	if err := os.WriteFile(scenario, scenarioBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "report")
	report, err := Run(t.Context(), Options{ScenarioPath: scenario, CorpusPath: filepath.Join(repository, "tests", "corpus", "manifest.json"), ConfigPath: profile, OutputDir: output, Repository: repository})
	if err != nil {
		t.Fatal(err)
	}
	if report.Measurements.Submitted != 2 || report.Measurements.Accepted != 2 || report.Measurements.Revisions != 2 || report.Measurements.RawVerified != 2 || report.Measurements.Rejected != 0 || report.Measurements.HashMismatches != 0 || report.Measurements.LinkageFailures != 0 {
		t.Fatalf("measurements = %+v", report.Measurements)
	}
	if report.Provenance.DatasetSHA256 == "" || report.Provenance.CodeSHA256 == "" || report.Measurements.Acceptance.Samples != 2 || report.Measurements.ThroughputEPS <= 0 {
		t.Fatalf("report = %+v", report)
	}
	for _, name := range []string{"report.json", "report.md"} {
		if info, err := os.Stat(filepath.Join(output, name)); err != nil || info.Size() == 0 {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
