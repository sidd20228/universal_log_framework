package benchgen

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	ScenarioVersion = "ulpf-benchmark-scenario/1"
	ReportVersion   = "ulpf-benchmark-generation-report/1"
	maxEvents       = 1_000_000
	maxBytes        = 16 << 20
)

type WeightedFixture struct {
	FixtureID string `json:"fixture_id"`
	Weight    int    `json:"weight"`
}

type WeightedSize struct {
	Bytes  int `json:"bytes"`
	Weight int `json:"weight"`
}

type Scenario struct {
	ScenarioVersion string            `json:"scenario_version"`
	Name            string            `json:"name"`
	Seed            int64             `json:"seed"`
	EventCount      int               `json:"event_count"`
	MaxEventBytes   int               `json:"max_event_bytes"`
	Mix             []WeightedFixture `json:"mix"`
	Sizes           []WeightedSize    `json:"sizes"`
}

type corpusManifest struct {
	Fixtures []corpusFixture `json:"fixtures"`
}

type corpusFixture struct {
	ID       string `json:"id"`
	Scenario string `json:"scenario"`
	Path     string `json:"path"`
}

type Event struct {
	Index          int    `json:"index"`
	OccurrenceID   string `json:"occurrence_id"`
	Path           string `json:"path"`
	SourceFixture  string `json:"source_fixture"`
	SourceScenario string `json:"source_scenario"`
	RequestedBytes int    `json:"requested_bytes"`
	SizeBytes      int    `json:"size_bytes"`
	SHA256         string `json:"sha256"`
}

type DatasetManifest struct {
	ManifestVersion string  `json:"manifest_version"`
	Scenario        string  `json:"scenario"`
	Seed            int64   `json:"seed"`
	Events          []Event `json:"events"`
}

type Report struct {
	ReportVersion        string         `json:"report_version"`
	Scenario             string         `json:"scenario"`
	Seed                 int64          `json:"seed"`
	GeneratedEvents      int            `json:"generated_events"`
	CorpusManifestSHA256 string         `json:"corpus_manifest_sha256"`
	ScenarioSHA256       string         `json:"scenario_sha256"`
	DatasetSHA256        string         `json:"dataset_sha256"`
	FixtureCounts        map[string]int `json:"fixture_counts"`
	ScenarioCounts       map[string]int `json:"source_scenario_counts"`
	RequestedSizeCounts  map[string]int `json:"requested_size_counts"`
	MinimumActualBytes   int            `json:"minimum_actual_bytes"`
	MaximumActualBytes   int            `json:"maximum_actual_bytes"`
	MeasurementClaim     string         `json:"measurement_claim"`
}

func LoadScenario(path string) (Scenario, []byte, error) {
	var scenario Scenario
	contents, err := os.ReadFile(path)
	if err != nil {
		return scenario, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&scenario); err != nil {
		return scenario, nil, fmt.Errorf("decode benchmark scenario: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return scenario, nil, err
	}
	if err := validateScenario(scenario); err != nil {
		return scenario, nil, err
	}
	return scenario, contents, nil
}

func Generate(scenarioPath, corpusManifestPath, outputDirectory string) (Report, error) {
	var report Report
	scenario, scenarioBytes, err := LoadScenario(scenarioPath)
	if err != nil {
		return report, err
	}
	corpusBytes, err := os.ReadFile(corpusManifestPath)
	if err != nil {
		return report, fmt.Errorf("read corpus manifest: %w", err)
	}
	var corpus corpusManifest
	// The corpus manifest intentionally contains richer metadata. Decode its
	// small index through an untyped projection to avoid weakening its schema.
	var raw struct {
		Fixtures []json.RawMessage `json:"fixtures"`
	}
	if err := json.Unmarshal(corpusBytes, &raw); err != nil {
		return report, fmt.Errorf("decode corpus manifest: %w", err)
	}
	for _, item := range raw.Fixtures {
		var fixture corpusFixture
		if err := json.Unmarshal(item, &fixture); err != nil {
			return report, fmt.Errorf("decode corpus fixture index: %w", err)
		}
		corpus.Fixtures = append(corpus.Fixtures, fixture)
	}
	if len(corpus.Fixtures) == 0 {
		return report, errors.New("corpus manifest has no fixtures")
	}
	if _, err := os.Stat(outputDirectory); !os.IsNotExist(err) {
		if err == nil {
			return report, fmt.Errorf("output directory %q already exists", outputDirectory)
		}
		return report, err
	}
	if err := os.MkdirAll(filepath.Join(outputDirectory, "events"), 0o750); err != nil {
		return report, err
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = os.RemoveAll(outputDirectory)
		}
	}()

	fixtureIndex := make(map[string]corpusFixture, len(corpus.Fixtures))
	for _, fixture := range corpus.Fixtures {
		if fixture.ID == "" || fixture.Path == "" || strings.Contains(fixture.Path, "..") || filepath.IsAbs(fixture.Path) {
			return report, fmt.Errorf("corpus fixture %q has unsafe identity or path", fixture.ID)
		}
		fixtureIndex[fixture.ID] = fixture
	}
	fixtureChoices := expandFixtureChoices(scenario.Mix)
	sizeChoices := expandSizeChoices(scenario.Sizes)
	random := rand.New(rand.NewSource(scenario.Seed))
	random.Shuffle(len(fixtureChoices), func(first, second int) {
		fixtureChoices[first], fixtureChoices[second] = fixtureChoices[second], fixtureChoices[first]
	})
	random.Shuffle(len(sizeChoices), func(first, second int) {
		sizeChoices[first], sizeChoices[second] = sizeChoices[second], sizeChoices[first]
	})

	manifest := DatasetManifest{ManifestVersion: "ulpf-benchmark-dataset/1", Scenario: scenario.Name, Seed: scenario.Seed, Events: make([]Event, 0, scenario.EventCount)}
	report = Report{
		ReportVersion:       ReportVersion,
		Scenario:            scenario.Name,
		Seed:                scenario.Seed,
		GeneratedEvents:     scenario.EventCount,
		FixtureCounts:       make(map[string]int),
		ScenarioCounts:      make(map[string]int),
		RequestedSizeCounts: make(map[string]int),
		MinimumActualBytes:  scenario.MaxEventBytes,
		MeasurementClaim:    "Dataset generation only; this report contains no throughput, latency, capacity, or format-support measurement.",
	}
	report.CorpusManifestSHA256 = digestHex(corpusBytes)
	report.ScenarioSHA256 = digestHex(scenarioBytes)
	corpusRoot := filepath.Dir(corpusManifestPath)
	for index := 0; index < scenario.EventCount; index++ {
		fixtureID := fixtureChoices[index%len(fixtureChoices)]
		fixture, found := fixtureIndex[fixtureID]
		if !found {
			return report, fmt.Errorf("scenario references unknown fixture %q", fixtureID)
		}
		sourcePath := filepath.Join(corpusRoot, filepath.FromSlash(fixture.Path))
		rawBytes, err := os.ReadFile(sourcePath)
		if err != nil {
			return report, fmt.Errorf("read fixture %q: %w", fixtureID, err)
		}
		requested := sizeChoices[index%len(sizeChoices)]
		generated := padFixture(rawBytes, fixture.Scenario, requested)
		if len(generated) > scenario.MaxEventBytes {
			return report, fmt.Errorf("event %d is %d bytes and exceeds max_event_bytes", index, len(generated))
		}
		relative := filepath.ToSlash(filepath.Join("events", fmt.Sprintf("%06d.bin", index)))
		if err := os.WriteFile(filepath.Join(outputDirectory, filepath.FromSlash(relative)), generated, 0o640); err != nil {
			return report, err
		}
		event := Event{
			Index: index, OccurrenceID: fmt.Sprintf("benchmark-%06d", index), Path: relative,
			SourceFixture: fixtureID, SourceScenario: fixture.Scenario, RequestedBytes: requested,
			SizeBytes: len(generated), SHA256: digestHex(generated),
		}
		manifest.Events = append(manifest.Events, event)
		report.FixtureCounts[fixtureID]++
		report.ScenarioCounts[fixture.Scenario]++
		report.RequestedSizeCounts[fmt.Sprintf("%d", requested)]++
		if len(generated) < report.MinimumActualBytes {
			report.MinimumActualBytes = len(generated)
		}
		if len(generated) > report.MaximumActualBytes {
			report.MaximumActualBytes = len(generated)
		}
	}
	report.DatasetSHA256 = datasetDigest(manifest.Events)
	if err := writeJSON(filepath.Join(outputDirectory, "manifest.json"), manifest); err != nil {
		return report, err
	}
	if err := writeJSON(filepath.Join(outputDirectory, "generation-report.json"), report); err != nil {
		return report, err
	}
	if err := os.WriteFile(filepath.Join(outputDirectory, "generation-report.md"), []byte(markdownReport(report)), 0o640); err != nil {
		return report, err
	}
	succeeded = true
	return report, nil
}

func validateScenario(scenario Scenario) error {
	if scenario.ScenarioVersion != ScenarioVersion || !validName(scenario.Name) {
		return errors.New("scenario_version or name is invalid")
	}
	if scenario.EventCount < 1 || scenario.EventCount > maxEvents {
		return fmt.Errorf("event_count must be between 1 and %d", maxEvents)
	}
	if scenario.MaxEventBytes < 1 || scenario.MaxEventBytes > maxBytes {
		return fmt.Errorf("max_event_bytes must be between 1 and %d", maxBytes)
	}
	if len(scenario.Mix) == 0 || len(scenario.Sizes) == 0 {
		return errors.New("mix and sizes must not be empty")
	}
	seen := make(map[string]struct{}, len(scenario.Mix))
	totalMix := 0
	for _, item := range scenario.Mix {
		if !validName(item.FixtureID) || item.Weight < 1 || item.Weight > 10_000 {
			return errors.New("fixture id or weight is invalid")
		}
		if _, duplicate := seen[item.FixtureID]; duplicate {
			return fmt.Errorf("fixture %q is duplicated", item.FixtureID)
		}
		seen[item.FixtureID] = struct{}{}
		totalMix += item.Weight
	}
	seenSizes := make(map[int]struct{}, len(scenario.Sizes))
	totalSizes := 0
	for _, item := range scenario.Sizes {
		if item.Bytes < 1 || item.Bytes > scenario.MaxEventBytes || item.Weight < 1 || item.Weight > 10_000 {
			return errors.New("size or weight is invalid")
		}
		if _, duplicate := seenSizes[item.Bytes]; duplicate {
			return fmt.Errorf("size %d is duplicated", item.Bytes)
		}
		seenSizes[item.Bytes] = struct{}{}
		totalSizes += item.Weight
	}
	if totalMix > 100_000 || totalSizes > 100_000 {
		return errors.New("total weights exceed 100000")
	}
	return nil
}

func expandFixtureChoices(items []WeightedFixture) []string {
	var result []string
	for _, item := range items {
		for count := 0; count < item.Weight; count++ {
			result = append(result, item.FixtureID)
		}
	}
	return result
}

func expandSizeChoices(items []WeightedSize) []int {
	var result []int
	for _, item := range items {
		for count := 0; count < item.Weight; count++ {
			result = append(result, item.Bytes)
		}
	}
	return result
}

func padFixture(input []byte, scenario string, requested int) []byte {
	if len(input) >= requested {
		return bytes.Clone(input)
	}
	missing := requested - len(input)
	if scenario == "router_text" {
		marker := []byte("|synthetic=true")
		if position := bytes.LastIndex(input, marker); position >= 0 {
			output := make([]byte, 0, requested)
			output = append(output, input[:position]...)
			output = append(output, bytes.Repeat([]byte{'x'}, missing)...)
			output = append(output, input[position:]...)
			return output
		}
	}
	position := len(input)
	if position > 0 && input[position-1] == '\n' {
		position--
	}
	output := make([]byte, 0, requested)
	output = append(output, input[:position]...)
	output = append(output, bytes.Repeat([]byte{' '}, missing)...)
	output = append(output, input[position:]...)
	return output
}

func datasetDigest(events []Event) string {
	hash := sha256.New()
	for _, event := range events {
		fmt.Fprintf(hash, "%s\x00%s\x00%d\n", event.Path, event.SHA256, event.SizeBytes)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func digestHex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func writeJSON(path string, value any) error {
	contents, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	contents = append(contents, '\n')
	return os.WriteFile(path, contents, 0o640)
}

func markdownReport(report Report) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "# Benchmark dataset generation report\n\n")
	fmt.Fprintf(&builder, "- Scenario: `%s`\n- Seed: `%d`\n- Generated events: `%d`\n", report.Scenario, report.Seed, report.GeneratedEvents)
	fmt.Fprintf(&builder, "- Dataset SHA-256: `%s`\n- Actual byte range: `%d`–`%d`\n\n", report.DatasetSHA256, report.MinimumActualBytes, report.MaximumActualBytes)
	fmt.Fprintf(&builder, "%s\n\n", report.MeasurementClaim)
	fmt.Fprintf(&builder, "## Source scenario counts\n\n| Scenario | Events |\n|---|---:|\n")
	keys := make([]string, 0, len(report.ScenarioCounts))
	for key := range report.ScenarioCounts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(&builder, "| `%s` | %d |\n", key, report.ScenarioCounts[key])
	}
	return builder.String()
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("decode trailing scenario data: %w", err)
	}
	return errors.New("scenario contains multiple JSON values")
}

func validName(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || index > 0 && (character == '-' || character == '_' || character == '.') {
			continue
		}
		return false
	}
	return true
}
