// Package benchrun measures the local durable ULPF pipeline with a generated,
// content-addressed dataset.
package benchrun

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sort"
	"strings"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/benchgen"
	"github.com/sidd20228/universal_log_framework/internal/detect"
	"github.com/sidd20228/universal_log_framework/internal/evidence"
	"github.com/sidd20228/universal_log_framework/internal/inbox"
	"github.com/sidd20228/universal_log_framework/internal/ingress"
	"github.com/sidd20228/universal_log_framework/internal/interpret/cef"
	csvparser "github.com/sidd20228/universal_log_framework/internal/interpret/csv"
	jsonparser "github.com/sidd20228/universal_log_framework/internal/interpret/json"
	"github.com/sidd20228/universal_log_framework/internal/interpret/kv"
	"github.com/sidd20228/universal_log_framework/internal/interpret/re2parser"
	"github.com/sidd20228/universal_log_framework/internal/interpret/syslog"
	"github.com/sidd20228/universal_log_framework/internal/interpret/xml"
	"github.com/sidd20228/universal_log_framework/internal/model"
	"github.com/sidd20228/universal_log_framework/internal/worker"
)

const (
	ConfigVersion = "ulpf-benchmark-profile/1"
	ReportVersion = "ulpf-performance-report/1"
)

type Config struct {
	ProfileVersion      string `json:"profile_version"`
	Name                string `json:"name"`
	TenantID            string `json:"tenant_id"`
	ListenerID          string `json:"listener_id"`
	PipelineVersion     string `json:"pipeline_version"`
	MaxEventBytes       int    `json:"max_event_bytes"`
	LeaseDurationMS     int    `json:"lease_duration_ms"`
	RenewIntervalMS     int    `json:"renew_interval_ms"`
	ProcessingTimeoutMS int    `json:"processing_timeout_ms"`
	MaxAttempts         int    `json:"max_attempts"`
	CaptureProfiles     bool   `json:"capture_profiles"`
}

type Options struct {
	ScenarioPath string
	CorpusPath   string
	ConfigPath   string
	OutputDir    string
	Repository   string
	WorkBase     string
}

type Provenance struct {
	GitCommit      string `json:"git_commit"`
	GitDirty       bool   `json:"git_dirty"`
	CodeSHA256     string `json:"code_sha256"`
	ScenarioSHA256 string `json:"scenario_sha256"`
	ConfigSHA256   string `json:"config_sha256"`
	DatasetSHA256  string `json:"dataset_sha256"`
	GoVersion      string `json:"go_version"`
	GOOS           string `json:"goos"`
	GOARCH         string `json:"goarch"`
	LogicalCPUs    int    `json:"logical_cpus"`
	GOMAXPROCS     int    `json:"gomaxprocs"`
	CPUModel       string `json:"cpu_model,omitempty"`
	MemoryBytes    uint64 `json:"memory_bytes,omitempty"`
}

type Latency struct {
	Samples int64 `json:"samples"`
	MinNS   int64 `json:"min_ns"`
	P50NS   int64 `json:"p50_ns"`
	P95NS   int64 `json:"p95_ns"`
	P99NS   int64 `json:"p99_ns"`
	MaxNS   int64 `json:"max_ns"`
}

type Allocations struct {
	TotalBytes        uint64  `json:"total_bytes"`
	TotalObjects      uint64  `json:"total_objects"`
	BytesPerEvent     float64 `json:"bytes_per_event"`
	ObjectsPerEvent   float64 `json:"objects_per_event"`
	HeapBeforeBytes   uint64  `json:"heap_before_bytes"`
	HeapAfterBytes    uint64  `json:"heap_after_bytes"`
	HeapSysAfterBytes uint64  `json:"heap_sys_after_bytes"`
}

type Resources struct {
	UserCPUSeconds    float64 `json:"user_cpu_seconds"`
	SystemCPUSeconds  float64 `json:"system_cpu_seconds"`
	TotalCPUSeconds   float64 `json:"total_cpu_seconds"`
	ProcessCPUPercent float64 `json:"process_cpu_percent"`
	PeakRSSBytes      uint64  `json:"peak_rss_bytes,omitempty"`
}

type Storage struct {
	RawPayloadBytes        uint64  `json:"raw_payload_bytes"`
	WorkingSetLogicalBytes uint64  `json:"working_set_logical_bytes"`
	LogicalWriteRatio      float64 `json:"logical_write_ratio"`
}

type Measurements struct {
	Submitted         int64          `json:"submitted"`
	Accepted          int64          `json:"accepted"`
	Rejected          int64          `json:"rejected"`
	Revisions         int64          `json:"revisions"`
	RawVerified       int64          `json:"raw_verified"`
	HashMismatches    int64          `json:"hash_mismatches"`
	LinkageFailures   int64          `json:"linkage_failures"`
	Statuses          map[string]int `json:"statuses"`
	WallTimeNS        int64          `json:"wall_time_ns"`
	ThroughputEPS     float64        `json:"throughput_events_per_second"`
	Acceptance        Latency        `json:"durable_acceptance_latency"`
	Processing        Latency        `json:"processing_latency"`
	ReceiptToRevision Latency        `json:"receipt_to_revision_latency"`
	Allocations       Allocations    `json:"allocations"`
	Resources         Resources      `json:"resources"`
	Storage           Storage        `json:"storage"`
}

type Artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type Report struct {
	ReportVersion string       `json:"report_version"`
	GeneratedAt   time.Time    `json:"generated_at"`
	Scope         string       `json:"scope"`
	Claim         string       `json:"claim"`
	Scenario      string       `json:"scenario"`
	Seed          int64        `json:"seed"`
	Config        Config       `json:"config"`
	Provenance    Provenance   `json:"provenance"`
	Measurements  Measurements `json:"measurements"`
	Artifacts     []Artifact   `json:"artifacts,omitempty"`
}

type receiptSample struct {
	receipt model.Receipt
	start   time.Time
	event   benchgen.Event
}

func Run(ctx context.Context, options Options) (Report, error) {
	var report Report
	if err := validateOptions(options); err != nil {
		return report, err
	}
	config, configBytes, err := LoadConfig(options.ConfigPath)
	if err != nil {
		return report, err
	}
	scenario, scenarioBytes, err := benchgen.LoadScenario(options.ScenarioPath)
	if err != nil {
		return report, err
	}
	provenance, err := collectProvenance(options.Repository, scenarioBytes, configBytes)
	if err != nil {
		return report, err
	}
	if _, err := os.Stat(options.OutputDir); !os.IsNotExist(err) {
		if err == nil {
			return report, fmt.Errorf("output directory %q already exists", options.OutputDir)
		}
		return report, err
	}
	if err := os.MkdirAll(options.OutputDir, 0o750); err != nil {
		return report, err
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = os.RemoveAll(options.OutputDir)
		}
	}()
	work, err := os.MkdirTemp(options.WorkBase, "ulpf-benchmark-*")
	if err != nil {
		return report, err
	}
	defer os.RemoveAll(work)
	datasetDir := filepath.Join(work, "dataset")
	generation, err := benchgen.Generate(options.ScenarioPath, options.CorpusPath, datasetDir)
	if err != nil {
		return report, err
	}
	provenance.DatasetSHA256 = generation.DatasetSHA256
	events, err := loadAndVerifyDataset(datasetDir)
	if err != nil {
		return report, err
	}

	report = Report{
		ReportVersion: ReportVersion,
		GeneratedAt:   time.Now().UTC(),
		Scope:         "single-process local filesystem evidence + SQLite inbox + built-in detection/parsing + SQLite envelope commit",
		Claim:         "Measured on the recorded host and generated dataset only; this is not a production, network-ingress, ClickHouse, multi-node, sustained-load, or capacity result.",
		Scenario:      scenario.Name,
		Seed:          scenario.Seed,
		Config:        config,
		Provenance:    provenance,
	}
	measurements, artifacts, err := execute(ctx, work, options.OutputDir, config, events)
	if err != nil {
		return report, err
	}
	report.Measurements = measurements
	report.Artifacts = artifacts
	if err := writeReport(options.OutputDir, report); err != nil {
		return report, err
	}
	succeeded = true
	return report, nil
}

func LoadConfig(path string) (Config, []byte, error) {
	var config Config
	contents, err := os.ReadFile(path)
	if err != nil {
		return config, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return config, nil, fmt.Errorf("decode benchmark profile: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return config, nil, errors.New("benchmark profile must contain one JSON value")
	}
	if err := config.validate(); err != nil {
		return config, nil, err
	}
	return config, contents, nil
}

func (config Config) validate() error {
	if config.ProfileVersion != ConfigVersion || strings.TrimSpace(config.Name) == "" || strings.TrimSpace(config.TenantID) == "" || strings.TrimSpace(config.ListenerID) == "" {
		return errors.New("benchmark profile version, name, tenant, and listener are required")
	}
	if strings.TrimSpace(config.PipelineVersion) == "" || config.MaxEventBytes < 1 || config.LeaseDurationMS < 1 || config.RenewIntervalMS < 1 || config.ProcessingTimeoutMS < 1 || config.MaxAttempts < 1 {
		return errors.New("benchmark profile limits must be positive")
	}
	if config.RenewIntervalMS >= config.LeaseDurationMS {
		return errors.New("benchmark lease duration must exceed renew interval")
	}
	return nil
}

func validateOptions(options Options) error {
	if options.ScenarioPath == "" || options.CorpusPath == "" || options.ConfigPath == "" || options.OutputDir == "" || options.Repository == "" {
		return errors.New("scenario, corpus, config, output, and repository paths are required")
	}
	return nil
}

func execute(ctx context.Context, work, output string, config Config, events []benchgen.Event) (Measurements, []Artifact, error) {
	measurements := Measurements{Submitted: int64(len(events)), Statuses: make(map[string]int)}
	rawStore, err := evidence.NewFilesystem(filepath.Join(work, "raw"))
	if err != nil {
		return measurements, nil, err
	}
	queue, err := inbox.OpenSQLite(ctx, filepath.Join(work, "inbox.sqlite"))
	if err != nil {
		return measurements, nil, err
	}
	defer queue.Close()
	admitter, err := ingress.NewCoordinator(rawStore, queue, int64(config.MaxEventBytes))
	if err != nil {
		return measurements, nil, err
	}
	detector, err := detect.NewDefault()
	if err != nil {
		return measurements, nil, err
	}
	pipelines, err := builtinPipelines()
	if err != nil {
		return measurements, nil, err
	}
	resolver, err := worker.NewStaticResolver(pipelines)
	if err != nil {
		return measurements, nil, err
	}
	processor, err := worker.New(worker.Config{
		Owner: "benchmark-worker", PipelineVersion: config.PipelineVersion,
		LeaseDuration:     time.Duration(config.LeaseDurationMS) * time.Millisecond,
		RenewInterval:     time.Duration(config.RenewIntervalMS) * time.Millisecond,
		ProcessingTimeout: time.Duration(config.ProcessingTimeoutMS) * time.Millisecond,
		MaxAttempts:       config.MaxAttempts, MaxEvidenceBytes: config.MaxEventBytes,
	}, queue, rawStore, detector, resolver)
	if err != nil {
		return measurements, nil, err
	}

	var artifacts []Artifact
	var cpuFile *os.File
	cpuRunning := false
	stopCPUProfile := func() error {
		if !cpuRunning {
			return nil
		}
		pprof.StopCPUProfile()
		cpuRunning = false
		return cpuFile.Close()
	}
	defer func() { _ = stopCPUProfile() }()
	if config.CaptureProfiles {
		cpuPath := filepath.Join(output, "cpu.pprof")
		cpuFile, err = os.OpenFile(cpuPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
		if err != nil {
			return measurements, nil, err
		}
		if err := pprof.StartCPUProfile(cpuFile); err != nil {
			_ = cpuFile.Close()
			return measurements, nil, err
		}
		cpuRunning = true
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	resourcesBefore := readProcessResources()
	wallStart := time.Now()
	acceptance := make([]time.Duration, 0, len(events))
	processing := make([]time.Duration, 0, len(events))
	endToEnd := make([]time.Duration, 0, len(events))
	samples := make(map[string]receiptSample, len(events))

	for _, event := range events {
		payload, err := os.ReadFile(event.Path)
		if err != nil {
			return measurements, nil, err
		}
		started := time.Now()
		admitted, err := admitter.Admit(ctx, ingress.AdmissionRequest{
			Payload: bytes.NewReader(payload), TenantID: config.TenantID, ListenerID: config.ListenerID,
			SourceProfileID: event.SourceScenario, Transport: model.TransportHTTP, FramingMode: model.FramingHTTPOctets,
		})
		acceptance = append(acceptance, time.Since(started))
		if err != nil {
			measurements.Rejected++
			return measurements, nil, fmt.Errorf("admit event %d: %w", event.Index, err)
		}
		measurements.Accepted++
		samples[admitted.Receipt.ID] = receiptSample{receipt: admitted.Receipt, start: started, event: event}
	}

	for range events {
		started := time.Now()
		step, err := processor.RunOnce(ctx)
		processing = append(processing, time.Since(started))
		if err != nil {
			return measurements, nil, err
		}
		if step.Outcome != worker.OutcomeCommitted && step.Outcome != worker.OutcomeDeadLetter {
			return measurements, nil, fmt.Errorf("worker returned non-terminal outcome %s for %s", step.Outcome, step.ReceiptID)
		}
		sample, found := samples[step.ReceiptID]
		if !found {
			measurements.LinkageFailures++
			continue
		}
		endToEnd = append(endToEnd, time.Since(sample.start))
		revision, err := queue.GetRevision(ctx, step.RevisionID)
		if err != nil {
			return measurements, nil, err
		}
		stored, err := queue.GetEnvelope(ctx, step.RevisionID)
		if err != nil {
			return measurements, nil, err
		}
		measurements.Revisions++
		measurements.Statuses[string(revision.Status)]++
		if revision.ReceiptID != step.ReceiptID || stored.Receipt.ID != step.ReceiptID || stored.Processing.RevisionID != step.RevisionID || stored.Raw.SHA256 != sample.receipt.Raw.SHA256 {
			measurements.LinkageFailures++
		}
	}
	wallDuration := time.Since(wallStart)
	if err := stopCPUProfile(); err != nil {
		return measurements, nil, err
	}
	measurements.WallTimeNS = wallDuration.Nanoseconds()
	if wallDuration > 0 {
		measurements.ThroughputEPS = float64(measurements.Revisions) / wallDuration.Seconds()
	}
	resourcesAfter := readProcessResources()
	runtime.ReadMemStats(&after)

	for _, sample := range samples {
		if err := rawStore.Verify(ctx, sample.receipt.Raw); err != nil {
			measurements.HashMismatches++
			continue
		}
		reader, err := rawStore.Open(ctx, sample.receipt.Raw)
		if err != nil {
			return measurements, nil, err
		}
		actual, readErr := io.ReadAll(reader)
		closeErr := reader.Close()
		expected, fileErr := os.ReadFile(sample.event.Path)
		if readErr != nil || closeErr != nil || fileErr != nil {
			return measurements, nil, errors.Join(readErr, closeErr, fileErr)
		}
		if !bytes.Equal(actual, expected) {
			measurements.HashMismatches++
			continue
		}
		measurements.RawVerified++
	}
	measurements.Acceptance = summarizeLatency(acceptance)
	measurements.Processing = summarizeLatency(processing)
	measurements.ReceiptToRevision = summarizeLatency(endToEnd)
	measurements.Allocations = allocationDelta(before, after, int64(len(events)))
	measurements.Resources = resourceDelta(resourcesBefore, resourcesAfter, wallDuration)
	measurements.Storage.RawPayloadBytes = sumEventBytes(events)
	measurements.Storage.WorkingSetLogicalBytes, err = pipelineLogicalBytes(work)
	if err != nil {
		return measurements, nil, err
	}
	if measurements.Storage.RawPayloadBytes > 0 {
		measurements.Storage.LogicalWriteRatio = float64(measurements.Storage.WorkingSetLogicalBytes) / float64(measurements.Storage.RawPayloadBytes)
	}

	if config.CaptureProfiles {
		if file, err := os.OpenFile(filepath.Join(output, "heap.pprof"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640); err != nil {
			return measurements, nil, err
		} else {
			if err := pprof.WriteHeapProfile(file); err != nil {
				file.Close()
				return measurements, nil, err
			}
			if err := file.Close(); err != nil {
				return measurements, nil, err
			}
		}
		for _, name := range []string{"cpu.pprof", "heap.pprof"} {
			digest, err := fileDigest(filepath.Join(output, name))
			if err != nil {
				return measurements, nil, err
			}
			artifacts = append(artifacts, Artifact{Path: name, SHA256: digest})
		}
	}
	return measurements, artifacts, nil
}

func builtinPipelines() ([]worker.Pipeline, error) {
	router, err := re2parser.New(re2parser.Config{
		ConfigVersion: re2parser.ConfigVersion, ID: "generic-router-text", Version: "1.0.0",
		Format: "delimited_text", Pattern: `^(?P<message>(?s:.*))$`, Required: []string{"message"},
	})
	if err != nil {
		return nil, fmt.Errorf("configure benchmark router parser: %w", err)
	}
	return []worker.Pipeline{
		{Parser: jsonparser.New()}, {Parser: syslog.New()}, {Parser: cef.NewCEF()}, {Parser: cef.NewLEEF()},
		{Parser: csvparser.New()}, {Parser: kvparser.New()}, {Parser: xmlparser.New()}, {Parser: router},
	}, nil
}

func loadAndVerifyDataset(directory string) ([]benchgen.Event, error) {
	contents, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var manifest benchgen.DatasetManifest
	if err := json.Unmarshal(contents, &manifest); err != nil {
		return nil, err
	}
	if manifest.ManifestVersion != "ulpf-benchmark-dataset/1" || len(manifest.Events) == 0 {
		return nil, errors.New("benchmark dataset manifest is invalid")
	}
	events := append([]benchgen.Event(nil), manifest.Events...)
	for index := range events {
		if filepath.IsAbs(events[index].Path) || strings.Contains(events[index].Path, "..") {
			return nil, fmt.Errorf("event %d has unsafe path", events[index].Index)
		}
		path := filepath.Join(directory, filepath.FromSlash(events[index].Path))
		contents, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if len(contents) != events[index].SizeBytes || digestBytes(contents) != events[index].SHA256 {
			return nil, fmt.Errorf("event %d failed dataset integrity verification", events[index].Index)
		}
		events[index].Path = path
	}
	sort.Slice(events, func(left, right int) bool { return events[left].Index < events[right].Index })
	return events, nil
}

func summarizeLatency(values []time.Duration) Latency {
	if len(values) == 0 {
		return Latency{}
	}
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return Latency{Samples: int64(len(sorted)), MinNS: sorted[0].Nanoseconds(), P50NS: nearestRank(sorted, 50).Nanoseconds(), P95NS: nearestRank(sorted, 95).Nanoseconds(), P99NS: nearestRank(sorted, 99).Nanoseconds(), MaxNS: sorted[len(sorted)-1].Nanoseconds()}
}

func nearestRank(sorted []time.Duration, percentile int) time.Duration {
	index := (percentile*len(sorted) + 99) / 100
	if index < 1 {
		index = 1
	}
	return sorted[index-1]
}

func allocationDelta(before, after runtime.MemStats, events int64) Allocations {
	result := Allocations{TotalBytes: after.TotalAlloc - before.TotalAlloc, TotalObjects: after.Mallocs - before.Mallocs, HeapBeforeBytes: before.HeapAlloc, HeapAfterBytes: after.HeapAlloc, HeapSysAfterBytes: after.HeapSys}
	if events > 0 {
		result.BytesPerEvent = float64(result.TotalBytes) / float64(events)
		result.ObjectsPerEvent = float64(result.TotalObjects) / float64(events)
	}
	return result
}

func sumEventBytes(events []benchgen.Event) uint64 {
	var total uint64
	for _, event := range events {
		total += uint64(event.SizeBytes)
	}
	return total
}

func directoryLogicalBytes(root string) (uint64, error) {
	var total uint64
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type().IsRegular() {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			total += uint64(info.Size())
		}
		return nil
	})
	return total, err
}

func pipelineLogicalBytes(work string) (uint64, error) {
	total, err := directoryLogicalBytes(filepath.Join(work, "raw"))
	if err != nil {
		return 0, err
	}
	for _, name := range []string{"inbox.sqlite", "inbox.sqlite-wal", "inbox.sqlite-shm"} {
		info, err := os.Stat(filepath.Join(work, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return 0, err
		}
		total += uint64(info.Size())
	}
	return total, nil
}

func collectProvenance(repository string, scenario, config []byte) (Provenance, error) {
	code, err := codeDigest(repository)
	if err != nil {
		return Provenance{}, err
	}
	commit := commandOutput(repository, "git", "rev-parse", "HEAD")
	dirty := commandOutput(repository, "git", "status", "--porcelain") != ""
	cpu, memory := hardwareInfo()
	return Provenance{GitCommit: commit, GitDirty: dirty, CodeSHA256: code, ScenarioSHA256: digestBytes(scenario), ConfigSHA256: digestBytes(config), GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, LogicalCPUs: runtime.NumCPU(), GOMAXPROCS: runtime.GOMAXPROCS(0), CPUModel: cpu, MemoryBytes: memory}, nil
}

func codeDigest(root string) (string, error) {
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	command := exec.Command("go", "list", "-deps", "-json", "./cmd/ulpf-benchmark")
	command.Dir = absoluteRoot
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("list benchmark dependencies: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	type packageFiles struct {
		Dir        string
		GoFiles    []string
		CgoFiles   []string
		SFiles     []string
		EmbedFiles []string
	}
	pathsByName := make(map[string]struct{})
	for {
		var pkg packageFiles
		if err := decoder.Decode(&pkg); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return "", fmt.Errorf("decode benchmark dependencies: %w", err)
		}
		if pkg.Dir != absoluteRoot && !strings.HasPrefix(pkg.Dir, absoluteRoot+string(filepath.Separator)) {
			continue
		}
		for _, name := range append(append(append(pkg.GoFiles, pkg.CgoFiles...), pkg.SFiles...), pkg.EmbedFiles...) {
			pathsByName[filepath.Join(pkg.Dir, name)] = struct{}{}
		}
	}
	for _, name := range []string{"go.mod", "go.sum"} {
		pathsByName[filepath.Join(absoluteRoot, name)] = struct{}{}
	}
	paths := make([]string, 0, len(pathsByName))
	for path := range pathsByName {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	hash := sha256.New()
	for _, path := range paths {
		relative, _ := filepath.Rel(absoluteRoot, path)
		contents, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(hash, "%s\x00", filepath.ToSlash(relative))
		hash.Write(contents)
		hash.Write([]byte{'\n'})
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func commandOutput(directory, name string, args ...string) string {
	command := exec.Command(name, args...)
	command.Dir = directory
	output, err := command.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func fileDigest(path string) (string, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return digestBytes(contents), nil
}

func writeReport(directory string, report Report) error {
	contents, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	contents = append(contents, '\n')
	if err := os.WriteFile(filepath.Join(directory, "report.json"), contents, 0o640); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(directory, "report.md"), []byte(markdown(report)), 0o640)
}

func markdown(report Report) string {
	m := report.Measurements
	var builder strings.Builder
	fmt.Fprintf(&builder, "# Local pipeline performance report\n\nGenerated: `%s`\n\n%s\n\n", report.GeneratedAt.Format(time.RFC3339), report.Claim)
	fmt.Fprintf(&builder, "## Scope\n\n%s.\n\n", report.Scope)
	fmt.Fprintf(&builder, "## Result\n\n| Metric | Measured value |\n|---|---:|\n")
	fmt.Fprintf(&builder, "| Submitted / accepted / rejected | %d / %d / %d |\n", m.Submitted, m.Accepted, m.Rejected)
	fmt.Fprintf(&builder, "| Revisions / raw verified | %d / %d |\n", m.Revisions, m.RawVerified)
	fmt.Fprintf(&builder, "| Hash mismatches / linkage failures | %d / %d |\n", m.HashMismatches, m.LinkageFailures)
	fmt.Fprintf(&builder, "| Wall time | %.3f s |\n| Throughput | %.2f events/s |\n", float64(m.WallTimeNS)/1e9, m.ThroughputEPS)
	fmt.Fprintf(&builder, "| Durable acceptance p50 / p95 / p99 | %.3f / %.3f / %.3f ms |\n", ms(m.Acceptance.P50NS), ms(m.Acceptance.P95NS), ms(m.Acceptance.P99NS))
	fmt.Fprintf(&builder, "| Processing p50 / p95 / p99 | %.3f / %.3f / %.3f ms |\n", ms(m.Processing.P50NS), ms(m.Processing.P95NS), ms(m.Processing.P99NS))
	fmt.Fprintf(&builder, "| Receipt-to-revision p50 / p95 / p99 | %.3f / %.3f / %.3f ms |\n", ms(m.ReceiptToRevision.P50NS), ms(m.ReceiptToRevision.P95NS), ms(m.ReceiptToRevision.P99NS))
	fmt.Fprintf(&builder, "| Allocated bytes / objects per event | %.0f / %.1f |\n", m.Allocations.BytesPerEvent, m.Allocations.ObjectsPerEvent)
	fmt.Fprintf(&builder, "| User / system CPU | %.3f / %.3f s |\n| Process CPU / wall | %.1f%% |\n", m.Resources.UserCPUSeconds, m.Resources.SystemCPUSeconds, m.Resources.ProcessCPUPercent)
	fmt.Fprintf(&builder, "| Peak RSS / final heap | %.2f / %.2f MiB |\n", mib(m.Resources.PeakRSSBytes), mib(m.Allocations.HeapAfterBytes))
	fmt.Fprintf(&builder, "| Logical working-set / raw ratio | %.3fx |\n", m.Storage.LogicalWriteRatio)
	fmt.Fprintf(&builder, "\n## Provenance\n\n| Field | Value |\n|---|---|\n")
	fmt.Fprintf(&builder, "| Scenario / seed | `%s` / `%d` |\n| Dataset SHA-256 | `%s` |\n| Scenario SHA-256 | `%s` |\n| Profile SHA-256 | `%s` |\n| Code SHA-256 | `%s` |\n", report.Scenario, report.Seed, report.Provenance.DatasetSHA256, report.Provenance.ScenarioSHA256, report.Provenance.ConfigSHA256, report.Provenance.CodeSHA256)
	fmt.Fprintf(&builder, "| Git commit / dirty | `%s` / `%t` |\n| Runtime | `%s %s/%s` |\n| CPU | `%s` (%d logical, GOMAXPROCS=%d) |\n| Host memory | %.2f GiB |\n", report.Provenance.GitCommit, report.Provenance.GitDirty, report.Provenance.GoVersion, report.Provenance.GOOS, report.Provenance.GOARCH, report.Provenance.CPUModel, report.Provenance.LogicalCPUs, report.Provenance.GOMAXPROCS, float64(report.Provenance.MemoryBytes)/(1<<30))
	if len(report.Artifacts) != 0 {
		fmt.Fprintf(&builder, "\n## Profiles\n\n")
		for _, artifact := range report.Artifacts {
			fmt.Fprintf(&builder, "- `%s` — SHA-256 `%s`\n", artifact.Path, artifact.SHA256)
		}
	}
	return builder.String()
}

func ms(nanoseconds int64) float64 { return float64(nanoseconds) / 1e6 }
func mib(bytes uint64) float64     { return float64(bytes) / (1 << 20) }
