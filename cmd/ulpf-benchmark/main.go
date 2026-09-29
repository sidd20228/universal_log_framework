package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/sidd20228/universal_log_framework/internal/benchrun"
)

func main() {
	scenario := flag.String("scenario", "benchmarks/scenarios/default.json", "benchmark scenario JSON")
	corpus := flag.String("corpus", "tests/corpus/manifest.json", "synthetic corpus manifest")
	profile := flag.String("profile", "benchmarks/profiles/local-e2e.json", "measurement profile JSON")
	output := flag.String("out", "", "new report directory (required)")
	repository := flag.String("repo", ".", "repository root used for code provenance")
	work := flag.String("work-dir", "", "temporary work parent; defaults to the operating-system temporary directory")
	flag.Parse()
	if *output == "" {
		fmt.Fprintln(os.Stderr, "-out is required and must not already exist")
		os.Exit(2)
	}
	report, err := benchrun.Run(context.Background(), benchrun.Options{
		ScenarioPath: *scenario, CorpusPath: *corpus, ConfigPath: *profile,
		OutputDir: *output, Repository: *repository, WorkBase: *work,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("measured %d revisions in %.3fs: %.2f events/s; report=%s\n",
		report.Measurements.Revisions,
		float64(report.Measurements.WallTimeNS)/1e9,
		report.Measurements.ThroughputEPS,
		*output,
	)
}
