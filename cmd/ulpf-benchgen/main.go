package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/sidd20228/universal_log_framework/internal/benchgen"
)

func main() {
	scenario := flag.String("scenario", "benchmarks/scenarios/default.json", "benchmark scenario JSON")
	corpus := flag.String("corpus", "tests/corpus/manifest.json", "synthetic corpus manifest")
	output := flag.String("out", "", "new output directory (required)")
	flag.Parse()
	if *output == "" {
		fmt.Fprintln(os.Stderr, "-out is required and must not already exist")
		os.Exit(2)
	}
	report, err := benchgen.Generate(*scenario, *corpus, *output)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("generated %d events; dataset_sha256=%s\n", report.GeneratedEvents, report.DatasetSHA256)
}
