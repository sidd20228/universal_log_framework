package registry_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sidd20228/universal_log_framework/internal/bundlecompile"
	"github.com/sidd20228/universal_log_framework/internal/registry"
)

func TestScaffoldIsDeterministicCompilableAndConflictSafe(t *testing.T) {
	for _, format := range []string{"json", "kv"} {
		t.Run(format, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "bundle")
			options := registry.ScaffoldOptions{Directory: directory, BundleID: "starter-" + format, Version: "1.0.0", Format: format}
			if err := registry.Scaffold(options); err != nil {
				t.Fatal(err)
			}
			if err := registry.Scaffold(options); err != nil {
				t.Fatalf("idempotent scaffold: %v", err)
			}
			descriptor, err := testLoader(t).LoadDirectory(context.Background(), directory)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := bundlecompile.Compile(context.Background(), descriptor); err != nil {
				t.Fatalf("compile scaffold: %v", err)
			}
			if err := os.WriteFile(filepath.Join(directory, "parser.json"), []byte("changed"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := registry.Scaffold(options); !errors.Is(err, registry.ErrScaffoldConflict) {
				t.Fatalf("conflict error = %v", err)
			}
		})
	}
}
