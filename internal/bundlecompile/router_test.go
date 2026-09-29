package bundlecompile_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/sidd20228/universal_log_framework/internal/bundlecompile"
	"github.com/sidd20228/universal_log_framework/internal/detect"
	"github.com/sidd20228/universal_log_framework/internal/inbox"
	"github.com/sidd20228/universal_log_framework/internal/registry"
)

func TestRouterLiveActivationRollbackPublishesWholeSnapshots(t *testing.T) {
	ctx := context.Background()
	loader := referenceLoader(t)
	fallbackBundle, err := bundlecompile.Compile(ctx, mustDescriptor(t, loader, referenceRoot("json-firewall")))
	if err != nil {
		t.Fatal(err)
	}
	fallbackDetector, err := fallbackBundle.NewDetector(detect.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	fallbackResolver, err := fallbackBundle.NewResolver()
	if err != nil {
		t.Fatal(err)
	}
	router, err := bundlecompile.NewRouter(fallbackDetector, fallbackResolver)
	if err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	t.Cleanup(func() {
		_ = filepath.Walk(filepath.Join(root, "catalog"), func(path string, info os.FileInfo, err error) error {
			if err == nil {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	store, err := inbox.OpenSQLite(ctx, filepath.Join(root, "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	lifecycle, err := registry.NewLifecycle(ctx, filepath.Join(root, "catalog"), loader, store)
	if err != nil {
		t.Fatal(err)
	}
	jsonBundle, err := lifecycle.Install(ctx, referenceRoot("json-firewall"))
	if err != nil {
		t.Fatal(err)
	}
	kvBundle, err := lifecycle.Install(ctx, referenceRoot("kv-firewall"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := router.Activate(ctx, lifecycle, "edge", jsonBundle.Digest, 0, "test"); err != nil {
		t.Fatal(err)
	}

	jsonPayload := readFile(t, filepath.Join(referenceRoot("json-firewall"), "fixtures/valid/traffic.json"))
	kvPayload := readFile(t, filepath.Join(referenceRoot("kv-firewall"), "fixtures/valid/traffic.log"))
	var wait sync.WaitGroup
	for index := 0; index < 16; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < 100; iteration++ {
				_, _ = router.Detect(ctx, bytes.NewReader(jsonPayload), detect.Hints{SourceProfileID: "edge"})
				_, _ = router.Detect(ctx, bytes.NewReader(kvPayload), detect.Hints{SourceProfileID: "edge"})
			}
		}()
	}
	if _, err := router.Activate(ctx, lifecycle, "edge", kvBundle.Digest, 1, "test"); err != nil {
		t.Fatal(err)
	}
	wait.Wait()
	selected, err := router.Detect(ctx, bytes.NewReader(kvPayload), detect.Hints{SourceProfileID: "edge"})
	if err != nil || selected.Selected == nil || selected.Selected.BundleDigest != kvBundle.Digest {
		t.Fatalf("kv activation = %+v, %v", selected, err)
	}
	if _, err := router.Activate(ctx, lifecycle, "edge", jsonBundle.Digest, 2, "test"); err != nil {
		t.Fatal(err)
	}
	selected, err = router.Detect(ctx, bytes.NewReader(jsonPayload), detect.Hints{SourceProfileID: "edge"})
	if err != nil || selected.Selected == nil || selected.Selected.BundleDigest != jsonBundle.Digest {
		t.Fatalf("rollback = %+v, %v", selected, err)
	}
}

func mustDescriptor(t *testing.T, loader *registry.Loader, directory string) registry.Descriptor {
	t.Helper()
	descriptor, err := loader.LoadDirectory(context.Background(), directory)
	if err != nil {
		t.Fatal(err)
	}
	return descriptor
}
