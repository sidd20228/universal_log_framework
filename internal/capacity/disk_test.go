package capacity

import (
	"context"
	"errors"
	"syscall"
	"testing"
)

func TestDiskGuardBlocksAtWatermarkAndUsesAvailableBlocks(t *testing.T) {
	guard, err := newDiskGuard("/data", 80, func(path string, value *syscall.Statfs_t) error {
		if path != "/data" {
			t.Fatalf("path=%q", path)
		}
		value.Blocks, value.Bavail, value.Bsize = 100, 20, 4096
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := guard.Snapshot(context.Background())
	if err != nil || !snapshot.Blocked || snapshot.UsedRatio != .8 || snapshot.FreeBytes != 20*4096 {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	if err := guard.Check(context.Background()); !errors.Is(err, ErrHighWatermark) {
		t.Fatalf("Check error=%v", err)
	}
}

func TestDiskGuardFailsClosedOnProbeError(t *testing.T) {
	want := errors.New("stat failed")
	guard, _ := newDiskGuard("/data", 90, func(string, *syscall.Statfs_t) error { return want })
	if err := guard.Check(context.Background()); !errors.Is(err, want) {
		t.Fatalf("Check error=%v", err)
	}
}
