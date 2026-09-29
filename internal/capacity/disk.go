// Package capacity provides bounded local-disk admission protection for the
// single-node reference runtime.
package capacity

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"syscall"
)

var ErrHighWatermark = errors.New("storage high watermark reached")

type Snapshot struct {
	Path       string
	TotalBytes uint64
	FreeBytes  uint64
	UsedBytes  uint64
	UsedRatio  float64
	Blocked    bool
}

type StatFS func(string, *syscall.Statfs_t) error

type DiskGuard struct {
	path          string
	highWatermark float64
	stat          StatFS
}

func NewDiskGuard(path string, highWatermarkPercent int) (*DiskGuard, error) {
	return newDiskGuard(path, highWatermarkPercent, syscall.Statfs)
}

func newDiskGuard(path string, highWatermarkPercent int, stat StatFS) (*DiskGuard, error) {
	if strings.TrimSpace(path) == "" || highWatermarkPercent < 1 || highWatermarkPercent > 99 || stat == nil {
		return nil, errors.New("capacity path, stat function, and watermark from 1 to 99 are required")
	}
	return &DiskGuard{path: path, highWatermark: float64(highWatermarkPercent) / 100, stat: stat}, nil
}

func (guard *DiskGuard) Snapshot(ctx context.Context) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	var value syscall.Statfs_t
	if err := guard.stat(guard.path, &value); err != nil {
		return Snapshot{}, fmt.Errorf("inspect storage capacity: %w", err)
	}
	total := saturatingMultiply(uint64(value.Blocks), uint64(value.Bsize))
	free := saturatingMultiply(uint64(value.Bavail), uint64(value.Bsize))
	if total == 0 || free > total {
		return Snapshot{}, errors.New("storage capacity probe returned invalid values")
	}
	used := total - free
	ratio := float64(used) / float64(total)
	return Snapshot{Path: guard.path, TotalBytes: total, FreeBytes: free, UsedBytes: used, UsedRatio: ratio, Blocked: ratio >= guard.highWatermark}, nil
}

func (guard *DiskGuard) Check(ctx context.Context) error {
	snapshot, err := guard.Snapshot(ctx)
	if err != nil {
		return err
	}
	if snapshot.Blocked {
		return fmt.Errorf("%w: used ratio %.4f is at or above %.4f", ErrHighWatermark, snapshot.UsedRatio, guard.highWatermark)
	}
	return nil
}

func saturatingMultiply(left, right uint64) uint64 {
	if left != 0 && right > math.MaxUint64/left {
		return math.MaxUint64
	}
	return left * right
}
