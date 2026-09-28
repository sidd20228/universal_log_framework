package registry

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
)

type Descriptor struct {
	bundleID  string
	version   string
	digest    string
	directory string
	manifest  Manifest
}

func (descriptor Descriptor) BundleID() string {
	return descriptor.bundleID
}

func (descriptor Descriptor) Version() string {
	return descriptor.version
}

func (descriptor Descriptor) Digest() string {
	return descriptor.digest
}

func (descriptor Descriptor) Directory() string {
	return descriptor.directory
}

func (descriptor Descriptor) Manifest() Manifest {
	return cloneManifest(descriptor.manifest)
}

type Snapshot struct {
	descriptors map[string]Descriptor
	ordered     []Descriptor
	digest      string
}

func (snapshot *Snapshot) Len() int {
	if snapshot == nil {
		return 0
	}
	return len(snapshot.ordered)
}

func (snapshot *Snapshot) Digest() string {
	if snapshot == nil {
		return ""
	}
	return snapshot.digest
}

func (snapshot *Snapshot) Find(bundleID, version string) (Descriptor, bool) {
	if snapshot == nil {
		return Descriptor{}, false
	}
	descriptor, found := snapshot.descriptors[bundleKey(bundleID, version)]
	return descriptor, found
}

func (snapshot *Snapshot) List() []Descriptor {
	if snapshot == nil {
		return nil
	}
	return append([]Descriptor(nil), snapshot.ordered...)
}

type Registry struct {
	loader     *Loader
	activation sync.Mutex
	active     atomic.Pointer[Snapshot]
}

func New(loader *Loader) *Registry {
	registry := &Registry{loader: loader}
	registry.active.Store(newSnapshot(nil))
	return registry
}

func (registry *Registry) Snapshot() *Snapshot {
	if registry == nil {
		return newSnapshot(nil)
	}
	snapshot := registry.active.Load()
	if snapshot == nil {
		return newSnapshot(nil)
	}
	return snapshot
}

func (registry *Registry) ActivateDirectories(ctx context.Context, directories []string) error {
	if registry == nil || registry.loader == nil {
		return fmt.Errorf("bundle registry requires a loader")
	}
	descriptors := make([]Descriptor, 0, len(directories))
	seen := make(map[string]struct{}, len(directories))
	for _, directory := range directories {
		if err := ctx.Err(); err != nil {
			return err
		}
		descriptor, err := registry.loader.LoadDirectory(ctx, directory)
		if err != nil {
			return err
		}
		key := bundleKey(descriptor.BundleID(), descriptor.Version())
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("%w: %s@%s", ErrDuplicateBundle, descriptor.BundleID(), descriptor.Version())
		}
		seen[key] = struct{}{}
		descriptors = append(descriptors, descriptor)
	}
	registry.activation.Lock()
	defer registry.activation.Unlock()
	current := registry.Snapshot()
	for _, descriptor := range descriptors {
		if existing, found := current.Find(descriptor.BundleID(), descriptor.Version()); found && existing.Digest() != descriptor.Digest() {
			return fmt.Errorf(
				"%w: %s@%s already has digest %s",
				ErrDuplicateBundle,
				descriptor.BundleID(),
				descriptor.Version(),
				existing.Digest(),
			)
		}
	}
	registry.active.Store(newSnapshot(descriptors))
	return nil
}

func newSnapshot(descriptors []Descriptor) *Snapshot {
	ordered := append([]Descriptor(nil), descriptors...)
	sort.Slice(ordered, func(first, second int) bool {
		if ordered[first].BundleID() == ordered[second].BundleID() {
			return ordered[first].Version() < ordered[second].Version()
		}
		return ordered[first].BundleID() < ordered[second].BundleID()
	})
	byIdentity := make(map[string]Descriptor, len(ordered))
	digest := sha256.New()
	for _, descriptor := range ordered {
		byIdentity[bundleKey(descriptor.BundleID(), descriptor.Version())] = descriptor
		fmt.Fprintf(digest, "%s\x00%s\x00%s\n", descriptor.BundleID(), descriptor.Version(), descriptor.Digest())
	}
	return &Snapshot{
		descriptors: byIdentity,
		ordered:     ordered,
		digest:      fmt.Sprintf("%x", digest.Sum(nil)),
	}
}

func bundleKey(bundleID, version string) string {
	return bundleID + "\x00" + version
}
