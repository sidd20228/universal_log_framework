package registry

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/model"
)

var (
	ErrBundleNotInstalled = errors.New("bundle is not installed")
	ErrActivationConflict = errors.New("bundle activation revision conflict")
	ErrInvalidLifecycle   = errors.New("invalid bundle lifecycle request")
	ErrReprocessNotFound  = errors.New("reprocess job not found")
	ErrReprocessLeaseLost = errors.New("reprocess job lease is no longer owned")
	ErrNoReprocessWork    = errors.New("no reprocess job is ready")
)

type InstalledBundle struct {
	BundleID    string    `json:"bundle_id"`
	Version     string    `json:"version"`
	Digest      string    `json:"sha256"`
	Directory   string    `json:"directory"`
	InstalledAt time.Time `json:"installed_at"`
}

type Activation struct {
	SourceProfileID string    `json:"source_profile_id"`
	BundleID        string    `json:"bundle_id"`
	Version         string    `json:"version"`
	BundleDigest    string    `json:"bundle_sha256"`
	ConfigRevision  uint64    `json:"config_revision"`
	ActivatedAt     time.Time `json:"activated_at"`
	ActivatedBy     string    `json:"activated_by"`
}

type ActivationState struct {
	ConfigRevision uint64
	Activations    []Activation
}

type ReprocessStatus string

const (
	ReprocessQueued     ReprocessStatus = "QUEUED"
	ReprocessProcessing ReprocessStatus = "PROCESSING"
	ReprocessComplete   ReprocessStatus = "COMPLETE"
	ReprocessFailed     ReprocessStatus = "FAILED"
)

type ReprocessJob struct {
	ID                  string          `json:"job_id"`
	ReceiptID           string          `json:"receipt_id"`
	PipelineVersion     string          `json:"pipeline_version"`
	BundleDigest        string          `json:"bundle_sha256"`
	Reason              string          `json:"reason"`
	Status              ReprocessStatus `json:"status"`
	RequestedAt         time.Time       `json:"requested_at"`
	RequestedBy         string          `json:"requested_by"`
	LeaseOwner          string          `json:"lease_owner,omitempty"`
	LeaseUntil          time.Time       `json:"lease_until,omitempty"`
	LastErrorCode       string          `json:"last_error_code,omitempty"`
	CompletedRevisionID string          `json:"completed_revision_id,omitempty"`
}

type LifecycleStore interface {
	RecordInstalledBundle(context.Context, InstalledBundle) error
	ListInstalledBundles(context.Context) ([]InstalledBundle, error)
	InstalledBundleByDigest(context.Context, string) (InstalledBundle, error)
	ActivationState(context.Context) (ActivationState, error)
	ActivateSourceProfile(context.Context, string, InstalledBundle, uint64, string, time.Time) (ActivationState, error)
	EnqueueReprocess(context.Context, ReprocessJob) (ReprocessJob, bool, error)
	GetReprocessJob(context.Context, string) (ReprocessJob, error)
	ClaimReprocess(context.Context, string, time.Time, time.Duration) (ReprocessJob, error)
	CommitReprocess(context.Context, string, string, model.Revision) (model.Revision, bool, error)
	ReleaseReprocess(context.Context, string, string, bool, string) error
}

const (
	maxLifecycleIDBytes     = 256
	maxPipelineVersionBytes = 128
	maxReprocessReasonBytes = 1024
	maxErrorCodeBytes       = 128
)

type ActivationSnapshot struct {
	revision uint64
	pins     map[string]Activation
}

func (snapshot *ActivationSnapshot) ConfigRevision() uint64 {
	if snapshot == nil {
		return 0
	}
	return snapshot.revision
}

func (snapshot *ActivationSnapshot) Resolve(sourceProfileID string) (Activation, bool) {
	if snapshot == nil {
		return Activation{}, false
	}
	activation, found := snapshot.pins[sourceProfileID]
	return activation, found
}

func (snapshot *ActivationSnapshot) List() []Activation {
	if snapshot == nil {
		return nil
	}
	result := make([]Activation, 0, len(snapshot.pins))
	for _, activation := range snapshot.pins {
		result = append(result, activation)
	}
	sortActivations(result)
	return result
}

type Lifecycle struct {
	catalog  *Catalog
	loader   *Loader
	store    LifecycleStore
	registry *Registry
	now      func() time.Time

	mu          sync.Mutex
	activations atomic.Pointer[ActivationSnapshot]
}

func NewLifecycle(ctx context.Context, catalogRoot string, loader *Loader, store LifecycleStore) (*Lifecycle, error) {
	if loader == nil || store == nil {
		return nil, errors.New("bundle lifecycle requires a loader and durable store")
	}
	catalog, err := NewCatalog(catalogRoot, loader)
	if err != nil {
		return nil, err
	}
	lifecycle := &Lifecycle{catalog: catalog, loader: loader, store: store, registry: New(loader), now: time.Now}
	if err := lifecycle.reload(ctx); err != nil {
		return nil, err
	}
	return lifecycle, nil
}

func (lifecycle *Lifecycle) RegistrySnapshot() *Snapshot {
	if lifecycle == nil {
		return newSnapshot(nil)
	}
	return lifecycle.registry.Snapshot()
}

// DescriptorByDigest reloads an installed descriptor through the immutable
// catalog so callers can perform semantic compilation before activation.
func (lifecycle *Lifecycle) DescriptorByDigest(ctx context.Context, digest string) (Descriptor, error) {
	if lifecycle == nil || !sha256Pattern.MatchString(digest) {
		return Descriptor{}, ErrInvalidLifecycle
	}
	installed, err := lifecycle.store.InstalledBundleByDigest(ctx, digest)
	if err != nil {
		return Descriptor{}, err
	}
	return lifecycle.catalog.LoadInstalled(ctx, installed)
}

func (lifecycle *Lifecycle) ActivationSnapshot() *ActivationSnapshot {
	if lifecycle == nil {
		return &ActivationSnapshot{pins: map[string]Activation{}}
	}
	snapshot := lifecycle.activations.Load()
	if snapshot == nil {
		return &ActivationSnapshot{pins: map[string]Activation{}}
	}
	return snapshot
}

func (lifecycle *Lifecycle) Install(ctx context.Context, sourceDirectory string) (InstalledBundle, error) {
	if lifecycle == nil {
		return InstalledBundle{}, errors.New("bundle lifecycle is required")
	}
	descriptor, err := lifecycle.catalog.InstallDirectory(ctx, sourceDirectory)
	if err != nil {
		return InstalledBundle{}, err
	}
	installed := InstalledBundle{
		BundleID: descriptor.BundleID(), Version: descriptor.Version(), Digest: descriptor.Digest(),
		Directory: descriptor.Directory(), InstalledAt: lifecycle.now().UTC(),
	}
	if err := lifecycle.store.RecordInstalledBundle(ctx, installed); err != nil {
		return InstalledBundle{}, err
	}
	return installed, nil
}

func (lifecycle *Lifecycle) Activate(ctx context.Context, sourceProfileID, bundleDigest string, expectedRevision uint64, actor string) (Activation, error) {
	if lifecycle == nil {
		return Activation{}, errors.New("bundle lifecycle is required")
	}
	if !boundedText(sourceProfileID, maxLifecycleIDBytes) || !sha256Pattern.MatchString(bundleDigest) || !boundedText(actor, maxLifecycleIDBytes) {
		return Activation{}, ErrInvalidLifecycle
	}
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()

	state, err := lifecycle.store.ActivationState(ctx)
	if err != nil {
		return Activation{}, err
	}
	if state.ConfigRevision != expectedRevision {
		return Activation{}, ErrActivationConflict
	}
	installed, err := lifecycle.store.InstalledBundleByDigest(ctx, bundleDigest)
	if err != nil {
		return Activation{}, err
	}
	if _, err := lifecycle.catalog.LoadInstalled(ctx, installed); err != nil {
		return Activation{}, err
	}
	activatedAt := lifecycle.now().UTC()
	candidate := replaceActivation(state, installed, sourceProfileID, actor, activatedAt)
	registrySnapshot, activationSnapshot, err := lifecycle.buildSnapshots(ctx, candidate)
	if err != nil {
		return Activation{}, err
	}
	persisted, err := lifecycle.store.ActivateSourceProfile(ctx, sourceProfileID, installed, expectedRevision, actor, activatedAt)
	if err != nil {
		return Activation{}, err
	}
	activationSnapshot.revision = persisted.ConfigRevision
	for profile, activation := range activationSnapshot.pins {
		if profile == sourceProfileID {
			activation.ConfigRevision = persisted.ConfigRevision
			activationSnapshot.pins[profile] = activation
		}
	}
	lifecycle.registry.active.Store(registrySnapshot)
	lifecycle.activations.Store(activationSnapshot)
	activation, _ := activationSnapshot.Resolve(sourceProfileID)
	return activation, nil
}

func (lifecycle *Lifecycle) ScheduleReprocess(ctx context.Context, receiptID, pipelineVersion, bundleDigest, reason, actor string) (ReprocessJob, bool, error) {
	if lifecycle == nil {
		return ReprocessJob{}, false, errors.New("bundle lifecycle is required")
	}
	if !boundedText(receiptID, maxLifecycleIDBytes) || !boundedText(pipelineVersion, maxPipelineVersionBytes) || !sha256Pattern.MatchString(bundleDigest) || !boundedText(reason, maxReprocessReasonBytes) || !boundedText(actor, maxLifecycleIDBytes) {
		return ReprocessJob{}, false, ErrInvalidLifecycle
	}
	installed, err := lifecycle.store.InstalledBundleByDigest(ctx, bundleDigest)
	if err != nil {
		return ReprocessJob{}, false, err
	}
	if _, err := lifecycle.catalog.LoadInstalled(ctx, installed); err != nil {
		return ReprocessJob{}, false, err
	}
	jobID, err := newLifecycleID()
	if err != nil {
		return ReprocessJob{}, false, fmt.Errorf("generate reprocess job id: %w", err)
	}
	job := ReprocessJob{
		ID: jobID, ReceiptID: receiptID, PipelineVersion: pipelineVersion, BundleDigest: bundleDigest,
		Reason: reason, Status: ReprocessQueued, RequestedAt: lifecycle.now().UTC(), RequestedBy: actor,
	}
	return lifecycle.store.EnqueueReprocess(ctx, job)
}

func (lifecycle *Lifecycle) GetReprocessJob(ctx context.Context, jobID string) (ReprocessJob, error) {
	return lifecycle.store.GetReprocessJob(ctx, jobID)
}

func (lifecycle *Lifecycle) ClaimReprocess(ctx context.Context, owner string, now time.Time, leaseDuration time.Duration) (ReprocessJob, error) {
	if !boundedText(owner, maxLifecycleIDBytes) {
		return ReprocessJob{}, ErrInvalidLifecycle
	}
	return lifecycle.store.ClaimReprocess(ctx, owner, now, leaseDuration)
}

func (lifecycle *Lifecycle) CommitReprocess(ctx context.Context, jobID, owner string, revision model.Revision) (model.Revision, bool, error) {
	if !boundedText(jobID, maxLifecycleIDBytes) || !boundedText(owner, maxLifecycleIDBytes) {
		return model.Revision{}, false, ErrInvalidLifecycle
	}
	return lifecycle.store.CommitReprocess(ctx, jobID, owner, revision)
}

func (lifecycle *Lifecycle) ReleaseReprocess(ctx context.Context, jobID, owner string, retry bool, errorCode string) error {
	if !boundedText(jobID, maxLifecycleIDBytes) || !boundedText(owner, maxLifecycleIDBytes) || !boundedText(errorCode, maxErrorCodeBytes) {
		return ErrInvalidLifecycle
	}
	return lifecycle.store.ReleaseReprocess(ctx, jobID, owner, retry, errorCode)
}

func (lifecycle *Lifecycle) reload(ctx context.Context) error {
	installed, err := lifecycle.store.ListInstalledBundles(ctx)
	if err != nil {
		return err
	}
	for _, bundle := range installed {
		if _, err := lifecycle.catalog.LoadInstalled(ctx, bundle); err != nil {
			return fmt.Errorf("verify installed bundle %s@%s: %w", bundle.BundleID, bundle.Version, err)
		}
	}
	state, err := lifecycle.store.ActivationState(ctx)
	if err != nil {
		return err
	}
	registrySnapshot, activationSnapshot, err := lifecycle.buildSnapshots(ctx, state)
	if err != nil {
		return err
	}
	lifecycle.registry.active.Store(registrySnapshot)
	lifecycle.activations.Store(activationSnapshot)
	return nil
}

func (lifecycle *Lifecycle) buildSnapshots(ctx context.Context, state ActivationState) (*Snapshot, *ActivationSnapshot, error) {
	descriptors := make([]Descriptor, 0, len(state.Activations))
	seen := make(map[string]struct{}, len(state.Activations))
	pins := make(map[string]Activation, len(state.Activations))
	for _, activation := range state.Activations {
		installed, err := lifecycle.store.InstalledBundleByDigest(ctx, activation.BundleDigest)
		if err != nil {
			return nil, nil, err
		}
		descriptor, err := lifecycle.catalog.LoadInstalled(ctx, installed)
		if err != nil {
			return nil, nil, err
		}
		activation.BundleID = descriptor.BundleID()
		activation.Version = descriptor.Version()
		pins[activation.SourceProfileID] = activation
		if _, exists := seen[descriptor.Digest()]; !exists {
			descriptors = append(descriptors, descriptor)
			seen[descriptor.Digest()] = struct{}{}
		}
	}
	return newSnapshot(descriptors), &ActivationSnapshot{revision: state.ConfigRevision, pins: pins}, nil
}

func replaceActivation(state ActivationState, installed InstalledBundle, sourceProfileID, actor string, at time.Time) ActivationState {
	replaced := false
	for index := range state.Activations {
		if state.Activations[index].SourceProfileID == sourceProfileID {
			state.Activations[index] = Activation{SourceProfileID: sourceProfileID, BundleID: installed.BundleID, Version: installed.Version, BundleDigest: installed.Digest, ActivatedAt: at, ActivatedBy: actor}
			replaced = true
		}
	}
	if !replaced {
		state.Activations = append(state.Activations, Activation{SourceProfileID: sourceProfileID, BundleID: installed.BundleID, Version: installed.Version, BundleDigest: installed.Digest, ActivatedAt: at, ActivatedBy: actor})
	}
	return state
}

func sortActivations(activations []Activation) {
	for left := 0; left < len(activations); left++ {
		for right := left + 1; right < len(activations); right++ {
			if activations[right].SourceProfileID < activations[left].SourceProfileID {
				activations[left], activations[right] = activations[right], activations[left]
			}
		}
	}
}

func newLifecycleID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func boundedText(value string, maximum int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= maximum
}
