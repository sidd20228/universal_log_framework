package bundlecompile

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"github.com/sidd20228/universal_log_framework/internal/detect"
	"github.com/sidd20228/universal_log_framework/internal/model"
	"github.com/sidd20228/universal_log_framework/internal/registry"
	"github.com/sidd20228/universal_log_framework/internal/worker"
)

type compiledPipeline struct {
	detector *detect.Detector
	resolver *worker.StaticResolver
}

type routingSnapshot struct {
	profiles map[string]compiledPipeline
}

// Router atomically routes a receipt through its activated source-profile
// bundle while preserving a validated fallback for unconfigured sources.
type Router struct {
	fallback compiledPipeline
	active   atomic.Pointer[routingSnapshot]
	control  sync.Mutex
}

// Activate validates and compiles the candidate before changing durable
// activation state, then atomically publishes a complete routing snapshot.
// Calls are serialized so a stale expected revision cannot publish over a
// newer activation. A failed validation or refresh leaves the last known-good
// routing snapshot serving traffic.
func (router *Router) Activate(ctx context.Context, lifecycle *registry.Lifecycle, sourceProfileID, bundleDigest string, expectedRevision uint64, actor string) (registry.Activation, error) {
	if lifecycle == nil {
		return registry.Activation{}, errors.New("bundle lifecycle is required")
	}
	router.control.Lock()
	defer router.control.Unlock()
	prepared, err := router.buildSnapshot(ctx, lifecycle, sourceProfileID, bundleDigest)
	if err != nil {
		return registry.Activation{}, err
	}
	activation, err := lifecycle.Activate(ctx, sourceProfileID, bundleDigest, expectedRevision, actor)
	if err != nil {
		return registry.Activation{}, err
	}
	router.active.Store(prepared)
	return activation, nil
}

func NewRouter(fallbackDetector *detect.Detector, fallbackResolver *worker.StaticResolver) (*Router, error) {
	if fallbackDetector == nil || fallbackResolver == nil {
		return nil, errors.New("fallback detector and resolver are required")
	}
	router := &Router{fallback: compiledPipeline{detector: fallbackDetector, resolver: fallbackResolver}}
	router.active.Store(&routingSnapshot{profiles: map[string]compiledPipeline{}})
	return router, nil
}

func (router *Router) Refresh(ctx context.Context, lifecycle *registry.Lifecycle) error {
	if lifecycle == nil {
		return errors.New("bundle lifecycle is required")
	}
	prepared, err := router.buildSnapshot(ctx, lifecycle, "", "")
	if err != nil {
		return err
	}
	router.active.Store(prepared)
	return nil
}

func (router *Router) buildSnapshot(ctx context.Context, lifecycle *registry.Lifecycle, overrideProfile, overrideDigest string) (*routingSnapshot, error) {
	compiled := make(map[string]compiledPipeline)
	activations := lifecycle.ActivationSnapshot().List()
	overridden := overrideProfile == ""
	for _, activation := range activations {
		digest := activation.BundleDigest
		if activation.SourceProfileID == overrideProfile {
			digest = overrideDigest
			overridden = true
		}
		descriptor, err := lifecycle.DescriptorByDigest(ctx, digest)
		if err != nil {
			return nil, err
		}
		bundle, err := Compile(ctx, descriptor)
		if err != nil {
			return nil, err
		}
		detector, err := bundle.NewDetector(detect.DefaultConfig())
		if err != nil {
			return nil, err
		}
		resolver, err := bundle.NewResolver()
		if err != nil {
			return nil, err
		}
		compiled[activation.SourceProfileID] = compiledPipeline{detector: detector, resolver: resolver}
	}
	if !overridden {
		descriptor, err := lifecycle.DescriptorByDigest(ctx, overrideDigest)
		if err != nil {
			return nil, err
		}
		bundle, err := Compile(ctx, descriptor)
		if err != nil {
			return nil, err
		}
		detector, err := bundle.NewDetector(detect.DefaultConfig())
		if err != nil {
			return nil, err
		}
		resolver, err := bundle.NewResolver()
		if err != nil {
			return nil, err
		}
		compiled[overrideProfile] = compiledPipeline{detector: detector, resolver: resolver}
	}
	return &routingSnapshot{profiles: compiled}, nil
}

func (router *Router) Detect(ctx context.Context, source io.Reader, hints detect.Hints) (detect.Result, error) {
	if snapshot := router.active.Load(); snapshot != nil {
		if pipeline, found := snapshot.profiles[hints.SourceProfileID]; found {
			return pipeline.detector.Detect(ctx, source, hints)
		}
	}
	return router.fallback.detector.Detect(ctx, source, hints)
}

func (router *Router) Resolve(ctx context.Context, receipt model.Receipt, candidate detect.Candidate) (worker.Pipeline, error) {
	if snapshot := router.active.Load(); snapshot != nil {
		if pipeline, found := snapshot.profiles[receipt.SourceProfileID]; found {
			return pipeline.resolver.Resolve(ctx, receipt, candidate)
		}
	}
	return router.fallback.resolver.Resolve(ctx, receipt, candidate)
}

var _ worker.Detector = (*Router)(nil)
var _ worker.Resolver = (*Router)(nil)
