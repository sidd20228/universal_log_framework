package bundlecompile

import (
	"context"
	"errors"
	"io"
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
	byDigest := make(map[string]registry.Descriptor)
	for _, descriptor := range lifecycle.RegistrySnapshot().List() {
		byDigest[descriptor.Digest()] = descriptor
	}
	compiled := make(map[string]compiledPipeline)
	for _, activation := range lifecycle.ActivationSnapshot().List() {
		descriptor, found := byDigest[activation.BundleDigest]
		if !found {
			return errors.New("active bundle descriptor is unavailable")
		}
		bundle, err := Compile(ctx, descriptor)
		if err != nil {
			return err
		}
		detector, err := bundle.NewDetector(detect.DefaultConfig())
		if err != nil {
			return err
		}
		resolver, err := bundle.NewResolver()
		if err != nil {
			return err
		}
		compiled[activation.SourceProfileID] = compiledPipeline{detector: detector, resolver: resolver}
	}
	router.active.Store(&routingSnapshot{profiles: compiled})
	return nil
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
