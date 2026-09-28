package worker

import (
	"context"
	"errors"
	"fmt"

	"github.com/sidd20228/universal_log_framework/internal/detect"
	"github.com/sidd20228/universal_log_framework/internal/model"
)

type StaticResolver struct{ pipelines map[string]Pipeline }

func NewStaticResolver(pipelines []Pipeline) (*StaticResolver, error) {
	resolver := &StaticResolver{pipelines: make(map[string]Pipeline, len(pipelines))}
	for index, pipeline := range pipelines {
		if pipeline.Parser == nil {
			return nil, fmt.Errorf("pipeline %d parser is nil", index)
		}
		descriptor := pipeline.Parser.Descriptor()
		if descriptor.ID == "" || descriptor.Version == "" {
			return nil, fmt.Errorf("pipeline %d parser identity is incomplete", index)
		}
		key := pipelineKey(descriptor.ID, descriptor.Version, pipeline.BundleDigest)
		if _, exists := resolver.pipelines[key]; exists {
			return nil, fmt.Errorf("duplicate pipeline %s@%s", descriptor.ID, descriptor.Version)
		}
		resolver.pipelines[key] = pipeline
	}
	if len(resolver.pipelines) == 0 {
		return nil, errors.New("at least one pipeline is required")
	}
	return resolver, nil
}

func (resolver *StaticResolver) Resolve(ctx context.Context, _ model.Receipt, candidate detect.Candidate) (Pipeline, error) {
	if err := ctx.Err(); err != nil {
		return Pipeline{}, err
	}
	pipeline, exists := resolver.pipelines[pipelineKey(candidate.ParserID, candidate.ParserVersion, candidate.BundleDigest)]
	if !exists {
		return Pipeline{}, fmt.Errorf("no pipeline for %s@%s", candidate.ParserID, candidate.ParserVersion)
	}
	return pipeline, nil
}

func pipelineKey(id, version, digest string) string { return id + "\x00" + version + "\x00" + digest }
