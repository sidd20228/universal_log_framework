package mapping

import (
	"bytes"
	"context"
	"fmt"

	"github.com/sidd20228/universal_log_framework/internal/interpret"
)

func (engine *Engine) Map(ctx context.Context, document interpret.ParsedDocument) Result {
	result := Result{
		Event:      make(map[string]any),
		Unmapped:   flattenFields(document.Fields),
		Unmatched:  bytes.Clone(document.Unmatched),
		Provenance: make(map[string]Provenance),
	}
	succeededSources := make(map[string]struct{})
	failedSources := make(map[string]struct{})
	for _, compiled := range engine.rules {
		rule := compiled.rule
		if rule.Required {
			result.RequiredTotal++
		}
		if err := ctx.Err(); err != nil {
			result.Issues = append(result.Issues, mappingIssue(IssueContextCancelled, rule, err.Error()))
			break
		}
		source, concretePath, found, err := resolveSource(document.Fields, compiled.path)
		if err != nil {
			result.Issues = append(result.Issues, mappingIssue(IssueSourceAmbiguous, rule, err.Error()))
			continue
		}
		if !found {
			if rule.Required {
				result.Issues = append(result.Issues, mappingIssue(IssueRequiredMissing, rule, "required source field is absent"))
			}
			continue
		}

		converted, err := convertValue(source, rule)
		if err != nil {
			failedSources[concretePath] = struct{}{}
			result.Issues = append(result.Issues, mappingIssue(IssueConversionFailed, rule, err.Error()))
			continue
		}
		if compiled.taxonomy != nil {
			lookup, ok := converted.(string)
			if !ok {
				failedSources[concretePath] = struct{}{}
				result.Issues = append(result.Issues, mappingIssue(IssueConversionFailed, rule, "taxonomy lookup requires text"))
				continue
			}
			canonical, found := compiled.taxonomy[lookup]
			if !found {
				failedSources[concretePath] = struct{}{}
				result.Issues = append(result.Issues, mappingIssue(IssueTaxonomyMiss, rule, fmt.Sprintf("value %q is absent from taxonomy %q", lookup, rule.Lookup)))
				continue
			}
			converted = canonical
		}
		kind, _ := targetForPath(rule.To)
		converted, err = coerceTarget(kind, converted)
		if err != nil {
			failedSources[concretePath] = struct{}{}
			result.Issues = append(result.Issues, mappingIssue(IssueConversionFailed, rule, err.Error()))
			continue
		}
		if err := setTarget(result.Event, compiled.targetPath, converted); err != nil {
			failedSources[concretePath] = struct{}{}
			result.Issues = append(result.Issues, mappingIssue(IssueTargetConflict, rule, err.Error()))
			continue
		}
		succeededSources[concretePath] = struct{}{}
		if rule.Required {
			result.RequiredPresent++
		}
		provenanceKind := ProvenanceNormalized
		if rule.Convert == ConvertString && rule.Lookup == "" {
			provenanceKind = ProvenanceMapped
		}
		result.Provenance[rule.To] = Provenance{
			Kind:           provenanceKind,
			SourcePath:     rule.From,
			RuleID:         rule.ID,
			MappingID:      engine.descriptor.id,
			MappingVersion: engine.descriptor.version,
			Taxonomy:       rule.Lookup,
		}
	}
	for sourcePath := range succeededSources {
		if _, failed := failedSources[sourcePath]; !failed {
			delete(result.Unmapped, sourcePath)
		}
	}
	return result
}

func mappingIssue(code string, rule Rule, message string) Issue {
	return Issue{
		Code:       code,
		RuleID:     rule.ID,
		SourcePath: rule.From,
		TargetPath: rule.To,
		Message:    message,
	}
}
