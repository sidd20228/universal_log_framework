package envelope

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/sidd20228/universal_log_framework/internal/interpret"
	"github.com/sidd20228/universal_log_framework/internal/interpret/mapping"
	"github.com/sidd20228/universal_log_framework/internal/model"
)

func Build(input Input) (Envelope, error) {
	if err := input.Receipt.Validate(); err != nil {
		return Envelope{}, fmt.Errorf("receipt: %w", err)
	}
	if err := input.Revision.Validate(); err != nil {
		return Envelope{}, fmt.Errorf("revision: %w", err)
	}
	if input.Revision.ReceiptID != input.Receipt.ID {
		return Envelope{}, errors.New("revision receipt_id does not match receipt id")
	}
	if input.Revision.SchemaVersion != SchemaVersion {
		return Envelope{}, fmt.Errorf("revision schema version must be %q", SchemaVersion)
	}
	if !bytes.Equal(input.Document.Unmatched, input.Mapping.Unmatched) {
		return Envelope{}, errors.New("mapping unmatched bytes differ from parsed document")
	}
	if input.Mapping.RequiredPresent < 0 || input.Mapping.RequiredTotal < 0 || input.Mapping.RequiredPresent > input.Mapping.RequiredTotal {
		return Envelope{}, errors.New("mapping required-field counts are invalid")
	}

	event, err := cloneMap(input.Mapping.Event)
	if err != nil {
		return Envelope{}, fmt.Errorf("copy event: %w", err)
	}
	fields, err := cloneMap(input.Document.Fields)
	if err != nil {
		return Envelope{}, fmt.Errorf("copy parsed fields: %w", err)
	}
	unmapped, err := cloneMap(input.Mapping.Unmapped)
	if err != nil {
		return Envelope{}, fmt.Errorf("copy unmapped fields: %w", err)
	}

	provenance, identity, err := buildProvenance(event, input.Mapping.Provenance)
	if err != nil {
		return Envelope{}, err
	}
	if len(event) > 0 {
		if identity == "" {
			return Envelope{}, errors.New("canonical event has no mapping identity")
		}
		if input.Revision.MappingVersion != identity {
			return Envelope{}, fmt.Errorf("revision mapping version %q does not match provenance %q", input.Revision.MappingVersion, identity)
		}
	} else if len(provenance) != 0 {
		return Envelope{}, errors.New("provenance is present without a canonical event")
	}

	if err := validateStatus(input.Revision.Status, event, input.Mapping); err != nil {
		return Envelope{}, err
	}
	issues, err := buildIssues(input.Revision.Issues, input.ParseIssues, input.Mapping.Issues)
	if err != nil {
		return Envelope{}, err
	}
	parser := cloneParser(input.Revision.Parser)
	confidence := cloneConfidence(input.Revision.Confidence)
	peer := clonePeer(input.Receipt.Peer)

	candidate := Envelope{
		SchemaVersion: SchemaVersion,
		Receipt: Receipt{
			ID: input.Receipt.ID, TenantID: input.Receipt.TenantID, ReceivedAt: input.Receipt.ReceivedAt.UTC(),
			EnvironmentID: input.Receipt.EnvironmentID, InstanceID: input.Receipt.InstanceID,
			ListenerID: input.Receipt.ListenerID, Transport: input.Receipt.Transport, Peer: peer,
			SourceProfileID: input.Receipt.SourceProfileID, Framing: input.Receipt.Framing,
		},
		Raw: input.Receipt.Raw,
		Processing: Processing{
			RevisionID: input.Revision.ID, PipelineVersion: input.Revision.PipelineVersion,
			Parser: parser, MappingVersion: input.Revision.MappingVersion, Status: input.Revision.Status,
			Confidence: confidence, Issues: issues,
			Timestamps: ProcessingTimestamps{StartedAt: input.Revision.StartedAt.UTC(), CompletedAt: input.Revision.CompletedAt.UTC()},
		},
		Event:       event,
		Provenance:  provenance,
		Quality:     ComputeQuality(input.Mapping),
		Correlation: Correlation{GroupIDs: []string{}},
	}
	if input.Document.Format != "" || len(fields) != 0 || len(unmapped) != 0 || len(input.Mapping.Unmatched) != 0 {
		candidate.Parsed = &Parsed{
			Format: input.Document.Format, Fields: fields, Unmapped: unmapped,
			Unmatched: bytes.Clone(input.Mapping.Unmatched),
		}
	}
	if err := candidate.Validate(); err != nil {
		return Envelope{}, err
	}
	return candidate, nil
}

func ComputeQuality(result mapping.Result) Quality {
	requiredTotal := max(result.RequiredTotal, 0)
	requiredPresent := min(max(result.RequiredPresent, 0), requiredTotal)
	leaves := eventLeafPaths(result.Event)
	provenancePresent := 0
	for _, path := range leaves {
		if value, present := result.Provenance[path]; present && validMappingProvenance(value) {
			provenancePresent++
		}
	}
	denominator := requiredTotal + len(leaves)
	score := 0.0
	if denominator != 0 {
		score = float64(requiredPresent+provenancePresent) / float64(denominator)
	}
	return Quality{
		Score: score, RequiredPresent: requiredPresent, RequiredTotal: requiredTotal,
		ProvenancePresent: provenancePresent, ProvenanceTotal: len(leaves),
	}
}

func buildProvenance(event map[string]any, source map[string]mapping.Provenance) (map[string]FieldProvenance, string, error) {
	leaves := eventLeafPaths(event)
	if len(leaves) == 0 && len(source) == 0 {
		return nil, "", nil
	}
	leafSet := make(map[string]struct{}, len(leaves))
	for _, path := range leaves {
		leafSet[path] = struct{}{}
	}
	for path := range source {
		if _, exists := leafSet[path]; !exists {
			return nil, "", fmt.Errorf("provenance path %q has no canonical event leaf", path)
		}
	}
	result := make(map[string]FieldProvenance, len(leaves))
	identity := ""
	for _, path := range leaves {
		value, exists := source[path]
		if !exists {
			return nil, "", fmt.Errorf("canonical event leaf %q has no provenance", path)
		}
		if !validMappingProvenance(value) {
			return nil, "", fmt.Errorf("canonical event leaf %q has invalid provenance", path)
		}
		currentIdentity := value.MappingID + "/" + value.MappingVersion
		if identity == "" {
			identity = currentIdentity
		} else if currentIdentity != identity {
			return nil, "", errors.New("canonical event provenance contains multiple mapping identities")
		}
		result[path] = FieldProvenance{
			Kind: value.Kind, SourcePath: value.SourcePath, RuleID: value.RuleID,
			MappingVersion: currentIdentity, Taxonomy: value.Taxonomy,
		}
	}
	return result, identity, nil
}

func validMappingProvenance(value mapping.Provenance) bool {
	if value.Kind != mapping.ProvenanceMapped && value.Kind != mapping.ProvenanceNormalized {
		return false
	}
	return strings.TrimSpace(value.SourcePath) != "" && strings.TrimSpace(value.RuleID) != "" &&
		strings.TrimSpace(value.MappingID) != "" && strings.TrimSpace(value.MappingVersion) != ""
}

func eventLeafPaths(event map[string]any) []string {
	paths := make([]string, 0)
	collectLeaves(event, "event", &paths)
	sort.Strings(paths)
	return paths
}

func collectLeaves(value any, path string, paths *[]string) {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			collectLeaves(typed[key], path+"."+key, paths)
		}
	default:
		*paths = append(*paths, path)
	}
}

func validateStatus(status model.InterpretationStatus, event map[string]any, result mapping.Result) error {
	switch status {
	case model.StatusParsed:
		if len(event) == 0 {
			return errors.New("PARSED revision requires a canonical event")
		}
		if result.RequiredPresent != result.RequiredTotal || len(result.Issues) != 0 {
			return errors.New("PARSED revision cannot contain incomplete required mappings or mapping issues")
		}
	case model.StatusPartiallyParsed:
		return nil
	case model.StatusUnparsed, model.StatusInvalid, model.StatusError:
		if len(event) != 0 || len(result.Provenance) != 0 {
			return fmt.Errorf("%s revision cannot contain a trusted canonical event", status)
		}
	}
	return nil
}

func buildIssues(existing []model.Issue, parser []interpret.Issue, mapped []mapping.Issue) ([]Issue, error) {
	total := len(existing) + len(parser) + len(mapped)
	if total > MaxIssues {
		return nil, fmt.Errorf("processing has %d issues; maximum is %d", total, MaxIssues)
	}
	result := make([]Issue, 0, total)
	for _, value := range existing {
		result = append(result, Issue{
			Code: safeIssueCode(value.Code), Stage: safeStage(value.Stage), Severity: safeModelSeverity(value.Severity),
			Retryable: value.Retryable, Message: safeIssueMessage(value.Message),
		})
	}
	for _, value := range parser {
		offset := max(value.Offset, 0)
		result = append(result, Issue{
			Code: safeIssueCode(value.Code), Stage: "parsing", Severity: parseSeverity(value.Severity),
			Message: safeIssueMessage(value.Message), Offset: &offset,
		})
	}
	for _, value := range mapped {
		severity := model.SeverityWarning
		retryable := false
		if value.Code == mapping.IssueContextCancelled || value.Code == mapping.IssueTargetConflict || value.Code == mapping.IssueSourceAmbiguous {
			severity = model.SeverityError
		}
		if value.Code == mapping.IssueContextCancelled {
			retryable = true
		}
		message := value.Message
		if value.RuleID != "" || value.TargetPath != "" {
			message = fmt.Sprintf("rule %s to %s: %s", value.RuleID, value.TargetPath, value.Message)
		}
		result = append(result, Issue{
			Code: safeIssueCode(value.Code), Stage: "mapping", Severity: severity, Retryable: retryable,
			Message: safeIssueMessage(message), SourcePath: safeSourcePath(value.SourcePath),
		})
	}
	return result, nil
}

func safeIssueCode(value string) string {
	value = strings.ToUpper(value)
	var builder strings.Builder
	lastUnderscore := false
	for _, character := range value {
		valid := character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
		if valid {
			builder.WriteRune(character)
			lastUnderscore = false
		} else if builder.Len() != 0 && !lastUnderscore {
			builder.WriteByte('_')
			lastUnderscore = true
		}
		if builder.Len() >= 64 {
			break
		}
	}
	code := strings.Trim(builder.String(), "_")
	if code == "" {
		return "UNKNOWN_ISSUE"
	}
	if code[0] < 'A' || code[0] > 'Z' {
		code = "ISSUE_" + code
	}
	if len(code) == 1 {
		code += "_ISSUE"
	}
	if len(code) > 64 {
		code = strings.TrimRight(code[:64], "_")
	}
	return code
}

func safeIssueMessage(value string) string {
	value = strings.ToValidUTF8(value, "�")
	var builder strings.Builder
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			character = ' '
		}
		if builder.Len()+utf8.RuneLen(character) > MaxIssueMessageBytes {
			break
		}
		builder.WriteRune(character)
	}
	message := strings.TrimSpace(builder.String())
	if message == "" {
		return "issue details unavailable"
	}
	return message
}

func safeSourcePath(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	value = safeIssueMessage(value)
	end := min(len(value), 512)
	for end > 0 && !utf8.ValidString(value[:end]) {
		end--
	}
	return value[:end]
}

func safeStage(stage string) string {
	switch stage {
	case "detection", "parsing", "mapping", "validation", "enrichment", "delivery":
		return stage
	default:
		return "validation"
	}
}

func safeModelSeverity(severity model.IssueSeverity) model.IssueSeverity {
	switch severity {
	case model.SeverityInfo, model.SeverityWarning, model.SeverityError:
		return severity
	default:
		return model.SeverityWarning
	}
}

func parseSeverity(severity interpret.IssueSeverity) model.IssueSeverity {
	switch severity {
	case interpret.SeverityInfo:
		return model.SeverityInfo
	case interpret.SeverityError:
		return model.SeverityError
	default:
		return model.SeverityWarning
	}
}

func cloneParser(parser *model.ParserIdentity) *model.ParserIdentity {
	if parser == nil {
		return nil
	}
	copyParser := *parser
	return &copyParser
}

func cloneConfidence(confidence *float64) *float64 {
	if confidence == nil {
		return nil
	}
	copyConfidence := *confidence
	return &copyConfidence
}

func clonePeer(peer *model.Peer) *model.Peer {
	if peer == nil {
		return nil
	}
	copyPeer := *peer
	return &copyPeer
}
