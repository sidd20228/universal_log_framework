// Package envelope builds and validates the stable JSON projection that links
// accepted evidence to one immutable interpretation revision.
package envelope

import (
	"time"

	"github.com/sidd20228/universal_log_framework/internal/interpret"
	"github.com/sidd20228/universal_log_framework/internal/interpret/mapping"
	"github.com/sidd20228/universal_log_framework/internal/model"
)

const (
	SchemaVersion        = "ulpf-envelope/1.0.0"
	MaxIssues            = 1024
	MaxIssueMessageBytes = 1024
)

type Input struct {
	Receipt     model.Receipt
	Revision    model.Revision
	Document    interpret.ParsedDocument
	Mapping     mapping.Result
	ParseIssues []interpret.Issue
}

type Envelope struct {
	SchemaVersion string                     `json:"schema_version"`
	Receipt       Receipt                    `json:"receipt"`
	Raw           model.RawReference         `json:"raw"`
	Processing    Processing                 `json:"processing"`
	Event         map[string]any             `json:"event,omitempty"`
	Parsed        *Parsed                    `json:"parsed,omitempty"`
	Provenance    map[string]FieldProvenance `json:"provenance,omitempty"`
	Quality       Quality                    `json:"quality"`
	Correlation   Correlation                `json:"correlation"`
}

type Receipt struct {
	ID              string          `json:"id"`
	TenantID        string          `json:"tenant_id"`
	ReceivedAt      time.Time       `json:"received_at"`
	ListenerID      string          `json:"listener_id"`
	Transport       model.Transport `json:"transport"`
	Peer            *model.Peer     `json:"peer,omitempty"`
	SourceProfileID string          `json:"source_profile_id,omitempty"`
	Framing         model.Framing   `json:"framing"`
}

type Processing struct {
	RevisionID      string                     `json:"revision_id"`
	PipelineVersion string                     `json:"pipeline_version"`
	Parser          *model.ParserIdentity      `json:"parser,omitempty"`
	MappingVersion  string                     `json:"mapping_version,omitempty"`
	Status          model.InterpretationStatus `json:"status"`
	Confidence      *float64                   `json:"confidence,omitempty"`
	Issues          []Issue                    `json:"issues"`
	Timestamps      ProcessingTimestamps       `json:"timestamps"`
}

type ProcessingTimestamps struct {
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
}

type Issue struct {
	Code       string              `json:"code"`
	Stage      string              `json:"stage"`
	Severity   model.IssueSeverity `json:"severity"`
	Retryable  bool                `json:"retryable"`
	Message    string              `json:"message"`
	SourcePath string              `json:"source_path,omitempty"`
	Offset     *int                `json:"offset,omitempty"`
}

type Parsed struct {
	Format    string         `json:"format,omitempty"`
	Fields    map[string]any `json:"fields,omitempty"`
	Unmapped  map[string]any `json:"unmapped,omitempty"`
	Unmatched []byte         `json:"unmatched,omitempty"`
}

type FieldProvenance struct {
	Kind           mapping.ProvenanceKind `json:"kind"`
	SourcePath     string                 `json:"source_path"`
	RuleID         string                 `json:"rule_id"`
	MappingVersion string                 `json:"mapping_version"`
	Taxonomy       string                 `json:"taxonomy,omitempty"`
}

type Quality struct {
	Score             float64 `json:"score"`
	RequiredPresent   int     `json:"required_present"`
	RequiredTotal     int     `json:"required_total"`
	ProvenancePresent int     `json:"provenance_present"`
	ProvenanceTotal   int     `json:"provenance_total"`
}

type Correlation struct {
	GroupIDs []string `json:"group_ids"`
}
