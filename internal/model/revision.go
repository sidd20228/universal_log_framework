package model

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

type InterpretationStatus string

const (
	StatusParsed          InterpretationStatus = "PARSED"
	StatusPartiallyParsed InterpretationStatus = "PARTIALLY_PARSED"
	StatusUnparsed        InterpretationStatus = "UNPARSED"
	StatusInvalid         InterpretationStatus = "INVALID"
	StatusError           InterpretationStatus = "ERROR"
)

type IssueSeverity string

const (
	SeverityInfo    IssueSeverity = "INFO"
	SeverityWarning IssueSeverity = "WARNING"
	SeverityError   IssueSeverity = "ERROR"
)

type Issue struct {
	Code      string        `json:"code"`
	Stage     string        `json:"stage"`
	Severity  IssueSeverity `json:"severity"`
	Retryable bool          `json:"retryable"`
	Message   string        `json:"message"`
}

type ParserIdentity struct {
	ID           string `json:"id"`
	Version      string `json:"version"`
	BundleSHA256 string `json:"bundle_sha256,omitempty"`
}

type Revision struct {
	ID              string               `json:"revision_id"`
	ReceiptID       string               `json:"receipt_id"`
	PipelineVersion string               `json:"pipeline_version"`
	SchemaVersion   string               `json:"schema_version"`
	MappingVersion  string               `json:"mapping_version,omitempty"`
	Parser          *ParserIdentity      `json:"parser,omitempty"`
	Status          InterpretationStatus `json:"status"`
	Confidence      *float64             `json:"confidence,omitempty"`
	Issues          []Issue              `json:"issues"`
	StartedAt       time.Time            `json:"started_at"`
	CompletedAt     time.Time            `json:"completed_at"`
}

func (revision Revision) Validate() error {
	var problems []error
	if strings.TrimSpace(revision.ID) == "" {
		problems = append(problems, errors.New("revision id is required"))
	}
	if strings.TrimSpace(revision.ReceiptID) == "" {
		problems = append(problems, errors.New("receipt id is required"))
	}
	if strings.TrimSpace(revision.PipelineVersion) == "" {
		problems = append(problems, errors.New("pipeline version is required"))
	}
	if strings.TrimSpace(revision.SchemaVersion) == "" {
		problems = append(problems, errors.New("schema version is required"))
	}
	if !revision.Status.Valid() {
		problems = append(problems, fmt.Errorf("invalid interpretation status %q", revision.Status))
	}
	if revision.Confidence != nil && (*revision.Confidence < 0 || *revision.Confidence > 1) {
		problems = append(problems, errors.New("confidence must be between 0 and 1"))
	}
	if revision.StartedAt.IsZero() || revision.CompletedAt.IsZero() {
		problems = append(problems, errors.New("processing timestamps are required"))
	} else if revision.CompletedAt.Before(revision.StartedAt) {
		problems = append(problems, errors.New("completed_at cannot precede started_at"))
	}
	if revision.Parser != nil {
		if strings.TrimSpace(revision.Parser.ID) == "" || strings.TrimSpace(revision.Parser.Version) == "" {
			problems = append(problems, errors.New("parser id and version are required together"))
		}
		if revision.Parser.BundleSHA256 != "" && !validSHA256(revision.Parser.BundleSHA256) {
			problems = append(problems, errors.New("bundle sha256 must be 64 lowercase hexadecimal characters"))
		}
	} else if revision.Status == StatusParsed || revision.Status == StatusPartiallyParsed {
		problems = append(problems, errors.New("parsed revisions require a parser identity"))
	}
	for index, issue := range revision.Issues {
		if err := issue.Validate(); err != nil {
			problems = append(problems, fmt.Errorf("issue %d: %w", index, err))
		}
	}
	if revision.Issues == nil {
		problems = append(problems, errors.New("issues must be present, use an empty list when there are none"))
	}
	return errors.Join(problems...)
}

func (status InterpretationStatus) Valid() bool {
	switch status {
	case StatusParsed, StatusPartiallyParsed, StatusUnparsed, StatusInvalid, StatusError:
		return true
	default:
		return false
	}
}

func (issue Issue) Validate() error {
	if strings.TrimSpace(issue.Code) == "" || strings.TrimSpace(issue.Stage) == "" || strings.TrimSpace(issue.Message) == "" {
		return errors.New("code, stage, and message are required")
	}
	switch issue.Severity {
	case SeverityInfo, SeverityWarning, SeverityError:
		return nil
	default:
		return fmt.Errorf("invalid severity %q", issue.Severity)
	}
}
