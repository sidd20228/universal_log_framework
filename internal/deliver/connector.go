package deliver

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"time"
)

type ConnectorDescriptor struct {
	ID      string
	Kind    string
	Version string
}

type ExportRecord struct {
	ReceiptID       string
	RevisionID      string
	TenantID        string
	EnvironmentID   string
	InstanceID      string
	ReceivedAt      time.Time
	EventTime       *time.Time
	SourceProfile   string
	ClassUID        *uint32
	ActivityID      *uint16
	Action          string
	SeverityID      *uint8
	SourceIP        *netip.Addr
	DestinationIP   *netip.Addr
	SourcePort      *uint16
	DestinationPort *uint16
	Protocol        string
	Status          string
	ParserID        string
	ParserVersion   string
	SchemaVersion   string
	RawSHA256       string
	QualityScore    float32
	IssueCodes      []string
	EnvelopeJSON    json.RawMessage
}

type DeliveryStatus string

const (
	DeliverySucceeded DeliveryStatus = "SUCCEEDED"
	DeliveryRetryable DeliveryStatus = "RETRYABLE"
	DeliveryPermanent DeliveryStatus = "PERMANENT_FAILURE"
)

type RecordResult struct {
	RevisionID string
	Status     DeliveryStatus
	Code       string
	Message    string
}

type BatchResult struct {
	Records []RecordResult
}

func (result BatchResult) AllSucceeded() bool {
	if len(result.Records) == 0 {
		return false
	}
	for _, record := range result.Records {
		if record.Status != DeliverySucceeded {
			return false
		}
	}
	return true
}

type Health struct {
	Healthy bool
	Code    string
	Message string
}

type Connector interface {
	Descriptor() ConnectorDescriptor
	Deliver(context.Context, []ExportRecord) BatchResult
	Health(context.Context) Health
}

var ErrInvalidRecord = errors.New("invalid export record")
