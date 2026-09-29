package deliver

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/envelope"
)

// ProjectEnvelope builds the only connector-facing representation of a
// canonical envelope. It validates stored truth before projection and never
// accepts or reads raw evidence bytes.
func ProjectEnvelope(value envelope.Envelope) (ExportRecord, error) {
	if err := value.Validate(); err != nil {
		return ExportRecord{}, fmt.Errorf("validate envelope for delivery: %w", err)
	}
	body, err := json.Marshal(value)
	if err != nil {
		return ExportRecord{}, fmt.Errorf("encode envelope for delivery: %w", err)
	}
	result := ExportRecord{
		ReceiptID: value.Receipt.ID, RevisionID: value.Processing.RevisionID,
		TenantID: value.Receipt.TenantID, EnvironmentID: value.Receipt.EnvironmentID,
		InstanceID: value.Receipt.InstanceID, ReceivedAt: value.Receipt.ReceivedAt,
		SourceProfile: value.Receipt.SourceProfileID, Status: string(value.Processing.Status),
		SchemaVersion: value.SchemaVersion, RawSHA256: value.Raw.SHA256,
		QualityScore: float32(value.Quality.Score), IssueCodes: make([]string, len(value.Processing.Issues)),
		EnvelopeJSON: body,
	}
	if value.Processing.Parser != nil {
		result.ParserID = value.Processing.Parser.ID
		result.ParserVersion = value.Processing.Parser.Version
	}
	for index, issue := range value.Processing.Issues {
		result.IssueCodes[index] = issue.Code
	}
	if len(value.Event) == 0 {
		return result, nil
	}
	if result.ClassUID, err = uint32Field(value.Event, "class_uid"); err != nil {
		return ExportRecord{}, err
	}
	if result.ActivityID, err = uint16Field(value.Event, "activity_id"); err != nil {
		return ExportRecord{}, err
	}
	if result.SeverityID, err = uint8Field(value.Event, "severity_id"); err != nil {
		return ExportRecord{}, err
	}
	if result.EventTime, err = timestampField(value.Event, "time"); err != nil {
		return ExportRecord{}, err
	}
	if result.Action, err = stringField(value.Event, "action"); err != nil {
		return ExportRecord{}, err
	}
	if result.SourceIP, result.SourcePort, err = endpointFields(value.Event, "src_endpoint"); err != nil {
		return ExportRecord{}, err
	}
	if result.DestinationIP, result.DestinationPort, err = endpointFields(value.Event, "dst_endpoint"); err != nil {
		return ExportRecord{}, err
	}
	if connection, present := value.Event["connection_info"]; present {
		object, ok := connection.(map[string]any)
		if !ok {
			return ExportRecord{}, errors.New("project event.connection_info: expected object")
		}
		if result.Protocol, err = stringField(object, "protocol_name"); err != nil {
			return ExportRecord{}, err
		}
	}
	return result, nil
}

func uint32Field(object map[string]any, name string) (*uint32, error) {
	value, present := object[name]
	if !present {
		return nil, nil
	}
	number, ok := unsignedInteger(value, math.MaxUint32)
	if !ok {
		return nil, fmt.Errorf("project event.%s: expected unsigned 32-bit integer", name)
	}
	result := uint32(number)
	return &result, nil
}

func uint16Field(object map[string]any, name string) (*uint16, error) {
	value, present := object[name]
	if !present {
		return nil, nil
	}
	number, ok := unsignedInteger(value, math.MaxUint16)
	if !ok {
		return nil, fmt.Errorf("project event.%s: expected unsigned 16-bit integer", name)
	}
	result := uint16(number)
	return &result, nil
}

func uint8Field(object map[string]any, name string) (*uint8, error) {
	value, present := object[name]
	if !present {
		return nil, nil
	}
	number, ok := unsignedInteger(value, math.MaxUint8)
	if !ok {
		return nil, fmt.Errorf("project event.%s: expected unsigned 8-bit integer", name)
	}
	result := uint8(number)
	return &result, nil
}

func unsignedInteger(value any, maximum uint64) (uint64, bool) {
	var result uint64
	switch typed := value.(type) {
	case int:
		if typed < 0 {
			return 0, false
		}
		result = uint64(typed)
	case int8:
		if typed < 0 {
			return 0, false
		}
		result = uint64(typed)
	case int16:
		if typed < 0 {
			return 0, false
		}
		result = uint64(typed)
	case int32:
		if typed < 0 {
			return 0, false
		}
		result = uint64(typed)
	case int64:
		if typed < 0 {
			return 0, false
		}
		result = uint64(typed)
	case uint:
		result = uint64(typed)
	case uint8:
		result = uint64(typed)
	case uint16:
		result = uint64(typed)
	case uint32:
		result = uint64(typed)
	case uint64:
		result = typed
	case json.Number:
		parsed, err := strconv.ParseUint(string(typed), 10, 64)
		if err != nil {
			return 0, false
		}
		result = parsed
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) || typed < 0 || math.Trunc(typed) != typed || typed > float64(maximum) {
			return 0, false
		}
		result = uint64(typed)
	default:
		return 0, false
	}
	return result, result <= maximum
}

func timestampField(object map[string]any, name string) (*time.Time, error) {
	value, present := object[name]
	if !present {
		return nil, nil
	}
	var result time.Time
	switch typed := value.(type) {
	case time.Time:
		result = typed
	case string:
		parsed, err := time.Parse(time.RFC3339Nano, typed)
		if err != nil {
			return nil, fmt.Errorf("project event.%s: expected RFC3339 timestamp", name)
		}
		result = parsed
	default:
		return nil, fmt.Errorf("project event.%s: expected timestamp", name)
	}
	result = result.UTC()
	return &result, nil
}

func stringField(object map[string]any, name string) (string, error) {
	value, present := object[name]
	if !present {
		return "", nil
	}
	result, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("project event.%s: expected string", name)
	}
	return result, nil
}

func endpointFields(event map[string]any, name string) (*netip.Addr, *uint16, error) {
	value, present := event[name]
	if !present {
		return nil, nil, nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("project event.%s: expected object", name)
	}
	var address *netip.Addr
	if rawIP, exists := object["ip"]; exists {
		var parsed netip.Addr
		switch typed := rawIP.(type) {
		case netip.Addr:
			parsed = typed
		case string:
			var err error
			parsed, err = netip.ParseAddr(typed)
			if err != nil {
				return nil, nil, fmt.Errorf("project event.%s.ip: expected IP address", name)
			}
		default:
			return nil, nil, fmt.Errorf("project event.%s.ip: expected IP address", name)
		}
		address = &parsed
	}
	port, err := uint16Field(object, "port")
	if err != nil {
		return nil, nil, fmt.Errorf("project event.%s.port: expected port", name)
	}
	return address, port, nil
}
