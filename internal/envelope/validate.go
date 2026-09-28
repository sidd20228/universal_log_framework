package envelope

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/model"
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
	uuidPattern       = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	versionPattern    = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)
	issueCodePattern  = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,63}$`)
	protocolPattern   = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,31}$`)
)

func (envelope Envelope) Validate() error {
	var problems []error
	if envelope.SchemaVersion != SchemaVersion {
		problems = append(problems, fmt.Errorf("schema_version must be %q", SchemaVersion))
	}
	if err := validateReceipt(envelope.Receipt, envelope.Raw); err != nil {
		problems = append(problems, err)
	}
	if err := validateProcessing(envelope.Processing); err != nil {
		problems = append(problems, err)
	}
	if err := validateCanonicalEvent(envelope.Event); err != nil {
		problems = append(problems, err)
	}
	if err := validateProvenance(envelope.Event, envelope.Provenance, envelope.Processing.MappingVersion); err != nil {
		problems = append(problems, err)
	}
	if err := validateQuality(envelope.Event, envelope.Provenance, envelope.Quality); err != nil {
		problems = append(problems, err)
	}
	if err := validateCorrelation(envelope.Correlation); err != nil {
		problems = append(problems, err)
	}
	return errors.Join(problems...)
}

func validateReceipt(receipt Receipt, raw model.RawReference) error {
	var problems []error
	if !uuidPattern.MatchString(receipt.ID) {
		problems = append(problems, errors.New("receipt id must be a UUID"))
	}
	for name, value := range map[string]string{"tenant_id": receipt.TenantID, "listener_id": receipt.ListenerID} {
		if !validIdentifier(value) {
			problems = append(problems, fmt.Errorf("receipt %s is invalid", name))
		}
	}
	if receipt.SourceProfileID != "" && !validIdentifier(receipt.SourceProfileID) {
		problems = append(problems, errors.New("receipt source_profile_id is invalid"))
	}
	if receipt.ReceivedAt.IsZero() {
		problems = append(problems, errors.New("receipt received_at is required"))
	}
	switch receipt.Transport {
	case model.TransportHTTP, model.TransportSyslogUDP, model.TransportSyslogTCP:
	default:
		problems = append(problems, errors.New("receipt transport is invalid"))
	}
	if receipt.Peer != nil && !receipt.Peer.IP.IsValid() {
		problems = append(problems, errors.New("receipt peer IP is invalid"))
	}
	switch receipt.Framing.Mode {
	case model.FramingDatagram, model.FramingOctetCounting, model.FramingNonTransparent, model.FramingHTTPOctets:
	default:
		problems = append(problems, errors.New("receipt framing mode is invalid"))
	}
	if !receipt.Framing.Complete {
		problems = append(problems, errors.New("envelope cannot represent an incomplete accepted frame"))
	}
	if raw.SizeBytes != receipt.Framing.ObservedBytes {
		problems = append(problems, errors.New("raw size does not match observed frame bytes"))
	}
	if raw.Ref == "" || len(raw.Ref) > 1024 || strings.ContainsAny(raw.Ref, "\r\n") {
		problems = append(problems, errors.New("raw reference is invalid"))
	}
	if !validDigest(raw.SHA256) {
		problems = append(problems, errors.New("raw sha256 is invalid"))
	}
	if raw.Compression != model.CompressionNone && raw.Compression != model.CompressionZstd {
		problems = append(problems, errors.New("raw compression must be none or zstd"))
	}
	return errors.Join(problems...)
}

func validateProcessing(processing Processing) error {
	var problems []error
	if !uuidPattern.MatchString(processing.RevisionID) {
		problems = append(problems, errors.New("processing revision_id must be a UUID"))
	}
	if !versionPattern.MatchString(processing.PipelineVersion) {
		problems = append(problems, errors.New("processing pipeline_version must be semantic"))
	}
	switch processing.Status {
	case model.StatusParsed, model.StatusPartiallyParsed, model.StatusUnparsed, model.StatusInvalid, model.StatusError:
	default:
		problems = append(problems, errors.New("processing status is invalid"))
	}
	if processing.Confidence != nil && (*processing.Confidence < 0 || *processing.Confidence > 1 || math.IsNaN(*processing.Confidence)) {
		problems = append(problems, errors.New("processing confidence is invalid"))
	}
	if processing.Parser != nil {
		if !validIdentifier(processing.Parser.ID) || !versionPattern.MatchString(processing.Parser.Version) {
			problems = append(problems, errors.New("processing parser identity is invalid"))
		}
		if processing.Parser.BundleSHA256 != "" && !validDigest(processing.Parser.BundleSHA256) {
			problems = append(problems, errors.New("processing parser bundle digest is invalid"))
		}
	} else if processing.Status == model.StatusParsed || processing.Status == model.StatusPartiallyParsed {
		problems = append(problems, errors.New("parsed processing status requires a parser"))
	}
	if processing.Issues == nil || len(processing.Issues) > MaxIssues {
		problems = append(problems, errors.New("processing issues must be a bounded present list"))
	}
	for index, issue := range processing.Issues {
		if err := validateIssue(issue); err != nil {
			problems = append(problems, fmt.Errorf("processing issue %d: %w", index, err))
		}
	}
	if processing.Timestamps.StartedAt.IsZero() || processing.Timestamps.CompletedAt.IsZero() || processing.Timestamps.CompletedAt.Before(processing.Timestamps.StartedAt) {
		problems = append(problems, errors.New("processing timestamps are invalid"))
	}
	return errors.Join(problems...)
}

func validateIssue(issue Issue) error {
	if !issueCodePattern.MatchString(issue.Code) {
		return errors.New("code is invalid")
	}
	switch issue.Stage {
	case "detection", "parsing", "mapping", "validation", "enrichment", "delivery":
	default:
		return errors.New("stage is invalid")
	}
	switch issue.Severity {
	case model.SeverityInfo, model.SeverityWarning, model.SeverityError:
	default:
		return errors.New("severity is invalid")
	}
	if issue.Message == "" || len(issue.Message) > MaxIssueMessageBytes {
		return errors.New("message is invalid")
	}
	if issue.SourcePath != "" && len(issue.SourcePath) > 512 {
		return errors.New("source_path is too long")
	}
	if issue.Offset != nil && *issue.Offset < 0 {
		return errors.New("offset is negative")
	}
	return nil
}

func validateCanonicalEvent(event map[string]any) error {
	if len(event) == 0 {
		return nil
	}
	allowed := map[string]struct{}{
		"class_uid": {}, "class_name": {}, "activity_id": {}, "activity": {}, "time": {},
		"action": {}, "status": {}, "severity_id": {}, "severity": {}, "src_endpoint": {},
		"dst_endpoint": {}, "connection_info": {}, "device": {}, "finding": {}, "extensions": {},
	}
	for key := range event {
		if _, exists := allowed[key]; !exists {
			return fmt.Errorf("event field %q is not allowed", key)
		}
	}
	classUID, present := event["class_uid"]
	if !present || !integerInRange(classUID, 0, math.MaxInt64) {
		return errors.New("event.class_uid is required and must be a non-negative integer")
	}
	if className, ok := event["class_name"].(string); !ok || className == "" || len(className) > 128 {
		return errors.New("event.class_name is required and invalid")
	}
	if value, exists := event["activity_id"]; exists && !integerInRange(value, 0, math.MaxInt64) {
		return errors.New("event.activity_id is invalid")
	}
	for _, key := range []string{"activity", "status"} {
		if value, exists := event[key]; exists {
			text, ok := value.(string)
			if !ok || text == "" || len(text) > 128 {
				return fmt.Errorf("event.%s is invalid", key)
			}
		}
	}
	if value, exists := event["time"]; exists {
		valid := false
		switch timestamp := value.(type) {
		case time.Time:
			valid = !timestamp.IsZero()
		case string:
			parsed, err := time.Parse(time.RFC3339Nano, timestamp)
			valid = err == nil && !parsed.IsZero()
		}
		if !valid {
			return errors.New("event.time must be a non-zero time.Time")
		}
	}
	if value, exists := event["action"]; exists {
		text, ok := value.(string)
		if !ok || !stringIn(text, "allow", "deny", "observe", "quarantine", "reset", "redirect", "unknown") {
			return errors.New("event.action is invalid")
		}
	}
	if value, exists := event["severity_id"]; exists && !integerInRange(value, 0, 6) {
		return errors.New("event.severity_id is invalid")
	}
	if value, exists := event["severity"]; exists {
		text, ok := value.(string)
		if !ok || !stringIn(text, "unknown", "informational", "low", "medium", "high", "critical") {
			return errors.New("event.severity is invalid")
		}
	}
	for _, key := range []string{"src_endpoint", "dst_endpoint"} {
		if value, exists := event[key]; exists {
			if err := validateEndpoint(key, value); err != nil {
				return err
			}
		}
	}
	if value, exists := event["connection_info"]; exists {
		if err := validateConnectionInfo(value); err != nil {
			return err
		}
	}
	if value, exists := event["device"]; exists {
		if err := validateDevice(value); err != nil {
			return err
		}
	}
	if value, exists := event["finding"]; exists {
		if err := validateFinding(value); err != nil {
			return err
		}
	}
	return nil
}

func validateEndpoint(name string, value any) error {
	endpoint, ok := value.(map[string]any)
	if !ok || len(endpoint) == 0 {
		return fmt.Errorf("event.%s must be a non-empty object", name)
	}
	for key, field := range endpoint {
		switch key {
		case "ip":
			switch address := field.(type) {
			case netip.Addr:
				if !address.IsValid() {
					return fmt.Errorf("event.%s.ip is invalid", name)
				}
			case string:
				if _, err := netip.ParseAddr(address); err != nil {
					return fmt.Errorf("event.%s.ip is invalid", name)
				}
			default:
				return fmt.Errorf("event.%s.ip is invalid", name)
			}
		case "port":
			if !integerInRange(field, 0, 65535) {
				return fmt.Errorf("event.%s.port is invalid", name)
			}
		case "hostname":
			if text, ok := field.(string); !ok || text == "" || len(text) > 255 {
				return fmt.Errorf("event.%s.hostname is invalid", name)
			}
		case "mac":
			if text, ok := field.(string); !ok || len(text) < 11 || len(text) > 23 {
				return fmt.Errorf("event.%s.mac is invalid", name)
			}
		default:
			return fmt.Errorf("event.%s field %q is not allowed", name, key)
		}
	}
	return nil
}

func validateConnectionInfo(value any) error {
	object, ok := value.(map[string]any)
	if !ok {
		return errors.New("event.connection_info must be an object")
	}
	for key, field := range object {
		switch key {
		case "protocol_name":
			text, ok := field.(string)
			if !ok || !protocolPattern.MatchString(text) {
				return errors.New("event.connection_info.protocol_name is invalid")
			}
		case "protocol_num":
			if !integerInRange(field, 0, 255) {
				return errors.New("event.connection_info.protocol_num is invalid")
			}
		default:
			return fmt.Errorf("event.connection_info field %q is not allowed", key)
		}
	}
	return nil
}

func validateDevice(value any) error {
	object, ok := value.(map[string]any)
	if !ok {
		return errors.New("event.device must be an object")
	}
	for key, field := range object {
		text, ok := field.(string)
		if !ok || text == "" {
			return fmt.Errorf("event.device.%s is invalid", key)
		}
		switch key {
		case "type":
			if !stringIn(text, "firewall", "router", "switch", "ids", "ips", "proxy", "vpn", "unknown") {
				return errors.New("event.device.type is invalid")
			}
		case "hostname":
			if len(text) > 255 {
				return errors.New("event.device.hostname is invalid")
			}
		case "vendor_name", "product_name":
			if len(text) > 128 {
				return fmt.Errorf("event.device.%s is invalid", key)
			}
		default:
			return fmt.Errorf("event.device field %q is not allowed", key)
		}
	}
	return nil
}

func validateFinding(value any) error {
	object, ok := value.(map[string]any)
	if !ok || len(object) == 0 {
		return errors.New("event.finding must be a non-empty object")
	}
	for key, field := range object {
		switch key {
		case "signature":
			text, ok := field.(string)
			if !ok || text == "" || len(text) > 512 {
				return errors.New("event.finding.signature is invalid")
			}
		case "signature_id":
			if !integerInRange(field, 0, math.MaxInt64) {
				return errors.New("event.finding.signature_id is invalid")
			}
		default:
			return fmt.Errorf("event.finding field %q is not allowed", key)
		}
	}
	return nil
}

func validateProvenance(event map[string]any, provenance map[string]FieldProvenance, mappingVersion string) error {
	leaves := eventLeafPaths(event)
	if len(leaves) != len(provenance) {
		return errors.New("provenance count does not match canonical event leaf count")
	}
	for _, path := range leaves {
		value, exists := provenance[path]
		if !exists {
			return fmt.Errorf("canonical event leaf %q has no provenance", path)
		}
		if value.Kind != "mapped" && value.Kind != "normalized" && value.Kind != "original" && value.Kind != "parsed" && value.Kind != "derived" && value.Kind != "enriched" {
			return fmt.Errorf("provenance %q has an invalid kind", path)
		}
		if value.SourcePath == "" || len(value.SourcePath) > 512 || !validIdentifier(value.RuleID) || value.MappingVersion == "" || value.MappingVersion != mappingVersion {
			return fmt.Errorf("provenance %q is incomplete", path)
		}
	}
	return nil
}

func validateQuality(event map[string]any, provenance map[string]FieldProvenance, quality Quality) error {
	leafCount := len(eventLeafPaths(event))
	if quality.RequiredTotal < 0 || quality.RequiredPresent < 0 || quality.RequiredPresent > quality.RequiredTotal ||
		quality.ProvenanceTotal != leafCount || quality.ProvenancePresent != len(provenance) || quality.ProvenancePresent > quality.ProvenanceTotal {
		return errors.New("quality counts are inconsistent")
	}
	denominator := quality.RequiredTotal + quality.ProvenanceTotal
	want := 0.0
	if denominator != 0 {
		want = float64(quality.RequiredPresent+quality.ProvenancePresent) / float64(denominator)
	}
	if quality.Score != want || quality.Score < 0 || quality.Score > 1 || math.IsNaN(quality.Score) {
		return errors.New("quality score is inconsistent with evidence counts")
	}
	return nil
}

func validateCorrelation(correlation Correlation) error {
	if correlation.GroupIDs == nil || len(correlation.GroupIDs) > 128 {
		return errors.New("correlation group_ids must be a bounded present list")
	}
	seen := make(map[string]struct{}, len(correlation.GroupIDs))
	for _, identifier := range correlation.GroupIDs {
		if !validIdentifier(identifier) {
			return errors.New("correlation group id is invalid")
		}
		if _, exists := seen[identifier]; exists {
			return errors.New("correlation group ids must be unique")
		}
		seen[identifier] = struct{}{}
	}
	return nil
}

func validIdentifier(value string) bool {
	return len(value) > 0 && len(value) <= 128 && identifierPattern.MatchString(value)
}

func validDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func integerInRange(value any, minimum, maximum int64) bool {
	var integer int64
	switch typed := value.(type) {
	case int:
		integer = int64(typed)
	case int8:
		integer = int64(typed)
	case int16:
		integer = int64(typed)
	case int32:
		integer = int64(typed)
	case int64:
		integer = typed
	case uint:
		if uint64(typed) > math.MaxInt64 {
			return false
		}
		integer = int64(typed)
	case uint8:
		integer = int64(typed)
	case uint16:
		integer = int64(typed)
	case uint32:
		integer = int64(typed)
	case uint64:
		if typed > math.MaxInt64 {
			return false
		}
		integer = int64(typed)
	case json.Number:
		parsed, err := strconv.ParseInt(string(typed), 10, 64)
		if err != nil {
			return false
		}
		integer = parsed
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) || math.Trunc(typed) != typed || typed < math.MinInt64 || typed > math.MaxInt64 {
			return false
		}
		integer = int64(typed)
	default:
		return false
	}
	return integer >= minimum && integer <= maximum
}

func stringIn(value string, allowed ...string) bool {
	sort.Strings(allowed)
	index := sort.SearchStrings(allowed, value)
	return index < len(allowed) && allowed[index] == value
}
