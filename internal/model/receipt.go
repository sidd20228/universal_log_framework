package model

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

type Transport string

const (
	TransportHTTP      Transport = "http"
	TransportSyslogUDP Transport = "syslog_udp"
	TransportSyslogTCP Transport = "syslog_tcp"
)

type FramingMode string

const (
	FramingDatagram       FramingMode = "datagram"
	FramingOctetCounting  FramingMode = "octet_counting"
	FramingNonTransparent FramingMode = "non_transparent"
	FramingHTTPOctets     FramingMode = "http_octets"
)

type Peer struct {
	IP   netip.Addr `json:"ip"`
	Port uint16     `json:"port"`
}

type Framing struct {
	Mode          FramingMode `json:"mode"`
	Complete      bool        `json:"complete"`
	ObservedBytes uint64      `json:"observed_bytes"`
}

type RawReference struct {
	Ref          string `json:"ref"`
	SHA256       string `json:"sha256"`
	SizeBytes    uint64 `json:"size_bytes"`
	EncodingHint string `json:"encoding_hint,omitempty"`
	Compression  string `json:"compression,omitempty"`
	Available    bool   `json:"available"`
}

const (
	CompressionNone = "none"
	CompressionZstd = "zstd"
)

type Receipt struct {
	ID              string       `json:"id"`
	TenantID        string       `json:"tenant_id"`
	EnvironmentID   string       `json:"environment_id,omitempty"`
	InstanceID      string       `json:"instance_id,omitempty"`
	ReceivedAt      time.Time    `json:"received_at"`
	ListenerID      string       `json:"listener_id"`
	Transport       Transport    `json:"transport"`
	Peer            *Peer        `json:"peer,omitempty"`
	SourceProfileID string       `json:"source_profile_id,omitempty"`
	Framing         Framing      `json:"framing"`
	Raw             RawReference `json:"raw"`
	State           ReceiptState `json:"state"`
}

func (receipt Receipt) Validate() error {
	var problems []error
	if strings.TrimSpace(receipt.ID) == "" {
		problems = append(problems, errors.New("receipt id is required"))
	}
	if strings.TrimSpace(receipt.TenantID) == "" {
		problems = append(problems, errors.New("tenant id is required"))
	}
	if (receipt.EnvironmentID == "") != (receipt.InstanceID == "") {
		problems = append(problems, errors.New("environment and instance ids must be supplied together"))
	}
	if receipt.ReceivedAt.IsZero() {
		problems = append(problems, errors.New("received_at is required"))
	}
	if strings.TrimSpace(receipt.ListenerID) == "" {
		problems = append(problems, errors.New("listener id is required"))
	}
	if !receipt.Transport.Valid() {
		problems = append(problems, fmt.Errorf("unsupported transport %q", receipt.Transport))
	}
	if receipt.Peer != nil && !receipt.Peer.IP.IsValid() {
		problems = append(problems, errors.New("peer ip is invalid"))
	}
	if !receipt.Framing.Mode.Valid() {
		problems = append(problems, fmt.Errorf("unsupported framing mode %q", receipt.Framing.Mode))
	}
	if !receipt.Framing.Complete {
		problems = append(problems, errors.New("accepted receipt must contain a complete frame"))
	}
	if strings.TrimSpace(receipt.Raw.Ref) == "" {
		problems = append(problems, errors.New("raw reference is required"))
	}
	if !validSHA256(receipt.Raw.SHA256) {
		problems = append(problems, errors.New("raw sha256 must be 64 lowercase hexadecimal characters"))
	}
	if receipt.Raw.SizeBytes != receipt.Framing.ObservedBytes {
		problems = append(problems, errors.New("raw size must equal framing observed bytes"))
	}
	if receipt.Raw.Compression != CompressionNone && receipt.Raw.Compression != CompressionZstd {
		problems = append(problems, errors.New("raw compression must be none or zstd"))
	}
	if !receipt.State.Valid() {
		problems = append(problems, fmt.Errorf("invalid receipt state %q", receipt.State))
	} else if receipt.State == StateAccepted && !receipt.Raw.Available {
		problems = append(problems, errors.New("raw evidence must be available at acceptance"))
	}
	return errors.Join(problems...)
}

func (transport Transport) Valid() bool {
	switch transport {
	case TransportHTTP, TransportSyslogUDP, TransportSyslogTCP:
		return true
	default:
		return false
	}
}

func (mode FramingMode) Valid() bool {
	switch mode {
	case FramingDatagram, FramingOctetCounting, FramingNonTransparent, FramingHTTPOctets:
		return true
	default:
		return false
	}
}

func validSHA256(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}
