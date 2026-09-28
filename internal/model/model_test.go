package model

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func validReceipt() Receipt {
	return Receipt{
		ID:         "0199f47e-38db-7000-8000-000000000001",
		TenantID:   "tenant-a",
		ReceivedAt: time.Date(2026, 9, 29, 10, 20, 30, 0, time.UTC),
		ListenerID: "syslog-udp-5514",
		Transport:  TransportSyslogUDP,
		Peer:       &Peer{IP: netip.MustParseAddr("192.0.2.10"), Port: 49152},
		Framing: Framing{
			Mode:          FramingDatagram,
			Complete:      true,
			ObservedBytes: 143,
		},
		Raw: RawReference{
			Ref:         "raw/2026/09/29/0199.bin",
			SHA256:      strings.Repeat("a", 64),
			SizeBytes:   143,
			Compression: CompressionNone,
			Available:   true,
		},
		State: StateAccepted,
	}
}

func TestReceiptValidate(t *testing.T) {
	if err := validReceipt().Validate(); err != nil {
		t.Fatalf("valid receipt rejected: %v", err)
	}

	receipt := validReceipt()
	receipt.Framing.Complete = false
	receipt.Raw.SHA256 = "BAD"
	receipt.State = ReceiptState("UNKNOWN")
	if err := receipt.Validate(); err == nil {
		t.Fatal("invalid receipt accepted")
	}
}

func TestReceiptAllowsExpiredRawEvidenceAfterProcessing(t *testing.T) {
	receipt := validReceipt()
	receipt.State = StateDelivered
	receipt.Raw.Available = false
	if err := receipt.Validate(); err != nil {
		t.Fatalf("retained receipt metadata rejected after raw expiry: %v", err)
	}
}

func TestReceiptRejectsUnspecifiedRawCompression(t *testing.T) {
	receipt := validReceipt()
	receipt.Raw.Compression = ""
	if err := receipt.Validate(); err == nil {
		t.Fatal("receipt with unspecified raw compression was accepted")
	}
}

func TestRevisionValidate(t *testing.T) {
	confidence := 0.98
	start := time.Date(2026, 9, 29, 10, 20, 31, 0, time.UTC)
	revision := Revision{
		ID:              "0199f47e-38db-7000-8000-000000000002",
		ReceiptID:       "0199f47e-38db-7000-8000-000000000001",
		PipelineVersion: "0.1.0",
		SchemaVersion:   "ulpf-envelope/1.0.0",
		Parser: &ParserIdentity{
			ID:           "cef",
			Version:      "1.0.0",
			BundleSHA256: strings.Repeat("b", 64),
		},
		Status:      StatusParsed,
		Confidence:  &confidence,
		Issues:      []Issue{},
		StartedAt:   start,
		CompletedAt: start.Add(time.Millisecond),
	}
	if err := revision.Validate(); err != nil {
		t.Fatalf("valid revision rejected: %v", err)
	}

	revision.Parser = nil
	revision.Issues = nil
	if err := revision.Validate(); err == nil {
		t.Fatal("parsed revision without parser and issues list accepted")
	}
}
