package ingress

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/evidence"
	"github.com/sidd20228/universal_log_framework/internal/inbox"
	"github.com/sidd20228/universal_log_framework/internal/model"
)

type udpAttempt struct {
	request AdmissionRequest
	payload []byte
	result  AdmissionResult
	err     error
}

type recordingUDPAdmission struct {
	delegate Admission
	attempts chan udpAttempt
	calls    atomic.Uint64
}

func (admission *recordingUDPAdmission) Admit(ctx context.Context, request AdmissionRequest) (AdmissionResult, error) {
	admission.calls.Add(1)
	payload, err := io.ReadAll(request.Payload)
	if err != nil {
		return AdmissionResult{}, err
	}
	request.Payload = bytes.NewReader(payload)
	result, admitErr := admission.delegate.Admit(ctx, request)
	attempt := udpAttempt{request: request, payload: payload, result: result, err: admitErr}
	select {
	case admission.attempts <- attempt:
	case <-ctx.Done():
	}
	return result, admitErr
}

type failingUDPAdmission struct {
	calls atomic.Uint64
	err   error
}

func (admission *failingUDPAdmission) Admit(context.Context, AdmissionRequest) (AdmissionResult, error) {
	admission.calls.Add(1)
	return AdmissionResult{}, admission.err
}

type udpHarness struct {
	listener *UDPListener
	client   *net.UDPConn
	cancel   context.CancelFunc
	serveErr chan error
}

func startUDPHarness(t *testing.T, admission Admission, maximum int) *udpHarness {
	t.Helper()
	listener, err := NewUDPListener(UDPConfig{
		Address:         "127.0.0.1:0",
		TenantID:        "tenant-udp",
		ListenerID:      "syslog-udp-test",
		SourceProfileID: "source-udp",
		MaxEventBytes:   maximum,
		SocketReadBytes: 64 << 10,
	}, admission, nil)
	if err != nil {
		t.Fatal(err)
	}
	serverAddress := listener.Addr().(*net.UDPAddr)
	client, err := net.DialUDP("udp", nil, serverAddress)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() { serveErr <- listener.Serve(ctx) }()
	harness := &udpHarness{listener: listener, client: client, cancel: cancel, serveErr: serveErr}
	t.Cleanup(func() {
		client.Close()
		cancel()
		listener.Close()
		select {
		case err := <-serveErr:
			if err != nil {
				t.Errorf("Serve() error = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("UDP listener did not stop")
		}
	})
	return harness
}

func sendUDP(t *testing.T, client *net.UDPConn, payload []byte) {
	t.Helper()
	count, err := client.Write(payload)
	if err != nil {
		t.Fatal(err)
	}
	if count != len(payload) {
		t.Fatalf("UDP write = %d bytes, want %d", count, len(payload))
	}
}

func waitUDPAttempt(t *testing.T, attempts <-chan udpAttempt) udpAttempt {
	t.Helper()
	select {
	case attempt := <-attempts:
		return attempt
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for UDP admission")
		return udpAttempt{}
	}
}

func waitUDPMetrics(t *testing.T, listener *UDPListener, predicate func(UDPMetricsSnapshot) bool) UDPMetricsSnapshot {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		snapshot := listener.Metrics()
		if predicate(snapshot) {
			return snapshot
		}
		select {
		case <-deadline.C:
			t.Fatalf("timed out waiting for UDP metrics; latest=%+v", snapshot)
		case <-ticker.C:
		}
	}
}

func TestUDPListenerPreservesDatagramBytesAndTrustedMetadata(t *testing.T) {
	evidence := &memoryEvidence{}
	inbox := &memoryInbox{}
	coordinator := fixedCoordinator(t, evidence, inbox, 1024)
	recording := &recordingUDPAdmission{delegate: coordinator, attempts: make(chan udpAttempt, 2)}
	harness := startUDPHarness(t, recording, 1024)

	for _, payload := range [][]byte{
		[]byte("<134>1 2026-09-29T10:20:29Z edge test - ID47 - event"),
		{0xff, 0xfe, 0x00, 's', 'y', 's', 'l', 'o', 'g'},
	} {
		sendUDP(t, harness.client, payload)
		attempt := waitUDPAttempt(t, recording.attempts)
		if attempt.err != nil {
			t.Fatalf("Admit() error = %v", attempt.err)
		}
		receipt := attempt.result.Receipt
		if !bytes.Equal(attempt.payload, payload) || !bytes.Equal(evidence.value(receipt.ID), payload) {
			t.Fatalf("payload changed: attempt=%x evidence=%x want=%x", attempt.payload, evidence.value(receipt.ID), payload)
		}
		if receipt.Transport != model.TransportSyslogUDP || receipt.Framing.Mode != model.FramingDatagram || receipt.ListenerID != "syslog-udp-test" || receipt.TenantID != "tenant-udp" || receipt.SourceProfileID != "source-udp" {
			t.Fatalf("receipt metadata = %+v", receipt)
		}
		if receipt.Peer == nil || !receipt.Peer.IP.IsLoopback() || receipt.Peer.Port == 0 {
			t.Fatalf("receipt peer = %+v", receipt.Peer)
		}
	}
	snapshot := waitUDPMetrics(t, harness.listener, func(metrics UDPMetricsSnapshot) bool { return metrics.DatagramsAccepted == 2 })
	if snapshot.DatagramsReceived != 2 || snapshot.DatagramsRejected != 0 || snapshot.DatagramsDropped != 0 {
		t.Fatalf("metrics = %+v", snapshot)
	}
}

func TestUDPListenerPersistsLoopbackDatagramThroughDurableAdapters(t *testing.T) {
	root := t.TempDir()
	evidenceStore, err := evidence.NewFilesystem(filepath.Join(root, "raw"))
	if err != nil {
		t.Fatal(err)
	}
	inboxStore, err := inbox.OpenSQLite(context.Background(), filepath.Join(root, "inbox.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { inboxStore.Close() })
	coordinator, err := NewCoordinator(evidenceStore, inboxStore, 1024)
	if err != nil {
		t.Fatal(err)
	}
	recording := &recordingUDPAdmission{delegate: coordinator, attempts: make(chan udpAttempt, 1)}
	harness := startUDPHarness(t, recording, 1024)
	payload := []byte{0xff, 0x00, '<', '1', '3', '>', 'x'}

	sendUDP(t, harness.client, payload)
	attempt := waitUDPAttempt(t, recording.attempts)
	if attempt.err != nil {
		t.Fatal(attempt.err)
	}
	record, err := inboxStore.GetReceipt(context.Background(), attempt.result.Receipt.ID)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := evidenceStore.Open(context.Background(), record.Receipt.Raw)
	if err != nil {
		t.Fatal(err)
	}
	stored, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("read evidence errors = (%v, %v)", readErr, closeErr)
	}
	if !bytes.Equal(stored, payload) || record.Receipt.Transport != model.TransportSyslogUDP || record.Receipt.State != model.StateAccepted {
		t.Fatalf("durable record=%+v bytes=%x", record.Receipt, stored)
	}
	metrics := waitUDPMetrics(t, harness.listener, func(snapshot UDPMetricsSnapshot) bool { return snapshot.DatagramsAccepted == 1 })
	if metrics.DatagramsRejected != 0 {
		t.Fatalf("metrics = %+v", metrics)
	}
}

func TestUDPListenerRetainsIdenticalDatagramsAsDistinctOccurrences(t *testing.T) {
	evidence := &memoryEvidence{}
	inbox := &memoryInbox{}
	coordinator := fixedCoordinator(t, evidence, inbox, 1024)
	recording := &recordingUDPAdmission{delegate: coordinator, attempts: make(chan udpAttempt, 2)}
	harness := startUDPHarness(t, recording, 1024)
	payload := []byte("identical syslog occurrence")

	sendUDP(t, harness.client, payload)
	sendUDP(t, harness.client, payload)
	first := waitUDPAttempt(t, recording.attempts)
	second := waitUDPAttempt(t, recording.attempts)
	if first.err != nil || second.err != nil {
		t.Fatalf("admission errors = (%v, %v)", first.err, second.err)
	}
	if first.result.Receipt.ID == second.result.Receipt.ID {
		t.Fatalf("identical datagrams shared receipt id %s", first.result.Receipt.ID)
	}
	if evidence.count() != 2 || inbox.count() != 2 {
		t.Fatalf("durable occurrences: evidence=%d inbox=%d", evidence.count(), inbox.count())
	}
}

func TestUDPListenerRejectsOversizeAndAccountsForTruncation(t *testing.T) {
	coordinator := &recordingUDPAdmission{
		delegate: fixedCoordinator(t, &memoryEvidence{}, &memoryInbox{}, 16),
		attempts: make(chan udpAttempt, 1),
	}
	harness := startUDPHarness(t, coordinator, 16)

	sendUDP(t, harness.client, bytes.Repeat([]byte{'a'}, 17))
	sendUDP(t, harness.client, bytes.Repeat([]byte{'b'}, 256))
	snapshot := waitUDPMetrics(t, harness.listener, func(metrics UDPMetricsSnapshot) bool { return metrics.DatagramsRejected == 2 })
	if snapshot.DatagramsAccepted != 0 || snapshot.DatagramsRejected != 2 || snapshot.DatagramsDropped != 2 || snapshot.OversizeDatagrams != 2 {
		t.Fatalf("metrics = %+v", snapshot)
	}
	if supportsDatagramTruncationFlag && snapshot.TruncatedDatagrams != 1 {
		t.Fatalf("truncated datagrams = %d, want 1", snapshot.TruncatedDatagrams)
	}
	if coordinator.calls.Load() != 0 {
		t.Fatalf("oversize datagrams reached admission %d times", coordinator.calls.Load())
	}
}

func TestUDPListenerDoesNotClaimAcceptanceOnAdmissionFailure(t *testing.T) {
	failing := &failingUDPAdmission{err: errors.New("durable admission failed")}
	harness := startUDPHarness(t, failing, 1024)
	sendUDP(t, harness.client, []byte("event"))

	snapshot := waitUDPMetrics(t, harness.listener, func(metrics UDPMetricsSnapshot) bool { return metrics.AdmissionFailures == 1 })
	if failing.calls.Load() != 1 || snapshot.DatagramsAccepted != 0 || snapshot.DatagramsRejected != 1 || snapshot.DatagramsDropped != 1 {
		t.Fatalf("calls=%d metrics=%+v", failing.calls.Load(), snapshot)
	}
}

func TestUDPListenerStopsOnCancellation(t *testing.T) {
	failing := &failingUDPAdmission{err: errors.New("unused")}
	listener, err := NewUDPListener(UDPConfig{
		Address:       "127.0.0.1:0",
		TenantID:      "tenant-udp",
		ListenerID:    "syslog-udp-test",
		MaxEventBytes: 1024,
	}, failing, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() { serveErr <- listener.Serve(ctx) }()
	cancel()
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("Serve() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve() did not stop after cancellation")
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if snapshot := listener.Metrics(); snapshot.DatagramsAccepted != 0 || snapshot.DatagramsRejected != 0 || snapshot.ReadErrors != 0 {
		t.Fatalf("metrics after cancellation = %+v", snapshot)
	}
}
