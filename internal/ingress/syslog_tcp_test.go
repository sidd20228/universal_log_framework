package ingress

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/model"
)

type tcpAttempt struct {
	request AdmissionRequest
	payload []byte
	result  AdmissionResult
	err     error
}

type recordingTCPAdmission struct {
	delegate Admission
	attempts chan tcpAttempt
	calls    atomic.Uint64
}

func (admission *recordingTCPAdmission) Admit(ctx context.Context, request AdmissionRequest) (AdmissionResult, error) {
	admission.calls.Add(1)
	payload, err := io.ReadAll(request.Payload)
	if err != nil {
		return AdmissionResult{}, err
	}
	request.Payload = bytes.NewReader(payload)
	result, admitErr := admission.delegate.Admit(ctx, request)
	attempt := tcpAttempt{request: request, payload: payload, result: result, err: admitErr}
	select {
	case admission.attempts <- attempt:
	case <-ctx.Done():
	}
	return result, admitErr
}

type failingTCPAdmission struct {
	calls atomic.Uint64
	err   error
}

func (admission *failingTCPAdmission) Admit(context.Context, AdmissionRequest) (AdmissionResult, error) {
	admission.calls.Add(1)
	return AdmissionResult{}, admission.err
}

type chunkReader struct {
	chunks [][]byte
}

func (reader *chunkReader) Read(buffer []byte) (int, error) {
	if len(reader.chunks) == 0 {
		return 0, io.EOF
	}
	chunk := reader.chunks[0]
	reader.chunks = reader.chunks[1:]
	count := copy(buffer, chunk)
	if count < len(chunk) {
		reader.chunks = append([][]byte{chunk[count:]}, reader.chunks...)
	}
	return count, nil
}

func TestReadTCPFrameExtractsCoalescedAndSplitOctetCountedFrames(t *testing.T) {
	reader := bufio.NewReader(&chunkReader{chunks: [][]byte{
		[]byte("5 he"), []byte("llo10 line"), []byte("\nvalue"),
	}})
	first, err := readTCPFrame(reader, model.FramingOctetCounting, nil, 64, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := readTCPFrame(reader, model.FramingOctetCounting, nil, 64, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, []byte("hello")) || !bytes.Equal(second, []byte("line\nvalue")) {
		t.Fatalf("frames = (%q, %q)", first, second)
	}
}

func TestReadTCPFrameExtractsDelimitedFramesAndExcludesDelimiter(t *testing.T) {
	reader := bufio.NewReader(stringsReader("first\r\nsecond\r\n"))
	first, err := readTCPFrame(reader, model.FramingNonTransparent, []byte("\r\n"), 64, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := readTCPFrame(reader, model.FramingNonTransparent, []byte("\r\n"), 64, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != "first" || string(second) != "second" {
		t.Fatalf("frames = (%q, %q)", first, second)
	}
}

func TestReadTCPFrameRejectsMalformedOversizeAndIncompleteInput(t *testing.T) {
	tests := []struct {
		name      string
		wire      []byte
		mode      model.FramingMode
		delimiter []byte
		maximum   int
		want      error
	}{
		{name: "zero count", wire: []byte("0 "), mode: model.FramingOctetCounting, maximum: 8, want: ErrTCPInvalidOctetCount},
		{name: "leading zero", wire: []byte("05 hello"), mode: model.FramingOctetCounting, maximum: 8, want: ErrTCPInvalidOctetCount},
		{name: "non digit", wire: []byte("x hello"), mode: model.FramingOctetCounting, maximum: 8, want: ErrTCPInvalidOctetCount},
		{name: "count overflow", wire: []byte("999999999999999999999 x"), mode: model.FramingOctetCounting, maximum: 8, want: ErrTCPInvalidOctetCount},
		{name: "oversize count", wire: []byte("9 ignored"), mode: model.FramingOctetCounting, maximum: 8, want: ErrTCPFrameTooLarge},
		{name: "short body", wire: []byte("5 abc"), mode: model.FramingOctetCounting, maximum: 8, want: ErrTCPIncompleteFrame},
		{name: "missing delimiter", wire: []byte("event"), mode: model.FramingNonTransparent, delimiter: []byte{'\n'}, maximum: 8, want: ErrTCPIncompleteFrame},
		{name: "oversize delimited", wire: []byte("123456789\n"), mode: model.FramingNonTransparent, delimiter: []byte{'\n'}, maximum: 8, want: ErrTCPFrameTooLarge},
		{name: "oversize before multibyte delimiter", wire: []byte("123456789\r\n"), mode: model.FramingNonTransparent, delimiter: []byte("\r\n"), maximum: 8, want: ErrTCPFrameTooLarge},
		{name: "empty delimited", wire: []byte("\n"), mode: model.FramingNonTransparent, delimiter: []byte{'\n'}, maximum: 8, want: ErrTCPEmptyFrame},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := readTCPFrame(bufio.NewReader(bytes.NewReader(test.wire)), test.mode, test.delimiter, test.maximum, nil)
			if !errors.Is(err, test.want) {
				t.Fatalf("readTCPFrame() error = %v, want %v", err, test.want)
			}
		})
	}
}

func stringsReader(value string) io.Reader { return bytes.NewBufferString(value) }

type tcpHarness struct {
	listener *TCPListener
	cancel   context.CancelFunc
	serveErr chan error
}

func startTCPHarness(t *testing.T, admission Admission, mode model.FramingMode, maximum int, mutate func(*TCPConfig)) *tcpHarness {
	t.Helper()
	config := TCPConfig{
		Address:         "127.0.0.1:0",
		TenantID:        "tenant-tcp",
		ListenerID:      "syslog-tcp-test",
		SourceProfileID: "source-tcp",
		MaxEventBytes:   maximum,
		FramingMode:     mode,
		IdleTimeout:     2 * time.Second,
		FrameTimeout:    2 * time.Second,
		MaxConnections:  8,
	}
	if mutate != nil {
		mutate(&config)
	}
	listener, err := NewTCPListener(config, admission, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() { serveErr <- listener.Serve(ctx) }()
	harness := &tcpHarness{listener: listener, cancel: cancel, serveErr: serveErr}
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		select {
		case err := <-serveErr:
			if err != nil {
				t.Errorf("Serve() error = %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("TCP listener did not stop")
		}
	})
	return harness
}

func dialTCP(t *testing.T, listener *TCPListener) *net.TCPConn {
	t.Helper()
	connection, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection
}

func writeTCP(t *testing.T, connection *net.TCPConn, payload []byte) {
	t.Helper()
	count, err := connection.Write(payload)
	if err != nil {
		t.Fatal(err)
	}
	if count != len(payload) {
		t.Fatalf("TCP write = %d bytes, want %d", count, len(payload))
	}
}

func waitTCPAttempt(t *testing.T, attempts <-chan tcpAttempt) tcpAttempt {
	t.Helper()
	select {
	case attempt := <-attempts:
		return attempt
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for TCP admission")
		return tcpAttempt{}
	}
}

func waitTCPMetrics(t *testing.T, listener *TCPListener, predicate func(TCPMetricsSnapshot) bool) TCPMetricsSnapshot {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
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
			t.Fatalf("timed out waiting for TCP metrics; latest=%+v", snapshot)
		case <-ticker.C:
		}
	}
}

func TestTCPListenerAdmitsEveryCompleteOctetCountedFrameWithTrustedMetadata(t *testing.T) {
	evidence := &memoryEvidence{}
	inbox := &memoryInbox{}
	recording := &recordingTCPAdmission{
		delegate: fixedCoordinator(t, evidence, inbox, 1024),
		attempts: make(chan tcpAttempt, 3),
	}
	harness := startTCPHarness(t, recording, model.FramingOctetCounting, 1024, nil)
	connection := dialTCP(t, harness.listener)

	writeTCP(t, connection, []byte("5 hello10 line\n"))
	writeTCP(t, connection, []byte("value5 hello"))
	wants := [][]byte{[]byte("hello"), []byte("line\nvalue"), []byte("hello")}
	var receipts []string
	for _, want := range wants {
		attempt := waitTCPAttempt(t, recording.attempts)
		if attempt.err != nil {
			t.Fatal(attempt.err)
		}
		if !bytes.Equal(attempt.payload, want) || !bytes.Equal(evidence.value(attempt.result.Receipt.ID), want) {
			t.Fatalf("payload = %q, evidence = %q, want %q", attempt.payload, evidence.value(attempt.result.Receipt.ID), want)
		}
		receipt := attempt.result.Receipt
		if receipt.Transport != model.TransportSyslogTCP || receipt.Framing.Mode != model.FramingOctetCounting || receipt.Peer == nil || !receipt.Peer.IP.IsLoopback() || receipt.Peer.Port == 0 {
			t.Fatalf("receipt metadata = %+v", receipt)
		}
		receipts = append(receipts, receipt.ID)
	}
	if receipts[0] == receipts[2] || evidence.count() != 3 || inbox.count() != 3 {
		t.Fatalf("identical occurrences were not distinct: ids=%v evidence=%d inbox=%d", receipts, evidence.count(), inbox.count())
	}
	metrics := waitTCPMetrics(t, harness.listener, func(snapshot TCPMetricsSnapshot) bool { return snapshot.FramesAccepted == 3 })
	if metrics.FramesReceived != 3 || metrics.BytesObserved != 20 || metrics.FramesRejected != 0 {
		t.Fatalf("metrics = %+v", metrics)
	}
}

func TestTCPListenerDelimiterInjectionCreatesSeparateExactFrames(t *testing.T) {
	evidence := &memoryEvidence{}
	recording := &recordingTCPAdmission{
		delegate: fixedCoordinator(t, evidence, &memoryInbox{}, 1024),
		attempts: make(chan tcpAttempt, 2),
	}
	harness := startTCPHarness(t, recording, model.FramingNonTransparent, 1024, nil)
	connection := dialTCP(t, harness.listener)
	writeTCP(t, connection, []byte("first\ninjected\n"))

	first := waitTCPAttempt(t, recording.attempts)
	second := waitTCPAttempt(t, recording.attempts)
	if string(first.payload) != "first" || string(second.payload) != "injected" {
		t.Fatalf("delimiter frames = (%q, %q)", first.payload, second.payload)
	}
	if first.result.Receipt.Framing.Mode != model.FramingNonTransparent || second.result.Receipt.Framing.Mode != model.FramingNonTransparent {
		t.Fatalf("framing modes = (%q, %q)", first.result.Receipt.Framing.Mode, second.result.Receipt.Framing.Mode)
	}
}

func TestTCPListenerRejectsInvalidOversizeAndIncompleteFramesBeforeAdmission(t *testing.T) {
	tests := []struct {
		name       string
		wire       []byte
		maximum    int
		wantMetric func(TCPMetricsSnapshot) bool
	}{
		{name: "invalid count", wire: []byte("x event"), maximum: 8, wantMetric: func(metric TCPMetricsSnapshot) bool { return metric.InvalidFrames == 1 }},
		{name: "oversize", wire: []byte("9 oversized"), maximum: 8, wantMetric: func(metric TCPMetricsSnapshot) bool { return metric.OversizeFrames == 1 }},
		{name: "EOF mid frame", wire: []byte("5 abc"), maximum: 8, wantMetric: func(metric TCPMetricsSnapshot) bool { return metric.IncompleteFrames == 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recording := &recordingTCPAdmission{
				delegate: fixedCoordinator(t, &memoryEvidence{}, &memoryInbox{}, int64(test.maximum)),
				attempts: make(chan tcpAttempt, 1),
			}
			harness := startTCPHarness(t, recording, model.FramingOctetCounting, test.maximum, nil)
			connection := dialTCP(t, harness.listener)
			writeTCP(t, connection, test.wire)
			if err := connection.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			metrics := waitTCPMetrics(t, harness.listener, test.wantMetric)
			if recording.calls.Load() != 0 || metrics.FramesAccepted != 0 || metrics.FramesRejected != 1 {
				t.Fatalf("calls=%d metrics=%+v", recording.calls.Load(), metrics)
			}
		})
	}
}

func TestTCPListenerEnforcesIdleAndFixedFrameDeadlines(t *testing.T) {
	recording := &recordingTCPAdmission{
		delegate: fixedCoordinator(t, &memoryEvidence{}, &memoryInbox{}, 64),
		attempts: make(chan tcpAttempt, 1),
	}
	harness := startTCPHarness(t, recording, model.FramingOctetCounting, 64, func(config *TCPConfig) {
		config.IdleTimeout = 80 * time.Millisecond
		config.FrameTimeout = 80 * time.Millisecond
	})
	idle := dialTCP(t, harness.listener)
	waitTCPMetrics(t, harness.listener, func(snapshot TCPMetricsSnapshot) bool { return snapshot.ReadTimeouts == 1 })
	_ = idle.Close()

	slow := dialTCP(t, harness.listener)
	writeTCP(t, slow, []byte("5 "))
	metrics := waitTCPMetrics(t, harness.listener, func(snapshot TCPMetricsSnapshot) bool { return snapshot.ReadTimeouts == 2 })
	if recording.calls.Load() != 0 || metrics.IncompleteFrames != 1 || metrics.FramesAccepted != 0 {
		t.Fatalf("calls=%d metrics=%+v", recording.calls.Load(), metrics)
	}
}

func TestTCPListenerDoesNotClaimAcceptanceAfterAdmissionFailure(t *testing.T) {
	failing := &failingTCPAdmission{err: errors.New("durable admission failed")}
	harness := startTCPHarness(t, failing, model.FramingOctetCounting, 64, nil)
	connection := dialTCP(t, harness.listener)
	writeTCP(t, connection, []byte("5 hello5 world"))

	metrics := waitTCPMetrics(t, harness.listener, func(snapshot TCPMetricsSnapshot) bool { return snapshot.AdmissionFailures == 1 })
	if failing.calls.Load() != 1 || metrics.FramesReceived != 1 || metrics.FramesAccepted != 0 || metrics.FramesRejected != 1 {
		t.Fatalf("calls=%d metrics=%+v", failing.calls.Load(), metrics)
	}
}

func TestTCPListenerBoundsConcurrentConnections(t *testing.T) {
	recording := &recordingTCPAdmission{
		delegate: fixedCoordinator(t, &memoryEvidence{}, &memoryInbox{}, 64),
		attempts: make(chan tcpAttempt, 1),
	}
	harness := startTCPHarness(t, recording, model.FramingOctetCounting, 64, func(config *TCPConfig) {
		config.MaxConnections = 1
		config.IdleTimeout = time.Minute
	})
	first := dialTCP(t, harness.listener)
	waitTCPMetrics(t, harness.listener, func(snapshot TCPMetricsSnapshot) bool { return snapshot.ActiveConnections == 1 })
	second := dialTCP(t, harness.listener)
	metrics := waitTCPMetrics(t, harness.listener, func(snapshot TCPMetricsSnapshot) bool { return snapshot.ConnectionsRejected == 1 })
	if metrics.ActiveConnections != 1 || recording.calls.Load() != 0 {
		t.Fatalf("calls=%d metrics=%+v", recording.calls.Load(), metrics)
	}
	_ = first.Close()
	_ = second.Close()
}

func TestTCPListenerStopsOnCancellationWithAnIncompleteClient(t *testing.T) {
	listener, err := NewTCPListener(TCPConfig{
		Address:        "127.0.0.1:0",
		TenantID:       "tenant-tcp",
		ListenerID:     "syslog-tcp-test",
		MaxEventBytes:  64,
		FramingMode:    model.FramingOctetCounting,
		IdleTimeout:    time.Minute,
		FrameTimeout:   time.Minute,
		MaxConnections: 1,
	}, &failingTCPAdmission{err: errors.New("unused")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() { serveErr <- listener.Serve(ctx) }()
	connection := dialTCP(t, listener)
	writeTCP(t, connection, []byte("20 partial"))
	waitTCPMetrics(t, listener, func(snapshot TCPMetricsSnapshot) bool { return snapshot.ActiveConnections == 1 })
	cancel()
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("Serve() error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve() did not stop after cancellation")
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

func TestNewTCPListenerValidatesFramingConfiguration(t *testing.T) {
	base := TCPConfig{
		Address:        "127.0.0.1:0",
		TenantID:       "tenant",
		ListenerID:     "listener",
		MaxEventBytes:  64,
		FramingMode:    model.FramingDatagram,
		MaxConnections: 1,
	}
	if _, err := NewTCPListener(base, &failingTCPAdmission{}, nil); !errors.Is(err, ErrTCPUnsupportedFraming) {
		t.Fatalf("NewTCPListener() error = %v", err)
	}
	base.FramingMode = model.FramingOctetCounting
	base.Delimiter = []byte{'\n'}
	if _, err := NewTCPListener(base, &failingTCPAdmission{}, nil); err == nil {
		t.Fatal("NewTCPListener() accepted a delimiter for octet-counting")
	}
}
