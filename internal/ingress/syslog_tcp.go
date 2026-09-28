package ingress

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/model"
)

const (
	defaultTCPIdleTimeout   = 30 * time.Second
	defaultTCPFrameTimeout  = 5 * time.Second
	defaultTCPConnections   = 128
	maximumTCPDelimiterSize = 64
	maximumOctetCountDigits = 20
)

var (
	ErrTCPUnsupportedFraming = errors.New("unsupported TCP framing mode")
	ErrTCPInvalidOctetCount  = errors.New("invalid TCP octet count")
	ErrTCPFrameTooLarge      = errors.New("TCP frame exceeds configured maximum")
	ErrTCPIncompleteFrame    = errors.New("incomplete TCP frame")
	ErrTCPEmptyFrame         = errors.New("empty TCP frame")
	ErrTCPReadTimeout        = errors.New("TCP frame read timeout")
)

// TCPConfig configures a bounded RFC 6587 syslog listener. Non-transparent
// framing defaults to a single LF delimiter when Delimiter is empty.
type TCPConfig struct {
	Address         string
	TenantID        string
	ListenerID      string
	SourceProfileID string
	MaxEventBytes   int
	FramingMode     model.FramingMode
	Delimiter       []byte
	IdleTimeout     time.Duration
	FrameTimeout    time.Duration
	MaxConnections  int
}

type TCPMetricsSnapshot struct {
	ConnectionsAccepted uint64
	ConnectionsRejected uint64
	ActiveConnections   uint64
	FramesReceived      uint64
	BytesObserved       uint64
	FramesAccepted      uint64
	FramesRejected      uint64
	InvalidFrames       uint64
	OversizeFrames      uint64
	IncompleteFrames    uint64
	ReadTimeouts        uint64
	AdmissionFailures   uint64
	AcceptErrors        uint64
}

type TCPMetrics struct {
	connectionsAccepted atomic.Uint64
	connectionsRejected atomic.Uint64
	activeConnections   atomic.Int64
	framesReceived      atomic.Uint64
	bytesObserved       atomic.Uint64
	framesAccepted      atomic.Uint64
	framesRejected      atomic.Uint64
	invalidFrames       atomic.Uint64
	oversizeFrames      atomic.Uint64
	incompleteFrames    atomic.Uint64
	readTimeouts        atomic.Uint64
	admissionFailures   atomic.Uint64
	acceptErrors        atomic.Uint64
}

func (metrics *TCPMetrics) Snapshot() TCPMetricsSnapshot {
	if metrics == nil {
		return TCPMetricsSnapshot{}
	}
	active := metrics.activeConnections.Load()
	if active < 0 {
		active = 0
	}
	return TCPMetricsSnapshot{
		ConnectionsAccepted: metrics.connectionsAccepted.Load(),
		ConnectionsRejected: metrics.connectionsRejected.Load(),
		ActiveConnections:   uint64(active),
		FramesReceived:      metrics.framesReceived.Load(),
		BytesObserved:       metrics.bytesObserved.Load(),
		FramesAccepted:      metrics.framesAccepted.Load(),
		FramesRejected:      metrics.framesRejected.Load(),
		InvalidFrames:       metrics.invalidFrames.Load(),
		OversizeFrames:      metrics.oversizeFrames.Load(),
		IncompleteFrames:    metrics.incompleteFrames.Load(),
		ReadTimeouts:        metrics.readTimeouts.Load(),
		AdmissionFailures:   metrics.admissionFailures.Load(),
		AcceptErrors:        metrics.acceptErrors.Load(),
	}
}

type TCPListener struct {
	config    TCPConfig
	admission Admission
	listener  *net.TCPListener
	metrics   *TCPMetrics
	serveOnce atomic.Bool
	closeOnce sync.Once

	mu          sync.Mutex
	closed      bool
	connections map[*net.TCPConn]struct{}
	connectionQ chan struct{}
	wait        sync.WaitGroup
}

func NewTCPListener(config TCPConfig, admission Admission, metrics *TCPMetrics) (*TCPListener, error) {
	if admission == nil {
		return nil, errors.New("TCP admission coordinator is required")
	}
	if strings.TrimSpace(config.Address) == "" || strings.TrimSpace(config.TenantID) == "" || strings.TrimSpace(config.ListenerID) == "" {
		return nil, errors.New("TCP address, tenant id, and listener id are required")
	}
	if config.MaxEventBytes < 1 {
		return nil, errors.New("TCP maximum event size must be positive")
	}
	if config.FramingMode != model.FramingOctetCounting && config.FramingMode != model.FramingNonTransparent {
		return nil, ErrTCPUnsupportedFraming
	}
	if config.IdleTimeout < 0 || config.FrameTimeout < 0 {
		return nil, errors.New("TCP idle and frame timeouts cannot be negative")
	}
	if config.IdleTimeout == 0 {
		config.IdleTimeout = defaultTCPIdleTimeout
	}
	if config.FrameTimeout == 0 {
		config.FrameTimeout = defaultTCPFrameTimeout
	}
	if config.MaxConnections < 0 {
		return nil, errors.New("TCP maximum connections cannot be negative")
	}
	if config.MaxConnections == 0 {
		config.MaxConnections = defaultTCPConnections
	}
	if config.FramingMode == model.FramingOctetCounting {
		if len(config.Delimiter) != 0 {
			return nil, errors.New("TCP delimiter is only valid for non-transparent framing")
		}
	} else {
		if len(config.Delimiter) == 0 {
			config.Delimiter = []byte{'\n'}
		}
		if len(config.Delimiter) > maximumTCPDelimiterSize {
			return nil, fmt.Errorf("TCP delimiter must not exceed %d bytes", maximumTCPDelimiterSize)
		}
		config.Delimiter = bytes.Clone(config.Delimiter)
	}

	address, err := net.ResolveTCPAddr("tcp", config.Address)
	if err != nil {
		return nil, fmt.Errorf("resolve TCP listener address: %w", err)
	}
	networkListener, err := net.ListenTCP("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("listen for TCP syslog: %w", err)
	}
	if metrics == nil {
		metrics = &TCPMetrics{}
	}
	return &TCPListener{
		config:      config,
		admission:   admission,
		listener:    networkListener,
		metrics:     metrics,
		connections: make(map[*net.TCPConn]struct{}),
		connectionQ: make(chan struct{}, config.MaxConnections),
	}, nil
}

func (listener *TCPListener) Addr() net.Addr {
	if listener == nil || listener.listener == nil {
		return nil
	}
	return listener.listener.Addr()
}

func (listener *TCPListener) Metrics() TCPMetricsSnapshot {
	if listener == nil {
		return TCPMetricsSnapshot{}
	}
	return listener.metrics.Snapshot()
}

func (listener *TCPListener) Serve(ctx context.Context) error {
	if listener == nil || listener.listener == nil {
		return errors.New("TCP listener is required")
	}
	if !listener.serveOnce.CompareAndSwap(false, true) {
		return errors.New("TCP listener can only be served once")
	}
	if ctx.Err() != nil {
		_ = listener.Close()
		return nil
	}
	stopCancellation := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-stopCancellation:
		}
	}()
	defer close(stopCancellation)
	defer listener.wait.Wait()

	for {
		connection, err := listener.listener.AcceptTCP()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || listener.isClosed() {
				return nil
			}
			listener.metrics.acceptErrors.Add(1)
			return fmt.Errorf("accept TCP syslog connection: %w", err)
		}
		select {
		case listener.connectionQ <- struct{}{}:
		default:
			listener.metrics.connectionsRejected.Add(1)
			_ = connection.Close()
			continue
		}
		if !listener.register(connection) {
			<-listener.connectionQ
			_ = connection.Close()
			return nil
		}
		listener.metrics.connectionsAccepted.Add(1)
		listener.metrics.activeConnections.Add(1)
		listener.wait.Add(1)
		go listener.serveConnection(ctx, connection)
	}
}

func (listener *TCPListener) serveConnection(ctx context.Context, connection *net.TCPConn) {
	defer listener.wait.Done()
	defer func() {
		listener.unregister(connection)
		listener.metrics.activeConnections.Add(-1)
		<-listener.connectionQ
		_ = connection.Close()
	}()

	reader := bufio.NewReader(connection)
	for {
		if err := connection.SetReadDeadline(time.Now().Add(listener.config.IdleTimeout)); err != nil {
			return
		}
		started := false
		frame, err := readTCPFrame(reader, listener.config.FramingMode, listener.config.Delimiter, listener.config.MaxEventBytes, func() error {
			started = true
			return connection.SetReadDeadline(time.Now().Add(listener.config.FrameTimeout))
		})
		if err != nil {
			if errors.Is(err, io.EOF) && !started {
				return
			}
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			listener.recordFrameError(err, started)
			return
		}

		listener.metrics.framesReceived.Add(1)
		listener.metrics.bytesObserved.Add(uint64(len(frame)))
		_, err = listener.admission.Admit(ctx, AdmissionRequest{
			Payload:         bytes.NewReader(frame),
			TenantID:        listener.config.TenantID,
			ListenerID:      listener.config.ListenerID,
			SourceProfileID: listener.config.SourceProfileID,
			Peer:            tcpPeer(connection.RemoteAddr()),
			Transport:       model.TransportSyslogTCP,
			FramingMode:     listener.config.FramingMode,
		})
		if err != nil {
			listener.metrics.framesRejected.Add(1)
			listener.metrics.admissionFailures.Add(1)
			return
		}
		listener.metrics.framesAccepted.Add(1)
	}
}

func (listener *TCPListener) recordFrameError(err error, started bool) {
	if started {
		listener.metrics.framesRejected.Add(1)
	}
	switch {
	case errors.Is(err, ErrTCPFrameTooLarge):
		listener.metrics.oversizeFrames.Add(1)
	case errors.Is(err, ErrTCPReadTimeout):
		listener.metrics.readTimeouts.Add(1)
		if started {
			listener.metrics.incompleteFrames.Add(1)
		}
	case errors.Is(err, ErrTCPIncompleteFrame):
		listener.metrics.incompleteFrames.Add(1)
	default:
		listener.metrics.invalidFrames.Add(1)
	}
}

func (listener *TCPListener) register(connection *net.TCPConn) bool {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	if listener.closed {
		return false
	}
	listener.connections[connection] = struct{}{}
	return true
}

func (listener *TCPListener) unregister(connection *net.TCPConn) {
	listener.mu.Lock()
	delete(listener.connections, connection)
	listener.mu.Unlock()
}

func (listener *TCPListener) isClosed() bool {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	return listener.closed
}

func (listener *TCPListener) Close() error {
	if listener == nil || listener.listener == nil {
		return nil
	}
	var closeErr error
	listener.closeOnce.Do(func() {
		listener.mu.Lock()
		listener.closed = true
		connections := make([]*net.TCPConn, 0, len(listener.connections))
		for connection := range listener.connections {
			connections = append(connections, connection)
		}
		listener.mu.Unlock()
		closeErr = listener.listener.Close()
		for _, connection := range connections {
			_ = connection.Close()
		}
	})
	return closeErr
}

func readTCPFrame(reader *bufio.Reader, mode model.FramingMode, delimiter []byte, maximum int, onStart func() error) ([]byte, error) {
	if maximum < 1 {
		return nil, ErrTCPFrameTooLarge
	}
	first, err := reader.ReadByte()
	if err != nil {
		return nil, classifyTCPReadError(err, false)
	}
	if onStart != nil {
		if err := onStart(); err != nil {
			return nil, err
		}
	}
	switch mode {
	case model.FramingOctetCounting:
		return readOctetCountedFrame(reader, first, maximum)
	case model.FramingNonTransparent:
		return readDelimitedFrame(reader, first, delimiter, maximum)
	default:
		return nil, ErrTCPUnsupportedFraming
	}
}

func readOctetCountedFrame(reader *bufio.Reader, first byte, maximum int) ([]byte, error) {
	if first < '1' || first > '9' {
		return nil, ErrTCPInvalidOctetCount
	}
	digits := []byte{first}
	for {
		character, err := reader.ReadByte()
		if err != nil {
			return nil, classifyTCPReadError(err, true)
		}
		if character == ' ' {
			break
		}
		if character < '0' || character > '9' || len(digits) >= maximumOctetCountDigits {
			return nil, ErrTCPInvalidOctetCount
		}
		digits = append(digits, character)
	}
	count, err := strconv.ParseUint(string(digits), 10, 64)
	if err != nil {
		return nil, ErrTCPInvalidOctetCount
	}
	if count == 0 {
		return nil, ErrTCPEmptyFrame
	}
	if count > uint64(maximum) {
		return nil, ErrTCPFrameTooLarge
	}
	frame := make([]byte, int(count))
	if _, err := io.ReadFull(reader, frame); err != nil {
		return nil, classifyTCPReadError(err, true)
	}
	return frame, nil
}

func readDelimitedFrame(reader *bufio.Reader, first byte, delimiter []byte, maximum int) ([]byte, error) {
	if len(delimiter) == 0 {
		return nil, ErrTCPUnsupportedFraming
	}
	buffer := make([]byte, 0, min(maximum, 4096))
	buffer = append(buffer, first)
	for {
		if bytes.HasSuffix(buffer, delimiter) {
			frame := buffer[:len(buffer)-len(delimiter)]
			if len(frame) == 0 {
				return nil, ErrTCPEmptyFrame
			}
			if len(frame) > maximum {
				return nil, ErrTCPFrameTooLarge
			}
			return bytes.Clone(frame), nil
		}
		if len(buffer) > maximum && len(buffer)-maximum > len(delimiter)-1 {
			return nil, ErrTCPFrameTooLarge
		}
		character, err := reader.ReadByte()
		if err != nil {
			return nil, classifyTCPReadError(err, true)
		}
		buffer = append(buffer, character)
	}
}

func classifyTCPReadError(err error, started bool) error {
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return fmt.Errorf("%w: %v", ErrTCPReadTimeout, err)
	}
	if !started && errors.Is(err, io.EOF) {
		return io.EOF
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("%w: %v", ErrTCPIncompleteFrame, err)
	}
	return err
}

func tcpPeer(address net.Addr) *model.Peer {
	peer, ok := address.(*net.TCPAddr)
	if !ok || !peer.AddrPort().Addr().IsValid() {
		return nil
	}
	return &model.Peer{IP: peer.AddrPort().Addr(), Port: peer.AddrPort().Port()}
}
