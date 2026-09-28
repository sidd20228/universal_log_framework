package ingress

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sidd20228/universal_log_framework/internal/model"
)

const MaxUDPEventBytes = 65_536

type UDPConfig struct {
	Address         string
	TenantID        string
	ListenerID      string
	SourceProfileID string
	MaxEventBytes   int
	SocketReadBytes int
}

type UDPMetricsSnapshot struct {
	DatagramsReceived  uint64
	BytesObserved      uint64
	DatagramsAccepted  uint64
	DatagramsRejected  uint64
	DatagramsDropped   uint64
	OversizeDatagrams  uint64
	TruncatedDatagrams uint64
	AdmissionFailures  uint64
	ReadErrors         uint64
}

type UDPMetrics struct {
	datagramsReceived  atomic.Uint64
	bytesObserved      atomic.Uint64
	datagramsAccepted  atomic.Uint64
	datagramsRejected  atomic.Uint64
	datagramsDropped   atomic.Uint64
	oversizeDatagrams  atomic.Uint64
	truncatedDatagrams atomic.Uint64
	admissionFailures  atomic.Uint64
	readErrors         atomic.Uint64
}

func (metrics *UDPMetrics) Snapshot() UDPMetricsSnapshot {
	if metrics == nil {
		return UDPMetricsSnapshot{}
	}
	return UDPMetricsSnapshot{
		DatagramsReceived:  metrics.datagramsReceived.Load(),
		BytesObserved:      metrics.bytesObserved.Load(),
		DatagramsAccepted:  metrics.datagramsAccepted.Load(),
		DatagramsRejected:  metrics.datagramsRejected.Load(),
		DatagramsDropped:   metrics.datagramsDropped.Load(),
		OversizeDatagrams:  metrics.oversizeDatagrams.Load(),
		TruncatedDatagrams: metrics.truncatedDatagrams.Load(),
		AdmissionFailures:  metrics.admissionFailures.Load(),
		ReadErrors:         metrics.readErrors.Load(),
	}
}

type UDPListener struct {
	config     UDPConfig
	admission  Admission
	connection *net.UDPConn
	metrics    *UDPMetrics
	serveOnce  atomic.Bool
	closeOnce  sync.Once
}

func NewUDPListener(config UDPConfig, admission Admission, metrics *UDPMetrics) (*UDPListener, error) {
	if admission == nil {
		return nil, errors.New("UDP admission coordinator is required")
	}
	if strings.TrimSpace(config.Address) == "" || strings.TrimSpace(config.TenantID) == "" || strings.TrimSpace(config.ListenerID) == "" {
		return nil, errors.New("UDP address, tenant id, and listener id are required")
	}
	if config.MaxEventBytes < 1 || config.MaxEventBytes > MaxUDPEventBytes {
		return nil, fmt.Errorf("UDP maximum event size must be between 1 and %d", MaxUDPEventBytes)
	}
	address, err := net.ResolveUDPAddr("udp", config.Address)
	if err != nil {
		return nil, fmt.Errorf("resolve UDP listener address: %w", err)
	}
	connection, err := net.ListenUDP("udp", address)
	if err != nil {
		return nil, fmt.Errorf("listen for UDP syslog: %w", err)
	}
	if config.SocketReadBytes > 0 {
		if err := connection.SetReadBuffer(config.SocketReadBytes); err != nil {
			connection.Close()
			return nil, fmt.Errorf("set UDP socket read buffer: %w", err)
		}
	}
	if metrics == nil {
		metrics = &UDPMetrics{}
	}
	return &UDPListener{
		config:     config,
		admission:  admission,
		connection: connection,
		metrics:    metrics,
	}, nil
}

func (listener *UDPListener) Addr() net.Addr {
	if listener == nil || listener.connection == nil {
		return nil
	}
	return listener.connection.LocalAddr()
}

func (listener *UDPListener) Metrics() UDPMetricsSnapshot {
	if listener == nil {
		return UDPMetricsSnapshot{}
	}
	return listener.metrics.Snapshot()
}

func (listener *UDPListener) Serve(ctx context.Context) error {
	if listener == nil || listener.connection == nil {
		return errors.New("UDP listener is required")
	}
	if !listener.serveOnce.CompareAndSwap(false, true) {
		return errors.New("UDP listener can only be served once")
	}
	if err := ctx.Err(); err != nil {
		listener.Close()
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

	buffer := make([]byte, listener.config.MaxEventBytes+1)
	for {
		count, _, flags, peer, err := listener.connection.ReadMsgUDP(buffer, nil)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			listener.metrics.readErrors.Add(1)
			return fmt.Errorf("read UDP syslog datagram: %w", err)
		}
		listener.metrics.datagramsReceived.Add(1)
		listener.metrics.bytesObserved.Add(uint64(count))
		truncated := datagramWasTruncated(flags)
		oversize := count > listener.config.MaxEventBytes
		if truncated || oversize {
			listener.metrics.datagramsRejected.Add(1)
			listener.metrics.datagramsDropped.Add(1)
			if oversize {
				listener.metrics.oversizeDatagrams.Add(1)
			}
			if truncated {
				listener.metrics.truncatedDatagrams.Add(1)
			}
			continue
		}
		payload := bytes.Clone(buffer[:count])
		_, err = listener.admission.Admit(ctx, AdmissionRequest{
			Payload:         bytes.NewReader(payload),
			TenantID:        listener.config.TenantID,
			ListenerID:      listener.config.ListenerID,
			SourceProfileID: listener.config.SourceProfileID,
			Peer: &model.Peer{
				IP:   peer.AddrPort().Addr(),
				Port: peer.AddrPort().Port(),
			},
			Transport:   model.TransportSyslogUDP,
			FramingMode: model.FramingDatagram,
		})
		if err != nil {
			listener.metrics.datagramsRejected.Add(1)
			listener.metrics.datagramsDropped.Add(1)
			listener.metrics.admissionFailures.Add(1)
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		listener.metrics.datagramsAccepted.Add(1)
	}
}

func (listener *UDPListener) Close() error {
	if listener == nil || listener.connection == nil {
		return nil
	}
	var closeErr error
	listener.closeOnce.Do(func() {
		closeErr = listener.connection.Close()
	})
	return closeErr
}
