# Ingress configuration

ULPF admits a message only after the exact application bytes have been written
to evidence storage and its receipt has been committed to the inbox. TCP stream
boundaries are resolved before admission. A TCP connection closing does not
acknowledge durable receipt to the sender.

## TCP syslog

`ingress.TCPConfig` selects one framing mode for each listener:

- `model.FramingOctetCounting` accepts RFC 6587-style `MSG-LEN SP MSG`
  frames. The decimal count is the number of message octets. The count prefix
  and separating space are transport framing and are not stored.
- `model.FramingNonTransparent` accepts messages terminated by the configured
  byte delimiter. `Delimiter` defaults to LF (`0x0a`) and may contain up to 64
  bytes. The delimiter is not stored. A delimiter within a sender's message
  ends that frame and begins another, so deployments should prefer octet
  counting when message content can contain the delimiter.

Both modes preserve message bytes without UTF-8 conversion. Empty, malformed,
incomplete, and oversized frames are rejected before admission. After a frame
or admission error, ULPF closes the connection because the remaining stream
position cannot be trusted as a new frame boundary.

`IdleTimeout` limits the wait for the first byte of each frame. Once the first
byte arrives, `FrameTimeout` sets a fixed deadline for the complete frame; slow
clients cannot extend it by sending occasional bytes. `MaxEventBytes` bounds
each decoded message, and `MaxConnections` bounds concurrently handled TCP
connections. Zero timeout and connection values select the safe package
defaults. Negative values are invalid.

```go
listener, err := ingress.NewTCPListener(ingress.TCPConfig{
    Address:         "127.0.0.1:6514",
    TenantID:        "tenant-a",
    ListenerID:      "edge-syslog-tcp",
    SourceProfileID: "edge-router",
    MaxEventBytes:   64 * 1024,
    FramingMode:     model.FramingOctetCounting,
    IdleTimeout:     30 * time.Second,
    FrameTimeout:    5 * time.Second,
    MaxConnections:  128,
}, coordinator, nil)
```

For newline-delimited input, set `FramingMode` to
`model.FramingNonTransparent` and leave `Delimiter` empty. For a CRLF listener,
set `Delimiter: []byte("\r\n")`.

`TCPListener.Metrics()` reports connection admission pressure, completed and
durably accepted frames, rejected frames, observed application bytes,
malformed and oversized input, incomplete frames, read timeouts, and admission
failures. These counters describe what the local listener observed; they do not
claim that a sender received an application acknowledgment.
