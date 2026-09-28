# Event transports and framing

Every accepted frame becomes a distinct occurrence. Transport listeners pass the exact application payload to the durable admission coordinator, which writes raw evidence before inserting the inbox receipt. A listener increments its accepted counter only after both writes succeed.

## UDP Syslog

Configure UDP with a bind address, tenant, listener ID, maximum event bytes, and an optional kernel socket receive-buffer size. Each datagram is one complete frame with `transport=syslog_udp` and `framing.mode=datagram`; the sender IP and source port come from the socket rather than payload headers.

```go
listener, err := ingress.NewUDPListener(ingress.UDPConfig{
    Address:         "127.0.0.1:5514",
    TenantID:        "lab",
    ListenerID:      "syslog-udp-lab",
    SourceProfileID: "lab-network",
    MaxEventBytes:   65536,
    SocketReadBytes: 1 << 20,
}, admission, metrics)
```

Datagrams larger than the configured maximum, kernel-truncated datagrams, and durable-admission failures are rejected and accounted separately. UDP cannot signal success or failure to the sender and does not provide delivery guarantees; accepted metrics mean local raw evidence and inbox metadata are durable. Two byte-identical datagrams still receive different receipt IDs.
