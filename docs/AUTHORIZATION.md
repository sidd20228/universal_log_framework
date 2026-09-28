# Scoped token authorization

The MVP uses high-entropy static bearer tokens with explicit scopes and tenant grants. ULPF stores only each token's SHA-256 digest in the active authorization snapshot and compares presented credentials in constant time. Token values must contain 32–512 visible ASCII characters. Configuration, logs, errors, metrics, and audit records must never include a plaintext token.

Scopes do not imply one another:

| Scope | Permission |
|---|---|
| `events:write` | Submit events |
| `events:read` | Read receipt and normalized-event metadata |
| `raw:read` | Retrieve exact raw evidence after tenant authorization and audit |
| `replay:write` | Request reprocessing or connector replay |
| `config:read` | Read parser, schema, and source-profile metadata |
| `config:write` | Validate or install configuration and bundles |
| `config:approve` | Activate a validated source-profile revision |
| `ops:read` | Read pipeline and connector status |

`events:read` never grants `raw:read`. Raw retrieval must look up the receipt tenant, authorize that tenant, and append an audit record containing the actor, reason, receipt ID, and time before streaming bytes.

Example construction for a development process:

```go
authorizer, err := auth.New([]auth.TokenConfig{
    {
        ID:      "lab-sender",
        Actor:   "lab-relay",
        Secret:  os.Getenv("ULPF_LAB_SENDER_TOKEN"),
        Scopes:  []auth.Scope{auth.ScopeEventsWrite},
        Tenants: []string{"lab"},
    },
})
```

Use separate tokens for senders, analysts, forensic raw access, and operators. The static-token MVP is intended for loopback or private-network use with TLS on non-local links. Production deployments should replace it with reviewed mTLS/OIDC identity and centralized policy.
