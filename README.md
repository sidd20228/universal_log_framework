# Universal Log Pre-processing Framework

ULPF is an offline-first framework for accepting perimeter-device events, preserving the exact received bytes, and producing deterministic, versioned security-event interpretations. Unknown and malformed events remain recoverable.

The project is under active implementation. The [implementation plan](docs/IMPLEMENTATION_PLAN.md) defines the scope, architecture, acceptance boundary, and 40-task backlog. GitHub issues are the source of truth for delivery status.

## Design commitments

- Durable acceptance happens before parsing or normalization.
- Exact received bytes and occurrence identity are retained independently of parser success.
- OCSF 1.9.0 supplies the normalized security vocabulary inside a ULPF evidence envelope.
- Deterministic built-in parsers and declarative bundles run without cloud services or mandatory AI.
- Unsupported semantics remain explicit instead of being guessed.
- The MVP is a Go modular monolith with replaceable storage and delivery adapters.

## Local development

Prerequisites: the Go version declared in `go.mod`, GNU Make, and Git.

```sh
make check
make build
./bin/ulpf version
```

Configuration and runnable deployment instructions will be added as their tracked issues land. Do not use this repository as a production collector until the security, failure-recovery, and benchmark gates in the implementation plan are complete.

Parser syntax, limits, preserved fields, and format references are documented in [Built-in syntax parsers](docs/PARSERS.md).
The MVP permission model and scope matrix are documented in [Scoped token authorization](docs/AUTHORIZATION.md).
Listener framing and transport durability behavior are documented in [Event transports and framing](docs/TRANSPORTS.md).

## Project status

- [Day 7 Vertical Slice milestone](https://github.com/sidd20228/universal_log_framework/milestone/1)
- [Day 14 Robust Prototype milestone](https://github.com/sidd20228/universal_log_framework/milestone/2)
- [Open implementation issues](https://github.com/sidd20228/universal_log_framework/issues)

## License

Licensed under the Apache License 2.0. See `LICENSE`.
