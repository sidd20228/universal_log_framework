# Security and fuzz testing

ULPF treats transport bytes, parser input, bundle metadata, and bearer credentials as untrusted. The deterministic security corpus exercises parser limits, malformed encodings, delimiter and escape handling, XML DTD rejection, duplicate fields, path traversal, symbolic links, authorization boundaries, and ingress oversize handling.

Run the bounded corpus used by CI with:

```sh
make security-smoke
```

Go runs every `Fuzz...` seed once during this command. The seeds are small synthetic inputs maintained in this repository. A discovered fuzz failure must be minimized and retained as a seed or deterministic regression before the defect is closed.

Mutation-based fuzzing is opt-in because its useful run time is workload dependent. Run every target for ten seconds with:

```sh
make fuzz
```

Set `FUZZTIME` to a Go duration to change the per-target budget:

```sh
make fuzz FUZZTIME=1m
```

The target list lives in `scripts/run-fuzz.sh`. Each target runs in a separate `go test` process so Go can select exactly one fuzz function. The current corpus covers TCP framing, Syslog headers, CEF/LEEF escaping, bounded JSON/XML/KV parsing, declarative RE2 configuration and matching, bundle manifests and paths, bearer-token parsing, and scope isolation. Parser fuzzing uses strict byte, field, depth, and token limits and checks deterministic results, immutable input, bounded output collections, and valid issue offsets.

Fuzzing provides evidence for the exercised inputs and duration only. It does not establish universal parser safety or performance bounds.
