# Contributing

Changes must be linked to a GitHub issue and preserve the invariants in `docs/IMPLEMENTATION_PLAN.md`.

Before opening a change:

```sh
make check
```

Parser or mapping changes must include positive, negative, ambiguous, and malformed fixtures. Any output-changing parser, mapping, schema, connector, or configuration change requires a new immutable version. Never add real secrets, personal data, or proprietary log samples to the repository.

Commit messages should be imperative and include the issue number when applicable, for example `Define durable receipt state machine (#6)`.
