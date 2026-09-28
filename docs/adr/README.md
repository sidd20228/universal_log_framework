# Architecture Decision Records

Architecture Decision Records (ADRs) capture decisions that constrain the Universal Log Pre-processing Framework. They complement the [implementation plan](../IMPLEMENTATION_PLAN.md); the plan defines delivery scope, while these records explain why the core architecture takes its chosen shape.

## Status vocabulary

- **Proposed:** under review and not yet binding.
- **Accepted:** binding for implementation unless superseded.
- **Superseded:** retained for history but replaced by a later ADR.
- **Deprecated:** no longer recommended, with migration handled separately.

## Index

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-durable-acceptance-boundary.md) | Define the durable acceptance boundary | Accepted |
| [0002](0002-modular-monolith.md) | Build the MVP as a modular monolith | Accepted |
| [0003](0003-canonical-ocsf-envelope.md) | Use a ULPF evidence envelope with an OCSF 1.9.0 projection | Accepted |
| [0004](0004-deterministic-extension-model.md) | Use deterministic, versioned extensions | Accepted |
| [0005](0005-production-adapter-evolution.md) | Evolve to production by replacing adapters and extracting processes | Accepted |

## Recording new decisions

Use the next four-digit number. State the context, decision, consequences, and alternatives. A decision that changes an accepted ADR must add a new record and mark the earlier record as superseded rather than rewriting its history.
