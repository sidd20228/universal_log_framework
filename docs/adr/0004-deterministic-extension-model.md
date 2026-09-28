# ADR 0004: Use deterministic, versioned extensions

- **Status:** Accepted
- **Date:** 2026-09-29
- **Decision owners:** ULPF maintainers

## Context

New sources, formats, mappings, enrichments, and destinations must be added without rewriting the engine. Extensions process attacker-controlled data and can affect trusted semantics, so arbitrary runtime code or probabilistic interpretation in the ingestion path would weaken isolation, repeatability, and auditability.

## Decision

Use two extension tiers:

1. Declarative parser bundles are the hot-installable path for source onboarding. A bundle contains an immutable manifest, compatibility range, fingerprints, bounded extraction rules, explicit semantic mappings, taxonomy tables, schemas, and golden fixtures.
2. Capabilities that require code are compiled into a reviewed release behind narrow parser, enricher, or connector interfaces. The MVP does not load arbitrary shared libraries, scripts, WebAssembly modules, or remote code at runtime.

Every bundle and compiled extension has a stable identifier, semantic version, content digest, compatibility declaration, and validation corpus. Activation is atomic: validation happens before registration, and the last known good registry remains active on failure. Production distribution requires signature-policy enforcement; the MVP records digests and remains signature-ready.

Parser selection is deterministic. It combines source-profile eligibility, hard syntax signatures, structural probes, and versioned fingerprints. A parser must clear a configured score threshold and margin. Ambiguous selection produces `UNPARSED` with candidate evidence rather than choosing a winner silently.

Extraction uses bounded parsers and RE2-compatible regular expressions. Mapping rules perform explicit typed conversions and retain failures as issues plus unmapped source values. Generative models may assist bundle authoring offline, but generated rules receive the same review and fixtures and never execute as trusted inference in the event path.

## Consequences

- The same bytes, configuration, bundle digests, and pipeline version produce the same interpretation.
- Source onboarding can usually occur without engine changes.
- Bundle authors must supply compatibility evidence and golden fixtures, increasing review work but preventing unsupported semantic claims.
- Some complex formats require a compiled release instead of immediate runtime installation.
- Registry, archive, path, size, regex, schema, and signature handling become explicit security surfaces with dedicated tests.

## Alternatives considered

- **Arbitrary runtime plugins:** rejected because crashes, dependency conflicts, privilege, and supply-chain risk enter the main process.
- **LLM parsing in the critical path:** rejected because results are not sufficiently deterministic, offline, or auditable for trusted normalization.
- **First-match parser selection:** rejected because registry order would silently change semantics.
- **Regex-only parsing:** rejected because nested and escaped formats require structural parsers and strict resource limits.
