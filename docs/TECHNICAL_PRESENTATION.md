# Technical presentation

The editable five-slide presentation is available in two forms:

- [Google Slides](https://docs.google.com/presentation/d/1jQlhbg6NUcOX7O5pVkbicD6g1OhT7vAYktjHsXM8fno/edit)
- [`output/presentation/ULPF-Technical-Presentation.pptx`](../output/presentation/ULPF-Technical-Presentation.pptx)

All diagrams, labels, and shapes are native editable slide objects. The deck uses a 16:9 layout, Arial typography, a navy/teal palette, and no external images.

## Slide 1 — Universal Log Pre-processing Framework

**On slide:** Lossless event handling for heterogeneous perimeter devices.

**Talk track:** ULPF accepts heterogeneous perimeter-device logs while preserving the exact evidence used to produce every normalized revision. The implementation is a runnable prototype with bounded parsers, durable admission, authenticated retrieval, and tested failure recovery.

## Slide 2 — What universal means

**On slide:** Shared contracts cover transport, evidence, processing, and export. Ingestion and bounded parsing are reusable; semantic mappings remain source-specific.

**Talk track:** “Universal” describes the framework contracts, not a claim that arbitrary proprietary syntax can be interpreted without source knowledge. New sources need fixtures, detection rules, and reviewed mappings while retaining the same evidence and processing envelope.

## Slide 3 — Durable event flow

**On slide:** Frame, admit, interpret, commit, and deliver over a durable rail.

**Talk track:** The HTTP listener acknowledges with 202 only after the raw bytes and receipt state are durable. Workers then detect, parse, map, and commit an immutable revision. Delivery state remains independent per sink, so one failing destination does not destroy evidence or block replay elsewhere.

## Slide 4 — Lossless revisions and controlled failure

**On slide:** The envelope contains receipt context, a content-addressed raw reference, processing identity, canonical fields, preserved source material, and lineage.

**Talk track:** Reprocessing creates a new revision over the same raw evidence. Expired leases make interrupted work recoverable. Retry and dead-letter state are sink-specific. Tenant and scope checks protect event query and raw-evidence retrieval separately.

## Slide 5 — Prototype evidence and production boundary

**On slide:** Tests cover schemas, corpora, races, fuzzing, fault injection, transports, outputs, Compose, and offline packaging. The demo admits, inspects, queries, and replays an event.

**Talk track:** The repository contains reproducible verification evidence. Performance results describe the measured host and configuration only; production sizing still requires measurements using representative partitions, replicas, storage, traffic, and source distributions.

## Presenter checklist

1. Run the two-minute demo from `docs/DEMO_SCRIPT.md` before presenting.
2. Keep the architecture brief available for implementation details.
3. State the Docker-daemon validation status from the current evaluation report.
4. Avoid extrapolating the single-host benchmark to production scale.
