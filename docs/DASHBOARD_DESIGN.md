# Green dashboard design and verification

The selected specification is [dashboard-green-concept.png](assets/dashboard-green-concept.png).
The reference and generated draft are on the
[Superdesign board](https://superdesign.dev/teams/2716b7b6-f924-4d85-9656-dd6812a94e8f/projects/91842f85-8513-4984-b540-2106b5aae839).
Issue: [#58](https://github.com/sidd20228/universal_log_framework/issues/58).

## Visual comparison

The concept was inspected with `view_image`, and the running implementation
was compared using Chrome screenshots through the Browser tool at a requested
1469 × 1069 viewport and a 390 × 844 mobile viewport. Browser scrollbars reduce
the available content width. These are visual checks, not an automated pixel-diff
or a claim that live data can reproduce the concept's illustrative values.

| Area | Implementation and comparison |
| --- | --- |
| Shell | 220px white sidebar, cool off-white canvas, 16px gutter; removed the old enclosing white frame. |
| Typography | Self-hosted DM Sans; 32px desktop headline, 36px metric values, 17px panel titles; strong hierarchy and small utility text. |
| Metrics | Four equally sized cards; first forest green, remaining white; live readiness and durable-storage values. |
| Main row | Wide rate chart beside dark forest simulation panel; adjusted excess vertical space and added the circular countdown. |
| Analysis row | Source bars, backlog chart, and a larger status ring with counts and percentages in three aligned panels. |
| Pipeline | Compact horizontal strip with mint circular icons, connectors, actual counts, and working detail panes. |
| Event table | Full-width compact rows with filters in the desktop header; horizontally scrollable table on small screens. |
| Motion | Short entrances, real counter changes, new-row highlights, chart reveals, countdown arc, and drawer transitions; reduced-motion support. |

The concept's main title, subtitle, navigation labels, chart titles, four metric
labels, and simulation actions are retained. Functional differences from the
illustration are explicit:

- Metrics, chart shapes, status proportions, sources, and table rows come from
  live service data. Inactive queues correctly remain flat at zero.
- The countdown is **03:00**, matching the actual bounded session limit.
- Existing event metadata columns (format, transport, status, action, inspect)
  remain. The summary API does not supply the concept's host/message/level
  columns. Search and filters describe the fields actually available.
- Readiness, storage, partial parsing, and current-window labels describe their
  real meaning. Source percentages refer to the current 20-event window.
- The top bar retains the functional refresh and connection controls. The
  illustration's account/avatar and notification features are not implemented.
- Source initials identify real sample names; the SVG brand and outline icons
  follow the concept's visual style. Source family detail remains visible on
  smaller layouts and is available through filters at desktop sizes.
- The incoming synthetic-input console, runtime-origin selectors, historical
  throughput, and source coverage remain below the primary screen because they
  are existing requested capabilities.

## Interaction checks

Chrome checks exercised real HTTP ingestion using the enterprise scenario,
actual receipt growth, the countdown, and live source diversity. Also checked:

- Top search filters the table and stays synchronized with table search.
- Event inspection opens receipt, SHA-256 evidence metadata, parser, canonical
  envelope and provenance information; Escape closes it.
- Pipeline stage buttons open stage counts and processing contracts.
- `/` cannot move focus behind an open detail pane; Escape restores focus.
- Pause stops both polling and simulation; resuming restores polling.
- Connection editing stays open across background polls.
- Mobile layout has no document-level horizontal overflow and the connection
  form, simulator, and event inspector remain usable.
- Browser console reports no application warnings or errors.

The review also restored wrapping for multi-instance runtime-origin lists.
The previous thick card accent was removed, Inter was replaced with DM Sans,
and the type hierarchy was strengthened; no new design-hook suppression was
added for this redesign.

## Verification and local constraint

`make test-dashboard` validates JavaScript syntax and 12 simulation/telemetry
behavior cases. Embedded-asset tests cover the font and license, including
`font/ttf` on minimal Linux images. `make fmt vet` checks Go formatting and vet.

The native full Go run encountered the Mac's storage high-watermark guard
(96% occupied, default guard 95%). Dashboard-specific tests passed locally;
the full Go suite passed inside Docker with the same source and test fixtures.
The guard was not weakened. Both ULPF and ClickHouse containers were healthy.

See [DASHBOARD.md](DASHBOARD.md) for operating instructions and data semantics.
