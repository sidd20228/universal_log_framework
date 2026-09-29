# Page dependency map and behavior contracts

## /dashboard/ — Universal event pipeline
Entry: `internal/dashboard/assets/index.html`

```text
internal/dashboard/assets/index.html
├── internal/dashboard/assets/styles.css (link; no imports or external font/assets)
├── internal/dashboard/assets/live.js (first deferred script; exposes global ULPFLive)
│   ├── browser DOM, Canvas 2D, AbortController and timers
│   └── no local imports; CommonJS export exists for testing only
└── internal/dashboard/assets/app.js (second deferred script; IIFE)
    ├── ULPFLive.mount from internal/dashboard/assets/live.js
    ├── browser DOM, Canvas 2D, sessionStorage, fetch and clipboard
    └── no local imports

Serving context:
internal/server/server.go
└── internal/dashboard/handler.go
    └── //go:embed assets/* and fs.Sub("assets")
        ├── internal/dashboard/assets/index.html
        ├── internal/dashboard/assets/styles.css
        ├── internal/dashboard/assets/live.js
        └── internal/dashboard/assets/app.js
```

These are every local UI dependency; no recursive JS/TS imports exist. The Go server has unrelated service dependencies outside this UI task. Existing verification includes `internal/dashboard/handler_test.go` and `internal/dashboard/live_test.cjs`.

## DOM invariants
All IDs below must remain present and unique, even if their containing layout moves. Preserve semantic input/select/button/canvas/table types and native validation.

`sidebarTenant`, `connection`, `connectionForm`, `tenantInput`, `tokenInput`, `disconnectButton`, `connectionDot`, `connectionLabel`, `connectionDetail`, `refreshButton`, `main-content`, `overview`, `pageTitle`, `lastUpdated`, `notice`, `scope`, `scopeTitle`, `scopeSummary`, `environmentFilter`, `instanceFilter`, `nodeGroups`, `totalReceipts`, `receiptHint`, `rawBytes`, `totalRevisions`, `revisionHint`, `healthMetric`, `healthHint`, `pipeline`, `pipelineTitle`, `pipelineDot`, `pipelineState`, `pipelineStages`, `simulation`, `simulationTitle`, `simulationBadge`, `simulationScenario`, `simulationSpeed`, `simulationStart`, `simulationStop`, `simulationAccepted`, `simulationClock`, `simulationMessage`, `liveRateValue`, `liveRateChart`, `liveRateDetail`, `liveQueueValue`, `liveQueueChart`, `liveQueueDetail`, `liveSourceCount`, `liveSourceMix`, `consoleTitle`, `consoleCount`, `consoleFollow`, `consoleClear`, `liveLogFeed`, `consoleState`, `recent`, `eventsTitle`, `eventScope`, `streamState`, `pauseStreamButton`, `eventSearch`, `sourceFamilyFilter`, `formatFilter`, `statusFilter`, `clearFiltersButton`, `sortTimeButton`, `eventsBody`, `eventCount`, `sources`, `sourcesTitle`, `sourceCoverageTotal`, `sourceCoverageSummary`, `sourceCoverage`, `activity`, `activityTitle`, `activityChart`, `chartSummary`, `distributionTitle`, `statusDonut`, `donutTotal`, `statusList`, `pipelineDrawer`, `pipelineDetailTitle`, `closePipelineButton`, `pipelineDetail`, `traceDrawer`, `traceTitle`, `closeTraceButton`, `traceContent`, `drawerScrim`, `announcer`

- `#pipelineStages` contains five `.pipeline-stage` buttons with data-stage values frame/admit/interpret/commit/deliver; each must retain child `b` and `small`. The delegated handler uses `closest('.pipeline-stage')`, updates those children and toggles aria-expanded/status classes.
- `#statusList` must keep four children in parsed / partial / failed / other order, each containing a `strong` count. `#statusDonut` retains nested `#donutTotal`.
- `#streamState.previousElementSibling` must remain the stream status-dot element.
- `#activityChart`, `#liveRateChart`, `#liveQueueChart` must be real canvases. Live chart keyboard controls use left/right/home/end; maintain tabindex and accessible labels.
- `#eventsBody` must remain tbody. Renderer creates tr with data-revision, seven cells, inspect buttons. Filter states and focus restoration rely on row ancestry.
- `#pipelineDrawer`, `#traceDrawer`, `#drawerScrim` visibility is controlled by `.open`; retain aria-hidden, close buttons, focus restoration, Escape and Tab trapping.
- Generated UI classes must remain styled: node-group/node-list/node-card/selected/unavailable/node-empty; source-cell/source-monogram/format-tag/status-pill/parsed/partial/failed/inspect-button/empty-row; source coverage button classes; trace-section/trace-check/trace-card/kv/copy-button/trace-warning/trace-error/trace-loading; pipeline-stage-detail/pipeline-stage-summary/pipeline-stage-metric/pipeline-stage-contract; log-line/log-format/log-status/console-empty.
- JavaScript overwrites className on notice and status dots; new essential styles must be attached to stable IDs/base classes or existing parent classes, not extra transient classes on those elements.
- Preserve connectionForm reportValidity: tenant required pattern `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`, max 128; API token password required min 32/max 512.
- `receiptHint` and `revisionHint` are presentational, but preserve them as source DOM contract. Nav anchors must target existing IDs.

## Complete app DOM bindings
Source: `internal/dashboard/assets/app.js`.

```javascript
  const element = (id) => document.getElementById(id);
  const ui = {
    form: element("connectionForm"), tenant: element("tenantInput"), token: element("tokenInput"),
    disconnect: element("disconnectButton"), refresh: element("refreshButton"),
    pauseStream: element("pauseStreamButton"), streamState: element("streamState"), sortTime: element("sortTimeButton"),
    sourceFamilyFilter: element("sourceFamilyFilter"), formatFilter: element("formatFilter"), statusFilter: element("statusFilter"),
    eventSearch: element("eventSearch"), clearFilters: element("clearFiltersButton"),
    notice: element("notice"), connectionDot: element("connectionDot"), connectionLabel: element("connectionLabel"),
    connectionDetail: element("connectionDetail"), sidebarTenant: element("sidebarTenant"), lastUpdated: element("lastUpdated"),
    totalReceipts: element("totalReceipts"), totalRevisions: element("totalRevisions"), rawBytes: element("rawBytes"),
    healthMetric: element("healthMetric"), healthHint: element("healthHint"), pipelineDot: element("pipelineDot"),
    pipelineState: element("pipelineState"), pipelineStages: element("pipelineStages"), chart: element("activityChart"),
    chartSummary: element("chartSummary"), donut: element("statusDonut"), donutTotal: element("donutTotal"),
    statusList: element("statusList"), eventsBody: element("eventsBody"), eventCount: element("eventCount"), eventScope: element("eventScope"),
    sourceCoverage: element("sourceCoverage"), sourceCoverageTotal: element("sourceCoverageTotal"), sourceCoverageSummary: element("sourceCoverageSummary"),
    environmentFilter: element("environmentFilter"), instanceFilter: element("instanceFilter"),
    scopeSummary: element("scopeSummary"), nodeGroups: element("nodeGroups"),
    pipelineDrawer: element("pipelineDrawer"), pipelineDetail: element("pipelineDetail"),
    closePipeline: element("closePipelineButton"),
    drawer: element("traceDrawer"), traceContent: element("traceContent"),
    closeTrace: element("closeTraceButton"), scrim: element("drawerScrim"), announcer: element("announcer"),
  };
```
