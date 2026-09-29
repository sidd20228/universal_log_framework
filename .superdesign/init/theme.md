# Theme — original-source snapshot

## Part 1 — compact tokens
These are the existing implementation values, not the final redesign mandate. User direction is white/green, generous rounded surfaces inspired by Donezo; the prior navy/teal palette is expected to change.

| Token | Value |
| --- | --- |
| --navy | #071426 |
| --navy-2 | #0c1d32 |
| --ink | #172436 |
| --muted | #69788b |
| --line | #dce4eb |
| --line-strong | #c9d4de |
| --surface | #ffffff |
| --canvas | #f4f7f9 |
| --teal | #0b8f82 |
| --teal-dark | #087166 |
| --teal-soft | #e8f7f4 |
| --blue | #1577a8 |
| --amber | #b66a0b |
| --red | #bd3c42 |
| --radius | 6px |

- Light theme only; no `.dark`, data-theme, theme provider or Tailwind configuration.
- Font: Inter (not downloaded), ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif. Log payloads use ui-monospace, SFMono-Regular, Consolas, monospace.
- Body 14px; h1 clamp(27px, 3vw, 38px), weight 720; h2 16px; controls 11–12px; labels 9–10px; metric counts 24px; simulation heading 21px.
- No formal spacing scale: repeated 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 28, 32px. Main padding 34px 32px 60px; sidebar width 172px; max main 1540px.
- Radii 2/3/4px for small controls, 6px shared panels, 50% round indicators and donut.
- Drawer shadow -18px 0 44px rgba(8,25,43,.14); live-dot shadow 0 0 0 3px rgba(14,168,117,.12).
- Responsive max-width breakpoints: 1120, 1100, 820, 650, 560px. Reduced-motion query disables smooth scroll, drawer transition and simulation pulse.
- Canvas/chart colors also exist as JavaScript literals in `app.js` and `live.js`; a palette change must update those alongside CSS and matching legends. Existing rate series teal #0b8f82 / blue #1577a8 / purple #965eae; queue amber #b66a0b / red #bd3c42.

## Part 2 — complete raw stylesheet
Source: `internal/dashboard/assets/styles.css`.

```css
:root {
  --navy: #071426;
  --navy-2: #0c1d32;
  --ink: #172436;
  --muted: #69788b;
  --line: #dce4eb;
  --line-strong: #c9d4de;
  --surface: #ffffff;
  --canvas: #f4f7f9;
  --teal: #0b8f82;
  --teal-dark: #087166;
  --teal-soft: #e8f7f4;
  --blue: #1577a8;
  --amber: #b66a0b;
  --red: #bd3c42;
  --radius: 6px;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  color: var(--ink);
  background: var(--canvas);
  font-synthesis: none;
}
.simulation-panel { background: var(--navy-2); color: #f0f7fc; padding: 22px 24px 16px; margin-bottom: 16px; border-radius: var(--radius); }
.simulation-intro, .simulation-controls { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
.simulation-intro { justify-content: space-between; margin-bottom: 20px; }
.simulation-intro h2 { font-size: 21px; margin-bottom: 6px; }
.simulation-intro p, .simulation-message { color: #aec3d5; font-size: 12px; margin: 0; line-height: 1.6; }
.simulation-badge { display: flex; align-items: center; gap: 8px; color: #c4d5e2; font-size: 12px; }
.simulation-badge::before { content: ""; width: 7px; height: 7px; border-radius: 50%; background: #839bb0; }
.simulation-badge.running { color: #75e2cf; }
.simulation-badge.running::before { background: #75e2cf; animation: simulation-pulse 1.6s ease-in-out infinite; }
.simulation-controls { align-items: end; }
.simulation-controls label { display: grid; gap: 7px; color: #aec3d5; font-size: 11px; }
.simulation-controls select { background: #162d45; border-color: #466079; color: #f0f7fc; min-width: 185px; }
.simulation-controls .button { height: 36px; }
.simulation-controls .button:not(.primary) { background: transparent; color: #d6e5f0; border-color: #466079; }
.simulation-controls .button:disabled { cursor: not-allowed; opacity: .5; }
.simulation-progress { margin-left: auto; display: grid; gap: 5px; text-align: right; font-variant-numeric: tabular-nums; }
.simulation-progress strong { font-size: 17px; }.simulation-progress span { color: #aec3d5; font-size: 11px; }
.simulation-message { padding-top: 14px; margin-top: 15px; border-top: 1px solid #294158; }
.telemetry-grid { display: grid; grid-template-columns: 1.2fr 1fr .95fr; gap: 14px; margin-bottom: 16px; }
.telemetry-grid > article { min-width: 0; padding: 17px 18px; }
.telemetry-grid .section-head { padding: 0; margin-bottom: 14px; align-items: baseline; gap: 10px; flex-wrap: wrap; }
.telemetry-grid h2 { font-size: 14px; }.telemetry-grid .section-head > strong { color: var(--teal-dark); font-size: 12px; font-variant-numeric: tabular-nums; }
.telemetry-grid .section-head > span { font-size: 11px; color: #586c80; }
.telemetry-chart canvas { display: block; width: 100%; height: 155px; cursor: crosshair; }
.telemetry-chart canvas:focus-visible { outline: 2px solid var(--teal); outline-offset: 3px; }
.telemetry-legend { display: flex; flex-wrap: wrap; gap: 12px; font-size: 10px; color: #526578; margin-bottom: 12px; }
.telemetry-legend span::before { content: ""; display: inline-block; width: 12px; height: 3px; background: var(--series); vertical-align: middle; margin-right: 5px; }
.rate-accepted { --series: #0b8f82; }.rate-processed { --series: #1577a8; }.rate-delivered { --series: #965eae; }.queue-pending { --series: #b66a0b; }.queue-failed { --series: #bd3c42; }
.telemetry-grid .chart-summary { margin: 10px 0 0; padding: 0; color: #526578; min-height: 30px; font-size: 10px; line-height: 1.6; }
.telemetry-grid .panel-copy { padding: 0; margin-bottom: 12px; font-size: 11px; }
.source-mix { display: grid; gap: 5px; }
.source-mix button { display: grid; grid-template-columns: 92px minmax(35px,1fr) 20px; align-items: center; gap: 10px; width: 100%; padding: 5px 0; border: 0; background: transparent; text-align: left; font-size: 11px; cursor: pointer; color: #40586e; }
.source-mix button:hover { color: var(--teal-dark); background: var(--teal-soft); }
.source-mix strong { text-align: right; font-size: 11px; }
.source-mix meter { width: 100%; height: 12px; border: 0; background: #e7eef2; border-radius: 2px; }
.source-mix meter::-webkit-meter-bar { background: #e7eef2; border: 0; border-radius: 2px; height: 6px; }
.source-mix meter::-webkit-meter-optimum-value { background: var(--teal); border-radius: 2px; }
.source-mix meter::-moz-meter-bar { background: var(--teal); }
.log-console { background: #09192b; color: #c5d6e5; border-radius: var(--radius); margin-bottom: 24px; overflow: hidden; }
.console-head { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 18px 20px; border-bottom: 1px solid #253b50; }
.console-head h2 { color: #f0f7fc; font-size: 15px; margin-bottom: 5px; }.console-head p { color: #9eb7cd; font-size: 11px; margin: 0; }
.console-actions { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }.console-actions > span { font-size: 11px; padding-right: 8px; color: #9eb7cd; }
.console-actions .button { background: #142c43; border-color: #3e5871; color: #d7e7f4; height: 30px; font-size: 11px; }
.console-actions .button:hover { background: #24435e; }
.live-log-feed { list-style: none; padding: 0 20px; margin: 0; height: 292px; overflow: auto; overscroll-behavior: contain; scrollbar-color: #426079 #09192b; scrollbar-gutter: stable; }
.log-line { display: grid; grid-template-columns: 65px minmax(140px,1fr) 60px 155px; gap: 7px 14px; align-items: center; padding: 12px 0; border-bottom: 1px solid #1c3349; font-size: 11px; }
.log-line time, .log-line code { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }
.log-line time { color: #89a9c3; font-variant-numeric: tabular-nums; }.log-line strong { color: #e4eef6; font-weight: 600; }
.log-format { color: #a8c6df; font-size: 10px; }
.log-status { background: transparent; border: 0; color: #76ddc5; cursor: pointer; text-align: right; font-size: 9px; padding: 0; min-height: 22px; }
.log-status:hover:not(:disabled) { text-decoration: underline; text-underline-offset: 3px; }.log-status:disabled { cursor: default; color: #b7c9d9; }
.log-line code { grid-column: 2 / -1; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; color: #97b4ca; font-size: 11px; line-height: 1.6; }
.console-empty { color: #9eb7cd; padding: 28px 0; line-height: 1.8; max-width: 70ch; font-size: 12px; }
.console-foot { display: flex; justify-content: space-between; gap: 14px; padding: 10px 20px; background: #10253a; color: #a7bfd2; font-size: 10px; }
#simulation, #recent { scroll-margin-top: 85px; }
@keyframes simulation-pulse { 50% { opacity: .35; } }
@media (max-width: 1100px) { .telemetry-grid { grid-template-columns: 1fr 1fr; }.source-mix-panel { grid-column: 1 / -1; }.source-mix { grid-template-columns: 1fr 1fr; column-gap: 28px; } }
@media (max-width: 650px) {
  .simulation-panel { padding: 18px 16px; }.simulation-intro h2 { font-size: 19px; }.simulation-controls { gap: 12px; }.simulation-controls label { width: 100%; }.simulation-controls select { width: 100%; }.simulation-progress { margin-left: auto; }
  .telemetry-grid { grid-template-columns: 1fr; }.source-mix { grid-template-columns: 1fr; }.console-head { align-items: start; flex-direction: column; padding: 16px; }.live-log-feed { padding: 0 12px; }.log-line { grid-template-columns: 57px 1fr 42px; gap: 6px 8px; }.log-status { grid-column: 2 / -1; text-align: left; }.log-line code { grid-column: 1 / -1; }.console-foot { flex-direction: column; gap: 5px; padding: 10px 12px; }
}
@media (prefers-reduced-motion: reduce) { .simulation-badge.running::before { animation: none; } }
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body { margin: 0; background: var(--canvas); color: var(--ink); font-size: 14px; }
button, input, select { font: inherit; }
button, a, input, select { -webkit-tap-highlight-color: transparent; }
button:focus-visible, a:focus-visible, input:focus-visible, select:focus-visible { outline: 3px solid rgba(21,119,168,.25); outline-offset: 2px; }
.skip-link { position: fixed; top: 8px; left: 8px; z-index: 100; transform: translateY(-160%); background: white; color: var(--navy); padding: 9px 12px; border-radius: 4px; }
.skip-link:focus { transform: none; }
.sr-only { position: absolute !important; width: 1px; height: 1px; overflow: hidden; clip: rect(0,0,0,0); white-space: nowrap; }
.shell { min-height: 100vh; display: grid; grid-template-columns: 172px minmax(0, 1fr); }
.sidebar { position: sticky; top: 0; height: 100vh; display: flex; flex-direction: column; padding: 26px 16px 20px; color: #c9d3df; background: var(--navy); }
.brand { display: flex; gap: 10px; align-items: center; color: white; text-decoration: none; margin: 0 4px 42px; }
.brand-mark { display: grid; place-items: center; width: 30px; height: 30px; border: 1px solid #32b6a8; color: #57d1c3; font-weight: 800; font-size: 14px; }
.brand strong { display: block; letter-spacing: .12em; font-size: 14px; }
.brand small { display: block; color: #8294aa; margin-top: 2px; font-size: 10px; }
.sidebar nav { display: grid; gap: 4px; }
.nav-link { position: relative; color: #8fa1b5; text-decoration: none; padding: 10px 12px; border-radius: 4px; font-size: 12px; font-weight: 650; }
.nav-link:hover { color: white; background: rgba(255,255,255,.055); }
.nav-link.active { color: white; background: #10253d; }
.nav-link.active::before { content: ""; position: absolute; left: -16px; top: 7px; bottom: 7px; width: 3px; background: #25b8a8; }
.sidebar-foot { margin-top: auto; display: grid; gap: 5px; padding: 14px 8px 0; border-top: 1px solid rgba(255,255,255,.1); font-size: 11px; color: #6f8299; }
.sidebar-foot strong { color: #dce5ee; overflow: hidden; text-overflow: ellipsis; }
.rail-label { text-transform: uppercase; letter-spacing: .1em; font-size: 9px; }
.workspace { min-width: 0; }
.topbar { min-height: 68px; display: flex; align-items: center; gap: 18px; padding: 10px 28px; background: white; border-bottom: 1px solid var(--line); position: sticky; top: 0; z-index: 20; }
.connection-form { display: flex; align-items: end; gap: 8px; flex: 1; }
.connection-form label, .scope-bar label { display: grid; gap: 4px; color: var(--muted); font-size: 10px; font-weight: 750; text-transform: uppercase; letter-spacing: .08em; }
input, select { height: 34px; border: 1px solid var(--line-strong); border-radius: 4px; background: white; color: var(--ink); padding: 0 10px; }
input:hover, select:hover { border-color: #9cacba; }
.connection-form input { width: 145px; }
.connection-form label:nth-child(2) input { width: 218px; }
.button { height: 34px; border: 1px solid var(--line-strong); border-radius: 4px; padding: 0 12px; background: white; color: #314255; font-weight: 700; font-size: 12px; cursor: pointer; }
.button:hover { border-color: #96a7b6; background: #f8fafb; }
.button.primary { background: var(--teal); color: white; border-color: var(--teal); }
.button.primary:hover { background: var(--teal-dark); }
.button:disabled { cursor: wait; opacity: .65; }
.connection-state { min-width: 160px; display: flex; gap: 9px; align-items: center; padding-left: 16px; border-left: 1px solid var(--line); }
.connection-state strong, .connection-state small { display: block; }
.connection-state strong { font-size: 12px; }
.connection-state small { color: var(--muted); max-width: 150px; overflow: hidden; text-overflow: ellipsis; }
.status-dot { display: inline-block; flex: 0 0 auto; width: 8px; height: 8px; border-radius: 50%; background: #a4afba; }
.status-dot.live { background: #0ea875; box-shadow: 0 0 0 3px rgba(14,168,117,.12); }
.status-dot.error { background: var(--red); }
.refresh.loading span:first-child { display: inline-block; animation: spin .7s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
main { max-width: 1540px; margin: 0 auto; padding: 34px 32px 60px; }
.hero { display: flex; justify-content: space-between; align-items: end; gap: 24px; margin-bottom: 22px; }
.eyebrow { margin: 0 0 6px; color: var(--teal-dark); font-weight: 800; font-size: 9px; letter-spacing: .14em; }
h1, h2, h3, p { margin-top: 0; }
h1 { margin-bottom: 6px; font-size: clamp(27px, 3vw, 38px); line-height: 1.08; letter-spacing: -.035em; font-weight: 720; }
h2 { margin-bottom: 0; font-size: 16px; letter-spacing: -.01em; }
.hero > div > p:last-child { margin: 0; color: var(--muted); font-size: 15px; }
.updated { text-align: right; }
.updated span, .updated strong { display: block; }
.updated span { color: var(--muted); font-size: 10px; text-transform: uppercase; letter-spacing: .08em; }
.updated strong { margin-top: 4px; font-size: 12px; }
.notice { display: none; margin-bottom: 16px; padding: 10px 12px; border: 1px solid #b8dcd6; border-radius: 4px; background: var(--teal-soft); color: #17665e; }
.notice:not(:empty) { display: block; }
.notice.error { border-color: #ecc6c9; background: #fff2f3; color: #9c3037; }
.scope-bar { display: grid; grid-template-columns: minmax(220px, 1fr) 150px 150px minmax(160px, auto); gap: 12px; align-items: end; padding: 14px 16px; margin-bottom: 14px; background: white; border: 1px solid var(--line); border-radius: var(--radius); }
.scope-bar h2 { font-size: 13px; }
.scope-bar p:last-child { margin: 3px 0 0; color: var(--muted); font-size: 11px; }
.node-groups { min-height: 34px; display: flex; flex-wrap: wrap; align-items: center; justify-content: flex-end; gap: 6px; }
.node-group { display: flex; align-items: center; gap: 6px; }
.node-group h3 { margin: 0; color: var(--muted); font-size: 9px; text-transform: uppercase; letter-spacing: .06em; }
.node-list { display: flex; flex-wrap: wrap; gap: 5px; }
.node-card { display: grid; gap: 1px; padding: 5px 7px; border: 1px solid var(--line); border-radius: 3px; background: white; color: #4e6073; text-align: left; cursor: pointer; }
.node-card:hover, .node-card.selected { border-color: #75b7ae; background: var(--teal-soft); }
.node-card strong { font-size: 10px; }.node-card span, .node-card small { color: var(--muted); font-size: 8px; }
.node-card.unavailable { border-color: #edc9cc; }.node-card.unavailable span { color: var(--red); }
.node-chip { padding: 5px 7px; border: 1px solid var(--line); border-radius: 3px; color: #4e6073; font-size: 10px; }
.node-chip.unavailable { color: var(--red); border-color: #edc9cc; }
.node-empty { margin: 0; color: var(--muted); font-size: 11px; }
.metric-strip { display: grid; grid-template-columns: repeat(4, 1fr); background: white; border: 1px solid var(--line); border-radius: var(--radius); margin-bottom: 14px; }
.metric-strip article { display: grid; gap: 4px; padding: 17px 20px; border-right: 1px solid var(--line); }
.metric-strip article:last-child { border-right: 0; }
.metric-strip span { color: var(--muted); font-size: 10px; font-weight: 750; text-transform: uppercase; letter-spacing: .08em; }
.metric-strip strong { font-size: 24px; letter-spacing: -.03em; }
.metric-strip small { color: #8794a3; font-size: 10px; }
.panel { background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius); }
.section-head { display: flex; justify-content: space-between; align-items: center; gap: 14px; padding: 16px 18px; border-bottom: 1px solid var(--line); }
.section-head .eyebrow { margin-bottom: 4px; }
.live-label { display: inline-flex; align-items: center; gap: 7px; color: #536477; font-size: 11px; font-weight: 700; }
.pipeline-panel { margin-bottom: 14px; }
.pipeline { display: grid; grid-template-columns: repeat(5, 1fr); list-style: none; margin: 0; padding: 0; }
.pipeline li { position: relative; border-right: 1px solid var(--line); }
.pipeline li:last-child { border-right: 0; }
.pipeline li:not(:last-child)::after { content: ""; position: absolute; right: -4px; top: 50%; width: 7px; height: 7px; border-top: 1px solid #aab7c3; border-right: 1px solid #aab7c3; transform: translateY(-50%) rotate(45deg); background: white; z-index: 2; }
.pipeline-stage { width: 100%; min-height: 78px; display: grid; grid-template-columns: auto 1fr auto; gap: 10px; align-items: center; padding: 13px 16px; border: 0; background: transparent; color: var(--ink); text-align: left; cursor: pointer; }
.pipeline-stage:hover, .pipeline-stage[aria-expanded="true"] { background: #f2faf8; }
.stage-num { color: #8a99a8; font-size: 10px; font-weight: 800; }
.pipeline-stage strong, .pipeline-stage small { display: block; }
.pipeline-stage strong { font-size: 12px; }
.pipeline-stage small { margin-top: 3px; color: var(--muted); font-size: 10px; }
.pipeline-stage b { color: var(--teal-dark); font-size: 18px; }
.pipeline-stage.attention b { color: var(--red); }
.operations-grid { display: grid; grid-template-columns: minmax(0, 1fr) 270px; gap: 14px; margin-bottom: 14px; align-items: stretch; }
.events-panel { min-width: 0; }
.event-heading p:last-child { color: var(--muted); font-size: 11px; margin: 4px 0 0; }
.stream-controls { display: flex; align-items: center; gap: 10px; }
.event-filters { display: grid; grid-template-columns: minmax(200px, 1fr) 155px 125px 130px auto; gap: 8px; padding: 10px 12px; background: #f8fafb; border-bottom: 1px solid var(--line); }
.event-filters input, .event-filters select { width: 100%; height: 32px; font-size: 11px; }
.table-wrap { overflow: auto; min-height: 276px; max-height: 470px; }
table { width: 100%; border-collapse: collapse; font-size: 11px; }
th { position: sticky; top: 0; z-index: 2; padding: 9px 10px; background: #fafcfd; border-bottom: 1px solid var(--line); color: #718093; text-align: left; text-transform: uppercase; letter-spacing: .07em; font-size: 9px; }
td { padding: 10px; border-bottom: 1px solid #edf1f4; color: #415164; white-space: nowrap; }
tbody tr { cursor: default; }
tbody tr:not(.empty-row):hover, tbody tr.selected { background: #f1faf8; }
.sort-button { border: 0; padding: 0; background: transparent; color: inherit; font: inherit; text-transform: inherit; letter-spacing: inherit; cursor: pointer; }
.source-cell { display: flex; align-items: center; gap: 9px; min-width: 190px; }
.source-monogram { display: grid; place-items: center; flex: 0 0 28px; width: 28px; height: 28px; border-radius: 4px; background: #e7f2f5; color: #176c85; font-size: 9px; font-weight: 800; letter-spacing: .03em; }
.source-cell strong, .source-cell small { display: block; }
.source-cell strong { max-width: 165px; overflow: hidden; text-overflow: ellipsis; color: #24364a; font-size: 11px; }
.source-cell small { color: #8996a4; font-size: 9px; margin-top: 2px; }
.format-tag { display: inline-block; padding: 3px 6px; border: 1px solid #cfdae3; border-radius: 3px; color: #52687a; text-transform: uppercase; font-size: 9px; font-weight: 800; letter-spacing: .04em; }
.status-pill { display: inline-flex; align-items: center; gap: 5px; color: #667789; font-size: 9px; font-weight: 800; letter-spacing: .04em; }
.status-pill::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: #9eabb8; }
.status-pill.parsed::before { background: #0aa47b; }
.status-pill.partial::before { background: var(--amber); }
.status-pill.failed::before { background: var(--red); }
.inspect-button { border: 1px solid var(--line-strong); border-radius: 3px; background: white; color: #405469; padding: 5px 8px; cursor: pointer; font-size: 10px; font-weight: 700; }
.inspect-button:hover { color: var(--teal-dark); border-color: #75b7ae; }
.empty-row td { height: 150px; color: var(--muted); text-align: center; }
.table-foot { min-height: 38px; display: flex; justify-content: space-between; gap: 12px; align-items: center; padding: 8px 12px; color: var(--muted); font-size: 10px; border-top: 1px solid var(--line); }
.sources-panel { display: flex; flex-direction: column; }
.sources-panel .section-head > strong { font-size: 22px; color: var(--teal-dark); }
.panel-copy { color: var(--muted); font-size: 11px; margin: 14px 16px 8px; }
.source-coverage { display: grid; gap: 5px; padding: 0 10px 14px; }
.source-family { width: 100%; display: grid; grid-template-columns: 10px 1fr auto; gap: 9px; align-items: center; padding: 9px 7px; border: 1px solid transparent; border-radius: 4px; background: transparent; color: #33475a; text-align: left; cursor: pointer; }
.source-family:hover, .source-family.selected { border-color: #c4e1dc; background: #eff9f7; }
.family-mark { width: 7px; height: 7px; border-radius: 2px; background: #4a8ea7; }
.source-family:nth-child(2n) .family-mark { background: #13a18d; }
.source-family:nth-child(3n) .family-mark { background: #7a78ae; }
.source-family span { font-size: 11px; font-weight: 700; }
.source-family strong { font-size: 12px; }
.source-note { margin-top: auto; padding: 13px 15px; background: #f8fafb; border-top: 1px solid var(--line); }
.source-note strong { font-size: 10px; text-transform: uppercase; letter-spacing: .06em; }
.source-note p { margin: 4px 0 0; color: var(--muted); font-size: 10px; line-height: 1.45; }
.visual-grid { display: grid; grid-template-columns: minmax(0, 1.45fr) minmax(300px, .55fr); gap: 14px; }
.legend { display: flex; gap: 12px; color: var(--muted); font-size: 10px; }
.legend span { display: inline-flex; align-items: center; gap: 5px; }
.legend i { width: 14px; height: 2px; background: var(--teal); }
.legend i.committed { background: var(--blue); }
.canvas-wrap { height: 220px; padding: 16px 18px 0; }
canvas { width: 100%; height: 100%; }
.chart-summary { margin: 4px 18px 14px; color: var(--muted); font-size: 10px; }
.distribution-body { display: grid; grid-template-columns: 128px 1fr; gap: 18px; align-items: center; padding: 28px 20px; }
.donut { width: 122px; height: 122px; display: grid; place-items: center; border-radius: 50%; background: conic-gradient(#d8e1e8 0 100%); position: relative; }
.donut::before { content: ""; position: absolute; inset: 23px; border-radius: 50%; background: white; }
.donut span { z-index: 1; text-align: center; }
.donut strong, .donut small { display: block; }
.donut strong { font-size: 20px; }
.donut small { color: var(--muted); font-size: 9px; }
.status-list { list-style: none; display: grid; gap: 11px; margin: 0; padding: 0; }
.status-list li { display: grid; grid-template-columns: 8px 1fr auto; align-items: center; gap: 8px; color: #57697a; font-size: 10px; }
.status-swatch { width: 7px; height: 7px; border-radius: 2px; background: #aab6c1; }
.status-swatch.parsed { background: #0aa47b; }.status-swatch.partial { background: #d68b24; }.status-swatch.failed { background: #cc4c53; }.status-swatch.other { background: #7b8a9a; }
.trace-drawer { position: fixed; z-index: 50; top: 0; right: 0; width: min(450px, 94vw); height: 100vh; transform: translateX(102%); transition: transform .22s ease; background: white; border-left: 1px solid var(--line); box-shadow: -18px 0 44px rgba(8,25,43,.14); overflow: auto; }
.trace-drawer.open { transform: translateX(0); }
.drawer-head { position: sticky; top: 0; z-index: 2; display: flex; justify-content: space-between; gap: 20px; padding: 22px 24px; border-bottom: 1px solid var(--line); background: white; }
.drawer-head p:last-child { margin: 6px 0 0; color: var(--muted); font-size: 11px; }
.icon-button { width: 32px; height: 32px; border: 1px solid var(--line); border-radius: 4px; background: white; color: #4a5b6c; cursor: pointer; font-size: 19px; }
.trace-content { padding: 22px 24px 50px; }
.trace-empty { min-height: 300px; display: grid; place-content: center; text-align: center; color: var(--muted); }
.trace-empty strong { color: var(--ink); }
.trace-empty p { max-width: 260px; margin: 7px 0 0; }
.trace-warning, .trace-error { padding: 11px 12px; border: 1px solid #e3d29b; background: #fff9e8; color: #775c13; font-size: 11px; line-height: 1.5; }
.trace-error { border-color: #ebc8ca; background: #fff3f3; color: #96343a; }
.trace-section { position: relative; padding: 0 0 18px 25px; border-left: 1px solid #b9ddd7; }
.trace-section:last-child { border-left-color: transparent; }
.trace-section h3 { margin: 0 0 8px; font-size: 12px; }
.trace-check { position: absolute; left: -9px; top: -2px; width: 17px; height: 17px; display: grid; place-items: center; border-radius: 50%; background: var(--teal); color: white; font-size: 10px; }
.trace-card { border: 1px solid var(--line); border-radius: 4px; overflow: hidden; }
.kv { display: grid; grid-template-columns: 118px 1fr; gap: 10px; padding: 8px 10px; border-bottom: 1px solid #edf1f4; font-size: 10px; }
.kv:last-child { border-bottom: 0; }.kv span { color: var(--muted); }.kv strong { min-width: 0; overflow-wrap: anywhere; }
.copy-button { width: 100%; padding: 8px; border: 0; border-top: 1px solid var(--line); background: #f8fafb; color: var(--teal-dark); cursor: pointer; font-size: 10px; font-weight: 750; }
.pipeline-stage-detail { display: grid; gap: 14px; }
.pipeline-stage-summary { padding: 14px; background: #f1f9f7; border-left: 3px solid var(--teal); line-height: 1.5; }
.pipeline-stage-metric { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.pipeline-stage-metric > div { padding: 12px; border: 1px solid var(--line); border-radius: 4px; }.pipeline-stage-metric span, .pipeline-stage-contract span { display: block; color: var(--muted); font-size: 9px; text-transform: uppercase; letter-spacing: .07em; }.pipeline-stage-metric strong { display: block; margin-top: 5px; font-size: 20px; }
.pipeline-stage-contract { display: grid; gap: 8px; }.pipeline-stage-contract > div { padding: 12px; border: 1px solid var(--line); border-radius: 4px; }.pipeline-stage-contract strong { display: block; margin-top: 5px; font-size: 11px; line-height: 1.45; }
.drawer-scrim { display: none; position: fixed; inset: 0; z-index: 40; border: 0; background: rgba(5,17,31,.4); }.drawer-scrim.open { display: block; }
@media (max-width: 1120px) { .connection-state { display: none; }.operations-grid { grid-template-columns: 1fr; }.sources-panel { min-height: 0; }.source-coverage { grid-template-columns: repeat(3, 1fr); }.source-note { margin-top: 0; }.scope-bar { grid-template-columns: 1fr 140px 140px; }.node-groups { grid-column: 1 / -1; justify-content: flex-start; } }
@media (max-width: 820px) { .shell { display: block; }.sidebar { position: static; width: 100%; height: auto; padding: 13px 16px; flex-direction: row; align-items: center; gap: 16px; overflow: auto; }.brand { margin: 0; flex: 0 0 auto; }.brand small, .sidebar-foot { display: none; }.sidebar nav { display: flex; }.nav-link { white-space: nowrap; padding: 8px 9px; }.nav-link.active::before { display: none; }.topbar { position: static; padding: 10px 16px; flex-wrap: wrap; }.connection-form { flex-wrap: wrap; }.refresh { margin-left: auto; } main { padding: 24px 16px 45px; }.metric-strip { grid-template-columns: 1fr 1fr; }.metric-strip article:nth-child(2) { border-right: 0; }.metric-strip article:nth-child(-n+2) { border-bottom: 1px solid var(--line); }.pipeline { grid-template-columns: 1fr; }.pipeline li { border-right: 0; border-bottom: 1px solid var(--line); }.pipeline li::after { display: none; }.pipeline-stage { min-height: 58px; }.visual-grid { grid-template-columns: 1fr; }.source-coverage { grid-template-columns: repeat(2, 1fr); } }
@media (max-width: 560px) { .hero { align-items: start; }.updated { display: none; }.connection-form label, .connection-form input { width: 100% !important; }.connection-form label { flex: 1 0 100%; }.scope-bar { grid-template-columns: 1fr 1fr; }.scope-bar > div:first-child { grid-column: 1 / -1; }.metric-strip { grid-template-columns: 1fr; }.metric-strip article { border-right: 0; border-bottom: 1px solid var(--line); }.metric-strip article:last-child { border-bottom: 0; }.event-filters { grid-template-columns: 1fr 1fr; }.event-filters label:first-child { grid-column: 1 / -1; }.source-coverage { grid-template-columns: 1fr; }.distribution-body { grid-template-columns: 1fr; justify-items: center; }.status-list { width: 100%; }.table-foot { align-items: flex-start; flex-direction: column; } }
@media (prefers-reduced-motion: reduce) { html { scroll-behavior: auto; }.trace-drawer { transition: none; } }
```
