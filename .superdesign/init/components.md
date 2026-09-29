# Existing UI primitives — source snapshot

Framework: none. Go embeds HTML, vanilla CSS and two browser JavaScript files. No frontend package manifest, component library, Tailwind, JSX, bundler or client router exists. There is no shared component directory. Reusable primitives are HTML/CSS patterns and local DOM factories. Full containing HTML is in `layouts.md`; full stylesheet is in `theme.md`. This file copies complete factory implementations and complete representative HTML primitives rather than duplicating the entire page.

The redesign may replace the navy/teal appearance with white/green rounded cards, while retaining API behavior and DOM contracts.

## replaceSelectOptions
- Source: `internal/dashboard/assets/app.js`
- Description: Rebuilds a select with all-option and preserves valid selection.
- Arguments: `select, values, allLabel, previous`

```javascript
  function replaceSelectOptions(select, values, allLabel, previous) {
    const fragment = document.createDocumentFragment();
    const all = document.createElement("option"); all.value = ""; all.textContent = allLabel; fragment.append(all);
    values.forEach((value) => {
      const option = document.createElement("option"); option.value = value; option.textContent = value; fragment.append(option);
    });
    select.replaceChildren(fragment);
    select.disabled = values.length === 0;
    select.value = values.includes(previous) ? previous : "";
  }
```

## detailRow
- Source: `internal/dashboard/assets/app.js`
- Description: Builds an accessible label/value metadata row.
- Arguments: `label, value`

```javascript
  function detailRow(label, value) {
    const row = document.createElement("div"); row.className = "kv";
    const key = document.createElement("span"); key.textContent = label;
    const data = document.createElement("strong"); data.textContent = value === undefined || value === null || value === "" ? "—" : String(value);
    row.append(key, data); return row;
  }
```

## traceSection
- Source: `internal/dashboard/assets/app.js`
- Description: Builds metadata card section and optional identifier copy action.
- Arguments: `title, rows, copyValue`

```javascript
  function traceSection(title, rows, copyValue = "") {
    const section = document.createElement("section"); section.className = "trace-section";
    const check = document.createElement("span"); check.className = "trace-check"; check.textContent = "✓"; check.setAttribute("aria-hidden", "true");
    const heading = document.createElement("h3"); heading.textContent = title;
    const card = document.createElement("div"); card.className = "trace-card"; rows.forEach((row) => card.append(detailRow(row[0], row[1])));
    if (copyValue) {
      const copy = document.createElement("button"); copy.type = "button"; copy.className = "copy-button"; copy.textContent = "Copy identifier";
      copy.addEventListener("click", async () => {
        try { await navigator.clipboard.writeText(copyValue); copy.textContent = "Copied"; announce("Identifier copied"); }
        catch (_) { copy.textContent = "Copy unavailable"; }
      });
      card.append(copy);
    }
    section.append(check, heading, card); return section;
  }
```

## eventStatusClass
- Source: `internal/dashboard/assets/app.js`
- Description: Maps status to reusable visual state.
- Arguments: `status`

```javascript
  function eventStatusClass(status) {
    const value = String(status || "").toUpperCase();
    if (value === "PARSED" || value === "PROCESSED") return "parsed";
    if (value === "PARTIALLY_PARSED" || value === "PARTIAL") return "partial";
    if (value.includes("FAIL") || value.includes("ERROR")) return "failed";
    return "";
  }
```

## Button and form primitives
Source: `internal/dashboard/assets/index.html`. Native controls retain type, validation and labels.

```html
<label>Tenant<input id="tenantInput" name="tenant" required maxlength="128" pattern="[A-Za-z0-9][A-Za-z0-9._-]{0,127}" placeholder="demo" spellcheck="false"></label>
<label>API token<input id="tokenInput" name="token" type="password" required minlength="32" maxlength="512" placeholder="Stored for this tab" autocomplete="off" spellcheck="false"></label>
<button class="button primary" type="submit">Connect</button>
<button class="button quiet" id="disconnectButton" type="button">Clear</button>
<div class="stream-controls"><span class="live-label"><span class="status-dot live" aria-hidden="true"></span><span id="streamState">Live</span></span><button class="button quiet" id="pauseStreamButton" type="button" aria-pressed="false">Pause</button></div>
```

## PipelineStage
Source: `internal/dashboard/assets/index.html`. State attributes: `data-stage`, `aria-expanded`; child `b` count and `small` detail are updated by JavaScript.

```html
<li><button class="pipeline-stage" data-stage="frame" type="button" aria-controls="pipelineDrawer" aria-expanded="false"><span class="stage-num">01</span><span><strong>Frame</strong><small>Transport boundaries</small></span><b>—</b></button></li>
```

## StatusDistribution
Source: `internal/dashboard/assets/index.html`. Dynamic count, conic gradient and ordered status values.

```html
<article class="panel distribution-panel" aria-labelledby="distributionTitle"><div class="section-head"><div><p class="eyebrow">NORMALIZATION QUALITY</p><h2 id="distributionTitle">Status distribution</h2></div></div><div class="distribution-body"><div class="donut" id="statusDonut" role="img" aria-label="No status distribution loaded"><span><strong id="donutTotal">—</strong><small>events</small></span></div><ul class="status-list" id="statusList"><li><span class="status-swatch parsed"></span><span>Parsed</span><strong>—</strong></li><li><span class="status-swatch partial"></span><span>Partially parsed</span><strong>—</strong></li><li><span class="status-swatch failed"></span><span>Failed</span><strong>—</strong></li><li><span class="status-swatch other"></span><span>Other</span><strong>—</strong></li></ul></div></article>
```
