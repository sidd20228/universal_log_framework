(() => {
  "use strict";

  const STORAGE_TENANT = "ulpf.dashboard.tenant";
  const STORAGE_TOKEN = "ulpf.dashboard.token";
  const REFRESH_INTERVAL_MS = 2_000;
  const PIPELINE_STAGE_DETAILS = Object.freeze({
    frame: {
      title: "Frame",
      summary: "Separates each incoming transport stream into complete event records.",
      input: "Bytes received through HTTP, syslog, files or another configured transport.",
      output: "A complete event frame with transport and listener context.",
      guarantee: "Transport boundaries are resolved before evidence is admitted.",
    },
    admit: {
      title: "Admit",
      summary: "Persists the original event and creates its durable receipt.",
      input: "A complete framed event plus tenant and source context.",
      output: "An immutable receipt linked to content-addressed raw evidence.",
      guarantee: "Original bytes remain available without lossy transformation.",
    },
    interpret: {
      title: "Interpret",
      summary: "Detects the source format, parses attributes and maps common fields.",
      input: "Raw evidence referenced by a durable receipt.",
      output: "Source attributes, canonical fields, provenance and quality metadata.",
      guarantee: "Every normalized value remains traceable to its source evidence.",
    },
    commit: {
      title: "Commit",
      summary: "Stores an immutable processing revision for the interpretation result.",
      input: "Parsed fields, canonical mappings, issues and parser identity.",
      output: "A versioned event envelope linked to its receipt and raw evidence.",
      guarantee: "Reprocessing adds revisions and never overwrites earlier meaning.",
    },
    deliver: {
      title: "Deliver",
      summary: "Routes committed envelopes to configured SIEM and data lake targets.",
      input: "A committed canonical event envelope.",
      output: "Tracked delivery attempts with pending, delivered or failed state.",
      guarantee: "Connector outcomes are observable and retryable without reparsing.",
    },
  });
  const state = {
    tenant: "",
    token: "",
    connected: false,
    loading: false,
    events: [],
    eventsNewestFirst: true,
    activity: [],
    summary: null,
    health: null,
    fallbackEvents: [],
    selectedRevision: "",
    selectedStage: "",
    refreshController: null,
    timer: null,
    previousFocus: null,
    streamPaused: false,
    sourceFamily: "",
    format: "",
    status: "",
    search: "",
    seenRevisions: new Set(),
  };

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
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  function updateValue(node, value) {
    const previous = node.textContent;
    node.textContent = value;
    if (previous !== value && previous !== "—" && value !== "—" && !reducedMotion.matches && node.animate) {
      node.animate([{ transform: "translateY(3px)", opacity: .5 }, { transform: "translateY(0)", opacity: 1 }], { duration: 380, easing: "cubic-bezier(.16,1,.3,1)" });
    }
  }

  const live = ULPFLive.mount({
    connection: () => state.connected && Boolean(state.summary) && state.health?.ready,
    ingest: (body, signal) => fetchJSON("/api/v1/ingest", { method: "POST", body, signal, headers: { "Content-Type": "application/octet-stream" } }),
    identity: sourceIdentity,
    inspect: inspectEvent,
    resume: () => { if (state.streamPaused) toggleStream(); },
    filter: (family) => {
      state.sourceFamily = state.sourceFamily === family ? "" : family;
      ui.sourceFamilyFilter.value = state.sourceFamily;
      renderEvents(); renderSourceCoverage();
      element("recent").scrollIntoView({ block: "start" });
      ui.sourceFamilyFilter.focus({ preventScroll: true });
      announce(state.sourceFamily ? `Showing ${family} events` : "Showing all source families");
    },
  });

  function getSession(key) {
    try { return sessionStorage.getItem(key) || ""; } catch (_) { return ""; }
  }

  function setSession(key, value) {
    try {
      if (value) sessionStorage.setItem(key, value);
      else sessionStorage.removeItem(key);
    } catch (_) { /* Dashboard remains usable when browser storage is disabled. */ }
  }

  function announce(message) {
    ui.announcer.textContent = "";
    window.setTimeout(() => { ui.announcer.textContent = message; }, 30);
  }

  function showNotice(message, kind = "") {
    ui.notice.hidden = !message;
    ui.notice.textContent = message || "";
    ui.notice.className = `notice${kind ? ` ${kind}` : ""}`;
  }

  function setConnection(kind, label, detail) {
    ui.connectionDot.className = `status-dot ${kind}`;
    ui.connectionLabel.textContent = label;
    ui.connectionDetail.textContent = detail;
    ui.streamState.textContent = state.streamPaused ? "Paused" : state.connected ? "Live" : "Offline";
    ui.streamState.previousElementSibling.className = `status-dot ${state.connected && !state.streamPaused ? "live" : "idle"}`;
  }

  function authHeaders() {
    return { Accept: "application/json", Authorization: `Bearer ${state.token}` };
  }

  async function fetchJSON(url, options = {}) {
    const response = await fetch(url, {
      method: "GET",
      credentials: "same-origin",
      cache: "no-store",
      ...options,
      headers: { ...authHeaders(), ...(options.headers || {}) },
    });
    const contentType = response.headers.get("content-type") || "";
    let body = null;
    if (contentType.includes("application/json")) {
      try { body = await response.json(); } catch (_) { body = null; }
    }
    if (!response.ok) {
      const error = new Error(body?.message || `Request failed with HTTP ${response.status}`);
      error.status = response.status;
      error.code = body?.code || "HTTP_ERROR";
      error.requestID = body?.request_id || response.headers.get("x-request-id") || "";
      throw error;
    }
    if (body === null) throw new Error("The server returned an invalid JSON response.");
    return body;
  }

  async function fetchHealth(signal) {
    const response = await fetch("/health/ready", { method: "GET", cache: "no-store", credentials: "same-origin", signal });
    return { ready: response.ok, status: response.status };
  }

  function numberOrNull(value) {
    if (value === null || value === undefined || value === "") return null;
    const parsed = typeof value === "number" ? value : Number(value);
    return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
  }

  function formatCount(value) {
    const number = numberOrNull(value);
    return number === null ? "—" : new Intl.NumberFormat().format(number);
  }

  function formatBytes(value) {
    let number = numberOrNull(value);
    if (number === null) return "—";
    const units = ["B", "KB", "MB", "GB", "TB", "PB"];
    let unit = 0;
    while (number >= 1000 && unit < units.length - 1) { number /= 1000; unit += 1; }
    return `${number >= 10 || unit === 0 ? number.toFixed(0) : number.toFixed(1)} ${units[unit]}`;
  }

  function formatTime(value, includeDate = true) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "—";
    return new Intl.DateTimeFormat(undefined, {
      ...(includeDate ? { year: "numeric", month: "2-digit", day: "2-digit" } : {}),
      hour: "2-digit", minute: "2-digit", second: "2-digit",
    }).format(date);
  }

  function compactHash(value) {
    if (!value) return "—";
    return value.length > 18 ? `${value.slice(0, 12)}…${value.slice(-6)}` : value;
  }

  function totalsOf(summary) {
    return summary?.totals && typeof summary.totals === "object" ? summary.totals : {};
  }

  function originsOf(summary) {
    return Array.isArray(summary?.origins) ? summary.origins : [];
  }

  function nodesOf(summary) {
    return Array.isArray(summary?.nodes) ? summary.nodes : [];
  }

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

  function populateScopeFilters(summary) {
    const origins = originsOf(summary);
    const records = [...origins, ...nodesOf(summary)];
    const previousEnvironment = ui.environmentFilter.value;
    const environments = [...new Set(records.map((item) => String(item?.environment_id || "")).filter(Boolean))].sort();
    replaceSelectOptions(ui.environmentFilter, environments, "All environments", previousEnvironment);
    const selectedEnvironment = ui.environmentFilter.value;
    const previousInstance = ui.instanceFilter.value;
    const instances = [...new Set(records
      .filter((item) => !selectedEnvironment || item?.environment_id === selectedEnvironment)
      .map((item) => String(item?.instance_id || "")).filter(Boolean))].sort();
    replaceSelectOptions(ui.instanceFilter, instances, "All instances", previousInstance);
  }

  function nodeState(node) {
    if (node?.available && !node?.stale) return { label: "Current", className: "current" };
    if (node?.available) return { label: "Stale", className: "stale" };
    if (node?.retained) return { label: "Unavailable · last known retained", className: "unavailable" };
    return { label: "Unavailable", className: "unavailable" };
  }

  function renderNodeGroups(summary) {
    ui.nodeGroups.replaceChildren();
    const nodes = nodesOf(summary);
    if (nodes.length === 0) {
      const empty = document.createElement("p"); empty.className = "node-empty"; empty.textContent = "No runtime origins were returned."; ui.nodeGroups.append(empty);
      return;
    }
    const groups = new Map();
    nodes.forEach((node) => {
      const environment = node?.environment_id || "Unidentified environment";
      if (!groups.has(environment)) groups.set(environment, []);
      groups.get(environment).push(node);
    });
    [...groups.keys()].sort().forEach((environment) => {
      const group = document.createElement("section"); group.className = "node-group";
      const heading = document.createElement("h3"); heading.textContent = environment; group.append(heading);
      const list = document.createElement("div"); list.className = "node-list";
      groups.get(environment).sort((left, right) => String(left?.instance_id).localeCompare(String(right?.instance_id))).forEach((node) => {
        const status = nodeState(node);
        const button = document.createElement("button"); button.type = "button"; button.className = `node-card ${status.className}`;
        if (ui.environmentFilter.value === node.environment_id && ui.instanceFilter.value === node.instance_id) button.classList.add("selected");
        const title = document.createElement("strong"); title.textContent = node.instance_id || node.id || "Unidentified instance";
        const detail = document.createElement("span"); detail.textContent = status.label;
        const observed = document.createElement("small");
        observed.textContent = node.last_seen_at ? `Last seen ${formatTime(node.last_seen_at)}` : node.generated_at ? `Snapshot ${formatTime(node.generated_at)}` : "No successful snapshot";
        button.append(title, detail, observed);
        button.addEventListener("click", () => {
          ui.environmentFilter.value = node.environment_id || "";
          populateScopeFilters(state.summary);
          ui.instanceFilter.value = node.instance_id || "";
          applyScope();
        });
        list.append(button);
      });
      group.append(list); ui.nodeGroups.append(group);
    });
  }

  function addCounts(target, source) {
    Object.entries(source && typeof source === "object" ? source : {}).forEach(([key, raw]) => {
      target[key] = (target[key] || 0) + (numberOrNull(raw) || 0);
    });
  }

  function buildScopedPipeline(totals, receiptStates) {
    return [
      ["frame", "Frame", totals.receipts], ["admit", "Admit", totals.receipts],
      ["interpret", "Interpret", totals.revisions], ["commit", "Commit", totals.revisions],
      ["deliver", "Deliver", totals.delivered],
    ].map(([stage, label, count]) => ({
      stage, label, count,
      status: stage === "deliver" && totals.failed > 0 ? "attention" : stage === "interpret" && (receiptStates.PROCESSING || 0) > 0 ? "active" : count > 0 ? "active" : "idle",
    }));
  }

  function aggregateOrigins(summary, origins) {
    const totals = { receipts: 0, revisions: 0, raw_bytes: 0, pending: 0, failed: 0, delivered: 0 };
    const receiptStateCounts = {}, statusCounts = {}, activityByTime = new Map(), recentEvents = [];
    let acceptedTotal = 0, committedTotal = 0;
    origins.forEach((origin) => {
      Object.keys(totals).forEach((key) => { totals[key] += numberOrNull(origin?.totals?.[key]) || 0; });
      acceptedTotal += numberOrNull(origin?.accepted_total) || 0;
      committedTotal += numberOrNull(origin?.committed_total) || 0;
      addCounts(receiptStateCounts, origin?.receipt_state_counts); addCounts(statusCounts, origin?.status_counts);
      (Array.isArray(origin?.activity) ? origin.activity : []).forEach((bucket) => {
        const key = String(bucket?.time || "");
        if (!key) return;
        const current = activityByTime.get(key) || { time: key, accepted: 0, committed: 0 };
        current.accepted += numberOrNull(bucket?.accepted) || 0; current.committed += numberOrNull(bucket?.committed) || 0;
        activityByTime.set(key, current);
      });
      if (Array.isArray(origin?.recent_events)) recentEvents.push(...origin.recent_events);
    });
    recentEvents.sort((left, right) => new Date(right?.received_at || 0) - new Date(left?.received_at || 0));
    const environment = ui.environmentFilter.value, instance = ui.instanceFilter.value;
    return {
      generated_at: summary?.generated_at, tenant_id: summary?.tenant_id, environment_id: environment, instance_id: instance,
      totals, accepted_total: acceptedTotal, committed_total: committedTotal,
      receipt_state_counts: receiptStateCounts, status_counts: statusCounts,
      pipeline: buildScopedPipeline(totals, receiptStateCounts),
      activity: [...activityByTime.values()].sort((left, right) => new Date(left.time) - new Date(right.time)),
      recent_events: recentEvents.slice(0, 20),
      nodes: nodesOf(summary).filter((node) => (!environment || node?.environment_id === environment) && (!instance || node?.instance_id === instance)),
      origins,
    };
  }

  function scopedSummary() {
    const summary = state.summary;
    const origins = originsOf(summary);
    const environment = ui.environmentFilter.value, instance = ui.instanceFilter.value;
    if (!summary || origins.length === 0 || (!environment && !instance)) return summary;
    return aggregateOrigins(summary, origins.filter((origin) =>
      (!environment || origin?.environment_id === environment) && (!instance || origin?.instance_id === instance)));
  }

  function applyScope(takeSample = false) {
    const view = scopedSummary();
    const environment = ui.environmentFilter.value, instance = ui.instanceFilter.value;
    const labels = [environment, instance].filter(Boolean);
    const scopeLabel = labels.length ? labels.join(" / ") : "All environments and instances";
    state.activity = normalizeActivity(view);
    state.events = Array.isArray(view?.recent_events) ? view.recent_events : state.fallbackEvents;
    state.events = [...state.events].sort((a, b) => new Date(b.received_at) - new Date(a.received_at));
    populateEventFilters();
    updateMetrics(view, state.health); updatePipeline(view); updateDistribution(view); drawActivityChart(); renderEvents(); renderSourceCoverage(); renderNodeGroups(state.summary);
    live.update(view, state.events, JSON.stringify([state.tenant, environment, instance]), takeSample === true);
    ui.scopeSummary.textContent = `${scopeLabel} · ${originsOf(view).length || nodesOf(view).length || 0} runtime origin${(originsOf(view).length || nodesOf(view).length) === 1 ? "" : "s"}`;
    ui.eventScope.textContent = `${scopeLabel} · ${state.eventsNewestFirst ? "newest" : "oldest"} first · refreshes every 2 seconds`;
  }

  function updateMetrics(summary, health) {
    const totals = totalsOf(summary);
    updateValue(ui.totalReceipts, formatCount(totals.receipts ?? totals.total_receipts));
    updateValue(ui.totalRevisions, formatCount(totals.revisions ?? totals.processed_revisions));
    updateValue(ui.rawBytes, formatBytes(totals.raw_bytes ?? totals.preserved_raw_bytes));
    ui.healthMetric.className = health?.ready ? "healthy" : "unhealthy";
    ui.healthMetric.textContent = health ? (health.ready ? "Ready" : "Not ready") : "—";
    const nodes = Array.isArray(summary?.nodes) ? summary.nodes : [];
    const availableNodes = nodes.filter((node) => node?.available && !node?.stale).length;
    const nodeDetail = nodes.length ? ` · ${availableNodes}/${nodes.length} nodes current` : "";
    ui.healthHint.textContent = health ? (health.ready ? `Readiness check passed${nodeDetail}` : `Readiness returned HTTP ${health.status}${nodeDetail}`) : "Readiness unavailable";
    ui.pipelineDot.className = `status-dot ${health?.ready ? "live" : health ? "error" : "idle"}`;
    ui.pipelineState.textContent = health?.ready ? "Live" : health ? "Unavailable" : "Waiting";
  }

  function updatePipeline(summary) {
    const byStage = new Map();
    const stages = Array.isArray(summary?.pipeline) ? summary.pipeline : [];
    stages.forEach((item) => {
      const key = String(item?.stage || item?.name || "").toLowerCase();
      if (key) byStage.set(key, item);
    });
    ui.pipelineStages.querySelectorAll(".pipeline-stage").forEach((node) => {
      const item = byStage.get(node.dataset.stage);
      node.classList.remove("ok", "warn", "error");
      const count = node.querySelector("b");
      if (count.textContent !== formatCount(item?.count) && count.textContent !== "—" && !reducedMotion.matches) {
        node.querySelector(".stage-num").animate([{ backgroundColor: "#a3dfba", transform: "scale(.9)" }, { backgroundColor: "#e9f3ed", transform: "scale(1)" }], { duration: 600, easing: "cubic-bezier(.16,1,.3,1)" });
      }
      updateValue(count, formatCount(item?.count));
      if (!item) return;
      const status = String(item.status || "ok").toLowerCase();
      node.classList.add(status === "failed" || status === "error" ? "error" : status === "warning" || status === "pending" || status === "attention" ? "warn" : "ok");
      if (item.detail || item.description) node.querySelector("small").textContent = String(item.detail || item.description);
    });
    if (state.selectedStage && ui.pipelineDrawer.classList.contains("open")) renderPipelineDetail(state.selectedStage);
  }

  function pipelineStatus(status) {
    const value = String(status || "idle").toLowerCase();
    if (value === "failed" || value === "error") return { label: value, className: "error" };
    if (value === "warning" || value === "pending" || value === "attention") return { label: value, className: "warn" };
    return { label: value, className: value === "idle" ? "" : "ok" };
  }

  function pipelineSignals(stage, summary, item) {
    const totals = totalsOf(summary);
    const groups = statusGroups(summary);
    const origins = originsOf(summary);
    const common = [["Current stage count", formatCount(item?.count)], ["Runtime origins", formatCount(origins.length || nodesOf(summary).length)]];
    if (stage === "frame") return [...common, ["Accepted receipts", formatCount(totals.receipts)], ["Observed raw data", formatBytes(totals.raw_bytes)]];
    if (stage === "admit") return [...common, ["Durable receipts", formatCount(totals.receipts)], ["Raw bytes preserved", formatBytes(totals.raw_bytes)]];
    if (stage === "interpret") return [...common, ["Parsed", formatCount(groups.parsed)], ["Partial / failed", formatCount(groups.partial + groups.failed)]];
    if (stage === "commit") return [...common, ["Immutable revisions", formatCount(totals.revisions)], ["Receipts", formatCount(totals.receipts)]];
    return [...common, ["Delivered", formatCount(totals.delivered)], ["Pending", formatCount(totals.pending)], ["Failed", formatCount(totals.failed)]];
  }

  function stageContractCard(label, value) {
    const card = document.createElement("div"); card.className = "stage-contract-card";
    const heading = document.createElement("span"); heading.textContent = label;
    const copy = document.createElement("p"); copy.textContent = value;
    card.append(heading, copy);
    return card;
  }

  function renderPipelineDetail(stage) {
    const definition = PIPELINE_STAGE_DETAILS[stage];
    if (!definition) return;
    const summary = scopedSummary();
    const item = (Array.isArray(summary?.pipeline) ? summary.pipeline : []).find((candidate) => String(candidate?.stage || candidate?.name || "").toLowerCase() === stage);
    const status = pipelineStatus(item?.status);
    const content = document.createDocumentFragment();
    const overview = document.createElement("section"); overview.className = "stage-overview";
    const description = document.createElement("div");
    const title = document.createElement("h3"); title.textContent = `${String(Object.keys(PIPELINE_STAGE_DETAILS).indexOf(stage) + 1).padStart(2, "0")} · ${definition.title}`;
    const summaryText = document.createElement("p"); summaryText.textContent = definition.summary;
    const statusBadge = document.createElement("span"); statusBadge.className = `stage-status${status.className ? ` ${status.className}` : ""}`; statusBadge.textContent = status.label;
    description.append(title, summaryText, statusBadge);
    const count = document.createElement("div"); count.className = "stage-count";
    const countValue = document.createElement("strong"); countValue.textContent = formatCount(item?.count);
    const countLabel = document.createElement("small"); countLabel.textContent = "events observed";
    count.append(countValue, countLabel); overview.append(description, count); content.append(overview);

    const signals = document.createElement("section"); signals.className = "trace-card";
    pipelineSignals(stage, summary, item).forEach(([label, value]) => {
      const row = document.createElement("div"); row.className = "kv";
      const key = document.createElement("span"); key.textContent = label;
      const signalValue = document.createElement("strong"); signalValue.textContent = value;
      row.append(key, signalValue); signals.append(row);
    });
    content.append(signals);

    const contract = document.createElement("section"); contract.className = "stage-contract";
    const contractTitle = document.createElement("h3"); contractTitle.textContent = "Processing contract";
    contract.append(contractTitle, stageContractCard("Input", definition.input), stageContractCard("Output", definition.output), stageContractCard("Guarantee", definition.guarantee));
    content.append(contract);
    ui.pipelineDetail.replaceChildren(content);
  }

  function openPipelineStage(stage, trigger) {
    if (!PIPELINE_STAGE_DETAILS[stage]) return;
    closeTrace(false);
    state.selectedStage = stage; state.previousFocus = trigger;
    ui.pipelineStages.querySelectorAll(".pipeline-stage").forEach((button) => button.setAttribute("aria-expanded", String(button === trigger)));
    renderPipelineDetail(stage);
    ui.pipelineDrawer.classList.add("open"); ui.scrim.classList.add("open"); ui.pipelineDrawer.setAttribute("aria-hidden", "false");
    ui.closePipeline.focus();
    announce(`${PIPELINE_STAGE_DETAILS[stage].title} pipeline stage details opened`);
  }

  function closePipelineStage(restoreFocus = true) {
    ui.pipelineDrawer.classList.remove("open"); ui.pipelineDrawer.setAttribute("aria-hidden", "true");
    ui.pipelineStages.querySelectorAll(".pipeline-stage").forEach((button) => button.setAttribute("aria-expanded", "false"));
    if (!ui.drawer.classList.contains("open")) ui.scrim.classList.remove("open");
    const previous = state.previousFocus; state.previousFocus = null; state.selectedStage = "";
    if (restoreFocus && previous && document.contains(previous)) previous.focus();
  }

  function statusGroups(summary) {
    const source = summary?.status_counts && typeof summary.status_counts === "object" ? summary.status_counts : {};
    let parsed = 0, partial = 0, failed = 0, other = 0;
    Object.entries(source).forEach(([key, raw]) => {
      const count = numberOrNull(raw) || 0;
      const status = key.toUpperCase();
      if (status === "PARSED" || status === "PROCESSED") parsed += count;
      else if (status === "PARTIALLY_PARSED" || status === "PARTIAL") partial += count;
      else if (status.includes("FAIL") || status.includes("ERROR")) failed += count;
      else other += count;
    });
    return { parsed, partial, failed, other };
  }

  function updateDistribution(summary) {
    const groups = statusGroups(summary);
    const values = [groups.parsed, groups.partial, groups.failed, groups.other];
    const total = values.reduce((sum, value) => sum + value, 0);
    ui.donutTotal.textContent = total ? formatCount(total) : "—";
    const labels = ["Parsed", "Partially parsed", "Failed", "Other"];
    const colors = ["#177c50", "#79c49e", "#df6a70", "#abb8b0"];
    let cursor = 0;
    const segments = values.map((value, index) => {
      const start = cursor;
      cursor += total ? (value / total) * 100 : 0;
      return `${colors[index]} ${start}% ${cursor}%`;
    });
    ui.donut.style.background = total ? `conic-gradient(${segments.join(",")})` : "conic-gradient(#e7ede9 0 100%)";
    ui.donut.setAttribute("aria-label", total ? labels.map((label, index) => `${label}: ${values[index]}`).join(", ") : "No status distribution available");
    [...ui.statusList.children].forEach((item, index) => { item.querySelector("strong").textContent = total ? formatCount(values[index]) : "—"; item.querySelector("small").textContent = total ? `${Math.round(values[index] / total * 100)}%` : "—"; });
  }

  function normalizeActivity(summary) {
    if (!Array.isArray(summary?.activity)) return [];
    return summary.activity.map((item) => ({
      label: formatTime(item?.time || item?.bucket || item?.timestamp, false),
      accepted: numberOrNull(item?.accepted) || 0,
      committed: numberOrNull(item?.committed) || 0,
    })).filter((item) => item.label !== "—");
  }

  function drawActivityChart() {
    const canvas = ui.chart;
    const rect = canvas.getBoundingClientRect();
    const ratio = Math.max(1, window.devicePixelRatio || 1);
    const width = Math.max(280, Math.floor(rect.width));
    const height = Math.max(160, Math.floor(rect.height));
    canvas.width = width * ratio;
    canvas.height = height * ratio;
    const context = canvas.getContext("2d");
    context.scale(ratio, ratio);
    context.clearRect(0, 0, width, height);
    const pad = { top: 12, right: 15, bottom: 31, left: 45 };
    const chartWidth = width - pad.left - pad.right;
    const chartHeight = height - pad.top - pad.bottom;
    const maximum = Math.max(1, ...state.activity.flatMap((item) => [item.accepted, item.committed]));
    context.font = '11px "DM Sans", system-ui, sans-serif';
    context.fillStyle = "#66766d";
    context.strokeStyle = "#e7ede9";
    context.lineWidth = 1;
    for (let step = 0; step <= 4; step += 1) {
      const y = pad.top + chartHeight - (chartHeight * step / 4);
      context.beginPath(); context.moveTo(pad.left, y); context.lineTo(width - pad.right, y); context.stroke();
      const value = Math.round(maximum * step / 4);
      context.fillText(new Intl.NumberFormat(undefined, { notation: "compact" }).format(value), 2, y + 3);
    }
    if (state.activity.length === 0) {
      context.fillStyle = "#8293a2";
      context.textAlign = "center";
      context.fillText("No activity data available", pad.left + chartWidth / 2, pad.top + chartHeight / 2);
      context.textAlign = "start";
      return;
    }
    const drawLine = (field, color) => {
      context.beginPath();
      state.activity.forEach((item, index) => {
        const x = pad.left + (state.activity.length === 1 ? chartWidth / 2 : chartWidth * index / (state.activity.length - 1));
        const y = pad.top + chartHeight - chartHeight * item[field] / maximum;
        if (index === 0) context.moveTo(x, y); else context.lineTo(x, y);
      });
      context.strokeStyle = color; context.lineWidth = 2; context.lineJoin = "round"; context.lineCap = "round"; context.stroke();
    };
    drawLine("accepted", "#177c50");
    drawLine("committed", "#438981");
    context.fillStyle = "#66766d";
    context.textAlign = "center";
    const indexes = [...new Set([0, Math.floor((state.activity.length - 1) / 2), state.activity.length - 1])];
    indexes.forEach((index) => {
      const x = pad.left + (state.activity.length === 1 ? chartWidth / 2 : chartWidth * index / (state.activity.length - 1));
      context.fillText(state.activity[index].label, x, height - 9);
    });
    context.textAlign = "start";
    const accepted = state.activity.reduce((sum, item) => sum + item.accepted, 0);
    const committed = state.activity.reduce((sum, item) => sum + item.committed, 0);
    canvas.setAttribute("aria-label", `Event activity: ${accepted} accepted and ${committed} committed in ${state.activity.length} time buckets`);
    ui.chartSummary.textContent = `${formatCount(accepted)} accepted and ${formatCount(committed)} committed across ${state.activity.length} time buckets.`;
  }

  function eventStatusClass(status) {
    const value = String(status || "").toUpperCase();
    if (value === "PARSED" || value === "PROCESSED") return "parsed";
    if (value === "PARTIALLY_PARSED" || value === "PARTIAL") return "partial";
    if (value.includes("FAIL") || value.includes("ERROR")) return "failed";
    return "";
  }

  function textCell(row, value, className = "") {
    const cell = document.createElement("td");
    cell.textContent = value;
    if (className) cell.className = className;
    row.append(cell);
    return cell;
  }

  function prettifyIdentifier(value) {
    return String(value || "").replace(/^generic-/, "").replace(/[-_]+/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
  }

  function sourceIdentity(event) {
    const hint = [event.source_name, event.source_profile_id, event.parser_id].filter(Boolean).join(" ").toLowerCase();
    let family = String(event.source_family || "").trim();
    if (!family) {
      if (/palo|cisco|asa|firewall|network|qradar|\bips\b|\bids\b/.test(hint)) family = "Network";
      else if (/okta|identity|auth|entra/.test(hint)) family = "Identity";
      else if (/aws|cloudtrail|azure|gcp|cloud/.test(hint)) family = "Cloud";
      else if (/windows|crowdstrike|endpoint|edr/.test(hint)) family = "Endpoint";
      else if (/nginx|payment|application|app/.test(hint)) family = "Application";
      else if (/kubernetes|linux|syslog|infra|oracle/.test(hint)) family = "Infrastructure";
      else family = "Other";
    }
    const name = prettifyIdentifier(event.source_name) || prettifyIdentifier(event.source_profile_id) || prettifyIdentifier(event.parser_id) || "Unprofiled source";
    const format = String(event.format || "").trim() || String(event.parser_id || "").replace(/^generic-/, "") || "unknown";
    return { name, family, format: format.toUpperCase() };
  }

  function replaceFilterOptions(select, values, label, selected) {
    const fragment = document.createDocumentFragment();
    const all = document.createElement("option"); all.value = ""; all.textContent = label; fragment.append(all);
    values.forEach((value) => { const option = document.createElement("option"); option.value = value; option.textContent = value; fragment.append(option); });
    select.replaceChildren(fragment); select.value = values.includes(selected) ? selected : "";
  }

  function populateEventFilters() {
    const families = [...new Set(state.events.map((item) => sourceIdentity(item).family))].sort();
    const formats = [...new Set(state.events.map((item) => sourceIdentity(item).format))].sort();
    const statuses = [...new Set(state.events.map((item) => String(item.status || "Unknown")))].sort();
    replaceFilterOptions(ui.sourceFamilyFilter, families, "All sources", state.sourceFamily);
    replaceFilterOptions(ui.formatFilter, formats, "All formats", state.format);
    replaceFilterOptions(ui.statusFilter, statuses, "All statuses", state.status);
    state.sourceFamily = ui.sourceFamilyFilter.value; state.format = ui.formatFilter.value; state.status = ui.statusFilter.value;
  }

  function filteredEvents() {
    const query = state.search.toLowerCase();
    const filtered = state.events.filter((event) => {
      const identity = sourceIdentity(event);
      if (state.sourceFamily && identity.family !== state.sourceFamily) return false;
      if (state.format && identity.format !== state.format) return false;
      if (state.status && String(event.status || "Unknown") !== state.status) return false;
      if (!query) return true;
      return [identity.name, identity.family, identity.format, event.transport, event.action, event.status, event.listener_id]
        .filter(Boolean).join(" ").toLowerCase().includes(query);
    });
    return state.eventsNewestFirst ? filtered : [...filtered].reverse();
  }

  function renderSourceCoverage() {
    ui.sourceCoverage.replaceChildren();
    const groups = new Map();
    state.events.forEach((event) => { const family = sourceIdentity(event).family; groups.set(family, (groups.get(family) || 0) + 1); });
    ui.sourceCoverageTotal.textContent = String(groups.size);
    if (groups.size === 0) {
      const empty = document.createElement("p"); empty.className = "node-empty"; empty.textContent = state.connected ? "No sources in this event window." : "Source families appear here."; ui.sourceCoverage.append(empty);
      ui.sourceCoverageSummary.textContent = state.connected ? "No recent source metadata was returned." : "Connect to inspect source diversity.";
      return;
    }
    [...groups.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).forEach(([family, count]) => {
      const button = document.createElement("button"); button.type = "button"; button.className = `source-family${state.sourceFamily === family ? " selected" : ""}`;
      button.setAttribute("aria-pressed", state.sourceFamily === family ? "true" : "false");
      const mark = document.createElement("i"); mark.className = "family-mark"; mark.setAttribute("aria-hidden", "true");
      const label = document.createElement("span"); label.textContent = family;
      const value = document.createElement("strong"); value.textContent = String(count);
      button.append(mark, label, value);
      button.addEventListener("click", () => { state.sourceFamily = state.sourceFamily === family ? "" : family; ui.sourceFamilyFilter.value = state.sourceFamily; renderEvents(); renderSourceCoverage(); announce(state.sourceFamily ? `Showing ${family} events` : "Showing all source families"); });
      ui.sourceCoverage.append(button);
    });
    ui.sourceCoverageSummary.textContent = `${state.events.length} recent events across ${groups.size} source ${groups.size === 1 ? "family" : "families"}. Select a family to filter.`;
  }

  function renderEvents() {
    const focusedRevision = ui.eventsBody.contains(document.activeElement) ? document.activeElement.closest("tr")?.dataset.revision : null;
    const returnRevision = state.previousFocus?.closest("tr")?.dataset.revision;
    const highlightArrivals = state.seenRevisions.size > 0;
    const incoming = new Set(state.events.filter((event) => !state.seenRevisions.has(event.revision_id)).map((event) => event.revision_id));
    state.events.forEach((event) => state.seenRevisions.add(event.revision_id));
    while (state.seenRevisions.size > 200) state.seenRevisions.delete(state.seenRevisions.values().next().value);
    ui.eventsBody.replaceChildren();
    const displayed = filteredEvents();
    if (displayed.length === 0) {
      const row = document.createElement("tr"); row.className = "empty-row";
      const message = state.events.length ? "No events match the selected filters." : state.connected ? "No events were returned for this tenant." : "Connect to load event metadata.";
      const cell = textCell(row, message); cell.colSpan = 7; ui.eventsBody.append(row); ui.eventCount.textContent = "0 events shown";
      if (focusedRevision) ui.pauseStream.focus({ preventScroll: true });
      return;
    }
    displayed.forEach((event) => {
      const identity = sourceIdentity(event);
      const row = document.createElement("tr"); row.dataset.revision = event.revision_id || "";
      if (highlightArrivals && incoming.has(event.revision_id)) row.classList.add("new-event");
      if (state.selectedRevision === event.revision_id) row.classList.add("selected");
      textCell(row, formatTime(event.received_at, false));
      const sourceCell = document.createElement("td");
      const source = document.createElement("div"); source.className = "source-cell";
      const monogram = document.createElement("span"); monogram.className = "source-monogram"; monogram.textContent = identity.name.split(/\s+/).map((part) => part[0]).join("").slice(0, 2).toUpperCase();
      const copy = document.createElement("span"); const sourceName = document.createElement("strong"); sourceName.textContent = identity.name; sourceName.title = identity.name;
      const family = document.createElement("small"); family.textContent = identity.family; copy.append(sourceName, family); source.append(monogram, copy); sourceCell.append(source); row.append(sourceCell);
      const formatCell = document.createElement("td"); const format = document.createElement("span"); format.className = "format-tag"; format.textContent = identity.format; formatCell.append(format); row.append(formatCell);
      textCell(row, prettifyIdentifier(event.transport) || "Indexed");
      const statusCell = document.createElement("td"); const status = document.createElement("span"); status.className = `status-pill ${eventStatusClass(event.status)}`; status.textContent = String(event.status || "Unknown").replaceAll("_", " "); statusCell.append(status); row.append(statusCell);
      textCell(row, event.action || "—");
      const action = document.createElement("td"); const button = document.createElement("button"); button.type = "button"; button.className = "inspect-button"; button.textContent = "Inspect";
      button.setAttribute("aria-label", `Inspect event ${event.revision_id || event.receipt_id || "metadata"}`); button.addEventListener("click", () => inspectEvent(event, button));
      action.append(button); row.append(action); ui.eventsBody.append(row);
      if (returnRevision === event.revision_id) state.previousFocus = button;
      if (focusedRevision === event.revision_id) button.focus({ preventScroll: true });
    });
    if (focusedRevision && !ui.eventsBody.contains(document.activeElement)) ui.pauseStream.focus({ preventScroll: true });
    ui.eventCount.textContent = `${formatCount(displayed.length)} of ${formatCount(state.events.length)} event${state.events.length === 1 ? "" : "s"} shown`;
  }

  function detailRow(label, value) {
    const row = document.createElement("div"); row.className = "kv";
    const key = document.createElement("span"); key.textContent = label;
    const data = document.createElement("strong"); data.textContent = value === undefined || value === null || value === "" ? "—" : String(value);
    row.append(key, data); return row;
  }

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

  function renderTrace(event, envelope, receiptResponse) {
    const receipt = receiptResponse?.receipt || envelope?.receipt || {};
    const raw = receipt.raw || envelope?.raw || {};
    const processing = envelope?.processing || {};
    const parser = processing.parser || receiptResponse?.revisions?.find((item) => item.revision_id === event.revision_id)?.parser || {};
    const canonical = envelope?.event || {};
    const provenanceCount = envelope?.provenance && typeof envelope.provenance === "object" ? Object.keys(envelope.provenance).length : 0;
    const content = document.createDocumentFragment();
    const warning = document.createElement("p"); warning.className = "trace-warning";
    warning.textContent = "Raw evidence is not fetched or displayed by the dashboard. Use the authorized raw API only when evidence access is required.";
    content.append(warning);
    content.append(traceSection("Durable receipt", [
      ["Receipt ID", receipt.id || event.receipt_id], ["Tenant", receipt.tenant_id || event.tenant_id],
      ["Environment", receipt.environment_id || event.environment_id], ["Instance", receipt.instance_id || event.instance_id],
      ["Received", formatTime(receipt.received_at || event.received_at)], ["Transport", receipt.transport], ["Listener", receipt.listener_id],
    ], receipt.id || event.receipt_id));
    content.append(traceSection("Raw evidence metadata", [
      ["SHA-256", raw.sha256 || event.raw_sha256], ["Size", formatBytes(raw.size_bytes)],
      ["Available", raw.available === true ? "Yes" : raw.available === false ? "No" : "—"], ["Encoding", raw.encoding_hint],
    ]));
    content.append(traceSection("Processing revision", [
      ["Revision ID", processing.revision_id || event.revision_id], ["Status", processing.status || event.status],
      ["Parser", parser.id ? `${parser.id}${parser.version ? ` ${parser.version}` : ""}` : "—"],
      ["Pipeline", processing.pipeline_version], ["Mapping", processing.mapping_version || "Not configured"], ["Completed", formatTime(processing.timestamps?.completed_at)],
      ["Issues", Array.isArray(processing.issues) ? processing.issues.length : "—"],
      ...((processing.issues || []).map((issue) => [issue.code, issue.source_path || issue.stage])),
    ], processing.revision_id || event.revision_id));
    content.append(traceSection("Canonical envelope", [
      ["Schema", envelope?.schema_version], ["Class UID", canonical.class_uid], ["Class", canonical.class_name], ["Action", canonical.action],
      ["Source IP", canonical.src_endpoint?.ip], ["Destination IP", canonical.dst_endpoint?.ip], ["Provenance fields", provenanceCount],
      ["Quality score", numberOrNull(envelope?.quality?.score) === null ? "—" : `${Math.round(envelope.quality.score * 100)}%`],
    ]));
    ui.traceContent.replaceChildren(content);
  }

  function traceMetadataURL(provided, fallback) {
    const tracePath = /^\/api\/v1\/(?:events|receipts)\/[^/?#]+$/;
    const federatedTracePath = /^\/api\/v1\/federation\/[^/?#]+\/(?:events|receipts)\/[^/?#]+$/;
    if (typeof provided === "string" && (tracePath.test(provided) || federatedTracePath.test(provided))) return provided;
    return fallback;
  }

  async function inspectEvent(event, trigger) {
    if (!event.revision_id || !event.receipt_id || !state.token) return;
    closePipelineStage(false);
    state.selectedRevision = event.revision_id;
    state.previousFocus = trigger;
    renderEvents();
    ui.drawer.classList.add("open"); ui.scrim.classList.add("open"); ui.drawer.setAttribute("aria-hidden", "false");
    ui.traceContent.replaceChildren();
    const loading = document.createElement("p"); loading.className = "trace-loading"; loading.textContent = "Loading trace metadata…"; ui.traceContent.append(loading);
    ui.closeTrace.focus();
    const traceTenant = state.tenant;
    try {
      const [envelope, receipt] = await Promise.all([
        fetchJSON(traceMetadataURL(event.event_url, `/api/v1/events/${encodeURIComponent(event.revision_id)}`)),
        fetchJSON(traceMetadataURL(event.receipt_url, `/api/v1/receipts/${encodeURIComponent(event.receipt_id)}`)),
      ]);
      if (traceTenant !== state.tenant || state.selectedRevision !== event.revision_id || !ui.drawer.classList.contains("open")) return;
      renderTrace(event, envelope, receipt);
      announce(`Trace loaded for revision ${event.revision_id}`);
    } catch (error) {
      if (traceTenant !== state.tenant || state.selectedRevision !== event.revision_id || !ui.drawer.classList.contains("open")) return;
      const message = document.createElement("div"); message.className = "trace-error";
      message.textContent = `Trace metadata could not be loaded: ${describeError(error)}`;
      const retry = document.createElement("button"); retry.type = "button"; retry.className = "copy-button"; retry.textContent = "Retry trace";
      retry.addEventListener("click", () => inspectEvent(event, trigger));
      ui.traceContent.replaceChildren(message, retry);
    }
  }

  function closeTrace(restoreFocus = true) {
    ui.drawer.classList.remove("open"); ui.scrim.classList.remove("open"); ui.drawer.setAttribute("aria-hidden", "true");
    const previous = state.previousFocus; state.previousFocus = null;
    if (restoreFocus) (previous && document.contains(previous) ? previous : ui.pauseStream).focus({ preventScroll: true });
  }

  function describeError(error) {
    if (error?.name === "AbortError") return "Request cancelled";
    const suffix = error?.requestID ? ` (request ${error.requestID})` : "";
    if (error?.status === 401) return `Token was rejected${suffix}`;
    if (error?.status === 403) return `Token does not grant access to this tenant${suffix}`;
    if (error?.status === 404) return `Requested metadata was not found${suffix}`;
    return `${error?.message || "Request failed"}${suffix}`;
  }

  function applySummary(summary, health) {
    state.summary = summary;
    state.health = health;
    populateScopeFilters(summary);
    applyScope(true);
    ui.lastUpdated.textContent = formatTime(summary?.generated_at || new Date().toISOString());
  }

  function resetData() {
    live.reset();
    state.summary = null; state.health = null; state.fallbackEvents = []; state.activity = []; state.events = []; state.eventsNewestFirst = true; state.selectedRevision = "";
    state.sourceFamily = ""; state.format = ""; state.status = ""; state.search = "";
    state.seenRevisions.clear();
    ui.eventSearch.value = "";
    element("globalSearch").value = "";
    ui.sortTime.textContent = "Time ↓";
    replaceSelectOptions(ui.environmentFilter, [], "All environments", "");
    replaceSelectOptions(ui.instanceFilter, [], "All instances", "");
    ui.nodeGroups.replaceChildren();
    const empty = document.createElement("p"); empty.className = "node-empty"; empty.textContent = "Node availability will appear after connection."; ui.nodeGroups.append(empty);
    ui.scopeSummary.textContent = "Connect to load runtime origins.";
    populateEventFilters(); updateMetrics(null, null); updatePipeline(null); updateDistribution(null); drawActivityChart(); renderEvents(); renderSourceCoverage();
    ui.lastUpdated.textContent = "—"; ui.eventScope.textContent = "Newest-first summary window";
  }

  async function refresh({ quiet = false } = {}) {
    if (!state.tenant || !state.token) return;
    if (state.refreshController) state.refreshController.abort();
    const controller = new AbortController(); state.refreshController = controller;
    const timeout = window.setTimeout(() => controller.abort(), 8_000);
    state.loading = true;
    ui.refresh.classList.add("loading"); ui.refresh.disabled = true;
    const tenant = encodeURIComponent(state.tenant);
    const jobs = [
      fetchHealth(controller.signal),
      fetchJSON(`/api/v1/dashboard/summary?tenant_id=${tenant}`, { signal: controller.signal }),
      fetchJSON(`/api/v1/events?tenant_id=${tenant}&limit=50`, { signal: controller.signal }),
    ];
    const results = await Promise.allSettled(jobs);
    window.clearTimeout(timeout);
    try {
      if (state.refreshController !== controller) return;
      if (controller.signal.aborted) throw new Error("Dashboard request timed out. Check the service and refresh.");
      const health = results[0].status === "fulfilled" ? results[0].value : null;
      const summaryResult = results[1];
      const eventsResult = results[2];
      if (summaryResult.status === "rejected" && eventsResult.status === "rejected") {
        throw summaryResult.reason?.status ? summaryResult.reason : eventsResult.reason;
      }
      const summary = summaryResult.status === "fulfilled" ? summaryResult.value : null;
      const page = eventsResult.status === "fulfilled" ? eventsResult.value : { items: [] };
      const recentEvents = Array.isArray(summary?.recent_events) ? summary.recent_events : null;
      state.connected = true;
      state.fallbackEvents = Array.isArray(page.items) ? page.items : [];
      state.events = recentEvents || state.fallbackEvents;
      applySummary(summary, health);
      if (!summary || !health?.ready) live.unavailable();
      setConnection(health?.ready ? "live" : "error", health?.ready ? "Connected" : "Connected · not ready", state.tenant);
      if (health?.ready && !quiet) element("connection").open = false;
      ui.sidebarTenant.textContent = state.tenant;
      const partial = summaryResult.status === "rejected" || eventsResult.status === "rejected";
      showNotice(partial ? "Connected, but part of the dashboard data is temporarily unavailable." : "", partial ? "error" : "");
      if (!quiet) announce(`Dashboard refreshed for tenant ${state.tenant}`);
    } catch (error) {
      if (error?.name !== "AbortError") {
        state.connected = false;
        live.unavailable();
        setConnection("error", "Connection failed", state.tenant || "No tenant");
        showNotice(describeError(error), "error");
        announce(`Dashboard refresh failed: ${describeError(error)}`);
      }
    } finally {
      if (state.refreshController === controller) {
        state.refreshController = null; state.loading = false;
        ui.refresh.classList.remove("loading"); ui.refresh.disabled = false;
      }
    }
  }

  function scheduleRefresh() {
    if (state.timer) window.clearInterval(state.timer);
    state.timer = null;
    if (!state.streamPaused) {
      state.timer = window.setInterval(() => {
        if (!document.hidden && state.tenant && state.token && !state.loading) refresh({ quiet: true });
      }, REFRESH_INTERVAL_MS);
    }
  }

  function toggleStream() {
    state.streamPaused = !state.streamPaused;
    if (state.streamPaused) {
      live.stop("Simulation stopped because dashboard refresh was paused. Accepted events remain stored.");
      cancelRefresh();
    }
    ui.pauseStream.textContent = state.streamPaused ? "Resume" : "Pause";
    ui.pauseStream.setAttribute("aria-pressed", state.streamPaused ? "true" : "false");
    ui.streamState.textContent = state.streamPaused ? "Paused" : "Live";
    const dot = ui.streamState.previousElementSibling;
    if (dot) dot.className = `status-dot ${state.streamPaused ? "idle" : "live"}`;
    scheduleRefresh(); announce(state.streamPaused ? "Live event refresh paused" : "Live event refresh resumed");
    if (!state.streamPaused && state.tenant && state.token) refresh({ quiet: true });
  }

  function connect(event) {
    event.preventDefault();
    if (!ui.form.reportValidity()) return;
    cancelRefresh();
    state.connected = false;
    closePipelineStage(false); closeTrace(false); resetData();
    state.tenant = ui.tenant.value.trim(); state.token = ui.token.value;
    setSession(STORAGE_TENANT, state.tenant); setSession(STORAGE_TOKEN, state.token);
    state.events = [];
    setConnection("idle", "Connecting", state.tenant);
    showNotice("Loading tenant-scoped pipeline data…");
    refresh(); scheduleRefresh();
  }

  function disconnect() {
    cancelRefresh();
    state.tenant = ""; state.token = ""; state.connected = false;
    setSession(STORAGE_TENANT, ""); setSession(STORAGE_TOKEN, "");
    ui.tenant.value = ""; ui.token.value = ""; ui.sidebarTenant.textContent = "No tenant";
    setConnection("idle", "Not connected", "Enter tenant and token");
    showNotice("Connection details cleared. Enter a tenant and token to reconnect.");
    closePipelineStage(false); closeTrace(false); resetData(); scheduleRefresh(); ui.tenant.focus();
  }

  function cancelRefresh() {
    state.refreshController?.abort(); state.refreshController = null; state.loading = false;
    ui.refresh.classList.remove("loading"); ui.refresh.disabled = false;
  }

  ui.form.addEventListener("submit", connect);
  ui.disconnect.addEventListener("click", disconnect);
  ui.refresh.addEventListener("click", () => refresh());
  ui.pauseStream.addEventListener("click", () => toggleStream());
  ui.sourceFamilyFilter.addEventListener("change", () => { state.sourceFamily = ui.sourceFamilyFilter.value; renderEvents(); renderSourceCoverage(); });
  ui.formatFilter.addEventListener("change", () => { state.format = ui.formatFilter.value; renderEvents(); });
  ui.statusFilter.addEventListener("change", () => { state.status = ui.statusFilter.value; renderEvents(); });
  ui.eventSearch.addEventListener("input", () => { state.search = ui.eventSearch.value.trim(); element("globalSearch").value = ui.eventSearch.value; renderEvents(); });
  element("globalSearch").addEventListener("input", (event) => { state.search = event.target.value.trim(); ui.eventSearch.value = event.target.value; renderEvents(); });
  element("globalSearch").addEventListener("keydown", (event) => { if (event.key === "Enter") { element("recent").scrollIntoView({ block: "start" }); ui.eventSearch.focus({ preventScroll: true }); } });
  ui.clearFilters.addEventListener("click", () => { state.sourceFamily = ""; state.format = ""; state.status = ""; state.search = ""; ui.eventSearch.value = ""; element("globalSearch").value = ""; populateEventFilters(); renderEvents(); renderSourceCoverage(); announce("Event filters cleared"); });
  ui.sortTime.addEventListener("click", () => { state.eventsNewestFirst = !state.eventsNewestFirst; ui.sortTime.textContent = state.eventsNewestFirst ? "Time ↓" : "Time ↑"; renderEvents(); });
  ui.environmentFilter.addEventListener("change", () => { populateScopeFilters(state.summary); applyScope(); });
  ui.instanceFilter.addEventListener("change", applyScope);
  ui.pipelineStages.addEventListener("click", (event) => {
    const trigger = event.target.closest(".pipeline-stage");
    if (trigger) openPipelineStage(trigger.dataset.stage, trigger);
  });
  ui.closePipeline.addEventListener("click", () => closePipelineStage());
  ui.closeTrace.addEventListener("click", closeTrace);
  ui.scrim.addEventListener("click", () => {
    if (ui.pipelineDrawer.classList.contains("open")) closePipelineStage();
    else closeTrace();
  });
  document.addEventListener("keydown", (event) => {
    const activeDrawer = ui.pipelineDrawer.classList.contains("open") ? ui.pipelineDrawer : ui.drawer.classList.contains("open") ? ui.drawer : null;
    if (!activeDrawer && event.key === "/" && !event.ctrlKey && !event.metaKey && !event.altKey && !/INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName)) { event.preventDefault(); element("globalSearch").focus(); }
    if (event.key === "Escape") element("connection").open = false;
    if (event.key === "Escape" && activeDrawer) {
      if (activeDrawer === ui.pipelineDrawer) closePipelineStage();
      else closeTrace();
    }
    if (event.key === "Tab" && activeDrawer) {
      const focusable = [...activeDrawer.querySelectorAll("button:not(:disabled), [href], input:not(:disabled), [tabindex]:not([tabindex='-1'])")];
      if (!focusable.length) return;
      const first = focusable[0], last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    }
  });
  document.addEventListener("visibilitychange", () => { if (!document.hidden && !state.streamPaused && state.tenant && state.token) refresh({ quiet: true }); });
  window.addEventListener("resize", drawActivityChart, { passive: true });

  document.querySelectorAll(".nav-link").forEach((link) => link.addEventListener("click", () => {
    document.querySelectorAll(".nav-link").forEach((item) => { item.classList.toggle("active", item === link); item.removeAttribute("aria-current"); });
    link.setAttribute("aria-current", "location");
    if (link.hash === "#connection") { element("connection").open = true; ui.tenant.focus(); }
  }));
  if (!reducedMotion.matches) {
    const panels = document.querySelectorAll(".metric-strip article, .command-grid > *, .insights-grid > *, .pipeline-panel");
    panels.forEach((panel, index) => panel.animate([{ opacity: .3, transform: "translateY(12px)" }, { opacity: 1, transform: "translateY(0)" }], { duration: 650, delay: Math.min(index * 45, 270), easing: "cubic-bezier(.16,1,.3,1)" }));
  }
  document.fonts.ready.then(drawActivityChart);

  ui.tenant.value = getSession(STORAGE_TENANT);
  ui.token.value = getSession(STORAGE_TOKEN);
  resetData();
  setConnection("idle", "Not connected", "Enter tenant and token");
  if (ui.tenant.value && ui.token.value) {
    state.tenant = ui.tenant.value; state.token = ui.token.value;
    setConnection("idle", "Reconnecting", state.tenant);
    refresh({ quiet: true });
  }
  scheduleRefresh();
})();
