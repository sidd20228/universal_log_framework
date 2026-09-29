/* Self-contained, offline simulation and live telemetry. */
(function (root) {
  "use strict";
  const SOURCES = [
    ["Palo Alto Firewall", "Network", "json"], ["Windows Security", "Endpoint", "json"],
    ["AWS CloudTrail", "Cloud", "json"], ["Okta System Log", "Identity", "json"],
    ["Kubernetes Audit", "Infrastructure", "json"], ["CrowdStrike Falcon", "Endpoint", "json"],
    ["PaymentApp", "Application", "json"], ["Cisco ASA", "Network", "cef"],
    ["IBM QRadar IPS", "Network", "leef"], ["NGINX Access", "Application", "kv"],
    ["Linux Syslog", "Infrastructure", "syslog"], ["Oracle Audit", "Infrastructure", "xml"],
    ["SaaS Audit Export", "Application", "csv"], ["Microsoft Entra ID", "Identity", "json"],
  ];
  function sample(sequence, scenario = "all", now = new Date()) {
    const families = { security: ["Network", "Identity"], operations: ["Cloud", "Infrastructure", "Application"], endpoint: ["Endpoint"] };
    const sources = SOURCES.filter((source) => !families[scenario] || families[scenario].includes(source[1]));
    const [name, family, format] = sources[sequence % sources.length];
    const stamp = now.toISOString(), src = `10.24.${sequence % 8}.${20 + sequence % 200}`, dst = `198.51.100.${10 + sequence % 200}`;
    const action = sequence % 3 === 0 ? "deny" : "allow";
    let payload;
    switch (format) {
      case "cef": payload = `CEF:0|Cisco|ASA|9.18|106023|Synthetic connection event|6|src=${src} dst=${dst} dpt=443 proto=TCP act=${action} msg=synthetic-live-${stamp}`; break;
      case "leef": payload = `LEEF:2.0|IBM|QRadar IPS|7.5|200|^|src=${src}^dst=${dst}^dstPort=443^proto=TCP^action=${action}^synthetic=true^time=${stamp}`; break;
      case "kv": payload = `time=${stamp} source_name="NGINX Access" source_family=Application src=${src} dst=${dst} method=GET path=/health status=200 action=${action} synthetic=true`; break;
      case "syslog": payload = `<134>1 ${stamp} demo-host linux-syslog ${1000 + sequence} LIVE [demo source_name="Linux Syslog" source_family="Infrastructure" src="${src}" action="${action}"] synthetic live event`; break;
      case "xml": payload = `<?xml version="1.0"?><event synthetic="true"><timestamp>${stamp}</timestamp><source_name>Oracle Audit</source_name><source_family>Infrastructure</source_family><source_ip>${src}</source_ip><action>${action}</action></event>`; break;
      case "csv": payload = `timestamp,source_name,source_family,src_ip,dst_ip,action,synthetic\n${stamp},SaaS Audit Export,Application,${src},${dst},${action},true\n`; break;
      default: payload = JSON.stringify({ timestamp: stamp, source_name: name, source_family: family, action, src_ip: src, dst_ip: dst, user: `demo-user-${sequence % 7}`, severity: ["low", "medium", "high"][sequence % 3], synthetic: true });
    }
    return { name, family, format, payload, time: now.getTime() };
  }

  function liveTotals(summary) {
    if (!summary) return null;
    const origins = [...(summary.origins || []), ...(summary.nodes || [])];
    return origins.some((origin) => origin.available === false || origin.stale || origin.retained) ? null : summary.totals;
  }

  class Telemetry {
    constructor() { this.reset(); }
    reset() { this.points = []; this.previous = null; }
    add(totals, time) {
      const keys = ["receipts", "revisions", "delivered", "pending", "failed"];
      if (!totals || keys.some((key) => typeof totals[key] !== "number" || !Number.isFinite(totals[key]) || totals[key] < 0)) {
        this.previous = null; this.points = []; return;
      }
      const previous = this.previous;
      this.previous = { ...totals, time };
      if (!previous || time <= previous.time) return;
      // Gaps and counter resets begin a new measurement, never a fabricated spike.
      if (time - previous.time > 15_000 || keys.slice(0, 3).some((key) => totals[key] < previous[key])) { this.points = []; return; }
      const seconds = (time - previous.time) / 1000;
      this.points.push({ time, accepted: (totals.receipts - previous.receipts) / seconds, processed: (totals.revisions - previous.revisions) / seconds, delivered: (totals.delivered - previous.delivered) / seconds, pending: totals.pending, failed: totals.failed });
      this.points = this.points.filter((point) => time - point.time <= 120_000).slice(-60);
    }
  }

  class Simulation {
    constructor({ send, onInput, onState, now = Date.now, later = (fn, delay) => setTimeout(fn, delay), cancel = (id) => clearTimeout(id) }) {
      Object.assign(this, { send, onInput, onState, now, later, cancel });
      this.running = false; this.generation = 0; this.accepted = 0;
    }
    start(scenario, speed) {
      if (this.running) return;
      this.running = true; this.accepted = 0; this.sequence = 0; this.started = this.now(); this.generation++;
      this.scenario = scenario; this.speed = [1, 2, 4].includes(Number(speed)) ? Number(speed) : 1;
      this.deadline = this.later(() => this.stop("Session complete. Accepted events remain stored."), 180_000);
      this.onState("Running · synthetic inputs, real processing. HTTP listener tenant is configured by the server.");
      void this.tick(this.generation);
    }
    stop(message = "Stopped. Accepted events remain stored.") {
      this.running = false; this.generation++;
      this.cancel(this.timer); this.cancel(this.deadline); this.cancel(this.timeout);
      this.controller?.abort(); this.controller = null;
      this.onState(message);
    }
    async tick(generation) {
      if (!this.running || generation !== this.generation) return;
      if (this.now() - this.started >= 180_000) { this.stop("Session complete. Accepted events remain stored."); return; }
      const started = this.now(), input = sample(this.sequence++, this.scenario, new Date(started));
      const controller = new AbortController(); this.controller = controller;
      const timeout = this.later(() => controller.abort(), 8000); this.timeout = timeout;
      try {
        const result = await this.send(input.payload, controller.signal);
        if (!this.running || generation !== this.generation) return;
        if (!result?.receipt_id) throw new Error("No durable receipt returned");
        this.accepted++; this.onInput({ ...input, receipt: result.receipt_id });
      } catch (error) {
        if (!this.running || generation !== this.generation) return;
        const reason = error?.status === 403 ? "This token cannot ingest into the configured listener tenant." : error?.status === 401 ? "Token rejected. Reconnect before starting again." : error?.name === "AbortError" ? "Request timed out; its admission outcome is unknown. Check receipts before restarting." : `Ingestion failed: ${error.message || "network error"}. Check the service before restarting.`;
        this.stop(reason); return;
      } finally {
        this.cancel(timeout);
        if (this.controller === controller) this.controller = null;
      }
      if (this.running && generation === this.generation) this.timer = this.later(() => void this.tick(generation), Math.max(0, 1000 / this.speed - (this.now() - started)));
    }
  }

  function mount({ ingest, connection, inspect, identity, filter, resume }) {
    const el = (id) => document.getElementById(id);
    const ui = Object.fromEntries(["simulationStart", "simulationStop", "simulationScenario", "simulationSpeed", "simulationBadge", "simulationMessage", "simulationAccepted", "simulationClock", "sessionRing", "heroSimulation", "liveRateChart", "liveQueueChart", "liveRateDetail", "liveQueueDetail", "liveRateValue", "liveQueueValue", "liveSourceCount", "liveSourceMix", "liveLogFeed", "consoleFollow", "consoleClear", "consoleCount", "consoleState"].map((id) => [id, el(id)]));
    const telemetry = new Telemetry();
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
    let renderedReceipts = new Set(), clockTimer = null;
    let inputs = [], following = true, scope = "", selected = -1, lastMessage = "Connect to send synthetic logs through this server’s configured HTTP listener. Events are persisted in its configured tenant.";
    const timeText = (time) => new Date(time).toLocaleTimeString([], { hour12: false });
    function controls() {
      ui.simulationStart.disabled = !connection() || simulation.running;
      ui.simulationStop.disabled = !simulation.running;
      ui.simulationScenario.disabled = simulation.running; ui.simulationSpeed.disabled = simulation.running;
      ui.simulationBadge.textContent = simulation.running ? "Simulation running" : simulation.accepted ? "Session stopped" : "Ready to simulate";
      ui.simulationBadge.classList.toggle("running", simulation.running);
      ui.simulationMessage.textContent = connection() && !simulation.running && !simulation.accepted ? "Ready · inputs persist in this server’s configured HTTP tenant." : lastMessage;
      ui.simulationAccepted.textContent = `${simulation.accepted} accepted`;
      const remaining = simulation.running ? Math.max(0, Math.ceil((180_000 - (Date.now() - simulation.started)) / 1000)) : 180;
      ui.simulationClock.textContent = `${String(Math.floor(remaining / 60)).padStart(2, "0")}:${String(remaining % 60).padStart(2, "0")}`;
      ui.simulationClock.nextElementSibling.textContent = simulation.running ? "remaining" : "session limit";
      ui.sessionRing.setAttribute("stroke-dashoffset", String(100 - remaining / 180 * 100));
      ui.heroSimulation.querySelector("span").textContent = simulation.running ? "Stop simulation" : "Run simulation";
    }
    const simulation = new Simulation({ send: ingest, onInput(input) { inputs.unshift(input); inputs = inputs.slice(0, 80); renderFeed(); controls(); }, onState(message) {
      lastMessage = message; controls(); renderFeed();
      if (clockTimer) window.clearInterval(clockTimer);
      clockTimer = simulation.running ? window.setInterval(controls, 1000) : null;
    } });
    function renderFeed() {
      ui.consoleCount.textContent = `${inputs.length} buffered inputs`;
      ui.consoleState.textContent = following ? simulation.running ? "Following incoming inputs" : "Session idle · retained input history" : simulation.running ? "Console frozen · ingestion continues" : "Console frozen · session stopped";
      if (!following) return;
      const fragment = document.createDocumentFragment();
      if (!inputs.length) { const li = document.createElement("li"); li.className = "console-empty"; li.textContent = "Start a simulation to watch incoming payloads. All samples are synthetic and are sent through real HTTP ingestion."; fragment.append(li); }
      for (const input of inputs) {
        const li = document.createElement("li"); li.className = "log-line";
        if (!renderedReceipts.has(input.receipt)) li.classList.add("new-arrival");
        const time = document.createElement("time"); time.dateTime = new Date(input.time).toISOString(); time.textContent = timeText(input.time);
        const source = document.createElement("strong"); source.textContent = input.name;
        const format = document.createElement("span"); format.className = "log-format"; format.textContent = input.format.toUpperCase();
        const status = document.createElement("button"); status.type = "button"; status.className = "log-status"; status.dataset.receipt = input.receipt;
        status.textContent = input.event ? String(input.event.status || "Processed").replaceAll("_", " ") : "ACCEPTED";
        status.disabled = !input.event;
        status.title = input.event ? `Inspect receipt ${input.receipt}` : `Receipt ${input.receipt}; processing has not yet been observed in this scope`;
        status.addEventListener("click", () => inspect(input.event, ui.consoleFollow));
        const code = document.createElement("code"); code.textContent = input.payload.replaceAll("\n", " ↵ ").slice(0, 340); code.title = `Receipt ${input.receipt}`;
        li.append(time, source, format, status, code); fragment.append(li);
      }
      const feed = ui.liveLogFeed, oldHeight = feed.scrollHeight, oldTop = feed.scrollTop;
      const focusedReceipt = feed.contains(document.activeElement) ? document.activeElement.dataset.receipt : null;
      feed.replaceChildren(fragment);
      renderedReceipts = new Set(inputs.map((input) => input.receipt));
      if (focusedReceipt) ([...feed.querySelectorAll("button")].find((button) => button.dataset.receipt === focusedReceipt) || ui.consoleFollow).focus({ preventScroll: true });
      if (oldTop > 5) feed.scrollTop = oldTop + feed.scrollHeight - oldHeight;
    }
    function draw(canvas, keys, colors, detail) {
      const rect = canvas.getBoundingClientRect();
      const width = Math.max(220, rect.width), height = Math.max(80, rect.height), ratio = window.devicePixelRatio || 1;
      canvas.width = width * ratio; canvas.height = height * ratio;
      const ctx = canvas.getContext("2d"); ctx.scale(ratio, ratio); ctx.clearRect(0, 0, width, height);
      const points = telemetry.points, max = Math.max(1, ...points.flatMap((point) => keys.map((key) => point[key])));
      const left = 32, right = width - 12, top = 12, bottom = height - 25;
      ctx.font = '11px "DM Sans", system-ui'; ctx.fillStyle = "#66766d";
      for (let i = 0; i <= 4; i++) {
        const y = top + (bottom - top) * i / 4;
        ctx.strokeStyle = "#e7ede9"; ctx.beginPath(); ctx.moveTo(left, y); ctx.lineTo(right, y); ctx.stroke();
        ctx.fillText((max * (1 - i / 4)).toFixed(max < 5 ? 1 : 0), 2, y + 3);
      }
      const newest = points.at(-1)?.time || Date.now(), oldest = newest - 120_000;
      const x = (point) => left + (right - left) * (point.time - oldest) / 120_000;
      keys.forEach((key, index) => {
        ctx.beginPath(); ctx.strokeStyle = colors[index]; ctx.lineWidth = 2;
        ctx.lineJoin = "round"; ctx.lineCap = "round";
        ctx.setLineDash(index === 1 ? [5, 3] : index === 2 ? [2, 3] : []);
        points.forEach((point, i) => { const px = x(point), py = bottom - (bottom - top) * point[key] / max; if (i) ctx.lineTo(px, py); else ctx.moveTo(px, py); }); ctx.stroke();
        ctx.setLineDash([]);
        if (points.length) { const point = points.at(-1); ctx.beginPath(); ctx.arc(x(point), bottom - (bottom - top) * point[key] / max, 2.7, 0, 2 * Math.PI); ctx.fillStyle = colors[index]; ctx.fill(); }
      });
      ctx.fillStyle = "#66766d";
      const ticks = width > 450 ? 6 : 3;
      for (let i = 0; i <= ticks; i++) {
        const px = left + (right - left) * i / ticks;
        const stamp = new Date(oldest + 120_000 * i / ticks).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
        ctx.strokeStyle = "#e7ede9"; ctx.beginPath(); ctx.moveTo(px, top); ctx.lineTo(px, bottom); ctx.stroke();
        ctx.textAlign = i === 0 ? "left" : i === ticks ? "right" : "center";
        ctx.fillText(stamp, px, height - 5);
      }
      ctx.textAlign = "left";
      const point = points[selected] || points.at(-1);
      if (point) {
        if (selected >= 0) { ctx.strokeStyle = "#69788b"; ctx.setLineDash([3, 3]); ctx.beginPath(); ctx.moveTo(x(point), top); ctx.lineTo(x(point), bottom); ctx.stroke(); ctx.setLineDash([]); }
        detail.textContent = `${timeText(point.time)} · ${keys.map((key) => `${key} ${point[key].toFixed(keys.includes("accepted") ? 1 : 0)}`).join(" · ")}${keys.includes("accepted") ? " counts/s" : " queue items"}`;
      } else detail.textContent = "Waiting for two valid samples · hover or use arrow keys to explore.";
      canvas.setAttribute("aria-label", `${keys.includes("accepted") ? "Live processing rate" : "Pipeline backlog"}. ${detail.textContent}. Last two minutes; arrow keys inspect samples.`);
    }
    function charts(animate = false) {
      draw(ui.liveRateChart, ["accepted", "processed", "delivered"], ["#177c50", "#438981", "#6f9887"], ui.liveRateDetail);
      draw(ui.liveQueueChart, ["pending", "failed"], ["#996515", "#bc4c50"], ui.liveQueueDetail);
      const point = telemetry.points.at(-1);
      if (animate === true && point && (point.accepted || point.processed || point.delivered || point.pending || point.failed) && !reducedMotion.matches) {
        for (const canvas of [ui.liveRateChart, ui.liveQueueChart]) canvas.animate([{ clipPath: "inset(0 3% 0 0)" }, { clipPath: "inset(0 0 0 0)" }], { duration: 500, easing: "cubic-bezier(.16,1,.3,1)" });
      }
      ui.liveRateValue.textContent = point ? `${point.accepted.toFixed(1)} events/s` : "— events/s";
      ui.liveQueueValue.textContent = point ? `${point.pending} pending` : "— pending";
    }
    function sourceMix(events) {
      const counts = new Map();
      for (const event of events) { const { family } = identity(event); counts.set(family, (counts.get(family) || 0) + 1); }
      ui.liveSourceCount.textContent = `${new Set(events.map((event) => identity(event).name)).size} sources`;
      const focused = document.activeElement?.dataset.family;
      ui.liveSourceMix.replaceChildren();
      if (!events.length) { const p = document.createElement("p"); p.className = "node-empty"; p.textContent = "No source metadata in this scope."; ui.liveSourceMix.append(p); }
      for (const [family, count] of [...counts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))) {
        const button = document.createElement("button"); button.type = "button"; button.dataset.family = family;
        button.setAttribute("aria-label", `Filter ${family}: ${count} of ${events.length} recent events`);
        const label = document.createElement("span"); label.textContent = family;
        const meter = document.createElement("meter"); meter.min = 0; meter.max = events.length; meter.value = count; meter.setAttribute("aria-hidden", "true");
        const number = document.createElement("strong"); number.textContent = `${count}`;
        const percent = document.createElement("small"); percent.textContent = `${Math.round(count / events.length * 100)}%`;
        button.append(label, meter, number, percent); button.addEventListener("click", () => filter(family)); ui.liveSourceMix.append(button);
        if (focused === family) button.focus({ preventScroll: true });
      }
    }
    ui.simulationStart.addEventListener("click", () => { if (!connection()) return; resume(); simulation.start(ui.simulationScenario.value, ui.simulationSpeed.value); ui.simulationStop.focus(); });
    ui.simulationStop.addEventListener("click", () => { simulation.stop("Stopped. An in-flight input may still finish; accepted events remain stored."); ui.simulationStart.focus(); });
    ui.heroSimulation.addEventListener("click", () => {
      if (simulation.running) ui.simulationStop.click();
      else if (connection()) { ui.simulationStart.click(); el("simulation").scrollIntoView({ block: "nearest" }); }
      else { el("connection").open = true; el("tenantInput").focus(); }
    });
    ui.consoleFollow.addEventListener("click", () => { following = !following; ui.consoleFollow.textContent = following ? "Freeze console" : "Follow live"; ui.consoleFollow.setAttribute("aria-pressed", String(following)); renderFeed(); });
    ui.consoleClear.addEventListener("click", () => { inputs = []; following = true; ui.consoleFollow.textContent = "Freeze console"; ui.consoleFollow.setAttribute("aria-pressed", "true"); renderFeed(); });
    for (const canvas of [ui.liveRateChart, ui.liveQueueChart]) {
      canvas.addEventListener("pointermove", (event) => { const rect = canvas.getBoundingClientRect(), points = telemetry.points; const target = (points.at(-1)?.time || 0) - 120_000 + (event.clientX - rect.left - 32) / (rect.width - 44) * 120_000; selected = points.reduce((best, point, index) => best < 0 || Math.abs(point.time - target) < Math.abs(points[best].time - target) ? index : best, -1); charts(); });
      canvas.addEventListener("pointerleave", () => { selected = -1; charts(); });
      canvas.addEventListener("keydown", (event) => { if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return; event.preventDefault(); const end = telemetry.points.length - 1; selected = event.key === "Home" ? 0 : event.key === "End" ? end : Math.max(0, Math.min(end, (selected < 0 ? end : selected) + (event.key === "ArrowLeft" ? -1 : 1))); charts(); });
    }
    window.addEventListener("resize", charts, { passive: true });
    document.fonts.ready.then(() => charts());
    window.addEventListener("pagehide", () => simulation.stop("Session stopped because the page was left."));
    document.addEventListener("visibilitychange", () => { if (document.hidden && simulation.running) simulation.stop("Stopped because the tab became hidden. Start another session when ready."); });
    return {
      update(summary, events, key, takeSample = true) {
        if (scope !== key) { scope = key; telemetry.reset(); selected = -1; }
        const totals = liveTotals(summary);
        if (takeSample) telemetry.add(totals, Date.now());
        const byReceipt = new Map(events.map((event) => [event.receipt_id, event]));
        inputs.forEach((input) => { if (byReceipt.has(input.receipt)) input.event = byReceipt.get(input.receipt); });
        charts(takeSample); sourceMix(events); renderFeed(); controls();
        if (summary && !totals) {
          for (const id of ["liveRateDetail", "liveQueueDetail"]) ui[id].textContent = "Live telemetry unavailable: this scope includes stale or unavailable origins.";
        }
      },
      reset() { simulation.stop("Connect to send synthetic logs. Inputs are persisted in the HTTP listener’s configured tenant."); simulation.accepted = 0; inputs = []; following = true; ui.consoleFollow.textContent = "Freeze console"; ui.consoleFollow.setAttribute("aria-pressed", "true"); telemetry.reset(); selected = -1; charts(); sourceMix([]); renderFeed(); controls(); },
      unavailable() { telemetry.reset(); charts(); if (simulation.running) simulation.stop("Simulation stopped because dashboard telemetry is unavailable. Reconnect before restarting."); controls(); },
      stop(message) { if (simulation.running) simulation.stop(message); },
    };
  }
  const api = { sample, liveTotals, Telemetry, Simulation, mount };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.ULPFLive = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
