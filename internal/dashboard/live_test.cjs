const { test } = require('node:test');
const assert = require('node:assert/strict');
const { sample, liveTotals, Telemetry, Simulation } = require('./assets/live.js');

function harness(send = async () => ({ receipt_id: 'receipt-1' })) {
  let now = 0, id = 0;
  const timers = new Map(), inputs = [], states = [];
  const simulation = new Simulation({ send, onInput: (input) => inputs.push(input), onState: (state) => states.push(state), now: () => now,
    later: (fn, delay) => { timers.set(++id, { fn, at: now + delay }); return id; }, cancel: (key) => timers.delete(key) });
  async function advance(ms) {
    const end = now + ms;
    for (;;) {
      await Promise.resolve(); await Promise.resolve();
      const next = [...timers].filter(([, timer]) => timer.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
      if (!next) break;
      now = next[1].at; timers.delete(next[0]); next[1].fn();
    }
    now = end; await Promise.resolve(); await Promise.resolve();
  }
  return { simulation, inputs, states, timers, advance };
}
const totals = (value, pending = 0, failed = 0) => ({ receipts: value, revisions: value, delivered: value, pending, failed });

test('enterprise cycle covers 14 named sources, six families and seven formats with synthetic payloads', () => {
  const samples = Array.from({ length: 14 }, (_, i) => sample(i, 'all', new Date(0)));
  assert.equal(new Set(samples.map((s) => s.name)).size, 14);
  assert.equal(new Set(samples.map((s) => s.family)).size, 6);
  assert.equal(new Set(samples.map((s) => s.format)).size, 7);
  for (const input of samples) {
    assert.match(input.payload.toLowerCase(), /synthetic/);
    assert.ok(Buffer.byteLength(input.payload) < 1024);
    if (input.format === 'json') assert.equal(JSON.parse(input.payload).synthetic, true);
  }
  assert.match(samples.find((s) => s.format === 'leef').payload, /\^dst=/);
});
test('source scenarios constrain generated families', () => {
  for (const [scenario, expected] of [['security', ['Network', 'Identity']], ['operations', ['Cloud', 'Infrastructure', 'Application']], ['endpoint', ['Endpoint']]]) {
    for (let i = 0; i < 30; i++) assert.ok(expected.includes(sample(i, scenario).family));
  }
});
test('rates use observed deltas and actual elapsed time; queues remain counts', () => {
  const history = new Telemetry(); history.add(totals(100), 1000);
  assert.equal(history.points.length, 0);
  history.add(totals(106, 2, 1), 4000);
  assert.deepEqual(history.points[0], { time: 4000, accepted: 2, processed: 2, delivered: 2, pending: 2, failed: 1 });
});
test('counter resets, unavailable data and long gaps do not invent spikes or zeroes', () => {
  const history = new Telemetry(); history.add(totals(100), 1000); history.add(totals(1), 3000);
  assert.equal(history.points.length, 0);
  history.add(totals(3), 5000); assert.equal(history.points[0].accepted, 1);
  history.add(null, 7000); assert.equal(history.points.length, 0);
  history.add(totals(50), 9000); assert.equal(history.points.length, 0);
  history.add(totals(80), 40000); assert.equal(history.points.length, 0);
});
test('history is bounded and reset clears the measurement baseline', () => {
  const history = new Telemetry();
  for (let i = 0; i < 200; i++) history.add(totals(i), i * 2000);
  assert.equal(history.points.length, 60); history.reset();
  history.add(totals(900), 999999); assert.equal(history.points.length, 0);
});
test('retained federated snapshots do not report zero rates or spike on recovery', () => {
  const history = new Telemetry();
  history.add(liveTotals({ totals: totals(10), origins: [{ available: true }] }), 0);
  for (const flag of [{ available: false }, { stale: true }, { retained: true }]) {
    assert.equal(liveTotals({ totals: totals(10), origins: [flag] }), null);
    assert.equal(liveTotals({ totals: totals(10), nodes: [flag] }), null);
  }
  history.add(liveTotals({ totals: totals(10), origins: [{ retained: true }] }), 2000);
  history.add(liveTotals({ totals: totals(40), origins: [{ available: true }] }), 4000);
  assert.equal(history.points.length, 0);
  history.add(liveTotals({ totals: totals(42) }), 6000);
  assert.equal(history.points[0].accepted, 1);
});
test('browser timer defaults keep the Window receiver instead of binding to Simulation', () => {
  const vm = require('node:vm'), fs = require('node:fs');
  const context = vm.createContext({ AbortController });
  vm.runInContext(`
    function setTimeout() { if (this !== globalThis) throw new TypeError('Illegal invocation'); return 1; }
    function clearTimeout() { if (this !== globalThis) throw new TypeError('Illegal invocation'); }
  `, context);
  vm.runInContext(fs.readFileSync(require.resolve('./assets/live.js'), 'utf8'), context);
  vm.runInContext(`const runner = new ULPFLive.Simulation({ send: () => new Promise(() => {}), onInput() {}, onState() {} }); runner.start('all', 1); runner.stop();`, context);
});
test('runner paces acknowledged inputs and stops all timers at three minutes', async () => {
  const h = harness(); h.simulation.start('all', 4);
  await h.advance(180000);
  assert.equal(h.inputs.length, 720);
  assert.equal(h.simulation.running, false); assert.equal(h.timers.size, 0);
  assert.match(h.states.at(-1), /Session complete/);
});
test('a slow request cannot create concurrent requests, stop ignores late acknowledgements', async () => {
  let resolve, signal, calls = 0;
  const h = harness((_, currentSignal) => { signal = currentSignal; calls++; return new Promise((r) => { resolve = r; }); });
  h.simulation.start('all', 4); await h.advance(4000);
  assert.equal(calls, 1); assert.equal(h.inputs.length, 0);
  h.simulation.stop(); assert.equal(signal.aborted, true);
  resolve({ receipt_id: 'late' }); await h.advance(1000);
  assert.equal(h.inputs.length, 0); assert.equal(h.timers.size, 0);
});
test('stop/restart ignores the previous session response', async () => {
  let resolve, count = 0;
  const h = harness(() => ++count === 1 ? new Promise((r) => { resolve = r; }) : Promise.resolve({ receipt_id: 'new' }));
  h.simulation.start('all', 1); h.simulation.stop(); h.simulation.start('endpoint', 1);
  resolve({ receipt_id: 'old' }); await h.advance(0);
  assert.deepEqual(h.inputs.map((i) => i.receipt), ['new']);
  assert.equal(h.inputs[0].family, 'Endpoint'); h.simulation.stop();
});
test('rejected tokens and malformed acknowledgements stop without counting or retrying', async () => {
  for (const status of [401, 403, 429, 500, 0]) {
    const h = harness(async () => { if (!status) return {}; throw Object.assign(new Error('rejected'), { status }); });
    h.simulation.start('all', 4); await h.advance(10000);
    assert.equal(h.simulation.running, false); assert.equal(h.inputs.length, 0); assert.equal(h.timers.size, 0);
  }
});
test('timeout stops and reports an unknown admission outcome without retrying', async () => {
  const h = harness((_, signal) => new Promise((resolve, reject) => signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })))));
  h.simulation.start('all', 4); await h.advance(10000);
  assert.equal(h.simulation.running, false); assert.equal(h.timers.size, 0);
  assert.match(h.states.at(-1), /outcome is unknown/);
});
