const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

function dashboard() {
  const html = fs.readFileSync(path.join(__dirname, '../../sentinel/web/index.html'), 'utf8');
  const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
  const elements = new Map();
  const streams = [];
  const document = { getElementById(id) {
    if (!elements.has(id)) elements.set(id, {
      textContent: '', innerHTML: '', value: '/local/project', checked: false,
      listeners: {}, addEventListener(name, callback) { this.listeners[name] = callback; },
    });
    return elements.get(id);
  }};
  class EventSource {
    constructor(url) { this.url = url; this.listeners = {}; this.closed = false; streams.push(this); }
    addEventListener(name, callback) { this.listeners[name] = callback; }
    close() { this.closed = true; }
    emit(category, status) { this.listeners.update({data: JSON.stringify({category, status, summary: 'test event'})}); }
  }
  const context = vm.createContext({document, EventSource, URLSearchParams, setInterval() {},
    fetch: async (url) => ({ok: true, json: async () => url === '/runs' ? {run_id: 'unit'} : []}),
  });
  vm.runInContext(script, context);
  return {context, document, streams};
}

function ledger(overrides = {}) {
  return {project_path: '/project', findings: [], source_files: [], report_artifacts: [], retry_count: 0,
    max_retries: 5, enabled_analyzers: ['slither', 'mythril'], mock_mode: false,
    analyzer_runs: [{tool: 'slither', status: 'completed'}, {tool: 'mythril', status: 'completed'}], ...overrides};
}

test('coverage agrees with the backend: all enabled tools, no skips or demos', () => {
  const view = dashboard();
  for (const [state, expected] of [
    [ledger(), 'pass'], [ledger({mock_mode: true}), 'fail'],
    [ledger({analyzer_runs: [{tool: 'slither', status: 'completed'}]}), 'fail'],
    [ledger({analyzer_runs: [{tool: 'slither', status: 'completed'}, {tool: 'mythril', status: 'skipped'}]}), 'fail'],
    [ledger({analyzer_runs: []}), 'warn'],
  ]) {
    view.context.input = state;
    vm.runInContext('renderLedger(input)', view.context);
    assert.ok(view.document.getElementById('gates').innerHTML.startsWith(`<div class="gate ${expected}">`));
  }
});

test('phase and command completion do not end live monitoring', async () => {
  const view = dashboard();
  await view.document.getElementById('scan-form').listeners.submit({preventDefault() {}});
  const stream = view.streams[0];
  stream.emit('phase', 'completed');
  assert.equal(stream.closed, false);
  assert.equal(view.document.getElementById('run').disabled, true);
  stream.emit('command', 'completed');
  assert.equal(stream.closed, false);
  stream.emit('run', 'completed');
  assert.equal(stream.closed, true);
  assert.equal(view.document.getElementById('run').disabled, false);
});

test('untrusted evidence is escaped in gate HTML and attribute values', () => {
  const view = dashboard();
  assert.ok(vm.runInContext('gate("<img src=x>", "warn", "<script>bad()</script>")', view.context).includes('&lt;script&gt;'));
  assert.equal(vm.runInContext('escape("\\\" onmouseover=\\\"bad")', view.context), '&quot; onmouseover=&quot;bad');
});

test('legacy verified ledgers require rescan rather than inheriting new approval', () => {
  const view = dashboard();
  view.context.input = ledger({final_verification_state: 'verified', judge_result: {verified: true, regression_passed: true}});
  vm.runInContext('renderLedger(input)', view.context);
  assert.equal(view.document.getElementById('outcome').textContent, 'legacy verification; rescan required');
  assert.ok(view.document.getElementById('gates').innerHTML.includes('no qualified regression evidence'));
});

test('temporary stream disconnect reconnects without claiming the run failed', async () => {
  const view = dashboard();
  await view.document.getElementById('scan-form').listeners.submit({preventDefault() {}});
  const stream = view.streams[0];
  stream.listeners.error();
  assert.equal(stream.closed, false);
  assert.equal(view.document.getElementById('run').disabled, true);
  stream.emit('phase', 'started');
  stream.listeners.error();
  stream.listeners.error();
  assert.equal(stream.closed, false);
  stream.listeners.error();
  assert.equal(stream.closed, true);
  assert.ok(view.document.getElementById('notice').textContent.includes('status is unknown'));
  assert.equal(view.document.getElementById('run').disabled, false);
});
