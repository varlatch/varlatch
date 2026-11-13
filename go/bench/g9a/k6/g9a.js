// SPDX-License-Identifier: Apache-2.0
//
// The load of ADR-0059's G9a, open loop: one constant-arrival-rate scenario
// per phase of the plan, started back to back. Every request is printed as
// one line, R,<phase>,<scheduled µs>,<latency µs>,<service µs>,<status>,<error>,
// with the latency counted from the request's scheduled start (scenario
// start + i / rate), so a request sent late counts its wait; a request k6
// could not start at all is a dropped iteration. run.sh sends the lines to
// requests.log and the summary to k6-summary.json.
//
// Environment: BASE (server URL), PLAN and MANIFEST (absolute paths),
// SUMMARY (where to write the summary).
import http from 'k6/http';
import exec from 'k6/execution';
import { SharedArray } from 'k6/data';

const plan = JSON.parse(open(__ENV.PLAN));
const manifest = new SharedArray('manifest', () => JSON.parse(open(__ENV.MANIFEST)));

const scenarios = {};
let at = 0;
for (const ph of plan.phases) {
  scenarios[ph.name] = {
    executor: 'constant-arrival-rate',
    rate: ph.rate,
    timeUnit: '1s',
    duration: `${Math.round(ph.seconds * 1000)}ms`,
    startTime: `${Math.round(at * 1000)}ms`,
    preAllocatedVUs: ph.rate * 2,
    maxVUs: Math.max(100, ph.rate * 10),
    gracefulStop: '15s',
    exec: 'retrieve',
    env: { RATE: String(ph.rate) },
  };
  at += ph.seconds;
}

export const options = {
  scenarios,
  setupTimeout: '30s',
  summaryTrendStats: ['med', 'p(95)', 'p(99)', 'max'],
  discardResponseBodies: true,
};

export function setup() {
  const r = http.post(`${__ENV.BASE}/run/start`, null, { timeout: '10s' });
  if (r.status !== 200) {
    throw new Error(`POST /run/start: ${r.status}`);
  }
}

export function retrieve() {
  const sc = exec.scenario;
  const sched = sc.startTime + (sc.iterationInTest * 1000) / Number(__ENV.RATE);
  const m = manifest[Math.floor(Math.random() * manifest.length)];
  const t0 = Date.now();
  const r = http.get(`${__ENV.BASE}/v1/retrieve/${m.env}/${m.key}`, {
    headers: { Authorization: `Bearer ${m.token}` },
    timeout: '10s',
    responseType: 'text',
    tags: { name: 'retrieve' },
  });
  const service = r.timings.blocked + r.timings.duration;
  const latency = Math.max(0, t0 - sched) + service;
  let err = '';
  if (r.status === 0) {
    err = 'transport';
  } else if (r.status !== 200) {
    err = String(r.body || '').includes('SQLITE_BUSY') ? 'busy' : `http_${r.status}`;
  }
  console.log(`R,${sc.name},${Math.round(sched * 1000)},${Math.round(latency * 1000)},${Math.round(service * 1000)},${r.status},${err}`);
}

export function handleSummary(data) {
  const m = data.metrics;
  const pick = (k) => (m[k] ? m[k].values : null);
  const out = {
    dropped_iterations: { count: m.dropped_iterations ? m.dropped_iterations.values.count : 0 },
    iterations: pick('iterations'),
    http_reqs: pick('http_reqs'),
    http_req_failed: pick('http_req_failed'),
    http_req_duration: pick('http_req_duration'),
    vus_max: pick('vus_max'),
  };
  return { [__ENV.SUMMARY]: JSON.stringify(out, null, 2) + '\n' };
}
