// SPDX-License-Identifier: Apache-2.0
/**
 * Shards of a run (run.mjs --shard <k>/<n>): the plan's suites split into n
 * parts, each run against a server of its own, so each part has the
 * server's whole request window (lib/request-log.mjs) and the parts run in
 * parallel. The suites, their checks and the production limits stay the
 * same; a shard is a --suite selection the runner makes itself.
 *
 * Every suite of the plan is owned by exactly one shard: `partition` assigns
 * each one once, so none can be in two shards or in none
 * (test/shard.test.mjs checks it for n = 1..5 against the inventory). A
 * shard judges the checks of the suites it owns, and the expected failures
 * of those checks (run.mjs scopes both to the selection), so every check and
 * every expected failure is judged in exactly one shard.
 *
 * Two exceptions, PER_SHARD, are in every shard's selection besides: they
 * check the server itself, after the suites before them in the plan, and
 * each shard has its own server. request-budget is the runner's proof that
 * the server refused nothing (no unexpected 429); one shard's server says
 * nothing about another's request window, so every shard must prove it for
 * its own. server-logs looks for the seeded secret in the server's logs
 * after the suites that handle it; the suites that do are spread over the
 * shards, so every shard's server logs are searched.
 *
 * The plan's `always` suites (the reconcile and passkey suites, whose work
 * every later step needs) run in every shard anyway, so they weigh nothing
 * when the shards are balanced; each is still owned, and judged, by one.
 *
 * Balance: greedy, longest first. The suites are taken by weight (seconds,
 * shard-weights.json, measured from CI logs without the request-budget
 * waits; DEFAULT_WEIGHT for a suite not measured yet), heaviest first and
 * ties in plan order, each to the shard with the least weight so far (ties
 * to the lowest shard). Within a shard the plan's order is kept, so every
 * ordering rule of plan.mjs still holds.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

/** Suites in every shard's selection: they check the shard's own server (see above). */
export const PER_SHARD = ["server-logs", "request-budget"];

/** The weight, in seconds, of a suite shard-weights.json does not list. */
export const DEFAULT_WEIGHT = 60;

/** `<k>/<n>` as { index: k, count: n }, 1 <= k <= n; null when it is not one. */
export function parseShard(text) {
  const m = /^([1-9]\d*)\/([1-9]\d*)$/.exec(String(text ?? ""));
  if (!m) return null;
  const index = Number(m[1]);
  const count = Number(m[2]);
  return index <= count ? { index, count } : null;
}

/** The measured weights: { suite: seconds }. */
export function loadWeights(file = join(HERE, "shard-weights.json")) {
  return JSON.parse(readFileSync(file, "utf8")).seconds;
}

/**
 * The plan's suites split into `count` shards: an array of `count` arrays of
 * suite names, each in plan order. PER_SHARD suites are not in any (every
 * shard runs them besides); every other suite of the plan is in exactly one.
 */
export function partition(plan, weights, count) {
  if (!Number.isInteger(count) || count < 1) throw new Error(`a run has at least one shard, not ${count}`);
  const entries = plan.map((e, position) => ({ ...e, position })).filter((e) => e.suite && !PER_SHARD.includes(e.suite));
  const weightOf = (e) => (e.always ? 0 : (weights[e.suite] ?? DEFAULT_WEIGHT));
  const order = [...entries].sort((a, b) => weightOf(b) - weightOf(a) || a.position - b.position);
  const shards = Array.from({ length: count }, () => ({ load: 0, entries: [] }));
  for (const e of order) {
    let lightest = shards[0];
    for (const s of shards) if (s.load < lightest.load) lightest = s;
    lightest.entries.push(e);
    lightest.load += weightOf(e);
  }
  return shards.map((s) => s.entries.sort((a, b) => a.position - b.position).map((e) => e.suite));
}

/**
 * The suites shard `index` of `count` selects, in plan order: the ones it
 * owns and the PER_SHARD ones the plan has.
 */
export function shardSuites(plan, weights, index, count) {
  if (!Number.isInteger(index) || index < 1 || index > count) throw new Error(`no shard ${index} of ${count}`);
  const owned = new Set(partition(plan, weights, count)[index - 1]);
  return plan.filter((e) => e.suite && (owned.has(e.suite) || PER_SHARD.includes(e.suite))).map((e) => e.suite);
}

/** The total weight of each shard, for the record (the always suites weigh nothing). */
export function shardLoads(plan, weights, count) {
  const always = new Set(plan.filter((e) => e.always).map((e) => e.suite));
  return partition(plan, weights, count).map((suites) => suites.reduce((sum, s) => sum + (always.has(s) ? 0 : (weights[s] ?? DEFAULT_WEIGHT)), 0));
}
