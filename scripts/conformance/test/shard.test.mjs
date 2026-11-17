// SPDX-License-Identifier: Apache-2.0
// The shards of a run (shard.mjs): every suite in exactly one shard, every
// shard checking its own server, balanced by the measured weights.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { PLAN } from "../plan.mjs";
import { DEFAULT_WEIGHT, loadWeights, parseShard, partition, PER_SHARD, shardLoads, shardSuites } from "../shard.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const inventory = JSON.parse(readFileSync(join(here, "..", "inventory.json"), "utf8"));
const weights = loadWeights();
const everySuite = Object.keys(inventory.suites).sort();

test("for n = 1..5 the shards are disjoint and together hold every inventory suite", () => {
  for (let n = 1; n <= 5; n++) {
    const shards = partition(PLAN, weights, n);
    assert.equal(shards.length, n);
    const owner = new Map();
    for (const [i, suites] of shards.entries()) {
      for (const s of suites) {
        assert.ok(!owner.has(s), `n=${n}: ${s} is in shard ${owner.get(s) + 1} and shard ${i + 1}`);
        owner.set(s, i);
      }
    }
    // The PER_SHARD suites are owned by none: every shard runs them.
    for (const s of PER_SHARD) assert.ok(!owner.has(s), `n=${n}: ${s} runs in every shard, so no shard owns it`);
    assert.deepEqual([...owner.keys(), ...PER_SHARD].sort(), everySuite, `n=${n}: the shards and PER_SHARD together are the inventory's suites`);
    // What each shard runs: the suites it owns and the PER_SHARD ones; the
    // union is every suite, and the owned parts never overlap (above).
    const selections = Array.from({ length: n }, (_, i) => shardSuites(PLAN, weights, i + 1, n));
    assert.deepEqual([...new Set(selections.flat())].sort(), everySuite, `n=${n}`);
    for (const [i, selection] of selections.entries()) {
      for (const s of PER_SHARD) assert.ok(selection.includes(s), `n=${n}: shard ${i + 1} does not check its own server with ${s}`);
      assert.deepEqual(selection.filter((s) => !PER_SHARD.includes(s)), shards[i], `n=${n}: shard ${i + 1} runs what it owns`);
    }
  }
});

test("a suite with shardWith shares a shard with the suite it names, for n = 1..5", () => {
  const pairs = PLAN.filter((e) => e.shardWith).map((e) => [e.suite, e.shardWith]);
  assert.ok(pairs.some(([s, w]) => s === "p4" && w === "access"), "p4 reads the identity.created events access writes");
  const weights = loadWeights();
  for (let n = 1; n <= 5; n++) {
    const shards = partition(PLAN, weights, n);
    for (const [suite, withSuite] of pairs) {
      const home = shards.findIndex((s) => s.includes(suite));
      assert.ok(home >= 0 && shards[home].includes(withSuite), `n=${n}: ${suite} and ${withSuite} in different shards`);
    }
  }
});

test("shardWith must name a sharded suite of the plan, without cycles", () => {
  const plan = [{ suite: "a" }, { suite: "b", shardWith: "nope" }];
  assert.throws(() => partition(plan, {}, 2), /shardWith nope/);
  const cycle = [{ suite: "a", shardWith: "b" }, { suite: "b", shardWith: "a" }];
  assert.throws(() => partition(cycle, {}, 2), /cycle/);
});

test("one shard of one is the whole plan", () => {
  assert.deepEqual(shardSuites(PLAN, weights, 1, 1), PLAN.filter((e) => e.suite).map((e) => e.suite));
});

test("a shard keeps the plan's order, so the plan's ordering rules still hold in it", () => {
  const position = (s) => PLAN.findIndex((e) => e.suite === s);
  for (let n = 1; n <= 5; n++) {
    for (let k = 1; k <= n; k++) {
      const positions = shardSuites(PLAN, weights, k, n).map(position);
      assert.deepEqual(positions, [...positions].sort((a, b) => a - b), `shard ${k}/${n}`);
    }
  }
});

test("the shards are deterministic, and the request-budget check runs last in each", () => {
  for (let n = 1; n <= 5; n++) {
    assert.deepEqual(partition(PLAN, weights, n), partition(PLAN, { ...weights }, n));
    for (let k = 1; k <= n; k++) assert.equal(shardSuites(PLAN, weights, k, n).at(-1), "request-budget", `shard ${k}/${n}`);
  }
});

test("greedy, longest first: ties in plan order, each to the lightest shard (ties to the lowest)", () => {
  const plan = [
    { suite: "boot", always: true },
    { setup: "seed" },
    { suite: "a" },
    { suite: "b" },
    { suite: "c" },
    { suite: "d" },
    { suite: "e" },
    { suite: "request-budget", runner: true },
  ];
  // a 50, b 30, c 30, d 20, e unmeasured (DEFAULT_WEIGHT 60); boot always (0).
  const w = { boot: 999, a: 50, b: 30, c: 30, d: 20 };
  // e 60 -> 1; a 50 -> 2; b 30 -> 2 (50 < 60); c 30 -> 1 (60 < 80); d 20 -> 2 (80 < 90); boot 0 -> 1 (90 < 100).
  assert.equal(DEFAULT_WEIGHT, 60);
  assert.deepEqual(partition(plan, w, 2), [["boot", "c", "e"], ["a", "b", "d"]]);
  assert.deepEqual(shardLoads(plan, w, 2), [90, 100]);
  assert.deepEqual(shardSuites(plan, w, 1, 2), ["boot", "c", "e", "request-budget"]);
  // More shards than suites: the extra ones own nothing and still check their server.
  assert.deepEqual(shardSuites(plan, w, 7, 7), ["request-budget"]);
});

test("the CI split (3 shards) is balanced within a minute by the measured weights", () => {
  const loads = shardLoads(PLAN, weights, 3);
  assert.ok(Math.max(...loads) - Math.min(...loads) <= 60, `loads ${loads.join(", ")}`);
});

test("shard-weights.json names only suites of the plan, each with a positive whole number of seconds", () => {
  for (const [suite, seconds] of Object.entries(weights)) {
    assert.ok(inventory.suites[suite] && PLAN.some((e) => e.suite === suite), `${suite} is not a suite of the plan`);
    assert.ok(Number.isInteger(seconds) && seconds > 0, `${suite}: ${seconds}`);
  }
});

test("--shard values: k/n with 1 <= k <= n", () => {
  assert.deepEqual(parseShard("1/3"), { index: 1, count: 3 });
  assert.deepEqual(parseShard("3/3"), { index: 3, count: 3 });
  assert.deepEqual(parseShard("1/1"), { index: 1, count: 1 });
  for (const bad of ["0/3", "4/3", "1/0", "3", "1/3/1", "a/b", "-1/3", "1.5/3", " 1/3", "", undefined]) {
    assert.equal(parseShard(bad), null, String(bad));
  }
  assert.throws(() => partition(PLAN, weights, 0));
  assert.throws(() => shardSuites(PLAN, weights, 4, 3));
});
