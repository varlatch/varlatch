// SPDX-License-Identifier: Apache-2.0
/**
 * The inventory, the plan and the suites agree, without running anything:
 * every suite script exists, every check ID in the inventory is written in
 * its suite's script (or reported by the runner), and every check ID a
 * script writes is in the inventory.
 */
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { validateInventory } from "../lib/inventory.mjs";
import { PLAN } from "../plan.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..", "..");
const inventory = JSON.parse(readFileSync(join(here, "..", "inventory.json"), "utf8"));

test("inventory.json is valid", () => {
  assert.deepEqual(validateInventory(inventory), []);
});

test("the plan runs every suite in the inventory once, and nothing else", () => {
  const planned = PLAN.filter((e) => e.suite).map((e) => e.suite);
  assert.deepEqual([...planned].sort(), Object.keys(inventory.suites).sort());
  assert.equal(new Set(planned).size, planned.length);
  for (const entry of PLAN) {
    if (entry.setup) assert.ok(["bootstrap", "seed"].includes(entry.setup), entry.setup);
    else if (inventory.suites[entry.suite].runner) assert.equal(entry.runner, true, entry.suite);
    else assert.equal(typeof entry.args, "function", entry.suite);
  }
  // The passkey suite enrolls the identity the seed step uses.
  assert.ok(PLAN.findIndex((e) => e.suite === "passkey") < PLAN.findIndex((e) => e.setup === "seed"));
});

test("each suite script exists and writes exactly its inventory's check IDs", () => {
  for (const [suite, entry] of Object.entries(inventory.suites)) {
    if (entry.runner) continue;
    const path = join(repoRoot, entry.script);
    assert.ok(existsSync(path), `${suite}: ${entry.script} does not exist`);
    const source = readFileSync(path, "utf8");
    const prefix = suite.replace(/[-.]/g, "\\$&");
    const written = new Set([...source.matchAll(new RegExp(`["'\`](${prefix}\\.[a-z0-9][a-z0-9.-]*)["'\`]`, "g"))].map((m) => m[1]));
    const expected = Object.entries(inventory.checks)
      .filter(([, c]) => c.suite === suite && c.reportedBy !== "runner")
      .map(([id]) => id);
    assert.deepEqual([...written].sort(), [...expected].sort(), suite);
  }
});

test("suites name the CLI under test through VARLATCH_CLI, never a path of their own", () => {
  for (const [suite, entry] of Object.entries(inventory.suites)) {
    if (entry.runner) continue;
    const source = readFileSync(join(repoRoot, entry.script), "utf8");
    assert.doesNotMatch(source, /apps\/cli\/dist|cli\/dist\/(main\.js|varlatch\.cjs)/, suite);
    // Server state through probes, compose through the target's operations.
    assert.doesNotMatch(source, /\bpsql\b|spawn(Sync)?\(\s*["']docker["']|compose\[0\]/, suite);
  }
});

/** The text of one release's section of CHANGELOG.md, whitespace collapsed. */
function changelogSection(release) {
  const text = readFileSync(join(repoRoot, "CHANGELOG.md"), "utf8");
  const start = text.search(new RegExp(`^## ${release.replace(/\./g, "\\.")} `, "m"));
  if (start < 0) return null;
  const rest = text.slice(start + 3);
  const end = rest.search(/^## /m);
  return (end < 0 ? rest : rest.slice(0, end)).replace(/\s+/g, " ");
}

test("each feature cites words that its release's CHANGELOG section contains", () => {
  for (const [name, feature] of Object.entries(inventory.features)) {
    const section = changelogSection(feature.changelog.release);
    assert.ok(section, `${name}: CHANGELOG.md has no section for ${feature.changelog.release}`);
    assert.ok(section.includes(feature.changelog.quote.replace(/\s+/g, " ")), `${name}: the ${feature.changelog.release} section does not say: ${feature.changelog.quote}`);
  }
});

test("each version-gated feature is gated in every suite that has its checks, and nothing else is", () => {
  for (const [suite, entry] of Object.entries(inventory.suites)) {
    if (entry.runner) continue;
    const source = readFileSync(join(repoRoot, entry.script), "utf8");
    const gated = new Set([...source.matchAll(/\bsupports\(\s*["']([a-z0-9-]+)["']\s*\)/g)].map((m) => m[1]));
    const needed = new Set(
      Object.values(inventory.checks)
        .filter((c) => c.suite === suite && c.feature && inventory.features[c.feature].core !== true)
        .map((c) => c.feature),
    );
    assert.deepEqual([...gated].sort(), [...needed].sort(), suite);
  }
});
