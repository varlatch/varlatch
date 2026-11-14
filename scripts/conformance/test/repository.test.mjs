// SPDX-License-Identifier: Apache-2.0
/**
 * The inventory, the plan and the suites agree, without running anything:
 * every suite script exists, every check ID in the inventory is written in
 * its suite's script (or reported by the runner), and every check ID a
 * script writes is in the inventory.
 */
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
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
  // A run limited with --suite still deploys Convex (the seed step's mirror
  // sync needs it) and enrolls the identity: exactly these always run.
  assert.deepEqual(PLAN.filter((e) => e.always).map((e) => e.suite), ["reconcile", "passkey"]);
  assert.ok(PLAN.findIndex((e) => e.suite === "reconcile") < PLAN.findIndex((e) => e.setup === "seed"));
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

test("every lifecycle and installer suite (scripts/test-*.mjs) is an external suite with its replacement, and only those", () => {
  const scripts = readdirSync(join(repoRoot, "scripts")).filter((f) => /^test-.*\.mjs$/.test(f)).map((f) => `scripts/${f}`).sort();
  const listed = Object.values(inventory.externalSuites ?? {}).map((s) => s.script).sort();
  assert.deepEqual(listed, scripts);
  for (const [name, suite] of Object.entries(inventory.externalSuites)) {
    assert.equal(suite.script, `scripts/test-${name}.mjs`, name);
  }
});

test("each expectations file is valid and named after a target", async () => {
  const { validateExpectations } = await import("../lib/expect.mjs");
  const { TARGET_NAMES } = await import("../targets/index.mjs");
  const clients = JSON.parse(readFileSync(join(here, "..", "clients.json"), "utf8"));
  for (const file of readdirSync(join(here, "..", "expect"))) {
    const targetName = file.replace(/\.json$/, "");
    assert.ok(file.endsWith(".json") && TARGET_NAMES.includes(targetName), `expect/${file} is not named after a target`);
    const parsed = JSON.parse(readFileSync(join(here, "..", "expect", file), "utf8"));
    assert.deepEqual(validateExpectations(parsed, { targetName, inventory, cliVersions: Object.keys(clients.cli) }), [], file);
  }
});

test("conformance-expect.yml runs only base code on pull_request_target, read-only, and never the pull request's", async () => {
  const { parse } = await import("yaml");
  const text = readFileSync(join(repoRoot, ".github/workflows/conformance-expect.yml"), "utf8");
  const wf = parse(text);
  assert.deepEqual(Object.keys(wf.on).sort(), ["pull_request_target", "push"]);
  assert.deepEqual(wf.on.push.branches, ["main"]);
  assert.deepEqual(wf.permissions, { contents: "read" });
  const job = wf.jobs.expectations;
  assert.equal(job.permissions, undefined);
  const checkouts = job.steps.filter((s) => String(s.uses ?? "").startsWith("actions/checkout@"));
  assert.equal(checkouts.length, 1);
  assert.equal(checkouts[0].with.ref, "${{ github.event_name == 'pull_request_target' && github.event.pull_request.base.sha || github.sha }}");
  assert.equal(checkouts[0].with["persist-credentials"], false);
  // No secret, no head ref anywhere it could be checked out or run.
  assert.doesNotMatch(text, /secrets\./);
  assert.doesNotMatch(text, /pull_request\.head\.(ref|repo)/);
  for (const step of job.steps) {
    if (!step.run) continue;
    assert.doesNotMatch(step.run, /git (checkout|switch|worktree)|pnpm|npm |npx|\bpull\/head\b.*node/, step.name);
    assert.doesNotMatch(step.run, /\$\{\{/, `${step.name}: expressions go through env, never inline`);
  }
  // The head reaches the checker only as a revision it reads with git show.
  assert.match(text, /git fetch --no-tags origin "\+refs\/pull\/\$\{PR\}\/head:refs\/remotes\/pull\/head"/);
  // A base without the checker fails; there is no success path without it.
  assert.doesNotMatch(text, /::notice::/);
  assert.match(text, /::error::the base commit has no scripts\/conformance\/expect-check\.mjs/);
});
