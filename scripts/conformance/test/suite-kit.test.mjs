// SPDX-License-Identifier: Apache-2.0
/**
 * suite-kit's feature groups, as a suite sees them: `supports()` reports a
 * group PREDATES-CLI only for a CLI older than the feature, never for the
 * compatibility core or a CLI built from source, and a result reported for a
 * group already reported as predating the CLI is an error.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseSuiteOutput } from "../lib/results.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const kitUrl = pathToFileURL(join(here, "..", "suite-kit.mjs")).href;
const inventory = JSON.parse(readFileSync(join(here, "..", "inventory.json"), "utf8"));

/** Runs a few lines against suite-kit as suite `suite`, with a CLI of `version` ("" for source) and the checks the runner says lack. */
function suite(body, { suite = "client-runtime", version = "", lacking } = {}) {
  const code = `import { reporter } from ${JSON.stringify(kitUrl)};\nconst kit = reporter();\n${body}\nkit.finish();`;
  const r = spawnSync(process.execPath, ["--input-type=module", "-e", code], {
    encoding: "utf8",
    env: { PATH: process.env.PATH ?? "", CONFORMANCE_SUITE: suite, VARLATCH_CLI_VERSION: version, ...(lacking ? { CONFORMANCE_LACKING: JSON.stringify(lacking) } : {}) },
  });
  return { ...r, parsed: parseSuiteOutput(r.stdout) };
}
const scanChecks = Object.entries(inventory.checks).filter(([, c]) => c.suite === "client-runtime" && c.feature === "scan").map(([id]) => id);

test("a CLI older than a feature: every check of the group reports PREDATES-CLI once, and the group is skipped", () => {
  const r = suite(`console.log("supports=" + kit.supports("scan")); kit.supports("scan");`, { version: "0.10.0" });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /supports=false/);
  assert.deepEqual(r.parsed.results.map((x) => x.id).sort(), [...scanChecks].sort());
  assert.ok(r.parsed.results.every((x) => x.status === "PREDATES-CLI"));
});

test("a CLI as new as the feature, a CLI from source, and the compatibility core run the group", () => {
  for (const [feature, version] of [["scan", "0.11.0"], ["scan", "0.22.0"], ["scan", ""], ["types-python", "0.0.1"], ["run-export-context", "0.1.0"]]) {
    const r = suite(`console.log("supports=" + kit.supports(${JSON.stringify(feature)}));`, { version });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /supports=true/, `${feature} at ${version || "source"}`);
    assert.deepEqual(r.parsed.results, []);
  }
});

test("a result for a group already reported as predating the CLI is an error", () => {
  const r = suite(`kit.supports("scan"); kit.check(${JSON.stringify(scanChecks[0])}, "x", true);`, { version: "0.10.0" });
  assert.equal(r.status, 1);
  assert.match(r.parsed.errors.join("\n"), /after its feature group scan was reported as predating the CLI/);
});

test("a feature the suite has no checks of is a mistake, not a skip", () => {
  const r = suite(`kit.supports("mcp");`, { version: "0.10.0" });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /client-runtime has no checks of feature mcp/);
});

// Operation groups (feature-parity decision 2): group() is false only when
// the runner says every check of the group lacks an operation; runs() names
// one check; a result for a skipped group is an error.
const groupChecks = (name) => Object.entries(inventory.checks).filter(([, c]) => c.suite === "client-runtime" && c.group === name).map(([id]) => id);

test("an operation group runs unless every one of its checks lacks an operation", () => {
  const audit = groupChecks("audit-export");
  assert.ok(audit.length > 1);
  for (const [lacking, runs] of [[undefined, true], [[], true], [audit.slice(1), true], [audit, false]]) {
    const r = suite(`console.log("group=" + kit.group("audit-export"));`, { lacking });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, new RegExp(`group=${runs}`), JSON.stringify(lacking));
    assert.deepEqual(r.parsed.results, []);
  }
});

test("runs() names one check of the suite; a check of another suite is a mistake", () => {
  const id = "client-runtime.export-context-run-cannot-export-context";
  assert.match(suite(`console.log("runs=" + kit.runs(${JSON.stringify(id)}));`, { lacking: [id] }).stdout, /runs=false/);
  assert.match(suite(`console.log("runs=" + kit.runs(${JSON.stringify(id)}));`, { lacking: [] }).stdout, /runs=true/);
  const r = suite(`kit.runs("sdk.reads");`);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /sdk\.reads is not a check of client-runtime/);
});

test("a result for a skipped operation group is an error; an unknown group is a mistake", () => {
  const audit = groupChecks("audit-export");
  const r = suite(`kit.group("audit-export"); kit.check(${JSON.stringify(audit[0])}, "x", true);`, { lacking: audit });
  assert.equal(r.status, 1);
  assert.match(r.parsed.errors.join("\n"), /after its operation group audit-export was skipped/);
  const unknown = suite(`kit.group("nope");`);
  assert.notEqual(unknown.status, 0);
  assert.match(unknown.stderr, /client-runtime has no operation group nope/);
});
