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

/** Runs a few lines against suite-kit as suite `suite`, with a CLI of `version` ("" for source). */
function suite(body, { suite = "client-runtime", version = "" } = {}) {
  const code = `import { reporter } from ${JSON.stringify(kitUrl)};\nconst kit = reporter();\n${body}\nkit.finish();`;
  const r = spawnSync(process.execPath, ["--input-type=module", "-e", code], {
    encoding: "utf8",
    env: { PATH: process.env.PATH ?? "", CONFORMANCE_SUITE: suite, VARLATCH_CLI_VERSION: version },
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
