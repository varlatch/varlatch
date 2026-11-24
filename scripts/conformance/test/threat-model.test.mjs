// SPDX-License-Identifier: Apache-2.0
// docs/THREAT-MODEL.md maps each shipped guarantee to what verifies it: a Go
// test (`server/values.TestX`), a replay (replay `access`) or a suite of this
// harness (suite `broker`). This fails when one named there does not exist,
// or when a shipped guarantee names none.
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const model = readFileSync(join(REPO, "docs/THREAT-MODEL.md"), "utf8");
const inventory = JSON.parse(readFileSync(join(REPO, "scripts/conformance/inventory.json"), "utf8"));

/** What `text` names that does not exist. */
function missing(text) {
  const out = [];
  for (const [, dir, name] of text.matchAll(/`((?:server|lib|cmd|install)(?:\/[a-z0-9]+)+)\.(Test\w+)`/g)) {
    const at = join(REPO, "go", dir);
    const declared = new RegExp(`^func ${name}\\(`, "m");
    const found = existsSync(at) && readdirSync(at).some((f) => f.endsWith("_test.go") && declared.test(readFileSync(join(at, f), "utf8")));
    if (!found) out.push(`${dir}.${name}`);
  }
  // "replay `a`", and "replays `a`, `b` and `c`"; the same for suites.
  const list = (word) =>
    [...text.matchAll(new RegExp(`\\b${word}s? ((?:\`[a-z-]+\`(?:, | and )?)+)`, "g"))].flatMap((m) => [...m[1].matchAll(/`([a-z-]+)`/g)].map((n) => n[1]));
  for (const name of list("replay")) {
    if (!["go/server/paritytest/testdata", "go/server/values/testdata"].some((d) => existsSync(join(REPO, d, `${name}-v0.22.0.json`)))) out.push(`replay ${name}`);
  }
  for (const name of list("suite")) if (!inventory.suites[name]) out.push(`suite ${name}`);
  return out;
}
const guarantees = model.split("\n").filter((l) => l.startsWith("| ") && l.includes("**SHIPPED GUARANTEE**"));
const proven = (row) => /`(?:server|lib|cmd)\/[^`]+\.Test\w+`|\breplays? `|\bsuites? `/.test(row.split(" | ").at(-1));

test("every test, replay and suite the threat model names exists", () => {
  assert.deepEqual(missing(model), []);
  assert.deepEqual(missing("`server/values.TestNoSuch`, `lib/nosuch.TestSealOpen`; replays `access` and `nosuch`; suite `no-such`"), ["server/values.TestNoSuch", "lib/nosuch.TestSealOpen", "replay nosuch", "suite no-such"], "control");
});

test("every shipped guarantee names what verifies it", () => {
  assert.ok(guarantees.length > 40, `${guarantees.length} guarantees found`);
  assert.deepEqual(guarantees.filter((row) => !proven(row)).map((row) => row.slice(0, 80)), []);
  assert.ok(!proven("| A claim | **SHIPPED GUARANTEE** | reviewed |"), "control");
});
