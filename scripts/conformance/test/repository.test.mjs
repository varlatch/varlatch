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
import ts from "typescript";
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

test("each operation group is skipped in its suite's script, and only its suite's groups are named", () => {
  for (const [suite, entry] of Object.entries(inventory.suites)) {
    if (entry.runner) continue;
    const source = readFileSync(join(repoRoot, entry.script), "utf8");
    const named = new Set([...source.matchAll(/\bkit\.group\(\s*["']([a-z0-9-]+)["']\s*\)/g)].map((m) => m[1]));
    assert.deepEqual([...named].sort(), Object.keys(entry.groups ?? {}).sort(), suite);
    // A check skipped on its own names a check of this suite.
    for (const m of source.matchAll(/\bkit\.runs\(\s*["']([a-z0-9.-]+)["']\s*\)/g)) assert.equal(inventory.checks[m[1]]?.suite, suite, m[1]);
  }
});

/**
 * The kit.group() and kit.runs() calls in a script that do not gate the
 * work they name, read from the script's syntax tree (TypeScript's parser,
 * on JavaScript). A skipped group's setup must not run against a target
 * that lacks its operations, so only these forms gate:
 *   1. `if (kit.group("g")) { ... }`: the work in the block. The call may
 *      be one conjunct of the condition (`if (kit.supports("f") &&
 *      kit.group("g")) { ... }`): the block still runs only when it is
 *      true. An else branch is the skipped case.
 *   2. `if (!kit.group("g")) return;` (or continue, break, throw; alone or
 *      as a block's only statement): an early exit before the work.
 *   3. Either through a const: `const g = kit.group("g");`, with every use
 *      of `g` the condition of form 1 or 2 (`if (g) { ... }`, `if (!g)
 *      return;`).
 * Anything else is a violation: the call as a statement or an argument, a
 * then-branch that is not a block, `||`, a ternary, a let, a const used any
 * other way, `kit["group"]`, or `group` taken from kit by destructuring.
 */
function ungatedCalls(source) {
  const sf = ts.createSourceFile("suite.mjs", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  const out = [];
  const isKit = (e) => ts.isIdentifier(e) && e.text === "kit";
  const isGate = (name) => name === "group" || name === "runs";
  const label = (call) => `kit.${call.expression.name.text}(${call.arguments.map((a) => a.getText(sf)).join(", ")})`;
  // The node as its enclosing expression sees it, past parentheses.
  const outer = (n) => {
    while (ts.isParenthesizedExpression(n.parent)) n = n.parent;
    return n;
  };
  const exits = (s) =>
    ts.isReturnStatement(s) || ts.isContinueStatement(s) || ts.isBreakStatement(s) || ts.isThrowStatement(s) ||
    (ts.isBlock(s) && s.statements.length === 1 && exits(s.statements[0]));
  // Whether an expression (a call, or a const's name) is a gate: form 1 or 2.
  const gates = (n) => {
    let e = outer(n);
    if (ts.isPrefixUnaryExpression(e.parent) && e.parent.operator === ts.SyntaxKind.ExclamationToken) {
      const not = outer(e.parent);
      return ts.isIfStatement(not.parent) && not.parent.expression === not && exits(not.parent.thenStatement);
    }
    while (ts.isBinaryExpression(e.parent) && e.parent.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken) e = outer(e.parent);
    return ts.isIfStatement(e.parent) && e.parent.expression === e && ts.isBlock(e.parent.thenStatement);
  };
  const references = (name, declaration) => {
    const refs = [];
    const walk = (n) => {
      if (ts.isIdentifier(n) && n.text === name && n !== declaration) refs.push(n);
      ts.forEachChild(n, walk);
    };
    walk(sf);
    return refs;
  };
  const visit = (n) => {
    if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && isKit(n.expression.expression) && isGate(n.expression.name.text)) {
      const d = outer(n).parent;
      const viaConst =
        ts.isVariableDeclaration(d) && d.initializer === outer(n) && ts.isIdentifier(d.name) &&
        (d.parent.flags & ts.NodeFlags.Const) !== 0 &&
        ((refs) => refs.length > 0 && refs.every(gates))(references(d.name.text, d.name));
      if (!gates(n) && !viaConst) out.push(label(n));
    } else if (ts.isElementAccessExpression(n) && isKit(n.expression) && ts.isStringLiteral(n.argumentExpression) && isGate(n.argumentExpression.text)) {
      out.push(`kit[${n.argumentExpression.getText(sf)}]`);
    } else if (ts.isVariableDeclaration(n) && n.initializer && isKit(n.initializer) && ts.isObjectBindingPattern(n.name)) {
      for (const el of n.name.elements) {
        const key = (el.propertyName ?? el.name).getText(sf);
        if (isGate(key)) out.push(`${key} taken from kit`);
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return out;
}

test("each kit.group() and kit.runs() result gates the work it names", () => {
  for (const [suite, entry] of Object.entries(inventory.suites)) {
    if (entry.runner) continue;
    assert.deepEqual(ungatedCalls(readFileSync(join(repoRoot, entry.script), "utf8")), [], suite);
  }
});

test("the gate detector: the three forms, whatever their formatting, and nothing else", () => {
  const ok = (code) => assert.deepEqual(ungatedCalls(code), [], code);
  const bad = (code, ...found) => assert.deepEqual(ungatedCalls(code), found.length ? found : [ungatedCalls(code)[0] ?? "(none found)"], code);
  // 1. The work in the block; a conjunct; an else for the skipped case.
  ok('if (kit.group("a")) { setup(); }');
  ok('if(kit.group("a")){setup()}');
  ok('if (\n  kit.group(\n    "a",\n  )\n) {\n  setup();\n}');
  ok('if (kit . group ("a")) { setup(); }');
  ok('if ((kit.group("a"))) { setup(); }');
  ok('if (kit.supports("f") && kit.group("a")) { setup(); }');
  ok('if (kit.runs("s.x")) { check(); } else { skip(); }');
  // 2. An early exit before the work.
  ok('function f() { if (!kit.group("a")) return; setup(); }');
  ok('for (;;) { if (!kit.group("a")) { continue; } setup(); }');
  ok('for (;;) { if (!kit.group("a")) break; setup(); }');
  ok('if (!kit.runs("s.x")) throw new Error("skip");');
  // 3. Through a const used only as those conditions.
  ok('const a = kit.group("a");\nif (a) { setup(); }\nif (a) { more(); }');
  ok('function f() { const a = kit.runs("s.x"); if (!a) return; check(); }');
  // Violations: Sol's counterexamples and the other shapes.
  bad('kit.group("a");\nsetup();', 'kit.group("a")');
  bad('kit.group ("a");\nsetup();', 'kit.group("a")');
  bad('const a = kit.group("a");\nconsole.log(a ? "run" : "skip");\nsetup();', 'kit.group("a")');
  bad('const a = kit.group("a");\nconst r = a ? 1 : 0;', 'kit.group("a")');
  bad('const a = kit.group("a");\nif (a) { setup(); }\nlog(a);', 'kit.group("a")');
  bad('const a = kit.group("a");\nsetup();', 'kit.group("a")');
  bad('let a = kit.group("a");\nif (a) { setup(); }', 'kit.group("a")');
  bad('if (kit.group("a")) setup();', 'kit.group("a")');
  bad('if (kit.group("a") || x) { setup(); }', 'kit.group("a")');
  bad('if (!kit.group("a")) { log(); }\nsetup();', 'kit.group("a")');
  bad('if (!kit.group("a") && x) return;', 'kit.group("a")');
  bad('await f(kit.runs("s.x"));', 'kit.runs("s.x")');
  bad('const ok = !kit.group("a");\nif (ok) { setup(); }', 'kit.group("a")');
  bad('if (kit["group"]("a")) { setup(); }', 'kit["group"]');
  bad('const { group } = kit;\nif (group("a")) { setup(); }', "group taken from kit");
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
  const { openapiOperations } = await import("../lib/operations.mjs");
  const { TARGET_NAMES } = await import("../targets/index.mjs");
  const clients = JSON.parse(readFileSync(join(here, "..", "clients.json"), "utf8"));
  const openapi = openapiOperations(readFileSync(join(repoRoot, "packages/protocol/openapi.yaml"), "utf8"));
  for (const file of readdirSync(join(here, "..", "expect"))) {
    const targetName = file.replace(/\.json$/, "");
    assert.ok(file.endsWith(".json") && TARGET_NAMES.includes(targetName), `expect/${file} is not named after a target`);
    const parsed = JSON.parse(readFileSync(join(here, "..", "expect", file), "utf8"));
    assert.deepEqual(validateExpectations(parsed, { targetName, inventory, cliVersions: Object.keys(clients.cli), openapi }), [], file);
  }
});

test("every operation the inventory names is an OpenAPI operationId or a named operation", async () => {
  const { openapiOperations, operationProblems } = await import("../lib/operations.mjs");
  const openapi = openapiOperations(readFileSync(join(repoRoot, "packages/protocol/openapi.yaml"), "utf8"));
  assert.deepEqual(operationProblems(inventory, openapi), []);
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
