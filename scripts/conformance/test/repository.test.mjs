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
 * The kit.group() and kit.runs() calls in a script that do not follow the
 * gate convention, read from the script's syntax tree (TypeScript's parser,
 * on JavaScript). This is a lint aid, not a proof: the guarantee is at run
 * time (a result reported for a skipped group fails the run, in the kit and
 * in the runner, and a skipped group's setup meets the target's 501s). The
 * convention, and nothing else:
 *   1. `if (call) { ... }`: a block with at least one statement and no
 *      else. The call may be one conjunct of the condition
 *      (`if (kit.supports("f") && kit.group("g")) { ... }`).
 *   2. `if (!call) return;`, `continue;` or `break;` (bare: no value, no
 *      label; alone or as a block's only statement), as a statement of a
 *      block with work after it: `return` in a function's own body,
 *      `continue` and `break` in the body of the loop they leave.
 *   3. Either through a const, `const g = kit.group("g");`, every use of
 *      `g` the condition of form 1 or 2.
 * A gate inside a function counts only when the function is called (its
 * name is used elsewhere, or it is passed as an argument or called where it
 * stands). Anything else is a violation.
 */
function ungatedCalls(source) {
  const sf = ts.createSourceFile("suite.mjs", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  const out = [];
  const isKit = (e) => ts.isIdentifier(e) && e.text === "kit";
  const isGate = (name) => name === "group" || name === "runs";
  const label = (call) => `kit.${call.expression.name.text}(${call.arguments.map((a) => a.getText(sf)).join(", ")})`;
  const outer = (n) => {
    while (ts.isParenthesizedExpression(n.parent)) n = n.parent;
    return n;
  };
  const isLoop = (n) => ts.isForStatement(n) || ts.isForOfStatement(n) || ts.isForInStatement(n) || ts.isWhileStatement(n) || ts.isDoStatement(n);
  const isFunction = (n) => ts.isFunctionDeclaration(n) || ts.isFunctionExpression(n) || ts.isArrowFunction(n) || ts.isMethodDeclaration(n);
  const references = (name, declaration) => {
    const refs = [];
    const walk = (n) => {
      if (ts.isIdentifier(n) && n.text === name && n !== declaration) refs.push(n);
      ts.forEachChild(n, walk);
    };
    walk(sf);
    return refs;
  };
  // The bare exit an early-exit gate's then-branch is, or null.
  const exitOf = (s) => {
    if (ts.isBlock(s)) return s.statements.length === 1 ? exitOf(s.statements[0]) : null;
    if (ts.isReturnStatement(s) && !s.expression) return s;
    if ((ts.isContinueStatement(s) || ts.isBreakStatement(s)) && !s.label) return s;
    return null;
  };
  // Form 2's place: a statement of a block with work after it, the block
  // being the function's own body (return) or the loop's body it leaves.
  const exitsBeforeWork = (ifs) => {
    const exit = exitOf(ifs.thenStatement);
    const block = ifs.parent;
    if (!exit || ifs.elseStatement || !ts.isBlock(block)) return false;
    if (block.statements.indexOf(ifs) >= block.statements.length - 1) return false;
    return ts.isReturnStatement(exit) ? isFunction(block.parent) && block.parent.body === block : isLoop(block.parent) && block.parent.statement === block;
  };
  // Whether an expression (a call, or a const's name) is a gate.
  const gates = (n) => {
    let e = outer(n);
    if (ts.isPrefixUnaryExpression(e.parent) && e.parent.operator === ts.SyntaxKind.ExclamationToken) {
      const not = outer(e.parent);
      return ts.isIfStatement(not.parent) && not.parent.expression === not && exitsBeforeWork(not.parent);
    }
    while (ts.isBinaryExpression(e.parent) && e.parent.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken) e = outer(e.parent);
    const ifs = e.parent;
    return ts.isIfStatement(ifs) && ifs.expression === e && !ifs.elseStatement && ts.isBlock(ifs.thenStatement) && ifs.thenStatement.statements.length > 0;
  };
  // Whether every function around a node is called.
  const called = (n) => {
    for (let p = n.parent; p; p = p.parent) {
      if (!isFunction(p)) continue;
      const f = outer(p);
      if (ts.isCallExpression(f.parent) && (f.parent.expression === f || f.parent.arguments.includes(f))) continue;
      const name = ts.isFunctionDeclaration(p) ? p.name : ts.isVariableDeclaration(f.parent) && f.parent.initializer === f && ts.isIdentifier(f.parent.name) ? f.parent.name : null;
      if (!name || references(name.text, name).length === 0) return false;
    }
    return true;
  };
  const visit = (n) => {
    if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && isKit(n.expression.expression) && isGate(n.expression.name.text)) {
      const d = outer(n).parent;
      const viaConst =
        ts.isVariableDeclaration(d) && d.initializer === outer(n) && ts.isIdentifier(d.name) &&
        (d.parent.flags & ts.NodeFlags.Const) !== 0 &&
        ((refs) => refs.length > 0 && refs.every((r) => gates(r) && called(r)))(references(d.name.text, d.name));
      if (!((gates(n) || viaConst) && called(n))) out.push(label(n));
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

test("the gate detector: the convention, whatever its formatting, and nothing else", () => {
  const ok = (code) => assert.deepEqual(ungatedCalls(code), [], code);
  const bad = (code, found) => assert.deepEqual(ungatedCalls(code), [found], code);
  // 1. The work in a non-empty block, no else; a conjunct.
  ok('if (kit.group("a")) { setup(); }');
  ok('if(kit.group("a")){setup()}');
  ok('if (\n  kit.group(\n    "a",\n  )\n) {\n  setup();\n}');
  ok('if (kit . group ("a")) { setup(); }');
  ok('if ((kit.group("a"))) { setup(); }');
  ok('if (kit.supports("f") && kit.group("a")) { setup(); }');
  // 2. A bare exit before the work, in the function's body or the loop's.
  ok('function f() { if (!kit.group("a")) return; setup(); }\nf();');
  ok('for (const x of xs) { if (!kit.group("a")) { continue; } setup(x); }');
  ok('while (true) { if (!kit.group("a")) break; setup(); }');
  // 3. Through a const used only as those conditions; inside a called function.
  ok('const a = kit.group("a");\nif (a) { setup(); }\nif (a) { more(); }');
  ok('const f = () => { const a = kit.runs("s.x"); if (!a) return; check(); };\nawait f();');
  ok('items.forEach((i) => { if (kit.runs("s.x")) { check(i); } });');
  ok('(async () => { if (kit.group("a")) { setup(); } })();');
  // Violations: Sol's counterexamples, from both reviews.
  bad('kit.group ("a");\nsetup();', 'kit.group("a")');
  bad('const a = kit.group("a");\nconsole.log(a ? "run" : "skip");\nsetup();', 'kit.group("a")');
  bad('function f() { if (!kit.group("a")) return setup(); }\nf();', 'kit.group("a")');
  bad('if (kit.group("a")) {} else { setup(); }', 'kit.group("a")');
  bad('if (kit.group("a")) { x(); } else { setup(); }', 'kit.group("a")');
  bad('for (const o of outer) { if (!kit.group("a")) { for (const i of inner) { continue; } } setup(o); }', 'kit.group("a")');
  bad('for (const o of outer) { if (!kit.group("a")) { for (const i of inner) continue; } setup(o); }', 'kit.group("a")');
  bad('function never() { if (kit.group("a")) { setup(); } }\nsetup();', 'kit.group("a")');
  // And the other shapes.
  bad('if (kit.group("a")) {}', 'kit.group("a")');
  bad('if (kit.group("a")) setup();', 'kit.group("a")');
  bad('if (kit.group("a") || x) { setup(); }', 'kit.group("a")');
  bad('function f() { if (!kit.group("a")) { log(); } setup(); }\nf();', 'kit.group("a")');
  bad('function f() { if (!kit.group("a")) return; }\nf();', 'kit.group("a")');
  bad('function f() { if (!kit.group("a")) throw new Error("skip"); setup(); }\nf();', 'kit.group("a")');
  bad('function f() { if (!kit.group("a") && x) return; setup(); }\nf();', 'kit.group("a")');
  bad('function f() { for (;;) { if (!kit.group("a")) return; setup(); } }\nf();', 'kit.group("a")');
  bad('outer: for (;;) { for (;;) { if (!kit.group("a")) continue outer; setup(); } }', 'kit.group("a")');
  bad('if (!kit.group("a")) return;\nsetup();', 'kit.group("a")');
  bad('const a = kit.group("a");\nif (a) { setup(); }\nlog(a);', 'kit.group("a")');
  bad('const a = kit.group("a");\nsetup();', 'kit.group("a")');
  bad('let a = kit.group("a");\nif (a) { setup(); }', 'kit.group("a")');
  bad('const ok = !kit.group("a");\nif (ok) { setup(); }', 'kit.group("a")');
  bad('await f(kit.runs("s.x"));', 'kit.runs("s.x")');
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

// An external suite whose replacement is `none` because its Go
// counterparts run in the Go workflow names them, each Go test by its
// package (go/<package dir>.TestName): it is defined in that package
// directory, in a file every workflow step that runs `go test ./...` on
// Linux builds (no build tag other than linux), and every step quoted is
// one of go.yml's. The S3 step runs the S3 tests named, in their package,
// and cannot skip them.
test("an external suite's Go counterparts it names exist", () => {
  const testsIn = (dir) => {
    const found = new Map();
    for (const e of readdirSync(join(repoRoot, dir), { withFileTypes: true })) {
      if (!e.isFile() || !e.name.endsWith("_test.go")) continue;
      const src = readFileSync(join(repoRoot, dir, e.name), "utf8");
      const tag = src.match(/^\/\/go:build (.+)$/m)?.[1]?.trim() ?? null;
      for (const m of src.matchAll(/^func (Test\w+)\(t \*testing\.T\)/gm)) found.set(m[1], tag);
    }
    return found;
  };
  const workflow = readFileSync(join(repoRoot, ".github/workflows/go.yml"), "utf8");
  const steps = new Set([...workflow.matchAll(/^\s+- name: (.+)$/gm)].map((m) => m[1].trim()));
  const qualified = /\b(go(?:\/[a-z0-9_]+)+)\.(Test[A-Z]\w*)/g;
  let named = 0;
  for (const [name, suite] of Object.entries(inventory.externalSuites)) {
    const why = suite.replacement?.none;
    if (typeof why !== "string" || !why.includes("go.yml")) continue;
    const bare = why.replace(qualified, "").match(/\bTest[A-Z]\w*/g);
    assert.equal(bare, null, `${name}: a Go test named without its package (go/<dir>.TestName): ${bare}`);
    for (const [, dir, t] of why.matchAll(qualified)) {
      assert.ok(existsSync(join(repoRoot, dir)), `${name}: ${dir} is not a directory`);
      const tests = testsIn(dir);
      assert.ok(tests.has(t), `${name}: ${t} is not a test of ${dir}`);
      const tag = tests.get(t);
      assert.ok(tag === null || tag === "linux", `${name}: ${dir}.${t} needs the build tag "${tag}", which the workflow's go test ./... does not set`);
      named++;
    }
    for (const [, step] of why.matchAll(/'([^']+)'/g)) assert.ok(steps.has(step), `${name}: '${step}' is not a step of go.yml`);
  }
  assert.ok(named >= 8, `only ${named} Go tests named`);
  // The step 'Test' runs every package under go/.
  const testStep = workflow.slice(workflow.indexOf("      - name: Test\n"));
  const testRun = testStep.slice(0, testStep.indexOf("\n      - ", 1));
  assert.match(testRun, /working-directory: go\n/);
  // -count=1 only (no cached results); -run, -list or -tags would narrow it.
  assert.match(testRun, /go test (-count=1 )?\.\/\.\.\.[ \t]*$/m);
  // The S3 step runs the S3 tests named, in their package, without skipping.
  const s3 = workflow.slice(workflow.indexOf("- name: G13, the S3 client"));
  const run = s3.slice(0, s3.indexOf("\n      - ", 1));
  assert.match(run, /VARLATCH_REQUIRE_S3=1/);
  assert.match(run, /working-directory: go\n/);
  const s3Named = [...inventory.externalSuites["backup-s3"].replacement.none.matchAll(qualified)];
  assert.ok(s3Named.length >= 3, "the S3 tests named");
  for (const [, dir, t] of s3Named) {
    assert.ok(run.includes(` ./${dir.replace(/^go\//, "")}`), `the S3 step does not run ${dir}`);
    assert.ok(run.includes(t), `the S3 step does not run ${t}`);
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
