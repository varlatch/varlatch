// SPDX-License-Identifier: Apache-2.0
/**
 * The inventory, the plan and the suites agree, without running anything:
 * every suite script exists, every check ID in the inventory is written in
 * its suite's script (or reported by the runner), and every check ID a
 * script writes is in the inventory.
 */
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { buildConstraintHolds, fileConstraint, goReferenceProblems, goTestDecls, goTestsIn, noneReasons, QUALIFIED, WORKFLOW_TAGS } from "../lib/go-tests.mjs";
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

// A `none` replacement that names Go tests names each by its package
// (go/<dir>.TestName, lib/go-tests.mjs): it is defined in that package
// directory, a test behind a build tag says so ("build tag <tag>"), and a
// reason that claims the Go workflow (go.yml) names only tests its
// go test ./... on Linux builds, and only steps of go.yml. The S3 step
// runs the S3 tests named, in their package, and cannot skip them.
test("the Go tests a none replacement names exist, by their package", () => {
  const testsIn = (dir) => goTestsIn(repoRoot, dir);
  const workflow = readFileSync(join(repoRoot, ".github/workflows/go.yml"), "utf8");
  const steps = new Set([...workflow.matchAll(/^\s+- name: (.+)$/gm)].map((m) => m[1].trim()));
  let named = 0;
  for (const { where, why } of noneReasons(inventory)) {
    const found = goReferenceProblems(why, testsIn);
    assert.deepEqual(found.problems, [], where);
    named += found.named.length;
    if (!why.includes("go.yml")) continue;
    for (const [, step] of why.matchAll(/'([^']+)'/g)) assert.ok(steps.has(step), `${where}: '${step}' is not a step of go.yml`);
  }
  assert.ok(named >= 10, `only ${named} Go tests named`);
  // The step 'Test' runs every package under go/.
  const testStep = workflow.slice(workflow.indexOf("      - name: Test\n"));
  const testRun = testStep.slice(0, testStep.indexOf("\n      - ", 1));
  assert.match(testRun, /working-directory: go\n/);
  assert.match(testRun, /go test \.\/\.\.\.\s*$/m);
  // The S3 step runs the S3 tests named, in their package, without skipping.
  const s3 = workflow.slice(workflow.indexOf("- name: G13, the S3 client"));
  const run = s3.slice(0, s3.indexOf("\n      - ", 1));
  assert.match(run, /VARLATCH_REQUIRE_S3=1/);
  assert.match(run, /working-directory: go\n/);
  const s3Named = [...inventory.externalSuites["backup-s3"].replacement.none.matchAll(QUALIFIED)];
  assert.ok(s3Named.length >= 3, "the S3 tests named");
  for (const [, dir, t] of s3Named) {
    assert.ok(run.includes(` ./${dir.replace(/^go\//, "")}`), `the S3 step does not run ${dir}`);
    assert.ok(run.includes(t), `the S3 step does not run ${t}`);
  }
});

test("the Go test reference guard: renames, removals, the old form and build tags", () => {
  // A package as the repository has it: one plain test, one Linux-only,
  // one behind a manual tag.
  const pkg = new Map([
    ["TestPlain", null],
    ["TestLinux", "linux"],
    ["TestLive", "coolifylive"],
    ["TestNotRace", "!race && linux"],
  ]);
  const testsIn = (dir) => (dir === "go/lib/sync" ? pkg : null);
  const problems = (why) => goReferenceProblems(why, testsIn).problems;
  const ok = (why) => assert.deepEqual(problems(why), [], why);
  const bad = (why, re) => {
    const p = problems(why);
    assert.ok(p.length === 1 && re.test(p[0]), `${why}: ${JSON.stringify(p)}`);
  };
  ok("run by go.yml: go/lib/sync.TestPlain, go/lib/sync.TestLinux and go/lib/sync.TestNotRace");
  ok("the manual check go/lib/sync.TestLive (build tag coolifylive)");
  ok("no Go test at all");
  // A rename or a removal of the test, or of its package.
  bad("run by go.yml: go/lib/sync.TestPlainRenamed", /TestPlainRenamed is not a test of go\/lib\/sync/);
  bad("the manual check go/lib/sync.TestGone (build tag coolifylive)", /TestGone is not a test of go\/lib\/sync/);
  bad("run by go.yml: go/lib/moved.TestPlain", /go\/lib\/moved is not a directory/);
  // A test named any other way is not checked, so it fails.
  bad("the manual check go/lib/sync TestLive (build tag coolifylive)", /without its package.*TestLive/);
  bad("run by go.yml: TestPlain", /without its package.*TestPlain/);
  // A tagged test: the reason names its tag, and never claims the workflow.
  bad("the manual check go/lib/sync.TestLive", /built only under coolifylive: say which tag/);
  bad("the manual check go/lib/sync.TestLive (build tag g9a)", /built only under coolifylive: say which tag/);
  bad("run by go.yml: go/lib/sync.TestLive (build tag coolifylive)", /go test \.\/\.\.\. does not satisfy/);
  // Go's test names: Test, then nothing or a character that is not a
  // lowercase letter. Each is checked; a missing one fails.
  pkg.set("Test_real", null).set("Test", null).set("Test1", null);
  ok("run by go.yml: go/lib/sync.Test_real, go/lib/sync.Test and go/lib/sync.Test1");
  bad("run by go.yml: go/lib/sync.Test_gone", /Test_gone is not a test of go\/lib\/sync/);
  bad("run by go.yml: Test_real", /without its package.*Test_real/);
  bad("run by go.yml: go/lib/sync.Testing", /go\/lib\/sync\.Testing is not a Go test name/);
  // A subtest path is refused: only the test would be checked.
  bad("run by go.yml: go/lib/sync.TestPlain/Removed", /go\/lib\/sync\.TestPlain\/Removed: name the test.*without a subtest path/);
  // The word Test alone, a workflow step's name, is not a test reference.
  ok("all in the step 'Test' of go.yml");
  // The real tagged tests resolve the same way.
  const real = (why) => goReferenceProblems(why, (dir) => goTestsIn(repoRoot, dir));
  assert.deepEqual(real("go/lib/sync.TestCoolifyLiveServices (build tag coolifylive)"), { problems: [], named: ["go/lib/sync.TestCoolifyLiveServices"] });
  assert.match(real("go/lib/sync.TestCoolifyLiveServices").problems.join(), /built only under coolifylive: say which tag/);
  assert.match(real("go/lib/sync.TestCoolifyLiveService (build tag coolifylive)").problems.join(), /not a test of go\/lib\/sync/);
});

test("Go test declarations: comments, strings, parameter names, formatting and import names", () => {
  const decls = (src) => goTestDecls(src).sort();
  const file = (body, imports = `import "testing"`) => `package p\n\n${imports}\n\n${body}\n`;
  // Declared, however the parameter is named, spaced or split.
  assert.deepEqual(decls(file("func TestA(t *testing.T) {}")), ["TestA"]);
  assert.deepEqual(decls(file("func TestReal(tb *testing.T) {}")), ["TestReal"]);
  assert.deepEqual(decls(file("func TestUnnamed(*testing.T) {}")), ["TestUnnamed"]);
  assert.deepEqual(decls(file("func TestSplit(\n\tt *testing.T,\n) {\n}")), ["TestSplit"]);
  assert.deepEqual(decls(file("func  TestSpaced ( t  * testing . T ) {}")), ["TestSpaced"]);
  assert.deepEqual(decls(file("func Test_real(t *testing.T) {}\nfunc Test(t *testing.T) {}")), ["Test", "Test_real"]);
  // testing under another name, or dot-imported.
  assert.deepEqual(decls(file("func TestAlias(t *tt.T) {}", `import tt "testing"`)), ["TestAlias"]);
  assert.deepEqual(decls(file("func TestGrouped(t *tt.T) {}", `import (\n\t"fmt"\n\ttt "testing"\n)`)), ["TestGrouped"]);
  assert.deepEqual(decls(file("func TestDot(t *T) {}", `import . "testing"`)), ["TestDot"]);
  // Not declared: commented out, inside strings, not a test's signature.
  assert.deepEqual(decls(file("/*\nfunc TestGone(t *testing.T) {}\n*/")), []);
  assert.deepEqual(decls(file("// func TestGone(t *testing.T) {}")), []);
  assert.deepEqual(decls(file("var src = `\nfunc TestGone(t *testing.T) {}\n`")), []);
  assert.deepEqual(decls(file('var src = "func TestGone(t *testing.T) {}"')), []);
  assert.deepEqual(decls(file("func Testing(t *testing.T) {}")), []);
  assert.deepEqual(decls(file("func TestB(b *testing.B) {}")), []);
  assert.deepEqual(decls(file("func (s suite) TestMethod(t *testing.T) {}")), []);
  assert.deepEqual(decls(file("func TestOther(t *other.T) {}")), []);
  // A string that looks like the end of a comment, and a rune, do not
  // confuse the lexer.
  assert.deepEqual(decls(file("var x = \"/*\"\nvar r = '\\''\nfunc TestAfter(t *testing.T) {}\nvar y = \"*/\"")), ["TestAfter"]);
});

test("Go file constraints: //go:build, // +build and the file's name", () => {
  const head = (lines) => `${lines}\n\npackage p\n`;
  assert.equal(fileConstraint("a_test.go", head("// SPDX-License-Identifier: Apache-2.0")), null);
  assert.equal(fileConstraint("a_test.go", head("//go:build coolifylive")), "coolifylive");
  // Legacy lines, honoured with a blank line before the package clause.
  assert.equal(fileConstraint("a_test.go", head("// +build coolifylive")), "((coolifylive))");
  assert.equal(fileConstraint("a_test.go", head("// +build linux,amd64 darwin\n// +build !race")), "((linux && amd64) || (darwin)) && ((!race))");
  assert.equal(fileConstraint("a_test.go", "// +build coolifylive\npackage p\n"), null);
  // //go:build wins over // +build; constraints after the package clause
  // or inside a block comment do not count.
  assert.equal(fileConstraint("a_test.go", head("//go:build g9a\n// +build coolifylive")), "g9a");
  assert.equal(fileConstraint("a_test.go", "package p\n\n//go:build coolifylive\n"), null);
  assert.equal(fileConstraint("a_test.go", head("/*\n//go:build coolifylive\n*/")), null);
  // The name's GOOS and GOARCH.
  assert.equal(fileConstraint("x_windows_test.go", "package p\n"), "windows");
  assert.equal(fileConstraint("x_arm64_test.go", "package p\n"), "arm64");
  assert.equal(fileConstraint("x_darwin_arm64_test.go", "package p\n"), "darwin && arm64");
  assert.equal(fileConstraint("linux_test.go", "package p\n"), null);
  assert.equal(fileConstraint("x_linux_test.go", head("//go:build coolifylive")), "(coolifylive) && (linux)");
  // What the workflow builds.
  for (const [name, src, built] of [
    ["x_test.go", head("// +build coolifylive"), false],
    ["x_windows_test.go", "package p\n", false],
    ["x_linux_test.go", "package p\n", true],
    ["x_test.go", head("//go:build go1.21 && !race"), true],
  ]) assert.equal(buildConstraintHolds(fileConstraint(name, src) ?? "linux", WORKFLOW_TAGS), built, name);
});

test("the Go test guard on files: commented-out tests, legacy tags and file names", () => {
  const root = mkdtempSync(join(tmpdir(), "go-tests-"));
  try {
    const dir = "go/lib/p";
    mkdirSync(join(root, dir), { recursive: true });
    const write = (name, src) => writeFileSync(join(root, dir, name), src);
    write("real_test.go", 'package p\n\nimport "testing"\n\nfunc TestReal(tb *testing.T) {}\n\n/*\nfunc TestGone(t *testing.T) {}\n*/\n');
    write("live_test.go", '// +build coolifylive\n\npackage p\n\nimport "testing"\n\nfunc TestLive(t *testing.T) {}\n');
    write("win_windows_test.go", 'package p\n\nimport "testing"\n\nfunc TestWindows(t *testing.T) {}\n');
    const problems = (why) => goReferenceProblems(why, (d) => goTestsIn(root, d)).problems;
    assert.deepEqual(problems("go.yml: go/lib/p.TestReal"), []);
    assert.match(problems("go.yml: go/lib/p.TestGone").join(), /TestGone is not a test of go\/lib\/p/);
    assert.match(problems("go.yml: go/lib/p.TestLive").join(), /built only under .*coolifylive.*does not satisfy/);
    assert.deepEqual(problems("manual: go/lib/p.TestLive (build tag coolifylive)"), []);
    assert.match(problems("go.yml: go/lib/p.TestWindows").join(), /built only under windows/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("build constraints read as Go reads them", () => {
  const holds = (expr, tags) => buildConstraintHolds(expr, tags);
  assert.equal(holds("linux", ["linux"]), true);
  assert.equal(holds("coolifylive", ["linux"]), false);
  assert.equal(holds("!race && linux", ["linux"]), true);
  assert.equal(holds("crashpoint && !windows", ["linux"]), false);
  assert.equal(holds("crashpoint && !windows", ["linux", "crashpoint"]), true);
  assert.equal(holds("linux || darwin", ["darwin"]), true);
  assert.equal(holds("!(a || b) && c", ["c"]), true);
  assert.equal(holds("!(a || b) && c", ["a", "c"]), false);
  assert.throws(() => holds("a &&", []));
  assert.throws(() => holds("a b", []));
  assert.throws(() => holds("(a", []));
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
