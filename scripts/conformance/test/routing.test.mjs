// SPDX-License-Identifier: Apache-2.0
/**
 * go.yml's selection of the conformance cells (go-binary x source,
 * go-binary x go), derived rather than kept by hand: every file the cells'
 * suites and go-binary's G3 steps import or load must match the changes
 * job's patterns (PATTERNS, CLI_PATTERNS, CONFORMANCE_PATTERNS), so a
 * change to it alone runs the cells. The walk starts from every suite
 * script in inventory.json, the runner's own entry points, the G3 vitest
 * files go.yml runs and the setup files their vitest config names, and
 * follows relative imports (a TypeScript `.js` specifier to its `.ts`) and
 * workspace package imports (to their manifests). The rewrite/go push
 * trigger's paths must be the same patterns, and the workspace's manifests
 * those of pnpm-workspace.yaml's packages alone.
 */
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, posix, relative, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const GO_YML = readFileSync(join(REPO, ".github/workflows/go.yml"), "utf8");

/** One of the changes job's pattern blocks (shell patterns, * crosses /). */
function block(name) {
  const m = GO_YML.match(new RegExp(`^ {10}${name}: \\|\\n((?: {12}\\S.*\\n)+)`, "m"));
  assert.ok(m, `go.yml has no ${name} block`);
  return m[1].split("\n").map((l) => l.trim()).filter((l) => l !== "");
}

const PATTERNS = block("PATTERNS");
const CLI_PATTERNS = block("CLI_PATTERNS");
const CONFORMANCE_PATTERNS = block("CONFORMANCE_PATTERNS");
const CELLS = [...PATTERNS, ...CLI_PATTERNS, ...CONFORMANCE_PATTERNS];

/** A changes-job pattern as a regular expression: * matches anything, / included. */
const shellGlob = (p) => new RegExp(`^${p.split("*").map((s) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`);
const selects = (patterns, file) => patterns.some((p) => shellGlob(p).test(file));

/** The rewrite/go push trigger's paths. */
function pushPaths() {
  const m = GO_YML.match(/^ {2}push:\n(?:.*\n)*? {4}paths:\n((?:(?: {6}#.*| {6}- ".*")\n)+)/m);
  assert.ok(m, "go.yml has no push paths");
  return [...m[1].matchAll(/^ {6}- "(.*)"$/gm)].map((x) => x[1]);
}

const isFile = (p) => existsSync(p) && statSync(p).isFile();

/** The workspace packages (pnpm-workspace.yaml): directory -> package name. */
function workspace() {
  const text = readFileSync(join(REPO, "pnpm-workspace.yaml"), "utf8");
  const globs = [...text.split(/^\S/m)[1].matchAll(/^\s+- "([^"]+)"$/gm)].map((m) => m[1]);
  const excluded = new Set(globs.filter((g) => g.startsWith("!")).map((g) => g.slice(1)));
  const dirs = [];
  for (const g of globs.filter((g) => !g.startsWith("!"))) {
    if (g.endsWith("/*")) {
      const parent = g.slice(0, -2);
      for (const d of readdirSync(join(REPO, parent))) dirs.push(`${parent}/${d}`);
    } else {
      dirs.push(g);
    }
  }
  const out = new Map();
  for (const d of dirs) {
    if (excluded.has(d) || !isFile(join(REPO, d, "package.json"))) continue;
    out.set(d, JSON.parse(readFileSync(join(REPO, d, "package.json"), "utf8")).name);
  }
  return { packages: out, excluded };
}

/** The files a source file imports or loads, as repository paths. */
function dependencies(file, packageDirs) {
  const abs = join(REPO, file);
  const text = readFileSync(abs, "utf8");
  const out = new Set();
  const resolveRelative = (base, spec) => {
    const p = resolve(base, spec);
    for (const c of [p, p.replace(/\.js$/, ".ts"), p.replace(/\.mjs$/, ".mts"), `${p}.ts`, `${p}.mjs`, `${p}.js`, join(p, "index.ts")]) {
      if (isFile(c)) return relative(REPO, c).split("\\").join("/");
    }
    return null;
  };
  for (const m of text.matchAll(/(?:from\s*|import\s*\(\s*|import\s+|require\s*\(\s*|new URL\s*\(\s*)["'`]([^"'`$\n]+)["'`]/g)) {
    const spec = m[1];
    if (spec.startsWith(".")) {
      const r = resolveRelative(dirname(abs), spec);
      if (r) out.add(r);
    } else if (spec.startsWith("@varlatch/")) {
      const name = spec.split("/").slice(0, 2).join("/");
      for (const [dir, pkg] of packageDirs) if (pkg === name) out.add(`${dir}/package.json`);
    }
  }
  // A vitest config names its setup files as strings, relative to itself.
  if (/(^|\/)vitest\.config\.[cm]?[tj]s$/.test(file)) {
    for (const m of text.matchAll(/["'](test\/[^"']+)["']/g)) {
      const r = resolveRelative(dirname(abs), m[1]);
      if (r) out.add(r);
    }
  }
  return out;
}

/** Every file reached from the cells' suites, runner and G3 steps. */
function reached(packageDirs) {
  const inventory = JSON.parse(readFileSync(join(REPO, "scripts/conformance/inventory.json"), "utf8"));
  const roots = Object.values(inventory.suites).map((s) => s.script).filter(Boolean);
  roots.push("scripts/conformance/run.mjs", "scripts/conformance/suite-kit.mjs", "scripts/conformance/lacks-probe.mjs", "scripts/conformance/target-op.mjs");
  // go-binary's G3 steps: vitest in services/varlatchd on each go-* file go.yml names.
  for (const m of GO_YML.matchAll(/pnpm --filter @varlatch\/varlatchd exec vitest run (test\/\S+)/g)) roots.push(`services/varlatchd/${m[1]}`);
  roots.push("services/varlatchd/vitest.config.ts");
  const seen = new Set();
  const queue = [...roots];
  while (queue.length > 0) {
    const f = queue.pop();
    if (seen.has(f)) continue;
    seen.add(f);
    if (!/\.(m?[jt]s|cjs|tsx)$/.test(f)) continue;
    for (const d of dependencies(f, packageDirs)) {
      if (d.includes("node_modules/")) continue;
      // A workspace package is selected whole or by its own patterns; its
      // manifest stands for it.
      if (d.endsWith("/package.json")) {
        seen.add(d);
        continue;
      }
      queue.push(d);
    }
  }
  return { seen, roots };
}

test("every file the cells' suites and go-binary's G3 steps import or load selects the cells", () => {
  const { packages } = workspace();
  const { seen, roots } = reached(packages);
  // The walk reached what it must: the G3 tests, a setup file, the server source a suite imports.
  for (const must of ["services/varlatchd/test/go-connections-fixture.test.ts", "services/varlatchd/test/helpers/lock-trace-setup.ts", "services/varlatchd/src/enroll/page.ts"]) {
    assert.ok(seen.has(must), `the walk did not reach ${must}`);
  }
  assert.ok(roots.filter((r) => r.startsWith("services/varlatchd/test/go-")).length >= 7, "go.yml's G3 steps were not found");
  const unselected = [...seen].filter((f) => !selects(CELLS, f)).sort();
  assert.deepEqual(unselected, [], `files the cells read that select neither cell:\n${unselected.join("\n")}`);
});

test("the workspace's manifests select the cells, and only the workspace's", () => {
  const { packages, excluded } = workspace();
  for (const dir of packages.keys()) assert.ok(selects(CELLS, `${dir}/package.json`), `${dir}/package.json does not select the cells`);
  assert.ok(selects(CELLS, "package.json"));
  for (const dir of excluded) assert.ok(!selects(CONFORMANCE_PATTERNS, `${dir}/package.json`), `${dir}/package.json is outside the workspace but selects the cells`);
});

test("the rewrite/go push trigger's paths are the changes job's patterns", () => {
  // A changes-job pattern x/* is the push path x/**; any other is the same.
  const asPush = (p) => (p.endsWith("/*") ? `${p}*` : p);
  const push = pushPaths();
  const covered = (p) => push.includes(p) || push.some((q) => q.endsWith("/**") && p.startsWith(q.slice(0, -2)));
  const missing = [...new Set(CELLS.map(asPush))].filter((p) => !covered(p));
  assert.deepEqual(missing, [], `patterns missing from the push trigger's paths:\n${missing.join("\n")}`);
  const fromPush = (q) => (q.endsWith("/**") ? q.slice(0, -1) : q);
  const extra = push.filter((q) => !CELLS.includes(fromPush(q)));
  assert.deepEqual(extra, [], `push paths that are no changes-job pattern:\n${extra.join("\n")}`);
});

test("the shell patterns match as the changes job's [[ == ]] does", () => {
  assert.ok(shellGlob("go/*").test("go/cmd/varlatch/main.go"));
  assert.ok(shellGlob("services/varlatchd/test/go-*").test("services/varlatchd/test/go-values-fixture.test.ts"));
  assert.ok(!shellGlob("services/varlatchd/test/go-*").test("services/varlatchd/test/values.test.ts"));
  assert.ok(!shellGlob("package.json").test("apps/docs/package.json"));
  assert.equal(posix.join("a", "b"), "a/b");
});
