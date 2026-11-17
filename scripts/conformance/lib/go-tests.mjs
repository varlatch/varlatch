// SPDX-License-Identifier: Apache-2.0
/**
 * Go tests named in the inventory's `{ "none": "<why>" }` replacements. A
 * reason that says a Go test replaces a check names it by its package
 * directory, `go/<dir>.TestName`, and the test must exist there: a rename
 * or a removal fails the repository test. A test behind a build tag runs
 * only when that tag is set, so the reason says so ("build tag <tag>"),
 * and a reason that claims the Go workflow's `go test ./...` (it names
 * .github/workflows/go.yml) names only tests that step builds.
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

/** A package-qualified Go test: go/<dir>.TestName. */
export const QUALIFIED = /\b(go(?:\/[a-z0-9_]+)+)\.(Test[A-Z]\w*)/g;

/** The tags the Go workflow's step 'Test' builds with (go test ./... on Linux, no -race). */
export const WORKFLOW_TAGS = ["linux", "unix", "amd64", "gc"];

/**
 * The tests of a package directory, as a Map from name to the file's
 * //go:build expression (null without one), or null if the directory does
 * not exist. Tagged files count: whether a reason may name one is
 * goReferenceProblems' question.
 */
export function goTestsIn(repoRoot, dir) {
  const abs = join(repoRoot, dir);
  if (!existsSync(abs)) return null;
  const found = new Map();
  for (const e of readdirSync(abs, { withFileTypes: true })) {
    if (!e.isFile() || !e.name.endsWith("_test.go")) continue;
    const src = readFileSync(join(abs, e.name), "utf8");
    const tag = src.match(/^\/\/go:build (.+)$/m)?.[1]?.trim() ?? null;
    for (const m of src.matchAll(/^func (Test\w+)\(t \*testing\.T\)/gm)) found.set(m[1], tag);
  }
  return found;
}

/**
 * Whether a //go:build expression holds with these tags set: identifiers,
 * !, &&, || and parentheses, as Go reads them. Throws on anything else.
 */
export function buildConstraintHolds(expr, tags) {
  const set = new Set(tags);
  const tokens = expr.match(/\s*(\|\||&&|!|\(|\)|[A-Za-z0-9_.]+)/gy)?.map((t) => t.trim()) ?? [];
  if (tokens.join("") !== expr.replace(/\s+/g, "")) throw new Error(`build constraint: ${expr}`);
  let i = 0;
  const peek = () => tokens[i];
  const take = (t) => {
    if (tokens[i] !== t) throw new Error(`build constraint: ${expr}`);
    i++;
  };
  const or = () => {
    let v = and();
    while (peek() === "||") {
      i++;
      v = and() || v;
    }
    return v;
  };
  const and = () => {
    let v = not();
    while (peek() === "&&") {
      i++;
      v = not() && v;
    }
    return v;
  };
  const not = () => {
    if (peek() === "!") {
      i++;
      return !not();
    }
    if (peek() === "(") {
      i++;
      const v = or();
      take(")");
      return v;
    }
    const t = tokens[i++];
    if (!t || !/^[A-Za-z0-9_.]+$/.test(t)) throw new Error(`build constraint: ${expr}`);
    return set.has(t);
  };
  const v = or();
  if (i !== tokens.length) throw new Error(`build constraint: ${expr}`);
  return v;
}

/**
 * The problems with the Go tests one `none` reason names, each a sentence,
 * and the tests it names (as go/<dir>.TestName). testsIn(dir) is
 * goTestsIn bound to a repository root. A Go test named any other way
 * than go/<dir>.TestName (bare, or as go/<dir> TestName) is a problem, so
 * that every name is checked.
 */
export function goReferenceProblems(why, testsIn) {
  const problems = [];
  const named = [];
  const bare = why.replace(QUALIFIED, "").match(/\bTest[A-Z]\w*/g);
  if (bare) problems.push(`a Go test named without its package as go/<dir>.TestName: ${bare.join(", ")}`);
  const workflow = why.includes("go.yml");
  const tagsNamed = [...why.matchAll(/\bbuild tags? ([a-z0-9_]+(?:(?:, | and )[a-z0-9_]+)*)/g)].flatMap((m) => m[1].split(/, | and /));
  for (const [, dir, test] of why.matchAll(QUALIFIED)) {
    const tests = testsIn(dir);
    if (!tests) {
      problems.push(`${dir} is not a directory`);
      continue;
    }
    if (!tests.has(test)) {
      problems.push(`${test} is not a test of ${dir}`);
      continue;
    }
    named.push(`${dir}.${test}`);
    const tag = tests.get(test);
    if (tag === null || buildConstraintHolds(tag, WORKFLOW_TAGS)) continue;
    if (workflow) problems.push(`${dir}.${test} needs //go:build ${tag}, which the Go workflow's go test ./... does not set`);
    else if (!buildConstraintHolds(tag, [...WORKFLOW_TAGS, ...tagsNamed])) problems.push(`${dir}.${test} needs //go:build ${tag}: say so, as "build tag <tag>"`);
  }
  return { problems, named };
}

/** Every `none` replacement reason in the inventory, with where it is. */
export function noneReasons(inventory) {
  const out = [];
  for (const [id, check] of Object.entries(inventory.checks ?? {})) {
    if (typeof check.replacement?.none === "string") out.push({ where: `checks.${id}`, why: check.replacement.none });
  }
  for (const [name, suite] of Object.entries(inventory.externalSuites ?? {})) {
    if (typeof suite.replacement?.none === "string") out.push({ where: `externalSuites.${name}`, why: suite.replacement.none });
  }
  return out;
}
