// SPDX-License-Identifier: Apache-2.0
/**
 * Go tests named in the inventory's `{ "none": "<why>" }` replacements. A
 * reason that says a Go test replaces a check names it by its package
 * directory, `go/<dir>.TestName`, and the test must exist there: a rename
 * or a removal fails the repository test. A test behind a build constraint
 * runs only when it holds, so the reason says which tag it needs ("build
 * tag <tag>"), and a reason that claims the Go workflow's `go test ./...`
 * (it names .github/workflows/go.yml) names only tests that step builds.
 *
 * Go source is read here without Go: a small lexer drops comments and
 * string literals before declarations are looked for (so a test commented
 * out, or written inside a raw string, does not count), and a file's
 * constraint is read as the go command does: its //go:build line, or else
 * its // +build lines, in the header before the package clause, and the
 * GOOS and GOARCH its name carries (name_linux_test.go).
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * A package-qualified reference: go/<dir>.Test..., with whatever follows
 * the name (a subtest path is refused, see goReferenceProblems). The name
 * itself is checked against Go's rule for test names (isTestName).
 */
export const QUALIFIED = /\b(go(?:\/[a-z0-9_]+)+)\.(Test\w*)(\/\S*)?/g;

/**
 * Go's rule for a test function's name: Test, then nothing or a character
 * that is not a lowercase letter (TestX, Test_x, Test1, Test).
 */
export function isTestName(name) {
  return /^Test(?![a-z])\w*$/.test(name);
}

// The release tags of the Go the workflow uses (go1.1 to go1.27 hold).
const RELEASE_TAGS = Array.from({ length: 27 }, (_, i) => `go1.${i + 1}`);

/** The tags the Go workflow's step 'Test' builds with (go test ./... on Linux amd64, no -race). */
export const WORKFLOW_TAGS = ["linux", "unix", "amd64", "gc", ...RELEASE_TAGS];

// The GOOS and GOARCH values a file name can carry (go help buildconstraint).
const GOOS = new Set("aix android darwin dragonfly freebsd hurd illumos ios js linux nacl netbsd openbsd plan9 solaris wasip1 windows zos".split(" "));
const GOARCH = new Set("386 amd64 amd64p32 arm armbe arm64 arm64be loong64 mips mipsle mips64 mips64le mips64p32 mips64p32le ppc ppc64 ppc64le riscv riscv64 s390 s390x sparc sparc64 wasm".split(" "));

/**
 * Go source with every comment replaced by spaces (newlines kept), and
 * every string and rune literal's contents too unless keepStrings; line
 * comments stay if keepLineComments. Raw strings, interpreted strings with
 * escapes and rune literals are lexed.
 */
export function stripGo(src, { keepStrings = false, keepLineComments = false } = {}) {
  let out = "";
  let i = 0;
  const blank = (s) => s.replace(/[^\n]/g, " ");
  while (i < src.length) {
    const c = src[i];
    const next = src[i + 1];
    if (c === "/" && next === "/") {
      const end = src.indexOf("\n", i);
      const stop = end < 0 ? src.length : end;
      out += keepLineComments ? src.slice(i, stop) : blank(src.slice(i, stop));
      i = stop;
    } else if (c === "/" && next === "*") {
      const end = src.indexOf("*/", i + 2);
      const stop = end < 0 ? src.length : end + 2;
      out += blank(src.slice(i, stop));
      i = stop;
    } else if (c === "`") {
      const end = src.indexOf("`", i + 1);
      const stop = end < 0 ? src.length : end + 1;
      out += keepStrings ? src.slice(i, stop) : "`" + blank(src.slice(i + 1, stop - 1)) + "`";
      i = stop;
    } else if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < src.length && src[j] !== c && src[j] !== "\n") j += src[j] === "\\" ? 2 : 1;
      const stop = Math.min(j + 1, src.length);
      out += keepStrings ? src.slice(i, stop) : c + blank(src.slice(i + 1, stop - 1)) + c;
      i = stop;
    } else {
      out += c;
      i++;
    }
  }
  return out;
}

/**
 * The names the file imports package testing as: "testing" unless it is
 * imported under another name, "." for a dot import.
 */
function testingNames(src) {
  const code = stripGo(src, { keepStrings: true });
  const names = new Set();
  const spec = /(?:^|[\s(;])(?:([A-Za-z_]\w*|\.)\s+)?"testing"/g;
  for (const block of code.matchAll(/\bimport\s*(\([^)]*\)|[^\n;]+)/g)) {
    for (const m of block[1].matchAll(spec)) names.add(m[1] ?? "testing");
  }
  return names;
}

/**
 * The test functions a Go file declares: top-level func TestX(<name>
 * *testing.T), however the parameter is named (or not), spaced or split
 * over lines, with testing under any import name; never one in a comment
 * or a string.
 */
export function goTestDecls(src) {
  const code = stripGo(src);
  const found = [];
  for (const pkg of testingNames(src)) {
    const type = pkg === "." ? String.raw`\*\s*T` : String.raw`\*\s*${pkg}\s*\.\s*T`;
    const decl = new RegExp(String.raw`\bfunc\s+(Test\w*)\s*\(\s*(?:[A-Za-z_]\w*\s+)?${type}\s*,?\s*\)`, "g");
    for (const m of code.matchAll(decl)) if (isTestName(m[1])) found.push(m[1]);
  }
  return found;
}

/**
 * A //go:build expression for a set of // +build lines: each line ORs its
 * space-separated options, each option ANDs its comma-separated terms,
 * and the lines are ANDed.
 */
function plusBuildExpr(lines) {
  return lines
    .map((l) => `(${l.split(/\s+/).filter(Boolean).map((opt) => `(${opt.split(",").join(" && ")})`).join(" || ")})`)
    .join(" && ");
}

/**
 * The build constraint a Go file is under, as one //go:build expression,
 * or null for none: its header's //go:build line (or else its // +build
 * lines, which the go command honours only when a blank line follows them
 * before the package clause), and its name's GOOS and GOARCH.
 */
export function fileConstraint(fileName, src) {
  const parts = [];
  // The header: everything before the package clause.
  // Line comments as written, block comments blanked: a constraint is a
  // line comment, never a line inside a block comment.
  const lines = stripGo(src, { keepStrings: true, keepLineComments: true }).split("\n");
  const code = stripGo(src).split("\n");
  let goBuild = null;
  const plus = [];
  let blankAfterPlus = false;
  for (let n = 0; n < lines.length; n++) {
    if (code[n].trim() !== "") break; // the package clause (or other code)
    const line = lines[n].trim();
    if (line === "") {
      if (plus.length) blankAfterPlus = true;
      continue;
    }
    const gb = line.match(/^\/\/go:build\s+(.+)$/);
    if (gb && goBuild === null) goBuild = gb[1].trim();
    const pb = line.match(/^\/\/\s*\+build\s+(.+)$/);
    if (pb) {
      plus.push(pb[1].trim());
      blankAfterPlus = false;
    }
  }
  if (goBuild !== null) parts.push(goBuild);
  else if (plus.length && blankAfterPlus) parts.push(plusBuildExpr(plus));
  // The name: *_GOOS, *_GOARCH or *_GOOS_GOARCH, after _test.go.
  const segs = fileName.replace(/\.go$/, "").replace(/_test$/, "").split("_");
  const last = segs.length > 1 ? segs.at(-1) : null;
  const prev = segs.length > 2 ? segs.at(-2) : null;
  if (last && GOARCH.has(last) && prev && GOOS.has(prev)) parts.push(`${prev} && ${last}`);
  else if (last && (GOOS.has(last) || GOARCH.has(last))) parts.push(last);
  if (parts.length === 0) return null;
  return parts.length === 1 ? parts[0] : parts.map((p) => `(${p})`).join(" && ");
}

/**
 * The tests of a package directory, as a Map from name to the constraint
 * of the file that declares it (null without one), or null if the
 * directory does not exist. Tagged files count: whether a reason may name
 * one is goReferenceProblems' question.
 */
export function goTestsIn(repoRoot, dir) {
  const abs = join(repoRoot, dir);
  if (!existsSync(abs)) return null;
  const found = new Map();
  for (const e of readdirSync(abs, { withFileTypes: true })) {
    if (!e.isFile() || !e.name.endsWith("_test.go")) continue;
    const src = readFileSync(join(abs, e.name), "utf8");
    const constraint = fileConstraint(e.name, src);
    for (const name of goTestDecls(src)) found.set(name, constraint);
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
 * than go/<dir>.TestName (bare, as go/<dir> TestName, or with a subtest
 * path) is a problem, so that every name is checked as written.
 */
export function goReferenceProblems(why, testsIn) {
  const problems = [];
  const named = [];
  // In prose, a bare test name is Test and at least one more character
  // (the word Test alone is a workflow step's name).
  const bare = why.replace(QUALIFIED, "").match(/\bTest(?![a-z])\w+/g);
  if (bare) problems.push(`a Go test named without its package as go/<dir>.TestName: ${bare.join(", ")}`);
  const workflow = why.includes("go.yml");
  const tagsNamed = [...why.matchAll(/\bbuild tags? ([a-z0-9_]+(?:(?:, | and )[a-z0-9_]+)*)/g)].flatMap((m) => m[1].split(/, | and /));
  for (const [ref, dir, test, subtest] of why.matchAll(QUALIFIED)) {
    if (!isTestName(test)) {
      problems.push(`${dir}.${test} is not a Go test name (Test, then nothing or a character that is not a lowercase letter)`);
      continue;
    }
    if (subtest) {
      problems.push(`${ref}: name the test, go/<dir>.TestName, without a subtest path (subtests are not checked)`);
      continue;
    }
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
    const constraint = tests.get(test);
    if (constraint === null || buildConstraintHolds(constraint, WORKFLOW_TAGS)) continue;
    if (workflow) problems.push(`${dir}.${test} is built only under ${constraint}, which the Go workflow's go test ./... does not satisfy`);
    else if (!buildConstraintHolds(constraint, [...WORKFLOW_TAGS, ...tagsNamed])) problems.push(`${dir}.${test} is built only under ${constraint}: say which tag it needs, as "build tag <tag>"`);
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
