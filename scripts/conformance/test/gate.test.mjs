// SPDX-License-Identifier: Apache-2.0
/**
 * Gate mode (lib/gate.mjs): each rule on its own, and why no target can
 * pass the gate today: replacements that later ADR-0059 steps write are
 * still open.
 */
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { canonical, judgeGate, onGoServer, predatedFeatures, readWalkthrough, recentCliProblems, replacements, TEMPLATE_SENTINEL } from "../lib/gate.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..", "..");
const inventory = JSON.parse(readFileSync(join(here, "..", "inventory.json"), "utf8"));

/** A small inventory whose replacements are all satisfiable. */
const small = {
  features: { scan: { title: "scan", introducedIn: "0.20.0", changelog: { release: "0.20.0", quote: "q" } } },
  checks: {
    "a.new": { suite: "a", kind: "conformance" },
    "a.old": { suite: "a", kind: "ts-stack", replacement: "a.new" },
    "a.gone": { suite: "a", kind: "ts-stack", replacement: { none: "no Convex" } },
  },
  externalSuites: { setup: { script: "scripts/test-setup.mjs", replacement: "a.new" } },
};
const candidateCommit = "a".repeat(40);
const signedWalkthroughContent = (commit = candidateCommit) =>
  [
    "# Gate G1 Browser Walkthrough Evidence",
    "",
    "| # | Done | Screen |",
    "| --- | --- | --- |",
    "| 1 | [x] | Projects |",
    "",
    "## 7. Owner Sign-Off",
    "",
    "- **Owner:** owner",
    "- **Date (UTC):** 2026-12-01 12:00 UTC",
    `- **Candidate commit:** \`${commit}\``,
    "- **Verdict:** `PASS`",
  ].join("\n");
const walkthrough = {
  path: "docs/evidence/walkthrough-2026-12.md",
  exists: true,
  isSymlink: false,
  size: signedWalkthroughContent().length,
  sha256: "w".repeat(64),
  content: signedWalkthroughContent(),
};
const implementation = { target: "go-binary", sha256: "b".repeat(64) };
const run = (outcomes, extra = {}) => ({
  target: "go-binary:/usr/bin/varlatchd",
  partial: false,
  ok: true,
  checks: Object.entries(outcomes).map(([id, outcome]) => ({ id, outcome })),
  expectedInForce: [],
  implementation,
  commit: candidateCommit,
  ...extra,
});
const passing = { "a.new": "pass", "a.old": "not-applicable", "a.gone": "not-applicable" };

test("a gate run passes when every rule holds", () => {
  const verdict = judgeGate({ inventory: small, run: run(passing), walkthrough });
  assert.deepEqual(verdict, { passed: true, problems: [], open: [] });
});

test("no expected failure is allowed, and the run itself must pass", () => {
  let v = judgeGate({ inventory: small, run: run(passing, { expectedInForce: ["a.new"] }), walkthrough });
  assert.equal(v.passed, false);
  assert.match(v.problems.join(), /no expected failure is allowed, and 1 are in force for go-binary:\/usr\/bin\/varlatchd: a\.new/);
  v = judgeGate({ inventory: small, run: run(passing, { ok: false }), walkthrough });
  assert.match(v.problems.join(), /the run itself did not pass/);
  v = judgeGate({ inventory: small, run: run(passing, { partial: ["a"] }), walkthrough });
  assert.match(v.problems.join(), /covers every suite/);
});

test("each replacement must be present and passing; an open one fails the gate", () => {
  let v = judgeGate({ inventory: small, run: run({ ...passing, "a.new": "expected-fail" }), walkthrough });
  assert.match(v.problems.join("\n"), /a\.old: its replacement a\.new must pass in this run \(expected-fail\)/);
  assert.match(v.problems.join("\n"), /setup \(scripts\/test-setup\.mjs\): its replacement a\.new must pass/);
  v = judgeGate({ inventory: small, run: run({ "a.old": "pass", "a.gone": "pass" }), walkthrough });
  assert.match(v.problems.join("\n"), /its replacement a\.new must pass in this run \(not in the run\)/);
  const withOpen = structuredClone(small);
  withOpen.externalSuites.setup.replacement = { open: "ADR-0059 step 6" };
  v = judgeGate({ inventory: withOpen, run: run(passing), walkthrough });
  assert.equal(v.passed, false);
  assert.deepEqual(v.open, ["setup (scripts/test-setup.mjs): ADR-0059 step 6"]);
});

test("the browser-walkthrough evidence must be named, under docs/evidence/, present, not empty, not a symlink, and signed off", () => {
  const problem = (w, extraRun = {}) => judgeGate({ inventory: small, run: run(passing, extraRun), walkthrough: w }).problems.join("\n");
  assert.match(problem(null), /names no browser-walkthrough evidence file/);
  assert.match(problem({ ...walkthrough, path: "notes.md" }), /is not under docs\/evidence\//);
  assert.match(problem({ ...walkthrough, path: "docs/evidence/../../x.md" }), /is not under docs\/evidence\//);
  assert.match(problem({ ...walkthrough, isSymlink: true }), /symlink/);
  assert.match(problem({ ...walkthrough, exists: false }), /does not exist/);
  assert.match(problem({ ...walkthrough, size: 0 }), /is empty/);
  assert.match(problem({ ...walkthrough, content: undefined }), /no readable content/);
  // Template sentinel (tolerant whitespace/case), unchecked checklist rows, and unreplaced placeholders fail the gate.
  assert.match(problem({ ...walkthrough, content: `${TEMPLATE_SENTINEL}\n${signedWalkthroughContent()}` }), /still the template/);
  assert.match(problem({ ...walkthrough, content: `<!--  G1-WALKTHROUGH:   template -->\n${signedWalkthroughContent()}` }), /still the template/);
  assert.match(problem({ ...walkthrough, content: `${signedWalkthroughContent()}\n| 2 | [ ] | Audit |` }), /unchecked checklist rows/);
  assert.match(problem({ ...walkthrough, content: `${signedWalkthroughContent()}\n| 3 | [ ] not done |` }), /unchecked checklist rows/);
  assert.match(problem({ ...walkthrough, content: `${signedWalkthroughContent()}\n| x | [ ]` }), /unchecked checklist rows/);
  assert.match(problem({ ...walkthrough, content: signedWalkthroughContent().replace("PASS", "PENDING") }), /unreplaced placeholders/);
  assert.match(problem({ ...walkthrough, content: `${signedWalkthroughContent()}\n| Commit | \`<commit-sha>\` |` }), /unreplaced placeholders/);
  assert.match(problem({ ...walkthrough, content: `${signedWalkthroughContent()}\n| Hash | \`<sha256>\` |` }), /unreplaced placeholders/);
  assert.match(problem({ ...walkthrough, content: `${signedWalkthroughContent()}\n| Date | \`YYYY-MM-DD HH:MM UTC\` |` }), /unreplaced placeholders/);
  assert.match(problem({ ...walkthrough, content: `${signedWalkthroughContent()}\n| Owner | \`<name / handle>\` |` }), /unreplaced placeholders/);
  for (const placeholder of ["<version / sha256>", "<e.g. Chromium 13x / Firefox 13x>", "<e.g. Linux / macOS>", "<GitHub Actions run URL / ID>", "<summary of sign-off>"]) {
    assert.match(problem({ ...walkthrough, content: `${signedWalkthroughContent()}\n\n- Field: \`${placeholder}\`` }), /unreplaced placeholders/, placeholder);
  }
  // The Done column decides a checklist row: a Notes cell starting with
  // [ ] does not uncheck a checked row, and a row without its outer
  // pipes, or with an empty Done cell, is still a row.
  const withRows = (...rows) => signedWalkthroughContent().replace("| 1 | [x] | Projects |", ["| 1 | [x] | Projects |", ...rows].join("\n"));
  assert.equal(problem({ ...walkthrough, content: withRows("| 2 | [x] | Audit | [ ] retest on Safari |") }), "");
  assert.equal(problem({ ...walkthrough, content: withRows("| 2 | [X] | Audit |", "3 | [x] | Access") }), "");
  assert.match(problem({ ...walkthrough, content: withRows("2 | [ ] | Audit") }), /unchecked checklist rows \(.*lines 6\)/);
  assert.match(problem({ ...walkthrough, content: withRows("| 2 | [ ] | Audit |", "3 | [ ] | Access |") }), /lines 6, 7\)/);
  assert.match(problem({ ...walkthrough, content: withRows("| 2 |  | Audit |") }), /unchecked checklist rows/);
  assert.match(problem({ ...walkthrough, content: withRows("| 2 | done | Audit |") }), /unchecked checklist rows/);
  assert.match(problem({ ...walkthrough, content: `${signedWalkthroughContent()}\n\n4 | [ ] | Settings` }), /unchecked checklist rows/);
  // GFM separators of one or two hyphens a cell still make a table with a
  // Done column, whose empty or other cells fail.
  const shortSeparator = signedWalkthroughContent().replace("| --- | --- | --- |", "| - | -- | --- |");
  assert.equal(problem({ ...walkthrough, content: shortSeparator }), "");
  for (const cell of ["", "todo"]) {
    assert.match(problem({ ...walkthrough, content: shortSeparator.replace("| 1 | [x] | Projects |", `| 1 | ${cell} | Projects |`) }), /unchecked checklist rows/, cell);
  }
  // A row a separator follows inside a table is still one of its rows.
  assert.match(problem({ ...walkthrough, content: withRows("| 2 | [ ] | Audit |", "| --- | --- | --- |", "| 3 | [x] | Access |") }), /unchecked checklist rows \(.*lines 6\)/);
  // The evidence is read as plain lines: any HTML comment or fenced code
  // block is refused, wherever it is (the review's bypasses of a parser
  // that blanked them: a comment opened in a cell, in inline code or mid
  // prose; fences an inline span opens or a mismatched marker closes; a
  // fence inside a comment; PASS split by a comment).
  const verdictLine = "- **Verdict:** `PASS`";
  const commitLine = `- **Candidate commit:** \`${candidateCommit}\``;
  const refused = /has HTML comments, raw HTML or fenced code blocks: remove them/;
  for (const [name, content] of [
    ["a commented-out Verdict", signedWalkthroughContent().replace(verdictLine, `<!-- ${verdictLine} -->`)],
    ["a commented-out Candidate commit", signedWalkthroughContent().replace(commitLine, `<!-- ${commitLine} -->`)],
    ["a comment opened in a cell", withRows("| 2 | [x] | Audit | <!-- note |", "| 3 | [ ] | Access |", "-->")],
    ["a comment opened in inline code", `${signedWalkthroughContent()}\n\nUse \`<!--\` sparingly.\n- **Verdict:** FAIL\n`],
    ["a comment opened mid prose", `${signedWalkthroughContent()}\n\nSee below <!-- later\n| 9 | [ ] | old |`],
    ["PASS split by a comment", signedWalkthroughContent().replace("`PASS`", "`PA<!-- -->SS`")],
    ["a backtick fence", signedWalkthroughContent().replace(verdictLine, `\`\`\`\n${verdictLine}\n\`\`\``)],
    ["a tilde fence", signedWalkthroughContent().replace(verdictLine, `~~~~md\n${verdictLine}\n~~~~`)],
    ["a fence closed by another marker", `${signedWalkthroughContent()}\n\`\`\`\n| 9 | [ ] | old |\n\`\`\`~~~`],
    ["an inline span that looks like a fence", `${signedWalkthroughContent()}\n\`\`\`note\`\`\``],
    ["a fence inside a closed comment", `${signedWalkthroughContent()}\n<!--\n\`\`\`\n-->`],
    ["an indented fence", `${signedWalkthroughContent()}\n   ~~~\n   x\n   ~~~`],
    ["a quoted example table", `${signedWalkthroughContent()}\n\n\`\`\`md\n| # | Done |\n| --- | --- |\n| 1 | [ ] |\n\`\`\`\n`],
    // Raw HTML that opens a block or hides its content, in any case.
    ...["details", "pre", "style", "script", "textarea", "template", "noscript", "xmp", "iframe", "table", "div"].map((tag) => [
      `a raw <${tag}> block`,
      signedWalkthroughContent().replace(verdictLine, `<${tag.toUpperCase()} class="x">\n${verdictLine}\n</${tag}>`),
    ]),
    ["a self-closing raw tag", `${signedWalkthroughContent()}\n<div/>`],
    ["a raw tag at the end of the file", `${signedWalkthroughContent()}\n<pre`],
    ["a raw tag across lines", `${signedWalkthroughContent()}\n<details\nopen>\n| 9 | [ ] | old |\n</details>`],
    ["a raw HTML table hiding a row", `${signedWalkthroughContent()}\n<table><tr><td>| 9 | [ ] | old |</td></tr></table>`],
    // Fences opened inside a list item or a blockquote, at any indent.
    ["a fence in a bullet", `${signedWalkthroughContent()}\n- \`\`\`\n  ${verdictLine}\n  \`\`\``],
    ["a fence in a numbered item", `${signedWalkthroughContent()}\n1. ~~~\n   x\n   ~~~`],
    ["a fence in a numbered item with a parenthesis", `${signedWalkthroughContent()}\n2) \`\`\`\n   x\n   \`\`\``],
    ["a fence in a blockquote", `${signedWalkthroughContent()}\n> \`\`\`\n> x\n> \`\`\``],
    ["a fence in a blockquote without a space", `${signedWalkthroughContent()}\n>\`\`\`\n>x\n>\`\`\``],
    ["a fence in a nested list in a blockquote", `${signedWalkthroughContent()}\n> - * ~~~\n>     x`],
    ["a fence indented four spaces", `${signedWalkthroughContent()}\n    \`\`\`\n    x`],
  ]) {
    assert.match(problem({ ...walkthrough, content }), refused, name);
  }
  // Route placeholders, other angle brackets and prose naming the
  // elements are not raw HTML; a bullet without a fence is not one.
  for (const fine of ["| 1 | [x] | Projects | `/o/<org>/p/<git-proj>` |", "The <table-less> layout, a <table-name>, a <predicate>, <divs> and <templates>.", "- Item `x` and ~two~ tildes", "> quoted note"]) {
    assert.equal(problem({ ...walkthrough, content: `${signedWalkthroughContent()}\n\n${fine}` }), "", fine);
  }
  // A 4-space indent is a code block: its Verdict or Candidate commit is
  // not the sign-off's.
  assert.match(problem({ ...walkthrough, content: signedWalkthroughContent().replace(verdictLine, `    ${verdictLine}`) }), /must record \*\*Verdict:\*\* PASS/);
  assert.match(problem({ ...walkthrough, content: signedWalkthroughContent().replace(commitLine, `    ${commitLine}`) }), /40-hex Candidate commit/);
  assert.equal(problem({ ...walkthrough, content: signedWalkthroughContent().replace(verdictLine, `   ${verdictLine}`) }), "");
  // A Verdict line of any bullet and case counts: a second one fails.
  assert.equal(problem({ ...walkthrough, content: signedWalkthroughContent().replace(verdictLine, "* **Verdict:** `PASS`") }), "");
  assert.match(problem({ ...walkthrough, content: `${signedWalkthroughContent()}\n* **verdict:** FAIL` }), /records 2 \*\*Verdict:\*\* lines/);
  assert.match(problem({ ...walkthrough, content: `${signedWalkthroughContent()}\n+ **VERDICT:** PASS` }), /records 2 \*\*Verdict:\*\* lines/);
  // Exactly one Verdict line, and it says PASS.
  for (const second of ["`FAIL`", "`PASS`"]) {
    assert.match(problem({ ...walkthrough, content: `${signedWalkthroughContent()}\n- **Verdict:** ${second}` }), /records 2 \*\*Verdict:\*\* lines; Owner Sign-Off holds exactly one/);
  }
  // Verdict must be PASS (backticks optional).
  assert.equal(problem({ ...walkthrough, content: signedWalkthroughContent().replace("`PASS`", "PASS") }), "");
  assert.match(problem({ ...walkthrough, content: signedWalkthroughContent().replace("`PASS`", "`FAIL`") }), /\*\*Verdict:\*\* PASS/);
  assert.match(problem({ ...walkthrough, content: signedWalkthroughContent().replace(/Verdict.*\n?/, "") }), /\*\*Verdict:\*\* PASS/);
  // Candidate commit must be 40 hex and match the run's commit, including on go-binary fingerprints (which carry no commit).
  assert.match(problem({ ...walkthrough, content: signedWalkthroughContent("deadbeef") }), /40-hex Candidate commit/);
  assert.match(problem({ ...walkthrough, content: signedWalkthroughContent().replace(/Candidate commit.*\n/, "") }), /40-hex Candidate commit/);
  const otherCommit = "f".repeat(40);
  assert.match(problem(walkthrough, { implementation, commit: otherCommit }), /does not match the run's commit/);
  assert.match(problem(walkthrough, { implementation, commit: null }), /recorded no expected commit/);
  assert.equal(problem(walkthrough, { implementation, commit: candidateCommit }), "");
  assert.match(
    problem(walkthrough, { implementation: { target: "ts-source", commit: otherCommit }, commit: null }),
    /does not match the run's commit/,
  );
  assert.equal(problem(walkthrough, { implementation: { target: "ts-source", commit: candidateCommit }, commit: null }), "");
});

test("the shipped g1-walkthrough-template.md fails the gate on its own", () => {
  const templatePath = join(repoRoot, "docs/evidence/g1-walkthrough-template.md");
  const w = readWalkthrough(templatePath, repoRoot);
  assert.equal(w.path, "docs/evidence/g1-walkthrough-template.md");
  assert.equal(w.exists, true);
  assert.equal(w.isSymlink, false);
  const verdict = judgeGate({ inventory: small, run: run(passing), walkthrough: w });
  assert.equal(verdict.passed, false);
  const joined = verdict.problems.join("\n");
  assert.match(joined, /still the template/);
  assert.match(joined, /has HTML comments, raw HTML or fenced code blocks/);
  assert.match(joined, /unchecked checklist rows/);
  assert.match(joined, /unreplaced placeholders/);
  assert.match(joined, /\*\*Verdict:\*\* PASS/);
  assert.match(joined, /40-hex Candidate commit/);
});

// The template, completed as an owner would: every row checked, every
// placeholder filled, the notice and the sentinel gone, Verdict PASS.
test("a completed copy of g1-walkthrough-template.md passes the gate", () => {
  const template = readFileSync(join(repoRoot, "docs/evidence/g1-walkthrough-template.md"), "utf8");
  const completed = template
    .replace(TEMPLATE_SENTINEL, "")
    .replace(/^> .*\n|^>\n/gm, "")
    .replaceAll("| [ ] |", "| [x] |")
    .replace("`PENDING` (set to `PASS` or `FAIL`)", "`PASS`")
    .replace("`PENDING` (set to `PASS` or `FAIL`)", "`PASS`")
    .replaceAll("<commit-sha>", candidateCommit)
    .replaceAll("<sha256>", "b".repeat(64))
    .replaceAll("<version / sha256>", `0.50.0 / ${"c".repeat(64)}`)
    .replace(/<e\.g\.[^>\n]*>/g, "Chromium 131 on Linux")
    .replaceAll("<GitHub Actions run URL / ID>", "123456789")
    .replaceAll("<summary of sign-off>", "Walked through; no findings.")
    .replaceAll("YYYY-MM-DD HH:MM UTC", "2026-12-01 12:00 UTC")
    .replaceAll("<name / handle>", "owner");
  const w = { ...walkthrough, size: completed.length, content: completed };
  const verdict = judgeGate({ inventory: small, run: run(passing), walkthrough: w });
  assert.deepEqual(verdict.problems, []);
  // Its CRLF copy too.
  const crlf = { ...w, content: completed.replace(/\n/g, "\r\n") };
  assert.deepEqual(judgeGate({ inventory: small, run: run(passing), walkthrough: crlf }).problems, []);
});

test("readWalkthrough and judgeGate reject symlinked evidence files and symlinked parent directories", () => {
  const dir = mkdtempSync(join(tmpdir(), "varlatch-gate-walkthrough-"));
  try {
    const evidenceDir = join(dir, "docs", "evidence");
    mkdirSync(evidenceDir, { recursive: true });
    const realFile = join(evidenceDir, "signed.md");
    writeFileSync(realFile, signedWalkthroughContent());
    // Direct file symlink inside docs/evidence/.
    const fileLink = join(evidenceDir, "link.md");
    symlinkSync(realFile, fileLink);
    const linked = readWalkthrough(fileLink, dir);
    assert.equal(linked.isSymlink, true);
    assert.match(judgeGate({ inventory: small, run: run(passing), walkthrough: linked }).problems.join("\n"), /symlink/);

    // Symlinked subdirectory inside docs/evidence/ pointing outside docs/evidence/.
    const outsideDir = join(dir, "outside");
    mkdirSync(outsideDir, { recursive: true });
    writeFileSync(join(outsideDir, "signed.md"), signedWalkthroughContent());
    symlinkSync(outsideDir, join(evidenceDir, "sub"));
    const viaDirLink = readWalkthrough(join(evidenceDir, "sub", "signed.md"), dir);
    assert.equal(viaDirLink.isSymlink, true);
    assert.match(judgeGate({ inventory: small, run: run(passing), walkthrough: viaDirLink }).problems.join("\n"), /symlink/);

    // Regular file inside docs/evidence/ passes cleanly.
    const regular = readWalkthrough(realFile, dir);
    assert.equal(regular.isSymlink, false);
    assert.equal(regular.exists, true);
    const ok = judgeGate({ inventory: small, run: run(passing), walkthrough: regular });
    assert.deepEqual(ok, { passed: true, problems: [], open: [] });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

/** A complete report of a gate run with a source CLI, as run.mjs writes it. */
const recentReport = (change = () => {}) => {
  const report = {
    target: "go-binary:/usr/bin/varlatchd",
    partial: false,
    implementation: structuredClone(implementation),
    cli: { spec: "source", version: null, sha256: "c".repeat(64) },
    checks: [
      { id: "a.new", outcome: "pass" },
      { id: "a.old", outcome: "not-applicable" },
      { id: "a.gone", outcome: "not-applicable" },
    ],
    problems: [],
    ok: true,
    gate: { passed: true, walkthrough: { ...walkthrough } },
  };
  change(report);
  return report;
};
const old = run({ "a.new": "pass", "a.old": "not-applicable", "a.gone": "predates-cli" });
const why = (report) => recentCliProblems(report, { inventory: small, target: old.target, implementation, walkthrough }).join("\n");

test("a run whose CLI predates checks needs the complete, passing report of the same implementation with a recent CLI", () => {
  assert.match(judgeGate({ inventory: small, run: old, walkthrough }).problems.join(), /1 checks predate this run's CLI, .*--recent-cli-report.*: none named/);
  const verdict = judgeGate({ inventory: small, run: old, walkthrough, recentCli: recentReport() });
  assert.equal(verdict.passed, true, verdict.problems.join());
  assert.equal(why(recentReport((r) => (r.cli = { spec: "0.22.0", version: "0.22.0" }))), "");
});

test("the recent-CLI report is judged again, not trusted: a bare or failing report with ok and gate.passed set is refused", () => {
  // Sol's case: only the fields a forger would set.
  const bare = why({ target: old.target, ok: true, gate: { passed: true } });
  assert.match(bare, /not a complete run/);
  assert.match(bare, /ran another implementation/);
  assert.match(bare, /names no verified CLI/);
  assert.match(bare, /reports problems outside its checks/);
  assert.match(bare, /3 inventory checks are missing/);
  // A failed check, with ok and gate.passed still claimed.
  assert.match(why(recentReport((r) => (r.checks[0].outcome = "fail"))), /1 of its checks did not pass \(a\.new: fail\)/);
  assert.match(why(recentReport((r) => (r.checks[0].outcome = "expected-fail"))), /did not pass/);
  assert.match(why(recentReport((r) => (r.checks[1].outcome = "predates-cli"))), /did not pass \(a\.old: predates-cli\)/);
  // Not applicable is accepted for a ts-stack check only.
  assert.match(why(recentReport((r) => (r.checks[0].outcome = "not-applicable"))), /a\.new: not-applicable/);
  assert.match(why(recentReport((r) => r.checks.pop())), /1 inventory checks are missing from it \(a\.gone\)/);
  assert.match(why(recentReport((r) => r.checks.push({ id: "a.extra", outcome: "pass" }))), /checks the inventory does not \(a\.extra\)/);
  assert.match(why(recentReport((r) => r.checks.push({ id: "a.new", outcome: "pass" }))), /more than once \(a\.new\)/);
  assert.match(why(recentReport((r) => (r.problems = ["runner: the run stopped"]))), /problems outside its checks/);
  assert.match(why(recentReport((r) => (r.partial = ["a"]))), /not a complete run/);
  assert.match(why(recentReport((r) => (r.checks[0].expected = { reason: "x" }))), /its own gate: no expected failure is allowed/);
});

test("the recent-CLI report must come from the same implementation, a CLI that predates nothing, and the same walkthrough", () => {
  assert.match(why(recentReport((r) => (r.target = "go-binary:/other/varlatchd"))), /a run of "go-binary:\/other\/varlatchd"/);
  // Same path, another binary.
  assert.match(why(recentReport((r) => (r.implementation.sha256 = "d".repeat(64)))), /ran another implementation/);
  assert.match(why(recentReport((r) => delete r.implementation)), /ran another implementation/);
  assert.match(recentCliProblems(recentReport(), { inventory: small, target: old.target, implementation: null }).join(), /this run recorded no implementation fingerprint/);
  // Its CLI must predate nothing in the current inventory.
  assert.match(why(recentReport((r) => (r.cli = { spec: "0.19.0", version: "0.19.0" }))), /its CLI 0\.19\.0 predates scan/);
  assert.match(why(recentReport((r) => (r.gate.walkthrough.sha256 = "x".repeat(64)))), /other browser-walkthrough evidence/);
  // Fingerprints compare by content, not key order.
  assert.equal(canonical({ b: 1, a: [1, { d: 2, c: 3 }] }), canonical({ a: [1, { c: 3, d: 2 }], b: 1 }));
  assert.deepEqual(predatedFeatures(small, null), []);
  assert.deepEqual(predatedFeatures(small, "0.19.9"), ["scan"]);
  assert.deepEqual(predatedFeatures(small, "0.20.0"), []);
});

test("a gate run needs its own implementation fingerprint", () => {
  const verdict = judgeGate({ inventory: small, run: run(passing, { implementation: null }), walkthrough });
  assert.match(verdict.problems.join(), /recorded no implementation fingerprint/);
});

test("every replacement is closed: the best run passes the gate on each target", () => {
  const open = replacements(inventory).filter((r) => r.replacement && typeof r.replacement === "object" && "open" in r.replacement);
  // Every check is replaced or has its Go counterpart named: doctor's are
  // the Go installation's (step 6.5), its pending upgrade the CLI's own
  // (step 6.6's journal), which the runner's doctor does not ask. Each
  // lifecycle and installer suite is written in the step its Go counterpart
  // lands. The Convex realtime checks' are
  // written (step 3.5): the degraded-state checks, which run on every
  // target.
  assert.ok(!open.some((r) => r.of.startsWith("realtime.")));
  for (const [id, c] of Object.entries(inventory.checks)) {
    if (id.startsWith("realtime.") && typeof c.replacement === "string") assert.match(c.replacement, /^(realtime-degraded|dashboard)\./, id);
  }
  assert.deepEqual(open.filter((r) => inventory.checks[r.of]).map((r) => r.of), []);
  assert.match(inventory.checks["doctor.release-pending-upgrade"].replacement.none, /go\.yml.*TestDoctorReadsTheUpgradeJournal/);
  // An external suite is open until its Go counterpart lands; the backup
  // suites', the Compose recovery gate's (the image test, step 6.10a), the
  // move's (step 6.9), setup's and its public ingress' (step 6.4a, with 6.3's
  // listener), the installers' (step 6.1) and the sidecar's (none: the Go
  // node is in process) run in the Go workflow, so they name none.
  for (const [name, suite] of Object.entries(inventory.externalSuites)) {
    if (["backup-e2e", "backup-s3", "backup-compose", "move", "setup", "ingress-public", "installers", "sidecar-restart"].includes(name)) assert.match(suite.replacement.none, /go\.yml/, name);
    // The Coolify live checks' Go counterparts are manual too (step 4.9e:
    // build tag coolifylive, run by hand on the lab, with their evidence).
    else if (["coolify-live", "coolify-live-expands"].includes(name)) assert.match(suite.replacement.none, /TestCoolifyLive\w+ \(build tag coolifylive/, name);
    // The Go CLI has no adopt: there is nothing to run.
    else if (name === "adopt") assert.match(suite.replacement.none, /never manages a Compose installation/);
    // A real tailnet, the rehearsals and the production archive: run by hand,
    // with their evidence.
    else if (["ingress-tailnet", "tailnet-endpoint", "prod-shape"].includes(name)) assert.match(suite.replacement.none, /internal docs\/evidence\//, name);
    else if (["backup-upgrade", "backup-v0100-restore"].includes(name)) assert.match(suite.replacement.none, /go\.yml[\s\S]*internal docs\/evidence\//, name);
    else assert.ok(open.some((r) => r.of.startsWith(`${name} (`)), name);
  }
  assert.deepEqual(open, []);

  // The best a run can do on each target: every check passes (a ts-stack
  // check does not apply where the target has no TypeScript stack, nor a
  // go-server check where it is not the Go server), with a recent CLI, no
  // expected failure and the walkthrough named.
  for (const [target, tsStack, goServer] of [["ts-source", "pass", "not-applicable"], ["ts-release:0.22.0", "pass", "not-applicable"], ["go-binary:/opt/varlatchd", "not-applicable", "pass"], ["go-container:varlatchd:test", "not-applicable", "pass"]]) {
    const outcomes = Object.fromEntries(Object.entries(inventory.checks).map(([id, c]) => [id, c.kind === "ts-stack" ? tsStack : c.kind === "go-server" ? goServer : "pass"]));
    const verdict = judgeGate({ inventory, run: run(outcomes, { target }), walkthrough });
    assert.deepEqual(verdict.problems, [], target);
    assert.equal(verdict.passed, true, target);
  }
});

test("a ts-stack check replaced by a go-server check: on the Go server the replacement must pass, off it the check itself", () => {
  const replaced = Object.entries(inventory.checks).filter(([, c]) => c.kind === "ts-stack" && typeof c.replacement === "string" && inventory.checks[c.replacement]?.kind === "go-server");
  assert.ok(replaced.length > 0, "the doctor's checks are replaced by the Go installation's (step 6.5)");
  const [of, { replacement }] = replaced[0];
  const outcomes = (failing) => Object.fromEntries(Object.entries(inventory.checks).map(([id, c]) => [id, id === failing ? "fail" : c.kind === "ts-stack" ? "pass" : c.kind === "go-server" ? "not-applicable" : "pass"]));
  const ts = judgeGate({ inventory, run: run(outcomes(of), { target: "ts-source" }), walkthrough });
  assert.ok(ts.problems.some((p) => p.startsWith(`${of}: off the Go server it must pass itself`)), ts.problems.join("\n"));
  const goOutcomes = Object.fromEntries(Object.entries(inventory.checks).map(([id, c]) => [id, c.kind === "ts-stack" ? "not-applicable" : id === replacement ? "fail" : "pass"]));
  // The Go server is go-binary and go-container alike (the image's
  // varlatchd, run as go-binary): there the replacement must pass.
  for (const target of ["go-binary:/opt/varlatchd", "go-container:varlatchd:test"]) {
    const go = judgeGate({ inventory, run: run(goOutcomes, { target }), walkthrough });
    assert.ok(go.problems.some((p) => p.startsWith(`${of}: its replacement ${replacement} must pass in this run`)), `${target}: ${go.problems.join("\n")}`);
    assert.ok(!go.problems.some((p) => p.startsWith(`${of}: off the Go server`)), target);
  }
  assert.equal(onGoServer("go-container:varlatchd:test"), true);
  assert.equal(onGoServer("go-binary:/opt/varlatchd"), true);
  assert.equal(onGoServer("ts-release:0.22.0"), false);
  assert.equal(onGoServer("go-binaryx:/x"), false);
});

test("the hand-over's go-client checks may be not applicable only when the CLI under test is not the Go CLI", () => {
  const handover = Object.keys(inventory.checks).filter((id) => inventory.checks[id].kind === "go-client");
  assert.ok(handover.length > 0);
  const outcomes = Object.fromEntries(Object.entries(inventory.checks).map(([id, c]) => [id, c.kind === "ts-stack" || c.kind === "go-client" ? "not-applicable" : "pass"]));
  for (const cli of ["source", "0.22.0"]) {
    const verdict = judgeGate({ inventory, run: run(outcomes, { cli }), walkthrough });
    assert.ok(!verdict.problems.some((p) => /must run and pass/.test(p)), `${cli}: ${verdict.problems.join("\n")}`);
  }
  const verdict = judgeGate({ inventory, run: run(outcomes, { cli: "go" }), walkthrough });
  assert.ok(verdict.problems.some((p) => /must run and pass: .*cli-handover\./.test(p)), verdict.problems.join("\n"));
});

test("on the Go server, G11's go-server checks must run: not applicable there fails the gate", () => {
  const outcomes = Object.fromEntries(Object.entries(inventory.checks).map(([id, c]) => [id, c.kind === "ts-stack" || c.kind === "go-server" ? "not-applicable" : "pass"]));
  const verdict = judgeGate({ inventory, run: run(outcomes, { target: "go-binary:/opt/varlatchd" }), walkthrough });
  assert.ok(verdict.problems.some((p) => /must run and pass: .*realtime-events\./.test(p)), verdict.problems.join("\n"));
});
