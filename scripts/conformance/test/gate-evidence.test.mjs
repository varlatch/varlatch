// SPDX-License-Identifier: Apache-2.0
/**
 * Gate evidence from a commit of its own (lib/gate-evidence.mjs,
 * gate-evidence.mjs, conformance.yml's gate job): the owner's committed
 * walkthrough passes, and everything else that could come with it is
 * refused. Each case is a real commit on top of a candidate, fetched from an
 * origin as CI fetches it.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { evidenceText, judgeGate, readWalkthrough, walkthroughProblems } from "../lib/gate.mjs";
import { evidenceDiffProblems, EvidenceRefused, evidencePathProblem, fetchEvidenceCommit, headCommit, readWalkthroughAt, refProblem } from "../lib/gate-evidence.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const PATH = "docs/evidence/g1-walkthrough-v0.50.0.md";
// Runs of git here never read this machine's configuration or hooks.
const env = {
  ...process.env,
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.invalid", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.invalid",
};
for (const k of Object.keys(env)) if (/^GIT_(DIR|WORK_TREE|INDEX_FILE|OBJECT_DIRECTORY|COMMON_DIR|PREFIX)$/.test(k)) delete env[k];
const git = (cwd, ...args) => {
  const r = spawnSync("git", args, { cwd, encoding: "utf8", env });
  assert.equal(r.status, 0, `git ${args.join(" ")}: ${r.stderr}`);
  return r.stdout.trim();
};

const signed = (commit, change = (t) => t) =>
  change(
    ["# G1 walkthrough", "", "| # | Done | Screen |", "| --- | --- | --- |", "| 1 | [x] | Projects |", "", "## 7. Owner Sign-Off", "",
      `- **Candidate commit:** \`${commit}\``, "- **Verdict:** `PASS`", ""].join("\n"),
  );

let dir;
let author; // where the owner commits; its origin is `origin`
let checkout; // CI's checkout of the candidate: depth 1, detached
let candidate;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "varlatch-gate-evidence-"));
  author = join(dir, "author");
  const origin = join(dir, "origin.git");
  mkdirSync(author);
  git(author, "init", "-q", "-b", "main");
  // The gate's own scripts are part of the candidate, as in CI.
  for (const f of ["gate-evidence.mjs", "lib"]) cpSync(join(repoRoot, "scripts/conformance", f), join(author, "scripts/conformance", f), { recursive: true });
  mkdirSync(join(author, "docs/evidence"), { recursive: true });
  writeFileSync(join(author, "docs/evidence/README.md"), "readme\n");
  writeFileSync(join(author, "docs/evidence/old.md"), "an earlier record, long enough to be found again if it moved\n");
  writeFileSync(join(author, "app.txt"), "the product\n");
  git(author, "add", "-A");
  git(author, "commit", "-q", "-m", "candidate");
  candidate = git(author, "rev-parse", "HEAD");
  git(dir, "clone", "-q", "--bare", author, origin);
  // As GitHub: a full hash of a ref it has can be fetched.
  git(origin, "config", "uploadpack.allowReachableSHA1InWant", "true");
  git(author, "remote", "add", "origin", `file://${origin}`);
  checkout = join(dir, "checkout");
  git(dir, "clone", "-q", "--depth=1", `file://${origin}`, checkout);
  git(checkout, "checkout", "-q", "--detach", candidate);
});
after(() => rmSync(dir, { recursive: true, force: true }));

let n = 0;
/** A pushed branch: the candidate, changed by `change(root)`; its name and commit. */
function evidence(change) {
  const branch = `evidence/case-${++n}`;
  git(author, "checkout", "-q", "-f", "-B", branch, candidate);
  git(author, "clean", "-qfdx");
  change(author);
  git(author, "add", "-A");
  git(author, "commit", "-q", "--allow-empty", "-m", branch);
  git(author, "push", "-q", "origin", branch);
  return { branch, commit: git(author, "rev-parse", "HEAD") };
}
const write = (root, path, text) => {
  mkdirSync(dirname(join(root, path)), { recursive: true });
  writeFileSync(join(root, path), text);
};
const good = (root) => write(root, PATH, signed(candidate));
/** gate-evidence.mjs of the candidate's checkout, as conformance.yml runs it. */
function preflight(ref, { path = PATH, at = candidate } = {}) {
  const output = join(dir, `output-${++n}`);
  writeFileSync(output, "");
  const r = spawnSync(process.execPath, ["scripts/conformance/gate-evidence.mjs", "--candidate", at, "--ref", ref, "--path", path, "--output", output], { cwd: checkout, encoding: "utf8", env });
  return { status: r.status, out: r.stdout + r.stderr, output: readFileSync(output, "utf8") };
}
const refusedRead = (commit, pattern, path = PATH) => {
  fetchEvidenceCommit(checkout, commit);
  assert.throws(() => readWalkthroughAt(checkout, { path, candidate, evidence: commit }), (err) => err instanceof EvidenceRefused && pattern.test(err.message));
};

const inventory = { features: {}, checks: { "a.new": { suite: "a", kind: "conformance" } }, externalSuites: {} };
const run = { target: "go-binary:/usr/bin/varlatchd", partial: false, ok: true, checks: [{ id: "a.new", outcome: "pass" }], expectedInForce: [], implementation: { target: "go-binary", sha256: "b".repeat(64) } };

test("a committed walkthrough passes: it names the candidate, and the evidence commit is another", () => {
  const { branch, commit } = evidence(good);
  assert.notEqual(commit, candidate);
  const r = preflight(branch);
  assert.equal(r.status, 0, r.out);
  assert.equal(r.output, `evidence=${commit}\n`);
  const w = readWalkthroughAt(checkout, { path: PATH, candidate, evidence: commit });
  assert.deepEqual(w, { ...w, path: PATH, exists: true, isSymlink: false, content: signed(candidate), evidenceCommit: commit });
  assert.deepEqual(judgeGate({ inventory, run: { ...run, commit: candidate }, walkthrough: w }), { passed: true, problems: [], open: [] });
  // Compared with the evidence commit, as HEAD would be had it been checked
  // out, it could never pass.
  assert.match(walkthroughProblems(w, { commit }).join(), /does not match the run's commit/);
  // Nothing of the evidence commit reached the checkout.
  assert.equal(headCommit(checkout), candidate);
  assert.equal(existsSync(join(checkout, PATH)), false);
  assert.equal(git(checkout, "status", "--porcelain"), "");
  // A tag and a full hash name it too.
  git(author, "tag", "evidence-tag", commit);
  git(author, "push", "-q", "origin", "evidence-tag");
  for (const ref of ["evidence-tag", commit]) assert.equal(preflight(ref).output, `evidence=${commit}\n`, ref);
});

test("other evidence files beside the walkthrough, added or changed, are allowed", () => {
  const { branch } = evidence((root) => {
    good(root);
    write(root, "docs/evidence/notes/shot.txt", "x\n");
    write(root, "docs/evidence/README.md", "readme, with the record listed\n");
  });
  const r = preflight(branch);
  assert.equal(r.status, 0, r.out);
});

test("a ref that changes anything outside docs/evidence/ is refused", () => {
  for (const [name, change, shown] of [
    ["a changed file", (root) => write(root, "app.txt", "another product\n"), '"app.txt"'],
    ["an added file", (root) => write(root, "scripts/conformance/expect/x.json", "{}\n"), '"scripts/conformance/expect/x.json"'],
    ["a deleted file", (root) => rmSync(join(root, "app.txt")), '"app.txt"'],
    ["a mode change", (root) => chmodSync(join(root, "app.txt"), 0o755), '"app.txt"'],
    ["the gate's own rules", (root) => write(root, "scripts/conformance/lib/gate.mjs", "export const walkthroughProblems = () => [];\n"), "gate.mjs"],
    ["a sibling directory whose name starts alike", (root) => write(root, "docs/evidence-extra/x.md", "x\n"), '"docs/evidence-extra/x.md"'],
    ["a name with a newline", (root) => write(root, "docs/evidence\n/x.md", "x\n"), "evidence\\n/x.md"],
  ]) {
    const { branch, commit } = evidence((root) => (good(root), change(root)));
    const r = preflight(branch);
    assert.equal(r.status, 1, `${name}: ${r.out}`);
    assert.match(r.out, /outside docs\/evidence\//, name);
    assert.ok(r.out.includes(shown), `${name}: ${r.out}`);
    assert.equal(r.output, "", name);
    refusedRead(commit, /outside docs\/evidence\//);
  }
});

test("under docs/evidence/, a deleted, renamed, executable or symlinked file and a submodule are refused", () => {
  for (const [name, change, pattern] of [
    ["deleted", (root) => rmSync(join(root, "docs/evidence/old.md")), /"docs\/evidence\/old\.md" is deleted/],
    ["renamed", (root) => git(root, "mv", "docs/evidence/old.md", "docs/evidence/new.md"), /"docs\/evidence\/old\.md" is deleted/],
    ["renamed out of it", (root) => git(root, "mv", "docs/evidence/old.md", "docs/old.md"), /"docs\/old\.md" differs from the candidate, outside/],
    ["executable", (root) => (write(root, "docs/evidence/run.sh", "x\n"), chmodSync(join(root, "docs/evidence/run.sh"), 0o755)), /run\.sh" is not a regular file added or changed/],
    ["made executable", (root) => chmodSync(join(root, "docs/evidence/old.md"), 0o755), /old\.md" is not a regular file added or changed/],
    ["a symlink", (root) => symlinkSync("../../app.txt", join(root, "docs/evidence/link.md")), /"docs\/evidence\/link\.md" is a symlink/],
    ["a file made a symlink", (root) => (rmSync(join(root, "docs/evidence/old.md")), symlinkSync("README.md", join(root, "docs/evidence/old.md"))), /"docs\/evidence\/old\.md" is a symlink/],
    ["a submodule", (root) => git(root, "update-index", "--add", "--cacheinfo", `160000,${candidate},docs/evidence/sub`), /"docs\/evidence\/sub" is a submodule/],
  ]) {
    // The submodule's entry is in the index only: git add -A keeps a gitlink without a directory out, so commit it as it is.
    const made = name === "a submodule" ? submodule() : evidence((root) => (good(root), change(root)));
    const r = preflight(made.branch);
    assert.equal(r.status, 1, `${name}: ${r.out}`);
    assert.match(r.out, pattern, name);
    refusedRead(made.commit, pattern);
  }
  function submodule() {
    const made = evidence(good);
    git(author, "update-index", "--add", "--cacheinfo", `160000,${candidate},docs/evidence/sub`);
    git(author, "commit", "-q", "--amend", "-m", "submodule");
    git(author, "push", "-q", "-f", "origin", made.branch);
    return { branch: made.branch, commit: git(author, "rev-parse", "HEAD") };
  }
});

test("the walkthrough itself must be a regular file of the evidence commit", () => {
  const link = evidence((root) => symlinkSync("README.md", join(root, PATH)));
  assert.match(preflight(link.branch).out, /is a symlink/);
  const none = evidence((root) => write(root, "docs/evidence/other.md", "x\n"));
  assert.match(preflight(none.branch).out, /has no file docs\/evidence\/g1-walkthrough-v0\.50\.0\.md/);
  const directory = evidence((root) => write(root, `${PATH}/inner.md`, "x\n"));
  assert.match(preflight(directory.branch).out, /is not a regular file/);
  const empty = evidence((root) => write(root, PATH, ""));
  assert.match(preflight(empty.branch).out, /is empty/);
  const big = evidence((root) => write(root, PATH, signed(candidate) + "x".repeat(1024 * 1024)));
  assert.match(preflight(big.branch).out, /more than 1048576/);
  for (const made of [link, none, directory, empty, big]) assert.equal(preflight(made.branch).status, 1);
  // The evidence commit as the candidate: no file was added.
  assert.match(preflight("main").out, /has no file/);
});

test("a wrong Candidate commit, an unticked row and the other content rules are refused before anything is built", () => {
  for (const [name, text, pattern] of [
    ["a wrong Candidate commit", () => signed("f".repeat(40)), /Candidate commit \(f{40}\) does not match the run's commit/],
    ["no Candidate commit", () => signed(candidate, (t) => t.replace(/.*Candidate commit.*\n/, "")), /40-hex Candidate commit/],
    ["an unticked row", () => signed(candidate, (t) => t.replace("[x]", "[ ]")), /unchecked checklist rows/],
    ["a failing verdict", () => signed(candidate, (t) => t.replace("PASS", "FAIL")), /\*\*Verdict:\*\* PASS/],
    ["a placeholder", () => signed(candidate, (t) => `${t}\n<summary of sign-off>\n`), /unreplaced placeholders/],
    ["an HTML comment", () => signed(candidate, (t) => `${t}\n<!-- note -->\n`), /HTML comments/],
  ]) {
    const { branch } = evidence((root) => write(root, PATH, text()));
    const r = preflight(branch);
    assert.equal(r.status, 1, `${name}: ${r.out}`);
    assert.match(r.out, pattern, name);
    assert.equal(r.output, "", name);
  }
  // Naming the evidence commit as the candidate is a wrong one too.
  const first = evidence(good);
  const { branch } = evidence((root) => write(root, PATH, signed(first.commit)));
  assert.match(preflight(branch).out, /does not match the run's commit/);
});

/** Text and raw bytes, joined. */
const bytes = (...parts) => Buffer.concat(parts.map((p) => Buffer.from(p)));
// The signed record with the bytes put into a Notes-like line before the sign-off.
const withBytes = (...raw) => {
  const [head, tail] = signed(candidate).split("## 7. Owner Sign-Off");
  return bytes(head, "Notes: ", ...raw, "\n\n## 7. Owner Sign-Off", tail);
};
// Bytes a forgiving reader would replace, drop or read as another line.
const NOT_TEXT = [
  ["a byte no UTF-8 has", [[0xff]], /is not valid UTF-8/],
  ["a truncated character", [[0xe2, 0x82]], /is not valid UTF-8/],
  ["an overlong NUL", [[0xc0, 0x80]], /is not valid UTF-8/],
  ["a surrogate", [[0xed, 0xa0, 0x80]], /is not valid UTF-8/],
  ["a code point past the last", [[0xf4, 0x90, 0x80, 0x80]], /is not valid UTF-8/],
  ["a NUL", ["a", [0x00], "b"], /has a NUL character/],
  ["a byte order mark inside", [[0xef, 0xbb, 0xbf]], /has a byte order mark/],
  ["a lone CR, a row of its own to a reader", ["x\r| 9 | [ ] | hidden |"], /has a control character/],
  ["a vertical tab", [[0x0b]], /has a control character/],
  ["an escape", [[0x1b], "[2K"], /has a control character/],
  ["a C1 next line", [[0xc2, 0x85]], /has a control character/],
  ["a line separator", [[0xe2, 0x80, 0xa8]], /has a control character/],
  ["a paragraph separator", [[0xe2, 0x80, 0xa9]], /has a control character/],
];

test("malformed UTF-8, a byte order mark, NUL and other control characters are refused, not replaced", () => {
  for (const [name, raw, pattern] of NOT_TEXT) {
    const { branch, commit } = evidence((root) => write(root, PATH, withBytes(...raw)));
    const r = preflight(branch);
    assert.equal(r.status, 1, `${name}: ${r.out}`);
    assert.match(r.out, pattern, name);
    assert.equal(r.output, "", name);
    refusedRead(commit, pattern);
  }
  // A byte order mark where one usually is, and UTF-16.
  for (const [raw, pattern] of [[bytes([0xef, 0xbb, 0xbf], signed(candidate)), /has a byte order mark/], [Buffer.from(signed(candidate), "utf16le"), /NUL|UTF-8/]]) {
    const { commit } = evidence((root) => write(root, PATH, raw));
    refusedRead(commit, pattern);
  }
});

test("LF, CRLF, tabs and UTF-8 are judged byte for byte: the recorded hash is of the committed file", () => {
  for (const [name, raw] of [
    ["LF", bytes(signed(candidate))],
    ["CRLF", bytes(signed(candidate).replace(/\n/g, "\r\n"))],
    ["tabs and other scripts", withBytes("a\tb: \u00e9, \u2713, \ud83d\ude80")],
  ]) {
    const { branch, commit } = evidence((root) => write(root, PATH, raw));
    // As committed: no line-ending conversion on the way.
    assert.deepEqual(Buffer.from(spawnSync("git", ["cat-file", "blob", `${commit}:${PATH}`], { cwd: author, env }).stdout), raw, name);
    const r = preflight(branch);
    assert.equal(r.status, 0, `${name}: ${r.out}`);
    const w = readWalkthroughAt(checkout, { path: PATH, candidate, evidence: commit });
    assert.equal(w.sha256, createHash("sha256").update(raw).digest("hex"), name);
    assert.deepEqual(Buffer.from(w.content), raw, name);
    assert.equal(w.size, raw.length, name);
    assert.deepEqual(walkthroughProblems(w, { commit: candidate }), [], name);
  }
});

test("a file of the checkout is read the same way: bytes that are not plain text fail the gate", () => {
  const root = join(dir, "working-tree");
  for (const [name, raw, pattern] of NOT_TEXT) {
    write(root, PATH, withBytes(...raw));
    const w = readWalkthrough(join(root, PATH), root);
    assert.equal(w.content, null, name);
    assert.match(judgeGate({ inventory, run: { ...run, commit: candidate }, walkthrough: w }).problems.join(), pattern, name);
  }
  write(root, PATH, signed(candidate).replace(/\n/g, "\r\n"));
  assert.deepEqual(walkthroughProblems(readWalkthrough(join(root, PATH), root), { commit: candidate }), []);
  assert.deepEqual(evidenceText(Buffer.from("a\r\nb\n\tc")), { text: "a\r\nb\n\tc" });
});

test("a missing ref, a ref that is not a plain name and a checkout elsewhere are refused", () => {
  const { branch, commit } = evidence(good);
  assert.match(preflight("evidence/none").out, /walkthrough_ref evidence\/none: git fetch/);
  assert.match(preflight("0".repeat(40)).out, /git fetch/);
  for (const ref of ["--upload-pack=touch x", "-x", "+main", "main:other", "a b", "a..b", "main^", "main~1", "main@{0}", "refs/*", "a;b", "$(id)", "`id`", "a\nb", "/main", "main/", "a//b", "a.lock", "a/.b", ""]) {
    assert.ok(refProblem(ref), JSON.stringify(ref));
    assert.throws(() => fetchEvidenceCommit(checkout, ref), EvidenceRefused, JSON.stringify(ref));
  }
  for (const ref of ["main", "evidence/g1-v0.50.0", "v0.50.0-rc.3", commit]) assert.equal(refProblem(ref), null, ref);
  // An empty ref or path is a usage error, so one without the other never passes.
  assert.equal(preflight("").status, 64);
  assert.equal(preflight(branch, { path: "" }).status, 64);
  // The judge must be the candidate's.
  assert.match(preflight(branch, { at: "f".repeat(40) }).out, /the checkout is at .*, not at the candidate/);
  assert.match(preflight(branch, { at: "main" }).out, /not at the candidate/);
  git(checkout, "fetch", "-q", "--depth=1", "origin", commit);
  git(checkout, "checkout", "-q", "--detach", commit);
  try {
    const r = preflight(branch);
    assert.equal(r.status, 1);
    assert.match(r.out, /not at the candidate/);
  } finally {
    git(checkout, "checkout", "-q", "--detach", candidate);
  }
  // Neither commit may be named by anything but its full hash.
  for (const bad of ["HEAD", commit.slice(0, 12), "", undefined]) {
    assert.throws(() => readWalkthroughAt(checkout, { path: PATH, candidate, evidence: bad }), EvidenceRefused);
    assert.throws(() => readWalkthroughAt(checkout, { path: PATH, candidate: bad, evidence: commit }), EvidenceRefused);
  }
  // A commit the checkout does not have, and an object that is no commit.
  assert.throws(() => readWalkthroughAt(checkout, { path: PATH, candidate, evidence: "1".repeat(40) }), EvidenceRefused);
  const tree = git(checkout, "rev-parse", `${candidate}^{tree}`);
  assert.throws(() => readWalkthroughAt(checkout, { path: PATH, candidate, evidence: tree }), /is a tree, not a commit/);
  assert.deepEqual(evidenceDiffProblems(checkout, candidate, candidate), []);
});

test("the walkthrough's path is a plain file path under docs/evidence/", () => {
  for (const path of ["notes.md", "docs/evidence", "docs/evidence/", "docs/evidence/../x.md", "docs/evidence/./x.md", "docs/evidence//x.md", "/docs/evidence/x.md", "docs/evidence/*.md", "docs/evidence/a b.md", "docs/evidence/x.md\n", ":(top)docs/evidence/x.md", "", undefined]) {
    assert.ok(evidencePathProblem(path), JSON.stringify(path));
    assert.throws(() => readWalkthroughAt(checkout, { path, candidate, evidence: candidate }), EvidenceRefused, JSON.stringify(path));
  }
  assert.equal(evidencePathProblem(PATH), null);
});

test("run.mjs refuses gate evidence it cannot use before anything starts", () => {
  const runner = (...args) => {
    const r = spawnSync(process.execPath, [join(repoRoot, "scripts/conformance/run.mjs"), "--target", "go-binary:/nonexistent", "--cli", "source", ...args], { encoding: "utf8", env, cwd: repoRoot });
    return { status: r.status, out: r.stdout + r.stderr };
  };
  const head = git(repoRoot, "rev-parse", "HEAD");
  let r = runner("--walkthrough-commit", head);
  assert.deepEqual([r.status, /belong to --gate/.test(r.out)], [64, true], r.out);
  r = runner("--gate", "--walkthrough-commit", head);
  assert.deepEqual([r.status, /needs --walkthrough and --candidate/.test(r.out)], [64, true], r.out);
  r = runner("--gate", "--walkthrough", PATH, "--walkthrough-commit", head);
  assert.deepEqual([r.status, /needs --walkthrough and --candidate/.test(r.out)], [64, true], r.out);
  r = runner("--gate", "--candidate", "f".repeat(40));
  assert.deepEqual([r.status, /the checkout is at/.test(r.out)], [64, true], r.out);
  r = runner("--gate", "--candidate", head, "--walkthrough", "docs/evidence/none.md", "--walkthrough-commit", head);
  assert.deepEqual([r.status, /has no file docs\/evidence\/none\.md/.test(r.out)], [64, true], r.out);
  // conformance.yml passes what the evidence step answered: nothing, when it was not accepted.
  r = runner("--gate", "--candidate", head, "--walkthrough", PATH, "--walkthrough-commit", "");
  assert.deepEqual([r.status, /evidence commit is not a full commit hash/.test(r.out)], [64, true], r.out);
});

test("conformance.yml's gate job takes evidence only from the accepted commit, and puts no input in a script", async () => {
  const { parse } = await import("yaml");
  const wf = parse(readFileSync(join(repoRoot, ".github/workflows/conformance.yml"), "utf8"));
  assert.ok(wf.on.workflow_dispatch.inputs.walkthrough_ref);
  for (const [name, job] of Object.entries(wf.jobs)) {
    for (const step of job.steps ?? []) assert.doesNotMatch(step.run ?? "", /\$\{\{/, `${name}: ${step.name ?? step.uses}`);
  }
  const steps = wf.jobs.gate.steps;
  const at = (found) => steps.findIndex(found);
  const checkouts = steps.filter((s) => s.uses?.startsWith("actions/checkout@"));
  assert.equal(checkouts.length, 1, "only the candidate is checked out");
  assert.deepEqual(checkouts[0].with, { ref: "${{ inputs.gate_ref || github.ref }}", "persist-credentials": false });
  const candidateStep = at((s) => s.id === "candidate");
  const check = at((s) => s.id === "evidence");
  const build = at((s) => s.run?.includes("go build") || s.run?.includes("pnpm"));
  const gate = at((s) => s.name === "Run ship gate G1");
  assert.ok(candidateStep === 1 && check === 2 && build > check && gate > build, "the candidate, its evidence, then the build and the run");
  // Either input alone runs the check, which needs both.
  assert.equal(steps[check].if, "inputs.walkthrough != '' || inputs.walkthrough_ref != ''");
  assert.deepEqual(steps[check].env, { CANDIDATE: "${{ steps.candidate.outputs.commit }}", WALKTHROUGH: "${{ inputs.walkthrough }}", WALKTHROUGH_REF: "${{ inputs.walkthrough_ref }}" });
  assert.equal(steps[check]["continue-on-error"], undefined);
  assert.equal(steps[gate].env.WALKTHROUGH_COMMIT, "${{ steps.evidence.outputs.evidence }}");
  assert.equal(steps[gate].env.CANDIDATE, "${{ steps.candidate.outputs.commit }}");
  assert.match(steps[gate].run, /--gate --candidate "\$CANDIDATE"/);
  assert.match(steps[gate].run, /--walkthrough "\$WALKTHROUGH" --walkthrough-commit "\$WALKTHROUGH_COMMIT"/);
});
