// SPDX-License-Identifier: Apache-2.0
/**
 * Gate evidence from a commit of its own (docs/evidence/README.md).
 *
 * The walkthrough names the candidate's commit, so it cannot be part of it:
 * no file holds the hash of the commit it is in. The owner commits it on
 * top, and the gate builds and runs the candidate and takes one file, the
 * walkthrough, from that evidence commit:
 *
 *   - the evidence commit's tree is the candidate's, except for regular
 *     files added or changed under docs/evidence/. A deleted, renamed,
 *     symlinked or executable file, a submodule, or a change anywhere else
 *     is refused;
 *   - the file is read as a blob from git's objects. Nothing of the evidence
 *     commit is checked out, so nothing of it can run or change the build;
 *   - the Candidate commit in it is compared with the candidate
 *     (lib/gate.mjs), never with the evidence commit.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { EVIDENCE_DIR, evidenceText } from "./gate.mjs";

const HEX_40 = /^[0-9a-f]{40}$/;
const REGULAR = "100644";
/** A walkthrough is a few tens of kilobytes. */
const MAX_SIZE = 1024 * 1024;
/** A branch, a tag or a full commit hash: one plain name, never a refspec or an option. */
const REF = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$/;

/** Refused evidence: every reason, and nothing was read from it. */
export class EvidenceRefused extends Error {}

/** git in repoRoot, with paths taken literally and no replaced objects; its output, or a refusal. */
function git(repoRoot, args, what) {
  const r = spawnSync("git", args, {
    cwd: repoRoot,
    maxBuffer: 64 * 1024 * 1024,
    timeout: 120_000,
    env: { ...process.env, GIT_LITERAL_PATHSPECS: "1", GIT_NO_REPLACE_OBJECTS: "1", GIT_TERMINAL_PROMPT: "0" },
  });
  if (r.error || r.status !== 0) {
    throw new EvidenceRefused(`${what}: git ${args[0]} ${r.error ? r.error.message : `exited ${r.status ?? r.signal}: ${r.stderr.toString().trim().slice(0, 300)}`}`);
  }
  return r.stdout;
}

/** The commit the checkout is at. */
export const headCommit = (repoRoot) => git(repoRoot, ["rev-parse", "--verify", "--quiet", "HEAD^{commit}"], "the checkout's commit").toString().trim();

/** Why `ref` is not a plain ref name; null when it is one. */
export function refProblem(ref) {
  if (typeof ref !== "string" || !REF.test(ref)) return "expected a branch, a tag or a full commit hash";
  if (ref.includes("..") || ref.includes("//") || /[/.]$/.test(ref) || /\.lock(\/|$)/.test(ref) || /\/\./.test(ref)) return "not a ref name git accepts";
  return null;
}

/** Why `path` is not a file path under docs/evidence/; null when it is one. */
export function evidencePathProblem(path) {
  if (typeof path !== "string" || !path.startsWith(EVIDENCE_DIR)) return `not under ${EVIDENCE_DIR}`;
  if (!/^[A-Za-z0-9._/-]+$/.test(path)) return "only letters, digits, dots, dashes, underscores and slashes";
  if (path.split("/").some((part) => part === "" || part === "." || part === "..")) return "empty, . and .. parts are not allowed";
  return null;
}

/** Fetches `ref` from origin, without checking anything out: the commit it names. */
export function fetchEvidenceCommit(repoRoot, ref) {
  const why = refProblem(ref);
  if (why) throw new EvidenceRefused(`walkthrough_ref ${JSON.stringify(String(ref).slice(0, 80))}: ${why}`);
  git(repoRoot, ["fetch", "--quiet", "--depth=1", "--no-tags", "--no-recurse-submodules", "--no-write-commit-graph", "origin", ref], `walkthrough_ref ${ref}`);
  return git(repoRoot, ["rev-parse", "--verify", "--quiet", "--end-of-options", "FETCH_HEAD^{commit}"], `walkthrough_ref ${ref}`).toString().trim();
}

/**
 * Why the evidence commit may not be used with the candidate: every entry of
 * its tree that differs, other than a regular file added or changed under
 * docs/evidence/. Empty when only those differ. Renames are not detected, so
 * one is a deletion and an addition; the deletion is refused.
 */
export function evidenceDiffProblems(repoRoot, candidate, evidence) {
  const raw = git(repoRoot, ["diff-tree", "-r", "-z", "--raw", "--no-renames", "--no-abbrev", "--no-ext-diff", "--no-commit-id", "--end-of-options", candidate, evidence], "comparing the evidence commit with the candidate").toString("utf8");
  const fields = raw.split("\0").slice(0, -1);
  const problems = [];
  for (let i = 0; i < fields.length; i += 2) {
    const m = /^:(\d{6}) (\d{6}) [0-9a-f]{40} [0-9a-f]{40} ([A-Z])$/.exec(fields[i]);
    const path = fields[i + 1];
    if (!m || path === undefined) {
      problems.push("git's comparison could not be read");
      break;
    }
    const [, from, to, status] = m;
    const shown = JSON.stringify(path).slice(0, 200);
    if (!path.startsWith(EVIDENCE_DIR)) problems.push(`${shown} differs from the candidate, outside ${EVIDENCE_DIR}`);
    else if (status === "D") problems.push(`${shown} is deleted`);
    else if (to === "120000" || from === "120000") problems.push(`${shown} is a symlink`);
    else if (to === "160000" || from === "160000") problems.push(`${shown} is a submodule`);
    else if (to !== REGULAR || !((status === "A" && from === "000000") || (status === "M" && from === REGULAR))) problems.push(`${shown} is not a regular file added or changed (mode ${from} to ${to}, ${status})`);
  }
  return problems;
}

/**
 * The walkthrough at `path` of the commit `evidence`, in readWalkthrough's
 * shape, with the evidence commit it came from. Throws EvidenceRefused when
 * the evidence may not be used with `candidate`.
 */
export function readWalkthroughAt(repoRoot, { path, candidate, evidence }) {
  for (const [name, commit] of [["candidate", candidate], ["evidence", evidence]]) {
    if (typeof commit !== "string" || !HEX_40.test(commit)) throw new EvidenceRefused(`the ${name} commit is not a full commit hash`);
  }
  const why = evidencePathProblem(path);
  if (why) throw new EvidenceRefused(`the walkthrough ${JSON.stringify(String(path).slice(0, 120))}: ${why}`);
  for (const [name, commit] of [["candidate", candidate], ["evidence", evidence]]) {
    const type = git(repoRoot, ["cat-file", "-t", commit], `the ${name} commit ${commit}`).toString().trim();
    if (type !== "commit") throw new EvidenceRefused(`the ${name} ${commit} is a ${type}, not a commit`);
  }
  const problems = evidenceDiffProblems(repoRoot, candidate, evidence);
  if (problems.length > 0) {
    throw new EvidenceRefused(`the evidence commit ${evidence} may differ from the candidate ${candidate} only in regular files added or changed under ${EVIDENCE_DIR}: ${problems.slice(0, 20).join("; ")}${problems.length > 20 ? `; and ${problems.length - 20} more` : ""}`);
  }
  const listed = git(repoRoot, ["ls-tree", "-z", "--full-tree", evidence, "--", path], "reading the evidence commit").toString("utf8").split("\0").filter(Boolean);
  const entry = listed.length === 1 ? /^(\d{6}) (\w+) ([0-9a-f]{40})\t(.*)$/s.exec(listed[0]) : null;
  if (!entry || entry[4] !== path) throw new EvidenceRefused(`the evidence commit ${evidence} has no file ${path}`);
  if (entry[1] !== REGULAR || entry[2] !== "blob") throw new EvidenceRefused(`${path} in the evidence commit is not a regular file (mode ${entry[1]})`);
  const size = Number(git(repoRoot, ["cat-file", "-s", entry[3]], `reading ${path}`).toString().trim());
  if (!(size <= MAX_SIZE)) throw new EvidenceRefused(`${path} is ${size} bytes, more than ${MAX_SIZE}`);
  const raw = git(repoRoot, ["cat-file", "blob", entry[3]], `reading ${path}`);
  const { text, problem } = evidenceText(raw);
  if (problem) throw new EvidenceRefused(`${path} ${problem}`);
  return {
    path,
    exists: true,
    isSymlink: false,
    size: raw.length,
    sha256: createHash("sha256").update(raw).digest("hex"),
    content: text,
    evidenceCommit: evidence,
  };
}
