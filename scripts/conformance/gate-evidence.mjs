#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * The G1 gate's evidence, checked before anything is built or started
 * (conformance.yml's gate job; docs/evidence/README.md):
 *
 *   node scripts/conformance/gate-evidence.mjs --candidate <40-hex> --ref <branch, tag or commit>
 *        --path docs/evidence/<file> [--output <GITHUB_OUTPUT file>]
 *
 * Fetches the ref from origin without checking it out, requires it to differ
 * from the candidate only under docs/evidence/ (lib/gate-evidence.mjs), and
 * judges the walkthrough's content against the candidate (lib/gate.mjs), so
 * that a run that cannot pass ends now and not an hour later. Writes
 * `evidence=<commit>` to --output; run.mjs reads the file from that commit
 * again (--walkthrough-commit).
 *
 * Exit status 0 when the evidence stands, 1 when it is refused, 64 on a
 * usage error.
 */
import { appendFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { walkthroughProblems } from "./lib/gate.mjs";
import { EvidenceRefused, fetchEvidenceCommit, headCommit, readWalkthroughAt } from "./lib/gate-evidence.mjs";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

function usage(message) {
  console.error(`${message}\nUsage: gate-evidence.mjs --candidate <40-hex> --ref <branch, tag or commit> --path docs/evidence/<file> [--output <file>]`);
  process.exit(64);
}

const options = {};
for (let i = 2; i < process.argv.length; i += 2) {
  const flag = process.argv[i];
  if (!["--candidate", "--ref", "--path", "--output"].includes(flag) || process.argv[i + 1] === undefined) usage(`unexpected argument ${flag}`);
  options[flag.slice(2)] = process.argv[i + 1];
}
for (const name of ["candidate", "ref", "path"]) if (!options[name]) usage(`--${name} is required: a gate run with a walkthrough names both its file and the ref it is taken from`);

try {
  // The scripts that judge, and everything that is built, are the candidate's.
  const head = headCommit(REPO_ROOT);
  if (head !== options.candidate) throw new EvidenceRefused(`the checkout is at ${head}, not at the candidate ${options.candidate}`);
  const evidence = fetchEvidenceCommit(REPO_ROOT, options.ref);
  const walkthrough = readWalkthroughAt(REPO_ROOT, { path: options.path, candidate: options.candidate, evidence });
  const problems = walkthroughProblems(walkthrough, { commit: options.candidate });
  if (problems.length > 0) throw new EvidenceRefused(problems.join("\n  "));
  if (headCommit(REPO_ROOT) !== options.candidate) throw new EvidenceRefused("the fetch moved the checkout");
  console.log(`Walkthrough evidence ${walkthrough.path} (sha256 ${walkthrough.sha256}) at ${evidence}, for the candidate ${options.candidate}`);
  if (options.output) appendFileSync(options.output, `evidence=${evidence}\n`);
} catch (err) {
  if (!(err instanceof EvidenceRefused)) throw err;
  console.error(`CONFORMANCE GATE EVIDENCE REFUSED\n  ${err.message}`);
  process.exit(1);
}
