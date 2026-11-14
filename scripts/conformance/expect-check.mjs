#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * The expected failures only shrink by default (scripts/conformance/README.md):
 * compares scripts/conformance/expect/*.json at a pull request's head with
 * its merge base, and fails when the head adds an entry, unless the pull
 * request carries the `conformance-regression` label. It also validates the
 * head's files against the head's inventory and clients.json.
 *
 *   node scripts/conformance/expect-check.mjs --base <rev> --head <rev> [--labeled] [--repo <dir>]
 *
 *   --base     the pull request's base (its merge base with --head is used)
 *   --head     the pull request's head commit
 *   --labeled  the pull request carries the conformance-regression label
 *   --repo     the repository to read (default: this checkout)
 *
 * Exit status 0 when nothing is added (or the label allows it) and every
 * file is valid; 1 otherwise; 64 on a usage error.
 */
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { addedEntries, entryKeys, REGRESSION_LABEL, validateExpectations } from "./lib/expect.mjs";

const CHECKOUT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const DIR = "scripts/conformance/expect";

function usage(message) {
  console.error(`${message}\nUsage: expect-check.mjs --base <rev> --head <rev> [--labeled] [--repo <dir>]`);
  process.exit(64);
}

const options = { labeled: false, repo: CHECKOUT };
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === "--base") options.base = argv[++i];
  else if (argv[i] === "--head") options.head = argv[++i];
  else if (argv[i] === "--labeled") options.labeled = true;
  else if (argv[i] === "--repo") options.repo = argv[++i];
  else usage(`unknown argument ${argv[i]}`);
}
if (!options.base || !options.head) usage("--base and --head are required");

function git(args) {
  const r = spawnSync("git", args, { cwd: options.repo, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")} failed: ${(r.stderr || "").trim()}`);
  return r.stdout;
}

/** The expectations files at `rev`: { "<target name>": parsed JSON }. */
function filesAt(rev) {
  const listing = spawnSync("git", ["ls-tree", "--name-only", rev, `${DIR}/`], { cwd: options.repo, encoding: "utf8" });
  if (listing.status !== 0) throw new Error(`git ls-tree ${rev} failed: ${listing.stderr.trim()}`);
  const files = {};
  for (const path of listing.stdout.split("\n").filter((p) => p.endsWith(".json"))) {
    const name = path.slice(DIR.length + 1, -".json".length);
    files[name] = JSON.parse(git(["show", `${rev}:${path}`]));
  }
  return files;
}

try {
  const head = git(["rev-parse", "--verify", `${options.head}^{commit}`]).trim();
  const mergeBase = git(["merge-base", options.base, head]).trim();
  const baseFiles = filesAt(mergeBase);
  const headFiles = filesAt(head);
  console.log(`--- expected failures at ${head.slice(0, 12)} against the merge base ${mergeBase.slice(0, 12)}: ${entryKeys(baseFiles).size} entries before, ${entryKeys(headFiles).size} now`);

  const inventory = JSON.parse(git(["show", `${head}:scripts/conformance/inventory.json`]));
  const clients = JSON.parse(git(["show", `${head}:scripts/conformance/clients.json`]));
  const problems = Object.entries(headFiles).flatMap(([targetName, file]) =>
    validateExpectations(file, { targetName, inventory, cliVersions: Object.keys(clients.cli ?? {}) }),
  );
  for (const p of problems) console.log(`INVALID  ${p}`);

  const removed = [...entryKeys(baseFiles)].filter((k) => !entryKeys(headFiles).has(k)).sort();
  for (const k of removed) console.log(`REMOVED  ${k}`);
  const added = addedEntries(baseFiles, headFiles);
  for (const k of added) console.log(`ADDED    ${k}`);
  if (added.length > 0 && !options.labeled) {
    console.log(
      `--- this pull request adds ${added.length} expected failures. The list only shrinks by default: fix the regression, ` +
        `or label the pull request ${REGRESSION_LABEL} and run this check again if the regression is intended.`,
    );
  } else if (added.length > 0) {
    console.log(`--- ${added.length} expected failures added, allowed by the ${REGRESSION_LABEL} label`);
  }
  process.exit(problems.length > 0 || (added.length > 0 && !options.labeled) ? 1 : 0);
} catch (err) {
  console.error(`--- expect-check failed: ${err.message}`);
  process.exit(1);
}
