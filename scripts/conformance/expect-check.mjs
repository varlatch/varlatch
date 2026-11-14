#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * The expected failures and declared gaps only shrink by default
 * (scripts/conformance/README.md): compares scripts/conformance/expect/*.json
 * and inventory.json at a pull request's head with its merge base, and fails
 * unless the pull request carries the `conformance-regression` label when
 * the head:
 *
 *   - adds an expected failure (moving one to another client or target
 *     counts);
 *   - adds a `lacks` entry (an operation a target does not have);
 *   - makes a check newly report target-lacks on a target: from a new
 *     `lacks` entry, or from a new operation in the inventory that a check
 *     needs and the target lacks. So an operation a target provides cannot
 *     quietly disappear from what is checked;
 *   - removes a target's file (or the whole directory), or deletes or
 *     renames this checker, a file it imports, inventory.json or
 *     clients.json.
 *
 * Removing an expected failure or a `lacks` entry needs nothing. It also
 * validates the head's files against the head's inventory, clients.json and
 * OpenAPI document.
 *
 *   node scripts/conformance/expect-check.mjs --base <rev> --head <rev> [--labeled] [--repo <dir>]
 *   node scripts/conformance/expect-check.mjs --validate-only --head <rev> [--repo <dir>]
 *
 *   --base           the pull request's base (its merge base with --head is used)
 *   --head           the pull request's head commit
 *   --labeled        the pull request carries the conformance-regression label
 *   --validate-only  only validate the files at --head (a push to main,
 *                    where the label was decided on the pull request)
 *   --repo           the repository to read (default: this checkout)
 *
 * Everything it reads from the commits (the expectations, inventory.json,
 * clients.json, packages/protocol/openapi.yaml) is read with `git show` and
 * parsed as data, never run as code. CI runs this script from the pull request's base commit
 * (.github/workflows/conformance-expect.yml), so a pull request cannot
 * change the checker that judges it.
 *
 * Exit status 0 when nothing is added (or the label allows it) and every
 * file is valid; 1 otherwise; 64 on a usage error.
 */
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { addedEntries, entryKeys, importClosure, lackingCheckKeys, lacksKeys, REGRESSION_LABEL, validateExpectations } from "./lib/expect.mjs";
import { openapiOperations } from "./lib/operations.mjs";
import { TARGET_NAMES } from "./targets/index.mjs";

const CHECKOUT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const DIR = "scripts/conformance/expect";

function usage(message) {
  console.error(`${message}\nUsage: expect-check.mjs --base <rev> --head <rev> [--labeled] [--repo <dir>] | --validate-only --head <rev> [--repo <dir>]`);
  process.exit(64);
}

const options = { labeled: false, validateOnly: false, repo: CHECKOUT };
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === "--base") options.base = argv[++i];
  else if (argv[i] === "--head") options.head = argv[++i];
  else if (argv[i] === "--labeled") options.labeled = true;
  else if (argv[i] === "--validate-only") options.validateOnly = true;
  else if (argv[i] === "--repo") options.repo = argv[++i];
  else usage(`unknown argument ${argv[i]}`);
}
if (!options.head) usage("--head is required");
if (!options.validateOnly && !options.base) usage("--base is required (or --validate-only)");
if (options.validateOnly && (options.base || options.labeled)) usage("--validate-only takes only --head");

/**
 * The files the checker cannot work without, relative to the repository:
 * this script, every module it imports, and the data it reads. Computed
 * from the checker that runs, which in CI is the base commit's.
 */
const protectedPaths = () =>
  [...importClosure(fileURLToPath(import.meta.url), CHECKOUT), "scripts/conformance/inventory.json", "scripts/conformance/clients.json"].sort();

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

/** A file at `rev`, or null when the commit does not have it. */
function showOrNull(rev, path) {
  const r = spawnSync("git", ["show", `${rev}:${path}`], { cwd: options.repo, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  return r.status === 0 ? r.stdout : null;
}

try {
  const head = git(["rev-parse", "--verify", `${options.head}^{commit}`]).trim();
  const headFiles = filesAt(head);
  const inventory = JSON.parse(git(["show", `${head}:scripts/conformance/inventory.json`]));
  const clients = JSON.parse(git(["show", `${head}:scripts/conformance/clients.json`]));
  const openapi = openapiOperations(showOrNull(head, "packages/protocol/openapi.yaml") ?? "");
  const problems = Object.entries(headFiles).flatMap(([targetName, file]) =>
    TARGET_NAMES.includes(targetName)
      ? validateExpectations(file, { targetName, inventory, cliVersions: Object.keys(clients.cli ?? {}), openapi })
      : [`expect/${targetName}.json: not named after a target (${TARGET_NAMES.join(", ")})`],
  );
  for (const p of problems) console.log(`INVALID  ${p}`);
  if (options.validateOnly) {
    console.log(`--- expected failures at ${head.slice(0, 12)}: ${entryKeys(headFiles).size} entries, ${problems.length === 0 ? "valid" : "INVALID"}`);
    process.exit(problems.length > 0 ? 1 : 0);
  }

  const mergeBase = git(["merge-base", options.base, head]).trim();
  const baseFiles = filesAt(mergeBase);
  console.log(`--- expected failures at ${head.slice(0, 12)} against the merge base ${mergeBase.slice(0, 12)}: ${entryKeys(baseFiles).size} entries before, ${entryKeys(headFiles).size} now`);

  // What the head takes away that this check needs: a target's expectations
  // file (or the whole directory), the checker, a module it imports, or the
  // data it reads. A rename counts: the old path is gone.
  const exists = (rev, path) => spawnSync("git", ["cat-file", "-e", `${rev}:${path}`], { cwd: options.repo }).status === 0;
  const removed = [
    ...Object.keys(baseFiles).filter((name) => !(name in headFiles)).map((name) => `${DIR}/${name}.json`),
    ...protectedPaths().filter((path) => exists(mergeBase, path) && !exists(head, path)),
  ];
  for (const path of removed) console.log(`DELETED  ${path}`);

  const removedEntries = [...entryKeys(baseFiles)].filter((k) => !entryKeys(headFiles).has(k)).sort();
  for (const k of removedEntries) console.log(`REMOVED  ${k}`);
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
  if (removed.length > 0 && !options.labeled) {
    console.log(
      `--- this pull request deletes or renames ${removed.length} files the expectations check depends on. ` +
        `Label the pull request ${REGRESSION_LABEL} and run this check again if that is intended.`,
    );
  } else if (removed.length > 0) {
    console.log(`--- ${removed.length} files the check depends on deleted or renamed, allowed by the ${REGRESSION_LABEL} label`);
  }

  // Declared gaps: entries added and removed, and the checks that report
  // target-lacks, each side judged with its own inventory.
  const baseInventory = JSON.parse(showOrNull(mergeBase, "scripts/conformance/inventory.json") ?? '{"checks":{}}');
  const lacksBefore = lacksKeys(baseFiles);
  const lacksNow = lacksKeys(headFiles);
  for (const k of [...lacksBefore].filter((k) => !lacksNow.has(k)).sort()) console.log(`REMOVED-LACKS  ${k}`);
  const addedLacks = [...lacksNow].filter((k) => !lacksBefore.has(k)).sort();
  for (const k of addedLacks) console.log(`ADDED-LACKS    ${k}`);
  const lackingBefore = lackingCheckKeys(baseFiles, baseInventory);
  const lackingNow = lackingCheckKeys(headFiles, inventory);
  const newlyLacking = [...lackingNow].filter((k) => !lackingBefore.has(k)).sort();
  for (const k of newlyLacking) console.log(`NEWLY-LACKS    ${k}`);
  console.log(`--- checks reporting target-lacks: ${lackingBefore.size} at the merge base, ${lackingNow.size} now (${newlyLacking.length} newly)`);
  const gaps = addedLacks.length + newlyLacking.length;
  if (gaps > 0 && !options.labeled) {
    console.log(
      `--- this pull request adds ${addedLacks.length} lacking operations and makes ${newlyLacking.length} checks newly report target-lacks. ` +
        `Declared gaps only shrink by default: keep the operations, or label the pull request ${REGRESSION_LABEL} and run this check again if the gap is intended.`,
    );
  } else if (gaps > 0) {
    console.log(`--- ${addedLacks.length} lacking operations added and ${newlyLacking.length} checks newly lacking, allowed by the ${REGRESSION_LABEL} label`);
  }

  const refused = (added.length > 0 || removed.length > 0 || gaps > 0) && !options.labeled;
  process.exit(problems.length > 0 || refused ? 1 : 0);
} catch (err) {
  console.error(`--- expect-check failed: ${err.message}`);
  process.exit(1);
}
