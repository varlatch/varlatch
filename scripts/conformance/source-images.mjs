#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Builds the `ts-source` target's images once, for several runs to share
 * (the weekly matrix, .github/workflows/conformance.yml):
 *
 *   node scripts/conformance/source-images.mjs <tag> [--save <file.tar.gz>]
 *
 * The images are built from this checkout, which must be exactly its commit
 * (no change, no untracked file), with the canonical Compose file, named
 * varlatch-conformance/<image>:<tag> and labeled with that commit. A run with CONFORMANCE_SOURCE_IMAGES=<tag> uses them instead of
 * building, and refuses them unless the label names its own commit.
 * `--save` writes them, gzipped, as `docker load` reads them.
 */
import { spawnSync } from "node:child_process";
import { closeSync, openSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as stack from "./targets/compose-stack.mjs";
import { BUILT_FROM_SOURCE, checkoutCommit, prepare, sourceImage, worktreeChanges } from "./targets/ts-source.mjs";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const [tag, flag, file] = process.argv.slice(2);
if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(tag ?? "") || (flag !== undefined && (flag !== "--save" || !file))) {
  console.error("Usage: source-images.mjs <tag> [--save <file.tar.gz>]");
  process.exit(64);
}

const commit = checkoutCommit(REPO_ROOT);
// The label names a commit, so the tree must be exactly that commit.
const changes = worktreeChanges(REPO_ROOT);
if (changes.length > 0) {
  console.error(`the checkout differs from ${commit}: commit or remove the changes first, the images are labeled with that commit\n${changes.slice(0, 40).join("\n")}`);
  process.exit(1);
}
const { state, lay } = prepare(REPO_ROOT, { mode: "tagged", tag, commit });
try {
  lay();
  await stack.configure(state);
  // One build per image: varlatch-migrate runs the varlatchd image.
  const services = Object.keys(BUILT_FROM_SOURCE).filter((s) => s !== "varlatch-migrate");
  stack.mustCompose(state, ["--profile", "deploy", "build", ...services], { inherit: true });
  const images = [...new Set(Object.values(BUILT_FROM_SOURCE))].map((i) => sourceImage(i, tag));
  console.log(`--- built ${images.join(", ")} from ${commit}`);
  if (file) {
    const out = openSync(file, "w");
    try {
      const save = spawnSync("bash", ["-o", "pipefail", "-c", 'docker save "$@" | gzip -1', "save", ...images], { stdio: ["ignore", out, "inherit"] });
      if (save.status !== 0) throw new Error(`docker save failed (exit ${save.status})`);
    } finally {
      closeSync(out);
    }
    console.log(`--- saved to ${file}`);
  }
} finally {
  rmSync(state.root, { recursive: true, force: true });
}
