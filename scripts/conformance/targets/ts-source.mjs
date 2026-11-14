// SPDX-License-Identifier: Apache-2.0
/**
 * Target `ts-source`: the TypeScript stack built from this checkout, as a
 * disposable Compose project (canonical infra/compose files, temporary
 * credentials, free loopback ports, its own volumes), removed on `down`.
 * Every operation is the shared Compose stack's (compose-stack.mjs).
 *
 * The images are built from the checkout when the stack starts, unless
 * CONFORMANCE_SOURCE_IMAGES names a tag that source-images.mjs built (and
 * labeled with this checkout's commit) earlier: the weekly matrix builds
 * them once and hands them to every cell (.github/workflows/conformance.yml).
 */
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as stack from "./compose-stack.mjs";

export const name = "ts-source";
export const capabilities = stack.CAPABILITIES;

/** The services built from source, and the image each one runs. */
export const BUILT_FROM_SOURCE = {
  varlatchd: "varlatchd",
  "varlatch-migrate": "varlatchd",
  "varlatch-web": "varlatch-web",
  "convex-deploy": "convex-deploy",
};
/** The label that names the commit a prebuilt image was built from. */
export const COMMIT_LABEL = "org.varlatch.conformance.commit";
export const sourceImage = (image, tag) => `varlatch-conformance/${image}:${tag}`;

/** The checkout's commit, for prebuilt images: they must come from exactly this one. */
export function checkoutCommit(repoRoot) {
  const r = spawnSync("git", ["rev-parse", "HEAD"], { cwd: repoRoot, encoding: "utf8" });
  if (r.status !== 0) throw new Error(`git rev-parse HEAD failed: ${r.stderr}`);
  return r.stdout.trim();
}

/**
 * The Compose override, as `{ file, text }`. `build` points the build
 * contexts at the checkout. `tagged` also names the images and labels them
 * with `commit` (what source-images.mjs builds). `prebuilt` runs those named
 * images and removes every `build:`, so nothing is rebuilt, not even the
 * profiled Convex deploy job the reconcile suite builds explicitly (it gets
 * "no services to build", as on a release bundle). JSON strings are YAML
 * scalars, so the values are written with JSON.stringify.
 */
export function buildOverride(repoRoot, { mode = "build", tag = null, commit = null } = {}) {
  const services = Object.entries(BUILT_FROM_SOURCE);
  if (mode === "build") {
    return { file: "build.json", text: JSON.stringify({ services: Object.fromEntries(services.map(([s]) => [s, { build: { context: repoRoot } }])) }) };
  }
  if (!tag) throw new Error(`a ${mode} override needs an image tag`);
  if (mode === "tagged") {
    return {
      file: "build.json",
      text: JSON.stringify({
        services: Object.fromEntries(services.map(([s, image]) => [s, { image: sourceImage(image, tag), build: { context: repoRoot, labels: { [COMMIT_LABEL]: commit } } }])),
      }),
    };
  }
  if (mode === "prebuilt") {
    const lines = ["services:"];
    for (const [s, image] of services) {
      lines.push(`  ${s}:`, `    image: ${JSON.stringify(sourceImage(image, tag))}`, "    pull_policy: never", "    build: !reset null");
    }
    return { file: "prebuilt.yml", text: `${lines.join("\n")}\n` };
  }
  throw new Error(`unknown override mode ${mode}`);
}

/** Lays out the canonical Compose files in a new project directory; returns the state and the step that writes the files. */
export function prepare(repoRoot, options = {}) {
  const dir = mkdtempSync(join(tmpdir(), "varlatch-conformance-"));
  const state = { target: name, root: dir, dir, project: stack.projectName(dir), composeFiles: [], env: {} };
  return {
    state,
    lay: () => {
      cpSync(join(repoRoot, "infra/compose/docker-compose.yml"), join(dir, "docker-compose.yml"));
      cpSync(join(repoRoot, "infra/compose/convex-supervisor.cjs"), join(dir, "convex-supervisor.cjs"));
      cpSync(join(repoRoot, "infra/compose/postgres-init"), join(dir, "postgres-init"), { recursive: true });
      // Build contexts resolve against the checkout; every runtime file,
      // secret, network and volume belongs to the disposable project.
      const override = buildOverride(repoRoot, options);
      writeFileSync(join(dir, override.file), override.text);
      state.composeFiles = ["docker-compose.yml", override.file];
    },
  };
}

/**
 * What differs in the checkout from its commit: changed tracked files and
 * untracked files that are not ignored (`git status --porcelain`). The
 * images are built with the whole checkout as their context, so any of these
 * may be a build input.
 */
export function worktreeChanges(repoRoot) {
  const r = spawnSync("git", ["status", "--porcelain", "--untracked-files=all"], { cwd: repoRoot, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  if (r.status !== 0) throw new Error(`git status failed: ${r.stderr}`);
  return r.stdout.split("\n").filter((l) => l.trim() !== "");
}

const inspectLabel = (ref) => {
  const r = spawnSync("docker", ["image", "inspect", "--format", `{{ index .Config.Labels "${COMMIT_LABEL}" }}`, ref], { encoding: "utf8" });
  return r.status === 0 ? r.stdout.trim() : null;
};

/**
 * Why the prebuilt images of `tag` cannot run for this checkout; empty when
 * they can. They must carry the checkout's commit, and the checkout must be
 * exactly that commit: a changed or untracked file would be in a build from
 * this checkout but is not in the images, so the run would test old code
 * under the new commit's name. Such a run fails here, before anything
 * starts, rather than quietly building instead: CONFORMANCE_SOURCE_IMAGES
 * says the images were built elsewhere, and a run that rebuilt would not be
 * the run that was asked for. Unset it to build from the checkout.
 * `inspect(ref)` (the label, or null when the image is missing) is replaced
 * in unit tests.
 */
export function prebuiltProblems({ repoRoot, tag, commit, inspect = inspectLabel }) {
  const problems = [];
  const changes = worktreeChanges(repoRoot);
  if (changes.length > 0) {
    problems.push(`the checkout differs from ${commit} (${changes.length} changed or untracked files: ${changes.slice(0, 5).map((l) => l.slice(3)).join(", ")}), so the prebuilt images are not this code`);
  }
  for (const image of new Set(Object.values(BUILT_FROM_SOURCE))) {
    const ref = sourceImage(image, tag);
    const label = inspect(ref);
    if (label === null) problems.push(`${ref} is not loaded`);
    else if (label !== commit) problems.push(`${ref} was built from ${label || "an unlabeled tree"}, not ${commit}`);
  }
  return problems;
}

/**
 * Starts a fresh installation. `onState` receives the state before anything
 * is created, so the runner can remove a partly started installation.
 */
export async function up({ repoRoot, onState = () => {} }) {
  const tag = process.env.CONFORMANCE_SOURCE_IMAGES || null;
  const commit = tag ? checkoutCommit(repoRoot) : null;
  const { state, lay } = prepare(repoRoot, tag ? { mode: "prebuilt", tag } : { mode: "build" });
  onState(state);
  try {
    if (tag) {
      const problems = prebuiltProblems({ repoRoot, tag, commit });
      if (problems.length > 0) {
        throw new Error(`CONFORMANCE_SOURCE_IMAGES=${tag}: ${problems.join("; ")} (build them from this commit with scripts/conformance/source-images.mjs, or unset it to build here)`);
      }
      console.log(`--- images prebuilt from ${commit} (${tag})`);
    }
    state.images = tag ? { prebuilt: tag, commit } : "built from this checkout";
    state.commit = checkoutCommit(repoRoot);
    state.clean = worktreeChanges(repoRoot).length === 0;
    lay();
    await stack.configure(state);
    await stack.start(state, tag ? ["--no-build"] : ["--build"]);
    return state;
  } catch (err) {
    err.state = state;
    throw err;
  }
}

/** What the report records about the target. */
export function describe(state) {
  return { images: state.images ?? null };
}

/**
 * The implementation fingerprint: the checkout's commit, whether the tree
 * was exactly that commit, and the image IDs the stack ran. Two runs match
 * only when they ran the same images, which is the case for the cells of one
 * matrix run (they share the prebuilt images), not for two separate builds.
 */
export function fingerprint(state) {
  return { target: name, commit: state.commit ?? null, clean: state.clean ?? null, imageIds: stack.imageIds(state) };
}

export const expectKey = () => name;

export const {
  down,
  diagnostics,
  origin,
  bootstrap,
  recover,
  restart,
  logs,
  requestLog,
  settle,
  probe,
  maintenance,
  serveCli,
  tsStack,
} = stack;
