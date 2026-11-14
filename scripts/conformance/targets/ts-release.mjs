// SPDX-License-Identifier: Apache-2.0
/**
 * Target `ts-release:<version>`: a released TypeScript stack, from the
 * release's own compose bundle (varlatch-compose-<version>.tar.gz) with every
 * image pulled by the digest varlatch-release.json pins. Nothing is built
 * from source. Every operation is the shared Compose stack's
 * (compose-stack.mjs): the bundle's Compose file is the canonical one with
 * `build:` replaced by digest-pinned images, so the admin CLI inside the
 * varlatchd image, the ports and the environment are the same as ts-source's.
 *
 * Before anything runs, the release is verified as
 * docs/operations/verify-release.md says, failing closed:
 *
 *   1. only a signed release can be selected (0.15.1 and later);
 *   2. cosign (pinned in clients.json, checked by hash) verifies SHA256SUMS
 *      against release.yml@refs/tags/v<version> of the pinned repository and
 *      GitHub's OIDC issuer;
 *   3. SHA256SUMS lists the bundle and varlatch-release.json each exactly
 *      once, with the hashes the downloads have;
 *   4. the manifest is for <version> and pins every image by digest; the
 *      bundle holds only regular files and directories under
 *      varlatch-<version>/, and its copy of the manifest is the same bytes;
 *   5. each Varlatch image (varlatchd, varlatch-web, convex-deploy) is
 *      verified by its digest with cosign, for the same identity;
 *   6. the bundle's Compose file, as Compose resolves it, runs only images
 *      the manifest pins, by digest, and builds nothing.
 *
 * The report records the verified hashes and digests (`describe`).
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fetchVerifiedRelease } from "../clients.mjs";
import {
  bundleAsset,
  bundleListingProblems,
  bundleRoot,
  composeImageProblems,
  MANIFEST,
  manifestProblems,
  releaseVersionProblem,
  VARLATCH_IMAGES,
} from "../lib/release.mjs";
import * as stack from "./compose-stack.mjs";

export const name = "ts-release";
export const capabilities = stack.CAPABILITIES;

function tar(args) {
  const r = spawnSync("tar", args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  if (r.status !== 0) throw new Error(`tar ${args[0]} failed: ${(r.stderr || String(r.error ?? "")).trim().slice(-300)}`);
  return r.stdout;
}

/**
 * Downloads and verifies release `version` into `workDir` (steps 1 to 5
 * above) and extracts its bundle. Returns `{ dir, manifest, record }`: the
 * bundle's own directory, the verified manifest, and what the report keeps.
 * `deps` replaces the network and cosign in unit tests (clients.mjs).
 */
export async function verifyRelease(version, { workDir, log = console.log, deps = {} }) {
  const problem = releaseVersionProblem(version);
  if (problem) throw new Error(problem);
  const bundle = bundleAsset(version);
  const release = await fetchVerifiedRelease(version, { assets: [bundle, MANIFEST], workDir, log, deps, label: "Release" });

  const manifestBytes = readFileSync(release.files[MANIFEST]);
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes.toString("utf8"));
  } catch {
    throw new Error(`${MANIFEST} of v${version} is not JSON`);
  }
  const manifestWrong = manifestProblems(manifest, version);
  if (manifestWrong.length > 0) throw new Error(`release ${version}: ${manifestWrong.join("; ")}`);

  // The bundle is read before it is extracted: only plain files and
  // directories, all under its own directory.
  const names = tar(["-tzf", release.files[bundle]]).split("\n").filter((l) => l !== "");
  const types = tar(["-tvzf", release.files[bundle]]).split("\n").filter((l) => l !== "").map((l) => l[0]);
  const listing = bundleListingProblems(names, types, version);
  if (listing.length > 0) throw new Error(`${bundle}: ${listing.join("; ")}`);
  const extracted = mkdtempSync(join(workDir, "bundle-"));
  tar(["-xzf", release.files[bundle], "-C", extracted, "--no-same-owner"]);
  const dir = join(extracted, bundleRoot(version));
  let bundled;
  try {
    bundled = readFileSync(join(dir, MANIFEST));
  } catch {
    throw new Error(`${bundle} holds no ${bundleRoot(version)}/${MANIFEST}`);
  }
  if (!bundled.equals(manifestBytes)) throw new Error(`${bundle}: its ${MANIFEST} differs from the release's signed ${MANIFEST}`);

  const images = {};
  for (const [key, image] of Object.entries(manifest.images)) {
    if (VARLATCH_IMAGES.includes(key)) {
      log(`--- release ${version}: verifying ${image.digest}`);
      release.verifyImage(image.digest);
      images[key] = { digest: image.digest, verified: "cosign signature for the release identity" };
    } else {
      images[key] = { digest: image.digest, verified: "pinned by digest in the signed manifest" };
    }
  }
  return {
    dir,
    manifest,
    record: {
      version,
      ...release.verified,
      assets: release.hashes,
      migrationVersion: manifest.migrationVersion ?? null,
      images,
    },
  };
}

/**
 * Starts a fresh installation of the release `argument`. `onState` receives
 * the state before anything is created, so the runner can remove a partly
 * started installation.
 */
export async function up({ argument, onState = () => {} }) {
  const version = argument ?? "";
  const problem = releaseVersionProblem(version);
  if (problem) throw new Error(problem);
  const root = mkdtempSync(join(tmpdir(), "varlatch-conformance-"));
  const state = { target: `${name}:${version}`, root, dir: root, project: stack.projectName(root), composeFiles: [], env: {} };
  onState(state);
  try {
    const verified = await verifyRelease(version, { workDir: root });
    state.dir = verified.dir;
    state.release = verified.record;
    state.composeFiles = ["docker-compose.yml"];
    await stack.configure(state);
    // Every profile: the Convex deploy job (profile deploy) runs a pinned image too.
    const config = JSON.parse(stack.mustCompose(state, ["--profile", "*", "config", "--format", "json"]));
    const composeWrong = composeImageProblems(config.services, verified.manifest);
    if (composeWrong.length > 0) throw new Error(`the bundle's Compose file: ${composeWrong.join("; ")}`);
    console.log(`--- release ${version} verified; pulling its images by digest`);
    stack.mustCompose(state, ["--profile", "*", "pull", "--quiet"], { inherit: true });
    await stack.start(state, ["--no-build"]);
    return state;
  } catch (err) {
    err.state = state;
    throw err;
  }
}

/** What the report records about the target: the verified release. */
export function describe(state) {
  return { release: state.release ?? null };
}

/** Expectations are kept per release: ts-release:<version>. */
export const expectKey = (argument) => `${name}:${argument}`;

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
