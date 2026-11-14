// SPDX-License-Identifier: Apache-2.0
/**
 * The pure rules of the `ts-release:<version>` target
 * (scripts/conformance/README.md): which releases can be selected, what the
 * compose bundle may contain, and that the Compose file runs exactly the
 * images the signed release manifest pins. targets/ts-release.mjs downloads
 * and verifies; everything here is checked without a network.
 */
import { compareVersions, VERSION } from "./inventory.mjs";

/**
 * The first signed release (docs/operations/verify-release.md): 0.15.0 and
 * earlier were published while the repository was private, unsigned. They
 * cannot be selected: a target is verified by signature or not run.
 */
export const FIRST_SIGNED = "0.15.1";

/** Varlatch's own images, each verified by digest with cosign; the rest are pinned by the signed manifest. */
export const VARLATCH_IMAGES = ["varlatchd", "varlatch-web", "convex-deploy"];

/** The compose bundle a release carries. */
export const bundleAsset = (version) => `varlatch-compose-${version}.tar.gz`;

/** The release manifest's asset name, and its path inside the bundle. */
export const MANIFEST = "varlatch-release.json";
export const bundleRoot = (version) => `varlatch-${version}`;

/** Why `version` cannot be a release target; null when it can. */
export function releaseVersionProblem(version) {
  if (!VERSION.test(String(version ?? ""))) return `ts-release needs a version, as ts-release:<x.y.z> (got ${JSON.stringify(version ?? "")})`;
  if (compareVersions(version, FIRST_SIGNED) < 0) {
    return `ts-release:${version}: releases before ${FIRST_SIGNED} are not signed and cannot be selected (docs/operations/verify-release.md)`;
  }
  return null;
}

/**
 * Problems with the bundle's listing: `names` from `tar -tzf`, `types` the
 * first character of each line of `tar -tvzf` (the same entries, in the same
 * order). Only regular files and directories under `varlatch-<version>/`, no
 * absolute path and no `..`: a link, a device or a path outside the bundle's
 * own directory refuses the archive before anything is extracted.
 */
export function bundleListingProblems(names, types, version) {
  const root = `${bundleRoot(version)}/`;
  const problems = [];
  if (names.length === 0) problems.push("the bundle is empty");
  if (names.length !== types.length) return [...problems, `the bundle's two listings disagree (${names.length} names, ${types.length} types)`];
  names.forEach((name, i) => {
    if (types[i] !== "-" && types[i] !== "d") problems.push(`the bundle holds ${name}, which is not a regular file or directory`);
    else if (name.startsWith("/") || name.split("/").includes("..") || !name.startsWith(root)) problems.push(`the bundle holds ${name}, outside ${root}`);
  });
  return problems;
}

/** Problems with the release manifest itself; empty when it pins every image by digest for `version`. */
export function manifestProblems(manifest, version) {
  if (!manifest || typeof manifest !== "object") return ["varlatch-release.json is not a JSON object"];
  const problems = [];
  if (manifest.version !== version) problems.push(`varlatch-release.json is for ${JSON.stringify(manifest.version)}, not ${version}`);
  const images = manifest.images ?? {};
  for (const key of VARLATCH_IMAGES) if (!images[key]) problems.push(`varlatch-release.json pins no ${key} image`);
  for (const [key, image] of Object.entries(images)) {
    if (!/^[a-z0-9.-]+(?::\d+)?\/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$/.test(String(image?.digest))) {
      problems.push(`varlatch-release.json: ${key} is not pinned by digest (${JSON.stringify(image?.digest)})`);
    }
  }
  return problems;
}

/** `name[:tag]@sha256:...` as `name@sha256:...`; null when the reference has no digest. */
export function digestReference(image) {
  const m = /^(.+?)@(sha256:[0-9a-f]{64})$/.exec(String(image ?? ""));
  if (!m) return null;
  const slash = m[1].lastIndexOf("/");
  const colon = m[1].lastIndexOf(":");
  const name = colon > slash ? m[1].slice(0, colon) : m[1];
  return `${name}@${m[2]}`;
}

/**
 * Problems with the bundle's Compose file as `docker compose config --format
 * json` resolves it: every service runs an image pinned by a digest the
 * signed manifest lists, and nothing is built.
 */
export function composeImageProblems(services, manifest) {
  const pinned = new Set(Object.values(manifest?.images ?? {}).map((i) => i?.digest));
  const problems = [];
  const entries = Object.entries(services ?? {});
  if (entries.length === 0) problems.push("the bundle's Compose file has no services");
  for (const [service, def] of entries) {
    if (def?.build) problems.push(`service ${service} is built from source, not pulled`);
    const ref = digestReference(def?.image);
    if (!ref) problems.push(`service ${service} runs ${JSON.stringify(def?.image ?? null)}, which is not pinned by digest`);
    else if (!pinned.has(ref)) problems.push(`service ${service} runs ${ref}, which varlatch-release.json does not pin`);
  }
  return problems;
}
