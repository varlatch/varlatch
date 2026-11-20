// SPDX-License-Identifier: Apache-2.0
/**
 * The Coolify variables that pin a release's images (infra/coolify/
 * compose.images.yml): one source for the release builder, which writes
 * them as coolify-image-digests.env, and for the checks that the Coolify
 * files and the documentation name the same variables.
 */

/** Release image name (build-release-artifacts.mjs --image) -> its variable and repository name. */
export const COOLIFY_IMAGES = {
  varlatchd: { variable: "VARLATCH_VARLATCHD_DIGEST", repository: "varlatchd" },
  "varlatch-web": { variable: "VARLATCH_WEB_DIGEST", repository: "varlatch-web" },
  "convex-deploy": { variable: "VARLATCH_CONVEX_DEPLOY_DIGEST", repository: "varlatch-convex-deploy" },
};
export const REGISTRY_VARIABLE = "VARLATCH_IMAGE_REGISTRY";
export const DIGEST_FILE = "coolify-image-digests.env";

/**
 * The file's text from the release's image references
 * ("<registry>/<repository>:<tag>@sha256:<hex>"). Every image must come from
 * one registry, under the repository name the Coolify files use.
 */
export function coolifyImageDigests(images) {
  const lines = [];
  let registry;
  for (const [name, { variable, repository }] of Object.entries(COOLIFY_IMAGES)) {
    const ref = images[name];
    if (!ref) throw new Error(`no release image ${name}`);
    const match = /^(.+)\/([^/:@]+)(?::[^@]+)?@(sha256:[0-9a-f]{64})$/.exec(ref);
    if (!match) throw new Error(`${name}: not a digest-pinned reference: ${ref}`);
    const [, from, repo, digest] = match;
    if (repo !== repository) throw new Error(`${name}: published as ${repo}, but the Coolify files pull ${repository}`);
    if (registry !== undefined && registry !== from) throw new Error(`${name}: published to ${from}, the others to ${registry}`);
    registry = from;
    lines.push(`${variable}=${digest}`);
  }
  return `${REGISTRY_VARIABLE}=${registry}\n${lines.join("\n")}\n`;
}

/** The variables a Compose file's `image:` lines interpolate, in order of first use. */
export function variablesIn(text) {
  return [...new Set([...text.matchAll(/\$\{(VARLATCH_[A-Z_]+_DIGEST|VARLATCH_IMAGE_REGISTRY)[:}?-]/g)].map(m => m[1]))];
}
