// SPDX-License-Identifier: Apache-2.0
// The images the nightly scan (.github/workflows/image-scan.yml) scans, from
// the files each release attaches:
//
//   node scripts/ci-scan-images.mjs <dir>     <dir>/<tag>/ per release
//
// A release of the Go line records its one image in varlatchd-image.txt; a
// TypeScript release pins its images in varlatch-release.json, of which the
// scan takes Varlatch's own two. Prints a JSON array of {image, tag, pinned},
// each pinned by digest, for the workflow's matrix. Anything else is an error:
// a release that names no image is never a scan of nothing.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

/** The images of one release: tag, and its files by name. */
export function releaseImages(tag, files) {
  const version = /^v([0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.]+)?)$/.exec(tag)?.[1];
  if (!version) throw new Error(`${JSON.stringify(tag)} is not a release's tag`);
  const pin = (image, pinned) => {
    if (!new RegExp(`^ghcr\\.io/[a-z0-9._-]+/${image}@sha256:[0-9a-f]{64}$`).test(String(pinned))) {
      throw new Error(`${tag} pins ${image} as ${JSON.stringify(pinned)}, not a ghcr.io image by digest`);
    }
    return { image, tag, pinned };
  };
  const line = files["varlatchd-image.txt"];
  const manifest = files["varlatch-release.json"];
  if ((line === undefined) === (manifest === undefined)) {
    throw new Error(`${tag} has ${line === undefined ? "neither" : "both"} varlatchd-image.txt (a Go release) and varlatch-release.json (a TypeScript one)`);
  }
  if (line !== undefined) {
    const [, repository, tagged, digest] = /^([^\s:@]+):([^\s:@]+)@(sha256:[0-9a-f]{64})\n$/.exec(line) ?? [];
    if (tagged !== version) throw new Error(`varlatchd-image.txt of ${tag} is ${JSON.stringify(line)}, not one line with that version's image`);
    return [pin("varlatchd", `${repository}@${digest}`)];
  }
  const { images } = JSON.parse(manifest);
  return ["varlatchd", "varlatch-web"].map((image) => pin(image, images?.[image]?.digest));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const dir = process.argv[2];
  const releases = readdirSync(dir).sort();
  if (releases.length === 0) throw new Error(`${dir} holds no release`);
  const found = releases.flatMap((tag) => {
    const files = Object.fromEntries(["varlatchd-image.txt", "varlatch-release.json"].map((f) => [f, join(dir, tag, f)])
      .filter(([, path]) => existsSync(path)).map(([f, path]) => [f, readFileSync(path, "utf8")]));
    return releaseImages(tag, files);
  });
  console.log(JSON.stringify(found));
}
