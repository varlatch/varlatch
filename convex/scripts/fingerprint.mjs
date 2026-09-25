#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Application Plane function fingerprint (ADR-0035 D4): a hash of the Convex
 * function sources and the Convex package version — what `convex deploy`
 * turns into the deployed bundle. The convex-deploy image stamps it into the
 * bundle (`meta:release`), the varlatchd image carries it as the expected
 * value, so reconciliation and `doctor` can tell whether the functions a
 * backend actually serves are this release's.
 *
 * Paths are relative to the package root, so the repository layout
 * (convex/package.json, convex/convex/…) and the deploy image layout
 * (/app/package.json, /app/convex/…) hash identically.
 *
 *   node fingerprint.mjs [--root <dir>]          print the fingerprint
 *   node fingerprint.mjs [--root <dir>] --stamp  write it into releaseStamp.ts
 */
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const STAMP = "convex/releaseStamp.ts";

function walk(root, dir) {
  const out = [];
  for (const entry of readdirSync(join(root, dir), { withFileTypes: true })) {
    const path = `${dir}/${entry.name}`;
    if (entry.isDirectory()) {
      if (entry.name !== "_generated" && entry.name !== "node_modules") out.push(...walk(root, path));
    } else if (path !== STAMP) {
      out.push(path);
    }
  }
  return out;
}

export function fingerprint(root) {
  const hash = createHash("sha256");
  for (const file of ["package.json", ...walk(root, "convex")].sort()) {
    hash.update(file).update("\0").update(readFileSync(join(root, file))).update("\0");
  }
  return hash.digest("hex");
}

export function stamp(root, value = fingerprint(root)) {
  writeFileSync(join(root, STAMP), `// Stamped by scripts/fingerprint.mjs when the deploy image is built
// (ADR-0035 D4). The committed value marks an unstamped development bundle.
export const FUNCTIONS_FINGERPRINT: string = ${JSON.stringify(value)};
`);
  return value;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const i = args.indexOf("--root");
  const root = resolve(i >= 0 ? args[i + 1] : fileURLToPath(new URL("..", import.meta.url)));
  console.log(args.includes("--stamp") ? stamp(root) : fingerprint(root));
}
