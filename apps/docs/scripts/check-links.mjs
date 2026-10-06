#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Fails the build when a page links to a page or an anchor the built site
 * does not have. It reads the HTML in dist/, so it checks what readers get:
 * the links repo-links.mjs rewrote, the sidebar, and every heading ID
 * as rendered. Links to other sites are not fetched.
 *
 *   check-links.mjs [dist]    run after `astro build`
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, posix, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** Where a site path is served from, or undefined when dist has no file for it. */
function fileFor(dist, path) {
  for (const candidate of [path, posix.join(path, "index.html")]) {
    const file = join(dist, decodeURIComponent(candidate));
    if (existsSync(file) && statSync(file).isFile()) return file;
  }
  return undefined;
}

/** @returns {string[]} one line per broken link */
export function checkLinks(dist) {
  const html = readdirSync(dist, { recursive: true })
    .map(String)
    .filter(path => path.endsWith(".html"));
  const ids = new Map();
  const idsOf = file => {
    if (!ids.has(file)) {
      ids.set(file, new Set([...readFileSync(file, "utf8").matchAll(/\sid="([^"]+)"/g)].map(m => m[1])));
    }
    return ids.get(file);
  };
  const problems = [];
  for (const page of html) {
    const file = join(dist, page);
    const base = `/${page.split("\\").join("/")}`;
    for (const [, href] of readFileSync(file, "utf8").matchAll(/\shref="([^"]+)"/g)) {
      if (/^[a-z][a-z0-9+.-]*:|^\/\//i.test(href)) continue;
      const [rawPath, hash] = href.replace(/&amp;/g, "&").split("#");
      const path = rawPath === "" ? base : posix.resolve(posix.dirname(base), rawPath.split("?")[0]);
      const target = rawPath === "" ? file : fileFor(dist, path);
      if (!target) {
        problems.push(`/${relative(dist, file)}: ${href} has no page`);
        continue;
      }
      if (hash && target.endsWith(".html") && !idsOf(target).has(decodeURIComponent(hash))) {
        problems.push(`/${relative(dist, file)}: ${href} has no #${hash} on its page`);
      }
    }
  }
  return problems;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const dist = resolve(process.argv[2] ?? join(dirname(fileURLToPath(import.meta.url)), "../dist"));
  const problems = checkLinks(dist);
  if (problems.length > 0) {
    console.error(`${problems.length} broken link(s):\n${problems.map(p => `  ${p}`).join("\n")}`);
    process.exit(1);
  }
  console.log("Every internal link and anchor resolves.");
}
