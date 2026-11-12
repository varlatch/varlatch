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
import { MOVED } from "../src/moved-anchors.mjs";

/** The site path a built file is served at: dist/a/index.html is /a/. */
function sitePathOf(dist, file) {
  return `/${relative(dist, file).split("\\").join("/")}`.replace(/index\.html$/, "");
}

/** Where a site path is served from, or undefined when dist has no file for it. */
function fileFor(dist, path) {
  for (const candidate of [path, posix.join(path, "index.html")]) {
    const file = join(dist, decodeURIComponent(candidate));
    if (existsSync(file) && statSync(file).isFile()) return file;
  }
  return undefined;
}

/**
 * A link to a section that moved (moved-anchors.mjs) counts as resolving:
 * the old page's script sends the reader on, and checkMoved checks where.
 * @returns {string[]} one line per broken link
 */
export function checkLinks(dist, moved = MOVED) {
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
      const id = hash && decodeURIComponent(hash);
      if (hash && target.endsWith(".html") && !idsOf(target).has(id) && !moved[sitePathOf(dist, target)]?.[id]) {
        problems.push(`/${relative(dist, file)}: ${href} has no #${hash} on its page`);
      }
    }
  }
  return problems;
}

/**
 * @param {Record<string, Record<string, string>>} moved old page, then old ID, to new place (moved-anchors.mjs)
 * @returns {string[]} one line per moved section whose new place is missing, or whose old ID still exists
 */
export function checkMoved(dist, moved = MOVED) {
  const problems = [];
  for (const [oldPath, anchors] of Object.entries(moved)) {
    const oldFile = fileFor(dist, oldPath);
    if (!oldFile) {
      problems.push(`moved from ${oldPath}: the page no longer exists, so its script never runs`);
      continue;
    }
    const oldIds = new Set([...readFileSync(oldFile, "utf8").matchAll(/\sid="([^"]+)"/g)].map(m => m[1]));
    for (const [id, target] of Object.entries(anchors)) {
      if (oldIds.has(id)) problems.push(`moved from ${oldPath}#${id}: the page still has that ID`);
      const [path, hash] = target.split("#");
      const file = fileFor(dist, path);
      if (!file) {
        problems.push(`moved from ${oldPath}#${id}: ${target} has no page`);
      } else if (hash && !readFileSync(file, "utf8").includes(` id="${hash}"`)) {
        problems.push(`moved from ${oldPath}#${id}: ${target} has no #${hash} on its page`);
      }
    }
  }
  return problems;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const dist = resolve(process.argv[2] ?? join(dirname(fileURLToPath(import.meta.url)), "../dist"));
  const problems = [...checkLinks(dist), ...checkMoved(dist)];
  if (problems.length > 0) {
    console.error(`${problems.length} broken link(s):\n${problems.map(p => `  ${p}`).join("\n")}`);
    process.exit(1);
  }
  console.log("Every internal link and anchor resolves.");
}
